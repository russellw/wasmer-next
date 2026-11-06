use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use tokio::runtime::{Handle, Runtime};
use wasixv2::{
    Machine, PackageInstallSource, ProcessConfig, ResolvedLayout, Stdio, command_config,
    install_package_sources, preflight_resolved_filesystem,
};
use wasmer_config::package::{PackageHash, PackageId};
use wasmer_package::{
    http::reqwest::ReqwestHttpClient,
    loader::{LoadedPackage, PackageDownloader, fetch_dependencies},
    resolver::{BackendSource, MultiSource, PackageInfo, Source, resolve},
    utils::from_bytes,
};
use webc::{Container, metadata::annotations::Wasi};

uniffi::setup_scaffolding!();

macro_rules! err {
    ($e:expr) => {
        match $e {
            Ok(r) => r,
            Err(e) => {
                println!("{e}");
                return Err(WasmerError::Err { e: e.to_string() });
            }
        }
    };
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum WasmerError {
    #[error("An error occurred during execution: {e:?}")]
    Err { e: String },
}

#[uniffi::export]
pub fn run_package(webc_bytes: Vec<u8>, args: Vec<String>) -> Result<String, WasmerError> {
    let tokio_rt = Runtime::new().unwrap();
    let _enter = tokio_rt.enter();
    let container = err!(from_bytes(webc_bytes));
    let client = Arc::new(ReqwestHttpClient::default());
    let mut source = MultiSource::default();
    source.add_source(BackendSource::new(
        BackendSource::WASMER_PROD_ENDPOINT.parse().unwrap(),
        client.clone(),
    ));
    let downloader = PackageDownloader::new(client);
    // Acquisition errors historically panic before entering the execution worker.
    let package = tokio_rt
        .block_on(acquire(container, &source, &downloader))
        .unwrap();
    run_loaded(tokio_rt.handle(), package, args)
}

async fn acquire(
    container: Container,
    source: &dyn Source,
    downloader: &PackageDownloader,
) -> anyhow::Result<LoadedPackage> {
    let id = PackageInfo::package_id_from_manifest(container.manifest())?
        .or_else(|| {
            container
                .webc_hash()
                .map(|hash| PackageId::Hash(PackageHash::from_sha256_bytes(hash)))
        })
        .context("webc file did not provide its hash")?;
    let info = PackageInfo::from_manifest(id.clone(), container.manifest(), container.version())?;
    let resolution = resolve(&id, &info, source).await?;
    let mut containers = fetch_dependencies(
        &resolution.package,
        &resolution.graph,
        |summary| async move { downloader.load(&summary).await },
    )
    .await?;
    containers.insert(id, container);
    preflight_resolved_filesystem(&containers, &resolution.package, false)?;
    LoadedPackage::from_containers(resolution, containers)
}

fn run_loaded(
    runtime: &Handle,
    package: LoadedPackage,
    args: Vec<String>,
) -> Result<String, WasmerError> {
    let Some(entrypoint) = package.resolution.package.entrypoint.clone() else {
        return Ok(format!(
            "This WEBC ({}) has no entrypoint!",
            package.resolution.package.root_package
        ));
    };
    let output = Arc::new(Mutex::new(Vec::new()));
    let capture = output.clone();
    let runtime = runtime.clone();
    let worker = std::thread::spawn(move || {
        let _enter = runtime.enter();
        with_machine(&runtime, async |machine| {
            // Preserve the Swift API's captured-output result on runner errors.
            let _ = execute(machine, &package, &entrypoint, args, capture).await;
        });
    });
    let _ = worker.join();
    let bytes = std::mem::take(&mut *output.lock().unwrap());
    Ok(err!(String::from_utf8(bytes)))
}

fn with_machine(runtime: &Handle, run: impl AsyncFnOnce(&mut Machine)) {
    let local = tokio::task::LocalSet::new();
    let mut machine = None;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(local.run_until(async {
            machine = Some(Machine::new());
            run(machine.as_mut().unwrap()).await;
        }));
    }));
    if let Some(machine) = &machine {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(local.run_until(machine.shutdown()));
        }));
    }
    // Stdio's FnSink copies writes synchronously. Keep this executor driving
    // retirement work through Machine drop, then drain it before reading output.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(local.run_until(async { drop(machine.take()) }));
    }));
    runtime.block_on(local);
}

async fn execute(
    machine: &mut Machine,
    package: &LoadedPackage,
    entrypoint: &str,
    args: Vec<String>,
    output: Arc<Mutex<Vec<u8>>>,
) -> anyhow::Result<()> {
    let command = package
        .get_command(entrypoint)
        .with_context(|| format!("The package doesn't contain a \"{entrypoint}\" command"))?;
    let annotation = command.metadata().annotation::<Wasi>(Wasi::KEY)?;
    let mut config = ProcessConfig {
        args,
        env: Vec::new(),
        stdio: Stdio::from_fns(
            move |bytes| output.lock().unwrap().extend_from_slice(bytes),
            |_| {},
        ),
    };
    let cwd = command_config(entrypoint, annotation.as_ref(), &mut config)?;
    anyhow::ensure!(
        config
            .args
            .iter()
            .chain(&config.env)
            .all(|value| !value.contains('\0')),
        "arguments and environment must not contain NUL bytes"
    );
    let layout = ResolvedLayout::new(package, false, None)?;
    install_package_sources(machine, &[PackageInstallSource::Resolved(&layout)]).await?;
    if let Some(cwd) = cwd {
        machine.ensure_directory(&cwd).await?;
        machine.set_working_dir(cwd);
    }
    // Run the selected atom directly: package mounts may hide its /bin alias.
    let _ = machine.run_process(&command.atom(), config).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::BoxFuture;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use wasmer_package::{
        http::{HttpClient, HttpRequest, HttpResponse},
        resolver::{DistributionInfo, InMemorySource, PackageSummary, WebcHash},
    };
    use webc::v3::{
        ChecksumAlgorithm, SignatureAlgorithm, Timestamps,
        write::{DirEntry, Directory, FileEntry, Writer},
    };

    fn manifest(entrypoint: bool) -> Value {
        let mut manifest = json!({
            "package":{"wapm":{"name":"swift/test","version":"1.0.0"}},
            "commands":{"hello":{"runner":"https://webc.org/runner/wasi", "annotations":{"atom":{"name":"main"}}}}
        });
        if entrypoint {
            manifest["entrypoint"] = json!("hello");
        }
        manifest
    }

    fn archive(mut manifest: Value, module: Option<&[u8]>, files: bool) -> Vec<u8> {
        if let Some(module) = module {
            let hash = WebcHash::sha256(module).as_bytes();
            manifest["atoms"]["main"] = json!({
                "kind": "https://webc.org/kind/wasm",
                "signature": webc::metadata::AtomSignature::Sha256(hash).to_string(),
            });
        }
        let manifest = serde_json::from_value(manifest).unwrap();
        let atoms = module
            .into_iter()
            .map(|module| {
                (
                    "main".parse().unwrap(),
                    FileEntry::borrowed(module, Timestamps::default()),
                )
            })
            .collect();
        let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(atoms)
            .unwrap();
        if files {
            writer
                .write_volume(
                    "data",
                    Directory::new(
                        BTreeMap::from([(
                            "message".parse().unwrap(),
                            DirEntry::File(FileEntry::borrowed(b"volume\n", Timestamps::default())),
                        )]),
                        Timestamps::default(),
                    ),
                )
                .unwrap();
        }
        writer.finish(SignatureAlgorithm::None).unwrap().to_vec()
    }

    fn printing(bytes: &[u8], tail: &str) -> Vec<u8> {
        let escaped = bytes
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect::<String>();
        wat::parse_str(format!(r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
            (memory (export "memory") 1)
            (data (i32.const 32) "{escaped}")
            (func (export "_start")
                (i32.store (i32.const 16) (i32.const 32))
                (i32.store (i32.const 20) (i32.const {length}))
                (drop (call $write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
                {tail}))"#, length=bytes.len())).unwrap()
    }

    // The same preview1 args/stdio pattern as api/tests/commands.rs, extended
    // to print the environment and actual cwd through the compatibility ABI.
    const CONFIG: &str = r#"(module
        (import "wasi_snapshot_preview1" "args_sizes_get" (func $args_size (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "args_get" (func $args (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "environ_sizes_get" (func $env_size (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "environ_get" (func $env (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        (import "wasix_32v1" "getcwd" (func $cwd (param i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 96) "/data/message")
        (data (i32.const 8) " \n")
        (func $print (param $p i32) (param $n i32)
            (i32.store (i32.const 16) (local.get $p))
            (i32.store (i32.const 20) (local.get $n))
            (drop (call $write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24))))
        (func $strlen (param $p i32) (result i32) (local $n i32)
            (block $done (loop $next
                (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
                (local.set $n (i32.add (local.get $n) (i32.const 1))) (br $next)))
            local.get $n)
        (func $strings (local $i i32) (local $p i32)
            (block $done (loop $next
                (br_if $done (i32.ge_u (local.get $i) (i32.load (i32.const 0))))
                (if (local.get $i) (then (call $print (i32.const 8) (i32.const 1))))
                (local.set $p (i32.load (i32.add (i32.const 128) (i32.shl (local.get $i) (i32.const 2)))))
                (call $print (local.get $p) (call $strlen (local.get $p)))
                (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $next)))
            (call $print (i32.const 9) (i32.const 1)))
        (func (export "_start")
            (drop (call $args_size (i32.const 0) (i32.const 4)))
            (drop (call $args (i32.const 128) (i32.const 512))) (call $strings)
            (drop (call $env_size (i32.const 0) (i32.const 4)))
            (drop (call $env (i32.const 128) (i32.const 512))) (call $strings)
            (i32.store (i32.const 64) (i32.const 4096))
            (drop (call $cwd (i32.const 4096) (i32.const 64)))
            (call $print (i32.const 4096) (i32.load (i32.const 64)))
            (call $print (i32.const 9) (i32.const 1))
            ;; extra
        ))"#;

    #[test]
    fn malformed_input_and_invalid_output_keep_the_swift_error_variant() {
        assert!(matches!(
            run_package(b"not a WEBC".to_vec(), vec![]),
            Err(WasmerError::Err { .. })
        ));
        let bytes = archive(manifest(true), Some(&printing(&[0xff], "")), false);
        assert!(matches!(
            run_package(bytes, vec![]),
            Err(WasmerError::Err { .. })
        ));
    }

    #[test]
    fn a_single_command_without_an_explicit_entrypoint_runs_the_inferred_command() {
        let bytes = archive(manifest(false), Some(&printing(b"inferred\n", "")), false);
        assert_eq!(run_package(bytes, vec![]).unwrap(), "inferred\n");
    }

    #[test]
    fn multiple_commands_without_an_entrypoint_keep_the_original_message() {
        let mut meta = manifest(false);
        meta["commands"]["other"] = meta["commands"]["hello"].clone();
        let bytes = archive(meta, Some(&printing(b"must not run", "")), false);
        assert_eq!(
            run_package(bytes, vec![]).unwrap(),
            "This WEBC (swift/test@1.0.0) has no entrypoint!"
        );
    }

    #[test]
    fn captured_output_survives_nonzero_exit_and_trap() {
        for tail in ["", "(call $exit (i32.const 7))", "unreachable"] {
            let bytes = archive(manifest(true), Some(&printing(b"before\n", tail)), false);
            assert_eq!(run_package(bytes, vec![]).unwrap(), "before\n");
        }
        let bytes = archive(manifest(true), Some(b"invalid module"), false);
        assert_eq!(run_package(bytes, vec![]).unwrap(), "");
    }

    #[test]
    fn annotations_preserve_argument_environment_and_single_directory_creation() {
        let mut meta = manifest(true);
        meta["commands"]["hello"]["annotations"]["wasi"] = json!({
            "atom":"main", "exec-name":"custom", "main-args":["default"],
            "env":["A=first", "B", "A=last", "V=x=y"], "cwd":"/swift-work"
        });
        let module = wat::parse_str(CONFIG).unwrap();
        let bytes = archive(meta.clone(), Some(&module), false);
        assert_eq!(
            run_package(bytes, vec!["caller".into()]).unwrap(),
            "custom default caller\nA=last B= V=x=y\n/swift-work\n"
        );
        meta["commands"]["hello"]["annotations"]["wasi"]["cwd"] =
            json!("/missing-parent/swift-work");
        assert_eq!(
            run_package(archive(meta, Some(&module), false), vec![]).unwrap(),
            ""
        );
        // No implicit host environment, HOME or PATH is supplied by Swift.
        assert_eq!(
            run_package(archive(manifest(true), Some(&module), false), vec![]).unwrap(),
            "hello\n\n/\n"
        );
    }

    #[test]
    fn nul_arguments_and_malformed_selected_annotations_keep_runner_error_policy() {
        let module = printing(b"must not run", "");
        let bytes = archive(manifest(true), Some(&module), false);
        assert_eq!(run_package(bytes, vec!["bad\0arg".into()]).unwrap(), "");
        let mut meta = manifest(true);
        meta["commands"]["hello"]["annotations"]["wasi"] = json!({"atom":"main", "env":42});
        assert_eq!(
            run_package(archive(meta, Some(&module), false), vec![]).unwrap(),
            ""
        );
    }

    #[test]
    fn stdin_is_eof_and_stderr_is_discarded() {
        let module = wat::parse_str(r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 32) "ok\nhidden")
            (func (export "_start")
                (i32.store (i32.const 16) (i32.const 64)) (i32.store (i32.const 20) (i32.const 8))
                (if (call $read (i32.const 0) (i32.const 16) (i32.const 1) (i32.const 24)) (then unreachable))
                (if (i32.load (i32.const 24)) (then unreachable))
                (i32.store (i32.const 16) (i32.const 35)) (i32.store (i32.const 20) (i32.const 6))
                (drop (call $write (i32.const 2) (i32.const 16) (i32.const 1) (i32.const 24)))
                (i32.store (i32.const 16) (i32.const 32)) (i32.store (i32.const 20) (i32.const 3))
                (drop (call $write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))))"#).unwrap();
        assert_eq!(
            run_package(archive(manifest(true), Some(&module), false), vec![]).unwrap(),
            "ok\n"
        );
    }

    #[test]
    fn original_nested_mount_fixture_runs_without_replacing_its_bytes() {
        let bytes = include_bytes!(
            "../../../tests/integration/cli/tests/packages/nested-mounted-paths/out.webc"
        );
        let output = run_package(bytes.to_vec(), vec![]).unwrap();
        assert!(output.contains("/app/a:\n"), "{output}");
        assert!(output.contains("data-a.txt"), "{output}");
        assert!(output.contains("/app/b:\n"), "{output}");
        assert!(output.contains("data-b.txt"), "{output}");
    }

    #[derive(Debug)]
    struct Download {
        bytes: Vec<u8>,
        calls: AtomicUsize,
    }
    impl HttpClient for Download {
        fn request(&self, request: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            assert_eq!(
                request.url.as_str(),
                "https://example.invalid/dependency.webc"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(HttpResponse {
                    body: Some(self.bytes.clone()),
                    redirected: false,
                    status: "200".parse().unwrap(),
                    headers: Default::default(),
                })
            })
        }
    }

    #[test]
    fn downloaded_dependency_atoms_keep_resolved_aliases_and_package_mounts() {
        let runtime = Runtime::new().unwrap();
        let _enter = runtime.enter();
        let mut dep_meta = manifest(true);
        dep_meta["package"]["wapm"]["name"] = json!("swift/dependency");
        dep_meta["package"]["fs"] = json!([{"volume_name":"data", "mount_path":"/data"}]);
        let module = wat::parse_str(CONFIG.replace(";; extra", r#"
            (if (call $open (i32.const 3) (i32.const 1) (i32.const 96) (i32.const 13) (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 80)) (then unreachable))
            (i32.store (i32.const 16) (i32.const 8192))
            (i32.store (i32.const 20) (i32.const 32))
            (if (call $read (i32.load (i32.const 80)) (i32.const 16) (i32.const 1) (i32.const 24)) (then unreachable))
            (call $print (i32.const 8192) (i32.load (i32.const 24)))
        "#)).unwrap();
        let dependency = archive(dep_meta, Some(&module), true);
        let hash = WebcHash::sha256(&dependency);
        let container = from_bytes(dependency.clone()).unwrap();
        let mut source = InMemorySource::new();
        source.add(PackageSummary {
            pkg: PackageInfo::from_manifest(
                PackageId::new_named("swift/dependency", "1.0.0".parse().unwrap()),
                container.manifest(),
                container.version(),
            )
            .unwrap(),
            dist: DistributionInfo {
                webc: "https://example.invalid/dependency.webc".parse().unwrap(),
                webc_sha256: hash,
            },
        });
        let root = json!({
            "package":{"wapm":{"name":"swift/root","version":"1.0.0"}},
            "entrypoint":"alias", "use":{"dep":"swift/dependency@1.0.0"},
            "commands":{"alias":{"runner":"https://webc.org/runner/wasi", "annotations":{
                "atom":{"name":"main", "dependency":"dep"}, "wasi":{"atom":"main", "exec-name":"aliased", "main-args":["default"], "cwd":"/data"}
            }}}
        });
        let client = Arc::new(Download {
            bytes: dependency,
            calls: AtomicUsize::new(0),
        });
        let downloader = PackageDownloader::new(client.clone());
        let package = runtime
            .block_on(acquire(
                from_bytes(archive(root, None, false)).unwrap(),
                &source,
                &downloader,
            ))
            .unwrap();
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            run_loaded(runtime.handle(), package, vec!["caller".into()]).unwrap(),
            "aliased default caller\n\n/data\nvolume\n"
        );
    }

    #[test]
    fn simultaneous_calls_capture_separate_output() {
        let workers: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|text| {
                let bytes = archive(manifest(true), Some(&printing(text.as_bytes(), "")), false);
                std::thread::spawn(move || run_package(bytes, vec![]).unwrap())
            })
            .collect();
        let output: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(output, ["first", "second"]);
    }
    #[test]
    fn worker_panic_drains_real_pending_instance_attachments_on_the_same_local_set() {
        use std::future::Future;
        use std::task::{Context as TaskContext, Poll};
        use wasixv2::{ExecEnv, InstanceAttachment, InstantiationHook, MachineSyscalls};
        use wasmer::{
            Function, FunctionEnv, Imports, Instance, Memory, Module, RuntimeError, StoreMut,
        };

        struct Hook(Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>);
        struct Attachment(Arc<AtomicUsize>, Arc<AtomicUsize>);
        impl InstantiationHook<MachineSyscalls> for Hook {
            fn prepare_imports(
                &self,
                _: &Module,
                store: &mut StoreMut<'_>,
                _: &FunctionEnv<ExecEnv<MachineSyscalls>>,
                imports: &mut Imports,
            ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
                imports.define(
                    "custom",
                    "pending",
                    Function::new_async(store, wasmer::FunctionType::new([], []), |_| async {
                        std::future::pending::<()>().await;
                        Ok(vec![])
                    }),
                );
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Some(Box::new(Attachment(self.1.clone(), self.2.clone()))))
            }
        }
        impl InstanceAttachment for Attachment {
            fn configure(
                &mut self,
                _: &Module,
                _: &mut StoreMut<'_>,
                _: &Instance,
                _: &Memory,
            ) -> Result<(), RuntimeError> {
                Ok(())
            }
            fn deactivate(&mut self, _: &mut StoreMut<'_>) {
                self.0.fetch_add(1, Ordering::SeqCst);
                let drained = self.1.clone();
                tokio::task::spawn_local(async move {
                    tokio::task::yield_now().await;
                    drained.fetch_add(1, Ordering::SeqCst);
                });
            }
        }
        let prepared = Arc::new(AtomicUsize::new(0));
        let deactivated = Arc::new(AtomicUsize::new(0));
        let drained = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new().unwrap();
        let _enter = runtime.enter();
        with_machine(runtime.handle(), async |machine| {
            *machine = Machine::builder()
                .instantiation_hook(Arc::new(Hook(
                    prepared.clone(),
                    deactivated.clone(),
                    drained.clone(),
                )))
                .build();
            let module = wat::parse_str(
                r#"(module
                (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
                (import "custom" "pending" (func $pending))
                (memory (export "memory") 1)
                (func (export "_start") call $pending))"#,
            )
            .unwrap();
            let mut run = Box::pin(machine.run_process(
                &module,
                ProcessConfig {
                    args: vec![],
                    env: vec![],
                    stdio: Stdio::from_fns(|_| {}, |_| {}),
                },
            ));
            let waker = futures_util::task::noop_waker();
            assert!(matches!(
                run.as_mut().poll(&mut TaskContext::from_waker(&waker)),
                Poll::Pending
            ));
            assert_eq!(prepared.load(Ordering::SeqCst), 1);
            assert_eq!(deactivated.load(Ordering::SeqCst), 0);
            panic!("deliberate worker panic with a suspended real guest");
        });
        assert_eq!(deactivated.load(Ordering::SeqCst), 1);
        assert_eq!(drained.load(Ordering::SeqCst), 1);
    }
}
