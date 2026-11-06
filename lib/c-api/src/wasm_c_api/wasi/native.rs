//! Native WASI facade. Configuration and process ownership remain outside the Store.

use super::{ConfigurationError, exit_trap, get_wasi_version, wasi_version_t};
use crate::wasm_c_api::store::{
    CleanupRetirement, ContinuationEndpoint, LocalContinuation, StoreRef,
};
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::{Arc, Condvar, Mutex},
};
use wasixv2::{
    ByteSink, DirectoryBootstrap, EmbeddingProcess, LocalFuture, Machine, MachineSyscalls,
    NamespaceBootstrap, ProcessConfig, Stdio,
};
use wasixv2_exec::{ExecError, HostCallHandoff, HostEnvironment, OwnedEntryWaiter};
use wasixv2_wasix1::{
    PreopenRights, StartupDescriptors, StartupInput,
    imports::{self, Module as Namespace},
};
use wasmer_api::{AsStoreAsync, AsStoreMut, Imports, Instance, Module, RuntimeError, StoreMut};

#[derive(Default)]
struct Capture {
    queue: Mutex<(VecDeque<(Vec<u8>, usize)>, bool)>,
    ready: Condvar,
}
struct Writer(Arc<Capture>);
impl ByteSink for Writer {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        if data.is_empty() {
            return Box::pin(async { Ok(0) });
        }
        self.0
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .push_back((data.to_vec(), 0));
        self.0.ready.notify_all();
        Box::pin(async move { Ok(data.len()) })
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.0.queue.lock().unwrap_or_else(|e| e.into_inner()).1 = true;
        self.0.ready.notify_all();
    }
}
impl Capture {
    fn read(&self, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let mut state = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        while state.0.is_empty() && !state.1 {
            state = self.ready.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        let Some((bytes, offset)) = state.0.front_mut() else {
            return 0;
        };
        let count = buffer.len().min(bytes.len() - *offset);
        buffer[..count].copy_from_slice(&bytes[*offset..*offset + count]);
        *offset += count;
        if *offset == bytes.len() {
            state.0.pop_front();
        }
        count
    }
}

pub(in crate::wasm_c_api) struct NativeWasi {
    endpoint: Rc<Endpoint>,
    stdout: Option<Arc<Capture>>,
    stderr: Option<Arc<Capture>>,
}
struct Endpoint {
    process: RefCell<Option<EmbeddingProcess>>,
    env: HostEnvironment<MachineSyscalls>,
    retire: RefCell<Option<Box<dyn FnOnce()>>>,
    retired: Cell<bool>,
    committed: Cell<bool>,
    handoff: RefCell<Option<HostCallHandoff>>,
}

impl NativeWasi {
    pub(super) fn new(
        store: &StoreRef,
        args: Vec<String>,
        env: Vec<(String, Vec<u8>)>,
        preopens: Vec<(String, String)>,
        capture_stdout: bool,
        capture_stderr: bool,
    ) -> anyhow::Result<Self> {
        for (key, _) in &env {
            if key.contains('=') {
                return Err(ConfigurationError::Environment(format!(
                    "found equal sign in env var key \"{key}\" (key=value)"
                ))
                .into());
            }
        }
        validate_preopens(&preopens)?;
        let startup_env: Vec<_> = env
            .iter()
            .map(|(key, value)| [key.as_bytes(), b"=", value].concat())
            .collect();
        let startup_args = args.iter().map(|arg| arg.as_bytes().to_vec()).collect();
        let stdout = capture_stdout.then(|| Arc::new(Capture::default()));
        let stderr = capture_stderr.then(|| Arc::new(Capture::default()));
        let mut stdio = Stdio::inherit();
        if let Some(capture) = &stdout {
            stdio.stdout = Arc::new(Writer(capture.clone()));
        }
        if let Some(capture) = &stderr {
            stdio.stderr = Arc::new(Writer(capture.clone()));
        }
        let kernel_env = env
            .iter()
            .map(|(key, value)| format!("{key}={}", String::from_utf8_lossy(value)))
            .collect();
        let (process, environment, input, descriptors) = store.run_host(async {
            let machine = Arc::new(Machine::new());
            // Legacy read/write/create directory rights cover the original
            // preview1 bits; later socket/WASIX rights are not inherited.
            let mapped_rights = PreopenRights {
                base: (1 << 29) - 1,
                inheriting: (1 << 29) - 1,
            };
            let root_fallback = preopens.iter().position(|(name, _)| name == "/");
            let mut directories = Vec::new();
            let mut input_preopens = vec![(b"/".to_vec(), b"/".to_vec())];
            for (name, host) in preopens {
                let lookup_name = (!name.is_empty()
                    && name != "."
                    && name != ".."
                    && !name.contains('/')
                    && name.len() <= wasixv2::NAME_MAX)
                    .then(|| name.as_bytes().to_vec());
                directories.push(DirectoryBootstrap {
                    source: machine.capture_host_directory(std::path::Path::new(&host), false)?,
                    lookup_name,
                    attachment: Some(
                        mapped_rights
                            .named_attachment(name.as_bytes())
                            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
                    ),
                });
                // Ready descriptors carry authority; these path strings are never reopened.
                input_preopens.push((Vec::new(), name.into_bytes()));
            }
            let (process, boot) = machine
                .start_embedding_with_namespace(
                    ProcessConfig {
                        args,
                        env: kernel_env,
                        stdio,
                    },
                    NamespaceBootstrap {
                        directories,
                        root_attachment: Some(
                            PreopenRights::ALL
                                .named_attachment(b"/")
                                .map_err(|error| anyhow::anyhow!("{error:?}"))?,
                        ),
                        root_fallback,
                    },
                )
                .await?;
            let wasi = process
                .wasix1()
                .ok_or_else(|| anyhow::anyhow!("process owner is closed"))?;
            let root_fd = *boot
                .descriptors
                .first()
                .ok_or_else(|| anyhow::anyhow!("namespace root descriptor is missing"))?;
            if boot.task != process.task() {
                anyhow::bail!("namespace bootstrap belongs to another process");
            }
            let input = StartupInput {
                args: startup_args,
                env: startup_env,
                preopens: input_preopens,
            };
            let descriptors = StartupDescriptors {
                descriptors: boot.descriptors,
                binding: boot.binding,
                virtual_root: Some(root_fd),
            };
            let environment = store.with_mut(|store| {
                let environment = HostEnvironment::new(
                    store,
                    process.syscalls(),
                    process.task(),
                    process.host(),
                    process.abis(),
                );
                environment.set_binding(store, wasi.unattached());
                environment
            })?;
            Ok::<_, anyhow::Error>((process, environment, input, descriptors))
        })??;
        let asynchronous = store.async_store()?;
        let local =
            wasixv2_exec::local_cleanup_runner(&asynchronous, environment.loader_cleanup().clone())
                .ok_or_else(|| anyhow::anyhow!("native loader cleanup runner is missing"))?;
        let scope = Arc::downgrade(environment.loader_cleanup());
        store.register_cleanup_fence(Box::new(move || {
            scope.upgrade().is_none_or(|scope| !scope.is_open())
        }))?;
        let retiring_env = environment.clone();
        let retiring_store = asynchronous.store();
        // Keep this initial fallback lazy. A committed handoff replaces it
        // before entry; dropping an unpolled Runner would otherwise close the
        // shared loader scope before the captured physical ancestry settles.
        let retire = store.cleanup_retirement(Box::pin(async move {
            local
                .run(async move {
                    let mut guard = retiring_store.write_lock().await;
                    retiring_env.deactivate(&mut guard.as_store_mut());
                })
                .await;
        }))?;
        let result = Self {
            endpoint: Rc::new(Endpoint {
                process: RefCell::new(Some(process)),
                env: environment,
                retire: RefCell::new(Some(retire)),
                retired: Cell::new(false),
                committed: Cell::new(false),
                handoff: RefCell::new(None),
            }),
            stdout,
            stderr,
        };
        // No endpoint is published until atomic startup preparation succeeds.
        store.run_host(async {
            let process = result
                .endpoint
                .process
                .borrow()
                .as_ref()
                .and_then(EmbeddingProcess::wasix1)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("process owner is closed"))?;
            process
                .configure_and_prepare_startup(
                    &asynchronous,
                    &result.endpoint.env,
                    input,
                    descriptors,
                )
                .await
                .map_err(anyhow::Error::from)
        })??;
        let endpoint: Rc<dyn ContinuationEndpoint> = result.endpoint.clone();
        store.register_endpoint(Rc::downgrade(&endpoint))?;
        Ok(result)
    }

    pub(super) fn import_object(
        &self,
        store: &mut StoreMut<'_>,
        module: &Module,
    ) -> anyhow::Result<Imports> {
        let version = get_wasi_version(module)
            .ok_or_else(|| anyhow::anyhow!("The WASI version could not be determined"))?;
        let namespace = match version {
            wasi_version_t::SNAPSHOT0 => Namespace::Unstable,
            wasi_version_t::SNAPSHOT1 | wasi_version_t::LATEST => Namespace::Preview1,
            wasi_version_t::WASIX32V1 => Namespace::Wasix32,
            wasi_version_t::WASIX64V1 => anyhow::bail!(
                "{}",
                wasixv2_wasix1::V1Flavor::Wasm64
                    .unsupported_reason()
                    .unwrap()
            ),
            wasi_version_t::INVALID_VERSION => {
                anyhow::bail!("The WASI version could not be determined")
            }
        };
        let mut result = imports::namespace(store, self.endpoint.env.environment(), namespace);
        result.extend(&imports::namespace(
            store,
            self.endpoint.env.environment(),
            Namespace::Wasi,
        ));
        Ok(result)
    }

    pub(super) fn environment(&self) -> &HostEnvironment<MachineSyscalls> {
        &self.endpoint.env
    }

    pub(super) fn initialize(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
    ) -> anyhow::Result<()> {
        if self.endpoint.retired.get() || self.endpoint.committed.get() {
            anyhow::bail!("WASI environment is retired or its image was replaced");
        }
        self.endpoint.env.validate_instance(store, instance)?;
        let binding = {
            let process = self.endpoint.process.borrow();
            let wasi = process
                .as_ref()
                .and_then(EmbeddingProcess::wasix1)
                .ok_or_else(|| anyhow::anyhow!("WASI environment is closed"))?;
            wasi.attach(instance, store)
        };
        self.endpoint.env.initialize(store, instance, binding)?;
        Ok(())
    }

    pub(super) fn read(&self, stderr: bool, buffer: &mut [u8]) -> isize {
        if self.endpoint.retired.get() {
            crate::error::update_last_error("WASI environment is closed");
            return -1;
        }
        let capture = if stderr { &self.stderr } else { &self.stdout };
        match capture {
            Some(capture) => capture.read(buffer) as isize,
            None => {
                crate::error::update_last_error("the stream is inherited, not captured");
                -1
            }
        }
    }

    pub(super) fn close(&mut self) {
        if self.endpoint.retired.replace(true) {
            return;
        }
        let handoff = self.endpoint.handoff.borrow().clone();
        if let Some(handoff) = handoff {
            handoff.cancel();
            // The registered predecessor/terminal owner retains the process.
            return;
        }
        let process = self.endpoint.process.borrow_mut().take();
        let retire = self.endpoint.retire.borrow_mut().take();
        if let Some(mut process) = process {
            process.close();
        }
        if let Some(retire) = retire {
            retire();
        }
    }
}
impl Drop for NativeWasi {
    fn drop(&mut self) {
        self.close();
    }
}

fn validate_preopens(preopens: &[(String, String)]) -> Result<(), ConfigurationError> {
    let mut aliases = HashSet::new();
    for (name, _) in preopens {
        if !aliases.insert(name) {
            return Err(ConfigurationError::Filesystem(format!(
                "Found duplicate entry for alias `{name}`"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_c_api::{engine::wasm_engine_new, store::wasm_store_new};

    #[test]
    fn duplicate_announced_aliases_fail_before_any_directory_is_mounted() {
        let engine = wasm_engine_new();
        let store = unsafe { wasm_store_new(Some(&engine)) }.unwrap();
        let error = NativeWasi::new(
            &store.inner,
            vec!["duplicates".into()],
            vec![],
            vec![
                ("same".into(), "a directory that does not exist".into()),
                ("same".into(), ".".into()),
            ],
            false,
            false,
        )
        .err()
        .expect("duplicate aliases must fail before mounting the missing directory");
        assert!(matches!(
            error.downcast_ref::<ConfigurationError>(),
            Some(ConfigurationError::Filesystem(message))
                if message == "Found duplicate entry for alias `same`"
        ));
        validate_preopens(&[
            ("same".into(), ".".into()),
            ("same/".into(), ".".into()),
            ("same/.".into(), ".".into()),
        ])
        .expect("distinct legacy aliases remain accepted even when paths normalize equally");
    }

    #[test]
    fn native_config_preserves_lossy_keys_raw_values_order_and_preopen_kinds() {
        use super::super::{
            wasi_config_arg, wasi_config_env, wasi_config_mapdir, wasi_config_new,
            wasi_config_preopen_dir,
        };
        use std::ffi::CString;

        let program = CString::new("program").unwrap();
        let invalid = CString::new(vec![0xff]).unwrap();
        let normalized = CString::new("\u{fffd}").unwrap();
        let other = CString::new("other").unwrap();
        let first = CString::new(vec![0xfe]).unwrap();
        let replacement = CString::new(vec![0x80]).unwrap();
        let root = CString::new("/").unwrap();
        let alias = CString::new("////").unwrap();
        let missing = CString::new("/missing-capi-config-directory").unwrap();
        let mut config = unsafe { wasi_config_new(program.as_ptr()) }.unwrap();
        unsafe {
            wasi_config_arg(&mut config, invalid.as_ptr());
            wasi_config_env(&mut config, invalid.as_ptr(), first.as_ptr());
            wasi_config_env(&mut config, other.as_ptr(), first.as_ptr());
            wasi_config_env(&mut config, normalized.as_ptr(), replacement.as_ptr());
            assert!(wasi_config_preopen_dir(&mut config, root.as_ptr()));
            assert!(wasi_config_mapdir(
                &mut config,
                alias.as_ptr(),
                missing.as_ptr()
            ));
        }
        assert_eq!(config.args, ["program", "\u{fffd}"]);
        assert_eq!(
            config.env,
            [
                ("\u{fffd}".to_owned(), vec![0x80]),
                ("other".to_owned(), vec![0xfe])
            ]
        );
        assert_eq!(config.preopens[0].announced(), "/");
        assert!(config.preopens[0].alias.is_none());
        assert_eq!(config.preopens[1].announced(), "");
        assert_eq!(config.preopens[1].alias.as_deref(), Some(""));
        // Config creation never opens or validates the host directory.
        assert_eq!(config.preopens[1].host, "/missing-capi-config-directory");
        assert!(unsafe { wasi_config_new(invalid.as_ptr()) }.is_none());
    }

    #[test]
    fn native_version_detection_uses_the_first_recognized_function_namespace() {
        let store = wasmer_api::Store::default();
        let module = Module::new(
            &store,
            r#"(module
            (import "wasix_64v1" "memory" (memory 1))
            (import "wasi_unstable" "g" (global i32))
            (import "other" "ignore" (func))
            (import "wasi_snapshot_preview1" "first" (func))
            (import "wasi_unstable" "later" (func)))"#,
        )
        .unwrap();
        assert_eq!(get_wasi_version(&module), Some(wasi_version_t::SNAPSHOT1));
        let memory_only = Module::new(
            &store,
            r#"(module
            (import "wasi_unstable" "memory" (memory 1))
            (import "wasix_32v1" "g" (global i32)))"#,
        )
        .unwrap();
        assert_eq!(get_wasi_version(&memory_only), None);
    }

    #[test]
    fn native_exit_trap_preserves_legacy_status_and_message_bytes() {
        assert_eq!(exit_trap(0).message(), "WASI exited with code: ExitCode::0");
        assert_eq!(
            exit_trap(257).message(),
            "WASI exited with code: ExitCode::1"
        );
        assert_eq!(
            exit_trap(-1).message(),
            "WASI exited with code: ExitCode::65535"
        );
    }

    #[test]
    fn foreign_instance_metadata_is_rejected_before_attachment_and_selection_survives() {
        let engine = wasm_engine_new();
        let store = unsafe { wasm_store_new(Some(&engine)) }.unwrap();
        let env = NativeWasi::new(
            &store.inner,
            vec!["identity".into()],
            vec![],
            vec![],
            false,
            false,
        )
        .unwrap();
        let source = wat::parse_str(
            r#"(module
                (memory (export "arbitrarily_named_memory") 1)
                (global (export "__wasix_exec_table_stable") i32 (i32.const 1)))"#,
        )
        .unwrap();
        let mut foreign_store = wasmer_api::Store::default();
        let foreign_module = Module::new(&foreign_store, &source).unwrap();
        let foreign = Instance::new(&mut foreign_store, &foreign_module, &Imports::new()).unwrap();
        let local = store
            .inner
            .with_mut(|store| {
                let module = Module::new(store, &source).unwrap();
                Instance::new(store, &module, &Imports::new()).unwrap()
            })
            .unwrap();
        store
            .inner
            .with_mut(|store| {
                env.initialize(store, &local).unwrap();
                let error = env.initialize(store, &foreign).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("instance belongs to another Store")
                );
                // A failed foreign attachment does not prevent explicit reselection.
                env.initialize(store, &local).unwrap();
            })
            .unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn foreign_swallowed_exec_forwards_once_and_ownerless_calls_retire_after_real_cleanup() {
        use crate::wasm_c_api::{
            externals::{wasm_extern_t, wasm_func_call, wasm_func_new_with_env, wasm_func_t},
            store::wasm_store_t,
            trap::wasm_trap_t,
            types::wasm_functype_t,
            value::{wasm_val_t, wasm_val_vec_t},
        };
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use wasmer_api::{Function, FunctionType, Value};
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct Invoke {
            target: RefCell<wasm_func_t>,
            calls: Rc<Cell<usize>>,
            retire: Option<Rc<RefCell<Option<NativeWasi>>>>,
        }
        unsafe extern "C" fn invoke(
            data: *mut std::ffi::c_void,
            _: &wasm_val_vec_t,
            _: &mut wasm_val_vec_t,
        ) -> Option<Box<wasm_trap_t>> {
            // Match the existing C API callback environment/finalizer ownership.
            let invoke = unsafe { &*data.cast::<Invoke>() };
            let mut target = invoke.target.borrow_mut();
            let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
            let mut results: wasm_val_vec_t =
                vec![wasm_val_t::from_value(&Value::I64(1234567), &target.extern_.store).unwrap()]
                    .into();
            let trap = unsafe { wasm_func_call(Some(&mut target), Some(&args), &mut results) };
            assert!(trap.is_some());
            assert_eq!(unsafe { results.as_slice()[0].of.int64_t }, 1234567);
            invoke.calls.set(invoke.calls.get() + 1);
            drop(trap);
            let retired = invoke
                .retire
                .as_ref()
                .and_then(|env| env.borrow_mut().take());
            drop(retired);
            // Deliberately swallow the committed nested trap. Native ancestry
            // must still prevent both old guests from returning to their code.
            None
        }
        unsafe extern "C" fn finalize(data: *mut std::ffi::c_void) {
            drop(unsafe { Box::from_raw(data.cast::<Invoke>()) });
        }
        fn bridge(
            store: &mut wasm_store_t,
            target: wasm_func_t,
            calls: Rc<Cell<usize>>,
            retire: Option<Rc<RefCell<Option<NativeWasi>>>>,
        ) -> (wasm_func_t, Instance) {
            let data = Box::into_raw(Box::new(Invoke {
                target: RefCell::new(target),
                calls,
                retire,
            }));
            let ty = wasm_functype_t::new(FunctionType::new([], []));
            let callback = unsafe {
                wasm_func_new_with_env(
                    Some(store),
                    Some(&ty),
                    Some(invoke),
                    data.cast(),
                    Some(finalize),
                )
            }
            .unwrap();
            let source = wat::parse_str(
                r#"(module
                (import "test" "invoke" (func $invoke))
                (global (export "resumed") (mut i32) (i32.const 0))
                (func (export "run") (result i64)
                    call $invoke i32.const 1 global.set 0 i64.const 99))"#,
            )
            .unwrap();
            let instance = store
                .inner
                .with_mut(|store| {
                    let module = Module::new(store, source).unwrap();
                    Instance::new(
                        store,
                        &module,
                        &wasmer_api::imports! {"test" => {"invoke" => callback.extern_.function()}},
                    )
                    .unwrap()
                })
                .unwrap();
            let function = instance.exports.get_function("run").unwrap().clone();
            (
                wasm_func_t {
                    extern_: wasm_extern_t::new(store.inner.clone(), function.into()),
                },
                instance,
            )
        }
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // Two actual C callback depths, then ordinary call_async, wrong typed
        // owner and dead outer owner. Missing owners must never run the child.
        for mode in 0..6 {
            let engine = wasm_engine_new();
            let t = unsafe { wasm_store_new(Some(&engine)) }.unwrap();
            let path = std::env::temp_dir().join(format!(
                "wasmer-capi-handoff-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            let directory = Directory(path);
            let child = wat::parse_str(
                r#"(module
                (import "wasix_32v1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
                (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
                (memory (export "memory") 1) (data (i32.const 100) "child")
                (func (export "_start")
                    i32.const 0 i32.const 100 i32.store
                    i32.const 4 i32.const 5 i32.store
                    i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write drop
                    i32.const 0 call $exit unreachable))"#,
            )
            .unwrap();
            std::fs::write(directory.0.join("child.wasm"), child).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                directory.0.join("child.wasm"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            let wasi = NativeWasi::new(
                &t.inner,
                vec!["parent".into()],
                vec![],
                vec![("prog".into(), directory.0.to_str().unwrap().into())],
                true,
                false,
            )
            .unwrap();
            let parent = wat::parse_str(r#"(module
                (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (global (export "resumed") (mut i32) (i32.const 0))
                (data (i32.const 1000) "/prog/child.wasm")
                (data (i32.const 1040) "child\0a")
                (func (export "run") (result i64)
                    i32.const 1000 i32.const 16 i32.const 1040 i32.const 6
                    i32.const 0 i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $exec drop
                    i32.const 1 global.set 0 i64.const -1))"#).unwrap();
            let instance = t
                .inner
                .with_mut(|store| {
                    let module = Module::new(store, parent).unwrap();
                    let imports = wasi.import_object(store, &module).unwrap();
                    let instance = Instance::new(store, &module, &imports).unwrap();
                    wasi.initialize(store, &instance).unwrap();
                    instance
                })
                .unwrap();
            let capture = wasi.stdout.clone().unwrap();
            let wasi = Rc::new(RefCell::new(Some(wasi)));
            let finalized = Rc::new(Cell::new(false));
            if mode == 5 {
                struct DeleteEnvironment {
                    env: std::rc::Weak<RefCell<Option<NativeWasi>>>,
                    finalized: Rc<Cell<bool>>,
                }
                impl Drop for DeleteEnvironment {
                    fn drop(&mut self) {
                        let env = self.env.upgrade().and_then(|env| env.borrow_mut().take());
                        drop(env);
                        self.finalized.set(true);
                    }
                }
                let local = wasixv2_exec::local_cleanup_runner(
                    &t.inner.async_store().unwrap(),
                    wasi.borrow()
                        .as_ref()
                        .unwrap()
                        .environment()
                        .loader_cleanup()
                        .clone(),
                )
                .unwrap();
                let finalizer = DeleteEnvironment {
                    env: Rc::downgrade(&wasi),
                    finalized: finalized.clone(),
                };
                let (delete, ready) = tokio::sync::oneshot::channel();
                t.inner
                    .cleanup_owner()
                    .unwrap()
                    .retain(Box::pin(async move {
                        let _ = ready.await;
                        // Rc stays on the existing local cleanup owner. The Send loader
                        // callback only signals when old-image cleanup reaches this point.
                        drop(finalizer);
                    }));
                assert!(
                    local
                        .submit(Box::new(move |_| Box::pin(async move {
                            let _ = delete.send(());
                        })))
                        .is_ok()
                );
            }
            let cleaned = Arc::new(AtomicBool::new(false));
            let complete = cleaned.clone();
            assert!(
                wasi.borrow()
                    .as_ref()
                    .unwrap()
                    .environment()
                    .loader_cleanup()
                    .submit(Box::new(move || Box::pin(async move {
                        let (done, waiting) = tokio::sync::oneshot::channel();
                        tokio::task::spawn_local(async move {
                            tokio::task::yield_now().await;
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            complete.store(true, Ordering::SeqCst);
                            let _ = done.send(());
                        });
                        let _ = waiting.await;
                    })))
                    .is_ok()
            );
            let target = wasm_func_t {
                extern_: wasm_extern_t::new(
                    t.inner.clone(),
                    instance.exports.get_function("run").unwrap().clone().into(),
                ),
            };
            let calls = Rc::new(Cell::new(0));
            let mut stores = Vec::new();
            let mut instances = Vec::new();
            let mut current = target;
            for hop in 0..if mode == 1 {
                2
            } else if mode == 5 {
                0
            } else {
                1
            } {
                let mut store = unsafe { wasm_store_new(Some(&engine)) }.unwrap();
                let (next, instance) = bridge(
                    &mut store,
                    current,
                    calls.clone(),
                    (mode >= 2 && hop == 0).then(|| wasi.clone()),
                );
                stores.push(store);
                instances.push(instance);
                current = next;
            }
            let outer = stores.last().map(|store| &store.inner).unwrap_or(&t.inner);
            let identity = outer.with_mut(|store| store.objects_mut().id()).unwrap();
            if mode < 2 || mode == 5 {
                let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
                let mut results: wasm_val_vec_t =
                    vec![wasm_val_t::from_value(&Value::I64(7654321), outer).unwrap()].into();
                let trap = unsafe { wasm_func_call(Some(&mut current), Some(&args), &mut results) }
                    .unwrap();
                if mode != 5 {
                    assert_eq!(trap.inner.message(), "WASI exited with code: ExitCode::0");
                    let mut message: crate::wasm_c_api::types::wasm_byte_vec_t = Vec::new().into();
                    unsafe {
                        crate::wasm_c_api::trap::wasm_trap_message(&trap, &mut message);
                    }
                    assert_eq!(message.as_slice(), b"WASI exited with code: ExitCode::0\0");
                } else {
                    assert!(
                        finalized.get(),
                        "valid-owner predecessor cleanup deleted the environment before claim"
                    );
                }
                assert_eq!(unsafe { results.as_slice()[0].of.int64_t }, 7654321);
            } else {
                let asynchronous = outer.async_store().unwrap();
                let function = current.extern_.function();
                let result = if mode == 2 {
                    futures_block_on(function.call_async(&asynchronous, vec![]))
                } else {
                    let erased: Rc<dyn std::any::Any> = Rc::new(17u32);
                    let weak = Rc::downgrade(&erased);
                    if mode == 4 {
                        drop(erased);
                    }
                    futures_block_on(wasmer_api::sys::call_async_with_local_owner(
                        &function,
                        &asynchronous,
                        vec![],
                        weak,
                    ))
                };
                assert!(wasixv2_exec::is_call_handoff(&result.unwrap_err()));
            }
            assert!(
                cleaned.load(Ordering::SeqCst),
                "finite original loader timer must finish"
            );
            assert_eq!(
                calls.get(),
                if mode == 1 {
                    2
                } else if mode == 5 {
                    0
                } else {
                    1
                }
            );
            for (store, instance) in stores.iter().zip(&instances) {
                assert_eq!(
                    store
                        .inner
                        .with_mut(|store| instance
                            .exports
                            .get_global("resumed")
                            .unwrap()
                            .get(store)
                            .i32())
                        .unwrap(),
                    Some(0)
                );
            }
            assert_eq!(
                t.inner
                    .with_mut(|store| instance
                        .exports
                        .get_global("resumed")
                        .unwrap()
                        .get(store)
                        .i32())
                    .unwrap(),
                Some(0)
            );
            assert_eq!(
                outer.with_mut(|store| store.objects_mut().id()).unwrap(),
                identity
            );
            let pure = outer
                .with_mut(|store| Function::new_typed(store, || 19i32))
                .unwrap();
            assert_eq!(outer.call(&pure, vec![]).unwrap()[0].i32(), Some(19));
            let mut bytes = [0; 5];
            if mode < 2 {
                let mut wasi = wasi.borrow_mut().take().unwrap();
                assert_eq!(wasi.read(false, &mut bytes), 5);
                assert_eq!(&bytes, b"child");
                assert_eq!(wasi.read(false, &mut bytes), 0);
                assert!(
                    t.inner
                        .with_mut(|store| wasi.initialize(store, &instance))
                        .unwrap()
                        .is_err(),
                    "committed endpoint cannot reactivate"
                );
                wasi.close();
                assert_eq!(wasi.read(false, &mut bytes), -1);
            } else {
                assert!(
                    wasi.borrow().is_none(),
                    "callback deleted the actual C API environment"
                );
                assert_eq!(
                    capture.read(&mut bytes),
                    0,
                    "canceled admission must not run the replacement image"
                );
            }
            drop(current);
            drop(instances);
            drop(stores);
            drop(wasi);
            drop(instance);
            drop(t);
            drop(directory);
        }
    }

    // An ordinary Rust current-thread Tokio caller supplies no C API dispatcher.
    // T must use its existing retirement executor after this root settles.
    fn futures_block_on<F: Future>(future: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(future)
    }
}

/// Keeps the original loader runner when canceled and transfers it before any
/// destructor callback. A panicked runner transfers its own final-drain keepalive.
struct PredecessorRetirement {
    ancestry: Option<wasmer_api::sys::NativeAncestrySettlement>,
    start: Option<Box<dyn FnOnce() -> LocalFuture<'static, ()>>>,
    running: Option<LocalFuture<'static, ()>>,
    owner: CleanupRetirement,
    on_settled: Option<Box<dyn FnOnce()>>,
    done: bool,
}
impl Future for PredecessorRetirement {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if let Some(ancestry) = &mut this.ancestry {
            if Pin::new(ancestry).poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.ancestry = None;
        }
        if let Some(settled) = this.on_settled.take() {
            settled();
        }
        if this.running.is_none() {
            this.running = Some(this.start.take().expect("one predecessor runner")());
        }
        let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.running.as_mut().unwrap().as_mut().poll(cx)
        }));
        match polled {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(())) => {
                this.done = true;
                this.running = None;
                Poll::Ready(())
            }
            Err(panic) => {
                this.done = true;
                // Never repoll a panicked async guest. Runner::drop retains its
                // real final drain and terminal keepalive in the same local sink.
                drop(this.running.take());
                std::panic::resume_unwind(panic)
            }
        }
    }
}
impl Drop for PredecessorRetirement {
    fn drop(&mut self) {
        if !self.done {
            let replacement = Self {
                ancestry: self.ancestry.take(),
                start: self.start.take(),
                running: self.running.take(),
                owner: self.owner.clone(),
                on_settled: self.on_settled.take(),
                done: false,
            };
            self.owner.retain(Box::pin(replacement));
        }
    }
}
struct TerminalKeepalive {
    owner: CleanupRetirement,
    terminal: Option<LocalFuture<'static, ()>>,
}
impl Drop for TerminalKeepalive {
    fn drop(&mut self) {
        if let Some(terminal) = self.terminal.take() {
            self.owner.retain(terminal);
        }
    }
}
struct CancelHandoff(Option<HostCallHandoff>);
impl Drop for CancelHandoff {
    fn drop(&mut self) {
        if let Some(handoff) = self.0.take() {
            handoff.cancel();
        }
    }
}
enum Admission {
    Worker(Result<OwnedEntryWaiter, ExecError>),
    Detached,
}

impl Endpoint {
    fn enqueue(
        self: Rc<Self>,
        store: &StoreRef,
        error: &RuntimeError,
        admitted: bool,
    ) -> Result<LocalContinuation, RuntimeError> {
        let handoff = store
            .with_mut(|store| self.env.call_handoff(store, error))?
            .ok_or_else(|| {
                RuntimeError::new("WASI handoff no longer belongs to this environment")
            })?;
        let asynchronous = store.async_store()?;
        let owner = store.retirement_owner()?;
        let native_owner = store.cleanup_owner()?;
        let ancestry = wasmer_api::sys::NativeAncestrySettlement::current(Some(&native_owner));
        let local =
            wasixv2_exec::local_cleanup_runner(&asynchronous, self.env.loader_cleanup().clone())
                .ok_or_else(|| RuntimeError::new("native loader retirement runner is missing"))?;
        let (predecessor_tx, predecessor_rx) = tokio::sync::oneshot::channel::<()>();
        let (admission_tx, admission_rx) = tokio::sync::oneshot::channel::<Admission>();
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel::<Result<i32, ExecError>>();
        let deactivated = Rc::new(Cell::new(false));
        let terminal_deactivated = deactivated.clone();
        let completed = Rc::new(Cell::new(false));
        let terminal_completed = completed.clone();
        let terminal_env = self.env.clone();
        let terminal_store = asynchronous.store();
        let terminal_endpoint = self.clone();
        let terminal_handoff = handoff.clone();
        // This future is owned before claim and before the synchronous starter.
        // The original runner releases it only after its actual final drain.
        let terminal = Box::pin(async move {
            {
                // A panic while obtaining the guest's original fence still has
                // this final actual Store fence before the worker barrier opens.
                let mut guard = terminal_store.write_lock().await;
                if !terminal_deactivated.get() {
                    terminal_env.deactivate(&mut guard.as_store_mut());
                    terminal_deactivated.set(true);
                }
            }
            drop(terminal_store);
            drop(terminal_env);
            let _ = predecessor_tx.send(());
            let result = match admission_rx.await {
                Ok(Admission::Worker(Ok(waiter))) => {
                    // Poll fallback authority alongside the waiter: an executor
                    // can accept and then drop its unentered ThreadStart closure.
                    let mut waiter = Box::pin(waiter);
                    let mut retire = Box::pin(terminal_handoff.retire());
                    let mut result = None;
                    let mut retired = false;
                    std::future::poll_fn(|cx| {
                        if !retired {
                            retired = retire.as_mut().poll(cx).is_ready();
                        }
                        if result.is_none() {
                            if let Poll::Ready(value) = waiter.as_mut().poll(cx) {
                                result = Some(value);
                            }
                        }
                        if retired && result.is_some() {
                            Poll::Ready(result.take().unwrap())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                }
                Ok(Admission::Worker(Err(error))) => {
                    terminal_handoff.cancel();
                    Err(error)
                }
                Ok(Admission::Detached) => terminal_handoff.wait_detached().await,
                Err(_) => {
                    terminal_handoff.cancel();
                    Err(ExecError::Dropped)
                }
            };
            terminal_handoff.retire().await;
            // The exact accepted/fallback owner has now finished native and
            // loader cleanup and released the task. Disarm the host guard once.
            let mut process = terminal_endpoint.process.borrow_mut().take();
            if let Some(process) = process.as_mut() {
                process.released();
            }
            *terminal_endpoint.process.borrow_mut() = process;
            terminal_completed.set(true);
            let _ = result_tx.send(result);
        }) as LocalFuture<'static, ()>;
        let keepalive = TerminalKeepalive {
            owner: owner.clone(),
            terminal: Some(terminal),
        };
        let retiring_env = self.env.clone();
        let start = Box::new(move || {
            Box::pin(local.run_with_keepalive(
                async move {
                    let mut guard = asynchronous.write_lock().await;
                    retiring_env.deactivate(&mut guard.as_store_mut());
                    deactivated.set(true);
                },
                keepalive,
            )) as LocalFuture<'static, ()>
        });
        let drive = owner.clone();
        let predecessor = PredecessorRetirement {
            ancestry,
            start: Some(start),
            running: None,
            owner: owner.clone(),
            on_settled: (!admitted).then(|| {
                Box::new(move || drive.drive_after_settlement(completed)) as Box<dyn FnOnce()>
            }),
            done: false,
        };
        self.committed.set(true);
        *self.handoff.borrow_mut() = Some(handoff.clone());
        let mut cancel = CancelHandoff(Some(handoff.clone()));
        // A missing owner admits no worker; publish that disposition before an
        // already-settled ancestry can synchronously pump its cancellation path.
        let mut admission_tx = Some(admission_tx);
        if !admitted {
            let _ = admission_tx
                .take()
                .unwrap()
                .send(Admission::Worker(Err(ExecError::Dropped)));
        }
        // NativeCleanupOwner commits this concrete custody before first polling.
        owner.retain(Box::pin(predecessor));
        let old = self.retire.borrow_mut().take();
        drop(old);
        // Retain can synchronously run old-image cleanup/finalizers. Deletion
        // there irrevocably cancels this endpoint before any replacement claim.
        if self.retired.get() {
            handoff.cancel();
        }
        if admitted {
            handoff.claim()?;
        }
        if self.retired.get() {
            handoff.cancel();
        }
        if admitted {
            let admission = if handoff.is_detached() {
                Admission::Detached
            } else if self.retired.get() {
                drop(predecessor_rx);
                Admission::Worker(Err(ExecError::Dropped))
            } else {
                Admission::Worker(handoff.start(Box::pin(async move {
                    let _ = predecessor_rx.await;
                })))
            };
            let _ = admission_tx.take().unwrap().send(admission);
        } else {
            handoff.cancel();
            drop(predecessor_rx);
        }
        let queue_handoff = cancel.0.take().expect("one cancellation guard");
        let poll_owner = native_owner.clone();
        let run = Box::new(move || {
            Box::pin(async move {
                struct Clear(wasmer_api::sys::NativeCleanupOwner);
                impl Drop for Clear {
                    fn drop(&mut self) {
                        self.0.clear_idle_waker();
                    }
                }
                let _clear = Clear(poll_owner.clone());
                let result = std::future::poll_fn(move |cx| {
                    let _ = poll_owner.poll_idle(cx);
                    Pin::new(&mut result_rx).poll(cx)
                })
                .await;
                let error = match result {
                    Ok(Ok(status)) => exit_trap(status),
                    Ok(Err(error)) => RuntimeError::user(Box::new(error)),
                    Err(_) => RuntimeError::new("WASI completion owner disappeared"),
                };
                Err(crate::wasm_c_api::store::completed_handoff(error))
            }) as Pin<Box<dyn Future<Output = Result<(), RuntimeError>>>>
        });
        Ok(LocalContinuation {
            store: store.clone(),
            run: Some(run),
            cancel: Some(Box::new(move || queue_handoff.cancel())),
        })
    }
}
impl ContinuationEndpoint for Endpoint {
    fn matches(&self, store: &mut StoreMut<'_>, error: &RuntimeError) -> bool {
        self.env.call_handoff(store, error).is_some()
    }
    fn prepare(
        self: Rc<Self>,
        store: &StoreRef,
        error: &RuntimeError,
    ) -> Result<LocalContinuation, RuntimeError> {
        self.enqueue(store, error, true)
    }
    fn cancel_unclaimed(
        self: Rc<Self>,
        store: &StoreRef,
        error: &RuntimeError,
    ) -> Result<(), RuntimeError> {
        // A plain Rust outer root has no explicit C API owner. Capture its exact
        // ancestry but never create a dispatcher or admit a replacement worker.
        let continuation = self.enqueue(store, error, false)?;
        drop(continuation);
        Ok(())
    }
}
