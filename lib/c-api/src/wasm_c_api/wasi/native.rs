//! Native WASI facade. Configuration and process ownership remain outside the Store.

use crate::wasm_c_api::store::StoreRef;
use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::{Arc, Condvar, Mutex},
};
use wasixv2::{
    ByteSink, EmbeddingProcess, LocalFuture, Machine, MachineSyscalls, ProcessConfig, Stdio,
};
use wasixv2_exec::HostEnvironment;
use wasixv2_wasix1::{
    StartupInput,
    imports::{self, Module as Namespace},
};
use wasmer_api::{AsStoreAsync, AsStoreMut, Imports, Instance, Module, StoreAsync, StoreMut};
use wasmer_wasix::{WasiError, WasiStateCreationError, WasiVersion, get_wasi_version};

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
    process: Option<EmbeddingProcess>,
    env: HostEnvironment<MachineSyscalls>,
    store: StoreAsync,
    owner: wasmer_api::sys::NativeCleanupOwner,
    stdout: Option<Arc<Capture>>,
    stderr: Option<Arc<Capture>>,
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
                return Err(
                    WasiStateCreationError::EnvironmentVariableFormatError(format!(
                        "found equal sign in env var key \"{key}\" (key=value)"
                    ))
                    .into(),
                );
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
        let (process, environment) = store.run_host(async {
            let machine = Arc::new(Machine::new());
            let mut input_preopens = Vec::new();
            for (index, (name, host)) in preopens.into_iter().enumerate() {
                // Announced aliases are opaque legacy names, not normalized mount
                // paths. Separate capabilities must never stack on the same mount.
                let path = format!("/.wasmer-c-api/preopens/{index}");
                machine
                    .mount_host_dir(&path, std::path::Path::new(&host), false)
                    .await?;
                input_preopens.push((path.into_bytes(), name.into_bytes()));
            }
            let process = machine
                .start_embedding(ProcessConfig {
                    args,
                    env: kernel_env,
                    stdio,
                })
                .await?;
            let wasi = process
                .wasix1()
                .ok_or_else(|| anyhow::anyhow!("process owner is closed"))?;
            wasi.set_startup_input(StartupInput {
                args: startup_args,
                env: startup_env,
                preopens: input_preopens,
            })
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
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
            Ok::<_, anyhow::Error>((process, environment))
        })??;
        let asynchronous = store.async_store()?;
        let owner = wasmer_api::sys::native_cleanup_owner(&asynchronous)
            .ok_or_else(|| anyhow::anyhow!("native cleanup owner is missing"))?;
        Ok(Self {
            process: Some(process),
            env: environment,
            store: asynchronous,
            owner,
            stdout,
            stderr,
        })
    }

    pub(super) fn import_object(
        &self,
        store: &mut StoreMut<'_>,
        module: &Module,
    ) -> anyhow::Result<Imports> {
        let version = get_wasi_version(module, false).ok_or(WasiError::UnknownWasiVersion)?;
        let namespace = match version {
            WasiVersion::Snapshot0 => Namespace::Unstable,
            WasiVersion::Snapshot1 | WasiVersion::Latest => Namespace::Preview1,
            WasiVersion::Wasix32v1 => Namespace::Wasix32,
            WasiVersion::Wasix64v1 => anyhow::bail!(
                "{}",
                wasixv2_wasix1::V1Flavor::Wasm64
                    .unsupported_reason()
                    .unwrap()
            ),
        };
        let mut result = imports::namespace(store, self.env.environment(), namespace);
        result.extend(&imports::namespace(
            store,
            self.env.environment(),
            Namespace::Wasi,
        ));
        Ok(result)
    }

    pub(super) fn environment(&self) -> &HostEnvironment<MachineSyscalls> {
        &self.env
    }

    pub(super) fn initialize(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
    ) -> anyhow::Result<()> {
        self.env.validate_instance(store, instance)?;
        let wasi = self
            .process
            .as_ref()
            .and_then(EmbeddingProcess::wasix1)
            .ok_or_else(|| anyhow::anyhow!("WASI environment is closed"))?;
        let binding = wasi.attach(instance, store);
        self.env.initialize(store, instance, binding)?;
        Ok(())
    }

    pub(super) fn read(&self, stderr: bool, buffer: &mut [u8]) -> isize {
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
        let Some(mut process) = self.process.take() else {
            return;
        };
        process.close();
        let store = self.store.store();
        let env = self.env.clone();
        self.owner.retain(Box::pin(async move {
            let mut guard = store.write_lock().await;
            env.deactivate(&mut guard.as_store_mut());
        }));
    }
}
impl Drop for NativeWasi {
    fn drop(&mut self) {
        self.close();
    }
}

fn validate_preopens(preopens: &[(String, String)]) -> Result<(), WasiStateCreationError> {
    let mut aliases = HashSet::new();
    for (name, _) in preopens {
        if !aliases.insert(name) {
            return Err(WasiStateCreationError::WasiFsCreationError(format!(
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
            error.downcast_ref::<WasiStateCreationError>(),
            Some(WasiStateCreationError::WasiFsCreationError(message))
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
}
