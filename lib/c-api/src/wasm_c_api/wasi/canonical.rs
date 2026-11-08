//! Canonical WASI configuration and instance handles, independent of retirement ownership.

use super::{ConfigurationError, get_wasi_version, wasi_version_t};
use crate::wasm_c_api::store::StoreRef;
use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    io,
    sync::{Arc, Condvar, Mutex},
};
use wasixv2::{
    ByteSink, DirectoryBootstrap, EmbeddingProcess, LocalFuture, Machine, MachineSyscalls,
    NamespaceBootstrap, ProcessConfig, Stdio,
};
use wasixv2_exec::HostEnvironment;
use wasixv2_wasix1::{
    PreopenRights, StartupDescriptors, StartupInput,
    imports::{self, Module as Namespace},
};
use wasmer_api::{Function, Imports, Instance, Module, StoreMut};

type CaptureState = (VecDeque<(Vec<u8>, usize)>, bool);

#[derive(Default)]
pub(super) struct Capture {
    queue: Mutex<CaptureState>,
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
    pub(super) fn read(&self, buffer: &mut [u8]) -> usize {
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

pub(super) struct Bootstrap {
    pub(super) process: EmbeddingProcess,
    pub(super) environment: HostEnvironment<MachineSyscalls>,
    pub(super) input: StartupInput,
    pub(super) descriptors: StartupDescriptors,
    pub(super) stdout: Option<Arc<Capture>>,
    pub(super) stderr: Option<Arc<Capture>>,
}

pub(super) fn bootstrap(
    store: &StoreRef,
    args: Vec<String>,
    env: Vec<(String, Vec<u8>)>,
    preopens: Vec<(String, String)>,
    capture_stdout: bool,
    capture_stderr: bool,
) -> anyhow::Result<Bootstrap> {
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
    Ok(Bootstrap {
        process,
        environment,
        input,
        descriptors,
        stdout,
        stderr,
    })
}

pub(super) fn import_object(
    environment: &HostEnvironment<MachineSyscalls>,
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
    let mut result = imports::namespace(store, environment.environment(), namespace);
    result.extend(&imports::namespace(
        store,
        environment.environment(),
        Namespace::Wasi,
    ));
    Ok(result)
}

pub(super) fn initialize(
    environment: &HostEnvironment<MachineSyscalls>,
    process: &RefCell<Option<EmbeddingProcess>>,
    selected_start: &RefCell<Option<Function>>,
    store: &mut StoreMut<'_>,
    instance: &Instance,
) -> anyhow::Result<()> {
    environment.validate_instance(store, instance)?;
    let (wasi, image_abi) = {
        let process = process.borrow();
        let process = process
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("WASI environment is closed"))?;
        (
            process
                .wasix1()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("WASI environment is closed"))?,
            process
                .wasix1_abi()
                .ok_or_else(|| anyhow::anyhow!("WASI environment is closed"))?,
        )
    };
    let binding = wasi.attach(instance, store);
    let selected = instance.exports.get_function("_start").ok().cloned();
    environment.initialize_with_thread_abi(store, instance, binding, image_abi)?;
    let _ = selected_start.replace(selected);
    Ok(())
}

pub(super) fn validate_preopens(preopens: &[(String, String)]) -> Result<(), ConfigurationError> {
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
