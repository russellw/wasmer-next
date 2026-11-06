//! Store-local execution handles for externally owned embedding processes.

use std::sync::Arc;
use wasixv2_host::{Host, LoaderCleanup};
use wasixv2_syscalls::{Control, Syscalls, TaskId};
use wasmer::{AsStoreMut, FunctionEnv, Instance, Memory, StoreMut};

use crate::{AbiInstance, Abis, ExecEnv, ExecError, asyncify, memory, process};

/// Host handles for one externally owned process. This owns no Store or kernel
/// process registration; its caller retains both and settles calls before retirement.
pub struct HostEnvironment<S: 'static> {
    env: FunctionEnv<ExecEnv<S>>,
    store_id: wasmer_types::StoreId,
    initialized: Arc<std::sync::atomic::AtomicBool>,
    cleanup: Arc<LoaderCleanup>,
}

impl<S: 'static> Clone for HostEnvironment<S> {
    fn clone(&self) -> Self {
        Self {
            env: self.env.clone(),
            store_id: self.store_id,
            initialized: self.initialized.clone(),
            cleanup: self.cleanup.clone(),
        }
    }
}

impl<S: Syscalls + Control + Send + Sync + 'static> HostEnvironment<S> {
    pub fn new(
        store: &mut StoreMut<'_>,
        syscalls: Arc<S>,
        task: TaskId,
        host: Arc<dyn Host>,
        abis: Arc<Abis<S>>,
    ) -> Self {
        let cleanup = LoaderCleanup::new(host.clone());
        let env = environment(
            store,
            syscalls,
            task,
            host,
            abis,
            cleanup.clone(),
            Arc::default(),
        );
        Self {
            env,
            store_id: store.objects_mut().id(),
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cleanup,
        }
    }

    pub fn environment(&self) -> &FunctionEnv<ExecEnv<S>> {
        &self.env
    }

    pub fn store_id(&self) -> wasmer_types::StoreId {
        self.store_id
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Retains the bound process registration before this environment is published.
    pub fn retain_exec_process(
        &self,
        store: &mut StoreMut<'_>,
    ) -> Result<(), wasmer::RuntimeError> {
        if store.objects_mut().id() != self.store_id {
            return Err(wasmer::RuntimeError::new(
                "environment belongs to another Store",
            ));
        }
        let data = self.env.as_ref(store);
        let abi = data
            .abi
            .as_ref()
            .ok_or_else(|| wasmer::RuntimeError::new("process custody before ABI binding"))?;
        data.proc
            .handoff
            .retain_process(data.syscalls.tgid(data.task), &**abi)
    }

    /// Nonconsuming identity check; function provenance never changes selected memory.
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub fn call_handoff(
        &self,
        store: &mut StoreMut<'_>,
        error: &wasmer::RuntimeError,
    ) -> Option<HostCallHandoff> {
        if store.objects_mut().id() != self.store_id {
            return None;
        }
        let marker = process::pending_marker(error)?;
        let data = self.env.as_ref(store);
        if !Arc::ptr_eq(marker, &data.proc.handoff) || !marker.is_pending() {
            return None;
        }
        Some(HostCallHandoff {
            handoff: marker.clone(),
            spawner: data.proc.spawner.clone(),
            state: Arc::new(std::sync::Mutex::new(HostCallState::Unclaimed)),
        })
    }

    /// The same loader scope used by this environment and its future images.
    pub fn loader_cleanup(&self) -> &Arc<LoaderCleanup> {
        &self.cleanup
    }

    /// Makes actual imported memory available before engine start without changing
    /// an already explicitly selected instance's WASI handles.
    pub fn prebind_memory(&self, store: &mut StoreMut<'_>, memory: &Memory) {
        if store.objects_mut().id() == self.store_id
            && memory.is_from_store(store)
            && !self.initialized.load(std::sync::atomic::Ordering::Relaxed)
        {
            self.env.as_mut(store).memory = Some(memory.clone());
        }
    }

    /// Selects host handles only. In particular, neither `_initialize` nor any
    /// process/thread entry runs, and the supplied process/mm remain unchanged.
    pub fn initialize(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        abi: Arc<dyn AbiInstance<S>>,
    ) -> Result<(), ExecError> {
        let memory = self.instance_memory(store, instance)?;
        if self.env.as_ref(store).proc.handoff.is_committed() {
            return Err(ExecError::StoreMode(wasmer::RuntimeError::new(
                "WASI image has already committed an exec handoff",
            )));
        }
        let asyncify = asyncify::Asyncify::new(instance, store)?;
        let stack_pointer = crate::stack_pointer(instance);
        let main_stack = memory::main_stack(instance, store);
        let data = self.env.as_mut(store);
        data.memory = Some(memory);
        data.main_stack = main_stack;
        data.stack_pointer = stack_pointer;
        data.abi = Some(abi);
        data.proc.set_module(instance.module());
        data.asyncify = asyncify;
        self.initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Checks identity before an ABI inspects Store-backed instance metadata.
    /// Any same-Store instance with exported memory remains eligible.
    pub fn validate_instance(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
    ) -> Result<(), ExecError> {
        self.instance_memory(store, instance).map(drop)
    }

    fn instance_memory(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
    ) -> Result<Memory, ExecError> {
        if store.objects_mut().id() != self.store_id {
            return Err(ExecError::StoreMode(wasmer::RuntimeError::new(
                "environment belongs to another Store",
            )));
        }
        let memory = instance
            .exports
            .iter()
            .find_map(|(_, export)| match export {
                wasmer::Extern::Memory(memory) => Some(memory.clone()),
                _ => None,
            })
            .ok_or_else(|| wasmer::ExportError::Missing("No exported memory found".into()))?;
        if !memory.is_from_store(store) {
            return Err(ExecError::StoreMode(wasmer::RuntimeError::new(
                "instance belongs to another Store",
            )));
        }
        Ok(memory)
    }

    /// Releases only this environment's Store-local handles after its calls settle.
    pub fn deactivate(&self, store: &mut StoreMut<'_>) {
        let hooks = self.env.as_ref(store).instance_hooks().cloned();
        if let Some(hooks) = hooks {
            hooks.deactivate(store);
        }
        let data = self.env.as_mut(store);
        data.proc.handoff.retire_process();
        data.memory = None;
        data.abi = None;
        data.imports = wasmer::Imports::new();
        data.abi_imports = None;
        data.threads = None;
        data.proc.module = None;
        data.asyncify = None;
        data.base = None;
        data.stack_pointer = None;
    }

    pub fn set_binding(&self, store: &mut StoreMut<'_>, abi: Arc<dyn AbiInstance<S>>) {
        self.env.as_mut(store).abi = Some(abi);
    }
}

/// Shared construction for ordinary runners and external process owners.
#[allow(clippy::too_many_arguments)] // Exact Store, process, host and cleanup inputs.
pub(crate) fn environment<S: Syscalls + Control + Send + Sync + 'static>(
    store: &mut StoreMut<'_>,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cleanup: Arc<LoaderCleanup>,
    handoff: Arc<process::Handoff>,
) -> FunctionEnv<ExecEnv<S>> {
    let spawner = process::spawner(
        store.engine().clone(),
        syscalls.clone(),
        host.clone(),
        abis.clone(),
    );
    let proc = process::ProcExports::new(spawner, handoff);
    let env = FunctionEnv::new(store, ExecEnv::new(syscalls, task, proc, host));
    env.as_mut(store).cleanup = Some(cleanup);
    abis.install_hooks(store, &env);
    env
}

/// An exact one-shot, engine-free committed image handoff. The caller installs
/// retirement custody before claiming or admitting its replacement worker.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[derive(Clone)]
pub struct HostCallHandoff {
    handoff: Arc<process::Handoff>,
    spawner: Arc<dyn process::Spawn>,
    state: Arc<std::sync::Mutex<HostCallState>>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
enum HostCallState {
    Unclaimed,
    Exec(crate::PreinstalledTerminalCustody),
    Detached,
    Retired,
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl HostCallHandoff {
    /// Claim only after an old-thread retirement owner has retained this token.
    pub fn claim(&self) -> Result<(), wasmer::RuntimeError> {
        let outcome = self.handoff.claim()?;
        let next = match outcome {
            process::PendingOutcome::Exec { task, image } => {
                HostCallState::Exec(crate::PreinstalledTerminalCustody::new(task, image))
            }
            process::PendingOutcome::Detached => HostCallState::Detached,
        };
        let old = std::mem::replace(
            &mut *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            next,
        );
        drop(old);
        Ok(())
    }

    pub fn cancel(&self) {
        let terminal = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*state {
                HostCallState::Exec(terminal) => Some(terminal.clone()),
                _ => None,
            }
        };
        if let Some(terminal) = terminal {
            terminal.cancel();
        }
    }

    /// The predecessor resolves only after physical roots, original Store guards,
    /// and the old loader/LocalSet retirement keepalive have actually settled.
    pub fn start(
        &self,
        predecessor: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) -> Result<crate::OwnedEntryWaiter, ExecError> {
        let terminal = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*state {
                HostCallState::Exec(terminal) => Some(terminal.clone()),
                _ => None,
            }
        }
        .ok_or_else(|| {
            ExecError::StoreMode(wasmer::RuntimeError::new("no claimed exec handoff"))
        })?;
        self.spawner
            .start_committed(terminal, predecessor, self.handoff.clone())
    }

    pub fn is_detached(&self) -> bool {
        matches!(
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            HostCallState::Detached
        )
    }

    pub async fn wait_detached(&self) -> Result<i32, ExecError> {
        self.handoff.wait().await
    }

    /// Called by the retained old-thread owner only after its physical/loader
    /// drain. Accepted workers keep terminal authority; all other paths fault
    /// and release exactly once here, including starters that never ran.
    pub async fn retire(&self) {
        let unclaimed = matches!(
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            HostCallState::Unclaimed
        );
        if unclaimed {
            if self.claim().is_err() {
                return;
            }
            self.cancel();
        }
        if unclaimed && self.is_detached() {
            // The existing takeover owns release. Retirement only waits for it.
            let _ = self.handoff.wait().await;
        }
        let terminal = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*state {
                HostCallState::Exec(terminal) => Some(terminal.clone()),
                _ => None,
            }
        };
        if let Some(terminal) = terminal {
            self.spawner
                .retire_committed(terminal, self.handoff.clone())
                .await;
        }
        let old = std::mem::replace(
            &mut *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            HostCallState::Retired,
        );
        drop(old);
    }
}
