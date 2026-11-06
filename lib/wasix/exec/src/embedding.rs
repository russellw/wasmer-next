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
