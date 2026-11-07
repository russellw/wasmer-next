//! Store-local execution handles for externally owned embedding processes.

use std::sync::Arc;
use wasixv2_host::{Host, LoaderCleanup};
use wasixv2_syscalls::{Control, Syscalls, TaskId};
use wasmer::{AsStoreMut, FunctionEnv, Instance, Memory, StoreMut};

use crate::{Abi, AbiInstance, Abis, ExecEnv, ExecError, asyncify, memory, process, thread};

/// Host handles for one externally owned process. This owns no Store or kernel
/// process registration; its caller retains both and settles calls before retirement.
pub struct HostEnvironment<S: 'static> {
    env: FunctionEnv<ExecEnv<S>>,
    store_id: wasmer_types::StoreId,
    initialized: Arc<std::sync::atomic::AtomicBool>,
    cleanup: Arc<LoaderCleanup>,
    abis: Arc<Abis<S>>,
    // None means never attempted. An expired Some must never retry attachment
    // after rejection/mm exit or take authority from an unrelated first owner.
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    selection: Arc<std::sync::Mutex<Option<std::sync::Weak<memory::ForeignSelection>>>>,
}

impl<S: 'static> Clone for HostEnvironment<S> {
    fn clone(&self) -> Self {
        Self {
            env: self.env.clone(),
            store_id: self.store_id,
            initialized: self.initialized.clone(),
            cleanup: self.cleanup.clone(),
            abis: self.abis.clone(),
            #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
            selection: self.selection.clone(),
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
            abis.clone(),
            cleanup.clone(),
            Arc::default(),
        );
        Self {
            env,
            store_id: store.objects_mut().id(),
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cleanup,
            abis,
            #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
            selection: Arc::default(),
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
            state: Arc::new(std::sync::Mutex::new(HostCallState::Unclaimed {
                canceled: false,
            })),
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
        self.initialize_image(store, instance, abi, None)
    }

    /// Selects an externally instantiated image and its canonical shared-memory
    /// thread factory, without starting or replacing the process. The factory is
    /// explicit so an otherwise accepted module with no ABI imports stays valid.
    pub fn initialize_with_thread_abi(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        binding: Arc<dyn AbiInstance<S>>,
        image_abi: Arc<dyn Abi<S>>,
    ) -> Result<(), ExecError> {
        self.initialize_image(store, instance, binding, Some(image_abi))
    }

    fn initialize_image(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        abi: Arc<dyn AbiInstance<S>>,
        image_abi: Option<Arc<dyn Abi<S>>>,
    ) -> Result<(), ExecError> {
        let memory = self.instance_memory(store, instance)?;
        if self.env.as_ref(store).proc.handoff.is_committed() {
            return Err(ExecError::StoreMode(wasmer::RuntimeError::new(
                "WASI image has already committed an exec handoff",
            )));
        }
        let image_abi = image_abi.map(|abi| abi.for_image(instance.module()).unwrap_or(abi));
        // Stage fallible instance metadata before publishing any selected handles.
        let asyncify = asyncify::Asyncify::new(instance, store)?;
        let stack_pointer = crate::stack_pointer(instance);
        let main_stack = memory::main_stack(instance, store);
        let shared = memory.as_shared(store);
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        let is_shared = shared.is_some();
        let (syscalls, task, host, handoff, low_guard, read_only, base, layout) = {
            let data = self.env.as_ref(store);
            (
                data.syscalls.clone(),
                data.task,
                data.host.clone(),
                data.proc.handoff.clone(),
                data.low_guard,
                data.read_only.clone(),
                data.base.clone(),
                data.layout.clone(),
            )
        };
        let foreign = memory::ForeignMemory::capture(
            &memory,
            store,
            shared.clone(),
            low_guard,
            read_only.clone(),
            syscalls.page_access(task),
            base.clone(),
        );
        let threads = shared.zip(image_abi).map(|(shared, image_abi)| {
            thread::Image::new(
                store.engine().clone(),
                instance.module(),
                shared,
                (low_guard, read_only, base),
                main_stack.clone(),
                layout,
                syscalls.clone(),
                host,
                image_abi,
                self.abis.clone(),
                handoff,
            ) as Arc<dyn thread::Start>
        });
        let old = {
            let data = self.env.as_mut(store);
            data.main_stack = main_stack;
            data.stack_pointer = stack_pointer;
            data.proc.set_module(instance.module());
            (
                data.memory.replace(memory),
                data.abi.replace(abi),
                std::mem::replace(&mut data.threads, threads),
                std::mem::replace(&mut data.asyncify, asyncify),
            )
        };
        // All fallible staging is complete and the selected local tuple is
        // installed before publishing remote visibility. No guest entry/await
        // occurs between these commits, under the caller's exclusive Store.
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        let retired = foreign.and_then(|foreign| {
            let attempt = {
                self.selection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            };
            match attempt {
                None => {
                    let selector = Arc::new(memory::ForeignSelection::new(Arc::new(foreign)));
                    let previous = self
                        .selection
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .replace(Arc::downgrade(&selector));
                    // Keep this strong candidate through the attachment call.
                    // The kernel owns acceptance; rejection leaves only Weak.
                    syscalls.attach_memory(task, selector.clone());
                    drop(previous);
                    drop(selector);
                    None
                }
                Some(weak) => {
                    let selector = weak.upgrade();
                    drop(weak);
                    match selector {
                        Some(selector) if is_shared => Some(selector.publish(Arc::new(foreign))),
                        _ => None, // Private selection/stale capability never republishes.
                    }
                }
            }
        });
        #[cfg(not(all(feature = "sys", not(target_arch = "wasm32"))))]
        if let Some(foreign) = foreign {
            syscalls.attach_memory(task, Arc::new(foreign));
        }
        self.initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        drop(old);
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        drop(retired);
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
    Unclaimed { canceled: bool },
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
        let (old, canceled) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let canceled = matches!(*state, HostCallState::Unclaimed { canceled: true });
            (std::mem::replace(&mut *state, next), canceled)
        };
        drop(old);
        if canceled {
            self.cancel();
        }
        Ok(())
    }

    pub fn cancel(&self) {
        let terminal = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &mut *state {
                HostCallState::Unclaimed { canceled } => {
                    *canceled = true;
                    None
                }
                HostCallState::Exec(terminal) => Some(terminal.clone()),
                _ => None,
            }
        };
        if let Some(terminal) = terminal {
            terminal.cancel();
        }
        self.handoff.cancel_takeover();
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
            HostCallState::Unclaimed { .. }
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

#[cfg(all(test, feature = "sys", not(target_arch = "wasm32")))]
mod selection_tests {
    use super::*;
    use crate::process::tests::{NoThreads, Recorder};

    #[test]
    fn rejected_host_selection_never_recreates_an_expired_attachment() {
        let mut store = wasmer::Store::default();
        let syscalls = Arc::new(Recorder::default());
        // Recorder's default attach_memory rejects/drops every provider, just
        // like an already-attached mm refusing an unrelated first provider.
        let environment = HostEnvironment::new(
            &mut store.as_store_mut(),
            syscalls,
            TaskId(2),
            Arc::new(NoThreads),
            Arc::new(Abis::wasixv2()),
        );
        let make = |store: &mut wasmer::Store, pages| {
            let source = format!(
                "(module (memory (export \"memory\") {pages} 3 shared) (func (export \"_start\")))"
            );
            let module = wasmer::Module::new(store, source.as_bytes()).unwrap();
            Instance::new(store, &module, &wasmer::Imports::new()).unwrap()
        };
        let first = make(&mut store, 1);
        let second = make(&mut store, 2);
        let select = |environment: &HostEnvironment<Recorder>,
                      store: &mut wasmer::Store,
                      instance: &Instance| {
            let binding = crate::Wasixv2
                .bind(
                    instance,
                    &mut store.as_store_mut(),
                    TaskId(2),
                    crate::Role::Process,
                )
                .unwrap();
            environment
                .initialize(&mut store.as_store_mut(), instance, binding)
                .unwrap();
        };
        select(&environment, &mut store, &first);
        let original = environment.selection.lock().unwrap().clone().unwrap();
        assert!(
            original.upgrade().is_none(),
            "rejection expires the only strong candidate"
        );
        let clone = environment.clone();
        assert!(Arc::ptr_eq(&clone.selection, &environment.selection));
        select(&clone, &mut store, &second);
        let current = environment.selection.lock().unwrap().clone().unwrap();
        assert!(
            std::sync::Weak::ptr_eq(&original, &current),
            "expired means attempted, never a fresh attachment"
        );
        assert!(current.upgrade().is_none());
        assert_eq!(
            environment.env.as_ref(&store).memory.as_ref().unwrap(),
            second.exports.get_memory("memory").unwrap(),
            "local selection still changes normally"
        );
        environment.deactivate(&mut store.as_store_mut());
        let current = environment.selection.lock().unwrap().clone().unwrap();
        assert!(
            std::sync::Weak::ptr_eq(&original, &current),
            "deactivation cannot reset attachment admission"
        );
    }
}
