//! The per-instance half of the v1 ABI: entry points, signal delivery and vfork resumption as
//! wasix-libc expects them.

use std::{
    any::Any,
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use wasixv2_exec::{
    AbiInstance, Entry, EntryReturn, ExecEnv, GuestMemory, Outcome, Role, Sigreturn, VforkResume,
    asyncify::StackId, call_guest, caller_parts, complete,
};
use wasixv2_syscalls::{Caller, Control, LocalFuture, SignalFrame, Syscalls, TaskId};
use wasmer::{AsyncFunctionEnvMut, Exports, Function, Instance, RuntimeError, Value};
use wasmer_types::TrapCode;

use crate::process::{Commands, HostOwner, ProcState, Procs};

#[derive(Debug)]
pub enum StartupPreparationError {
    Configuration(wasixv2_abi::Errno),
    Guest(crate::abi::Errno),
    Engine(RuntimeError),
}
impl std::fmt::Display for StartupPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "invalid startup configuration: {error:?}"),
            Self::Guest(error) => write!(f, "startup preparation failed: {error:?}"),
            Self::Engine(error) => std::fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for StartupPreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            _ => None,
        }
    }
}

/// `_initialize`, which reactors and some commands export; it runs before `_start`.
const INITIALIZE: &str = "_initialize";
const START: &str = "_start";
/// The thread entry, as `wasi_thread_start(tid, start_arg)`.
pub const THREAD_ENTRY: &str = "wasi_thread_start";
/// The signal callback libc registers with `callback_signal`.
pub const SIGNAL_CALLBACK: &str = "__wasm_signal";

pub struct Wasix1Instance {
    pub(crate) http: Arc<crate::http::State>,
    pub(crate) limits: crate::Limits,
    pub(crate) realloc: Option<Function>,
    procs: Arc<Procs>,
    /// The package commands v1 programs start with their defaults.
    commands: Arc<RwLock<Commands>>,
    /// For a process image: its pid and the compat state it started with (or took over from
    /// its parent, for a fork child).
    image: Mutex<Option<(TaskId, Arc<ProcState>)>>,
    host_owner: Option<Weak<HostOwner>>,
    exports: Exports,
    initialize: Option<Function>,
    /// `_start` of a process image, `wasi_thread_start` of a thread.
    entry: Option<Function>,
    table_cacheable: bool,
    /// The export `callback_signal` last named that exists: `__wasm_signal` unless libc
    /// named another.
    signal: Mutex<Option<Function>>,
    /// Only the instance that called callback_signal owns guest signal delivery.
    pub(crate) signal_registered: AtomicBool,
    /// Whether this instance's thread holds signals back: `callback_signal` named an export the
    /// module does not have (see `calls::signal`).
    blocked: AtomicBool,
    /// Whether this instance's process loaded its startup state.
    started: AtomicBool,
    /// The vfork children running in this instance, by tid.
    vforks: Mutex<HashMap<TaskId, Vfork>>,
    /// The process of the task that asked last, by the kernel's ids, as `task << 32 | process`
    /// ([`NO_PROCESS`] before any), so a shim needs no call into the kernel to find its
    /// process's compat state. A task's process stays while it runs here: the instance's own
    /// task belongs to its process for life, a vfork child that runs here is a process of its
    /// own, and a new image (`execve`) or a fork child gets an instance of its own.
    process: AtomicU64,
}

/// Compat state owned by one embedding environment, shared by its attachments.
/// Dropping an attachment never retires this process or replaces its startup data.
#[derive(Clone)]
pub struct HostProcessState(Arc<HostProcess>);

struct HostProcess {
    procs: Arc<Procs>,
    commands: Arc<RwLock<Commands>>,
    http: Arc<crate::http::State>,
    limits: crate::Limits,
    task: TaskId,
    owner: Arc<HostOwner>,
}

impl HostProcessState {
    pub(crate) fn new(
        procs: Arc<Procs>,
        commands: Arc<RwLock<Commands>>,
        http: Option<Arc<dyn crate::http::HttpProvider>>,
        limits: crate::Limits,
        task: TaskId,
    ) -> Self {
        let owner = procs.host_owner(task);
        Self(Arc::new(HostProcess {
            procs,
            commands,
            http: Arc::new(crate::http::State::new(http)),
            limits,
            task,
            owner,
        }))
    }

    /// Configures the environment's exact byte buffers and explicit preopens once.
    pub fn set_startup_input(&self, input: crate::StartupInput) -> Result<(), wasixv2_abi::Errno> {
        self.current_state()?.set_startup_input(input)
    }

    /// Configures the same startup input with indexed WASI preopen rights.
    pub fn set_startup_input_with_preopen_rights(
        &self,
        input: crate::StartupInput,
        rights: Vec<crate::PreopenRights>,
    ) -> Result<(), wasixv2_abi::Errno> {
        self.current_state()?
            .set_startup_input_with_preopen_rights(input, rights)
    }

    fn current_state(&self) -> Result<Arc<ProcState>, wasixv2_abi::Errno> {
        self.0
            .procs
            .owned_state(self.0.task, &self.0.owner)
            .ok_or(wasixv2_abi::Errno::ESRCH)
    }

    /// Atomically configures and prepares an unpublished host environment.
    ///
    /// Retain its process and existing Store/loader cleanup owners until this
    /// returns. After admission, error or cancellation consumes the one attempt:
    /// retire that unpublished environment rather than retrying or exposing it.
    pub async fn configure_and_prepare_startup<S>(
        &self,
        store: &wasmer::StoreAsync,
        environment: &wasixv2_exec::HostEnvironment<S>,
        input: crate::StartupInput,
        descriptors: crate::StartupDescriptors,
    ) -> Result<(), crate::StartupPreparationError>
    where
        S: wasixv2_syscalls::Syscalls + wasixv2_syscalls::Control + Send + Sync + 'static,
    {
        use crate::StartupPreparationError as Error;
        use wasmer::{AsStoreAsync, AsStoreMut, Function};
        if store.store_id() != environment.store_id() || environment.is_initialized() {
            return Err(Error::Configuration(wasixv2_abi::Errno::EINVAL));
        }
        let state = self.current_state().map_err(Error::Configuration)?;
        struct Admission {
            state: Arc<ProcState>,
            admitted: bool,
        }
        impl Drop for Admission {
            fn drop(&mut self) {
                if self.admitted {
                    self.state.finish_preparation();
                }
            }
        }
        let mut admission = Admission {
            state: state.clone(),
            admitted: false,
        };
        let function = {
            let mut guard = store.write_lock().await;
            let data = environment.environment().as_ref(&guard);
            let matching = data.task() == self.0.task
                && data.memory().is_none()
                && data
                    .abi()
                    .and_then(|abi| abi.as_any().downcast_ref::<Wasix1Instance>())
                    .is_some_and(|abi| Arc::ptr_eq(&abi.procs, &self.0.procs));
            if !matching {
                return Err(Error::Configuration(wasixv2_abi::Errno::EINVAL));
            }
            state
                .set_startup_input_with_descriptors(input, descriptors)
                .map_err(Error::Configuration)?;
            admission.admitted = true;
            environment
                .retain_exec_process(&mut guard.as_store_mut())
                .map_err(Error::Engine)?;
            Function::new_typed_with_env_async(
                &mut guard.as_store_mut(),
                environment.environment(),
                |env: crate::shim::Env<S>| async move {
                    Ok::<i32, RuntimeError>(
                        match crate::shim::call(&env, async |frame| {
                            crate::calls::startup::prepare_stdio(frame).await?;
                            crate::calls::startup::prepare_preopen_names(frame).await?;
                            frame.startup().await?;
                            Ok(())
                        })
                        .await?
                        {
                            crate::shim::Done::Ok(()) => 0,
                            crate::shim::Done::Err(error) => i32::from(error.0),
                            _ => {
                                return Err(RuntimeError::new("startup preparation changed tasks"));
                            }
                        },
                    )
                },
            )
        };
        let _admission = admission;
        let result = function
            .call_async(store, vec![])
            .await
            .map_err(Error::Engine)?;
        match result.as_ref() {
            [Value::I32(0)] => Ok(()),
            [Value::I32(errno)] => Err(Error::Guest(crate::abi::Errno(*errno as u16))),
            _ => Err(Error::Engine(RuntimeError::new(
                "invalid startup preparation result",
            ))),
        }
    }

    /// The process's import binding before the engine has produced an instance.
    pub fn unattached<S: Syscalls + Control + Send + Sync + 'static>(
        &self,
    ) -> Arc<dyn AbiInstance<S>> {
        let mut binding = Wasix1Instance::from_exports(
            self.0.procs.clone(),
            self.0.commands.clone(),
            self.0.http.clone(),
            self.0.limits,
            Exports::new(),
            false,
        );
        binding.host_owner = Some(Arc::downgrade(&self.0.owner));
        Arc::new(binding)
    }

    /// Captures an actual instance's handles without requiring or running `_start`.
    /// The environment explicitly selects the returned binding; calling a function
    /// from an older instance does not select that instance again.
    pub fn attach<S: Syscalls + Control + Send + Sync + 'static>(
        &self,
        instance: &Instance,
        store: &mut wasmer::StoreMut<'_>,
    ) -> Arc<dyn AbiInstance<S>> {
        let mut binding = Wasix1Instance::attach(
            self.0.procs.clone(),
            self.0.commands.clone(),
            self.0.http.clone(),
            self.0.limits,
            instance,
            store,
        );
        binding.host_owner = Some(Arc::downgrade(&self.0.owner));
        Arc::new(binding)
    }
}

/// [`Wasix1Instance::process`] before any task asked: no task id is `u32::MAX`.
const NO_PROCESS: u64 = u64::MAX;

/// A vfork child that runs in its parent's instance.
pub(crate) struct Vfork {
    /// The compat state the child started with, a copy of its parent's.
    pub(crate) state: Arc<ProcState>,
    /// For `proc_fork` without a memory copy (asyncify builds): the parent's stack, saved at
    /// the vfork point, which the parent resumes on. `None` for `proc_fork_env` and
    /// `proc_spawn`, whose parent resumes by returning from the child's last import.
    pub(crate) resume: Option<StackId>,
    pub(crate) lease: Option<Box<dyn wasixv2_exec::ExecProcessLease>>,
}

impl Wasix1Instance {
    #[allow(clippy::too_many_arguments)] // image inputs, compat policy and exact store context
    pub(crate) fn bind(
        procs: Arc<Procs>,
        commands: Arc<RwLock<Commands>>,
        http: Option<Arc<dyn crate::http::HttpProvider>>,
        limits: crate::Limits,
        instance: &Instance,
        store: &mut wasmer::StoreMut<'_>,
        task: TaskId,
        role: Role,
    ) -> Result<Self, wasmer::ExportError> {
        let exports = &instance.exports;
        let function = |name: &str| exports.get_function(name).ok().cloned();
        let (entry, image) = match role {
            Role::Process => {
                let entry = exports.get_function(START)?.clone();
                let state = procs.next_image(task);
                (entry, Some((task, state)))
            }
            Role::Thread => (exports.get_function(THREAD_ENTRY)?.clone(), None),
        };
        let mut attached = Self::attach(
            procs,
            commands,
            Arc::new(crate::http::State::new(http)),
            limits,
            instance,
            store,
        );
        attached.initialize = function(INITIALIZE).filter(|_| role == Role::Process);
        attached.entry = Some(entry);
        *attached.image.get_mut().unwrap() = image;
        Ok(attached)
    }

    /// Captures host handles without starting or replacing a process image.
    pub(crate) fn attach(
        procs: Arc<Procs>,
        commands: Arc<RwLock<Commands>>,
        http: Arc<crate::http::State>,
        limits: crate::Limits,
        instance: &Instance,
        store: &mut wasmer::StoreMut<'_>,
    ) -> Self {
        let exports = &instance.exports;
        Self::from_exports(
            procs,
            commands,
            http,
            limits,
            exports.clone(),
            wasixv2_exec::TableMetadata::bind(instance, store).cacheable(),
        )
    }

    fn from_exports(
        procs: Arc<Procs>,
        commands: Arc<RwLock<Commands>>,
        http: Arc<crate::http::State>,
        limits: crate::Limits,
        exports: Exports,
        table_cacheable: bool,
    ) -> Self {
        let function = |name: &str| exports.get_function(name).ok().cloned();
        Self {
            http,
            limits,
            realloc: function("canonical_abi_realloc"),
            procs,
            commands,
            image: Mutex::new(None),
            host_owner: None,
            initialize: None,
            entry: None,
            table_cacheable,
            signal: Mutex::new(function(SIGNAL_CALLBACK)),
            signal_registered: AtomicBool::new(false),
            exports,
            blocked: AtomicBool::new(false),
            started: AtomicBool::new(false),
            vforks: Mutex::new(HashMap::new()),
            process: AtomicU64::new(NO_PROCESS),
        }
    }

    /// The process of `task` if it is the task that asked last.
    pub(crate) fn cached_process(&self, task: TaskId) -> Option<TaskId> {
        let packed = self.process.load(Ordering::Relaxed);
        let hit = packed != NO_PROCESS && (packed >> 32) as u32 == task.0;
        hit.then_some(TaskId(packed as u32))
    }

    /// Remembers that `task`'s process is `process`.
    pub(crate) fn cache_process(&self, task: TaskId, process: TaskId) {
        self.process.store(
            u64::from(task.0) << 32 | u64::from(process.0),
            Ordering::Relaxed,
        );
    }

    /// Host attachment accepts reactors and incomplete modules. A spawn must
    /// check the selected instance's actual entry before creating a kernel task.
    pub(crate) fn thread_entry_available(&self, store: &impl wasmer::AsStoreRef) -> bool {
        self.exports
            .get_typed_function::<(i32, i32), ()>(store, THREAD_ENTRY)
            .is_ok()
    }

    pub(crate) fn procs(&self) -> &Arc<Procs> {
        &self.procs
    }

    pub(crate) fn commands(&self) -> &RwLock<Commands> {
        &self.commands
    }

    pub(crate) fn started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    pub(crate) fn set_started(&self) {
        self.started.store(true, Ordering::Relaxed);
    }

    /// Makes `name` the signal callback if the instance exports a function by that name, and
    /// says whether it does; signals are held back while it does not.
    pub(crate) fn select_signal_callback(&self, name: &str) -> bool {
        self.signal_registered.store(true, Ordering::Relaxed);
        let found = match self.exports.get_function(name) {
            Ok(function) => {
                *self.signal.lock().unwrap() = Some(function.clone());
                true
            }
            Err(_) => false,
        };
        self.blocked.store(!found, Ordering::Relaxed);
        found
    }

    /// Whether the instance has a callback to run signal handlers through.
    pub(crate) fn has_signal_callback(&self) -> bool {
        self.signal.lock().unwrap().is_some()
    }

    /// Whether the instance's thread holds signals back.
    pub(crate) fn blocked(&self) -> bool {
        self.blocked.load(Ordering::Relaxed)
    }

    /// Makes `state`, a copy of the forking parent's, the compat state of this process image,
    /// a fork child, the process `pid`.
    pub(crate) fn adopt(&self, pid: TaskId, state: Arc<ProcState>) {
        let state = self.procs.adopt(pid, &state);
        let old = self.image.lock().unwrap().replace((pid, state));
        if let Some((pid, old)) = old {
            self.procs.remove(pid, &old);
        }
        self.set_started();
    }

    /// An abandoned host-only spawn never resumes a guest vfork continuation.
    pub(crate) fn discard_spawn(&self, child: TaskId) {
        if let Some(vfork) = self.vforks.lock().unwrap().remove(&child) {
            self.procs.remove(child, &vfork.state);
        }
    }
    /// Records the vfork child `child`, which now runs in this instance.
    pub(crate) fn add_vfork(&self, child: TaskId, vfork: Vfork) {
        self.vforks.lock().unwrap().insert(child, vfork);
    }

    /// Whether `task` is a vfork child running in this instance.
    pub(crate) fn is_vfork_child(&self, task: TaskId) -> bool {
        self.vforks.lock().unwrap().contains_key(&task)
    }
}

impl Drop for Wasix1Instance {
    fn drop(&mut self) {
        if let Some((pid, state)) = self.image.get_mut().unwrap().take() {
            self.procs.remove(pid, &state);
        }
        // A vfork parent whose image ended instead of resuming leaves its child's vfork here.
        for (child, vfork) in self.vforks.get_mut().unwrap().drain() {
            self.procs.remove(child, &vfork.state);
        }
    }
}

impl<S: Syscalls + Control + Send + Sync + 'static> AbiInstance<S> for Wasix1Instance {
    fn retain_exec_process(
        &self,
        process: TaskId,
    ) -> Result<Option<Box<dyn wasixv2_exec::ExecProcessLease>>, RuntimeError> {
        if let Some(child) = self.vforks.lock().unwrap().get_mut(&process) {
            return child.lease.take().map(Some).ok_or_else(|| {
                RuntimeError::new("vfork child execution custody already transferred")
            });
        }
        let image = self.image.lock().unwrap().clone();
        if let Some((leader, state)) = image {
            if leader != process {
                return Err(RuntimeError::new(
                    "process custody requires the image's leader",
                ));
            }
            return self.procs.retain_process(process, &state).map(Some);
        }
        let owner = self
            .host_owner
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                RuntimeError::new("no exact process registration is held by this instance")
            })?;
        let state = self
            .procs
            .owned_state(process, &owner)
            .ok_or_else(|| RuntimeError::new("host process registration was retired"))?;
        self.procs.retain_process(process, &state).map(Some)
    }

    fn function_table(&self) -> Option<&wasmer::Table> {
        self.exports
            .get_table("__wasix_exec_table")
            .or_else(|_| self.exports.get_table("__indirect_function_table"))
            .or_else(|_| self.exports.get_table("__wasix_dylink_table_0"))
            .ok()
    }

    fn function_cacheable(&self, _: u32) -> bool {
        // Filled from source metadata during ABI binding, never inferred from a slot index.
        self.table_cacheable
    }
    /// `_initialize` cannot fork: a fork child resumes in `_start`.
    fn start<'a>(&'a self, entry: &'a Entry<'a, S>) -> LocalFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let function = self
                .entry
                .as_ref()
                .ok_or_else(|| RuntimeError::new("host attachment has no process entry"))?;
            if let Some(initialize) = &self.initialize {
                entry.call_once(initialize, &[]).await?;
            }
            entry.call(START, function, &[]).await.map(drop)
        })
    }

    /// WASI: returning from `_start` is `exit(0)`.
    fn on_entry_return(&self) -> EntryReturn {
        EntryReturn::Exit(0)
    }

    fn start_thread<'a>(
        &'a self,
        entry: &'a Entry<'a, S>,
        tid: i32,
        start_arg: u32,
    ) -> LocalFuture<'a, Result<(), RuntimeError>> {
        let args = [Value::I32(tid), Value::I32(start_arg as i32)];
        Box::pin(async move {
            let function = self
                .entry
                .as_ref()
                .ok_or_else(|| RuntimeError::new("host attachment has no thread entry"))?;
            entry.call(THREAD_ENTRY, function, &args).await.map(drop)
        })
    }

    /// A v1 thread that returns from its entry exited cleanly.
    fn on_thread_return(&self) -> EntryReturn {
        EntryReturn::Exit(0)
    }

    /// libc keeps the dispositions and runs the handler from its callback, `__wasm_signal(sig)`;
    /// the host only decides that it runs. The mask in force before delivery is restored
    /// afterwards. v1's handler has no frame to cancel a restart through, so `restart` stands.
    fn deliver_signal<'a>(
        &'a self,
        env: &'a AsyncFunctionEnvMut<ExecEnv<S>>,
        frame: &'a SignalFrame,
        restart: bool,
    ) -> LocalFuture<'a, Result<Sigreturn, RuntimeError>> {
        Box::pin(async move {
            // A directed signal can reach an unregistered pthread. Its
            // exported __wasm_signal alone does not register a callback.
            if !self.signal_registered.load(Ordering::Relaxed) {
                return Ok(Sigreturn {
                    mask: Some(frame.mask),
                    restart,
                });
            }
            let Some(callback) = self.signal.lock().unwrap().clone() else {
                return Err(RuntimeError::new(format!(
                    "a signal handler must run, but the guest has no `{SIGNAL_CALLBACK}`"
                )));
            };
            if let Err(error) = call_guest(env, &callback, &[Value::I32(frame.signo())]).await {
                // Keep the legacy status for guest traps. Host interrupts use the runner's
                // signal status.
                if matches!(error.clone().to_trap(), Some(code) if code != TrapCode::HostInterrupt)
                {
                    let (syscalls, task) = caller_parts(env).await;
                    let memory = GuestMemory::new(env);
                    let caller = Caller::new(task, &memory);
                    let status = i32::from(crate::abi::Errno::INTR.0);
                    if syscalls.exit_group(&caller, status).await.is_ok()
                        && let Outcome::Unwind(exit) = complete(env, &*syscalls, task, Ok(())).await
                    {
                        return Err(exit);
                    }
                }
                return Err(error);
            }
            Ok(Sigreturn {
                mask: Some(frame.mask),
                restart,
            })
        })
    }

    /// A parent that vforked with `proc_fork_env` or `proc_spawn` resumes by returning from the
    /// child's `proc_exec*` or `proc_exit2` (libc then calls `__vfork_restore` itself); one that
    /// vforked with `proc_fork` rewinds the stack saved at its vfork point, so `proc_fork`
    /// returns the child's pid.
    fn vfork_resume<'a>(
        &'a self,
        env: &'a AsyncFunctionEnvMut<ExecEnv<S>>,
        child: TaskId,
        pid: i32,
    ) -> LocalFuture<'a, VforkResume> {
        Box::pin(async move {
            let Some(vfork) = self.vforks.lock().unwrap().remove(&child) else {
                return VforkResume::ReturnSuccess;
            };
            // A new image of the child has a state of its own by now, which stays.
            self.procs.remove(child, &vfork.state);
            match vfork.resume {
                None => VforkResume::ReturnSuccess,
                Some(id) => {
                    VforkResume::Unwind(wasixv2_exec::asyncify::import::restore(env, id, pid).await)
                }
            }
        })
    }

    /// Below the scratch window, which the shims hand the kernel for translated values.
    fn memory_limit(&self) -> u64 {
        u64::from(crate::memory::SCRATCH_BASE)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use wasmer::{AsStoreMut, Imports, Module, Store};

    #[test]
    fn missing_start_does_not_consume_the_predecessors_process_registration() {
        let mut store = Store::default();
        let module = Module::new(
            &store,
            wat::parse_str("(module (memory (export \"memory\") 1))").unwrap(),
        )
        .unwrap();
        let instance = Instance::new(&mut store, &module, &Imports::new()).unwrap();
        let wasi = crate::Wasix1::new();
        let task = TaskId(17);
        let old = wasi.procs.get_or_create(task);
        let lease = wasi.procs.retain_process(task, &old).unwrap();
        wasi.procs.remove(task, &old);
        assert!(
            Wasix1Instance::bind(
                wasi.procs.clone(),
                Arc::default(),
                None,
                crate::Limits::default(),
                &instance,
                &mut store.as_store_mut(),
                task,
                Role::Process
            )
            .is_err()
        );
        assert!(Arc::ptr_eq(&wasi.procs.get_or_create(task), &old));
        drop(lease);
        assert!(!Arc::ptr_eq(&wasi.procs.get_or_create(task), &old));
    }

    #[test]
    fn host_owner_follows_only_its_exec_lineage_and_old_image_cleanup_cannot_remove_it() {
        let wasi = crate::Wasix1::new();
        let task = TaskId(11);
        let owner = wasi.host_process(task);
        let last_owner = owner.clone();
        let old = owner.current_state().unwrap();
        old.set_startup_input(crate::StartupInput::default())
            .unwrap();
        old.seal_startup_input();
        let old_weak = Arc::downgrade(&old);
        let current = wasi.procs.next_image(task);
        wasi.procs.remove(task, &old);
        assert!(Arc::ptr_eq(&owner.current_state().unwrap(), &current));
        drop(old);
        assert!(
            old_weak.upgrade().is_none(),
            "host owner must not pin an obsolete image"
        );
        assert_eq!(
            owner.set_startup_input(crate::StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
        let child = TaskId(12);
        let fork = Arc::new(current.fork());
        wasi.procs.replace(child, fork.clone());
        drop(owner);
        assert!(Arc::ptr_eq(&last_owner.current_state().unwrap(), &current));
        drop(last_owner);
        assert!(!Arc::ptr_eq(&wasi.procs.get_or_create(task), &current));
        assert!(Arc::ptr_eq(&wasi.procs.get_or_create(child), &fork));
        // A recycled task key with a new lineage cannot be removed by the old owner.
        let owner = wasi.host_process(task);
        let replacement = Arc::new(ProcState::default());
        wasi.procs.replace(task, replacement.clone());
        assert_eq!(
            owner.set_startup_input(crate::StartupInput::default()),
            Err(wasixv2_abi::Errno::ESRCH)
        );
        drop(owner);
        assert!(Arc::ptr_eq(&wasi.procs.get_or_create(task), &replacement));
    }

    #[test]
    fn host_attachments_share_process_and_http_until_the_last_owner_drops() {
        let mut store = Store::default();
        let module = Module::new(
            &store,
            wat::parse_str(
                r#"(module (memory (export "backing") 1)
                (global $count (mut i32) (i32.const 0))
                (func (export "_initialize") i32.const 1 global.set $count)
                (func (export "count") (result i32) global.get $count))"#,
            )
            .unwrap(),
        )
        .unwrap();
        let a = Instance::new(&mut store, &module, &Imports::new()).unwrap();
        let b = Instance::new(&mut store, &module, &Imports::new()).unwrap();
        let wasi = crate::Wasix1::default();
        let task = TaskId(7);
        let owner = wasi.host_process(task);
        let other_owner = owner.clone();
        let state = owner.current_state().unwrap();
        let attached_a = owner.attach::<wasixv2_kernel::Kernel>(&a, &mut store.as_store_mut());
        let attached_b = owner.attach::<wasixv2_kernel::Kernel>(&b, &mut store.as_store_mut());
        let selected_a = attached_a
            .as_any()
            .downcast_ref::<Wasix1Instance>()
            .unwrap();
        let selected_b = attached_b
            .as_any()
            .downcast_ref::<Wasix1Instance>()
            .unwrap();
        assert!(Arc::ptr_eq(&selected_a.http, &selected_b.http));
        assert!(selected_a.entry.is_none() && selected_a.initialize.is_none());
        assert!(selected_b.entry.is_none() && selected_b.initialize.is_none());
        assert!(selected_a.image.lock().unwrap().is_none());
        assert!(Arc::ptr_eq(&wasi.procs.get_or_create(task), &state));
        for instance in [&a, &b] {
            assert_eq!(
                instance
                    .exports
                    .get_typed_function::<(), i32>(&store, "count")
                    .unwrap()
                    .call(&mut store)
                    .unwrap(),
                0
            );
        }
        drop(owner);
        assert!(Arc::ptr_eq(&wasi.procs.get_or_create(task), &state));
        drop(other_owner);
        let next = wasi.procs.get_or_create(task);
        assert!(!Arc::ptr_eq(&next, &state));
        drop(attached_a);
        drop(attached_b);
        assert!(Arc::ptr_eq(&wasi.procs.get_or_create(task), &next));
    }
}
