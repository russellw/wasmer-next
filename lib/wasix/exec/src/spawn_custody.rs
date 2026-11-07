//! A host-only spawn owns its child until reap or an explicit successor transfer.

use std::{
    cell::RefCell,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use wasixv2_abi::Signal;
use wasixv2_syscalls::{Caller, Control, GuestAction, Resume, Syscalls, TaskId, VforkParent};
use wasmer::{AsStoreAsync, AsyncFunctionEnvMut, RuntimeError};

use crate::{ExecEnv, GuestMemory, process};

#[derive(Clone)]
struct State {
    parent: TaskId,
    child: Option<TaskId>,
    returning: Option<VforkParent>,
    published: bool,
    memory_left: bool,
    released: bool,
}

type SpawnCleanup = Box<dyn FnOnce(State, Option<wasixv2_host::LocalFuture<'static, ()>>)>;

/// Import-local custody for a spawn that never resumes a guest child activation.
/// Construct before clone and pass to every completion until exec or failed-child reap.
pub struct HostSpawn {
    state: Arc<Mutex<State>>,
    cleanup: Option<SpawnCleanup>,
    exit_memory: Box<dyn Fn(TaskId) -> wasixv2_host::LocalFuture<'static, ()>>,
    pending_memory: RefCell<Option<wasixv2_host::LocalFuture<'static, ()>>>,
}

impl HostSpawn {
    /// Captures the actual Store and cleanup owner before a child can exist.
    /// `retired` removes only this child's ABI bookkeeping, without entering wasm.
    pub async fn new<S: Syscalls + Control + 'static>(
        env: &AsyncFunctionEnvMut<ExecEnv<S>>,
        retired: impl FnOnce(TaskId) + 'static,
    ) -> Result<Self, RuntimeError> {
        let (parent, syscalls, shared) = {
            let guard = env.read().await;
            let data = guard.data();
            (
                data.task(),
                data.syscalls().clone(),
                data.loader_cleanup()
                    .cloned()
                    .ok_or_else(|| RuntimeError::new("spawn requires managed cleanup"))?,
            )
        };
        let local = crate::local_cleanup_runner(&env.as_store_async().store(), shared.clone());
        let env = env
            .downgrade()
            .and_then(|weak| weak.upgrade())
            .ok_or_else(|| RuntimeError::new("spawn requires its asynchronous Store"))?;
        let memory_env = env.downgrade().expect("owning async Store");
        let memory_syscalls = syscalls.clone();
        Ok(Self {
            exit_memory: Box::new(move |child| {
                let env = memory_env.upgrade().expect("spawn retains its Store");
                let syscalls = memory_syscalls.clone();
                Box::pin(async move {
                    let memory = GuestMemory::new(&env);
                    syscalls.exit_mm(&Caller::new(child, &memory)).await;
                })
            }),
            pending_memory: RefCell::new(None),
            state: Arc::new(Mutex::new(State {
                parent,
                child: None,
                returning: None,
                published: false,
                memory_left: false,
                released: false,
            })),
            cleanup: Some(Box::new(move |state, pending| {
                let future = Box::pin(async move {
                    retire(&env, &*syscalls, state, pending, retired).await;
                });
                match local {
                    Some(local) => local.spawn_with_fallback(future),
                    None => shared.spawn(future),
                }
            })),
        })
    }

    pub(crate) fn switched(&self, from: TaskId, child: TaskId) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if from == state.parent && state.child.is_none() {
            state.child = Some(child);
        }
    }

    pub(crate) fn returning(&self, child: TaskId, parent: VforkParent) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.child == Some(child) {
            state.returning = Some(parent);
        }
    }

    pub(crate) async fn exit_mm(&self, child: TaskId) {
        if self.pending_memory.borrow().is_none() {
            *self.pending_memory.borrow_mut() = Some((self.exit_memory)(child));
        }
        std::future::poll_fn(|cx| {
            self.pending_memory
                .borrow_mut()
                .as_mut()
                .unwrap()
                .as_mut()
                .poll(cx)
        })
        .await;
        *self.pending_memory.borrow_mut() = None;
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .memory_left = true;
    }

    pub(crate) fn released(&self, child: TaskId) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.child == Some(child) {
            state.released = true;
        }
    }

    pub(crate) fn publication(&self, child: TaskId) -> Option<Publication> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        (state.child == Some(child)).then(|| Publication(self.state.clone()))
    }

    /// The parent resumed after successful exec, or waitid authoritatively reaped failure.
    pub fn finish(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for HostSpawn {
    fn drop(&mut self) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        // An unconsumed SwitchTask remains the kernel's existing unstarted-child owner.
        if state.child.is_some()
            && let Some(cleanup) = self.cleanup.take()
        {
            let pending = self.pending_memory.get_mut().take();
            let unwinding = std::thread::panicking();
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cleanup(state, pending)));
            if let Err(panic) = result {
                if unwinding {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(panic)));
                } else {
                    std::panic::resume_unwind(panic);
                }
            }
        }
    }
}

pub(crate) struct Publication(Arc<Mutex<State>>);
impl Publication {
    #[cfg(all(test, feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn test_child(child: TaskId) -> Self {
        Self(Arc::new(Mutex::new(State {
            parent: TaskId(0),
            child: Some(child),
            returning: None,
            published: false,
            memory_left: false,
            released: false,
        })))
    }

    pub(crate) fn startup<S: Control + Send + Sync + 'static>(
        &self,
        syscalls: Arc<S>,
        task: TaskId,
    ) -> Startup {
        let entered = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(AtomicBool::new(false));
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        let authority = crate::cancellation::Cancellation::new(task);
        Startup {
            state: self.0.clone(),
            finished: Arc::new(AtomicBool::new(false)),
            entered: entered.clone(),
            terminal: terminal.clone(),
            #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
            authority: authority.clone(),
            cleanup: Some(Box::new(move || {
                // An entered worker resolves a possibly concurrent sibling takeover
                // on its driven async path after physical retirement.
                if entered.load(Ordering::Acquire) {
                    terminal.store(true, Ordering::Release);
                    return;
                }
                #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
                if !authority.claim_terminal() {
                    return;
                }
                let unwinding = std::thread::panicking();
                let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    syscalls.fault(task, Signal::SIGSEGV.0);
                }));
                let release = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    syscalls.release(task);
                }));
                for result in [fault, release] {
                    if let Err(panic) = result {
                        if unwinding {
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                drop(panic)
                            }));
                        } else {
                            std::panic::resume_unwind(panic);
                        }
                    }
                }
            })),
        }
    }

    /// The factory already contains its successor's drop-safe owner. Nothing fallible
    /// or externally observable separates this transfer from executor publication.
    pub(crate) fn accept(self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .published = true;
    }
}

pub(crate) struct Startup {
    state: Arc<Mutex<State>>,
    pub(crate) finished: Arc<AtomicBool>,
    pub(crate) entered: Arc<AtomicBool>,
    pub(crate) terminal: Arc<AtomicBool>,
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) authority: crate::cancellation::Cancellation,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}
impl Drop for Startup {
    fn drop(&mut self) {
        if self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .published
            && !self.finished.load(Ordering::Acquire)
            && let Some(cleanup) = self.cleanup.take()
        {
            cleanup();
        }
    }
}

async fn retire<S: Syscalls + Control + 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    syscalls: &S,
    mut state: State,
    pending: Option<wasixv2_host::LocalFuture<'static, ()>>,
    retired: impl FnOnce(TaskId),
) {
    let child = state.child.expect("captured before transfer");
    if !state.published && !state.released {
        // This child ran only host file actions; no guest activation or successor owns it.
        syscalls.fault(child, Signal::SIGKILL.0);
        let memory = GuestMemory::new(env);
        if let Some(pending) = pending {
            pending.await;
        } else if !state.memory_left {
            syscalls.exit_mm(&Caller::new(child, &memory)).await;
        }
        while let Some(action) = syscalls.take_pending(child) {
            match action {
                GuestAction::VforkReturn { parent, .. } => state.returning = Some(parent),
                GuestAction::Exec { vfork_parent } => {
                    state.returning = vfork_parent.or(state.returning);
                    drop(syscalls.take_image(child));
                }
                GuestAction::ExitMm { task } => {
                    syscalls.exit_mm(&Caller::new(task, &memory)).await;
                }
                GuestAction::StartImage { task } => {
                    let image = syscalls
                        .take_image(task)
                        .unwrap_or_else(|| wasixv2_syscalls::Image::copied(Vec::new()));
                    match process::exec_image(env, task, image).await {
                        Ok(image) => process::take_over(env, task, image).await,
                        Err(error) => {
                            // A missing/already-transferred exact lease grants no
                            // new terminal authority to this abandoned host call.
                            tracing::warn!(?task, %error, "cannot transfer abandoned spawn image custody");
                        }
                    }
                    if let Some(parent) = &mut state.returning {
                        parent.resumes = Resume::Gone;
                    }
                }
                _ => {}
            }
        }
        // abort_thread's unstarted-process path reaps the process and clears kernel
        // vfork state. exit_mm above ran first on the exact retained old memory.
        syscalls.abort_thread(child);
    }
    if !state.published
        && state.released
        && let Some(parent) = state.returning
    {
        let memory = GuestMemory::new(env);
        loop {
            let result = syscalls
                .waitid(
                    &Caller::new(state.parent, &memory),
                    wasixv2_abi::Idtype::P_PID,
                    parent.pid,
                    wasixv2_abi::SiginfoPtr::NULL,
                    wasixv2_abi::WaitOptions::WEXITED,
                    wasixv2_abi::RusagePtr::NULL,
                )
                .await;
            match result {
                Err(
                    wasixv2_syscalls::SysErr::Restart
                    | wasixv2_syscalls::SysErr::RestartNoIntr
                    | wasixv2_syscalls::SysErr::RestartNoHand
                    | wasixv2_syscalls::SysErr::RestartBlock,
                ) => continue,
                Ok(_) | Err(wasixv2_syscalls::SysErr::Errno(wasixv2_syscalls::Errno::ECHILD)) => {
                    break;
                }
                Err(error) => {
                    tracing::error!(?error, child = child.0, "cannot reap abandoned spawn");
                    break;
                }
            }
        }
    }
    retired(child);
    if state
        .returning
        .is_some_and(|parent| parent.resumes == Resume::Returns)
    {
        let mut guard = env.write().await;
        let data = guard.data_mut();
        if data.task() == child {
            data.switch(state.parent);
        }
    }
}

#[cfg(all(test, feature = "sys", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::process::tests::Recorder;
    use std::{
        cell::Cell,
        future::Future,
        rc::Rc,
        task::{Context, Poll},
        time::Duration,
    };
    use wasixv2_host::{Executor, Host, LocalFuture, ThreadStart};
    use wasixv2_syscalls::Image;
    use wasmer::{Function, FunctionEnv, Store};

    const PARENT: TaskId = TaskId(2);
    const CHILD: TaskId = TaskId(3);
    thread_local! {
        static ENV: RefCell<Option<wasmer::WeakAsyncFunctionEnvMut<ExecEnv<Recorder>>>> = const { RefCell::new(None) };
    }

    fn guard(cleanup: impl FnOnce(State, Option<LocalFuture<'static, ()>>) + 'static) -> HostSpawn {
        HostSpawn {
            state: Arc::new(Mutex::new(State {
                parent: PARENT,
                child: None,
                returning: None,
                published: false,
                memory_left: false,
                released: false,
            })),
            cleanup: Some(Box::new(cleanup)),
            exit_memory: Box::new(|_| panic!("this proof must not leave memory")),
            pending_memory: RefCell::new(None),
        }
    }

    struct NoSpawn;
    impl process::Spawn for NoSpawn {
        fn start_committed(
            &self,
            _: crate::PreinstalledTerminalCustody,
            _: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
            _: Arc<process::Handoff>,
        ) -> Result<crate::OwnedEntryWaiter, crate::ExecError> {
            unreachable!()
        }
        fn retire_committed(
            &self,
            _: crate::PreinstalledTerminalCustody,
            _: Arc<process::Handoff>,
        ) -> LocalFuture<'static, ()> {
            unreachable!()
        }
        fn spawn(&self, _: TaskId, _: process::ExecImage) {
            unreachable!()
        }
        fn fork(&self, _: TaskId, _: crate::asyncify::ForkImage) {
            unreachable!()
        }
        fn take_over(&self, _: TaskId, _: process::ExecImage, _: Arc<process::Handoff>) {
            unreachable!()
        }
    }

    #[test]
    fn consumed_switch_is_owned_before_waiting_for_the_store() {
        futures::executor::block_on(async {
            let control = Arc::new(Recorder::default());
            let mut store = Store::default();
            let env = FunctionEnv::new(
                &mut store,
                ExecEnv::new(
                    control.clone(),
                    PARENT,
                    process::ProcExports::new(Arc::new(NoSpawn), Arc::default()),
                    Arc::new(process::tests::NoThreads),
                ),
            );
            let capture = Function::new_typed_with_env_async(
                &mut store,
                &env,
                |env: AsyncFunctionEnvMut<ExecEnv<Recorder>>| async move {
                    ENV.with_borrow_mut(|slot| *slot = env.downgrade());
                },
            );
            let store = store.into_async();
            capture.call_async(&store, vec![]).await.unwrap();
            let env = ENV.with_borrow_mut(|slot| slot.take().unwrap().upgrade().unwrap());
            let observed = Rc::new(Cell::new(None));
            let returned = observed.clone();
            let custody = guard(move |state, _| returned.set(state.child));
            control.queue(
                PARENT,
                GuestAction::SwitchTask {
                    task: CHILD,
                    ret: 0,
                },
            );
            // Reads can finish and consume SwitchTask; the subsequent write must wait.
            let loan = store.read_lock().await;
            let mut call = Box::pin(crate::complete_with_spawn(
                &env,
                &*control,
                PARENT,
                Ok(()),
                &custody,
            ));
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(call.as_mut().poll(&mut cx).is_pending());
            assert_eq!(control.take_pending(PARENT), None);
            drop(call);
            drop(loan);
            drop(custody);
            assert_eq!(observed.get(), Some(CHILD));
            assert_eq!(env.read().await.data().task(), PARENT);
        });
    }

    #[test]
    fn canceled_memory_exit_transfers_the_same_pending_future() {
        let created = Rc::new(Cell::new(0));
        let polls = Rc::new(Cell::new(0));
        let ready = Rc::new(Cell::new(false));
        let pending = Rc::new(RefCell::new(None));
        let returned = pending.clone();
        let mut custody = guard(move |state, future| {
            assert_eq!(state.child, Some(CHILD));
            *returned.borrow_mut() = future;
        });
        custody.switched(PARENT, CHILD);
        custody.exit_memory = Box::new({
            let created = created.clone();
            let polls = polls.clone();
            let ready = ready.clone();
            move |_| {
                created.set(created.get() + 1);
                let polls = polls.clone();
                let ready = ready.clone();
                Box::pin(std::future::poll_fn(move |_| {
                    polls.set(polls.get() + 1);
                    if ready.get() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }))
            }
        });
        let mut exit = Box::pin(custody.exit_mm(CHILD));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(exit.as_mut().poll(&mut cx).is_pending());
        drop(exit);
        drop(custody);
        assert_eq!(created.get(), 1);
        ready.set(true);
        futures::executor::block_on(pending.borrow_mut().take().unwrap());
        assert_eq!((created.get(), polls.get()), (1, 2));
    }

    enum FactoryMode {
        Drop,
        Reject,
        Panic,
        Capture,
    }
    struct FactoryHost {
        mode: FactoryMode,
        factory: Mutex<Option<ThreadStart>>,
    }
    impl Host for FactoryHost {
        fn realtime(&self) -> Duration {
            Duration::ZERO
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _: Duration) -> LocalFuture<'_, ()> {
            Box::pin(async {})
        }
        fn random(&self, _: &mut [u8]) {}
        fn report(&self, _: &str) {}
        fn executor(&self) -> &dyn Executor {
            self
        }
    }
    impl Executor for FactoryHost {
        fn spawn_local(&self, _: LocalFuture<'static, ()>) {
            panic!("no cleanup job expected")
        }
        fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
            Box::pin(async move { work() })
        }
        fn spawn_thread(&self, start: ThreadStart) -> std::io::Result<()> {
            match self.mode {
                FactoryMode::Drop => {
                    drop(start);
                    Ok(())
                }
                FactoryMode::Reject => {
                    drop(start);
                    Err(std::io::ErrorKind::Unsupported.into())
                }
                FactoryMode::Panic => {
                    drop(start);
                    panic!("publication panic")
                }
                FactoryMode::Capture => {
                    *self.factory.lock().unwrap() = Some(start);
                    Ok(())
                }
            }
        }
    }
    struct PendingLoader;
    impl crate::Loader for PendingLoader {
        fn load<'a>(
            &'a self,
            _: &'a wasmer::Engine,
            _: &'a Image,
        ) -> LocalFuture<'a, Result<(wasmer::Engine, wasmer::Module), crate::LoadError>> {
            Box::pin(std::future::pending())
        }
    }

    #[test]
    fn successor_owns_rejected_discarded_and_panicking_publications() {
        for mode in [
            FactoryMode::Drop,
            FactoryMode::Reject,
            FactoryMode::Panic,
            FactoryMode::Capture,
        ] {
            {
                let control = Arc::new(Recorder::default());
                let host = Arc::new(FactoryHost {
                    mode: match mode {
                        FactoryMode::Drop => FactoryMode::Drop,
                        FactoryMode::Reject => FactoryMode::Reject,
                        FactoryMode::Panic => FactoryMode::Panic,
                        FactoryMode::Capture => FactoryMode::Capture,
                    },
                    factory: Mutex::new(None),
                });
                let mut abis = crate::Abis::new();
                abis.set_loader(Arc::new(PendingLoader));
                let spawner = process::spawner(
                    Store::default().engine().clone(),
                    control.clone(),
                    host.clone(),
                    Arc::new(abis),
                );
                let published = Rc::new(Cell::new(false));
                let returned = published.clone();
                let custody = guard(move |state, _| {
                    returned.set(state.published);
                });
                custody.switched(PARENT, CHILD);
                let publication = custody.publication(CHILD).unwrap();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    spawner.spawn_owned(CHILD, Image::copied(Vec::new()).into(), publication);
                }));
                assert_eq!(result.is_err(), matches!(host.mode, FactoryMode::Panic));
                drop(custody);
                assert!(
                    published.get(),
                    "parent must relinquish only to the factory owner"
                );
                let factory = host.factory.lock().unwrap().take();
                if let Some(factory) = factory {
                    drop(factory());
                }
                assert_eq!(
                    *control.faulted.lock().unwrap(),
                    [(CHILD, Signal::SIGSEGV.0)]
                );
                assert_eq!(*control.released.lock().unwrap(), [CHILD]);
            }
        }
    }
}
