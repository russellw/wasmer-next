//! Match instantiation's native-scope subprocess proofs, using a real LoaderControl.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    ops::Range,
    sync::{Arc, Mutex, Weak, mpsc},
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::{
    channel::{mpsc as async_mpsc, oneshot},
    executor::{LocalPool, LocalSpawner},
    task::LocalSpawnExt,
};
use wasixv2_host::{Executor, Host, LoaderCleanup, LocalFuture, ThreadStart};
use wasixv2_syscalls::{
    AtomicWait, AtomicWord, Caller, Control, CpuTime, ExitMm, GroupStop, GuestAction,
    HostMemoryLease, Image, LoaderControl, MaybeFuture, PidView, SharedMapping, SharedMappings,
    SysResult, Syscalls, TaskId, VforkWait,
};
use wasmer::{Function, FunctionEnv, Imports, Module, RuntimeError, Store, StoreMut};

use super::*;
use crate::{ExecEnv, InstanceAttachment, InstantiationHook};

thread_local! {
    static SPAWNER: RefCell<Option<LocalSpawner>> = const { RefCell::new(None) };
}

type Event = (&'static str, std::thread::ThreadId);
enum FrameCommand {
    ObserveCancellation,
    Release,
}
struct Proof {
    events: mpsc::Sender<Event>,
    scope: Mutex<Option<Weak<LoaderCleanup>>>,
    frame: Mutex<Option<async_mpsc::UnboundedReceiver<FrameCommand>>>,
    cleanup: Mutex<Option<oneshot::Receiver<()>>>,
    tail: Mutex<Option<oneshot::Receiver<()>>>,
    group: Mutex<Option<oneshot::Receiver<()>>>,
    pending: Mutex<HashMap<TaskId, VecDeque<GuestAction>>>,
    start: Mutex<Option<mpsc::Receiver<()>>>,
    drop_worker: Mutex<Option<oneshot::Receiver<()>>>,
    authority: Mutex<Option<WeakCancellation>>,
    publications: std::sync::atomic::AtomicUsize,
    hold_publication: Mutex<Option<mpsc::Receiver<()>>>,
    reject: bool,
    complete: Mutex<Option<oneshot::Receiver<()>>>,
    sibling_done: Mutex<Option<oneshot::Sender<()>>>,
}
impl Proof {
    fn event(&self, phase: &'static str) {
        self.events
            .send((phase, std::thread::current().id()))
            .unwrap();
    }
}

struct ProofHost(Arc<Proof>);
impl Host for ProofHost {
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
    fn executor(&self) -> &dyn Executor {
        self
    }
    fn report(&self, _: &str) {}
}
impl Executor for ProofHost {
    fn spawn_local(&self, future: LocalFuture<'static, ()>) {
        SPAWNER.with(|spawner| {
            spawner
                .borrow()
                .as_ref()
                .unwrap()
                .spawn_local(future)
                .unwrap();
        });
    }
    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
        Box::pin(async move { work() })
    }
    fn spawn_thread(&self, start: ThreadStart) -> std::io::Result<()> {
        let proof = self.0.clone();
        if proof.reject {
            return Err(std::io::ErrorKind::Unsupported.into());
        }
        if proof
            .publications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            == 2
            && let Some(gate) = proof.hold_publication.lock().unwrap().take()
        {
            proof.event("publication-held");
            gate.recv().unwrap();
        }
        let gate = proof.start.lock().unwrap().take();
        let drop_worker = proof.drop_worker.lock().unwrap().take();
        std::thread::Builder::new().spawn(move || {
            if let Some(gate) = gate {
                gate.recv().unwrap();
            }
            let mut pool = LocalPool::new();
            SPAWNER.with(|slot| *slot.borrow_mut() = Some(pool.spawner()));
            proof.event("worker-start");
            pool.run_until(async move {
                match drop_worker {
                    Some(drop_worker) => {
                        if let futures::future::Either::Right((_, old_worker)) =
                            futures::future::select(start(), drop_worker).await
                        {
                            drop(old_worker);
                        }
                    }
                    None => start().await,
                }
            });
            pool.run_until_stalled();
            // OwningThread::run must have released the exact old permit.
            thread::OwningThread::acquire()
                .unwrap()
                .authorize()
                .unwrap();
            proof.event("worker-done");
            SPAWNER.with(|slot| drop(slot.borrow_mut().take()));
        })?;
        Ok(())
    }
}

struct PendingControl(Arc<Proof>);
struct PendingLease {
    proof: Arc<Proof>,
    polled: bool,
}
impl Future for PendingLease {
    type Output = SysResult<Box<dyn HostMemoryLease>>;
    fn poll(mut self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.polled {
            self.proof.event("loader-pending");
            self.polled = true;
        }
        // Deliberately neither observes kernel death nor registers a wakeup.
        Poll::Pending
    }
}
impl Drop for PendingLease {
    fn drop(&mut self) {
        self.proof.event("loader-drop");
    }
}
impl LoaderControl for PendingControl {
    fn loader_reserve_host<'a>(
        &'a self,
        _: &'a Caller<'_>,
        bytes: u32,
        alignment: u32,
    ) -> LocalFuture<'a, SysResult<Box<dyn HostMemoryLease>>> {
        assert_eq!((bytes, alignment), (17, 64));
        Box::pin(PendingLease {
            proof: self.0.clone(),
            polled: false,
        })
    }
}
impl Syscalls for PendingControl {
    fn exit_group<'a>(
        &'a self,
        caller: &'a Caller<'_>,
        status: i32,
    ) -> MaybeFuture<'a, SysResult<()>> {
        self.0
            .pending
            .lock()
            .unwrap()
            .entry(caller.task())
            .or_default()
            .push_back(GuestAction::Exit(status));
        MaybeFuture::Ready(Ok(()))
    }
    fn exit<'a>(&'a self, caller: &'a Caller<'_>, status: i32) -> MaybeFuture<'a, SysResult<()>> {
        self.exit_group(caller, status)
    }
}
impl Control for PendingControl {
    fn take_pending(&self, task: TaskId) -> Option<GuestAction> {
        self.0.pending.lock().unwrap().get_mut(&task)?.pop_front()
    }
    fn group_wait(&self, task: TaskId) -> LocalFuture<'_, ()> {
        let gate = if task == TaskId(1) {
            self.0.group.lock().unwrap().take()
        } else {
            None
        };
        Box::pin(async move {
            if let Some(gate) = gate {
                self.0.event("group-wait");
                gate.await.unwrap();
                self.0.event("group-retired");
            }
        })
    }
    fn take_image(&self, _: TaskId) -> Option<Image> {
        None
    }
    fn fault(&self, _: TaskId, signal: i32) -> bool {
        assert_eq!(signal, wasixv2_abi::Signal::SIGSEGV.0);
        self.0.event("fault");
        true
    }
    fn release(&self, task: TaskId) {
        if task == TaskId(2) {
            self.0.event("sibling-release");
            if let Some(done) = self.0.sibling_done.lock().unwrap().take() {
                done.send(()).unwrap();
            }
        } else {
            self.0.event("release");
        }
    }
}
impl CpuTime for PendingControl {}
impl PidView for PendingControl {
    fn tgid(&self, _: TaskId) -> TaskId {
        TaskId(1)
    }
}
impl ExitMm for PendingControl {
    fn exit_mm<'a>(&'a self, _: &'a Caller<'a>) -> LocalFuture<'a, ()> {
        Box::pin(async {})
    }
}
impl GroupStop for PendingControl {
    fn stop_wait(&self, _: TaskId) -> LocalFuture<'_, ()> {
        Box::pin(async {})
    }
}
impl VforkWait for PendingControl {
    fn vfork_wait(&self, _: TaskId) -> LocalFuture<'_, ()> {
        Box::pin(async {})
    }
}
impl AtomicWait for PendingControl {
    fn atomic_wait<'a>(
        &'a self,
        _: &'a Caller<'a>,
        _: u32,
        _: AtomicWord,
        _: Option<Duration>,
    ) -> LocalFuture<'a, SysResult<i32>> {
        Box::pin(async { Ok(0) })
    }
    fn atomic_notify(&self, _: TaskId, _: u32, _: u32) -> u32 {
        0
    }
}
impl SharedMappings for PendingControl {
    fn shared_mappings(&self, _: TaskId) -> Vec<SharedMapping> {
        Vec::new()
    }
    fn wipe_on_fork(&self, _: TaskId) -> Vec<Range<u64>> {
        Vec::new()
    }
}

struct PendingHook {
    proof: Arc<Proof>,
    host: Arc<ProofHost>,
}
impl InstantiationHook<PendingControl> for PendingHook {
    fn requires_owning_thread(&self) -> bool {
        true
    }
    fn prepare_imports(
        &self,
        _: &Module,
        store: &mut StoreMut<'_>,
        env: &FunctionEnv<ExecEnv<PendingControl>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        self.proof.event("prepare");
        let scope = env.as_ref(&*store).loader_cleanup().unwrap();
        *self.proof.scope.lock().unwrap() = Some(Arc::downgrade(scope));
        let proof = self.proof.clone();
        let host = self.host.clone();
        imports.define(
            "custom",
            "pending",
            Function::new_typed_with_env_async(
                store,
                env,
                move |env: wasmer::AsyncFunctionEnvMut<ExecEnv<PendingControl>>| {
                    if let Some(mut commands) = proof.frame.lock().unwrap().take() {
                        let root = wasmer::sys::WeakNativeInvocation::current().unwrap();
                        let proof = proof.clone();
                        host.spawn_local(Box::pin(async move {
                            use futures::StreamExt;
                            // SAFETY: this is the original owner after the actual
                            // invocation parked. The guard never leaves this local
                            // task, and no independent native root is parked here.
                            let frame = unsafe { root.enter_descendant_frame() }.unwrap();
                            proof.event("frame-held");
                            while let Some(command) = commands.next().await {
                                match command {
                                    FrameCommand::ObserveCancellation => {
                                        poll_fn(|cx| match frame.retirement_error() {
                                            Some(error) => {
                                                assert!(error.is_host_abort());
                                                Poll::Ready(())
                                            }
                                            None => {
                                                cx.waker().wake_by_ref();
                                                Poll::Pending
                                            }
                                        })
                                        .await;
                                        assert!(matches!(
                                            thread::OwningThread::acquire(),
                                            Err(ExecError::OwningThreadBusy)
                                        ));
                                        proof.event("cancellation-observed");
                                    }
                                    FrameCommand::Release => break,
                                }
                            }
                            drop(frame);
                            proof.event("frame-released");
                        }));
                    }
                    async move {
                        let (syscalls, task) = {
                            let read = env.read().await;
                            (read.data().syscalls().clone(), read.data().task())
                        };
                        let memory = crate::GuestMemory::new(&env);
                        let caller = Caller::new(task, &memory);
                        let _lease = syscalls
                            .loader_reserve_host(&caller, 17, 64)
                            .await
                            .map_err(|_| RuntimeError::new("unexpected loader completion"))?;
                        Ok::<(), RuntimeError>(())
                    }
                },
            ),
        );
        Ok(Some(Box::new(PendingAttachment(self.proof.clone()))))
    }
}
struct PendingAttachment(Arc<Proof>);
impl InstanceAttachment for PendingAttachment {
    fn configure(
        &mut self,
        _: &Module,
        _: &mut StoreMut<'_>,
        _: &wasmer::Instance,
        _: &wasmer::Memory,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }
    fn deactivate(&mut self, _: &mut StoreMut<'_>) {
        self.0.event("deactivate");
        let proof = self.0.clone();
        let scope = proof
            .scope
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        let cleanup = proof.cleanup.lock().unwrap().take().unwrap();
        let tail = proof.tail.lock().unwrap().take().unwrap();
        assert!(
            scope
                .submit(Box::new(move || Box::pin(async move {
                    proof.event("cleanup-start");
                    cleanup.await.unwrap();
                    let scope = proof
                        .scope
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .upgrade()
                        .unwrap();
                    let tail_proof = proof.clone();
                    assert!(
                        scope
                            .submit(Box::new(move || Box::pin(async move {
                                tail_proof.event("tail-start");
                                tail.await.unwrap();
                                tail_proof.event("tail-end");
                            })))
                            .is_ok()
                    );
                    proof.event("cleanup-end");
                })))
                .is_ok()
        );
    }
}

fn subprocess(name: &str) -> bool {
    const CHILD: &str = "WASIXV2_CANCEL_OWNER_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, "1")
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "owning-worker cancellation proof failed: {status}"
                );
                return false;
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            status => panic!("owning-worker cancellation proof did not finish: {status:?}"),
        }
    }
}

fn dropped_waiter(image: bool, retain_frame: bool) {
    dropped_waiter_mode(image, retain_frame, false)
}
fn dropped_waiter_mode(image: bool, retain_frame: bool, detached: bool) {
    let (events, observed) = mpsc::channel();
    let (frame_tx, frame_rx) = async_mpsc::unbounded();
    let (cleanup_tx, cleanup_rx) = oneshot::channel();
    let (tail_tx, tail_rx) = oneshot::channel();
    let proof = Arc::new(Proof {
        events,
        scope: Mutex::new(None),
        frame: Mutex::new(retain_frame.then_some(frame_rx)),
        cleanup: Mutex::new(Some(cleanup_rx)),
        tail: Mutex::new(Some(tail_rx)),
        group: Mutex::new(None),
        pending: Mutex::new(HashMap::new()),
        start: Mutex::new(None),
        drop_worker: Mutex::new(None),
        authority: Mutex::new(None),
        publications: std::sync::atomic::AtomicUsize::new(0),
        hold_publication: Mutex::new(None),
        reject: false,
        complete: Mutex::new(None),
        sibling_done: Mutex::new(None),
    });
    let host = Arc::new(ProofHost(proof.clone()));
    let mut abis = Abis::wasixv2();
    abis.push_instantiation_hook(Arc::new(PendingHook {
        proof: proof.clone(),
        host: host.clone(),
    }));
    let syscalls = Arc::new(PendingControl(proof.clone()));
    let engine = Store::default().engine().clone();
    let wasm = wat::parse_str(
        r#"(module
        (import "custom" "pending" (func $pending))
        (import "wasixv2" "exit_group" (func (param i32)))
        (memory (export "memory") 1)
        (func (export "_start") call $pending unreachable))"#,
    )
    .unwrap();
    let module = Module::new(&engine, &wasm).unwrap();
    let detached_handoff = Arc::new(process::Handoff::default());
    let mut caller: std::pin::Pin<Box<dyn Future<Output = Result<i32, ExecError>> + '_>> =
        if detached {
            process::spawner(engine, syscalls, host, Arc::new(abis)).take_over(
                TaskId(1),
                Image::copied(wasm).into(),
                detached_handoff.clone(),
            );
            let handoff = detached_handoff.clone();
            Box::pin(async move { handoff.wait().await })
        } else if image {
            Box::pin(crate::run_exec(
                engine,
                Image::copied(wasm),
                syscalls,
                TaskId(1),
                host,
                Arc::new(abis),
            ))
        } else {
            Box::pin(crate::run_on_owning_thread(
                engine,
                &module,
                syscalls,
                TaskId(1),
                host,
                Arc::new(abis),
            ))
        };
    assert!(
        caller
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let mut events = Vec::new();
    let mut until = |phase| loop {
        let event = observed.recv_timeout(Duration::from_secs(5)).unwrap();
        events.push(event);
        if event.0 == phase {
            break;
        }
    };
    until(if retain_frame {
        "frame-held"
    } else {
        "loader-pending"
    });
    // This is the sole cancellation trigger. The custom control never wakes its
    // pending lease and kernel fault/release cannot make that future complete.
    drop(caller);
    if detached {
        detached_handoff.cancel_takeover();
    }
    let mut completion = detached.then(|| Box::pin(detached_handoff.wait()));
    if retain_frame {
        frame_tx
            .unbounded_send(FrameCommand::ObserveCancellation)
            .unwrap();
        until("cancellation-observed");
        assert!(
            observed.try_recv().is_err(),
            "physical pin still blocks teardown"
        );
        frame_tx.unbounded_send(FrameCommand::Release).unwrap();
    }
    until("cleanup-start");
    if let Some(completion) = &mut completion {
        assert!(
            completion
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "detached completion precedes neither native nor loader retirement"
        );
    }
    let scope = proof
        .scope
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap();
    assert!(scope.is_open());
    assert!(
        observed.try_recv().is_err(),
        "the first cleanup generation still owns completion"
    );
    cleanup_tx.send(()).unwrap();
    until("tail-start");
    if let Some(completion) = &mut completion {
        assert!(
            completion
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "the successor's actual final loader generation still owns completion"
        );
    }
    assert!(scope.is_open());
    assert!(
        observed.try_recv().is_err(),
        "the next cleanup generation still owns completion"
    );
    tail_tx.send(()).unwrap();
    until("worker-done");
    drop(until);
    if let Some(completion) = &mut completion {
        assert!(matches!(
            completion
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ExecError::Dropped))
        ));
    }
    assert!(!scope.is_open());
    let owner = events[0].1;
    assert_ne!(owner, std::thread::current().id());
    assert!(events.iter().all(|(_, thread)| *thread == owner));
    let phases = events.iter().map(|(phase, _)| *phase).collect::<Vec<_>>();
    let at = |phase| phases.iter().position(|seen| *seen == phase).unwrap();
    assert!(at("loader-pending") < at("loader-drop"));
    assert!(at("loader-drop") < at("deactivate"));
    assert!(at("tail-end") < at("fault"));
    assert!(at("fault") < at("release"));
    assert!(at("release") < at("worker-done"));
    for phase in [
        "prepare",
        "loader-pending",
        "loader-drop",
        "deactivate",
        "fault",
        "release",
    ] {
        assert_eq!(
            phases.iter().filter(|seen| **seen == phase).count(),
            1,
            "{phase}"
        );
    }
    if retain_frame {
        assert!(at("cancellation-observed") < at("frame-released"));
        assert!(at("frame-released") < at("deactivate"));
    }
}

#[test]
fn dropped_module_waiter_cancels_a_permanently_pending_loader_on_its_owner() {
    if subprocess(
        "cancellation::tests::dropped_module_waiter_cancels_a_permanently_pending_loader_on_its_owner",
    ) {
        dropped_waiter(false, false);
    }
}

#[test]
fn dropped_exec_waiter_drains_its_physical_frame_and_every_cleanup_generation() {
    if subprocess(
        "cancellation::tests::dropped_exec_waiter_drains_its_physical_frame_and_every_cleanup_generation",
    ) {
        dropped_waiter(true, true);
    }
}

fn lifecycle_proof(reject: bool) -> (Arc<Proof>, mpsc::Receiver<Event>) {
    let (events, observed) = mpsc::channel();
    (
        Arc::new(Proof {
            events,
            scope: Mutex::new(None),
            frame: Mutex::new(None),
            cleanup: Mutex::new(None),
            tail: Mutex::new(None),
            group: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            start: Mutex::new(None),
            drop_worker: Mutex::new(None),
            authority: Mutex::new(None),
            publications: std::sync::atomic::AtomicUsize::new(0),
            hold_publication: Mutex::new(None),
            reject,
            complete: Mutex::new(None),
            sibling_done: Mutex::new(None),
        }),
        observed,
    )
}

struct LifecycleHook {
    proof: Arc<Proof>,
    image: Vec<u8>,
}
impl InstantiationHook<PendingControl> for LifecycleHook {
    fn requires_owning_thread(&self) -> bool {
        true
    }
    fn prepare_imports(
        &self,
        module: &Module,
        store: &mut StoreMut<'_>,
        env: &FunctionEnv<ExecEnv<PendingControl>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        let data = env.as_ref(store);
        if data.task() == TaskId(1) {
            let mut authority = self.proof.authority.lock().unwrap();
            if authority.is_none() {
                *authority = data
                    .proc
                    .handoff
                    .cancellation()
                    .map(|owner| owner.downgrade());
            }
        }
        self.proof.event("lifecycle-prepare");
        imports.define(
            "custom",
            "start",
            Function::new_typed_with_env_async(
                store,
                env,
                |env: wasmer::AsyncFunctionEnvMut<ExecEnv<PendingControl>>| async move {
                    let image = env.read().await.data().threads.clone().unwrap();
                    image.start(TaskId(2), 2, 0).unwrap();
                    Ok::<(), RuntimeError>(())
                },
            ),
        );
        let proof = self.proof.clone();
        imports.define(
            "custom",
            "wait",
            Function::new_typed_with_env_async(
                store,
                env,
                move |_: wasmer::AsyncFunctionEnvMut<ExecEnv<PendingControl>>| {
                    proof.event("owned-pending");
                    std::future::pending::<Result<(), RuntimeError>>()
                },
            ),
        );
        let proof = self.proof.clone();
        imports.define(
            "custom",
            "old",
            Function::new_typed_with_env_async(
                store,
                env,
                move |_: wasmer::AsyncFunctionEnvMut<ExecEnv<PendingControl>>| {
                    let proof = proof.clone();
                    async move {
                        let _drop = OldProvider(proof.clone());
                        proof.event("old-pending");
                        // Never observes kernel state, completes, or wakes itself.
                        std::future::pending::<Result<(), RuntimeError>>().await
                    }
                },
            ),
        );
        let proof = self.proof.clone();
        let image = self.image.clone();
        imports.define(
            "custom",
            "transfer",
            Function::new_typed_with_env_async(
                store,
                env,
                move |env: wasmer::AsyncFunctionEnvMut<ExecEnv<PendingControl>>| {
                    let image = image.clone();
                    let proof = proof.clone();
                    async move {
                        // The real thread instance inherited the original image's
                        // Handoff, despite having its own worker/Store/cleanup scope.
                        process::take_over(&env, TaskId(1), Image::copied(image).into()).await;
                        proof.event("transferred");
                        Err::<(), RuntimeError>(RuntimeError::user(Box::new(crate::Exited(0))))
                    }
                },
            ),
        );
        let proof = self.proof.clone();
        imports.define(
            "custom",
            "complete",
            Function::new_typed_with_env_async(
                store,
                env,
                move |_: wasmer::AsyncFunctionEnvMut<ExecEnv<PendingControl>>| {
                    let gate = proof.complete.lock().unwrap().take().unwrap();
                    let proof = proof.clone();
                    async move {
                        proof.event("complete-pending");
                        gate.await.unwrap();
                        Ok::<(), RuntimeError>(())
                    }
                },
            ),
        );
        if module
            .imports()
            .any(|import| import.module() == "custom" && import.name() == "old")
        {
            Ok(Some(Box::new(OldAttachment {
                proof: self.proof.clone(),
                env: env.clone(),
            })))
        } else {
            Ok(None)
        }
    }
}
struct OldProvider(Arc<Proof>);
impl Drop for OldProvider {
    fn drop(&mut self) {
        self.0.event("old-drop");
    }
}
struct OldAttachment {
    proof: Arc<Proof>,
    env: FunctionEnv<ExecEnv<PendingControl>>,
}
impl InstanceAttachment for OldAttachment {
    fn configure(
        &mut self,
        _: &Module,
        _: &mut StoreMut<'_>,
        _: &wasmer::Instance,
        _: &wasmer::Memory,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }
    fn deactivate(&mut self, store: &mut StoreMut<'_>) {
        if self.env.as_ref(store).task() == TaskId(1) {
            self.proof.event("old-deactivate");
            let exec = self.env.as_ref(store);
            let scope = exec.loader_cleanup().unwrap().clone();
            let proof = self.proof.clone();
            assert!(
                scope
                    .submit(Box::new(move || Box::pin(async move {
                        proof.event("old-cleanup");
                    })))
                    .is_ok()
            );
            let proof = self.proof.clone();
            exec.host.executor().spawn_local(Box::pin(async move {
                poll_fn(|cx| {
                    if scope.is_open() {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
                proof.event("old-drained");
            }));
        }
    }
}

fn until(observed: &mpsc::Receiver<Event>, events: &mut Vec<Event>, phase: &'static str) {
    loop {
        let event = observed.recv_timeout(Duration::from_secs(5)).unwrap();
        events.push(event);
        if event.0 == phase {
            return;
        }
    }
}
fn lifecycle_module(engine: &Engine, body: &str) -> Module {
    Module::new(
        engine,
        wat::parse_str(format!(
            r#"(module
        (import "wasixv2" "exit_group" (func $exit (param i32)))
        (memory (export "memory") 1)
        (func (export "_start") {body}))"#
        ))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn cancellation_before_the_factory_first_poll_never_prepares_guest_bindings() {
    if !subprocess(
        "cancellation::tests::cancellation_before_the_factory_first_poll_never_prepares_guest_bindings",
    ) {
        return;
    }
    let (proof, observed) = lifecycle_proof(false);
    let (start_tx, start_rx) = mpsc::channel();
    *proof.start.lock().unwrap() = Some(start_rx);
    let host = Arc::new(ProofHost(proof.clone()));
    let engine = Store::default().engine().clone();
    let module = lifecycle_module(&engine, "i32.const 37 call $exit");
    let control = Arc::new(PendingControl(proof));
    let mut abis = Abis::wasixv2();
    abis.push_instantiation_hook(Arc::new(LifecycleHook {
        proof: control.0.clone(),
        image: vec![],
    }));
    let mut caller = Box::pin(crate::run_on_owning_thread(
        engine,
        &module,
        control,
        TaskId(1),
        host,
        Arc::new(abis),
    ));
    assert!(
        caller
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(caller);
    start_tx.send(()).unwrap();
    let mut events = Vec::new();
    until(&observed, &mut events, "worker-done");
    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        ["worker-start", "fault", "release", "worker-done"]
    );
    assert!(events.iter().all(|event| event.1 == events[0].1));
}

#[test]
fn normal_completion_and_spawn_rejection_preserve_the_original_result_and_single_release() {
    if !subprocess(
        "cancellation::tests::normal_completion_and_spawn_rejection_preserve_the_original_result_and_single_release",
    ) {
        return;
    }
    for reject in [false, true] {
        let (proof, observed) = lifecycle_proof(reject);
        let host = Arc::new(ProofHost(proof.clone()));
        let engine = Store::default().engine().clone();
        let module = lifecycle_module(&engine, "i32.const 37 call $exit");
        let result = futures::executor::block_on(crate::run_on_owning_thread(
            engine,
            &module,
            Arc::new(PendingControl(proof)),
            TaskId(1),
            host,
            Arc::new(Abis::wasixv2()),
        ));
        let mut events = Vec::new();
        if reject {
            assert!(matches!(result, Err(ExecError::OwningThreadSpawn(_))));
            until(&observed, &mut events, "release");
            assert_eq!(
                events.iter().map(|event| event.0).collect::<Vec<_>>(),
                ["fault", "release"]
            );
        } else {
            assert_eq!(result.unwrap(), 37);
            until(&observed, &mut events, "worker-done");
            assert_eq!(
                events.iter().map(|event| event.0).collect::<Vec<_>>(),
                ["worker-start", "release", "worker-done"]
            );
        }
    }
}

fn shared_module(transfer: bool) -> Vec<u8> {
    let (original, sibling) = if transfer {
        ("old", "transfer")
    } else {
        ("wait", "complete")
    };
    wat::parse_str(format!(
        r#"(module
        (import "env" "memory" (memory 1 2 shared))
        (import "custom" "start" (func $start))
        (import "custom" "{original}" (func $original))
        (import "custom" "{sibling}" (func $sibling))
        (import "wasixv2" "exit" (func $exit (param i32)))
        (export "memory" (memory 0))
        (func (export "_start") call $start call $original unreachable)
        (func (export "wasixv2_thread_start") (param i32 i32)
            call $sibling i32.const 0 call $exit unreachable))"#
    ))
    .unwrap()
}

#[test]
fn a_sibling_takeover_relinquishes_cancellation_before_the_old_image_finishes() {
    if !subprocess(
        "cancellation::tests::a_sibling_takeover_relinquishes_cancellation_before_the_old_image_finishes",
    ) {
        return;
    }
    let (proof, observed) = lifecycle_proof(false);
    let (complete_tx, complete_rx) = oneshot::channel();
    *proof.complete.lock().unwrap() = Some(complete_rx);
    let image = wat::parse_str(
        r#"(module
        (import "custom" "complete" (func $complete))
        (import "wasixv2" "exit_group" (func $exit (param i32)))
        (memory (export "memory") 1)
        (func (export "_start") call $complete i32.const 37 call $exit unreachable))"#,
    )
    .unwrap();
    let mut abis = Abis::wasixv2();
    abis.push_instantiation_hook(Arc::new(LifecycleHook {
        proof: proof.clone(),
        image,
    }));
    let engine = Store::default().engine().clone();
    let module = Module::new(&engine, shared_module(true)).unwrap();
    let mut caller = Box::pin(crate::run_on_owning_thread(
        engine,
        &module,
        Arc::new(PendingControl(proof.clone())),
        TaskId(1),
        Arc::new(ProofHost(proof)),
        Arc::new(abis),
    ));
    assert!(
        caller
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let mut events = Vec::new();
    until(&observed, &mut events, "complete-pending");
    if !events.iter().any(|event| event.0 == "old-pending") {
        until(&observed, &mut events, "old-pending");
    }
    drop(caller);
    until(&observed, &mut events, "old-drained");
    let at = |phase| events.iter().position(|event| event.0 == phase).unwrap();
    assert!(at("old-drop") < at("old-deactivate"));
    assert!(at("old-deactivate") < at("old-cleanup"));
    assert!(at("old-cleanup") < at("old-drained"));
    assert!(
        events
            .iter()
            .all(|event| event.0 != "fault" && event.0 != "release")
    );
    complete_tx.send(()).unwrap();
    while events
        .iter()
        .filter(|event| event.0 == "worker-done")
        .count()
        < 3
    {
        until(&observed, &mut events, "worker-done");
    }
    assert_eq!(
        events.iter().filter(|event| event.0 == "release").count(),
        1
    );
    assert!(events.iter().all(|event| event.0 != "fault"));
    let successor = events
        .iter()
        .find(|event| event.0 == "complete-pending")
        .unwrap()
        .1;
    assert!(
        events
            .iter()
            .filter(|event| event.0 == "release")
            .all(|event| event.1 == successor)
    );
}

#[test]
fn published_child_takeover_survives_dropping_its_old_worker() {
    if !subprocess("cancellation::tests::published_child_takeover_survives_dropping_its_old_worker")
    {
        return;
    }
    for overlap in [false, true] {
        TERMINAL_WAITS.store(0, std::sync::atomic::Ordering::Release);
        let (proof, observed) = lifecycle_proof(false);
        let (publication_tx, publication_rx) = mpsc::channel();
        if overlap {
            *proof.hold_publication.lock().unwrap() = Some(publication_rx);
        }
        let (drop_tx, drop_rx) = oneshot::channel();
        *proof.drop_worker.lock().unwrap() = Some(drop_rx);
        let (complete_tx, complete_rx) = oneshot::channel();
        *proof.complete.lock().unwrap() = Some(complete_rx);
        let image = wat::parse_str(
            r#"(module
        (import "custom" "complete" (func $complete))
        (import "wasixv2" "exit_group" (func $exit (param i32)))
        (memory (export "memory") 1)
        (func (export "_start") call $complete i32.const 37 call $exit unreachable))"#,
        )
        .unwrap();
        let mut abis = Abis::wasixv2();
        abis.push_instantiation_hook(Arc::new(LifecycleHook {
            proof: proof.clone(),
            image,
        }));
        let spawner = process::spawner(
            Store::default().engine().clone(),
            Arc::new(PendingControl(proof.clone())),
            Arc::new(ProofHost(proof.clone())),
            Arc::new(abis),
        );
        spawner.spawn_owned(
            TaskId(1),
            Image::copied(shared_module(true)).into(),
            crate::spawn_custody::Publication::test_child(TaskId(1)),
        );
        let mut events = Vec::new();
        if overlap {
            until(&observed, &mut events, "publication-held");
            if !events.iter().any(|event| event.0 == "old-pending") {
                until(&observed, &mut events, "old-pending");
            }
            proof
                .authority
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .request();
            until(&observed, &mut events, "old-drained");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while TERMINAL_WAITS.load(std::sync::atomic::Ordering::Acquire) == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "drained owner must await the sibling's reservation"
                );
                std::thread::yield_now();
            }
            publication_tx.send(()).unwrap();
            until(&observed, &mut events, "complete-pending");
        } else {
            until(&observed, &mut events, "complete-pending");
            if !events.iter().any(|event| event.0 == "old-pending") {
                until(&observed, &mut events, "old-pending");
            }
            // Once transfer commits, even the original worker itself can be dropped.
            drop_tx.send(()).unwrap();
            until(&observed, &mut events, "old-drained");
        }
        assert!(
            events
                .iter()
                .all(|event| event.0 != "fault" && event.0 != "release")
        );
        complete_tx.send(()).unwrap();
        while events
            .iter()
            .filter(|event| event.0 == "worker-done")
            .count()
            < 3
        {
            until(&observed, &mut events, "worker-done");
        }
        assert!(events.iter().all(|event| event.0 != "fault"));
        assert_eq!(
            events.iter().filter(|event| event.0 == "release").count(),
            1
        );
        let replacement = events
            .iter()
            .find(|event| event.0 == "complete-pending")
            .unwrap()
            .1;
        assert!(
            events
                .iter()
                .filter(|event| event.0 == "release")
                .all(|event| event.1 == replacement)
        );
    }
}

#[test]
fn published_child_cancellation_drives_its_group_wait_before_release() {
    if !subprocess(
        "cancellation::tests::published_child_cancellation_drives_its_group_wait_before_release",
    ) {
        return;
    }
    let (proof, observed) = lifecycle_proof(false);
    let (complete_tx, complete_rx) = oneshot::channel();
    let (group_tx, group_rx) = oneshot::channel();
    *proof.complete.lock().unwrap() = Some(complete_rx);
    *proof.group.lock().unwrap() = Some(group_rx);
    *proof.sibling_done.lock().unwrap() = Some(group_tx);
    let mut abis = Abis::wasixv2();
    abis.push_instantiation_hook(Arc::new(LifecycleHook {
        proof: proof.clone(),
        image: vec![],
    }));
    let spawner = process::spawner(
        Store::default().engine().clone(),
        Arc::new(PendingControl(proof.clone())),
        Arc::new(ProofHost(proof.clone())),
        Arc::new(abis),
    );
    spawner.spawn_owned(
        TaskId(1),
        Image::copied(shared_module(false)).into(),
        crate::spawn_custody::Publication::test_child(TaskId(1)),
    );
    let mut events = Vec::new();
    until(&observed, &mut events, "complete-pending");
    proof
        .authority
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap()
        .request();
    until(&observed, &mut events, "group-wait");
    assert!(
        events
            .iter()
            .all(|event| event.0 != "release" && event.0 != "sibling-release")
    );
    complete_tx.send(()).unwrap();
    while events
        .iter()
        .filter(|event| event.0 == "worker-done")
        .count()
        < 2
    {
        until(&observed, &mut events, "worker-done");
    }
    let at = |phase| events.iter().position(|event| event.0 == phase).unwrap();
    assert!(at("fault") < at("group-wait"));
    assert!(at("sibling-release") < at("group-retired"));
    assert!(at("group-retired") < at("release"));
    for phase in ["fault", "release", "sibling-release"] {
        assert_eq!(events.iter().filter(|event| event.0 == phase).count(), 1);
    }
}

#[test]
fn cancellation_waits_for_an_actual_live_sibling_before_releasing_the_leader() {
    if !subprocess(
        "cancellation::tests::cancellation_waits_for_an_actual_live_sibling_before_releasing_the_leader",
    ) {
        return;
    }
    let (proof, observed) = lifecycle_proof(false);
    let (complete_tx, complete_rx) = oneshot::channel();
    let (group_tx, group_rx) = oneshot::channel();
    *proof.complete.lock().unwrap() = Some(complete_rx);
    *proof.group.lock().unwrap() = Some(group_rx);
    *proof.sibling_done.lock().unwrap() = Some(group_tx);
    let mut abis = Abis::wasixv2();
    abis.push_instantiation_hook(Arc::new(LifecycleHook {
        proof: proof.clone(),
        image: vec![],
    }));
    let engine = Store::default().engine().clone();
    let module = Module::new(&engine, shared_module(false)).unwrap();
    let mut caller = Box::pin(crate::run_on_owning_thread(
        engine,
        &module,
        Arc::new(PendingControl(proof.clone())),
        TaskId(1),
        Arc::new(ProofHost(proof)),
        Arc::new(abis),
    ));
    assert!(
        caller
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let mut events = Vec::new();
    until(&observed, &mut events, "complete-pending");
    drop(caller);
    until(&observed, &mut events, "group-wait");
    assert!(
        events
            .iter()
            .all(|event| event.0 != "release" && event.0 != "sibling-release")
    );
    complete_tx.send(()).unwrap();
    while events
        .iter()
        .filter(|event| event.0 == "worker-done")
        .count()
        < 2
    {
        until(&observed, &mut events, "worker-done");
    }
    let at = |phase| events.iter().position(|event| event.0 == phase).unwrap();
    assert!(at("fault") < at("group-wait"));
    assert!(at("sibling-release") < at("group-retired"));
    assert!(at("group-retired") < at("release"));
    for phase in ["fault", "release", "sibling-release"] {
        assert_eq!(events.iter().filter(|event| event.0 == phase).count(), 1);
    }
}

#[derive(Clone, Copy)]
enum CommittedStarter {
    Normal,
    Reject,
    Panic,
    Discard,
    Busy,
}
struct CommittedHost {
    proof: Arc<Proof>,
    mode: CommittedStarter,
}
impl Host for CommittedHost {
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
    fn executor(&self) -> &dyn Executor {
        self
    }
    fn report(&self, _: &str) {}
}
impl Executor for CommittedHost {
    fn spawn_local(&self, future: LocalFuture<'static, ()>) {
        ProofHost(self.proof.clone()).spawn_local(future);
    }
    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
        Box::pin(async move { work() })
    }
    fn spawn_thread(&self, start: ThreadStart) -> std::io::Result<()> {
        match self.mode {
            CommittedStarter::Busy => {
                ProofHost(self.proof.clone()).spawn_thread(Box::new(move || {
                    let busy = thread::OwningThread::acquire().unwrap();
                    let run = start();
                    Box::pin(async move {
                        run.await;
                        drop(busy);
                    })
                }))
            }
            CommittedStarter::Normal => ProofHost(self.proof.clone()).spawn_thread(start),
            CommittedStarter::Reject => Err(std::io::ErrorKind::Unsupported.into()),
            CommittedStarter::Panic => panic!("committed starter panic sentinel"),
            CommittedStarter::Discard => {
                drop(start);
                Ok(())
            }
        }
    }
}

#[test]
fn committed_cancellation_and_starter_failures_retain_predecessor_and_exact_terminal_custody() {
    if !subprocess(
        "cancellation::tests::committed_cancellation_and_starter_failures_retain_predecessor_and_exact_terminal_custody",
    ) {
        return;
    }
    struct Lease(Arc<std::sync::atomic::AtomicUsize>);
    impl crate::ExecProcessLease for Lease {}
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    use std::sync::atomic::{AtomicUsize, Ordering};
    for mode in [
        CommittedStarter::Normal,
        CommittedStarter::Reject,
        CommittedStarter::Panic,
        CommittedStarter::Discard,
        CommittedStarter::Busy,
    ] {
        let (proof, observed) = lifecycle_proof(false);
        let host = Arc::new(CommittedHost {
            proof: proof.clone(),
            mode,
        });
        let control = Arc::new(PendingControl(proof.clone()));
        let engine = Store::default().engine().clone();
        let retired = Arc::new(AtomicUsize::new(0));
        let image = process::ExecImage::new(
            Image::copied(vec![]),
            Some(Box::new(Lease(retired.clone()))),
        );
        let terminal = PreinstalledTerminalCustody::new(TaskId(1), image);
        let completion = Arc::new(process::Handoff::default());
        let mut abis = Abis::wasixv2();
        abis.push_instantiation_hook(Arc::new(LifecycleHook {
            proof: proof.clone(),
            image: vec![],
        }));
        let abis = Arc::new(abis);
        let (barrier_tx, barrier_rx) = oneshot::channel::<()>();
        let starter = start_committed_entry(
            engine.clone(),
            control.clone(),
            host.clone(),
            abis.clone(),
            Box::pin(async move {
                let _ = barrier_rx.await;
            }),
            terminal.clone(),
            completion.clone(),
        );
        // Drop even an entirely unpolled waiter. Cancellation must not drop the
        // predecessor receiver or the only replacement image/lease.
        drop(starter);
        assert_eq!(retired.load(Ordering::SeqCst), 0);
        let mut events = Vec::new();
        if matches!(mode, CommittedStarter::Normal | CommittedStarter::Busy) {
            until(&observed, &mut events, "worker-start");
        }
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.0, "fault" | "release"))
        );
        assert!(
            observed.try_recv().is_err(),
            "no terminal action before predecessor settlement"
        );
        let _ = barrier_tx.send(());
        let spawner = process::spawner(engine, control, host, abis);
        // This is the preinstalled old-thread owner, entered only once its real
        // predecessor keepalive has released the barrier above.
        futures::executor::block_on(spawner.retire_committed(terminal, completion));
        if matches!(mode, CommittedStarter::Normal | CommittedStarter::Busy) {
            until(&observed, &mut events, "worker-done");
        } else {
            while let Ok(event) = observed.try_recv() {
                events.push(event);
            }
        }
        assert_eq!(events.iter().filter(|event| event.0 == "fault").count(), 1);
        assert_eq!(
            events.iter().filter(|event| event.0 == "release").count(),
            1
        );
        assert_eq!(retired.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn detached_pending_successor_cancellation_waits_for_physical_and_loader_cleanup() {
    if subprocess(
        "cancellation::tests::detached_pending_successor_cancellation_waits_for_physical_and_loader_cleanup",
    ) {
        dropped_waiter_mode(true, true, true);
    }
}

#[test]
fn takeover_cancellation_latches_before_install_and_before_transfer_without_rebinding_predecessor()
{
    for before_transfer in [false, true] {
        let handoff = Arc::new(process::Handoff::default());
        let original = Cancellation::new(TaskId(1));
        handoff.bind_cancellation(Some(&original));
        let successor = Cancellation::new(TaskId(1));
        if before_transfer {
            original.request_process();
            let Transfer::Reserved(transfer) = original.transfer(TaskId(1)) else {
                panic!("original owner");
            };
            assert!(handoff.install_takeover(&successor));
            transfer.relinquish();
        } else {
            handoff.cancel_takeover();
            assert!(handoff.install_takeover(&successor));
        }
        assert!(successor.0.lock().unwrap().requested);
        original.0.lock().unwrap().image = None;
        handoff.bind_cancellation(Some(&original));
        assert!(
            original
                .0
                .lock()
                .unwrap()
                .image
                .as_ref()
                .is_some_and(|image| Arc::ptr_eq(image, &handoff)),
            "takeover installation preserves exact predecessor binding"
        );
        let unrelated = Cancellation::new(TaskId(1));
        assert!(
            !handoff.install_takeover(&unrelated),
            "never replace existing successor authority"
        );
        assert!(!unrelated.0.lock().unwrap().requested);
    }
    // Old image waiter cancellation deliberately leaves an accepted successor alone.
    let handoff = Arc::new(process::Handoff::default());
    let original = Cancellation::new(TaskId(1));
    handoff.bind_cancellation(Some(&original));
    let successor = Cancellation::new(TaskId(1));
    assert!(handoff.install_takeover(&successor));
    let Transfer::Reserved(transfer) = original.transfer(TaskId(1)) else {
        panic!("original owner");
    };
    transfer.relinquish();
    original.request();
    assert!(
        !successor.0.lock().unwrap().requested,
        "an old image waiter is not process cancellation authority"
    );
}

#[test]
fn detached_factory_failures_publish_only_after_single_release_and_lease_retirement() {
    struct ControlProbe {
        inner: PendingControl,
        handoff: std::sync::Weak<process::Handoff>,
        released: Arc<std::sync::atomic::AtomicBool>,
    }
    impl LoaderControl for ControlProbe {}
    impl Syscalls for ControlProbe {}
    impl Control for ControlProbe {
        fn take_pending(&self, task: TaskId) -> Option<GuestAction> {
            self.inner.take_pending(task)
        }
        fn fault(&self, task: TaskId, signal: i32) -> bool {
            let handoff = self.handoff.upgrade().unwrap();
            assert!(
                Box::pin(handoff.wait())
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            self.inner.fault(task, signal)
        }
        fn release(&self, task: TaskId) {
            let handoff = self.handoff.upgrade().unwrap();
            assert!(
                Box::pin(handoff.wait())
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "no completion before actual release"
            );
            assert!(
                !self
                    .released
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            );
            self.inner.release(task);
        }
    }
    struct Lease {
        released: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl crate::ExecProcessLease for Lease {}
    impl Drop for Lease {
        fn drop(&mut self) {
            assert!(self.released.load(std::sync::atomic::Ordering::SeqCst));
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    for mode in [
        CommittedStarter::Reject,
        CommittedStarter::Panic,
        CommittedStarter::Discard,
    ] {
        let (proof, observed) = lifecycle_proof(false);
        let handoff = Arc::new(process::Handoff::default());
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let control = Arc::new(ControlProbe {
            inner: PendingControl(proof.clone()),
            handoff: Arc::downgrade(&handoff),
            released: released.clone(),
        });
        let host = Arc::new(CommittedHost { proof, mode });
        process::spawner(
            Store::default().engine().clone(),
            control,
            host,
            Arc::new(Abis::wasixv2()),
        )
        .take_over(
            TaskId(1),
            process::ExecImage::new(
                Image::copied(vec![]),
                Some(Box::new(Lease {
                    released,
                    dropped: dropped.clone(),
                })),
            ),
            handoff.clone(),
        );
        assert!(
            Box::pin(handoff.wait())
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        let events: Vec<_> = observed.try_iter().map(|event| event.0).collect();
        assert_eq!(events, ["fault", "release"]);
    }
}
