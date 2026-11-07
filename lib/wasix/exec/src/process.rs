//! Process images: `execve` replaces the instance with a new one of the image the kernel
//! loaded, vfork switches an instance between the parent and child tasks, and a fork child
//! starts from a copy of its parent's instance.
//!
//! A task switch is one field, [`ExecEnv::task`], which every import reads on entry.
//!
//! A process's run usually follows it from instance to instance until it exits. One `execve`
//! moves it to another host thread: a thread's, while the leader waits for its vfork child
//! ([`GuestAction::StartImage`]). The new image then runs on its own, and the instance the
//! leader's old image ran in ends with the child ([`Ended::Detached`]); its run returns the
//! status of the run that took over, which it gets through the image's [`Handoff`].

use std::{
    future::{Future, poll_fn},
    sync::{Arc, Mutex, PoisonError},
    task::{Poll, Waker},
};

use wasixv2_abi::Signal;
use wasixv2_host::Host;
use wasixv2_syscalls::{Control, GuestAction, Image, Resume, Syscalls, TaskId};
use wasmer::{AsyncFunctionEnvMut, Engine, Function, Module, RuntimeError, Store, Value};

use crate::{Ended, ExecEnv, ExecError, abi::Abis, asyncify};

/// Raised from an import to unwind the old image after `execve`, carrying the new one.
#[derive(Debug, thiserror::Error)]
#[error("execve replaced the image")]
pub(crate) struct ExecNew(pub(crate) Arc<Handoff>);

/// The new image and lifetime-only registration moved out of its predecessor.
pub(crate) struct ExecImage {
    image: Image,
    lease: Option<Box<dyn crate::ExecProcessLease>>,
}
impl ExecImage {
    pub(crate) fn new(image: Image, lease: Option<Box<dyn crate::ExecProcessLease>>) -> Self {
        Self { image, lease }
    }
}
impl From<Image> for ExecImage {
    fn from(image: Image) -> Self {
        Self::new(image, None)
    }
}
impl std::ops::Deref for ExecImage {
    type Target = Image;
    fn deref(&self) -> &Self::Target {
        &self.image
    }
}
impl std::fmt::Debug for ExecImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecImage")
            .field("image", &self.image)
            .finish_non_exhaustive()
    }
}

/// Raised from an import to end an instance whose vfork child is done after the task the
/// instance's run belongs to went on in another instance ([`Resume::Gone`]).
///
/// [`Resume::Gone`]: wasixv2_syscalls::Resume::Gone
#[derive(Debug, thiserror::Error)]
#[error("the vfork parent's image went on in another instance")]
pub(crate) struct Detached(pub(crate) Arc<Handoff>);

/// Where the run that takes over a process leaves its result for the run it took over from,
/// shared by the instances of one process image: the process instance and its threads'. Only
/// one run takes over from an image, as the image is dead to every thread once it did.
#[derive(Default)]
pub(crate) struct Handoff(Mutex<HandoffState>);

#[derive(Default)]
struct HandoffState {
    result: Option<Result<i32, ExecError>>,
    /// The result was taken.
    taken: bool,
    waker: Option<Waker>,
    cancellation: Option<crate::cancellation::WeakCancellation>,
    process: Option<(TaskId, Option<Box<dyn crate::ExecProcessLease>>)>,
    process_moved: bool,
    pending: Option<PendingOutcome>,
    committed: bool,
    claimed: bool,
    retired: bool,
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    takeover: Option<crate::cancellation::WeakCancellation>,
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    takeover_requested: bool,
}

pub(crate) enum PendingOutcome {
    Exec { task: TaskId, image: ExecImage },
    Detached,
}

impl std::fmt::Debug for Handoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handoff").finish_non_exhaustive()
    }
}

impl Handoff {
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn install_takeover(
        &self,
        cancellation: &crate::cancellation::Cancellation,
    ) -> bool {
        let requested = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.takeover.is_some() {
                return false;
            }
            state.takeover = Some(cancellation.downgrade());
            state.takeover_requested
        };
        if requested {
            cancellation.request_process();
        }
        true
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn cancel_takeover(&self) {
        let successor = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.takeover_requested = true;
            state.takeover.clone()
        };
        if let Some(successor) = successor.and_then(|successor| successor.upgrade()) {
            successor.request_process();
        }
    }

    pub(crate) fn publish(&self, outcome: PendingOutcome) -> Result<(), RuntimeError> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.committed || state.retired {
            drop(state);
            drop(outcome);
            return Err(RuntimeError::new(
                "image handoff is already committed or retired",
            ));
        }
        state.pending = Some(outcome);
        state.committed = true;
        Ok(())
    }

    pub(crate) fn is_committed(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .committed
    }

    pub(crate) fn is_pending(&self) -> bool {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.committed && !state.claimed && !state.retired
    }

    pub(crate) fn claim(&self) -> Result<PendingOutcome, RuntimeError> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.claimed || state.retired {
            return Err(RuntimeError::new(
                "image handoff was already claimed or retired",
            ));
        }
        let outcome = state
            .pending
            .take()
            .ok_or_else(|| RuntimeError::new("no committed image handoff"))?;
        state.claimed = true;
        Ok(outcome)
    }

    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn retire_pending(&self) -> Option<PendingOutcome> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.retired = true;
        state.pending.take()
    }

    pub(crate) fn retain_process<S: 'static>(
        &self,
        task: TaskId,
        abi: &dyn crate::AbiInstance<S>,
    ) -> Result<(), RuntimeError> {
        {
            let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.process_moved {
                return Err(RuntimeError::new(
                    "process execution custody was transferred",
                ));
            }
            if let Some((owner, _)) = &state.process {
                return if *owner == task {
                    Ok(())
                } else {
                    Err(RuntimeError::new(
                        "process execution custody belongs to another leader",
                    ))
                };
            }
        }
        // The ABI can lock its registry or destroy rejected custody. Never call it
        // while holding the handoff's state lock.
        let lease = abi.retain_exec_process(task)?;
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.process_moved || state.process.is_some() {
            drop(state);
            drop(lease);
            return Err(RuntimeError::new(
                "process execution custody was already installed",
            ));
        }
        state.process = Some((task, lease));
        Ok(())
    }

    fn owns_process(&self, task: TaskId) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .process
            .as_ref()
            .is_some_and(|(owner, _)| *owner == task)
    }

    fn take_process(
        &self,
        task: TaskId,
    ) -> Result<Option<Box<dyn crate::ExecProcessLease>>, RuntimeError> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.process_moved
            || !state
                .process
                .as_ref()
                .is_some_and(|(owner, _)| *owner == task)
        {
            return Err(RuntimeError::new(
                "exact process execution custody is missing",
            ));
        }
        let (_, lease) = state.process.take().expect("checked process");
        state.process_moved = true;
        Ok(lease)
    }

    pub(crate) fn retire_process(&self) {
        let process = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.process_moved = true;
            state.process.take()
        };
        drop(process);
    }

    /// Cancellation authority follows only this exact image; result delivery is unchanged.
    pub(crate) fn bind_cancellation(
        self: &Arc<Self>,
        cancellation: Option<&crate::cancellation::Cancellation>,
    ) {
        let Some(cancellation) = cancellation else {
            return;
        };
        let (accepted, previous) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let previous = state
                .cancellation
                .as_ref()
                .and_then(|owner| owner.upgrade());
            let accepted = previous
                .as_ref()
                .is_none_or(|owner| owner.same(cancellation));
            if accepted {
                state.cancellation = Some(cancellation.downgrade());
            }
            (accepted, previous)
        };
        drop(previous);
        if accepted {
            cancellation.bind_image(self.clone());
        }
    }
    pub(crate) fn cancellation(&self) -> Option<crate::cancellation::Cancellation> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cancellation
            .as_ref()
            .and_then(|owner| owner.upgrade())
    }

    /// The run that took over ended with `result`; only the first result counts.
    pub(crate) fn complete(&self, result: Result<i32, ExecError>) {
        let waker = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.taken || state.result.is_some() {
                return;
            }
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Waits for the run that took over to end, and returns how it ended.
    pub(crate) async fn wait(&self) -> Result<i32, ExecError> {
        poll_fn(|cx| {
            let next = cx.waker().clone();
            let (result, old_waker) = {
                let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
                match state.result.take() {
                    Some(result) => {
                        state.taken = true;
                        (Some(result), state.waker.take())
                    }
                    None => (None, state.waker.replace(next)),
                }
            };
            drop(old_waker);
            result.map_or(Poll::Pending, Poll::Ready)
        })
        .await
    }
}

/// The run that takes over a process, once it runs, with the [`Handoff`] it reports to. A run
/// the host drops before it ends reports [`ExecError::Dropped`]. (One the host never starts
/// reports what killing the process gave; see [`Spawner::take_over`].)
pub(crate) struct Takeover(pub(crate) Arc<Handoff>);

impl Takeover {
    pub(crate) fn report(self, result: Result<i32, ExecError>) {
        self.0.complete(result);
    }
}

impl Drop for Takeover {
    fn drop(&mut self) {
        self.0.complete(Err(ExecError::Dropped));
    }
}

/// Starts the processes an instance creates on instances of their own: the image of a vfork
/// child that called `execve`, a fork child, and the new image of a leader that waits for its
/// vfork child; the type-erased part of the execution layer that the return-to-guest path can
/// reach.
pub(crate) trait Spawn: Send + Sync {
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn start_committed(
        &self,
        terminal: crate::PreinstalledTerminalCustody,
        predecessor: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
        completion: Arc<Handoff>,
    ) -> Result<crate::OwnedEntryWaiter, ExecError>;
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn retire_committed(
        &self,
        terminal: crate::PreinstalledTerminalCustody,
        completion: Arc<Handoff>,
    ) -> wasixv2_host::LocalFuture<'static, ()>;
    fn spawn(&self, task: TaskId, image: ExecImage);
    fn spawn_owned(&self, _: TaskId, _: ExecImage, _: crate::spawn_custody::Publication) {
        panic!("this spawner does not accept host-only child custody")
    }
    fn fork(&self, task: TaskId, image: asyncify::ForkImage);
    /// Starts `image` as `task`, whose run goes on there, and reports how it ends to
    /// `handoff`.
    fn take_over(&self, task: TaskId, image: ExecImage, handoff: Arc<Handoff>);
}

pub(crate) struct Spawner<S> {
    engine: Engine,
    syscalls: Arc<S>,
    host: Arc<dyn Host>,
    /// The ABIs the images of the processes it starts select from.
    abis: Arc<Abis<S>>,
}

pub(crate) fn spawner<S>(
    engine: Engine,
    syscalls: Arc<S>,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
) -> Arc<dyn Spawn>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    Arc::new(Spawner {
        engine,
        syscalls,
        host,
        abis,
    })
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[derive(Clone, Copy)]
enum RetirementPhase {
    Admission,
    Fault,
    Actions,
    Group,
    Release,
    Image,
    Publish,
    Finished,
    Done,
}

/// The same claimed entry and pending group observation survive every Pending.
/// All finite synchronous teardown panics are delayed until terminal settlement;
/// no generic Control future is reconstructed or repolled after a panic.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
struct CommittedRetirement<S> {
    syscalls: Arc<S>,
    terminal: crate::PreinstalledTerminalCustody,
    completion: Arc<Handoff>,
    phase: RetirementPhase,
    entry: Option<ExecImage>,
    waiting: Option<wasixv2_host::LocalFuture<'static, ()>>,
    opaque_panicked: bool,
    observation_completed: std::rc::Rc<std::cell::Cell<bool>>,
    first: Option<Box<dyn std::any::Any + Send>>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl<S: Control + 'static> CommittedRetirement<S> {
    fn new(
        syscalls: Arc<S>,
        terminal: crate::PreinstalledTerminalCustody,
        completion: Arc<Handoff>,
    ) -> Self {
        let admission = terminal.clone();
        Self {
            syscalls,
            terminal,
            completion,
            phase: RetirementPhase::Admission,
            entry: None,
            waiting: Some(Box::pin(async move { admission.retirement_ready().await })),
            opaque_panicked: false,
            observation_completed: std::rc::Rc::new(std::cell::Cell::new(false)),
            first: None,
        }
    }
    fn remember(&mut self, panic: Box<dyn std::any::Any + Send>) {
        if self.first.is_none() {
            self.first = Some(panic);
        } else {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(panic)));
        }
    }
    fn observation_ready(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        if self.opaque_panicked {
            return false;
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.waiting.as_mut().unwrap().as_mut().poll(cx)
        })) {
            Ok(Poll::Ready(())) => true,
            Ok(Poll::Pending) => false,
            Err(panic) => {
                self.remember(panic);
                if self.observation_completed.get() {
                    // Actual Ready was observed BEFORE consuming the completed
                    // observer's destructor. Its finite Drop failure must not
                    // turn physical settlement into an opaque-future retry.
                    return true;
                }
                // Generic Control supplies no recovery/retry contract. Keep
                // the SAME observer and claimed entry in this owned state;
                // never unwind them away, repoll, recreate or fake settlement.
                self.opaque_panicked = true;
                false
            }
        }
    }
    fn attempt(&mut self, action: impl FnOnce(&mut Self)) -> bool {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(self))) {
            Ok(()) => true,
            Err(panic) => {
                self.remember(panic);
                false
            }
        }
    }
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl<S: Control + 'static> Future for CommittedRetirement<S> {
    type Output = ();
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.opaque_panicked {
            return Poll::Pending;
        }
        loop {
            match this.phase {
                RetirementPhase::Admission => {
                    if !this.observation_ready(cx) {
                        return Poll::Pending;
                    }
                    this.attempt(|this| drop(this.waiting.take()));
                    this.entry = this.terminal.claim_fallback();
                    this.phase = if this.entry.is_some() {
                        RetirementPhase::Fault
                    } else {
                        RetirementPhase::Done
                    };
                }
                RetirementPhase::Fault => {
                    this.phase = RetirementPhase::Actions;
                    // Consume fault exactly once. Its original exit_status /
                    // take_pending work is a separate resumable phase below.
                    this.attempt(|this| {
                        this.syscalls.fault(this.terminal.task(), Signal::SIGSEGV.0);
                    });
                }
                RetirementPhase::Actions => {
                    // take_pending runs kernel vfork/ptrace/exit work, not just
                    // an exit-code read. Consume each Copy action once before
                    // asking for the next, preserving the original work drain.
                    let mut action = None;
                    if !this.attempt(|this| {
                        action = this.syscalls.take_pending(this.terminal.task());
                    }) {
                        this.opaque_panicked = true;
                        return Poll::Pending;
                    }
                    if action.is_some() {
                        continue;
                    }
                    this.phase = RetirementPhase::Group;
                    let syscalls = this.syscalls.clone();
                    let task = this.terminal.task();
                    let completed = this.observation_completed.clone();
                    completed.set(false);
                    this.waiting = Some(Box::pin(async move {
                        let mut actual = Some(syscalls.group_wait(task));
                        let mut unknown = None;
                        // Catch INSIDE this owning async frame: unwinding an
                        // outer `.await` would drop the actual borrowed Control
                        // observer before its enclosing state could latch it.
                        poll_fn(|cx| {
                            if unknown.is_some() {
                                return Poll::Pending;
                            }
                            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                actual.as_mut().unwrap().as_mut().poll(cx)
                            })) {
                                Ok(Poll::Pending) => Poll::Pending,
                                Ok(Poll::Ready(())) => {
                                    completed.set(true);
                                    Poll::Ready(())
                                }
                                Err(panic) => {
                                    unknown = Some(panic);
                                    Poll::Pending
                                }
                            }
                        })
                        .await;
                        // Take BEFORE Drop; outer progress distinguishes this
                        // completed-observer destructor panic from a poll panic.
                        drop(actual.take());
                    }));
                }
                RetirementPhase::Group => {
                    if !this.observation_ready(cx) {
                        return Poll::Pending;
                    }
                    this.phase = RetirementPhase::Release;
                    this.attempt(|this| drop(this.waiting.take()));
                }
                RetirementPhase::Release => {
                    this.phase = RetirementPhase::Image;
                    this.attempt(|this| this.syscalls.release(this.terminal.task()));
                }
                RetirementPhase::Image => {
                    this.phase = RetirementPhase::Publish;
                    this.attempt(|this| drop(this.entry.take()));
                }
                RetirementPhase::Publish => {
                    this.phase = RetirementPhase::Finished;
                    this.attempt(|this| this.completion.complete(Err(ExecError::Dropped)));
                }
                RetirementPhase::Finished => {
                    this.phase = RetirementPhase::Done;
                    this.attempt(|this| this.terminal.mark_finished());
                }
                RetirementPhase::Done => {
                    if let Some(panic) = this.first.take() {
                        std::panic::resume_unwind(panic);
                    }
                    return Poll::Ready(());
                }
            }
        }
    }
}

impl<S> Spawn for Spawner<S>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn start_committed(
        &self,
        terminal: crate::PreinstalledTerminalCustody,
        predecessor: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
        completion: Arc<Handoff>,
    ) -> Result<crate::OwnedEntryWaiter, ExecError> {
        crate::cancellation::start_committed_entry(
            self.engine.clone(),
            self.syscalls.clone(),
            self.host.clone(),
            self.abis.clone(),
            predecessor,
            terminal,
            completion,
        )
    }

    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn retire_committed(
        &self,
        terminal: crate::PreinstalledTerminalCustody,
        completion: Arc<Handoff>,
    ) -> wasixv2_host::LocalFuture<'static, ()> {
        Box::pin(CommittedRetirement::new(
            self.syscalls.clone(),
            terminal,
            completion,
        ))
    }

    fn spawn(&self, task: TaskId, image: ExecImage) {
        self.spawn_image_owned(task, image, None);
    }
    fn spawn_owned(
        &self,
        task: TaskId,
        image: ExecImage,
        publication: crate::spawn_custody::Publication,
    ) {
        self.spawn_image_owned(task, image, Some(publication));
    }

    fn fork(&self, task: TaskId, image: asyncify::ForkImage) {
        let (engine, syscalls, host, abis) = (
            self.engine.clone(),
            self.syscalls.clone(),
            self.host.clone(),
            self.abis.clone(),
        );
        // Without a thread the process died; nothing waits for its status.
        let _ = self.start(task, move |cleanup| {
            let run = run_forked(engine, image, syscalls.clone(), task, host, abis, cleanup);
            async move {
                let result = crate::catch_panic(run)
                    .await
                    .unwrap_or_else(|panic| Err(crate::host_panicked(&*syscalls, task, panic)));
                report_failure(task, result);
            }
        });
    }

    fn take_over(&self, task: TaskId, image: ExecImage, handoff: Arc<Handoff>) {
        let transfer = handoff
            .cancellation()
            .map(|authority| authority.transfer(task));
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        if matches!(transfer, Some(crate::cancellation::Transfer::Refused)) {
            handoff.complete(Err(ExecError::Dropped));
            return;
        }
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        crate::cancellation::start_takeover(
            self.engine.clone(),
            image,
            self.syscalls.clone(),
            task,
            self.host.clone(),
            self.abis.clone(),
            handoff.clone(),
        );
        #[cfg(not(all(feature = "sys", not(target_arch = "wasm32"))))]
        {
            let (engine, syscalls, host, abis) = (
                self.engine.clone(),
                self.syscalls.clone(),
                self.host.clone(),
                self.abis.clone(),
            );
            let done = handoff.clone();
            let started = self.start(task, move |cleanup| {
                let takeover = Takeover(done);
                let run = run_new_image(engine, image, syscalls, task, host, abis, cleanup);
                async move { takeover.report(run.await) }
            });
            // The process died of SIGSEGV, as one whose image cannot start does.
            if let Err(status) = started {
                handoff.complete(Ok(status));
            }
        }
        if let Some(crate::cancellation::Transfer::Reserved(transfer)) = transfer {
            // Successful spawn owns release. Failed spawn already faulted and
            // released the task through start's existing failure path.
            transfer.relinquish();
        }
    }
}

/// Logs a process image that failed; its run ended the process.
fn report_failure(task: TaskId, result: Result<i32, ExecError>) {
    if let Err(err) = result {
        tracing::warn!(tid = task.0, %err, "process image failed");
    }
}

impl<S> Spawner<S>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    fn spawn_image_owned(
        &self,
        task: TaskId,
        image: ExecImage,
        publication: Option<crate::spawn_custody::Publication>,
    ) {
        let (engine, syscalls, host, abis) = (
            self.engine.clone(),
            self.syscalls.clone(),
            self.host.clone(),
            self.abis.clone(),
        );
        // Without a thread the process died; nothing waits for its status.
        let _ = self.start_inner(
            task,
            move |cleanup| {
                let run = run_new_image(engine, image, syscalls, task, host, abis, cleanup);
                async move { report_failure(task, run.await) }
            },
            publication,
        );
    }

    /// Runs the process `task` on a host thread of its own. The run ends the process itself when
    /// its image fails; when no thread can start, the process dies of SIGSEGV here, and
    /// `Err` has its status.
    fn start<F, R>(&self, task: TaskId, run: R) -> Result<(), i32>
    where
        R: FnOnce(crate::cleanup::RunCleanup) -> F + Send + 'static,
        F: Future<Output = ()> + 'static,
    {
        self.start_inner(task, run, None)
    }

    fn start_inner<F, R>(
        &self,
        task: TaskId,
        run: R,
        publication: Option<crate::spawn_custody::Publication>,
    ) -> Result<(), i32>
    where
        R: FnOnce(crate::cleanup::RunCleanup) -> F + Send + 'static,
        F: Future<Output = ()> + 'static,
    {
        let startup = publication
            .as_ref()
            .map(|publication| publication.startup(self.syscalls.clone(), task));
        let owned = startup.is_some();
        let finished = startup.as_ref().map(|startup| startup.finished.clone());
        let entered = startup.as_ref().map(|startup| startup.entered.clone());
        let terminal = startup.as_ref().map(|startup| startup.terminal.clone());
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        let authority = startup.as_ref().map(|startup| startup.authority.clone());
        let host = self.host.clone();
        let syscalls = self.syscalls.clone();
        let owning_thread = self.abis.requires_owning_thread();
        #[cfg(feature = "sys")]
        let native = self.engine.is_sys();
        #[cfg(not(feature = "sys"))]
        let native = false;
        let start = Box::new(move || {
            let profile = crate::thread::OwningThread::required(owning_thread);
            let cleanup =
                crate::cleanup::RunCleanup::new(wasixv2_host::LoaderCleanup::new(host), native);
            #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
            let cleanup = match authority {
                Some(authority) => cleanup.with_cancellation(authority),
                None => cleanup,
            };
            let scope = cleanup.clone();
            #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
            let terminal_authority = cleanup.cancellation().cloned();
            Box::pin(async move {
                let profile = match profile {
                    Ok(profile) => profile,
                    Err(error) => {
                        // Construct/drop the engine-free future so Takeover
                        // still reports to its waiting parent; do not poll it.
                        let dropped =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                drop(run(scope))
                            }));
                        let error = match dropped {
                            Ok(()) if owned => error,
                            Ok(()) => crate::reject_profile(&*syscalls, task, error),
                            Err(panic) if owned => crate::panic_error(task, panic),
                            Err(panic) => crate::host_panicked(&*syscalls, task, panic),
                        };
                        report_failure(task, Err(error));
                        return;
                    }
                };
                // Once entered, the executor must drive this worker through cancellation,
                // physical retirement and group_wait. It may discard a never-polled factory,
                // or an old worker whose authority already transferred to its successor.
                if let Some(entered) = entered {
                    entered.store(true, std::sync::atomic::Ordering::Release);
                }
                let terminal_syscalls = syscalls.clone();
                match profile {
                    Some(profile) => {
                        let guest = async move {
                            let cancellation = scope.cancellation().cloned();
                            if crate::cancellation::execution(cancellation.as_ref(), async move {
                                Box::pin(run(scope)).await
                            })
                            .await
                            .is_some()
                                && let Some(finished) = finished
                            {
                                finished.store(true, std::sync::atomic::Ordering::Release);
                            }
                        };
                        if let Err(panic) =
                            crate::catch_panic(profile.run_with_keepalive(&cleanup, guest, startup))
                                .await
                        {
                            let error = if owned {
                                crate::panic_error(task, panic)
                            } else {
                                crate::host_panicked(&*syscalls, task, panic)
                            };
                            report_failure(task, Err(error));
                        }
                    }
                    None => {
                        cleanup
                            .run_with_keepalive(
                                async move {
                                    let cancellation = scope.cancellation().cloned();
                                    let result =
                                        crate::catch_panic(crate::cancellation::execution(
                                            cancellation.as_ref(),
                                            async move { Box::pin(run(scope)).await },
                                        ))
                                        .await;
                                    if let Err(panic) = result {
                                        let error = if owned {
                                            crate::panic_error(task, panic)
                                        } else {
                                            crate::host_panicked(&*syscalls, task, panic)
                                        };
                                        report_failure(task, Err(error));
                                    } else if matches!(result, Ok(Some(())))
                                        && let Some(finished) = finished
                                    {
                                        finished.store(true, std::sync::atomic::Ordering::Release);
                                    }
                                },
                                startup,
                            )
                            .await
                    }
                }
                if terminal
                    .as_ref()
                    .is_some_and(|terminal| terminal.load(std::sync::atomic::Ordering::Acquire))
                {
                    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
                    if terminal_authority
                        .as_ref()
                        .expect("published child authority")
                        .terminal_owner()
                        .await
                        .is_some()
                    {
                        return;
                    }
                    terminal_syscalls.fault(task, Signal::SIGSEGV.0);
                    finish_task(&*terminal_syscalls, task).await;
                }
            }) as wasixv2_host::LocalFuture<'static, ()>
        });
        if let Some(publication) = publication {
            publication.accept();
        }
        if let Err(err) = self.host.executor().spawn_thread(start) {
            tracing::warn!(%err, "cannot start a process on a thread of its own");
            if owned {
                return Err(128 + Signal::SIGSEGV.0);
            }
            let status = fault(&*self.syscalls, task, Signal::SIGSEGV.0);
            self.syscalls.release(task);
            return Err(status);
        }
        Ok(())
    }
}

/// Runs `module` as `task`, then every image its `execve` calls load, until the process exits;
/// releases the task then.
pub(crate) async fn run<S>(
    store: Store,
    module: &Module,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cleanup: crate::cleanup::RunCleanup,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let engine = store.engine().clone();
    let Some(first) = crate::cancellation::execution(
        cleanup.cancellation(),
        crate::run_image(
            store,
            module,
            syscalls.clone(),
            task,
            host.clone(),
            abis.clone(),
            cleanup.clone(),
        ),
    )
    .await
    else {
        return Err(ExecError::Dropped);
    };
    finish(engine, first, syscalls, task, host, abis, cleanup).await
}

/// Runs a fork child from the copy of its parent's instance, then every image its `execve`
/// calls load, until the process exits; releases the task then.
async fn run_forked<S>(
    engine: Engine,
    image: asyncify::ForkImage,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cleanup: crate::cleanup::RunCleanup,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let store = Store::new(engine.clone());
    let first = crate::run_forked(
        store,
        image,
        syscalls.clone(),
        task,
        host.clone(),
        abis.clone(),
        cleanup.clone(),
    )
    .await;
    finish(engine, first, syscalls, task, host, abis, cleanup).await
}

/// Runs `image`, which `kernel_execve` made `task`'s, then every image its `execve` calls load,
/// until the process exits; releases the task then. `engine` is the engine the process would
/// have run on, which the loader may compile with.
///
/// Only the images the process's own `execve` calls load die of SIGSEGV when they do not start:
/// `image` is the embedder's program, so it fails as [`run`]'s module does, with the error, the
/// process killed.
pub(crate) async fn run_exec<S>(
    mut engine: Engine,
    image: Image,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cleanup: crate::cleanup::RunCleanup,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let Some(waited) =
        crate::cancellation::execution(cleanup.cancellation(), syscalls.exec_wait(task)).await
    else {
        return Err(ExecError::Dropped);
    };
    let first = match waited {
        // Killed meanwhile: it ends as the kill says.
        Err(status) => Ok(Ended::Exited(status)),
        Ok(()) => {
            let Some(loaded) = crate::cancellation::execution(
                cleanup.cancellation(),
                abis.loader().load(&engine, &image),
            )
            .await
            else {
                return Err(ExecError::Dropped);
            };
            drop(image);
            match loaded {
                Ok((image_engine, module)) => {
                    engine = image_engine;
                    let store = Store::new(engine.clone());
                    let run = crate::run_image(
                        store,
                        &module,
                        syscalls.clone(),
                        task,
                        host.clone(),
                        abis.clone(),
                        cleanup.clone(),
                    );
                    let Some(ended) =
                        crate::cancellation::execution(cleanup.cancellation(), run).await
                    else {
                        return Err(ExecError::Dropped);
                    };
                    ended
                }
                Err(err) => Err(ExecError::Load(err)),
            }
        }
    };
    finish(engine, first, syscalls, task, host, abis, cleanup).await
}

/// A default/noop ABI preserves its predecessor's compat custody. A successor
/// that supplies ownership has already installed its new token before entry.
fn keep_process_lease(
    current: &mut Option<Box<dyn crate::ExecProcessLease>>,
    successor: Option<Box<dyn crate::ExecProcessLease>>,
) {
    if let Some(successor) = successor {
        let previous = current.replace(successor);
        drop(previous);
    }
}

/// Follows `task`'s process from the end of its first image's run through the images its
/// `execve` calls load, until it exits; releases the task then. An image that cannot start kills
/// the process with SIGSEGV.
async fn finish<S>(
    mut engine: Engine,
    first: Result<Ended, ExecError>,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cleanup: crate::cleanup::RunCleanup,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let mut ended = match first {
        Ok(ended) => ended,
        Err(err) => {
            fault(&*syscalls, task, Signal::SIGSEGV.0);
            syscalls.release(task);
            return Err(err);
        }
    };
    let mut process_lease = None;
    let status = loop {
        let mut image = match ended {
            // The task runs on in the instance that took over, which releases it.
            Ended::Detached(handoff) => return handoff.wait().await,
            Ended::Exited(status) => break status,
            Ended::Fault {
                task: at,
                signal,
                killed,
                report,
                handoff,
            } => match fault_in(&*syscalls, &*host, task, at, (signal, killed), &report) {
                Some(status) => break status,
                // The trap was the vfork child's whose parent went on elsewhere.
                None => {
                    let handoff = handoff.expect("only an instance's trap leaves a vfork parent");
                    return handoff.wait().await;
                }
            },
            Ended::Exec(image) => image,
        };
        keep_process_lease(&mut process_lease, image.lease.take());
        // `de_thread`: the old image is gone from every thread before the new one starts.
        let Some(waited) =
            crate::cancellation::execution(cleanup.cancellation(), syscalls.exec_wait(task)).await
        else {
            return Err(ExecError::Dropped);
        };
        if let Err(status) = waited {
            break status;
        }
        let Some(loaded) = crate::cancellation::execution(
            cleanup.cancellation(),
            abis.loader().load(&engine, &image),
        )
        .await
        else {
            return Err(ExecError::Dropped);
        };
        drop(image);
        ended = match loaded {
            Ok((image_engine, module)) => {
                engine = image_engine;
                let store = Store::new(engine.clone());
                let run = crate::run_image(
                    store,
                    &module,
                    syscalls.clone(),
                    task,
                    host.clone(),
                    abis.clone(),
                    cleanup.clone(),
                );
                let Some(ended) = crate::cancellation::execution(cleanup.cancellation(), run).await
                else {
                    return Err(ExecError::Dropped);
                };
                ended.unwrap_or_else(|err| Ended::Fault {
                    task,
                    handoff: None,
                    signal: Signal::SIGSEGV.0,
                    killed: None,
                    report: format!(
                        "wasixv2: cannot start the image process {} loaded with execve, \
                         killing it with SIGSEGV: {err}",
                        task.0
                    ),
                })
            }
            // Past the point of no return, a binary that does not load is a SIGSEGV.
            Err(err) => Ended::Fault {
                task,
                handoff: None,
                signal: Signal::SIGSEGV.0,
                killed: None,
                report: format!(
                    "wasixv2: process {} loaded a module with execve that does not compile, \
                     killing it with SIGSEGV: {err}",
                    task.0
                ),
            },
        };
    };
    finish_task(&*syscalls, task).await;
    Ok(status)
}

/// A zombie leader stays until its group is empty, including after cancellation.
pub(crate) async fn finish_task<S: Control>(syscalls: &S, task: TaskId) {
    syscalls.group_wait(task).await;
    syscalls.release(task);
}

/// The image of a vfork child's `execve`.
pub(crate) async fn run_new_image<S>(
    engine: Engine,
    mut image: ExecImage,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cleanup: crate::cleanup::RunCleanup,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let _process = image.lease.take();
    // `de_thread`: the old image is gone from every thread before the new one starts.
    if let Err(status) = syscalls.exec_wait(task).await {
        syscalls.group_wait(task).await;
        syscalls.release(task);
        return Ok(status);
    }
    let loaded = abis.loader().load(&engine, &image).await;
    drop(image);
    let (engine, module) = match loaded {
        Ok(loaded) => loaded,
        Err(err) => {
            tracing::warn!(tid = task.0, %err, "execve loaded a module that does not compile");
            let status = fault(&*syscalls, task, Signal::SIGSEGV.0);
            syscalls.release(task);
            return Ok(status);
        }
    };
    // Preserve the public runner's panic result before Takeover reports it, while
    // sharing this worker's cleanup scope instead of creating a nested runner.
    let run = run(
        Store::new(engine),
        &module,
        syscalls.clone(),
        task,
        host,
        abis,
        cleanup,
    );
    crate::catch_panic(run)
        .await
        .unwrap_or_else(|panic| Err(crate::host_panicked(&*syscalls, task, panic)))
}

/// Kills `task`'s thread group with the fault `signal` and returns its exit status.
pub(crate) fn fault<S: Control>(syscalls: &S, task: TaskId, signal: i32) -> i32 {
    syscalls.fault(task, signal);
    exit_status(syscalls, task)
}

/// A trap of the instance of `task` while it ran as `at`: `task` itself, or a vfork child
/// running in its instance. The child dies of the fault; the parent's stack went with the
/// instance, so it cannot resume either and dies of SIGSEGV, unless the parent went on in
/// another instance ([`Resume::Gone`]), where it is not touched: then `None`, and the run
/// ends with the one that took over. `report` goes to `host` when the fault kills a process:
/// a trap while its group is exiting anyway is part of tearing it down. Returns `task`'s exit
/// status.
pub(crate) fn fault_in<S: Control>(
    syscalls: &S,
    host: &dyn Host,
    task: TaskId,
    at: TaskId,
    (signal, killed): (i32, Option<bool>),
    report: &str,
) -> Option<i32> {
    if killed.unwrap_or_else(|| syscalls.fault(at, signal)) {
        host.report(report);
    }
    if at == task {
        return Some(exit_status(syscalls, task));
    }
    // The child's end, which its exit queued, says what becomes of the parent.
    let mut gone = false;
    while let Some(action) = syscalls.take_pending(at) {
        if let GuestAction::VforkReturn { parent, .. } = action {
            gone |= parent.resumes == Resume::Gone;
        }
    }
    syscalls.release(at);
    (!gone).then(|| fault(syscalls, task, Signal::SIGSEGV.0))
}

/// The status of the exit pending on `task`, taking everything else that is.
pub(crate) fn exit_status<S: Control>(syscalls: &S, task: TaskId) -> i32 {
    let mut status = 128 + Signal::SIGKILL.0;
    while let Some(action) = syscalls.take_pending(task) {
        if let GuestAction::Exit(exit) = action {
            status = exit;
        }
    }
    status
}

/// Makes the instance behind `env` run as `task` from now on.
pub(crate) async fn switch<S: Control + 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    task: TaskId,
) {
    env.write().await.data_mut().switch(task);
}

/// Starts the image `task` loaded with `execve` while it was a vfork child.
pub(crate) fn pending_marker(error: &RuntimeError) -> Option<&Arc<Handoff>> {
    error
        .downcast_ref::<ExecNew>()
        .map(|marker| &marker.0)
        .or_else(|| error.downcast_ref::<Detached>().map(|marker| &marker.0))
}

pub(crate) async fn commit_exec<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    task: TaskId,
    image: Image,
) -> RuntimeError {
    let image = match exec_image(env, task, image).await {
        Ok(image) => image,
        Err(error) => return error,
    };
    let handoff = env.read().await.data().proc.handoff.clone();
    if let Err(error) = handoff.publish(PendingOutcome::Exec { task, image }) {
        return error;
    }
    RuntimeError::host_abort(Box::new(ExecNew(handoff)))
}

pub(crate) async fn commit_detached<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
) -> RuntimeError {
    let handoff = env.read().await.data().proc.handoff.clone();
    if let Err(error) = handoff.publish(PendingOutcome::Detached) {
        return error;
    }
    RuntimeError::host_abort(Box::new(Detached(handoff)))
}

pub(crate) async fn exec_image<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    process: TaskId,
    image: Image,
) -> Result<ExecImage, RuntimeError> {
    let (handoff, abi) = {
        let guard = env.read().await;
        (guard.data().proc.handoff.clone(), guard.data().abi.clone())
    };
    let lease = if handoff.owns_process(process) {
        handoff.take_process(process)?
    } else {
        // A shared-instance vfork child already owns this lease in its ABI record.
        abi.ok_or_else(|| RuntimeError::new("exec before ABI binding"))?
            .retain_exec_process(process)?
    };
    Ok(ExecImage::new(image, lease))
}

/// Starts the image of a vfork child, with custody taken before its record is removed.
pub(crate) async fn spawn_image<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    task: TaskId,
    image: ExecImage,
    publication: Option<crate::spawn_custody::Publication>,
) {
    let spawner = env.read().await.data().proc.spawner.clone();
    match publication {
        Some(publication) => spawner.spawn_owned(task, image, publication),
        None => spawner.spawn(task, image),
    }
}

/// Starts a leader's replacement without looking up a registration its old image retired.
pub(crate) async fn take_over<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    task: TaskId,
    image: ExecImage,
) {
    let (spawner, handoff) = {
        let env = env.read().await;
        let proc = &env.data().proc;
        (proc.spawner.clone(), proc.handoff.clone())
    };
    spawner.take_over(task, image, handoff);
}

/// What the execution layer needs of an instance for processes.
pub(crate) struct ProcExports {
    pub(crate) spawner: Arc<dyn Spawn>,
    /// The instance's module, which a fork child instantiates.
    pub(crate) module: Option<Module>,
    /// The handoff of the instance's process image ([`Handoff`]).
    pub(crate) handoff: Arc<Handoff>,
}

impl ProcExports {
    pub(crate) fn new(spawner: Arc<dyn Spawn>, handoff: Arc<Handoff>) -> Self {
        Self {
            spawner,
            module: None,
            handoff,
        }
    }

    pub(crate) fn set_module(&mut self, module: &Module) {
        self.module = Some(module.clone());
    }
}

/// The export a vfork parent resumes through, as `wasixv2_vfork_return(child_tid)`.
pub const VFORK_RETURN: &str = "wasixv2_vfork_return";

/// Calls the guest's vfork return, `function`, with the child's pid as the parent sees it, in
/// the vfork parent, which unwinds to the vfork point with an exception; returns that error
/// for the import to raise.
pub(crate) async fn vfork_return<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    function: Option<&Function>,
    pid: i32,
) -> RuntimeError {
    let Some(function) = function else {
        return RuntimeError::new(format!(
            "a vfork child ended, but the guest has no `{VFORK_RETURN}`"
        ));
    };
    let args = [Value::I32(pid)];
    match asyncify::call(env, None, function, &args).await {
        Err(err) => err,
        Ok(_) => RuntimeError::new(format!("`{VFORK_RETURN}` returned")),
    }
}

#[cfg(test)]
pub(super) mod tests {
    #[test]
    fn cloned_runtime_markers_cannot_claim_or_restart_an_owned_image_twice() {
        let handoff = Arc::new(Handoff::default());
        handoff
            .publish(PendingOutcome::Exec {
                task: TaskId(71),
                image: Image::copied(vec![1, 2, 3]).into(),
            })
            .unwrap();
        let error = RuntimeError::host_abort(Box::new(ExecNew(handoff.clone())));
        let cloned = error.clone();
        let first = pending_marker(&cloned).unwrap();
        assert!(Arc::ptr_eq(first, &handoff));
        let PendingOutcome::Exec { task, image } = first.claim().unwrap() else {
            panic!("exec payload");
        };
        assert_eq!(task, TaskId(71));
        assert!(!handoff.is_pending());
        assert!(pending_marker(&error).unwrap().claim().is_err());
        drop(image);
        assert!(
            handoff.claim().is_err(),
            "dropping payload never rearms the marker"
        );
    }

    #[test]
    fn repeated_exec_retires_predecessor_leases_and_keeps_noop_abi_custody_bounded() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counted {
            live: Arc<AtomicUsize>,
            retired: Arc<AtomicUsize>,
        }
        impl crate::ExecProcessLease for Counted {}
        impl Drop for Counted {
            fn drop(&mut self) {
                self.live.fetch_sub(1, Ordering::SeqCst);
                self.retired.fetch_add(1, Ordering::SeqCst);
            }
        }
        let live = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicUsize::new(0));
        let mut custody = None;
        super::keep_process_lease(&mut custody, None);
        for image in 0..1000 {
            live.fetch_add(1, Ordering::SeqCst);
            super::keep_process_lease(
                &mut custody,
                Some(Box::new(Counted {
                    live: live.clone(),
                    retired: retired.clone(),
                })),
            );
            assert_eq!(
                live.load(Ordering::SeqCst),
                1,
                "one predecessor after image {image}"
            );
            assert_eq!(retired.load(Ordering::SeqCst), image);
            for _ in 0..3 {
                super::keep_process_lease(&mut custody, None);
            }
            assert_eq!(
                live.load(Ordering::SeqCst),
                1,
                "noop successors retain custody"
            );
            assert_eq!(retired.load(Ordering::SeqCst), image);
        }
        drop(custody);
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(retired.load(Ordering::SeqCst), 1000);
    }

    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    #[test]
    fn committed_fallback_image_destructor_panic_is_delivered_after_exact_terminal_release() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Lease(Arc<AtomicUsize>);
        impl crate::ExecProcessLease for Lease {}
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("fallback image lease destructor");
            }
        }
        let control = Arc::new(Recorder::default());
        let drops = Arc::new(AtomicUsize::new(0));
        let task = TaskId(77);
        control.queue(task, GuestAction::Stopped);
        let terminal = crate::PreinstalledTerminalCustody::new(
            task,
            ExecImage::new(
                Image::copied(Vec::new()),
                Some(Box::new(Lease(drops.clone()))),
            ),
        );
        terminal.cancel();
        let completion = Arc::new(Handoff::default());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(CommittedRetirement::new(
                control.clone(),
                terminal.clone(),
                completion.clone(),
            ));
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"fallback image lease destructor")
        );
        assert!(
            terminal.is_finished(),
            "completion follows actual fallback release, not merely claimed entry"
        );
        assert_eq!(
            *control.faulted.lock().unwrap(),
            [(task, Signal::SIGSEGV.0)]
        );
        assert_eq!(*control.released.lock().unwrap(), [task]);
        assert_eq!(
            control.pending_calls.load(Ordering::SeqCst),
            3,
            "post-fault work drains the prior action, the fault exit and final None exactly once"
        );
        assert!(
            control
                .pending
                .lock()
                .unwrap()
                .get(&task)
                .unwrap()
                .is_empty()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(matches!(
            futures::executor::block_on(completion.wait()),
            Err(ExecError::Dropped)
        ));
        // Re-observation is safe only because the concrete phase committed
        // finished; it cannot claim/drop/release the consumed entry again.
        futures::executor::block_on(CommittedRetirement::new(
            control.clone(),
            terminal,
            completion,
        ));
        assert_eq!(*control.released.lock().unwrap(), [task]);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    #[test]
    fn committed_fallback_keeps_the_same_panicked_group_observer_and_claimed_entry() {
        use std::sync::atomic::{AtomicU32, Ordering};
        struct Lease(Arc<AtomicU32>);
        impl crate::ExecProcessLease for Lease {}
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let probe = Arc::new(GroupWaitProbe::default());
        let control = Arc::new(Recorder {
            group_wait_failure: Some(probe.clone()),
            ..Default::default()
        });
        let drops = Arc::new(AtomicU32::new(0));
        let task = TaskId(78);
        let terminal = crate::PreinstalledTerminalCustody::new(
            task,
            ExecImage::new(
                Image::copied(Vec::new()),
                Some(Box::new(Lease(drops.clone()))),
            ),
        );
        terminal.cancel();
        let completion = Arc::new(Handoff::default());
        let mut retiring = Box::pin(CommittedRetirement::new(
            control.clone(),
            terminal.clone(),
            completion.clone(),
        ));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(retiring.as_mut().poll(&mut cx).is_pending());
        assert!(retiring.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            probe.polls.load(Ordering::SeqCst),
            1,
            "a panicked opaque future is never repolled/recreated"
        );
        assert_eq!(
            probe.drops.load(Ordering::SeqCst),
            0,
            "the SAME actual observation remains owned"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the claimed image/lease remains owned"
        );
        assert!(!terminal.is_finished());
        assert!(control.released.lock().unwrap().is_empty());
        assert_eq!(control.faulted.lock().unwrap().len(), 1);
        let mut completion_wait = Box::pin(completion.wait());
        assert!(
            completion_wait.as_mut().poll(&mut cx).is_pending(),
            "no publication may manufacture physical settlement"
        );
        // Progress of arbitrary panicked Control observers is explicitly
        // unproved. This local test finally disposes its mock process owner;
        // production CAPI transfers the enclosing SAME pending state on Drop.
        drop(completion_wait);
        drop(retiring);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[derive(Default)]
    struct GroupWaitProbe {
        polls: std::sync::atomic::AtomicU32,
        drops: std::sync::atomic::AtomicU32,
    }
    struct GroupWaitFailure(Arc<GroupWaitProbe>);
    impl Future for GroupWaitFailure {
        type Output = ();
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<()> {
            self.0
                .polls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("opaque group observer poll failure");
        }
    }
    impl Drop for GroupWaitFailure {
        fn drop(&mut self) {
            self.0
                .drops
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    use std::{
        collections::{HashMap, VecDeque},
        ops::Range,
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };
    use wasixv2_syscalls::MaybeFuture;

    use wasixv2_abi::Errno;
    use wasixv2_host::{Executor, LocalFuture};
    use wasixv2_syscalls::{
        AtomicWait, AtomicWord, Caller, CpuAccount, CpuTime, ExitMm, GroupStop, PidView,
        SharedMapping, SharedMappings, SysErr, SysResult, VforkParent, VforkWait,
    };

    use super::*;

    /// Control that records faults and releases; a fault leaves the exit it causes pending.
    #[derive(Default)]
    pub(crate) struct Recorder {
        pub(crate) loader: Option<Arc<wasixv2_syscalls::LoaderGate>>,
        pending: Mutex<HashMap<TaskId, VecDeque<GuestAction>>>,
        pending_calls: AtomicU32,
        group_wait_failure: Option<Arc<GroupWaitProbe>>,
        pub(crate) faulted: Mutex<Vec<(TaskId, i32)>>,
        pub(crate) released: Mutex<Vec<TaskId>>,
        /// The tasks that left their memory and the ones that faulted, in order.
        ended: Mutex<Vec<(&'static str, TaskId)>>,
        memory_task_work: bool,
        exit_from_final_drain: bool,
        task_work_calls: std::sync::atomic::AtomicUsize,
        resume_flag: Option<Arc<wasixv2_syscalls::WorkFlag>>,
        cpu: Option<Arc<CpuAccount>>,
        retry: Option<(Arc<crate::cputime::tests::Clocks>, SysErr)>,
        calls: AtomicU32,
        pub(crate) buffer_allocations: AtomicU32,
    }

    impl Recorder {
        pub(crate) fn queue(&self, task: TaskId, action: GuestAction) {
            if let Some(flag) = &self.resume_flag {
                flag.raise();
            }
            let mut pending = self.pending.lock().unwrap();
            pending.entry(task).or_default().push_back(action);
        }
    }

    impl Syscalls for Recorder {
        fn mmap<'a>(
            &'a self,
            caller: &'a Caller<'_>,
            _: u32,
            len: u32,
            _: wasixv2_abi::ProtFlags,
            _: wasixv2_abi::MapFlags,
            _: wasixv2_abi::Fd,
            _: i64,
        ) -> MaybeFuture<'a, SysResult<u32>> {
            MaybeFuture::Future(Box::pin(async move {
                let index = self.buffer_allocations.fetch_add(1, Ordering::Relaxed);
                let at = 4 * 65536 + index * len;
                let size = caller.memory().size().await;
                let end = u64::from(at) + u64::from(len);
                if end > size {
                    caller
                        .memory()
                        .grow((end - size).div_ceil(65536) as u32)
                        .await
                        .ok_or(Errno::ENOMEM)?;
                }
                Ok(at)
            }))
        }

        fn sched_yield<'a>(&'a self, _: &'a Caller<'_>) -> MaybeFuture<'a, SysResult<i32>> {
            MaybeFuture::Future(Box::pin(async move {
                let Some((clocks, error)) = &self.retry else {
                    return Err(Errno::ENOSYS.into());
                };
                let used = Duration::from_micros(2);
                clocks.advance(used, used);
                if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(*error)
                } else {
                    Ok(0)
                }
            }))
        }

        fn restart_syscall<'a>(&'a self, _: &'a Caller<'_>) -> MaybeFuture<'a, SysResult<i32>> {
            MaybeFuture::Future(Box::pin(async move {
                let (clocks, _) = self.retry.as_ref().expect("a restart block");
                let used = Duration::from_micros(3);
                clocks.advance(used, used);
                Ok(0)
            }))
        }

        fn exit_group<'a>(
            &'a self,
            caller: &'a Caller<'_>,
            status: i32,
        ) -> MaybeFuture<'a, SysResult<()>> {
            MaybeFuture::Future(Box::pin(async move {
                self.queue(caller.task(), GuestAction::Exit(status));
                Ok(())
            }))
        }
    }

    impl wasixv2_syscalls::LoaderControl for Recorder {
        fn loader_gate(&self, _: TaskId) -> Option<Arc<wasixv2_syscalls::LoaderGate>> {
            self.loader.clone()
        }
        fn loader_sleep<'a>(
            &'a self,
            _: TaskId,
            _: &'a wasixv2_syscalls::LoaderGate,
            _: wasixv2_syscalls::LoaderWait,
        ) -> wasixv2_syscalls::LocalFuture<'a, Result<(), wasixv2_syscalls::Errno>> {
            Box::pin(async { Err(wasixv2_syscalls::Errno::EINTR) })
        }
    }

    impl Control for Recorder {
        fn work_flag(&self, _: TaskId) -> Arc<wasixv2_syscalls::WorkFlag> {
            self.resume_flag
                .clone()
                .unwrap_or_else(|| Arc::new(wasixv2_syscalls::WorkFlag::always()))
        }

        fn run_task_work<'a>(&'a self, caller: &'a Caller<'_>) -> LocalFuture<'a, ()> {
            Box::pin(async move {
                if self.exit_from_final_drain
                    && self
                        .task_work_calls
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        == 1
                {
                    self.queue(caller.task(), GuestAction::Exit(42));
                }
                if self.memory_task_work {
                    caller
                        .memory()
                        .write(4096, &1u32.to_le_bytes())
                        .await
                        .unwrap();
                }
            })
        }

        fn take_pending(&self, task: TaskId) -> Option<GuestAction> {
            self.pending_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.pending.lock().unwrap().get_mut(&task)?.pop_front()
        }

        fn group_wait(&self, _: TaskId) -> LocalFuture<'_, ()> {
            match &self.group_wait_failure {
                Some(probe) => Box::pin(GroupWaitFailure(probe.clone())),
                None => Box::pin(async {}),
            }
        }

        fn take_image(&self, _: TaskId) -> Option<Image> {
            None
        }

        fn fault(&self, task: TaskId, signal: i32) -> bool {
            self.ended.lock().unwrap().push(("fault", task));
            self.faulted.lock().unwrap().push((task, signal));
            self.queue(task, GuestAction::Exit(128 + signal));
            true
        }

        fn release(&self, task: TaskId) {
            self.released.lock().unwrap().push(task);
        }
    }

    impl CpuTime for Recorder {
        fn cpu_account(&self, _: TaskId) -> Arc<CpuAccount> {
            self.cpu
                .clone()
                .unwrap_or_else(|| Arc::new(CpuAccount::detached()))
        }
    }

    impl PidView for Recorder {}

    impl ExitMm for Recorder {
        fn exit_mm<'a>(&'a self, caller: &'a Caller<'a>) -> LocalFuture<'a, ()> {
            self.ended.lock().unwrap().push(("exit_mm", caller.task()));
            Box::pin(async {})
        }
    }

    impl GroupStop for Recorder {
        fn stop_wait(&self, _: TaskId) -> LocalFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    impl VforkWait for Recorder {
        fn vfork_wait(&self, _: TaskId) -> LocalFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    impl AtomicWait for Recorder {
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

    impl SharedMappings for Recorder {
        fn shared_mappings(&self, _: TaskId) -> Vec<SharedMapping> {
            Vec::new()
        }

        fn wipe_on_fork(&self, _: TaskId) -> Vec<Range<u64>> {
            Vec::new()
        }
    }

    /// A host that cannot start threads.
    pub(crate) struct NoThreads;

    impl Host for NoThreads {
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

    impl Executor for NoThreads {
        fn spawn_local(&self, _: LocalFuture<'static, ()>) {
            unreachable!("nothing runs in the background")
        }

        fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
            Box::pin(async move { work() })
        }
    }

    // Linux mm/mmap.c:do_brk_flags grows backing memory without requiring any host
    // pointer representation; the JS backend must use its refreshed buffer views.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn memory_grow_hook_accepts_growth_and_reports_the_previous_size() {
        let wasm = wat::parse_str(
            r#"(module
            (import "wasixv2" "exit_group" (func $exit (param i32)))
            (import "wasixv2-exec" "memory-grow" (func $grow (param i32) (result i32)))
            (memory (export "memory") 1 2)
            (func (export "_start")
                (if (i32.ne (call $grow (i32.const 1)) (i32.const 1)) (then unreachable))
                (i32.store (i32.const 65536) (i32.const 42))
                (if (i32.ne (call $grow (i32.const 1)) (i32.const -1)) (then unreachable))
                (call $exit (i32.const 0))))"#,
        )
        .unwrap();
        let store = Store::default();
        let module = wasmer::Module::new(&store, wasm).unwrap();
        let control = Arc::new(Recorder::default());
        let run = crate::run(store, &module, control.clone(), PARENT, Arc::new(NoThreads));
        assert_eq!(futures::executor::block_on(run).unwrap(), 0);
        assert!(control.faulted.lock().unwrap().is_empty());
    }

    const PARENT: TaskId = TaskId(2);
    const CHILD: TaskId = TaskId(3);

    #[cfg(feature = "sys")]
    #[test]
    fn restarted_syscalls_keep_charging_system_time() {
        let wasm = wat::parse_str(
            r#"(module
                (import "wasixv2" "sched_yield" (func $yield (result i32)))
                (import "wasixv2" "exit_group" (func $exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start") call $yield call $exit unreachable))"#,
        )
        .unwrap();
        for error in [
            SysErr::Restart,
            SysErr::RestartNoIntr,
            SysErr::RestartNoHand,
            SysErr::RestartBlock,
        ] {
            let (clocks, account, _) = crate::cputime::tests::setup(true);
            let control = Arc::new(Recorder {
                cpu: Some(account.clone()),
                retry: Some((clocks.clone(), error)),
                ..Recorder::default()
            });
            let store = Store::default();
            let module = wasmer::Module::new(&store, &wasm).unwrap();
            let run = crate::run(store, &module, control, PARENT, clocks);
            assert_eq!(futures::executor::block_on(run).unwrap(), 0);
            let micros = if error == SysErr::RestartBlock { 5 } else { 4 };
            assert_eq!(
                account.times().system,
                Duration::from_micros(micros),
                "{error:?}"
            );
            assert_eq!(account.times().user, Duration::ZERO, "{error:?}");
        }
    }

    /// A trap of a vfork child whose parent's image went on in another instance ends the child
    /// alone: the parent is neither killed nor released here, as the run that took it over
    /// owns it.
    /// A trap kills the task as any fatal signal does on Linux (`force_sig_fault`, whose
    /// `get_signal` dumps core), then `do_exit` runs `exit_mm` (`mm_release`: the robust futex
    /// list, `clear_child_tid` and its futex wake), as for every exit: the kernel hears of the
    /// fault first, then the instance hands it the task's memory, still there.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn a_trapped_task_faults_before_it_leaves_its_memory() {
        let wasm = wat::parse_str(
            r#"(module
                (import "wasixv2" "sched_yield" (func (result i32)))
                (memory (export "memory") 1)
                (func (export "_start") unreachable))"#,
        )
        .unwrap();
        let store = Store::default();
        let module = crate::load(store.engine(), &wasm).unwrap();
        let control = Arc::new(Recorder::default());
        let run = crate::run(store, &module, control.clone(), PARENT, Arc::new(NoThreads));
        let status = futures::executor::block_on(run).unwrap();
        assert_eq!(status, 128 + Signal::SIGILL.0);
        let ended = control.ended.lock().unwrap();
        assert_eq!(ended[..2], [("fault", PARENT), ("exit_mm", PARENT)]);
    }

    /// Kernel task work must see the current memory on syscall returns and user-code
    /// preemption, while an unraised WorkFlag keeps the hook off the fast path.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn task_work_runs_before_returning_from_syscalls_and_preemption() {
        for raised in [true, false] {
            let expected = i32::from(raised);
            let wasm = wat::parse_str(format!(r#"(module
                (import "wasixv2" "sched_yield" (func $yield (result i32)))
                (import "wasixv2" "exit_group" (func $exit (param i32)))
                (import "wasixv2-exec" "preempt" (func $preempt (result i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (i32.store (i32.const 4096) (i32.const 0))
                    (drop (call $yield))
                    (if (i32.ne (i32.load (i32.const 4096)) (i32.const {expected})) (then unreachable))
                    (i32.store (i32.const 4096) (i32.const 0))
                    (drop (call $preempt))
                    (if (i32.ne (i32.load (i32.const 4096)) (i32.const {expected})) (then unreachable))
                    (call $exit (i32.const 0))))"#)).unwrap();
            let store = Store::default();
            let module = wasmer::Module::new(&store, wasm).unwrap();
            let control = Arc::new(Recorder {
                memory_task_work: true,
                resume_flag: (!raised).then(|| Arc::new(wasixv2_syscalls::WorkFlag::default())),
                ..Recorder::default()
            });
            let run = crate::run(store, &module, control, PARENT, Arc::new(NoThreads));
            assert_eq!(
                futures::executor::block_on(run).unwrap(),
                0,
                "raised={raised}"
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn actions_generated_by_the_final_task_work_drain_precede_guest_resume() {
        let wasm = wat::parse_str(
            r#"(module
            (import "wasixv2" "sched_yield" (func $yield (result i32)))
            (memory (export "memory") 1)
            (func (export "_start") (drop (call $yield)) unreachable))"#,
        )
        .unwrap();
        let store = Store::default();
        let module = wasmer::Module::new(&store, wasm).unwrap();
        let control = Arc::new(Recorder {
            exit_from_final_drain: true,
            ..Recorder::default()
        });
        let run = crate::run(store, &module, control.clone(), PARENT, Arc::new(NoThreads));
        assert_eq!(futures::executor::block_on(run).unwrap(), 42);
        assert!(
            control.faulted.lock().unwrap().is_empty(),
            "guest resumed before final-drain action delivery"
        );
    }

    #[test]
    fn a_trap_of_a_detached_vfork_child_leaves_its_parent_alone() {
        let control = Recorder::default();
        let parent = VforkParent {
            task: PARENT,
            resumes: Resume::Gone,
            pid: CHILD.0 as i32,
        };
        control.queue(
            CHILD,
            GuestAction::VforkReturn {
                parent,
                child: CHILD,
            },
        );
        let sigill = Signal::SIGILL.0;
        let ended = fault_in(&control, &NoThreads, PARENT, CHILD, (sigill, None), "trap");
        assert_eq!(ended, None);
        assert_eq!(*control.faulted.lock().unwrap(), [(CHILD, sigill)]);
        assert_eq!(*control.released.lock().unwrap(), [CHILD]);

        // A parent that waits dies with its stack.
        let control = Recorder::default();
        let parent = VforkParent {
            resumes: Resume::Returns,
            ..parent
        };
        control.queue(
            CHILD,
            GuestAction::VforkReturn {
                parent,
                child: CHILD,
            },
        );
        let ended = fault_in(&control, &NoThreads, PARENT, CHILD, (sigill, None), "trap");
        assert_eq!(ended, Some(128 + Signal::SIGSEGV.0));
    }

    /// A take-over that gets no thread kills the process as an image that cannot start does,
    /// releases it, and reports that status to the run it took over from.
    #[test]
    fn a_take_over_without_a_thread_reports_the_kill() {
        let control = Arc::new(Recorder::default());
        let abis = Arc::new(Abis::wasixv2());
        let spawner = spawner(
            Engine::default(),
            control.clone(),
            Arc::new(NoThreads),
            abis,
        );
        let handoff = Arc::new(Handoff::default());
        spawner.take_over(PARENT, Image::copied(Vec::new()).into(), handoff.clone());
        let status = futures::executor::block_on(handoff.wait());
        assert_eq!(status.ok(), Some(128 + Signal::SIGSEGV.0));
        assert_eq!(*control.released.lock().unwrap(), [PARENT]);
    }
}
