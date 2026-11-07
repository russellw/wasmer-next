//! Abandoning the outer waiter cancels its guest on the original owning worker.

use std::{
    future::{Future, poll_fn},
    sync::{Arc, Mutex, PoisonError, Weak},
    task::{Context, Poll, Waker},
};

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
use wasixv2_host::Host;
use wasixv2_syscalls::TaskId;
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
use wasixv2_syscalls::{Control, Syscalls};
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
use wasmer::{Engine, Store};

use crate::process;
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
use crate::{Abis, ExecError, ThreadEntry, cleanup::RunCleanup, thread};

#[cfg(all(test, feature = "sys", not(target_arch = "wasm32")))]
#[path = "cancellation_tests.rs"]
mod tests;

#[cfg(all(test, feature = "sys", not(target_arch = "wasm32")))]
static TERMINAL_WAITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[derive(Clone)]
pub(crate) struct Cancellation(Arc<Mutex<State>>);
#[derive(Clone)]
pub(crate) struct WeakCancellation(Weak<Mutex<State>>);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Owned,
    Transferring,
    Transferred,
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    Terminal,
}
struct State {
    task: TaskId,
    phase: Phase,
    requested: bool,
    process_requested: bool,
    selected: bool,
    image: Option<Arc<process::Handoff>>,
    waker: Option<Waker>,
}

pub(crate) enum Transfer {
    Uninvolved,
    Reserved(TransferGuard),
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    Refused,
}
pub(crate) struct TransferGuard(Option<Cancellation>);
impl TransferGuard {
    pub(crate) fn relinquish(mut self) {
        self.0.take().unwrap().set_phase(Phase::Transferred);
    }
}
impl Drop for TransferGuard {
    fn drop(&mut self) {
        // A panic before spawn's result leaves teardown with the old owner.
        if let Some(authority) = self.0.take() {
            if std::thread::panicking() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    authority.set_phase(Phase::Owned);
                }));
            } else {
                authority.set_phase(Phase::Owned);
            }
        }
    }
}
impl WeakCancellation {
    pub(crate) fn upgrade(&self) -> Option<Cancellation> {
        self.0.upgrade().map(Cancellation)
    }
}
impl Cancellation {
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn new(task: TaskId) -> Self {
        Self(Arc::new(Mutex::new(State {
            task,
            phase: Phase::Owned,
            requested: false,
            process_requested: false,
            selected: false,
            image: None,
            waker: None,
        })))
    }
    pub(crate) fn downgrade(&self) -> WeakCancellation {
        WeakCancellation(Arc::downgrade(&self.0))
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn bind_image(&self, image: Arc<process::Handoff>) {
        let previous = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .image
            .replace(image);
        drop(previous);
    }
    pub(crate) fn transfer(&self, task: TaskId) -> Transfer {
        let (result, requested_image) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.task != task {
                return Transfer::Uninvolved;
            }
            let result = match state.phase {
                Phase::Owned => {
                    state.phase = Phase::Transferring;
                    Transfer::Reserved(TransferGuard(Some(self.clone())))
                }
                #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
                Phase::Terminal => Transfer::Refused,
                Phase::Transferring | Phase::Transferred => Transfer::Uninvolved,
            };
            (
                result,
                state
                    .process_requested
                    .then(|| state.image.clone())
                    .flatten(),
            )
        };
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        if let Some(image) = requested_image {
            image.cancel_takeover();
        }
        #[cfg(not(all(feature = "sys", not(target_arch = "wasm32"))))]
        drop(requested_image);
        result
    }
    fn set_phase(&self, phase: Phase) {
        let wake = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.phase = phase;
            state.waker.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    /// Only a never-entered factory can retire synchronously: it has no bound
    /// image or sibling that could hold a takeover reservation.
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn claim_terminal(&self) -> bool {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match state.phase {
            Phase::Owned => {
                state.phase = Phase::Terminal;
                true
            }
            Phase::Terminal | Phase::Transferred => false,
            Phase::Transferring => unreachable!("takeover outlived the drained owner"),
        }
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn selected(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .selected
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) async fn terminal_owner(&self) -> Option<Arc<process::Handoff>> {
        let result = poll_fn(|cx| {
            let next = cx.waker().clone();
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.phase == Phase::Transferring {
                #[cfg(test)]
                TERMINAL_WAITS.fetch_add(1, std::sync::atomic::Ordering::Release);
                let old = state.waker.replace(next);
                drop(state);
                drop(old);
                return Poll::Pending;
            }
            if state.phase == Phase::Transferred {
                return Poll::Ready(Some(state.image.clone().expect("transferred image")));
            }
            state.phase = Phase::Terminal;
            Poll::Ready(None)
        })
        .await;
        if result.is_none() {
            // This observer runs after the worker's physical/loader cleanup.
            // A cloned diagnostic marker must not retain an unclaimed image.
            let image = self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .image
                .clone();
            let pending = image.and_then(|image| image.retire_pending());
            drop(pending);
        }
        result
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn request(&self) {
        let waker = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.requested = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn request_process(&self) {
        let (waker, successor) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.requested = true;
            state.process_requested = true;
            (
                state.waker.take(),
                matches!(state.phase, Phase::Transferring | Phase::Transferred)
                    .then(|| state.image.clone())
                    .flatten(),
            )
        };
        if let Some(image) = successor {
            image.cancel_takeover();
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        let next = cx.waker().clone();
        let (requested, old) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            // Execution cancellation is independent of terminal release authority.
            let requested = state.requested;
            state.selected |= requested;
            (requested, state.waker.replace(next))
        };
        drop(old);
        if requested {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    async fn run<R>(&self, guest: impl Future<Output = R>) -> Option<R> {
        let mut guest = Box::pin(guest);
        let result = poll_fn(|cx| {
            if self.poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            guest.as_mut().poll(cx).map(Some)
        })
        .await;
        // This is inside the cleanup runner on the original worker. Dropping
        // only its outer profile would leave a pending loader alive forever.
        drop(guest);
        result
    }
}

pub(crate) async fn execution<R>(
    cancellation: Option<&Cancellation>,
    guest: impl Future<Output = R>,
) -> Option<R> {
    match cancellation {
        Some(cancellation) => cancellation.run(guest).await,
        None => Some(guest.await),
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
struct WaitGuard(Option<Cancellation>);

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl Drop for WaitGuard {
    fn drop(&mut self) {
        if let Some(cancellation) = self.0.take() {
            cancellation.request();
        }
    }
}

/// Preinstalled, engine-free disposition for a committed external call.
/// Its old-thread retirement owner remains responsible until a worker accepts.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[derive(Clone)]
pub(crate) struct PreinstalledTerminalCustody(Arc<Mutex<TerminalState>>);
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalPhase {
    Starting,
    Fallback,
    WorkerAccepted,
    Terminal,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
type UnenteredFailure = Box<dyn FnOnce() -> Option<(Arc<process::Handoff>, i32)> + Send>;

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
struct TerminalState {
    task: TaskId,
    entry: Option<process::ExecImage>,
    phase: TerminalPhase,
    canceled: bool,
    cancellation: Option<Cancellation>,
    finished: bool,
    phase_waiter: Option<Waker>,
    completion_waiters: std::collections::BTreeMap<usize, Waker>,
    next_waiter: usize,
    unentered_failure: Option<UnenteredFailure>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl PreinstalledTerminalCustody {
    pub(crate) fn new(task: TaskId, entry: process::ExecImage) -> Self {
        Self(Arc::new(Mutex::new(TerminalState {
            task,
            entry: Some(entry),
            phase: TerminalPhase::Starting,
            canceled: false,
            cancellation: None,
            finished: false,
            phase_waiter: None,
            completion_waiters: Default::default(),
            next_waiter: 0,
            unentered_failure: None,
        })))
    }
    pub fn cancel(&self) {
        let (cancellation, wake, observers) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.canceled = true;
            if state.phase == TerminalPhase::Starting {
                state.phase = TerminalPhase::Fallback;
            }
            (
                state.cancellation.clone(),
                state.phase_waiter.take(),
                if state.phase == TerminalPhase::Fallback {
                    std::mem::take(&mut state.completion_waiters)
                } else {
                    Default::default()
                },
            )
        };
        if let Some(cancellation) = cancellation {
            cancellation.request_process();
        }
        if let Some(wake) = wake {
            wake.wake();
        }
        for (_, wake) in observers {
            wake.wake();
        }
    }
    pub(crate) fn retirement_ready(&self) -> TerminalWait {
        TerminalWait {
            terminal: self.clone(),
            key: None,
        }
    }
    pub(crate) fn task(&self) -> TaskId {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).task
    }
    fn bind(&self, cancellation: Cancellation) -> bool {
        let canceled = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.phase != TerminalPhase::Starting || state.cancellation.is_some() {
                return false;
            }
            state.cancellation = Some(cancellation.clone());
            state.canceled
        };
        if canceled {
            cancellation.request_process();
        }
        true
    }
    fn decide(&self, accepted: bool) -> bool {
        let (result, wake, observers) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let result = accepted && state.phase == TerminalPhase::Starting;
            if state.phase == TerminalPhase::Starting {
                state.phase = if result {
                    TerminalPhase::WorkerAccepted
                } else {
                    TerminalPhase::Fallback
                };
            }
            (
                result,
                state.phase_waiter.take(),
                if state.phase == TerminalPhase::Fallback {
                    std::mem::take(&mut state.completion_waiters)
                } else {
                    Default::default()
                },
            )
        };
        if let Some(wake) = wake {
            wake.wake();
        }
        for (_, wake) in observers {
            wake.wake();
        }
        result
    }
    async fn accepted(&self) -> bool {
        poll_fn(|cx| {
            let next = cx.waker().clone();
            let old = {
                let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
                if state.phase != TerminalPhase::Starting {
                    let accepted = state.phase == TerminalPhase::WorkerAccepted;
                    drop(state);
                    drop(next);
                    return Poll::Ready(accepted);
                }
                state.phase_waiter.replace(next)
            };
            drop(old);
            Poll::Pending
        })
        .await
    }
    fn worker_entry(&self) -> Option<process::ExecImage> {
        let (entry, fallback) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.phase != TerminalPhase::WorkerAccepted {
                return None;
            }
            (state.entry.take(), state.unentered_failure.take())
        };
        drop(fallback);
        entry
    }
    fn set_unentered_failure(&self, fallback: UnenteredFailure) {
        let old = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unentered_failure
            .replace(fallback);
        assert!(old.is_none(), "one unentered owner");
        drop(old);
    }
    fn finish_unentered(&self) {
        let (callback, entry) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.phase != TerminalPhase::Fallback || state.unentered_failure.is_none() {
                return;
            }
            state.phase = TerminalPhase::Terminal;
            (state.unentered_failure.take(), state.entry.take())
        };
        let completion = callback.and_then(|callback| callback());
        drop(entry);
        self.mark_finished();
        if let Some((handoff, status)) = completion {
            handoff.complete(Ok(status));
        }
    }
    /// Called only by the preinstalled old-thread owner after actual predecessor drain.
    pub(crate) fn claim_fallback(&self) -> Option<process::ExecImage> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.phase != TerminalPhase::Fallback {
            return None;
        }
        state.phase = TerminalPhase::Terminal;
        state.entry.take()
    }
    pub(crate) fn is_finished(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .finished
    }
    pub(crate) fn mark_finished(&self) {
        let (wake, cancellation, fallback) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.phase = TerminalPhase::Terminal;
            state.finished = true;
            (
                std::mem::take(&mut state.completion_waiters),
                state.cancellation.take(),
                state.unentered_failure.take(),
            )
        };
        drop(cancellation);
        drop(fallback);
        for (_, wake) in wake {
            wake.wake();
        }
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
pub(crate) struct TerminalWait {
    terminal: PreinstalledTerminalCustody,
    key: Option<usize>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl Future for TerminalWait {
    type Output = ();
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut next = Some(cx.waker().clone());
        let (ready, key, old) = {
            let mut state = self
                .terminal
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.finished || state.phase == TerminalPhase::Fallback {
                (
                    true,
                    self.key,
                    self.key
                        .and_then(|key| state.completion_waiters.remove(&key)),
                )
            } else {
                let key = self.key.unwrap_or_else(|| {
                    let key = state.next_waiter;
                    state.next_waiter = key.checked_add(1).expect("terminal waiter id exhausted");
                    key
                });
                (
                    false,
                    Some(key),
                    state
                        .completion_waiters
                        .insert(key, next.take().expect("owned terminal waker")),
                )
            }
        };
        self.key = if ready { None } else { key };
        drop(old);
        drop(next);
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl Drop for TerminalWait {
    fn drop(&mut self) {
        let old = self.key.take().and_then(|key| {
            self.terminal
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .completion_waiters
                .remove(&key)
        });
        drop(old);
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
struct StartAdmission(Option<PreinstalledTerminalCustody>);
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl Drop for StartAdmission {
    fn drop(&mut self) {
        if let Some(terminal) = self.0.take() {
            // A starter may accept and then discard the unentered ThreadStart.
            // No worker owns the entry yet; the installed predecessor owns fallback.
            terminal.cancel();
            let wake = {
                let mut state = terminal.0.lock().unwrap_or_else(PoisonError::into_inner);
                if state.entry.is_some() && state.phase == TerminalPhase::WorkerAccepted {
                    state.phase = TerminalPhase::Fallback;
                    std::mem::take(&mut state.completion_waiters)
                } else {
                    Default::default()
                }
            };
            for (_, wake) in wake {
                wake.wake();
            }
            terminal.finish_unentered();
        }
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
pub struct OwnedEntryWaiter {
    waiting: WaitGuard,
    completion: std::pin::Pin<Box<dyn Future<Output = Result<i32, ExecError>>>>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl Future for OwnedEntryWaiter {
    type Output = Result<i32, ExecError>;
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = self.completion.as_mut().poll(cx);
        if result.is_ready() {
            self.waiting.0 = None;
        }
        result
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl OwnedEntryWaiter {
    fn detach(mut self) {
        self.waiting.0 = None;
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
fn panic_error(panic: Box<dyn std::any::Any + Send>) -> ExecError {
    let message = panic
        .downcast_ref::<&str>()
        .map(|value| (*value).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic without a message".to_owned());
    ExecError::Panic(message)
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[allow(clippy::too_many_arguments)]
async fn committed_worker<S>(
    profile: Result<Option<thread::OwningThread>, ExecError>,
    engine: Engine,
    entry: process::ExecImage,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    cancellation: Cancellation,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let profile = match profile.and_then(|profile| {
        if let Some(profile) = &profile {
            profile.authorize()?;
        }
        Ok(profile)
    }) {
        Ok(profile) => profile,
        Err(error) => {
            process::fault(&*syscalls, task, wasixv2_abi::Signal::SIGSEGV.0);
            process::finish_task(&*syscalls, task).await;
            return Err(error);
        }
    };
    let cleanup = RunCleanup::new(
        wasixv2_host::LoaderCleanup::new(host.clone()),
        engine.is_sys(),
    )
    .with_cancellation(cancellation.clone());
    let call = async {
        let run = async {
            cancellation
                .run(process::run_new_image(
                    engine,
                    entry,
                    syscalls.clone(),
                    task,
                    host,
                    abis,
                    cleanup.clone(),
                ))
                .await
                .unwrap_or(Err(ExecError::Dropped))
        };
        let result = match profile {
            Some(profile) => profile.run(&cleanup, run).await,
            None => cleanup.run(run).await,
        };
        if cancellation.selected() {
            if let Some(handoff) = cancellation.terminal_owner().await {
                return handoff.wait().await;
            }
            process::fault(&*syscalls, task, wasixv2_abi::Signal::SIGSEGV.0);
            process::finish_task(&*syscalls, task).await;
        }
        result
    };
    match crate::catch_panic(call).await {
        Ok(result) => result,
        Err(panic) => {
            let error = panic_error(panic);
            process::fault(&*syscalls, task, wasixv2_abi::Signal::SIGSEGV.0);
            process::finish_task(&*syscalls, task).await;
            Err(error)
        }
    }
}

/// Synchronous admission: a supplied terminal already belongs to old-thread
/// retirement custody. No ThreadStart closure owns its only pending image/lease.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
pub(crate) fn start_committed_entry<S>(
    engine: Engine,
    syscalls: Arc<S>,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    predecessor: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    terminal: PreinstalledTerminalCustody,
    completion: Arc<process::Handoff>,
) -> Result<OwnedEntryWaiter, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    start_entry(
        engine,
        syscalls,
        host,
        abis,
        predecessor,
        terminal,
        completion,
        None,
    )
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[allow(clippy::too_many_arguments)]
fn start_entry<S>(
    engine: Engine,
    syscalls: Arc<S>,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    predecessor: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    terminal: PreinstalledTerminalCustody,
    completion: Arc<process::Handoff>,
    existing: Option<Cancellation>,
) -> Result<OwnedEntryWaiter, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let task = terminal.task();
    let cancellation = existing.unwrap_or_else(|| Cancellation::new(task));
    let waiting = WaitGuard(Some(cancellation.clone()));
    if !terminal.bind(cancellation.clone()) {
        return Err(ExecError::Dropped);
    }
    let worker_completion = completion.clone();
    let worker_host = host.clone();
    let worker_terminal = terminal.clone();
    let mut admission = StartAdmission(Some(terminal.clone()));
    let required = abis.requires_owning_thread();
    let start = Box::new(move || {
        let profile = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            thread::OwningThread::required(required)
        }))
        .unwrap_or_else(|panic| Err(panic_error(panic)));
        Box::pin(async move {
            let accepted = worker_terminal.accepted().await;
            // This is deliberately outside cancellation::execution. Cancel records
            // intent, but the predecessor owns the old physical drain and sender.
            predecessor.await;
            if !accepted {
                return;
            }
            drop(admission.0.take());
            let result = match worker_terminal.worker_entry() {
                Some(entry) => {
                    committed_worker(
                        profile,
                        engine,
                        entry,
                        syscalls,
                        task,
                        worker_host,
                        abis,
                        cancellation,
                    )
                    .await
                }
                None => Err(ExecError::Dropped),
            };
            worker_terminal.mark_finished();
            worker_completion.complete(result);
        }) as wasixv2_host::LocalFuture<'static, ()>
    });
    let started = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host.executor().spawn_thread(start)
    })) {
        Ok(result) => result.map_err(ExecError::OwningThreadSpawn),
        Err(panic) => Err(panic_error(panic)),
    };
    if let Err(error) = started {
        terminal.decide(false);
        return Err(error);
    }
    if !terminal.decide(true) {
        return Err(ExecError::Dropped);
    }
    Ok(OwnedEntryWaiter {
        waiting,
        completion: Box::pin(async move { completion.wait().await }),
    })
}

/// The canonical detached worker owns cancellation and release; a C caller
/// merely observes its Handoff, including when no predecessor Cancellation exists.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
pub(crate) fn start_takeover<S>(
    engine: Engine,
    image: process::ExecImage,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
    handoff: Arc<process::Handoff>,
) where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let cancellation = Cancellation::new(task);
    if !handoff.install_takeover(&cancellation) {
        return;
    }
    let terminal = PreinstalledTerminalCustody::new(task, image);
    let failed = handoff.clone();
    let authority = cancellation.clone();
    let control = syscalls.clone();
    terminal.set_unentered_failure(Box::new(move || {
        if authority.claim_terminal() {
            let status = process::fault(&*control, task, wasixv2_abi::Signal::SIGSEGV.0);
            control.release(task);
            Some((failed, status))
        } else {
            None
        }
    }));
    match start_entry(
        engine,
        syscalls,
        host,
        abis,
        Box::pin(async {}),
        terminal.clone(),
        handoff,
        Some(cancellation),
    ) {
        Ok(waiter) => waiter.detach(),
        Err(_) => {
            terminal.cancel();
            terminal.finish_unentered();
        }
    }
}

#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
pub(super) async fn run_owned_entry<S>(
    engine: Engine,
    entry: ThreadEntry,
    syscalls: Arc<S>,
    task: TaskId,
    host: Arc<dyn Host>,
    abis: Arc<Abis<S>>,
) -> Result<i32, ExecError>
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    let cancellation = Cancellation::new(task);
    let mut waiting = WaitGuard(Some(cancellation.clone()));
    let completion = Arc::new(process::Handoff::default());
    let done = process::Takeover(completion.clone());
    let worker_syscalls = syscalls.clone();
    let worker_host = host.clone();
    host.executor()
        .spawn_thread(Box::new(move || {
            // Acquire on the selected owner, before any Store or FunctionEnv.
            let profile = thread::OwningThread::acquire();
            Box::pin(async move {
                let result = match profile {
                    Err(error) => Err(crate::reject_profile(&*worker_syscalls, task, error)),
                    Ok(profile) => {
                        let call = async {
                            profile.authorize().map_err(|error| {
                                crate::reject_profile(&*worker_syscalls, task, error)
                            })?;
                            let cleanup = RunCleanup::new(
                                wasixv2_host::LoaderCleanup::new(worker_host.clone()),
                                engine.is_sys(),
                            )
                            .with_cancellation(cancellation.clone());
                            let run = async {
                                match entry {
                                    ThreadEntry::Module(module) => {
                                        process::run(
                                            Store::new(engine),
                                            &module,
                                            worker_syscalls.clone(),
                                            task,
                                            worker_host,
                                            abis,
                                            cleanup.clone(),
                                        )
                                        .await
                                    }
                                    ThreadEntry::Image(image) => {
                                        process::run_exec(
                                            engine,
                                            image,
                                            worker_syscalls.clone(),
                                            task,
                                            worker_host,
                                            abis,
                                            cleanup.clone(),
                                        )
                                        .await
                                    }
                                }
                            };
                            let result = profile.run(&cleanup, run).await;
                            if cancellation.selected() {
                                if let Some(handoff) = cancellation.terminal_owner().await {
                                    return handoff.wait().await;
                                }
                                process::fault(
                                    &*worker_syscalls,
                                    task,
                                    wasixv2_abi::Signal::SIGSEGV.0,
                                );
                                process::finish_task(&*worker_syscalls, task).await;
                            }
                            result
                        };
                        crate::catch_panic(call).await.unwrap_or_else(|panic| {
                            Err(crate::host_panicked(&*worker_syscalls, task, panic))
                        })
                    }
                };
                done.report(result);
            })
        }))
        .map_err(|error| {
            crate::reject_profile(&*syscalls, task, ExecError::OwningThreadSpawn(error))
        })?;
    let result = completion.wait().await;
    waiting.0 = None;
    result
}
