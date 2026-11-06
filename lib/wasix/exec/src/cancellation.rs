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
    fn new(task: TaskId) -> Self {
        Self(Arc::new(Mutex::new(State {
            task,
            phase: Phase::Owned,
            requested: false,
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
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.task != task {
            return Transfer::Uninvolved;
        }
        match state.phase {
            Phase::Owned => {
                state.phase = Phase::Transferring;
                Transfer::Reserved(TransferGuard(Some(self.clone())))
            }
            #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
            Phase::Terminal => Transfer::Refused,
            // One takeover per image; leave existing transfer custody untouched.
            Phase::Transferring | Phase::Transferred => Transfer::Uninvolved,
        }
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
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    fn selected(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .selected
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    async fn terminal_owner(&self) -> Option<Arc<process::Handoff>> {
        poll_fn(|cx| {
            let next = cx.waker().clone();
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.phase == Phase::Transferring {
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
        .await
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
