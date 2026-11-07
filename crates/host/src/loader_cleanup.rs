//! Loader jobs only; unrelated detached host work does not delay runner retirement.

use crate::{Host, LocalFuture};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

pub type LoaderCleanupJob = Box<dyn FnOnce() -> LocalFuture<'static, ()> + Send>;
/// The factory crosses threads; its runner capability is supplied on materialization.
pub type LocalLoaderCleanupJob =
    Box<dyn FnOnce(Option<LocalCleanupRunner>) -> LocalFuture<'static, ()> + Send>;

/// Owner-local retirement custody. Implementations must commit custody before
/// invoking callbacks and retain a continuation if notification unwinds.
pub trait LocalCleanupSink {
    /// Trusted internal transfer of the SAME counted/canonical obligation.
    /// Fresh metadata-only work must use try_retain. This is a caller contract,
    /// not an unforgeable capability or a Store seal check.
    fn retain(&self, future: LocalFuture<'static, ()>);
    fn try_retain(&self, future: LocalFuture<'static, ()>) -> Result<(), LocalFuture<'static, ()>> {
        self.retain(future);
        Ok(())
    }
    fn notify(&self);
}

/// Local capability for the single runner of a shared cleanup scope. Keep this
/// capability across image replacements; shared image declarations retain only
/// the Send + Sync LoaderCleanup and receive this capability in their factories.
#[derive(Clone)]
pub struct LocalCleanupRunner {
    scope: Arc<LoaderCleanup>,
    sink: Rc<dyn LocalCleanupSink>,
}
impl LocalCleanupRunner {
    pub fn new(scope: Arc<LoaderCleanup>, sink: Rc<dyn LocalCleanupSink>) -> Self {
        Self { scope, sink }
    }
    pub fn shared(&self) -> &Arc<LoaderCleanup> {
        &self.scope
    }
    pub fn spawn(&self, future: LocalFuture<'static, ()>) {
        self.scope.spawn_inner(future, Some(self), false);
    }
    /// Only native owner drains use fallback; ordinary jobs retain their existing
    /// cancellation behavior and notify this local runner when their lease ends.
    pub fn spawn_with_fallback(&self, future: LocalFuture<'static, ()>) {
        self.scope.spawn_inner(future, Some(self), true);
    }
    /// Admit a new native cleanup obligation. Closed runners return exact custody;
    /// transferring a previously admitted ScopedJob never calls this method.
    pub fn retain(&self, future: LocalFuture<'static, ()>) -> Result<(), LocalFuture<'static, ()>> {
        {
            let mut state = self.scope.state();
            if state.closed {
                return Err(future);
            }
            state.pending += 1;
        }
        self.sink.try_retain(Box::pin(ScopedJob {
            future: Some(ScopedJobFuture::Counted(future)),
            completion: Some(Completion {
                scope: self.scope.clone(),
                local: Some(self.clone()),
            }),
            fallback: None,
            panicked: false,
        }))
    }
    /// Trusted internal transfer used by native Driver/attachment cancellation.
    /// The caller already owns the actual Store/generation/receipt obligation;
    /// fresh work must use retain. Err is ONLY the same raw input on scope close.
    pub fn retain_existing(
        &self,
        future: LocalFuture<'static, ()>,
    ) -> Result<(), LocalFuture<'static, ()>> {
        {
            let mut state = self.scope.state();
            if state.closed {
                return Err(future);
            }
            state.pending += 1;
        }
        self.sink.retain(Box::pin(ScopedJob {
            future: Some(ScopedJobFuture::Counted(future)),
            completion: Some(Completion {
                scope: self.scope.clone(),
                local: Some(self.clone()),
            }),
            fallback: None,
            panicked: false,
        }));
        Ok(())
    }
    pub fn submit(&self, job: LocalLoaderCleanupJob) -> Result<(), LocalLoaderCleanupJob> {
        self.scope.submit_local(job)
    }
    pub fn on_retire(
        &self,
        owner: &Arc<()>,
        job: LocalLoaderCleanupJob,
    ) -> Result<(), LocalLoaderCleanupJob> {
        self.scope.on_retire_local(owner, job)
    }
    pub fn run<'a, R: 'a, G: Future<Output = R> + 'a>(
        &self,
        guest: G,
    ) -> impl Future<Output = R> + 'a + use<'a, R, G> {
        Runner::new(self.scope.clone(), Some(self.clone()), guest, None)
    }
    pub fn run_with_keepalive<'a, R: 'a, G: Future<Output = R> + 'a, K: std::any::Any>(
        &self,
        guest: G,
        keepalive: K,
    ) -> impl Future<Output = R> + 'a + use<'a, R, G, K> {
        Runner::new(
            self.scope.clone(),
            Some(self.clone()),
            guest,
            Some(Box::new(keepalive)),
        )
    }
}

enum Job {
    Shared(LoaderCleanupJob),
    Local(LocalLoaderCleanupJob),
}
impl Job {
    fn materialize(self, local: Option<&LocalCleanupRunner>) -> LocalFuture<'static, ()> {
        match self {
            Self::Shared(job) => job(),
            Self::Local(job) => job(local.cloned()),
        }
    }
}

/// Resource-local completion metadata; retains no loader, host or job.
#[derive(Clone)]
pub struct LoaderSettlement(Arc<LoaderSettlementState>);
struct LoaderSettlementState {
    base_closed: AtomicBool,
    callbacks: AtomicUsize,
    destroyed: AtomicBool,
    waiters: Mutex<Vec<Weak<LoaderSettlementWaiter>>>,
}
struct LoaderSettlementWaiter {
    waker: Mutex<Option<Arc<Waker>>>,
}
/// One independently cancellable wake registration. Distinct Store owners may
/// observe the same loader without replacing each other's registrations.
pub struct LoaderSettlementObserver {
    state: Arc<LoaderSettlementState>,
    waiter: Arc<LoaderSettlementWaiter>,
}
struct LoaderSettlementGuard(LoaderSettlement);
struct LoaderCallbackSpan(LoaderSettlement);
impl LoaderSettlement {
    fn new() -> Self {
        Self(Arc::new(LoaderSettlementState {
            base_closed: AtomicBool::new(false),
            callbacks: AtomicUsize::new(0),
            destroyed: AtomicBool::new(false),
            waiters: Mutex::default(),
        }))
    }
    fn enter(&self) -> LoaderCallbackSpan {
        self.0.callbacks.fetch_add(1, Ordering::AcqRel);
        LoaderCallbackSpan(self.clone())
    }
    pub fn is_ready(&self) -> bool {
        (self.0.destroyed.load(Ordering::Acquire) || self.0.base_closed.load(Ordering::Acquire))
            && self.0.callbacks.load(Ordering::Acquire) == 0
    }
    pub fn observer(&self) -> LoaderSettlementObserver {
        let waiter = Arc::new(LoaderSettlementWaiter {
            waker: Mutex::default(),
        });
        self.0
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&waiter));
        LoaderSettlementObserver {
            state: self.0.clone(),
            waiter,
        }
    }
    fn notify(&self) {
        let unwinding = std::thread::panicking();
        let waiters = {
            let mut registered = self
                .0
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registered.retain(|waiter| waiter.strong_count() != 0);
            registered
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        let mut first = None;
        for waiter in waiters {
            let waker = waiter
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let signal = waker.clone(); // Arc clone never invokes RawWaker code
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callbacks(
                    || {
                        if let Some(waker) = signal {
                            waker.wake_by_ref();
                        }
                    },
                    || drop(waker),
                );
            }));
            if let Err(panic) = result {
                if first.is_none() {
                    first = Some(panic);
                } else {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(panic)));
                }
            }
        }
        if let Some(first) = first {
            if unwinding {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(first)));
            } else {
                std::panic::resume_unwind(first);
            }
        }
    }
}
impl LoaderSettlementObserver {
    fn subscribe(&self) {
        let identity = Arc::downgrade(&self.waiter);
        let mut waiters = self
            .state
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !waiters.iter().any(|waiter| waiter.ptr_eq(&identity)) {
            waiters.push(identity);
        }
    }
    fn unregister(&self) {
        self.state
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|waiter| !waiter.ptr_eq(&Arc::downgrade(&self.waiter)));
        let previous = self
            .waiter
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(previous);
    }
}
impl Future for LoaderSettlementObserver {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let handle = LoaderSettlement(self.state.clone());
        if handle.is_ready() {
            self.unregister();
            return Poll::Ready(());
        }
        // Closed readiness is nonmonotonic: a later real callback/destructor
        // span may be active after Ready removed this observer's registration.
        // Rearm the SAME identity before callback-bearing clone/drop code.
        self.subscribe();
        let next = Arc::new(cx.waker().clone());
        let previous = self
            .waiter
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(next);
        drop(previous);
        if handle.is_ready() {
            self.unregister();
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
impl Drop for LoaderSettlementObserver {
    fn drop(&mut self) {
        self.unregister();
    }
}
impl Drop for LoaderCallbackSpan {
    fn drop(&mut self) {
        if self.0.0.callbacks.fetch_sub(1, Ordering::AcqRel) == 1 && self.0.is_ready() {
            self.0.notify();
        }
    }
}
impl Drop for LoaderSettlementGuard {
    fn drop(&mut self) {
        // LoaderCleanup::drop enters before field destruction; this LAST field
        // publishes only after host/state/factory destructors returned or unwound.
        self.0.0.destroyed.store(true, Ordering::Release);
        self.0.0.callbacks.fetch_sub(1, Ordering::AcqRel);
        self.0.notify();
    }
}

pub struct LoaderCleanup {
    host: Arc<dyn Host>,
    state: Mutex<State>,
    settlement: LoaderSettlementGuard, // LAST: actual resource destruction receipt
}
#[derive(Default)]
struct State {
    jobs: VecDeque<Job>,
    retire: Vec<Retirement>,
    pending: usize,
    closed: bool,
    waker: Option<Waker>,
}
struct Retirement {
    owner: Weak<()>,
    job: Job,
}
impl LoaderCleanup {
    pub fn new(host: Arc<dyn Host>) -> Arc<Self> {
        Arc::new(Self {
            host,
            state: Mutex::default(),
            settlement: LoaderSettlementGuard(LoaderSettlement::new()),
        })
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn settlement(&self) -> LoaderSettlement {
        self.settlement.0.clone()
    }
    fn callback_span(&self) -> LoaderCallbackSpan {
        self.settlement.0.enter()
    }
    pub fn is_open(&self) -> bool {
        !self.state().closed
    }
    pub fn submit(self: &Arc<Self>, job: LoaderCleanupJob) -> Result<(), LoaderCleanupJob> {
        self.enqueue(Job::Shared(job)).map_err(|job| match job {
            Job::Shared(job) => job,
            _ => unreachable!(),
        })
    }
    pub fn submit_local(
        self: &Arc<Self>,
        job: LocalLoaderCleanupJob,
    ) -> Result<(), LocalLoaderCleanupJob> {
        self.enqueue(Job::Local(job)).map_err(|job| match job {
            Job::Local(job) => job,
            _ => unreachable!(),
        })
    }
    fn enqueue(&self, job: Job) -> Result<(), Job> {
        let _span = self.callback_span();
        let mut state = self.state();
        if state.closed {
            return Err(job);
        }
        state.pending += 1;
        state.jobs.push_back(job);
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }
    pub fn on_retire(
        &self,
        owner: &Arc<()>,
        job: LoaderCleanupJob,
    ) -> Result<(), LoaderCleanupJob> {
        self.retirement(owner, Job::Shared(job))
            .map_err(|job| match job {
                Job::Shared(job) => job,
                _ => unreachable!(),
            })
    }
    pub fn on_retire_local(
        &self,
        owner: &Arc<()>,
        job: LocalLoaderCleanupJob,
    ) -> Result<(), LocalLoaderCleanupJob> {
        self.retirement(owner, Job::Local(job))
            .map_err(|job| match job {
                Job::Local(job) => job,
                _ => unreachable!(),
            })
    }
    fn retirement(&self, owner: &Arc<()>, job: Job) -> Result<(), Job> {
        let _span = self.callback_span();
        let mut state = self.state();
        if state.closed {
            return Err(job);
        }
        let retired = std::mem::take(&mut state.retire);
        let mut expired = Vec::new();
        for retirement in retired {
            if retirement.owner.strong_count() != 0 {
                state.retire.push(retirement);
            } else {
                expired.push(retirement);
            }
        }
        state.retire.push(Retirement {
            owner: Arc::downgrade(owner),
            job,
        });
        drop(state);
        drop(expired); // factory destructors may reenter; never hold state mutex
        Ok(())
    }
    /// Transfer on this runner's executor while its guest or another job owns custody.
    pub fn spawn(self: &Arc<Self>, future: LocalFuture<'static, ()>) {
        self.spawn_inner(future, None, false);
    }
    fn spawn_inner(
        self: &Arc<Self>,
        future: LocalFuture<'static, ()>,
        local: Option<&LocalCleanupRunner>,
        fallback: bool,
    ) {
        let mut state = self.state();
        if state.closed {
            drop(state);
            self.host.executor().spawn_local(future);
            return;
        }
        state.pending += 1;
        drop(state);
        self.start(future, local, fallback);
    }
    fn start(
        self: &Arc<Self>,
        future: LocalFuture<'static, ()>,
        local: Option<&LocalCleanupRunner>,
        fallback: bool,
    ) {
        self.host.executor().spawn_local(Box::pin(ScopedJob {
            future: Some(ScopedJobFuture::Counted(future)),
            completion: Some(Completion {
                scope: self.clone(),
                local: local.cloned(),
            }),
            fallback: fallback
                .then(|| local.expect("fallback requires local custody").sink.clone()),
            panicked: false,
        }));
    }
    fn flush(self: &Arc<Self>, cx: &mut Context<'_>, local: Option<&LocalCleanupRunner>) {
        let _span = self.callback_span();
        let next = cx.waker().clone();
        let old = self.state().waker.replace(next);
        drop(old);
        loop {
            // Keep unmaterialized factories in shared custody if a factory or its
            // destructor unwinds. The popped admission has its lease first.
            let Some(job) = self.state().jobs.pop_front() else {
                break;
            };
            let completion = Completion {
                scope: self.clone(),
                local: local.cloned(),
            };
            let future = job.materialize(local);
            self.host.executor().spawn_local(Box::pin(ScopedJob {
                future: Some(ScopedJobFuture::Counted(future)),
                completion: Some(completion),
                fallback: None,
                panicked: false,
            }));
        }
    }
    fn poll_drain(
        self: &Arc<Self>,
        cx: &mut Context<'_>,
        local: Option<&LocalCleanupRunner>,
    ) -> Poll<()> {
        let _span = self.callback_span();
        loop {
            self.flush(cx, local);
            let retired = {
                let mut state = self.state();
                if state.pending != 0 {
                    return Poll::Pending;
                }
                std::mem::take(&mut state.retire)
            };
            let mut expired = Vec::new();
            {
                let mut state = self.state();
                for retirement in retired {
                    if retirement.owner.strong_count() != 0 {
                        state.pending += 1;
                        state.jobs.push_back(retirement.job);
                    } else {
                        expired.push(retirement);
                    }
                }
            }
            drop(expired);
            let closed_waker = {
                let mut state = self.state();
                if state.pending != 0 || !state.jobs.is_empty() || !state.retire.is_empty() {
                    continue;
                }
                state.closed = true;
                self.settlement
                    .0
                    .0
                    .base_closed
                    .store(true, Ordering::Release);
                state.waker.take()
            };
            drop(closed_waker);
            return Poll::Ready(());
        }
    }
    pub fn run<'a, R: 'a>(
        self: &Arc<Self>,
        guest: impl Future<Output = R> + 'a,
    ) -> impl Future<Output = R> + 'a {
        Runner::new(self.clone(), None, guest, None)
    }
    pub fn run_with_keepalive<'a, R: 'a>(
        self: &Arc<Self>,
        guest: impl Future<Output = R> + 'a,
        keepalive: impl std::any::Any,
    ) -> impl Future<Output = R> + 'a {
        Runner::new(self.clone(), None, guest, Some(Box::new(keepalive)))
    }
}

impl Drop for LoaderCleanup {
    fn drop(&mut self) {
        // Keep an already-closed scope unready through actual field destruction.
        self.settlement.0.0.callbacks.fetch_add(1, Ordering::AcqRel);
    }
}

fn callbacks(wake: impl FnOnce(), notify: impl FnOnce()) {
    let unwinding = std::thread::panicking();
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(wake));
    let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(notify));
    let mut failures = [first, second].into_iter().filter_map(Result::err);
    let first = failures.next();
    for failure in failures {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(failure)));
    }
    if let Some(first) = first {
        if unwinding {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(first)));
        } else {
            std::panic::resume_unwind(first);
        }
    }
}
struct Completion {
    scope: Arc<LoaderCleanup>,
    local: Option<LocalCleanupRunner>,
}
impl Drop for Completion {
    fn drop(&mut self) {
        let _span = self.scope.callback_span();
        let waker = {
            let mut state = self.scope.state();
            state.pending -= 1;
            state.waker.take()
        };
        callbacks(
            || {
                if let Some(waker) = waker {
                    waker.wake();
                }
            },
            || {
                if let Some(local) = &self.local {
                    local.sink.notify();
                }
            },
        );
    }
}

/// This wrapper transfers the same future and completion lease before either
/// can drop. The sink-owned copy has no recursive executor fallback.
enum ScopedJobFuture {
    Counted(LocalFuture<'static, ()>),
    CanonicalFinalDrain(FinalDrain),
}
impl Future for ScopedJobFuture {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.get_mut() {
            Self::Counted(future) => future.as_mut().poll(cx),
            Self::CanonicalFinalDrain(future) => Pin::new(future).poll(cx),
        }
    }
}
struct ScopedJob {
    future: Option<ScopedJobFuture>,
    completion: Option<Completion>,
    fallback: Option<Rc<dyn LocalCleanupSink>>,
    panicked: bool,
}
impl Unpin for ScopedJob {}
impl Future for ScopedJob {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let _span = this
            .completion
            .as_ref()
            .map(|completion| completion.scope.callback_span())
            .or_else(|| match &this.future {
                Some(ScopedJobFuture::CanonicalFinalDrain(future)) => {
                    future.scope().map(|scope| scope.callback_span())
                }
                _ => None,
            });
        let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(this.future.as_mut().expect("live cleanup")).poll(cx)
        }));
        match polled {
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(())) => (),
            Err(panic) => {
                this.panicked = true;
                std::panic::resume_unwind(panic);
            }
        }
        drop(this.future.take());
        drop(this.completion.take());
        this.fallback = None;
        Poll::Ready(())
    }
}
impl Drop for ScopedJob {
    fn drop(&mut self) {
        let _span = self
            .completion
            .as_ref()
            .map(|completion| completion.scope.callback_span())
            .or_else(|| match &self.future {
                Some(ScopedJobFuture::CanonicalFinalDrain(future)) => {
                    future.scope().map(|scope| scope.callback_span())
                }
                _ => None,
            });
        if let Some(ScopedJobFuture::CanonicalFinalDrain(future)) = &mut self.future {
            future.finish_closed();
        }
        if !self.panicked
            && let Some(sink) = self.fallback.take()
            && self.future.as_ref().is_some_and(|future| {
                !matches!(
                    future,
                    ScopedJobFuture::CanonicalFinalDrain(FinalDrain {
                        completed: true,
                        ..
                    })
                )
            })
        {
            let future = Box::pin(Self {
                future: self.future.take(),
                completion: self.completion.take(),
                fallback: None,
                panicked: false,
            });
            callbacks(|| {}, || sink.retain(future));
            return;
        }
        // A panicked async orchestration is never polled again. Embedded native
        // guards commit replacement state while the original lease is still held.
        let future = self.future.take();
        let completion = self.completion.take();
        let fallback = self.fallback.take();
        callbacks(
            || callbacks(|| drop(future), || drop(completion)),
            || drop(fallback),
        );
    }
}

struct Drain {
    scope: Arc<LoaderCleanup>,
    local: Option<LocalCleanupRunner>,
}
impl Future for Drain {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.scope.poll_drain(cx, self.local.as_ref())
    }
}
enum FinalDrainObserver {
    Canonical(Drain),
    // Existing manual panic-observer control; production never erases a Drain.
    #[cfg(test)]
    Opaque(LocalFuture<'static, ()>),
}
impl Future for FinalDrainObserver {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.get_mut() {
            Self::Canonical(drain) => Pin::new(drain).poll(cx),
            #[cfg(test)]
            Self::Opaque(future) => future.as_mut().poll(cx),
        }
    }
}
struct FinalDrain {
    drain: Option<FinalDrainObserver>,
    keepalive: Option<Box<dyn std::any::Any>>,
    local: Option<LocalCleanupRunner>,
    completed: bool,
}
impl Future for FinalDrain {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let _span = this.scope().map(|scope| scope.callback_span());
        if Pin::new(this.drain.as_mut().expect("live final drain"))
            .poll(cx)
            .is_pending()
        {
            return Poll::Pending;
        }
        this.completed = true;
        let drain = this.drain.take();
        let keepalive = this.keepalive.take();
        callbacks(|| drop(drain), || drop(keepalive));
        Poll::Ready(())
    }
}
impl FinalDrain {
    fn scope(&self) -> Option<&Arc<LoaderCleanup>> {
        match self.drain.as_ref()? {
            FinalDrainObserver::Canonical(drain) => Some(&drain.scope),
            #[cfg(test)]
            FinalDrainObserver::Opaque(_) => self.local.as_ref().map(|local| &local.scope),
        }
    }
    /// Only a concrete Drain may use this shortcut, never an opaque async frame.
    fn finish_closed(&mut self) -> bool {
        if self.completed {
            return true;
        }
        let Some(FinalDrainObserver::Canonical(drain)) = self.drain.as_ref() else {
            return false;
        };
        let scope = drain.scope.clone();
        let _span = scope.callback_span();
        let waker = {
            let mut state = scope.state();
            if state.pending != 0 || !state.jobs.is_empty() || !state.retire.is_empty() {
                return false;
            }
            state.closed = true;
            scope
                .settlement
                .0
                .0
                .base_closed
                .store(true, Ordering::Release);
            state.waker.take()
        };
        // Commit and take SAME fields before ANY fallible callback/drop.
        self.completed = true;
        let drain = self.drain.take();
        let keepalive = self.keepalive.take();
        callbacks(
            || drop(waker),
            || callbacks(|| drop(drain), || drop(keepalive)),
        );
        true
    }
}
impl Drop for FinalDrain {
    fn drop(&mut self) {
        let _span = self.scope().map(|scope| scope.callback_span());
        if self.finish_closed() {
            return;
        }
        if let Some(local) = self.local.take() {
            let future = Box::pin(Self {
                drain: self.drain.take(),
                keepalive: self.keepalive.take(),
                local: Some(local.clone()),
                completed: false,
            });
            self.completed = true; // replacement owns every unfinished field
            // This same obligation is uncounted: it observes the counted jobs.
            // A failed poll transfers its actual drain/lease without the executor.
            callbacks(|| {}, || local.sink.retain(future));
        } else {
            // Unbound/shared cancellation retains its old disposal behavior,
            // but actual fields must finish inside the callback span as well.
            self.completed = true;
            let drain = self.drain.take();
            let keepalive = self.keepalive.take();
            callbacks(|| drop(drain), || drop(keepalive));
        }
    }
}
struct Runner<'a, R> {
    scope: Arc<LoaderCleanup>,
    local: Option<LocalCleanupRunner>,
    guest: Option<LocalFuture<'a, R>>,
    output: Option<R>,
    drain: Option<Drain>,
    keepalive: Option<Box<dyn std::any::Any>>,
    done: bool,
}
impl<'a, R: 'a> Runner<'a, R> {
    fn new(
        scope: Arc<LoaderCleanup>,
        local: Option<LocalCleanupRunner>,
        guest: impl Future<Output = R> + 'a,
        keepalive: Option<Box<dyn std::any::Any>>,
    ) -> Self {
        Self {
            scope,
            local,
            guest: Some(Box::pin(guest)),
            output: None,
            drain: None,
            keepalive,
            done: false,
        }
    }
}
impl<R> Unpin for Runner<'_, R> {}
impl<R> Future for Runner<'_, R> {
    type Output = R;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let this = self.get_mut();
        let _span = this.scope.callback_span();
        this.scope.flush(cx, this.local.as_ref());
        if let Some(guest) = &mut this.guest {
            match guest.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(output) => this.output = Some(output),
            }
            drop(this.guest.take());
            this.drain = Some(Drain {
                scope: this.scope.clone(),
                local: this.local.clone(),
            });
        }
        if Pin::new(this.drain.as_mut().unwrap()).poll(cx).is_pending() {
            return Poll::Pending;
        }
        this.drain = None;
        this.done = true;
        let output = this.output.take().unwrap();
        drop(this.keepalive.take());
        Poll::Ready(output)
    }
}
impl<R> Drop for Runner<'_, R> {
    fn drop(&mut self) {
        let _span = self.scope.callback_span();
        if self.done {
            return;
        }
        let custody = DrainCustody {
            scope: self.scope.clone(),
            local: self.local.clone(),
            drain: self.drain.take(),
            keepalive: self.keepalive.take(),
        };
        let output = self.output.take();
        let guest = self.guest.take();
        callbacks(
            || callbacks(|| drop(guest), || drop(output)),
            || drop(custody),
        );
    }
}
struct DrainCustody {
    scope: Arc<LoaderCleanup>,
    local: Option<LocalCleanupRunner>,
    drain: Option<Drain>,
    keepalive: Option<Box<dyn std::any::Any>>,
}
impl Drop for DrainCustody {
    fn drop(&mut self) {
        let _span = self.scope.callback_span();
        let mut future = FinalDrain {
            drain: Some(FinalDrainObserver::Canonical(
                self.drain.take().unwrap_or_else(|| Drain {
                    scope: self.scope.clone(),
                    local: self.local.clone(),
                }),
            )),
            keepalive: self.keepalive.take(),
            local: self.local.clone(),
            completed: false,
        };
        if future.finish_closed() {
            return;
        }
        if let Some(local) = &self.local {
            self.scope.host.executor().spawn_local(Box::pin(ScopedJob {
                future: Some(ScopedJobFuture::CanonicalFinalDrain(future)),
                completion: None,
                fallback: Some(local.sink.clone()),
                panicked: false,
            }));
        } else {
            self.scope.host.executor().spawn_local(Box::pin(future));
        }
    }
}

#[cfg(all(test, feature = "tokio", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{Host, TokioHost};
    use std::{
        future::{Future, pending, poll_fn},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };
    #[test]
    fn canceling_without_loader_work_needs_no_executor_context() {
        // Default/custom ABIs must not gain a detached task on cancellation.
        let host: Arc<dyn Host> = Arc::new(TokioHost::default());
        let scope = LoaderCleanup::new(host);
        drop(scope.run(pending::<()>()));
        assert!(!scope.is_open());
    }
    #[tokio::test]
    async fn runner_waits_for_loader_jobs_but_not_unrelated_host_work() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let host: Arc<dyn Host> = Arc::new(TokioHost::default());
                host.executor().spawn_local(Box::pin(pending()));
                let scope = LoaderCleanup::new(host);
                let done = Arc::new(AtomicBool::new(false));
                let job_done = done.clone();
                let result = scope
                    .run(async {
                        scope.spawn(Box::pin(async move {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            job_done.store(true, Ordering::Release);
                        }));
                        42
                    })
                    .await;
                assert_eq!(result, 42);
                assert!(done.load(Ordering::Acquire));
                assert!(!scope.is_open());
            })
            .await;
    }
    #[tokio::test]
    async fn final_weak_callbacks_follow_guest_teardown_and_prior_cleanup() {
        use std::sync::atomic::AtomicUsize;
        struct Guest(Arc<AtomicUsize>);
        impl Drop for Guest {
            fn drop(&mut self) {
                self.0.store(1, Ordering::Release);
            }
        }
        let local = tokio::task::LocalSet::new();
        let phase = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(());
        local
            .run_until(async {
                let scope = LoaderCleanup::new(Arc::new(TokioHost::default()));
                let image = Arc::new(());
                let weak = Arc::downgrade(&image);
                let checked = phase.clone();
                assert!(
                    scope
                        .on_retire(
                            &owner,
                            Box::new(move || Box::pin(async move {
                                assert!(
                                    weak.upgrade().is_none(),
                                    "weak callback must not pin image"
                                );
                                assert_eq!(checked.load(Ordering::Acquire), 2);
                                checked.store(3, Ordering::Release);
                            }))
                        )
                        .is_ok()
                );
                let stage = phase.clone();
                let mut runner = Box::pin(scope.run(async {
                    let _guest = Guest(phase.clone());
                    let _image = image;
                    scope.spawn(Box::pin(async move {
                        // The canceled guest drops before this executor polls its job.
                        assert_eq!(stage.load(Ordering::Acquire), 1);
                        stage.store(2, Ordering::Release);
                    }));
                    pending::<()>().await;
                }));
                poll_fn(|cx| {
                    assert!(runner.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(runner);
            })
            .await;
        local.await;
        assert_eq!(phase.load(Ordering::Acquire), 3);
    }
    async fn keepalive_proof(panic_on_drop: bool) {
        use std::{cell::Cell, rc::Rc};
        type Events = Arc<Mutex<Vec<&'static str>>>;
        struct Lease {
            scope: Weak<LoaderCleanup>,
            released: Rc<Cell<bool>>,
            closed: Rc<Cell<bool>>,
            events: Events,
        }
        impl Drop for Lease {
            fn drop(&mut self) {
                self.closed
                    .set(self.scope.upgrade().is_none_or(|scope| !scope.is_open()));
                self.events.lock().unwrap().push("lease_drop");
                self.released.set(true);
            }
        }
        struct Guest {
            scope: Arc<LoaderCleanup>,
            job: Option<LocalFuture<'static, ()>>,
            panic_on_drop: bool,
            events: Events,
        }
        impl Future for Guest {
            type Output = i32;
            fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<i32> {
                if let Some(job) = self.job.take() {
                    self.scope.spawn(job);
                }
                if self.panic_on_drop {
                    Poll::Pending
                } else {
                    Poll::Ready(42)
                }
            }
        }
        impl Drop for Guest {
            fn drop(&mut self) {
                self.events.lock().unwrap().push("guest_drop");
                assert!(!self.panic_on_drop, "guest destructor proof");
            }
        }
        tokio::task::LocalSet::new()
            .run_until(async move {
                let scope = LoaderCleanup::new(Arc::new(TokioHost::default()));
                let released = Rc::new(Cell::new(false));
                let closed = Rc::new(Cell::new(false));
                let events: Events = Arc::default();
                let (send, receive) = tokio::sync::oneshot::channel::<()>();
                let job_events = events.clone();
                let guest = Guest {
                    scope: scope.clone(),
                    job: Some(Box::pin(async move {
                        receive.await.unwrap();
                        job_events.lock().unwrap().push("job_done");
                    })),
                    panic_on_drop,
                    events: events.clone(),
                };
                let lease = Lease {
                    scope: Arc::downgrade(&scope),
                    released: released.clone(),
                    closed: closed.clone(),
                    events: events.clone(),
                };
                let mut runner = Box::pin(scope.run_with_keepalive(guest, lease));
                poll_fn(|cx| {
                    assert!(runner.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runner)));
                assert_eq!(result.is_err(), panic_on_drop);
                assert!(!released.get(), "pending drain lost its owner-local lease");
                send.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !released.get() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(closed.get());
                assert_eq!(
                    *events.lock().unwrap(),
                    ["guest_drop", "job_done", "lease_drop"]
                );
            })
            .await;
    }

    #[tokio::test]
    async fn keepalive_survives_cancellation_of_an_in_progress_drain() {
        keepalive_proof(false).await;
    }

    #[tokio::test]
    async fn guest_destructor_panic_keeps_the_lease_until_cleanup_finishes() {
        keepalive_proof(true).await;
    }

    #[tokio::test]
    async fn panicking_old_waker_keeps_queued_factories_in_scope_custody() {
        struct DropPanic;
        // The custom destructor is the operation exercised by this regression.
        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for DropPanic {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for DropPanic {
            fn drop(&mut self) {
                panic!("old cleanup waker destructor proof");
            }
        }
        tokio::task::LocalSet::new()
            .run_until(async {
                let scope = LoaderCleanup::new(Arc::new(TokioHost::default()));
                let executed = Arc::new(AtomicBool::new(false));
                let job_executed = executed.clone();
                assert!(
                    scope
                        .submit(Box::new(move || {
                            Box::pin(async move {
                                job_executed.store(true, Ordering::Release);
                            })
                        }))
                        .is_ok()
                );
                scope.state().waker = Some(Waker::from(Arc::new(DropPanic)));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    scope.flush(&mut Context::from_waker(Waker::noop()), None);
                }));
                assert!(result.is_err());
                {
                    let state = scope.state();
                    assert_eq!(state.pending, 1);
                    assert_eq!(state.jobs.len(), 1);
                }
                assert!(!executed.load(Ordering::Acquire));
                scope.run(async {}).await;
                assert!(executed.load(Ordering::Acquire));
                assert!(!scope.is_open());
            })
            .await;
    }

    #[test]
    fn dead_weak_callbacks_stay_bounded_across_image_replacements() {
        let scope = LoaderCleanup::new(Arc::new(TokioHost::default()));
        for _ in 0..1000 {
            let owner = Arc::new(());
            assert!(
                scope
                    .on_retire(
                        &owner,
                        Box::new(|| Box::pin(async {
                            panic!("dead image callback must not execute");
                        }))
                    )
                    .is_ok()
            );
            assert!(scope.state().retire.len() <= 1);
        }
        let mut run = Box::pin(scope.run(async {}));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(run.as_mut().poll(&mut cx).is_ready());
    }
    #[test]
    fn native_worker_finishes_scoped_release_before_retirement() {
        use std::sync::mpsc;
        let host: Arc<dyn Host> = Arc::new(TokioHost::default());
        let worker_host = host.clone();
        let (send, receive) = mpsc::channel();
        host.executor()
            .spawn_thread(Box::new(move || {
                let scope = LoaderCleanup::new(worker_host);
                Box::pin(async move {
                    let release = send.clone();
                    scope
                        .run(async {
                            scope.spawn(Box::pin(async move {
                                tokio::task::yield_now().await;
                                release.send("released").unwrap();
                            }));
                        })
                        .await;
                    send.send("retired").unwrap();
                })
            }))
            .unwrap();
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(5)).unwrap(),
            "released"
        );
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(5)).unwrap(),
            "retired"
        );
    }
    #[tokio::test]
    async fn canceling_runner_transfers_exact_drain_and_keeps_nonce() {
        let local = tokio::task::LocalSet::new();
        let weak = local
            .run_until(async {
                let host: Arc<dyn Host> = Arc::new(TokioHost::default());
                let scope = LoaderCleanup::new(host);
                let nonce = Arc::new(());
                let weak = Arc::downgrade(&nonce);
                let mut runner = Box::pin(scope.run(async {
                    scope.spawn(Box::pin(async move {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        drop(nonce);
                    }));
                }));
                poll_fn(|cx| {
                    assert!(runner.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(runner);
                assert!(weak.upgrade().is_some());
                weak
            })
            .await;
        local.await;
        assert!(weak.upgrade().is_none());
    }
}

#[cfg(test)]
mod local_custody_tests {
    use super::*;
    use crate::Executor;
    use std::{
        cell::{Cell, RefCell},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Duration,
    };

    thread_local! {
        static JOBS: RefCell<Vec<LocalFuture<'static, ()>>> = const { RefCell::new(Vec::new()) };
    }
    struct QueueHost(AtomicBool);
    impl Host for QueueHost {
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
    impl Executor for QueueHost {
        fn spawn_local(&self, future: LocalFuture<'static, ()>) {
            if self.0.load(Ordering::SeqCst) {
                drop(future);
            } else {
                JOBS.with(|jobs| jobs.borrow_mut().push(future));
            }
        }
        fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
            Box::pin(async move { work() })
        }
    }
    #[derive(Default)]
    struct Sink {
        futures: RefCell<Vec<LocalFuture<'static, ()>>>,
        running: Cell<bool>,
        ready: Cell<bool>,
        notifications: Cell<usize>,
    }
    impl LocalCleanupSink for Sink {
        fn retain(&self, future: LocalFuture<'static, ()>) {
            self.futures.borrow_mut().push(future);
            self.notify();
        }
        fn notify(&self) {
            self.notifications.set(self.notifications.get() + 1);
            self.ready.set(true);
            if self.running.replace(true) {
                return;
            }
            while self.ready.replace(false) {
                let futures = std::mem::take(&mut *self.futures.borrow_mut());
                for mut future in futures {
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                    {
                        self.futures.borrow_mut().push(future);
                    }
                }
            }
            self.running.set(false);
        }
    }
    struct Probe {
        ready: Arc<AtomicBool>,
        dropped: Arc<AtomicUsize>,
        address: Arc<AtomicUsize>,
    }
    impl Future for Probe {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            let address = (&*self as *const Self) as usize;
            let previous = self.address.swap(address, Ordering::SeqCst);
            assert!(
                previous == 0 || previous == address,
                "the exact pinned future moved"
            );
            if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn probe() -> (Probe, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let ready = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        (
            Probe {
                ready: ready.clone(),
                dropped: dropped.clone(),
                address: Arc::new(AtomicUsize::new(0)),
            },
            ready,
            dropped,
        )
    }
    #[test]
    fn queued_native_discard_transfers_exact_future_and_completion_lease_once() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<LoaderCleanup>();
        assert!(JOBS.with(|jobs| jobs.borrow().is_empty()));
        let host = Arc::new(QueueHost(AtomicBool::new(false)));
        let scope = LoaderCleanup::new(host);
        let sink = Rc::new(Sink::default());
        let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
        let (future, ready, dropped) = probe();
        local.spawn_with_fallback(Box::pin(future));
        let mut queued = JOBS.with(|jobs| jobs.borrow_mut().pop().unwrap());
        assert!(
            queued
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(queued);
        assert_eq!(
            scope.state().pending,
            1,
            "discard is a transfer, not completion"
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(
            JOBS.with(|jobs| jobs.borrow().is_empty()),
            "no recursive executor submission"
        );
        ready.store(true, Ordering::SeqCst);
        sink.notify();
        assert_eq!(scope.state().pending, 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(sink.futures.borrow().is_empty());
    }
    #[test]
    fn final_drain_waits_for_generic_completion_after_the_last_native_event() {
        assert!(JOBS.with(|jobs| jobs.borrow().is_empty()));
        let host = Arc::new(QueueHost(AtomicBool::new(false)));
        let scope = LoaderCleanup::new(host.clone());
        let sink = Rc::new(Sink::default());
        let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
        let (future, ready, dropped) = probe();
        local.spawn(Box::pin(future));
        struct Lease(Rc<Cell<bool>>);
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let released = Rc::new(Cell::new(false));
        let mut runner = Box::pin(local.run_with_keepalive(async {}, Lease(released.clone())));
        assert!(
            runner
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        host.0.store(true, Ordering::SeqCst);
        drop(runner); // Final drain is synchronously discarded into local custody.
        assert!(!released.get());
        assert_eq!(
            scope.state().pending,
            1,
            "the final drain does not count itself"
        );
        ready.store(true, Ordering::SeqCst);
        let mut job = JOBS.with(|jobs| jobs.borrow_mut().pop().unwrap());
        assert!(
            job.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(job); // This ordinary Completion is the only remaining progress event.
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(released.get());
        assert!(!scope.is_open());
        assert!(sink.futures.borrow().is_empty());
    }
    #[test]
    fn generic_completion_notifies_owner_after_a_panicking_user_waker() {
        struct PanicWake;
        impl std::task::Wake for PanicWake {
            fn wake(self: Arc<Self>) {
                panic!("cleanup wake proof");
            }
        }
        assert!(JOBS.with(|jobs| jobs.borrow().is_empty()));
        let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
        let sink = Rc::new(Sink::default());
        let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
        local.spawn(Box::pin(async {}));
        scope.state().waker = Some(Waker::from(Arc::new(PanicWake)));
        let job = JOBS.with(|jobs| jobs.borrow_mut().pop().unwrap());
        let panic =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(job))).unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"cleanup wake proof"));
        assert_eq!(scope.state().pending, 0);
        assert_eq!(sink.notifications.get(), 1);
    }

    #[test]
    fn final_drain_poll_panic_transfers_the_exact_drain_and_keepalive() {
        struct PanicOnceThenPending {
            polls: Rc<Cell<usize>>,
            address: Rc<Cell<usize>>,
            ready: Rc<Cell<bool>>,
            drops: Rc<Cell<usize>>,
        }
        impl Future for PanicOnceThenPending {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                let this = self.get_mut();
                let address = this as *mut Self as usize;
                let previous = this.address.replace(address);
                assert!(previous == 0 || previous == address, "exact drain moved");
                let polls = this.polls.get() + 1;
                this.polls.set(polls);
                if polls == 1 {
                    panic!("final drain poll proof");
                }
                if this.ready.get() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }
        impl Drop for PanicOnceThenPending {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }
        struct Lease(Rc<Cell<usize>>);
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let sink = Rc::new(Sink::default());
        let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
        let local = LocalCleanupRunner::new(scope, sink.clone());
        let polls = Rc::new(Cell::new(0));
        let address = Rc::new(Cell::new(0));
        let ready = Rc::new(Cell::new(false));
        let drops = Rc::new(Cell::new(0));
        let lease_drops = Rc::new(Cell::new(0));
        let drain: LocalFuture<'static, ()> = Box::pin(PanicOnceThenPending {
            polls: polls.clone(),
            address: address.clone(),
            ready: ready.clone(),
            drops: drops.clone(),
        });
        let mut final_drain = Box::pin(FinalDrain {
            drain: Some(FinalDrainObserver::Opaque(drain)),
            keepalive: Some(Box::new(Lease(lease_drops.clone()))),
            local: Some(local),
            completed: false,
        });
        let first_poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            final_drain
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
        }))
        .unwrap_err();
        assert_eq!(
            first_poll.downcast_ref::<&str>(),
            Some(&"final drain poll proof")
        );

        // FinalDrain's own Drop must transfer both exact objects before the
        // owner-local poll can run or any panic can escape.
        drop(final_drain);
        assert_eq!(polls.get(), 2);
        assert_eq!(drops.get(), 0);
        assert_eq!(lease_drops.get(), 0);
        assert_eq!(sink.futures.borrow().len(), 1);
        ready.set(true);
        sink.notify();
        assert_eq!(polls.get(), 3);
        assert_eq!(drops.get(), 1);
        assert_eq!(lease_drops.get(), 1);
        assert!(sink.futures.borrow().is_empty());
    }

    #[test]
    fn drain_custody_finishes_after_a_panicking_raw_waker_destructor() {
        struct Lease(Rc<Cell<usize>>);
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        struct DropPanicWake;
        impl std::task::Wake for DropPanicWake {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for DropPanicWake {
            fn drop(&mut self) {
                panic!("drain custody waker destructor proof");
            }
        }

        let host = Arc::new(QueueHost(AtomicBool::new(false)));
        let scope = LoaderCleanup::new(host);
        let sink = Rc::new(Sink::default());
        let local = LocalCleanupRunner::new(scope.clone(), sink);
        local.spawn(Box::pin(async {}));
        let lease_drops = Rc::new(Cell::new(0));
        let mut runner = Box::pin(local.run_with_keepalive(async {}, Lease(lease_drops.clone())));
        assert!(
            runner
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let mut job = JOBS.with(|jobs| jobs.borrow_mut().pop().unwrap());
        assert!(
            job.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(job);
        assert_eq!(scope.state().pending, 0);
        // Reinstall a destructor that panics after the runner's ordinary
        // completion callback has already returned.
        scope.state().waker = Some(Waker::from(Arc::new(DropPanicWake)));

        let panic =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runner))).unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"drain custody waker destructor proof")
        );
        assert!(!scope.is_open());
        assert_eq!(lease_drops.get(), 1);
    }

    #[test]
    fn factory_panic_keeps_admitted_sibling_until_final_drain() {
        let host = Arc::new(QueueHost(AtomicBool::new(false)));
        let scope = LoaderCleanup::new(host);
        let sink = Rc::new(Sink::default());
        let local = LocalCleanupRunner::new(scope.clone(), sink);
        let first: LocalLoaderCleanupJob =
            Box::new(|_| -> LocalFuture<'static, ()> { panic!("factory panic proof") });
        let materialized = Arc::new(AtomicUsize::new(0));
        let ran = Arc::new(AtomicUsize::new(0));
        let made = materialized.clone();
        let ran_by_future = ran.clone();
        let sibling: LocalLoaderCleanupJob = Box::new(move |_| -> LocalFuture<'static, ()> {
            made.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                ran_by_future.fetch_add(1, Ordering::SeqCst);
            })
        });
        assert!(local.submit(first).is_ok());
        assert!(local.submit(sibling).is_ok());
        let lease_drops = Rc::new(Cell::new(0));
        let mut runner = Box::pin(local.run_with_keepalive(async {}, {
            struct Lease(Rc<Cell<usize>>);
            impl Drop for Lease {
                fn drop(&mut self) {
                    self.0.set(self.0.get() + 1);
                }
            }
            Lease(lease_drops.clone())
        }));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"factory panic proof"));
        assert_eq!(scope.state().pending, 1);
        assert_eq!(scope.state().jobs.len(), 1, "sibling admission was lost");
        drop(runner);
        assert_eq!(lease_drops.get(), 0);

        let mut final_drain = JOBS.with(|jobs| jobs.borrow_mut().pop().unwrap());
        assert!(
            final_drain
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(materialized.load(Ordering::SeqCst), 1);
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        let mut sibling = JOBS.with(|jobs| jobs.borrow_mut().pop().unwrap());
        assert!(
            sibling
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(sibling);
        assert_eq!(scope.state().pending, 0);
        assert!(
            final_drain
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(final_drain);
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(lease_drops.get(), 1);
        assert!(!scope.is_open());
    }

    #[test]
    fn runner_drop_during_unwind_preserves_primary_panic_and_cleanup_custody() {
        const CHILD: &str = "WASIXV2_CLEANUP_UNWIND_DROP_CHILD";
        const TEST: &str = "loader_cleanup::local_custody_tests::runner_drop_during_unwind_preserves_primary_panic_and_cleanup_custody";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(TEST)
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated unwind proof failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        struct Lease(Rc<Cell<usize>>);
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        struct DropOnUnwind<R>(Option<LocalFuture<'static, R>>);
        impl<R> Drop for DropOnUnwind<R> {
            fn drop(&mut self) {
                drop(self.0.take());
            }
        }
        struct PanickingGuest;
        impl Future for PanickingGuest {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        impl Drop for PanickingGuest {
            fn drop(&mut self) {
                panic!("guest destructor proof");
            }
        }
        struct PanickingOutput;
        impl Drop for PanickingOutput {
            fn drop(&mut self) {
                panic!("output destructor proof");
            }
        }
        struct DropPanicWake;
        impl std::task::Wake for DropPanicWake {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for DropPanicWake {
            fn drop(&mut self) {
                panic!("unwind waker destructor proof");
            }
        }
        fn drop_runner_during_primary_unwind<R: 'static>(runner: LocalFuture<'static, R>) {
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _runner = DropOnUnwind(Some(runner));
                panic!("primary unwind proof");
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&str>(), Some(&"primary unwind proof"));
        }

        fn fixture() -> (
            Arc<LoaderCleanup>,
            Rc<Sink>,
            LocalCleanupRunner,
            Arc<AtomicBool>,
        ) {
            let host = Arc::new(QueueHost(AtomicBool::new(true)));
            let scope = LoaderCleanup::new(host);
            let sink = Rc::new(Sink::default());
            let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
            let (future, ready, _) = probe();
            assert!(local.retain(Box::pin(future)).is_ok());
            (scope, sink, local, ready)
        }
        fn settle(
            scope: &Arc<LoaderCleanup>,
            sink: &Sink,
            ready: &AtomicBool,
            lease_drops: &Cell<usize>,
        ) {
            assert_eq!(lease_drops.get(), 0, "pending work lost keepalive");
            assert_eq!(scope.state().pending, 1);
            ready.store(true, Ordering::SeqCst);
            sink.notify();
            assert_eq!(scope.state().pending, 0);
            assert_eq!(lease_drops.get(), 1);
            assert!(!scope.is_open());
        }

        // A guest future's destructor can panic while the caller is already
        // unwinding; its admitted sibling and the exact lease still settle.
        {
            let (scope, sink, local, ready) = fixture();
            let lease_drops = Rc::new(Cell::new(0));
            let mut runner: LocalFuture<'static, ()> =
                Box::pin(local.run_with_keepalive(PanickingGuest, Lease(lease_drops.clone())));
            assert!(
                runner
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop_runner_during_primary_unwind(runner);
            settle(&scope, &sink, &ready, &lease_drops);
        }

        // The output destructor is a distinct Runner::drop phase after guest
        // completion; it must not bypass transfer of the final drain.
        {
            let (scope, sink, local, ready) = fixture();
            let lease_drops = Rc::new(Cell::new(0));
            let mut runner: LocalFuture<'static, PanickingOutput> = Box::pin(
                local.run_with_keepalive(async { PanickingOutput }, Lease(lease_drops.clone())),
            );
            assert!(
                runner
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop_runner_during_primary_unwind(runner);
            settle(&scope, &sink, &ready, &lease_drops);
        }

        // A user RawWaker destructor can also panic after the last counted job
        // finishes, exactly while the runner unwinds.
        {
            let (scope, sink, local, ready) = fixture();
            let lease_drops = Rc::new(Cell::new(0));
            let mut runner: LocalFuture<'static, ()> =
                Box::pin(local.run_with_keepalive(async {}, Lease(lease_drops.clone())));
            assert!(
                runner
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            ready.store(true, Ordering::SeqCst);
            sink.notify();
            assert_eq!(scope.state().pending, 0);
            scope.state().waker = Some(Waker::from(Arc::new(DropPanicWake)));
            drop_runner_during_primary_unwind(runner);
            assert_eq!(lease_drops.get(), 1);
            assert!(!scope.is_open());
            assert!(sink.futures.borrow().is_empty());
        }
    }
    struct SettlementWake(AtomicUsize);
    impl std::task::Wake for SettlementWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn poll_host_jobs() {
        let jobs = JOBS.with(|jobs| std::mem::take(&mut *jobs.borrow_mut()));
        for mut job in jobs {
            assert!(
                job.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
        }
    }

    #[test]
    fn settlement_new_sink_refusal_returns_same_once_counted_wrapper() {
        struct Reject {
            notifications: Cell<usize>,
        }
        impl LocalCleanupSink for Reject {
            fn retain(&self, _: LocalFuture<'static, ()>) {
                panic!("fresh work used trusted transfer");
            }
            fn try_retain(
                &self,
                exact: LocalFuture<'static, ()>,
            ) -> Result<(), LocalFuture<'static, ()>> {
                Err(exact)
            }
            fn notify(&self) {
                self.notifications.set(self.notifications.get() + 1);
            }
        }
        let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
        let sink = Rc::new(Reject {
            notifications: Cell::new(0),
        });
        let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
        let (future, _, dropped) = probe();
        let mut refused = local.retain(Box::pin(future)).unwrap_err();
        assert_eq!(scope.state().pending, 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(sink.notifications.get(), 0);
        assert!(
            refused
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(refused);
        assert_eq!(scope.state().pending, 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(sink.notifications.get(), 1);
        assert!(scope.is_open(), "Completion must not close the scope");
        drop(local.run(std::future::pending::<()>()));
        let raw: LocalFuture<'static, ()> = Box::pin(async {});
        let address = (&*raw) as *const dyn Future<Output = ()>;
        let raw = local.retain(raw).unwrap_err();
        assert!(std::ptr::eq(
            address,
            (&*raw) as *const dyn Future<Output = ()>
        ));
        assert_eq!(scope.state().pending, 0);
    }

    #[test]
    fn settlement_existing_transfer_scope_closed_refusal_stays_raw() {
        let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
        let sink = Rc::new(Sink::default());
        let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
        drop(local.run(std::future::pending::<()>()));
        let raw: LocalFuture<'static, ()> = Box::pin(async {});
        let address = (&*raw) as *const dyn Future<Output = ()>;
        let raw = local.retain_existing(raw).unwrap_err();
        assert!(std::ptr::eq(
            address,
            (&*raw) as *const dyn Future<Output = ()>
        ));
        assert_eq!(scope.state().pending, 0);
        assert!(sink.futures.borrow().is_empty());
        assert!(JOBS.with(|jobs| jobs.borrow().is_empty()));
    }

    #[test]
    fn settlement_covers_unmaterialized_factories_and_requires_actual_closer() {
        let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
        let local = LocalCleanupRunner::new(scope.clone(), Rc::new(Sink::default()));
        let settlement = scope.settlement();
        let called = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(());
        let submit = called.clone();
        assert!(
            local
                .submit(Box::new(move |_| {
                    submit.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async {})
                }))
                .is_ok()
        );
        let retire = called.clone();
        assert!(
            local
                .on_retire(
                    &owner,
                    Box::new(move |_| {
                        retire.fetch_add(1, Ordering::SeqCst);
                        Box::pin(async {})
                    })
                )
                .is_ok()
        );
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert!(!settlement.is_ready());
        let mut runner = Box::pin(local.run(async {}));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(runner.as_mut().poll(&mut cx).is_pending());
        poll_host_jobs();
        assert!(scope.is_open());
        assert!(
            !settlement.is_ready(),
            "job completion alone is not a closer"
        );
        assert!(runner.as_mut().poll(&mut cx).is_pending());
        poll_host_jobs();
        assert!(runner.as_mut().poll(&mut cx).is_ready());
        assert_eq!(called.load(Ordering::SeqCst), 2);
        assert!(settlement.is_ready());
    }

    #[test]
    fn settlement_observers_cancel_independently_on_shared_scope() {
        let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
        let settlement = scope.settlement();
        let mut first = settlement.observer();
        let mut second = settlement.observer();
        let mut canceled = settlement.observer();
        let first_wake = Arc::new(SettlementWake(AtomicUsize::new(0)));
        let second_wake = Arc::new(SettlementWake(AtomicUsize::new(0)));
        let canceled_wake = Arc::new(SettlementWake(AtomicUsize::new(0)));
        for (observer, wake) in [
            (&mut first, &first_wake),
            (&mut second, &second_wake),
            (&mut canceled, &canceled_wake),
        ] {
            assert!(
                Pin::new(observer)
                    .poll(&mut Context::from_waker(&Waker::from(wake.clone())))
                    .is_pending()
            );
        }
        drop(canceled);
        assert!(
            !settlement.is_ready(),
            "helper/empty open scope is not a closer"
        );
        drop(scope.run(std::future::pending::<()>())); // actual never-polled Runner closer
        assert!(settlement.is_ready());
        assert_eq!(first_wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(second_wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(canceled_wake.0.load(Ordering::SeqCst), 0);
        assert!(
            Pin::new(&mut first)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert!(
            Pin::new(&mut second)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }

    #[test]
    fn settlement_canonical_closed_drop_covers_exact_keepalive_and_unwind() {
        struct Lease {
            settlement: LoaderSettlement,
            dropped: Arc<AtomicUsize>,
            panic: bool,
        }
        impl Drop for Lease {
            fn drop(&mut self) {
                assert!(
                    !self.settlement.is_ready(),
                    "keepalive callback is still running"
                );
                self.dropped.fetch_add(1, Ordering::SeqCst);
                if self.panic {
                    panic!("exact canonical keepalive");
                }
            }
        }
        for panic in [false, true] {
            let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
            let sink = Rc::new(Sink::default());
            let local = LocalCleanupRunner::new(scope.clone(), sink.clone());
            let settlement = scope.settlement();
            drop(scope.run(std::future::pending::<()>()));
            let dropped = Arc::new(AtomicUsize::new(0));
            let final_drain = FinalDrain {
                drain: Some(FinalDrainObserver::Canonical(Drain {
                    scope: scope.clone(),
                    local: Some(local.clone()),
                })),
                keepalive: Some(Box::new(Lease {
                    settlement: settlement.clone(),
                    dropped: dropped.clone(),
                    panic,
                })),
                local: Some(local),
                completed: false,
            };
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(final_drain)));
            if panic {
                assert_eq!(
                    result.unwrap_err().downcast_ref::<&str>(),
                    Some(&"exact canonical keepalive")
                );
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert!(settlement.is_ready());
            assert!(sink.futures.borrow().is_empty());
            assert!(JOBS.with(|jobs| jobs.borrow().is_empty()));
        }
    }

    #[test]
    fn settlement_actual_scope_destruction_finishes_after_factory_return_or_unwind() {
        struct FactoryResource {
            scope: Weak<LoaderCleanup>,
            settlement: LoaderSettlement,
            dropped: Arc<AtomicUsize>,
            panic: bool,
        }
        impl Drop for FactoryResource {
            fn drop(&mut self) {
                assert!(self.scope.upgrade().is_none());
                assert!(!self.settlement.is_ready());
                self.dropped.fetch_add(1, Ordering::SeqCst);
                if self.panic {
                    panic!("original factory destructor");
                }
            }
        }
        for panic in [false, true] {
            let scope = LoaderCleanup::new(Arc::new(QueueHost(AtomicBool::new(false))));
            let settlement = scope.settlement();
            let dropped = Arc::new(AtomicUsize::new(0));
            let resource = FactoryResource {
                scope: Arc::downgrade(&scope),
                settlement: settlement.clone(),
                dropped: dropped.clone(),
                panic,
            };
            assert!(
                scope
                    .submit(Box::new(move || {
                        drop(resource);
                        Box::pin(async {})
                    }))
                    .is_ok()
            );
            let mut observer = settlement.observer();
            let notified = Arc::new(SettlementWake(AtomicUsize::new(0)));
            assert!(
                Pin::new(&mut observer)
                    .poll(&mut Context::from_waker(&Waker::from(notified.clone())))
                    .is_pending()
            );
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(scope)));
            if panic {
                assert_eq!(
                    result.unwrap_err().downcast_ref::<&str>(),
                    Some(&"original factory destructor")
                );
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert!(settlement.is_ready());
            assert_eq!(notified.0.load(Ordering::SeqCst), 1);
            assert!(
                Pin::new(&mut observer)
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
        }
    }
    #[test]
    fn settlement_ready_observer_rearms_during_actual_scope_destruction_and_unwind() {
        struct ReenterHost {
            executor: QueueHost,
            observer: Arc<Mutex<Option<LoaderSettlementObserver>>>,
            wake: Arc<SettlementWake>,
            entered: Arc<AtomicUsize>,
            panic: bool,
        }
        impl Host for ReenterHost {
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
                &self.executor
            }
            fn report(&self, _: &str) {}
        }
        impl Drop for ReenterHost {
            fn drop(&mut self) {
                let mut observer = self.observer.lock().unwrap().take().unwrap();
                let waker = Waker::from(self.wake.clone());
                assert!(
                    Pin::new(&mut observer)
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending(),
                    "the actual host resource destructor is still running"
                );
                *self.observer.lock().unwrap() = Some(observer);
                self.entered.fetch_add(1, Ordering::SeqCst);
                if self.panic {
                    panic!("original scope host callback");
                }
            }
        }
        for panic in [false, true] {
            let observer = Arc::new(Mutex::new(None));
            let wake = Arc::new(SettlementWake(AtomicUsize::new(0)));
            let entered = Arc::new(AtomicUsize::new(0));
            let scope = LoaderCleanup::new(Arc::new(ReenterHost {
                executor: QueueHost(AtomicBool::new(false)),
                observer: observer.clone(),
                wake: wake.clone(),
                entered: entered.clone(),
                panic,
            }));
            let settlement = scope.settlement();
            drop(scope.run(std::future::pending::<()>())); // REAL canonical closer
            let mut same = settlement.observer();
            assert!(
                Pin::new(&mut same)
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            *observer.lock().unwrap() = Some(same);
            assert_eq!(wake.0.load(Ordering::SeqCst), 0);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(scope)));
            if panic {
                assert_eq!(
                    result.unwrap_err().downcast_ref::<&str>(),
                    Some(&"original scope host callback")
                );
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(entered.load(Ordering::SeqCst), 1);
            assert_eq!(
                wake.0.load(Ordering::SeqCst),
                1,
                "completion must wake the rearmed original observer"
            );
            let mut same = observer.lock().unwrap().take().unwrap();
            assert!(
                Pin::new(&mut same)
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            assert!(settlement.is_ready());
        }
    }
}
