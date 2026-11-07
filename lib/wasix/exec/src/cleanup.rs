//! One local retirement owner spans preparation, every exec image and final drain.

use std::sync::Arc;
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
use wasixv2_host::LocalCleanupSink;
use wasixv2_host::{LoaderCleanup, LocalCleanupRunner};

#[derive(Clone)]
pub(crate) struct RunCleanup {
    shared: Arc<LoaderCleanup>,
    local: Option<LocalCleanupRunner>,
    cancellation: Option<crate::cancellation::Cancellation>,
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    owner: Option<wasmer::sys::NativeCleanupOwner>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
struct Sink(wasmer::sys::NativeCleanupOwner);
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl LocalCleanupSink for Sink {
    fn retain(&self, future: wasixv2_host::LocalFuture<'static, ()>) {
        // SAME counted/canonical obligation; the bound loader settlement fence
        // and actual Store/receipt custody exclude a valid prior seal.
        self.0.transfer_existing(future);
    }
    fn try_retain(
        &self,
        future: wasixv2_host::LocalFuture<'static, ()>,
    ) -> Result<(), wasixv2_host::LocalFuture<'static, ()>> {
        self.0.try_retain(future)
    }
    fn notify(&self) {
        self.0.notify();
    }
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
struct LoaderFence {
    settlement: wasixv2_host::LoaderSettlement,
    observer: std::cell::RefCell<Option<wasixv2_host::LoaderSettlementObserver>>,
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl LoaderFence {
    fn observe(&self, waker: &std::task::Waker) {
        // Registration clones/drops user Wakers. Reentry must not encounter a
        // borrowed observer, and unwind must restore the SAME registration.
        struct Restore<'a> {
            slot: &'a std::cell::RefCell<Option<wasixv2_host::LoaderSettlementObserver>>,
            observer: Option<wasixv2_host::LoaderSettlementObserver>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                *self.slot.borrow_mut() = self.observer.take();
            }
        }
        let observer = self.observer.borrow_mut().take();
        let Some(observer) = observer else {
            return;
        };
        let mut restore = Restore {
            slot: &self.observer,
            observer: Some(observer),
        };
        let _ = std::future::Future::poll(
            std::pin::Pin::new(restore.observer.as_mut().unwrap()),
            &mut std::task::Context::from_waker(waker),
        );
    }
}
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
impl Sink {
    fn bound(owner: wasmer::sys::NativeCleanupOwner, scope: &Arc<LoaderCleanup>) -> Self {
        if owner.is_store_bound() {
            let settlement = scope.settlement();
            let fence = std::rc::Rc::new(LoaderFence {
                observer: std::cell::RefCell::new(Some(settlement.observer())),
                settlement,
            });
            let observed = fence.clone();
            owner.bind_store_cleanup_fence(wasmer::sys::NativeCleanupFence::new(
                std::rc::Rc::new(move |waker| observed.observe(waker)),
                std::rc::Rc::new(move || fence.settlement.is_ready()),
            ));
        }
        Self(owner)
    }
}
impl RunCleanup {
    pub(crate) fn new(shared: Arc<LoaderCleanup>, native: bool) -> Self {
        #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
        {
            let owner = native.then(wasmer::sys::NativeCleanupOwner::new);
            let local = owner.as_ref().map(|owner| {
                LocalCleanupRunner::new(shared.clone(), std::rc::Rc::new(Sink(owner.clone())))
            });
            Self {
                shared,
                local,
                owner,
                cancellation: None,
            }
        }
        #[cfg(not(all(feature = "sys", not(target_arch = "wasm32"))))]
        {
            let _ = native;
            Self {
                shared,
                local: None,
                cancellation: None,
            }
        }
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn with_cancellation(
        mut self,
        cancellation: crate::cancellation::Cancellation,
    ) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
    pub(crate) fn cancellation(&self) -> Option<&crate::cancellation::Cancellation> {
        self.cancellation.as_ref()
    }
    pub(crate) fn shared(&self) -> &Arc<LoaderCleanup> {
        &self.shared
    }
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    pub(crate) fn owner(&self) -> Option<wasmer::sys::NativeCleanupOwner> {
        self.owner.clone()
    }
    pub(crate) async fn run<R>(&self, guest: impl std::future::Future<Output = R>) -> R {
        match &self.local {
            Some(local) => local.run(guest).await,
            None => self.shared.run(guest).await,
        }
    }
    pub(crate) async fn run_with_keepalive<R>(
        &self,
        guest: impl std::future::Future<Output = R>,
        keepalive: impl std::any::Any,
    ) -> R {
        match &self.local {
            Some(local) => local.run_with_keepalive(guest, keepalive).await,
            None => self.shared.run_with_keepalive(guest, keepalive).await,
        }
    }
}
impl From<Arc<LoaderCleanup>> for RunCleanup {
    fn from(shared: Arc<LoaderCleanup>) -> Self {
        Self::new(
            shared,
            cfg!(all(feature = "sys", not(target_arch = "wasm32"))),
        )
    }
}
impl From<&RunCleanup> for RunCleanup {
    fn from(cleanup: &RunCleanup) -> Self {
        cleanup.clone()
    }
}
impl std::ops::Deref for RunCleanup {
    type Target = Arc<LoaderCleanup>;
    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}

/// Capture during ordinary owner construction. Destructors retain the returned
/// capability directly; they never look up a scope during TLS destruction.
///
/// A Store-bound supplied scope must have an existing Runner/DrainCustody
/// lifecycle that actually closes it, or be destroyed. This helper binds its
/// settlement metadata BEFORE publication; it is NOT a closer. Holding an open
/// scope keeps final Store settlement Pending even after its jobs finish. The
/// native finalizer never silently closes a shared scope on the caller's behalf.
pub fn local_cleanup_runner(
    store: &wasmer::StoreAsync,
    shared: Arc<LoaderCleanup>,
) -> Option<LocalCleanupRunner> {
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    {
        wasmer::sys::native_cleanup_owner(store).map(|owner| {
            let sink = Sink::bound(owner, &shared);
            LocalCleanupRunner::new(shared, std::rc::Rc::new(sink))
        })
    }
    #[cfg(not(all(feature = "sys", not(target_arch = "wasm32"))))]
    {
        let _ = (store, shared);
        None
    }
}

#[cfg(all(test, feature = "sys", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Waker},
        time::Duration,
    };
    struct EmptyHost;
    impl wasixv2_host::Host for EmptyHost {
        fn realtime(&self) -> Duration {
            Duration::ZERO
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _: Duration) -> wasixv2_host::LocalFuture<'_, ()> {
            Box::pin(async {})
        }
        fn random(&self, _: &mut [u8]) {}
        fn executor(&self) -> &dyn wasixv2_host::Executor {
            self
        }
        fn report(&self, _: &str) {}
    }
    impl wasixv2_host::Executor for EmptyHost {
        fn spawn_local(&self, _: wasixv2_host::LocalFuture<'static, ()>) {
            panic!("empty scope must not spawn");
        }
        fn spawn_blocking(
            &self,
            work: Box<dyn FnOnce() + Send>,
        ) -> wasixv2_host::LocalFuture<'static, ()> {
            Box::pin(async move { work() })
        }
    }
    #[test]
    fn bound_supplied_scope_is_pending_until_its_existing_closer_or_destruction() {
        for destroy in [false, true] {
            let owner = wasmer::sys::NativeCleanupOwner::new_store_bound();
            let mut store = wasmer::Store::default();
            let generation = wasmer::sys::NativeInvocationScope::bind_with_cleanup(
                &mut store,
                Some(owner.clone()),
            )
            .unwrap();
            let asynchronous = store.into_async();
            let shared = LoaderCleanup::new(Arc::new(EmptyHost));
            let weak = Arc::downgrade(&shared);
            let local = local_cleanup_runner(&asynchronous, shared.clone()).unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            // This exercises ONLY the bound loader-fence primitive, while the
            // actual Store is still alive. No final-seal certificate is claimed.
            assert!(owner.poll_quiescent(&mut cx).is_pending());
            if destroy {
                drop(local);
                drop(shared);
                assert!(weak.upgrade().is_none(), "fence must not pin the scope");
            } else {
                let mut runner = Box::pin(local.run(async {}));
                assert!(runner.as_mut().poll(&mut cx).is_ready());
                drop(runner);
                assert!(!shared.is_open());
            }
            assert!(owner.poll_quiescent(&mut cx).is_ready());
            assert!(owner.is_store_bound());
            drop(asynchronous);
            drop(generation);
        }
    }
}
