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
        self.0.retain(future);
    }
    fn notify(&self) {
        self.0.notify();
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
pub fn local_cleanup_runner(
    store: &wasmer::StoreAsync,
    shared: Arc<LoaderCleanup>,
) -> Option<LocalCleanupRunner> {
    #[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
    {
        wasmer::sys::native_cleanup_owner(store)
            .map(|owner| LocalCleanupRunner::new(shared, std::rc::Rc::new(Sink(owner))))
    }
    #[cfg(not(all(feature = "sys", not(target_arch = "wasm32"))))]
    {
        let _ = (store, shared);
        None
    }
}
