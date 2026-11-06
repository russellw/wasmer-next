use super::engine::wasm_engine_t;
use std::cell::RefCell;
use std::rc::{Rc, Weak};
use wasmer_api::{
    AsStoreMut, Extern, Function, Instance, InstantiationError, Module, RuntimeError, Store,
    StoreMut, Value,
};

#[derive(Clone)]
pub struct StoreRef {
    inner: Rc<StoreState>,
}

struct StoreState {
    id: wasmer_types::StoreId,
    mode: StoreMode,
}

enum StoreMode {
    Plain(RefCell<Store>),
    #[cfg(feature = "sys")]
    Native(ManagedStore),
}

#[cfg(feature = "sys")]
struct ManagedStore {
    store: Option<wasmer_api::StoreAsync>,
    generation: Option<wasmer_api::sys::NativeInvocationScope>,
    owner: wasmer_api::sys::NativeCleanupOwner,
    driver: RefCell<Option<Rc<Driver>>>,
    cleanup_fences: RefCell<Vec<Box<dyn Fn() -> bool>>>,
    #[cfg(feature = "wasi")]
    endpoints: RefCell<Vec<Weak<dyn ContinuationEndpoint>>>,
}

#[cfg(feature = "sys")]
pub(crate) struct Driver {
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
    local: tokio::task::LocalSet,
    active: std::cell::Cell<bool>,
    owner: wasmer_api::sys::NativeCleanupOwner,
    enrolled: RefCell<Vec<Rc<std::cell::Cell<bool>>>>,
}

#[cfg(all(feature = "sys", feature = "wasi"))]
#[derive(Debug)]
struct CompletedHandoff(RuntimeError);
#[cfg(all(feature = "sys", feature = "wasi"))]
impl std::fmt::Display for CompletedHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.message())
    }
}
#[cfg(all(feature = "sys", feature = "wasi"))]
impl std::error::Error for CompletedHandoff {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
#[cfg(all(feature = "sys", feature = "wasi"))]
pub(crate) fn completed_handoff(error: RuntimeError) -> RuntimeError {
    RuntimeError::user(Box::new(CompletedHandoff(error)))
}

#[cfg(all(feature = "sys", feature = "wasi"))]
pub(crate) trait ContinuationEndpoint {
    fn matches(&self, store: &mut StoreMut<'_>, error: &RuntimeError) -> bool;
    fn prepare(
        self: Rc<Self>,
        store: &StoreRef,
        error: &RuntimeError,
    ) -> Result<LocalContinuation, RuntimeError>;
    fn cancel_unclaimed(
        self: Rc<Self>,
        store: &StoreRef,
        error: &RuntimeError,
    ) -> Result<(), RuntimeError>;
}

#[cfg(all(feature = "sys", feature = "wasi"))]
pub(crate) struct LocalContinuation {
    pub(crate) store: StoreRef,
    pub(crate) run: Option<
        Box<
            dyn FnOnce() -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<(), RuntimeError>>>,
            >,
        >,
    >,
    pub(crate) cancel: Option<Box<dyn FnOnce()>>,
}
#[cfg(all(feature = "sys", feature = "wasi"))]
impl Drop for LocalContinuation {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

/// Captured before admission; owns only the existing local executor and cleanup pump.
#[cfg(feature = "sys")]
#[derive(Clone)]
pub(crate) struct CleanupRetirement {
    driver: Rc<Driver>,
    owner: wasmer_api::sys::NativeCleanupOwner,
}
#[cfg(feature = "sys")]
impl CleanupRetirement {
    pub(crate) fn retain(
        &self,
        mut future: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
    ) {
        let driver = self.driver.clone();
        self.owner.retain(Box::pin(std::future::poll_fn(move |cx| {
            let _runtime = driver.runtime.enter();
            let _local = driver.local.enter();
            future.as_mut().poll(cx)
        })));
    }
    #[cfg(feature = "wasi")]
    pub(crate) fn drive_after_settlement(&self, completed: Rc<std::cell::Cell<bool>>) {
        let driver = self.driver.clone();
        self.owner.after_pump(Box::new(move || {
            if completed.get() {
                return;
            }
            if driver.active.get() {
                // The same LocalSet is already being polled. Enroll this exact
                // cleanup in its existing poller, never recursively enter it.
                driver.enrolled.borrow_mut().push(completed);
                return;
            }
            driver.drain_retirement(completed);
        }));
    }
}

#[cfg(feature = "sys")]
struct CallOwner {
    driver: Rc<Driver>,
    #[cfg(feature = "wasi")]
    pending: RefCell<std::collections::VecDeque<LocalContinuation>>,
}

#[cfg(feature = "sys")]
impl CallOwner {
    async fn drain(&self) -> Option<RuntimeError> {
        #[cfg(feature = "wasi")]
        {
            let mut outcome = None;
            loop {
                let next = self.pending.borrow_mut().pop_front();
                let Some(mut next) = next else {
                    return outcome;
                };
                let driver = match &next.store.inner.mode {
                    StoreMode::Native(native) => match native.driver() {
                        Ok(driver) => driver,
                        Err(error) => {
                            outcome = Some(error);
                            continue;
                        }
                    },
                    StoreMode::Plain(_) => {
                        outcome = Some(RuntimeError::new("native continuation lost its Store"));
                        continue;
                    }
                };
                let future = next.run.take().expect("queued continuation has one entry")();
                let result = if Rc::ptr_eq(&self.driver, &driver) {
                    future.await
                } else {
                    driver.run_local(future).await
                };
                if let Err(error) = result {
                    outcome = Some(error);
                }
                // A final Store retirement must see no escaped Driver clone.
                drop(driver);
                drop(next);
            }
        }
        #[cfg(not(feature = "wasi"))]
        {
            let _ = &self.driver;
            None
        }
    }
}

impl StoreRef {
    #[allow(unused_mut)] // Only the native backend binds a generation before conversion.
    fn new(mut store: Store) -> Result<Self, RuntimeError> {
        let id = store.id();
        #[cfg(feature = "sys")]
        if store.engine().is_sys() {
            let owner = wasmer_api::sys::NativeCleanupOwner::new();
            let generation = wasmer_api::sys::NativeInvocationScope::bind_with_cleanup(
                &mut store,
                Some(owner.clone()),
            )?;
            let store = store.into_async();
            // Actual unlock must repump a retirement fence even for a bare Store
            // that never constructed a WASI environment or cleanup driver.
            let owner = wasmer_api::sys::native_cleanup_owner(&store)
                .ok_or_else(|| RuntimeError::new("native cleanup owner is missing"))?;
            return Ok(Self {
                inner: Rc::new(StoreState {
                    id,
                    mode: StoreMode::Native(ManagedStore {
                        store: Some(store),
                        generation: Some(generation),
                        owner,
                        driver: RefCell::new(None),
                        cleanup_fences: RefCell::default(),
                        #[cfg(feature = "wasi")]
                        endpoints: RefCell::default(),
                    }),
                }),
            });
        }
        Ok(Self {
            inner: Rc::new(StoreState {
                id,
                mode: StoreMode::Plain(RefCell::new(store)),
            }),
        })
    }

    /// A host-only loan. No Store reference or guard escapes this closure.
    pub(crate) fn with_mut<R>(
        &self,
        f: impl FnOnce(&mut StoreMut<'_>) -> R,
    ) -> Result<R, RuntimeError> {
        let mut f = Some(f);
        if let Some(Some(result)) = Store::with_current(|current| {
            (current.objects_mut().id() == self.inner.id).then(|| f.take().unwrap()(current))
        }) {
            return Ok(result);
        }
        match &self.inner.mode {
            StoreMode::Plain(store) => {
                let mut guard = store
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::new("Store is already borrowed"))?;
                if guard.as_store_mut().objects_mut().id() != self.inner.id {
                    return Err(RuntimeError::new("host loan belongs to another Store"));
                }
                Ok(f.take().unwrap()(&mut guard.as_store_mut()))
            }
            #[cfg(feature = "sys")]
            StoreMode::Native(native) => {
                use std::{
                    future::Future,
                    task::{Context, Poll, Waker},
                };
                use wasmer_api::AsStoreAsync;
                let expected = native.store.as_ref().unwrap();
                let loan = wasmer_api::sys::current_native_store_loan(expected)?;
                let capability = loan.as_ref().unwrap_or(expected);
                let mut lock = std::pin::pin!(capability.write_lock());
                let Poll::Ready(mut guard) =
                    lock.as_mut().poll(&mut Context::from_waker(Waker::noop()))
                else {
                    return Err(RuntimeError::new("Store has no available host loan"));
                };
                Ok(f.take().unwrap()(&mut guard.as_store_mut()))
            }
        }
    }

    pub(crate) fn call(
        &self,
        function: &Function,
        args: Vec<Value>,
    ) -> Result<Box<[Value]>, RuntimeError> {
        let _keepalive = self.clone();
        if let Some(result) = Store::with_current(|current| {
            if current.objects_mut().id() == self.inner.id {
                function.call(current, &args)
            } else {
                current.parked(|| match &self.inner.mode {
                    #[cfg(feature = "sys")]
                    StoreMode::Native(native) => {
                        let driver = native.driver()?;
                        wasmer_api::sys::call_native_descendant(
                            function,
                            native.store.as_ref().unwrap(),
                            args.clone(),
                            move |child| async move { driver.run_descendant(child).await },
                        )
                    }
                    StoreMode::Plain(_) => self
                        .with_mut(|store| function.call(store, &args))
                        .and_then(|result| result),
                })
            }
        }) {
            #[cfg(all(feature = "sys", feature = "wasi"))]
            if let Err(error) = &result {
                self.forward_handoff(error, None)?;
            }
            return result;
        }
        match &self.inner.mode {
            StoreMode::Plain(_) => self.with_mut(|store| function.call(store, &args))?,
            #[cfg(feature = "sys")]
            StoreMode::Native(native) => self.native_call(native, function, args),
        }
    }

    #[cfg(feature = "sys")]
    fn native_call(
        &self,
        native: &ManagedStore,
        function: &Function,
        args: Vec<Value>,
    ) -> Result<Box<[Value]>, RuntimeError> {
        let driver = native.driver()?;
        let owner = Rc::new(CallOwner {
            driver: driver.clone(),
            #[cfg(feature = "wasi")]
            pending: RefCell::default(),
        });
        let erased: Rc<dyn std::any::Any> = owner.clone();
        let store = native.store.as_ref().unwrap();
        let call = wasmer_api::sys::call_async_with_local_owner(
            function,
            store,
            args,
            Rc::downgrade(&erased),
        );
        driver.run(async {
            use wasmer_api::AsStoreAsync;
            let result = call.await;
            // Native settlement notification precedes the actual unlock.
            drop(store.write_lock().await);
            #[cfg(feature = "wasi")]
            if let Err(error) = &result {
                self.forward_handoff(error, Some(&owner))?;
            }
            match owner.drain().await {
                Some(error) => Err(error),
                None => result,
            }
        })?
    }

    pub(crate) fn instantiate(
        &self,
        module: &Module,
        externs: Vec<Extern>,
    ) -> Result<Result<Instance, InstantiationError>, RuntimeError> {
        let _keepalive = self.clone();
        if let Some(result) = Store::with_current(|current| {
            if current.objects_mut().id() == self.inner.id {
                Ok(Instance::new_by_index(current, module, &externs))
            } else {
                current.parked(|| match &self.inner.mode {
                    #[cfg(feature = "sys")]
                    StoreMode::Native(_) => self.instantiate_native(module, externs.clone()),
                    StoreMode::Plain(_) => {
                        self.with_mut(|store| Instance::new_by_index(store, module, &externs))
                    }
                })
            }
        }) {
            #[cfg(all(feature = "sys", feature = "wasi"))]
            match &result {
                Err(error) | Ok(Err(InstantiationError::Start(error))) => {
                    self.forward_handoff(error, None)?
                }
                _ => (),
            }
            return result;
        }
        match &self.inner.mode {
            StoreMode::Plain(_) => {
                self.with_mut(|store| Instance::new_by_index(store, module, &externs))
            }
            #[cfg(feature = "sys")]
            StoreMode::Native(_) => self.instantiate_native(module, externs),
        }
    }

    #[cfg(feature = "sys")]
    fn instantiate_native(
        &self,
        module: &Module,
        externs: Vec<Extern>,
    ) -> Result<Result<Instance, InstantiationError>, RuntimeError> {
        use std::sync::{Arc, Mutex};
        let result = Arc::new(Mutex::new(None));
        let output = Arc::downgrade(&result);
        let request = Arc::new(Mutex::new(Some((module.clone(), externs))));
        let input = Arc::downgrade(&request);
        // Per-operation weak payloads own no Store/driver/module roots.
        // Recursive calls have independent request and result custody.
        let trampoline = self.with_mut(|store| {
            let env = wasmer_api::FunctionEnv::new(store, ());
            Function::new_with_env(
                store,
                &env,
                wasmer_api::FunctionType::new([], []),
                move |mut env, _| {
                    let request = input
                        .upgrade()
                        .ok_or_else(|| RuntimeError::new("instantiation request expired"))?;
                    let (module, externs) = request
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .take()
                        .ok_or_else(|| {
                            RuntimeError::new("instantiation request already entered")
                        })?;
                    let output = output
                        .upgrade()
                        .ok_or_else(|| RuntimeError::new("instantiation result expired"))?;
                    let instance =
                        Instance::new_by_index(&mut env.as_store_mut(), &module, &externs);
                    let abort = match &instance {
                        Err(InstantiationError::Start(error)) if error.is_host_abort() => {
                            Some(error.clone())
                        }
                        _ => None,
                    };
                    *output.lock().unwrap_or_else(|error| error.into_inner()) = Some(instance);
                    // Committed start cannot be swallowed by the trampoline
                    // before the enclosing native caller latches its abort.
                    match abort {
                        Some(error) => Err(error),
                        None => Ok(Vec::new()),
                    }
                },
            )
        });
        let trampoline = trampoline?;
        if let Err(error) = self.call(&trampoline, Vec::new()) {
            #[cfg(feature = "wasi")]
            if wasixv2_exec::is_call_handoff(&error)
                || error.downcast_ref::<CompletedHandoff>().is_some()
            {
                return Ok(Err(InstantiationError::Start(error)));
            }
            let value = result
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            return match value {
                Some(Err(instance_error)) => Ok(Err(instance_error)),
                // The call can fail after the trampoline saved success, during
                // its final unlock/retirement. That instance was never admitted.
                Some(Ok(instance)) => {
                    drop(instance);
                    Err(error)
                }
                None => Err(error),
            };
        }
        let value = result
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        value.ok_or_else(|| RuntimeError::new("native instantiation did not settle"))
    }

    pub(crate) fn is_native(&self) -> bool {
        match &self.inner.mode {
            #[cfg(feature = "sys")]
            StoreMode::Native(_) => true,
            StoreMode::Plain(_) => false,
        }
    }

    #[cfg(feature = "sys")]
    pub(crate) fn async_store(&self) -> Result<wasmer_api::StoreAsync, RuntimeError> {
        use wasmer_api::AsStoreAsync;
        match &self.inner.mode {
            StoreMode::Native(native) => Ok(native.store.as_ref().unwrap().store()),
            StoreMode::Plain(_) => Err(RuntimeError::new(
                "Store is not managed by the native driver",
            )),
        }
    }

    #[cfg(feature = "sys")]
    pub(crate) fn run_host<R>(
        &self,
        future: impl std::future::Future<Output = R>,
    ) -> Result<R, RuntimeError> {
        match &self.inner.mode {
            StoreMode::Native(native) => native.driver()?.run(future),
            StoreMode::Plain(_) => Err(RuntimeError::new(
                "Store is not managed by the native driver",
            )),
        }
    }

    #[cfg(feature = "sys")]
    pub(crate) fn register_cleanup_fence(
        &self,
        fence: Box<dyn Fn() -> bool>,
    ) -> Result<(), RuntimeError> {
        match &self.inner.mode {
            StoreMode::Native(native) => {
                native.cleanup_fences.borrow_mut().push(fence);
                Ok(())
            }
            StoreMode::Plain(_) => Err(RuntimeError::new("Store has no native cleanup owner")),
        }
    }

    #[cfg(feature = "sys")]
    pub(crate) fn cleanup_owner(
        &self,
    ) -> Result<wasmer_api::sys::NativeCleanupOwner, RuntimeError> {
        match &self.inner.mode {
            StoreMode::Native(native) => Ok(native.owner.clone()),
            StoreMode::Plain(_) => Err(RuntimeError::new("Store has no native cleanup owner")),
        }
    }

    #[cfg(feature = "sys")]
    pub(crate) fn retirement_owner(&self) -> Result<CleanupRetirement, RuntimeError> {
        let StoreMode::Native(native) = &self.inner.mode else {
            return Err(RuntimeError::new("Store has no native cleanup owner"));
        };
        Ok(CleanupRetirement {
            driver: native.driver()?,
            owner: native.owner.clone(),
        })
    }

    #[cfg(feature = "sys")]
    pub(crate) fn cleanup_retirement(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
    ) -> Result<Box<dyn FnOnce()>, RuntimeError> {
        let owner = self.retirement_owner()?;
        Ok(Box::new(move || owner.retain(future)))
    }

    #[cfg(all(feature = "sys", feature = "wasi"))]
    pub(crate) fn register_endpoint(
        &self,
        endpoint: Weak<dyn ContinuationEndpoint>,
    ) -> Result<(), RuntimeError> {
        match &self.inner.mode {
            StoreMode::Native(native) => {
                let mut endpoints = native.endpoints.borrow_mut();
                endpoints.retain(|endpoint| endpoint.strong_count() != 0);
                endpoints.push(endpoint);
                Ok(())
            }
            StoreMode::Plain(_) => Err(RuntimeError::new("Store has no native continuation owner")),
        }
    }

    #[cfg(all(feature = "sys", feature = "wasi"))]
    fn forward_handoff(
        &self,
        error: &RuntimeError,
        explicit: Option<&Rc<CallOwner>>,
    ) -> Result<(), RuntimeError> {
        let StoreMode::Native(native) = &self.inner.mode else {
            return Ok(());
        };
        let weak = {
            let mut endpoints = native.endpoints.borrow_mut();
            endpoints.retain(|endpoint| endpoint.strong_count() != 0);
            endpoints.clone()
        };
        let endpoints = weak
            .into_iter()
            .filter_map(|endpoint| endpoint.upgrade())
            .collect::<Vec<_>>();
        let endpoint = self.with_mut(|store| {
            endpoints
                .into_iter()
                .find(|endpoint| endpoint.matches(store, error))
        })?;
        let Some(endpoint) = endpoint else {
            return Ok(());
        };
        let owner = explicit
            .cloned()
            .or_else(wasmer_api::sys::current_native_local_owner::<CallOwner>);
        let Some(owner) = owner else {
            // Never claim work that has no exact outer local dispatcher.
            return endpoint.cancel_unclaimed(self, error);
        };
        owner.pending.borrow_mut().reserve(1);
        let continuation = endpoint.prepare(self, error)?;
        owner.pending.borrow_mut().push_back(continuation);
        Ok(())
    }

    pub fn downgrade(&self) -> WeakStoreRef {
        WeakStoreRef {
            inner: Rc::downgrade(&self.inner),
        }
    }
}

#[cfg(feature = "sys")]
impl ManagedStore {
    fn driver(&self) -> Result<Rc<Driver>, RuntimeError> {
        if let Some(driver) = self.driver.borrow().as_ref() {
            return Ok(driver.clone());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| RuntimeError::new(error.to_string()))?;
        let driver = Rc::new(Driver {
            runtime: std::sync::Arc::new(runtime),
            local: tokio::task::LocalSet::new(),
            active: std::cell::Cell::new(false),
            owner: self.owner.clone(),
            enrolled: RefCell::default(),
        });
        *self.driver.borrow_mut() = Some(driver.clone());
        Ok(driver)
    }
}

#[cfg(feature = "sys")]
impl Driver {
    async fn drive<R>(&self, future: impl std::future::Future<Output = R>) -> R {
        struct Clear(wasmer_api::sys::NativeCleanupOwner);
        impl Drop for Clear {
            fn drop(&mut self) {
                self.0.clear_idle_waker();
            }
        }
        let _clear = Clear(self.owner.clone());
        let mut future = std::pin::pin!(future);
        let mut output = None;
        std::future::poll_fn(|cx| {
            let _ = self.owner.poll_idle(cx);
            if output.is_none() {
                if let std::task::Poll::Ready(value) = future.as_mut().poll(cx) {
                    output = Some(value);
                }
            }
            // The guest can finish a nested local observer which clears the
            // same pump's drain registration. Reinstall before waiting for any
            // enrolled retirement, then recheck flags changed by that poll.
            let _ = self.owner.poll_idle(cx);
            let waiting = {
                let mut enrolled = self.enrolled.borrow_mut();
                enrolled.retain(|completed| !completed.get());
                !enrolled.is_empty()
            };
            if !waiting && output.is_some() {
                std::task::Poll::Ready(output.take().unwrap())
            } else {
                std::task::Poll::Pending
            }
        })
        .await
    }

    async fn run_descendant<R>(&self, future: impl std::future::Future<Output = R>) -> R {
        if self.active.get() {
            // An ancestor's LocalSet already has an outer poller. Enter only
            // its spawn/runtime context; let that poller run its queued tasks.
            let mut future = std::pin::pin!(future);
            return std::future::poll_fn(|cx| {
                let _runtime = self.runtime.enter();
                let _local = self.local.enter();
                let _ = self.owner.poll_idle(cx);
                future.as_mut().poll(cx)
            })
            .await;
        }
        self.active.set(true);
        struct Reset<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _reset = Reset(&self.active);
        // Nested guest completion must return to its still-parked ancestor.
        // Global enrolled retirement joins belong to that outer call owner.
        let mut run = std::pin::pin!(self.local.run_until(future));
        std::future::poll_fn(|cx| {
            let _runtime = self.runtime.enter();
            std::future::Future::poll(run.as_mut(), cx)
        })
        .await
    }

    #[cfg(feature = "wasi")]
    async fn run_local<R>(&self, future: impl std::future::Future<Output = R>) -> R {
        assert!(!self.active.replace(true), "recursive native LocalSet poll");
        struct Reset<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _reset = Reset(&self.active);
        let mut run = std::pin::pin!(self.local.run_until(self.drive(future)));
        std::future::poll_fn(|cx| {
            let _runtime = self.runtime.enter();
            std::future::Future::poll(run.as_mut(), cx)
        })
        .await
    }

    #[cfg(feature = "wasi")]
    fn drain_retirement(&self, completed: Rc<std::cell::Cell<bool>>) {
        use std::{
            sync::{Arc, Condvar, Mutex},
            task::{Context, Wake, Waker},
        };
        #[derive(Default)]
        struct WakeSignal(Mutex<bool>, Condvar);
        impl Wake for WakeSignal {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                *self.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
                self.1.notify_one();
            }
        }
        struct Clear(wasmer_api::sys::NativeCleanupOwner);
        impl Drop for Clear {
            fn drop(&mut self) {
                self.0.clear_idle_waker();
            }
        }
        let _clear = Clear(self.owner.clone());
        let signal = Arc::new(WakeSignal::default());
        let waker = Waker::from(signal.clone());
        let mut cx = Context::from_waker(&waker);
        let mut panic = None;
        loop {
            *signal.0.lock().unwrap_or_else(|e| e.into_inner()) = false;
            attempt_retirement(&mut panic, || {
                let _runtime = self.runtime.enter();
                let local = self.local.run_until(std::future::pending::<()>());
                let _ = std::pin::pin!(local).as_mut().poll(&mut cx);
                let _local = self.local.enter();
                let _ = self.owner.poll_idle(&mut cx);
            });
            if completed.get() {
                break;
            }
            // Runtime/LocalSet entry guards never span the blocking wait.
            let mut ready = signal.0.lock().unwrap_or_else(|e| e.into_inner());
            while !*ready {
                ready = signal.1.wait(ready).unwrap_or_else(|e| e.into_inner());
            }
        }
        if let Some(panic) = panic {
            std::panic::resume_unwind(panic);
        }
    }

    fn run<R>(&self, future: impl std::future::Future<Output = R>) -> Result<R, RuntimeError> {
        // This blocking boundary is not a Tokio task. A callback with an exact
        // parked loan takes the synchronous path before reaching the driver.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(RuntimeError::new(
                "blocking C API entry has no parked Store loan in the entered runtime",
            ));
        }
        if self.active.replace(true) {
            return Err(RuntimeError::new(
                "nested native entry requires a parked Store loan",
            ));
        }
        struct Reset<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _reset = Reset(&self.active);
        Ok(self
            .runtime
            .block_on(self.local.run_until(self.drive(future))))
    }
}

#[cfg(feature = "sys")]
type RetirementPanic = Box<dyn std::any::Any + Send>;

#[cfg(feature = "sys")]
fn remember_retirement_panic(first: &mut Option<RetirementPanic>, panic: RetirementPanic) {
    if first.is_none() {
        *first = Some(panic);
    } else {
        // A later user panic payload may itself panic on destruction.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(panic)));
    }
}

#[cfg(feature = "sys")]
fn attempt_retirement(first: &mut Option<RetirementPanic>, cleanup: impl FnOnce()) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)) {
        Ok(()) => true,
        Err(panic) => {
            remember_retirement_panic(first, panic);
            false
        }
    }
}

#[cfg(feature = "sys")]
async fn catch_retirement_future<F: std::future::Future>(
    future: F,
) -> Result<F::Output, RetirementPanic> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(poll) => poll.map(Ok),
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    })
    .await
}

#[cfg(feature = "sys")]
impl Drop for ManagedStore {
    fn drop(&mut self) {
        let Some(mut generation) = self.generation.take() else {
            return;
        };
        let store = self.store.take();
        let driver = self.driver.get_mut().take();
        let fences = std::mem::take(self.cleanup_fences.get_mut());
        let owner = self.owner.clone();
        self.owner.retain(Box::pin(async move {
            use wasmer_api::AsStoreAsync;
            let mut first_panic = None;
            // Commit concrete resource custody before close can pump a callback.
            // Recreate interrupted observers without dropping the Store/driver.
            loop {
                match catch_retirement_future(generation.close_and_wait_for_cleanup()).await {
                    Ok(()) => break,
                    Err(panic) => remember_retirement_panic(&mut first_panic, panic),
                }
            }
            // Physical root settlement is notified before its original guard
            // unlocks. Fence the actual Store before any post-pump retirement.
            if let Some(store) = &store {
                loop {
                    match catch_retirement_future(async { drop(store.write_lock().await) }).await {
                        Ok(()) => break,
                        Err(panic) => remember_retirement_panic(&mut first_panic, panic),
                    }
                }
            }
            let final_owner = owner.clone();
            owner.after_pump(Box::new(move || {
                retire_store(store, driver, fences, final_owner, first_panic);
            }));
        }));
    }
}

#[cfg(feature = "sys")]
fn retire_store(
    store: Option<wasmer_api::StoreAsync>,
    driver: Option<Rc<Driver>>,
    fences: Vec<Box<dyn Fn() -> bool>>,
    owner: wasmer_api::sys::NativeCleanupOwner,
    mut first_panic: Option<RetirementPanic>,
) {
    use std::{
        future::Future,
        sync::{Arc, Condvar, Mutex},
        task::{Context, Wake, Waker},
    };
    #[derive(Default)]
    struct WakeSignal(Mutex<bool>, Condvar);
    impl Wake for WakeSignal {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            *self.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.1.notify_one();
        }
    }
    struct ClearWake(wasmer_api::sys::NativeCleanupOwner);
    impl Drop for ClearWake {
        fn drop(&mut self) {
            self.0.clear_idle_waker();
        }
    }
    let _clear = ClearWake(owner.clone());
    let signal = Arc::new(WakeSignal::default());
    let runtime = driver.as_ref().map(|driver| driver.runtime.clone());
    let waker = Waker::from(signal.clone());
    let mut cx = Context::from_waker(&waker);
    let mut drain = |driver: Option<&Driver>, require_fences: bool| {
        loop {
            *signal.0.lock().unwrap_or_else(|e| e.into_inner()) = false;
            let idle = {
                // Also enter after LocalSet cancellation and VM Store drop:
                // those destructors can retain finite timer/IO cleanup.
                let _enter = runtime.as_ref().map(|runtime| runtime.enter());
                if let Some(driver) = driver {
                    let local = driver.local.run_until(std::future::pending::<()>());
                    let _ = std::pin::pin!(local).as_mut().poll(&mut cx);
                }
                let _local = driver.map(|driver| driver.local.enter());
                // Install our real signal in every retained continuation.
                owner.poll_idle(&mut cx).is_ready()
                    && (!require_fences || fences.iter().all(|closed| closed()))
            };
            if idle {
                break;
            }
            // No runtime or LocalSet context is held across this blocking wait.
            let mut ready = signal.0.lock().unwrap_or_else(|e| e.into_inner());
            while !*ready {
                ready = signal.1.wait(ready).unwrap_or_else(|e| e.into_inner());
            }
        }
    };
    // Keep the concrete Store, driver and runtime outside every fallible poll.
    // Native cleanup transfers interrupted custody before propagating a panic;
    // repoll that replacement work before advancing to resource destruction.
    while !attempt_retirement(&mut first_panic, || drain(driver.as_deref(), true)) {}
    if let Some(driver) = driver {
        // Cleanup continuations may retain the driver until their fences settle.
        // Public calls retain StoreRef, so no other execution survives this point.
        let driver = Rc::try_unwrap(driver)
            .ok()
            .expect("native driver survived its Store owner");
        let Driver { local, .. } = driver;
        {
            let _enter = runtime.as_ref().map(|runtime| runtime.enter());
            // Loader/native obligations have settled. Cancel unrelated local work,
            // including tasks that would otherwise stay pending forever.
            attempt_retirement(&mut first_panic, || drop(local));
        }
    }
    while !attempt_retirement(&mut first_panic, || drain(None, false)) {}
    {
        let _enter = runtime.as_ref().map(|runtime| runtime.enter());
        attempt_retirement(&mut first_panic, || drop(store));
    }
    while !attempt_retirement(&mut first_panic, || drain(None, false)) {}
    drop(drain);
    drop(_clear);
    // Runtime destruction can block and is illegal in a foreign Tokio callback.
    // Only the Send runtime moves; all Store/LocalSet custody stayed on this thread.
    if let Some(runtime) = runtime {
        let shutdown = std::thread::spawn(move || drop(runtime)).join();
        if let Err(panic) = shutdown {
            remember_retirement_panic(&mut first_panic, panic);
        }
    }
    if let Some(panic) = first_panic {
        std::panic::resume_unwind(panic);
    }
}

#[derive(Clone)]
pub struct WeakStoreRef {
    inner: Weak<StoreState>,
}
// SAFETY: C API Stores and these callbacks are confined to their construction thread.
unsafe impl Send for WeakStoreRef {}
unsafe impl Sync for WeakStoreRef {}
impl WeakStoreRef {
    pub fn upgrade(&self) -> Option<StoreRef> {
        self.inner.upgrade().map(|inner| StoreRef { inner })
    }
}

/// Opaque type representing a WebAssembly store.
#[allow(non_camel_case_types)]
pub struct wasm_store_t {
    pub(crate) inner: StoreRef,
}

/// Creates a new WebAssembly store given a specific [engine][super::engine].
///
/// # Example
///
/// See the module's documentation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_store_new(
    engine: Option<&wasm_engine_t>,
) -> Option<Box<wasm_store_t>> {
    let engine = engine?;
    let store = Store::new(engine.inner.clone());

    Some(Box::new(wasm_store_t {
        inner: c_try!(StoreRef::new(store)),
    }))
}

/// Deletes a WebAssembly store.
///
/// # Example
///
/// See the module's documentation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_store_delete(_store: Option<Box<wasm_store_t>>) {}

#[cfg(all(test, feature = "sys"))]
mod tests {
    use super::*;
    use crate::wasm_c_api::{
        externals::{
            wasm_extern_t, wasm_extern_vec_t, wasm_func_call, wasm_func_new_with_env, wasm_func_t,
        },
        instance::wasm_instance_new,
        module::wasm_module_t,
        trap::wasm_trap_t,
        types::wasm_functype_t,
        value::{wasm_val_t, wasm_val_vec_t},
    };

    #[cfg(feature = "wasi")]
    #[test]
    fn endpoint_reuse_prunes_dead_controls_and_preserves_live_matching_outside_registry_borrows() {
        struct Endpoint(Rc<std::cell::Cell<usize>>);
        impl ContinuationEndpoint for Endpoint {
            fn matches(&self, _: &mut StoreMut<'_>, _: &RuntimeError) -> bool {
                self.0.set(self.0.get() + 1);
                false
            }
            fn prepare(
                self: Rc<Self>,
                _: &StoreRef,
                _: &RuntimeError,
            ) -> Result<LocalContinuation, RuntimeError> {
                unreachable!()
            }
            fn cancel_unclaimed(
                self: Rc<Self>,
                _: &StoreRef,
                _: &RuntimeError,
            ) -> Result<(), RuntimeError> {
                unreachable!()
            }
        }
        let store = StoreRef::new(Store::default()).unwrap();
        let calls = Rc::new(std::cell::Cell::new(0));
        let live: Rc<dyn ContinuationEndpoint> = Rc::new(Endpoint(calls.clone()));
        store.register_endpoint(Rc::downgrade(&live)).unwrap();
        for _ in 0..1000 {
            let endpoint: Rc<dyn ContinuationEndpoint> = Rc::new(Endpoint(calls.clone()));
            store.register_endpoint(Rc::downgrade(&endpoint)).unwrap();
            drop(endpoint);
            let StoreMode::Native(native) = &store.inner.mode else {
                unreachable!()
            };
            assert!(
                native.endpoints.borrow().len() <= 2,
                "history must stay bounded"
            );
        }
        store
            .forward_handoff(&RuntimeError::new("ordinary guest trap"), None)
            .unwrap();
        assert_eq!(calls.get(), 1, "snapshot retains exactly the live endpoint");
        let StoreMode::Native(native) = &store.inner.mode else {
            unreachable!()
        };
        assert_eq!(native.endpoints.borrow().len(), 1);
        drop(live);
        store
            .forward_handoff(&RuntimeError::new("ordinary guest trap"), None)
            .unwrap();
        assert!(native.endpoints.borrow().is_empty());
    }

    #[test]
    fn final_store_retirement_waits_for_a_bare_stores_actual_unlock() {
        use std::{future::Future, task::Context};
        use wasmer_api::AsStoreAsync;
        let store = StoreRef::new(Store::default()).unwrap();
        let weak = store.downgrade();
        let asynchronous = store.async_store().unwrap();
        let owner = match &store.inner.mode {
            StoreMode::Native(native) => native.owner.clone(),
            StoreMode::Plain(_) => unreachable!(),
        };
        let mut lock = std::pin::pin!(asynchronous.write_lock());
        let std::task::Poll::Ready(guard) = lock
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
        else {
            panic!("the unused Store must have an available write guard");
        };
        drop(store);
        assert!(weak.upgrade().is_none());
        assert!(
            !owner.is_idle(),
            "physical generation settlement must not bypass the actual guard"
        );
        drop(guard);
        assert!(
            owner.is_idle(),
            "unlock alone must repump the bare Store fence"
        );
    }

    #[test]
    fn entered_runtime_final_store_retirement_drains_timer_cleanup_from_both_drop_phases() {
        struct TimerOnDrop {
            owner: wasmer_api::sys::NativeCleanupOwner,
            complete: Rc<std::cell::Cell<bool>>,
        }
        impl Drop for TimerOnDrop {
            fn drop(&mut self) {
                let complete = self.complete.clone();
                self.owner.retain(Box::pin(async move {
                    // Construct the timer on a later retained poll, after the
                    // cancellation/finalizer's own runtime guard has ended.
                    tokio::task::yield_now().await;
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    complete.set(true);
                }));
            }
        }
        unsafe extern "C" fn callback(
            _: *mut std::ffi::c_void,
            _: &wasm_val_vec_t,
            _: &mut wasm_val_vec_t,
        ) -> Option<Box<wasm_trap_t>> {
            None
        }
        unsafe extern "C" fn finalize(data: *mut std::ffi::c_void) {
            // This C API Store and its user environment stay on this thread.
            drop(unsafe { Box::from_raw(data.cast::<TimerOnDrop>()) });
        }
        let mut store = wasm_store_t {
            inner: StoreRef::new(Store::default()).unwrap(),
        };
        let owner = match &store.inner.inner.mode {
            StoreMode::Native(native) => native.owner.clone(),
            StoreMode::Plain(_) => unreachable!(),
        };
        let cancellation = Rc::new(std::cell::Cell::new(false));
        let vm_finalizer = Rc::new(std::cell::Cell::new(false));
        let local_guard = TimerOnDrop {
            owner: owner.clone(),
            complete: cancellation.clone(),
        };
        store
            .inner
            .run_host(async move {
                tokio::task::spawn_local(async move {
                    let _guard = local_guard;
                    std::future::pending::<()>().await;
                });
            })
            .unwrap();
        let data = Box::into_raw(Box::new(TimerOnDrop {
            owner: owner.clone(),
            complete: vm_finalizer.clone(),
        }));
        let ty = wasm_functype_t::new(wasmer_api::FunctionType::new([], []));
        let function = unsafe {
            wasm_func_new_with_env(
                Some(&mut store),
                Some(&ty),
                Some(callback),
                data.cast(),
                Some(finalize),
            )
        }
        .unwrap();
        drop(function);
        assert!(
            !vm_finalizer.get(),
            "the VM arena still owns the environment"
        );
        let foreign = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        {
            let _entered = foreign.enter();
            drop(store);
        }
        assert!(
            cancellation.get(),
            "cancellation-enqueued timer must finish"
        );
        assert!(
            vm_finalizer.get(),
            "VM-finalizer-enqueued timer must finish"
        );
        assert!(owner.is_idle());
    }

    #[test]
    fn entered_runtime_final_store_retirement_keeps_custody_until_the_first_panic_is_resumed() {
        let store = StoreRef::new(Store::default()).unwrap();
        store.run_host(async {}).unwrap();
        let (owner, runtime) = match &store.inner.mode {
            StoreMode::Native(native) => (
                native.owner.clone(),
                std::sync::Arc::downgrade(&native.driver.borrow().as_ref().unwrap().runtime),
            ),
            StoreMode::Plain(_) => unreachable!(),
        };
        owner.retain(Box::pin(async {
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            panic!("retirement panic sentinel");
        }));
        let foreign = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let panic = {
            let _entered = foreign.enter();
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(store)))
        }
        .expect_err("the original cleanup panic must be resumed");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"retirement panic sentinel")
        );
        assert!(
            runtime.upgrade().is_none(),
            "the owned runtime must be destroyed first"
        );
        assert!(owner.is_idle());
    }

    #[test]
    fn final_store_retirement_cancels_unrelated_pending_local_work() {
        struct Dropped(Rc<std::cell::Cell<bool>>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let store = StoreRef::new(Store::default()).unwrap();
        let weak = store.downgrade();
        let dropped = Rc::new(std::cell::Cell::new(false));
        let guard = Dropped(dropped.clone());
        store
            .run_host(async move {
                tokio::task::spawn_local(async move {
                    let _guard = guard;
                    for _ in 0..256 {
                        tokio::task::yield_now().await;
                    }
                    std::future::pending::<()>().await;
                });
            })
            .unwrap();
        drop(store);
        assert!(weak.upgrade().is_none());
        assert!(dropped.get(), "unrelated pending work must be cancelled");
    }

    #[test]
    fn final_store_retirement_pumps_owner_continuations_needed_by_managed_local_work() {
        let store = StoreRef::new(Store::default()).unwrap();
        let StoreMode::Native(native) = &store.inner.mode else {
            panic!("native test requires the sys backend");
        };
        let owner = native.owner.clone();
        let gate = Rc::new(std::cell::Cell::new(false));
        let waiter = Rc::new(RefCell::new(None::<std::task::Waker>));
        let (send, receive) = tokio::sync::oneshot::channel();
        let owner_gate = gate.clone();
        let owner_waiter = waiter.clone();
        owner.retain(Box::pin(async move {
            std::future::poll_fn(|cx| {
                if owner_gate.get() {
                    std::task::Poll::Ready(())
                } else {
                    *owner_waiter.borrow_mut() = Some(cx.waker().clone());
                    std::task::Poll::Pending
                }
            })
            .await;
            send.send(()).unwrap();
        }));
        let completed = Rc::new(std::cell::Cell::new(false));
        let fence = completed.clone();
        store
            .register_cleanup_fence(Box::new(move || fence.get()))
            .unwrap();
        let task_completed = completed.clone();
        store
            .run_host(async move {
                tokio::task::spawn_local(async move {
                    // Exceed a LocalSet poll's budget: progress must come from its
                    // real wake signal, not a later unrelated native call.
                    for _ in 0..256 {
                        tokio::task::yield_now().await;
                    }
                    gate.set(true);
                    let wake = waiter.borrow_mut().take();
                    if let Some(wake) = wake {
                        wake.wake();
                    }
                    receive.await.unwrap();
                    task_completed.set(true);
                });
            })
            .unwrap();
        drop(store);
        assert!(
            completed.get(),
            "managed work must finish before cancellation"
        );
        assert!(owner.is_idle());
    }

    #[test]
    fn native_foreign_calls_reenter_the_exact_ancestor_loan_and_poll_its_queued_work() {
        let a = StoreRef::new(Store::default()).unwrap();
        let b = StoreRef::new(Store::default()).unwrap();
        let queued = Rc::new(std::cell::Cell::new(0));
        let observed = queued.clone();
        let leaf = a
            .with_mut(|store| {
                Function::new_async(
                    store,
                    wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]),
                    move |_| {
                        let queued = queued.clone();
                        async move {
                            let (send, receive) = tokio::sync::oneshot::channel();
                            tokio::task::spawn_local(async move {
                                tokio::task::yield_now().await;
                                queued.set(queued.get() + 1);
                                send.send(()).unwrap();
                            });
                            receive.await.unwrap();
                            Ok(vec![Value::I32(37)])
                        }
                    },
                )
            })
            .unwrap();
        let module = a
            .with_mut(|store| {
                Module::new(
                    store,
                    wat::parse_str(
                        r#"(module
            (import "test" "wait" (func $wait (result i32)))
            (global $value (mut i32) (i32.const 0))
            (func $init call $wait global.set $value) (start $init)
            (func (export "value") (result i32) global.get $value))"#,
                    )
                    .unwrap(),
                )
            })
            .unwrap()
            .unwrap();
        let weak_a = a.downgrade();
        let middle = b
            .with_mut(|store| {
                Function::new_async(
                    store,
                    wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]),
                    move |_| {
                        let a = weak_a.upgrade().unwrap();
                        a.with_mut(|store| assert_eq!(store.objects_mut().id(), a.inner.id))
                            .unwrap();
                        let result = a.call(&leaf, vec![]).and_then(|values| {
                            assert_eq!(values[0].i32(), Some(37));
                            let instance = a
                                .instantiate(&module, vec![leaf.clone().into()])?
                                .map_err(|error| RuntimeError::new(error.to_string()))?;
                            a.call(instance.exports.get_function("value").unwrap(), vec![])
                        });
                        std::future::ready(result.map(Vec::from))
                    },
                )
            })
            .unwrap();
        let weak_b = b.downgrade();
        let root = a
            .with_mut(|store| {
                Function::new_async(
                    store,
                    wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]),
                    move |_| {
                        let result = weak_b.upgrade().unwrap().call(&middle, vec![]);
                        std::future::ready(result.map(Vec::from))
                    },
                )
            })
            .unwrap();
        for expected in 1..=2 {
            let result = a.call(&root, vec![]).unwrap();
            assert_eq!(result[0].i32(), Some(37));
            assert_eq!(observed.get(), 2 * expected);
            assert_eq!(
                a.with_mut(|store| store.objects_mut().id()).unwrap(),
                a.inner.id
            );
            assert_eq!(
                b.with_mut(|store| store.objects_mut().id()).unwrap(),
                b.inner.id
            );
        }
    }

    #[cfg(feature = "wasi")]
    #[test]
    fn native_ancestor_handoff_matches_once_with_host_access_after_the_child_abort() {
        struct Endpoint {
            store: WeakStoreRef,
            marker: RuntimeError,
            claimed: Rc<std::cell::Cell<bool>>,
            completed: Rc<std::cell::Cell<usize>>,
        }
        impl ContinuationEndpoint for Endpoint {
            fn matches(&self, store: &mut StoreMut<'_>, error: &RuntimeError) -> bool {
                store.objects_mut().id() == self.store.upgrade().unwrap().inner.id
                    && !self.claimed.get()
                    && std::ptr::eq(
                        error.downcast_ref::<std::io::Error>().unwrap(),
                        self.marker.downcast_ref::<std::io::Error>().unwrap(),
                    )
            }
            fn prepare(
                self: Rc<Self>,
                store: &StoreRef,
                _: &RuntimeError,
            ) -> Result<LocalContinuation, RuntimeError> {
                assert!(!self.claimed.replace(true));
                // Original A is still parked. This must use its captured loan,
                // including when current B has already latched the child abort.
                store.with_mut(|loan| assert_eq!(loan.objects_mut().id(), store.inner.id))?;
                let weak = self.store.clone();
                let completed = self.completed.clone();
                Ok(LocalContinuation {
                    store: store.clone(),
                    run: Some(Box::new(move || {
                        Box::pin(async move {
                            let a = weak.upgrade().unwrap();
                            a.with_mut(|loan| assert_eq!(loan.objects_mut().id(), a.inner.id))?;
                            completed.set(completed.get() + 1);
                            Err(RuntimeError::new("completed exact ancestor continuation"))
                        })
                    })),
                    cancel: None,
                })
            }
            fn cancel_unclaimed(
                self: Rc<Self>,
                _: &StoreRef,
                _: &RuntimeError,
            ) -> Result<(), RuntimeError> {
                panic!("the real outer call owner must be found")
            }
        }
        let a = StoreRef::new(Store::default()).unwrap();
        let b = StoreRef::new(Store::default()).unwrap();
        let marker =
            RuntimeError::host_abort(Box::new(std::io::Error::other("exact ancestor handoff")));
        let claimed = Rc::new(std::cell::Cell::new(false));
        let completed = Rc::new(std::cell::Cell::new(0));
        let endpoint: Rc<dyn ContinuationEndpoint> = Rc::new(Endpoint {
            store: a.downgrade(),
            marker: marker.clone(),
            claimed: claimed.clone(),
            completed: completed.clone(),
        });
        a.register_endpoint(Rc::downgrade(&endpoint)).unwrap();
        let leaf = a
            .with_mut(|store| {
                Function::new_async(store, wasmer_api::FunctionType::new([], []), move |_| {
                    std::future::ready(Err(marker.clone()))
                })
            })
            .unwrap();
        let weak_a = a.downgrade();
        let middle = b
            .with_mut(|store| {
                Function::new_async(store, wasmer_api::FunctionType::new([], []), move |_| {
                    assert!(weak_a.upgrade().unwrap().call(&leaf, vec![]).is_err());
                    std::future::ready(Ok(Vec::new())) // Deliberately swallow the trap.
                })
            })
            .unwrap();
        let weak_b = b.downgrade();
        let root = a
            .with_mut(|store| {
                Function::new_async(store, wasmer_api::FunctionType::new([], []), move |_| {
                    assert!(weak_b.upgrade().unwrap().call(&middle, vec![]).is_err());
                    std::future::ready(Ok(Vec::new()))
                })
            })
            .unwrap();
        let error = a.call(&root, vec![]).unwrap_err();
        assert_eq!(error.message(), "completed exact ancestor continuation");
        assert!(claimed.get());
        assert_eq!(completed.get(), 1);
        a.with_mut(|loan| assert_eq!(loan.objects_mut().id(), a.inner.id))
            .unwrap();
        b.with_mut(|loan| assert_eq!(loan.objects_mut().id(), b.inner.id))
            .unwrap();
    }

    #[cfg(feature = "wasi")]
    #[test]
    fn native_instantiation_never_publishes_saved_success_after_call_owner_failure() {
        let mut store = wasm_store_t {
            inner: StoreRef::new(Store::default()).unwrap(),
        };
        let weak = store.inner.downgrade();
        let completed = Rc::new(std::cell::Cell::new(0));
        let observed = completed.clone();
        let error = RuntimeError::user(Box::new(std::io::Error::other(
            "exact post-instantiation continuation failure",
        )));
        let expected = error.to_string();
        let arm = store
            .inner
            .with_mut(|store| {
                Function::new_async(store, wasmer_api::FunctionType::new([], []), move |_| {
                    let owner = wasmer_api::sys::current_native_local_owner::<CallOwner>().unwrap();
                    let store = weak.upgrade().unwrap();
                    let weak = weak.clone();
                    let completed = completed.clone();
                    let error = error.clone();
                    owner.pending.borrow_mut().push_back(LocalContinuation {
                        store,
                        run: Some(Box::new(move || {
                            Box::pin(async move {
                                // drain runs AFTER the native trampoline saved Ok(instance)
                                // and the original Store guard physically unlocked.
                                let store = weak.upgrade().unwrap();
                                store.with_mut(|loan| {
                                    assert_eq!(loan.objects_mut().id(), store.inner.id)
                                })?;
                                completed.set(completed.get() + 1);
                                Err(error)
                            })
                        })),
                        cancel: None,
                    });
                    std::future::ready(Ok(Vec::new()))
                })
            })
            .unwrap();
        let module = wasm_module_t {
            inner: store
                .inner
                .with_mut(|store| {
                    Module::new(
                        store,
                        wat::parse_str(
                            r#"(module
                (import "test" "arm" (func $arm))
                (func $init call $arm) (start $init)
                (func (export "value") (result i32) i32.const 42))"#,
                        )
                        .unwrap(),
                    )
                })
                .unwrap()
                .unwrap(),
        };
        let imports: wasm_extern_vec_t = vec![Some(Box::new(wasm_extern_t::new(
            store.inner.clone(),
            arm.into(),
        )))]
        .into();
        let mut trap = std::ptr::null_mut();
        let instance = unsafe {
            wasm_instance_new(
                Some(&mut store),
                Some(&module),
                Some(&imports),
                Some(&mut trap),
            )
        };
        assert!(
            instance.is_none(),
            "saved success must not override the enclosing call failure"
        );
        assert!(
            trap.is_null(),
            "host completion errors keep their existing last-error phase"
        );
        assert_eq!(observed.get(), 1);
        let length = crate::error::wasmer_last_error_length();
        assert_eq!(length as usize, expected.len() + 1);
        let mut message = vec![0u8; length as usize];
        let written = unsafe {
            crate::error::wasmer_last_error_message(
                std::ptr::NonNull::new(message.as_mut_ptr().cast()),
                length,
            )
        };
        assert_eq!(written, length);
        let mut expected = expected.into_bytes();
        expected.push(0);
        assert_eq!(message, expected);
        store
            .inner
            .with_mut(|loan| assert_eq!(loan.objects_mut().id(), store.inner.inner.id))
            .unwrap();
    }

    #[test]
    fn native_foreign_instantiation_suspends_start_and_preserves_the_callers_store() {
        let a = StoreRef::new(Store::default()).unwrap();
        let b = StoreRef::new(Store::default()).unwrap();
        let wait = b
            .with_mut(|store| {
                Function::new_async(
                    store,
                    wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]),
                    |_| async {
                        tokio::task::yield_now().await;
                        Ok(vec![Value::I32(42)])
                    },
                )
            })
            .unwrap();
        let module = b
            .with_mut(|store| {
                Module::new(
                    store,
                    wat::parse_str(
                        r#"(module
            (import "test" "wait" (func $wait (result i32)))
            (global $value (mut i32) (i32.const 0))
            (func $init call $wait global.set $value) (start $init)
            (func (export "value") (result i32) global.get $value))"#,
                    )
                    .unwrap(),
                )
            })
            .unwrap()
            .unwrap();
        let weak_b = b.downgrade();
        let root = a
            .with_mut(|store| {
                Function::new_async(
                    store,
                    wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]),
                    move |_| {
                        let b = weak_b.upgrade().unwrap();
                        let result =
                            b.instantiate(&module, vec![wait.clone().into()])
                                .and_then(|result| {
                                    let instance = result
                                        .map_err(|error| RuntimeError::new(error.to_string()))?;
                                    b.call(instance.exports.get_function("value").unwrap(), vec![])
                                });
                        std::future::ready(result.map(Vec::from))
                    },
                )
            })
            .unwrap();
        assert_eq!(a.call(&root, vec![]).unwrap()[0].i32(), Some(42));
        assert_eq!(
            a.with_mut(|store| store.objects_mut().id()).unwrap(),
            a.inner.id
        );
        assert_eq!(
            b.with_mut(|store| store.objects_mut().id()).unwrap(),
            b.inner.id
        );
    }

    #[test]
    fn entered_runtime_calls_fail_without_panicking_and_leave_the_store_usable() {
        let mut store = wasm_store_t {
            inner: StoreRef::new(Store::default()).unwrap(),
        };
        let function = store
            .inner
            .with_mut(|store| Function::new_typed(store, || 19i32))
            .unwrap();
        let mut function = wasm_func_t {
            extern_: wasm_extern_t::new(store.inner.clone(), function.into()),
        };
        let module = wasm_module_t {
            inner: store
                .inner
                .with_mut(|store| Module::new(store, wat::parse_str("(module)").unwrap()))
                .unwrap()
                .unwrap(),
        };
        let imports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
        let mut results: wasm_val_vec_t = vec![wasm_val_t::default()].into();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        {
            let _entered = runtime.enter();
            let trap = unsafe { wasm_func_call(Some(&mut function), Some(&args), &mut results) };
            assert!(trap.is_some(), "an entered-runtime error remains a C trap");
            let mut trap = std::ptr::null_mut();
            assert!(
                unsafe {
                    wasm_instance_new(
                        Some(&mut store),
                        Some(&module),
                        Some(&imports),
                        Some(&mut trap),
                    )
                }
                .is_none()
            );
            assert!(trap.is_null(), "host admission errors use last_error");
        }
        assert!(
            unsafe { wasm_func_call(Some(&mut function), Some(&args), &mut results) }.is_none()
        );
        assert_eq!(unsafe { results.as_slice()[0].of.int32_t }, 19);
        assert!(
            unsafe { wasm_instance_new(Some(&mut store), Some(&module), Some(&imports), None) }
                .is_some()
        );
    }

    #[test]
    fn native_c_entrypoints_suspend_engine_start_and_return_reactor_values() {
        let mut store = wasm_store_t {
            inner: StoreRef::new(Store::default()).unwrap(),
        };
        let wait = store
            .inner
            .with_mut(|store| {
                Function::new_async(
                    store,
                    wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]),
                    |_| async {
                        tokio::task::yield_now().await;
                        Ok(vec![Value::I32(42)])
                    },
                )
            })
            .unwrap();
        let source = wat::parse_str(
            r#"(module
            (import "proof" "wait" (func $wait (result i32)))
            (global $result (mut i32) (i32.const 0))
            (func $init call $wait global.set $result) (start $init)
            (func (export "value") (result i32) global.get $result))"#,
        )
        .unwrap();
        let module = wasm_module_t {
            inner: store
                .inner
                .with_mut(|store| Module::new(store, &source))
                .unwrap()
                .unwrap(),
        };
        let imports: wasm_extern_vec_t = vec![Some(Box::new(wasm_extern_t::new(
            store.inner.clone(),
            wait.into(),
        )))]
        .into();
        let instance =
            unsafe { wasm_instance_new(Some(&mut store), Some(&module), Some(&imports), None) }
                .unwrap();
        let mut function = wasm_func_t {
            extern_: wasm_extern_t::new(
                store.inner.clone(),
                instance
                    .inner
                    .exports
                    .get_function("value")
                    .unwrap()
                    .clone()
                    .into(),
            ),
        };
        let arguments: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
        let mut results: wasm_val_vec_t = vec![wasm_val_t::default()].into();
        for _ in 0..2 {
            assert!(
                unsafe { wasm_func_call(Some(&mut function), Some(&arguments), &mut results) }
                    .is_none()
            );
            assert_eq!(unsafe { results.as_slice()[0].of.int32_t }, 42);
        }
        assert!(
            store
                .inner
                .with_mut(|store| function.extern_.function().is_from_store(store))
                .unwrap()
        );
    }
}
