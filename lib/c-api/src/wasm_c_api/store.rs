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
}

#[cfg(feature = "sys")]
struct Driver {
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
    local: tokio::task::LocalSet,
    active: std::cell::Cell<bool>,
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
            return Ok(Self {
                inner: Rc::new(StoreState {
                    id,
                    mode: StoreMode::Native(ManagedStore {
                        store: Some(store.into_async()),
                        generation: Some(generation),
                        owner,
                        driver: RefCell::new(None),
                        cleanup_fences: RefCell::default(),
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
                Ok(f.take().unwrap()(&mut guard.as_store_mut()))
            }
            #[cfg(feature = "sys")]
            StoreMode::Native(native) => {
                use std::{
                    future::Future,
                    task::{Context, Poll, Waker},
                };
                use wasmer_api::AsStoreAsync;
                let mut lock = std::pin::pin!(native.store.as_ref().unwrap().write_lock());
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
                current.parked(|| {
                    self.with_mut(|store| function.call(store, &args))
                        .and_then(|result| result)
                })
            }
        }) {
            return result;
        }
        match &self.inner.mode {
            StoreMode::Plain(_) => self.with_mut(|store| function.call(store, &args))?,
            #[cfg(feature = "sys")]
            StoreMode::Native(native) => {
                let driver = native.driver()?;
                driver.run(function.call_async(native.store.as_ref().unwrap(), args))?
            }
        }
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
                current.parked(|| {
                    self.with_mut(|store| Instance::new_by_index(store, module, &externs))
                })
            }
        }) {
            return result;
        }
        match &self.inner.mode {
            StoreMode::Plain(_) => {
                self.with_mut(|store| Instance::new_by_index(store, module, &externs))
            }
            #[cfg(feature = "sys")]
            StoreMode::Native(native) => {
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
                            let request = input.upgrade().ok_or_else(|| {
                                RuntimeError::new("instantiation request expired")
                            })?;
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
                            *output.lock().unwrap_or_else(|error| error.into_inner()) =
                                Some(instance);
                            Ok(Vec::new())
                        },
                    )
                });
                let trampoline = trampoline?;
                let driver = native.driver()?;
                driver.run(trampoline.call_async(native.store.as_ref().unwrap(), Vec::new()))??;
                let value = result
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                value.ok_or_else(|| RuntimeError::new("native instantiation did not settle"))
            }
        }
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
    pub(crate) fn cleanup_retirement(
        &self,
        mut future: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
    ) -> Result<Box<dyn FnOnce()>, RuntimeError> {
        use std::future::Future;
        let StoreMode::Native(native) = &self.inner.mode else {
            return Err(RuntimeError::new("Store has no native cleanup owner"));
        };
        let driver = native.driver()?;
        let owner = native.owner.clone();
        Ok(Box::new(move || {
            owner.retain(Box::pin(std::future::poll_fn(move |cx| {
                let _runtime = driver.runtime.enter();
                let _local = driver.local.enter();
                future.as_mut().poll(cx)
            })));
        }))
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
        });
        *self.driver.borrow_mut() = Some(driver.clone());
        Ok(driver)
    }
}

#[cfg(feature = "sys")]
impl Driver {
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
        Ok(self.runtime.block_on(self.local.run_until(future)))
    }
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
        generation.close();
        self.owner.retain(Box::pin(async move {
            generation.close_and_wait_for_cleanup().await;
            let final_owner = owner.clone();
            owner.after_pump(Box::new(move || {
                retire_store(store, driver, fences, final_owner);
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
    let waker = Waker::from(signal.clone());
    let mut cx = Context::from_waker(&waker);
    let mut drain = |driver: Option<&Driver>, require_fences: bool| {
        loop {
            *signal.0.lock().unwrap_or_else(|e| e.into_inner()) = false;
            let runtime = driver.as_ref().map(|driver| driver.runtime.clone());
            let _enter = runtime.as_ref().map(|runtime| runtime.enter());
            if let Some(driver) = driver {
                let local = driver.local.run_until(std::future::pending::<()>());
                let _ = std::pin::pin!(local).as_mut().poll(&mut cx);
            }
            let _local = driver.map(|driver| driver.local.enter());
            // Unlike notify's fallback, this poll installs our real thread-safe
            // wake signal in every retained continuation. Pump before waiting.
            if owner.poll_idle(&mut cx).is_ready()
                && (!require_fences || fences.iter().all(|closed| closed()))
            {
                break;
            }
            let mut ready = signal.0.lock().unwrap_or_else(|e| e.into_inner());
            while !*ready {
                ready = signal.1.wait(ready).unwrap_or_else(|e| e.into_inner());
            }
        }
    };
    drain(driver.as_deref(), true);
    let runtime = driver.map(|driver| {
        // Cleanup continuations may retain the driver until their fences settle.
        // Public calls retain StoreRef, so no other execution survives this point.
        let driver = Rc::try_unwrap(driver)
            .ok()
            .expect("native driver survived its Store owner");
        let Driver { runtime, local, .. } = driver;
        {
            let _enter = runtime.enter();
            // Loader/native obligations have settled. Cancel unrelated local work,
            // including tasks that would otherwise stay pending forever.
            drop(local);
        }
        runtime
    });
    drain(None, false);
    drop(store);
    drain(None, false);
    drop(drain);
    drop(_clear);
    // Runtime destruction can block and is illegal in a foreign Tokio callback.
    // Only the Send runtime moves; all Store/LocalSet custody stayed on this thread.
    if let Some(runtime) = runtime {
        let _ = std::thread::spawn(move || drop(runtime)).join();
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
        externals::{wasm_extern_t, wasm_extern_vec_t, wasm_func_call, wasm_func_t},
        instance::wasm_instance_new,
        module::wasm_module_t,
        value::{wasm_val_t, wasm_val_vec_t},
    };

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
