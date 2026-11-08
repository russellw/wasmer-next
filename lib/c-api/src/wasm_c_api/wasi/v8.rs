//! Canonical WASI handles for the V8 original-thread C API owner.

use super::canonical::{self, Bootstrap, Capture};
use crate::wasm_c_api::{store::StoreRef, store::v8::Driver};
use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    sync::Arc,
};
use wasixv2::{EmbeddingProcess, LocalFuture, MachineSyscalls};
use wasixv2_exec::HostEnvironment;
use wasmer_api::{
    AsStoreAsync, AsStoreMut, Function, Imports, Instance, Memory, Module, RuntimeError, StoreMut,
};

pub(super) struct V8Wasi {
    pub(in crate::wasm_c_api) endpoint: Rc<Endpoint>,
    stdout: Option<Arc<Capture>>,
    stderr: Option<Arc<Capture>>,
}
pub(in crate::wasm_c_api) struct Endpoint {
    process: RefCell<Option<EmbeddingProcess>>,
    environment: HostEnvironment<MachineSyscalls>,
    retirement: RefCell<Option<LocalFuture<'static, ()>>>,
    driver: Weak<Driver>,
    retired: Cell<bool>,
    selected_start: RefCell<Option<Function>>,
}
impl V8Wasi {
    pub(super) fn new(
        store: &StoreRef,
        args: Vec<String>,
        env: Vec<(String, Vec<u8>)>,
        preopens: Vec<(String, String)>,
        capture_stdout: bool,
        capture_stderr: bool,
    ) -> anyhow::Result<Self> {
        let Bootstrap {
            process,
            environment,
            input,
            descriptors,
            stdout,
            stderr,
        } = canonical::bootstrap(store, args, env, preopens, capture_stdout, capture_stderr)?;
        let driver = store.v8_driver()?;
        let local = driver.bind_scope(environment.loader_cleanup().clone());
        let asynchronous = store.async_store()?;
        let retiring_store = asynchronous.store();
        let retiring_env = environment.clone();
        let retirement = Box::pin(async move {
            local
                .run(async move {
                    let mut guard = retiring_store.write_lock().await;
                    retiring_env.deactivate(&mut guard.as_store_mut());
                })
                .await;
        });
        let result = Self {
            endpoint: Rc::new(Endpoint {
                process: RefCell::new(Some(process)),
                environment,
                retirement: RefCell::new(Some(retirement)),
                driver: Rc::downgrade(&driver),
                retired: Cell::new(false),
                selected_start: RefCell::new(None),
            }),
            stdout,
            stderr,
        };
        store.run_host(async {
            let process = result
                .endpoint
                .process
                .borrow()
                .as_ref()
                .and_then(EmbeddingProcess::wasix1)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("process owner is closed"))?;
            process
                .configure_and_prepare_startup(
                    &asynchronous,
                    &result.endpoint.environment,
                    input,
                    descriptors,
                )
                .await
                .map_err(anyhow::Error::from)
        })??;
        driver
            .endpoints
            .borrow_mut()
            .push(Rc::downgrade(&result.endpoint));
        Ok(result)
    }
    pub(super) fn import_object(
        &self,
        store: &mut StoreMut<'_>,
        module: &Module,
    ) -> anyhow::Result<Imports> {
        canonical::import_object(&self.endpoint.environment, store, module)
    }
    pub(super) fn initialize(
        &self,
        store: &mut StoreMut<'_>,
        instance: &Instance,
    ) -> anyhow::Result<()> {
        if self.endpoint.retired.get() {
            anyhow::bail!("WASI environment is retired");
        }
        canonical::initialize(
            &self.endpoint.environment,
            &self.endpoint.process,
            &self.endpoint.selected_start,
            store,
            instance,
        )
    }
    pub(super) fn read(&self, stderr: bool, buffer: &mut [u8]) -> isize {
        if self.endpoint.retired.get() {
            crate::error::update_last_error("WASI environment is closed");
            return -1;
        }
        match if stderr { &self.stderr } else { &self.stdout } {
            Some(capture) => capture.read(buffer) as isize,
            None => {
                crate::error::update_last_error("the stream is inherited, not captured");
                -1
            }
        }
    }
    pub(super) fn close(&mut self) {
        self.endpoint.close();
    }
}
impl Drop for V8Wasi {
    fn drop(&mut self) {
        self.close();
    }
}
impl Endpoint {
    pub(in crate::wasm_c_api) fn prebind_memory(&self, store: &mut StoreMut<'_>, memory: &Memory) {
        if !self.retired.get() {
            self.environment.prebind_memory(store, memory);
        }
    }
    pub(in crate::wasm_c_api) fn exit_status(
        &self,
        function: &Function,
        error: &RuntimeError,
    ) -> Option<i32> {
        if self.retired.get()
            || !self
                .selected_start
                .borrow()
                .as_ref()
                .is_some_and(|selected| selected == function)
        {
            return None;
        }
        wasixv2_exec::thread_exit_status(error)
    }
    fn close(&self) {
        if self.retired.replace(true) {
            return;
        }
        let process = self.process.borrow_mut().take();
        let retirement = self.retirement.borrow_mut().take();
        if let Some(retirement) = retirement {
            // wasi_env_t retains StoreRef through this actual field Drop; its
            // owner therefore remains strong through publication and closure.
            let driver = self
                .driver
                .upgrade()
                .expect("V8 WASI retirement lost its actual owner");
            driver.retire(retirement, move || {
                if let Some(mut process) = process {
                    process.close();
                }
            });
        } else if let Some(mut process) = process {
            process.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_c_api::{
        engine::{
            wasm_config_new, wasm_config_set_backend, wasm_engine_new_with_config, wasmer_backend_t,
        },
        externals::{
            wasm_extern_as_func, wasm_extern_as_memory, wasm_extern_t, wasm_extern_vec_t,
            wasm_func_call, wasm_func_copy, wasm_memory_copy, wasm_memory_data,
        },
        instance::{wasm_instance_exports, wasm_instance_new},
        module::wasm_module_new,
        store::wasm_store_new,
        types::{wasm_byte_vec_t, wasm_valkind_enum},
        value::{wasm_val_inner, wasm_val_t, wasm_val_vec_t},
        wasi::{
            wasi_config_arg, wasi_config_capture_stdout, wasi_config_env, wasi_config_new,
            wasi_env_delete, wasi_env_initialize_instance, wasi_env_new, wasi_env_read_stdout,
            wasi_get_imports, wasi_get_start_function,
        },
    };
    use std::{
        ffi::CString,
        process::{Child, Command},
        time::{Duration, Instant},
    };

    #[test]
    fn public_v8_canonical_wasi_start_args_env_write_and_actual_timer_pending() {
        const TEST: &str = "wasm_c_api::wasi::v8::tests::public_v8_canonical_wasi_start_args_env_write_and_actual_timer_pending";
        const CHILD: &str = "WASMER_CAPI_V8_WASI_CHILD";
        if std::env::var_os(CHILD).is_none() {
            struct OwnedChild(Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut child = OwnedChild(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(CHILD, "1")
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                match child.0.try_wait() {
                    Ok(Some(status)) => {
                        assert!(status.success(), "canonical V8 WASI child failed: {status}");
                        return;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    status => panic!("canonical V8 WASI did not finish: {status:?}"),
                }
            }
        }
        let mut config = wasm_config_new();
        wasm_config_set_backend(&mut config, wasmer_backend_t::V8);
        let engine = wasm_engine_new_with_config(Some(config)).unwrap();
        let mut store = unsafe { wasm_store_new(Some(&engine)) }.unwrap();
        assert!(store.inner.is_v8_managed());
        let program = CString::new("v8-wasi").unwrap();
        let argument = CString::new("hello").unwrap();
        let key = CString::new("K").unwrap();
        let value = CString::new("V").unwrap();
        let mut config = unsafe { wasi_config_new(program.as_ptr()) }.unwrap();
        unsafe {
            wasi_config_arg(&mut config, argument.as_ptr());
            wasi_config_env(&mut config, key.as_ptr(), value.as_ptr());
        }
        wasi_config_capture_stdout(&mut config);
        let mut env = unsafe { wasi_env_new(Some(&mut store), config) }.unwrap();
        let guest: wasm_byte_vec_t = wat::parse_str(r#"(module
            (import "wasi_snapshot_preview1" "args_sizes_get" (func $args_sizes (param i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "args_get" (func $args (param i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "environ_sizes_get" (func $env_sizes (param i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "environ_get" (func $env (param i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
            (import "env" "memory" (memory 1))
            (export "memory" (memory 0))
            (data (i32.const 1024) "v8-canonical\0a")
            (func $boot
                i32.const 280 i32.const 284 call $args_sizes if unreachable end
                i32.const 300 i32.const 1 i32.store)
            (start $boot)
            (func (export "_start") (result i32)
                i32.const 400 i32.const 420 call $args if unreachable end
                i32.const 288 i32.const 292 call $env_sizes if unreachable end
                i32.const 600 i32.const 620 call $env if unreachable end
                i32.const 0 i64.const 41 i64.store
                i32.const 8 i32.const 0 i32.store8
                i32.const 16 i32.const 1 i32.store
                i32.const 24 i64.const 250000000 i64.store
                i32.const 32 i64.const 1 i64.store
                i32.const 40 i32.const 0 i32.store16
                i32.const 0 i32.const 128 i32.const 1 i32.const 256 call $poll if unreachable end
                i32.const 300 i32.const 2 i32.store
                i32.const 512 i32.const 1024 i32.store
                i32.const 516 i32.const 13 i32.store
                i32.const 1 i32.const 512 i32.const 1 i32.const 520 call $write if unreachable end
                i32.const 37)
            (func (export "timer_only") (result i32)
                i32.const 304 i32.const 3 i32.store
                i32.const 256 i32.const 0 i32.store
                i32.const 0 i64.const 73 i64.store
                i32.const 8 i32.const 0 i32.store8
                i32.const 16 i32.const 1 i32.store
                i32.const 24 i64.const 250000000 i64.store
                i32.const 32 i64.const 1 i64.store
                i32.const 40 i32.const 0 i32.store16
                i32.const 0 i32.const 128 i32.const 1 i32.const 256 call $poll if unreachable end
                i32.const 304 i32.const 4 i32.store
                i32.const 41))"#).unwrap().into();
        let module = unsafe { wasm_module_new(Some(&mut store), Some(&guest)) }.unwrap();
        let mut imports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        assert!(unsafe {
            wasi_get_imports(Some(&store), Some(&mut env), Some(&module), &mut imports)
        });
        let mut trap = std::ptr::null_mut();
        let mut instance = unsafe {
            wasm_instance_new(
                Some(&mut store),
                Some(&module),
                Some(&imports),
                Some(&mut trap),
            )
        }
        .unwrap();
        assert!(trap.is_null(), "actual Wasm start imports must be accepted");
        let mut exports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        unsafe {
            wasm_instance_exports(&instance, &mut exports);
        }
        let memory = exports
            .as_slice()
            .iter()
            .flatten()
            .find_map(|value| wasm_extern_as_memory(Some(value.as_ref())))
            .unwrap();
        let mut memory = unsafe { wasm_memory_copy(memory) };
        // Use the actual public memory export, not a synthetic completion bit.
        let bytes =
            unsafe { std::slice::from_raw_parts(wasm_memory_data(Some(&mut memory)), 2048) };
        assert_eq!(u32::from_le_bytes(bytes[300..304].try_into().unwrap()), 1);
        assert!(unsafe { wasi_env_initialize_instance(&mut env, &mut store, &mut instance) });
        let driver = store.inner.v8_driver().unwrap();
        let before_pending = driver.pending_imports();
        let mut start = unsafe { wasi_get_start_function(&mut instance) }.unwrap();
        let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
        let mut results: wasm_val_vec_t = vec![wasm_val_t {
            kind: wasm_valkind_enum::WASM_I32 as _,
            of: wasm_val_inner { int32_t: 0 },
        }]
        .into();
        assert!(unsafe { wasm_func_call(Some(&mut start), Some(&args), &mut results) }.is_none());
        assert_eq!(unsafe { results.as_slice()[0].of.int32_t }, 37);
        assert!(
            driver.pending_imports() > before_pending,
            "real WASI timer import must have returned Pending"
        );
        let bytes =
            unsafe { std::slice::from_raw_parts(wasm_memory_data(Some(&mut memory)), 2048) };
        assert_eq!(u32::from_le_bytes(bytes[280..284].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(bytes[284..288].try_into().unwrap()), 14);
        assert_eq!(u32::from_le_bytes(bytes[288..292].try_into().unwrap()), 1);
        assert_eq!(&bytes[420..434], b"v8-wasi\0hello\0");
        assert_eq!(&bytes[620..624], b"K=V\0");
        assert_eq!(u32::from_le_bytes(bytes[256..260].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[300..304].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(bytes[520..524].try_into().unwrap()), 13);
        let mut captured = [0u8; 32];
        let read =
            unsafe { wasi_env_read_stdout(&mut env, captured.as_mut_ptr().cast(), captured.len()) };
        assert_eq!(read, 13);
        assert_eq!(&captured[..13], b"v8-canonical\n");
        // This export has ONLY the real timer import, so another import's
        // Pending cannot satisfy the timer-specific progress oracle.
        let mut timer =
            wasm_func_copy(wasm_extern_as_func(exports.as_slice()[2].as_deref()).unwrap());
        let before_timer = driver.pending_imports();
        assert!(unsafe { wasm_func_call(Some(&mut timer), Some(&args), &mut results) }.is_none());
        assert_eq!(unsafe { results.as_slice()[0].of.int32_t }, 41);
        assert!(driver.pending_imports() > before_timer);
        let bytes =
            unsafe { std::slice::from_raw_parts(wasm_memory_data(Some(&mut memory)), 2048) };
        assert_eq!(u32::from_le_bytes(bytes[304..308].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(bytes[256..260].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[128..136].try_into().unwrap()), 73);
        assert_eq!(u16::from_le_bytes(bytes[136..138].try_into().unwrap()), 0);
        drop(timer);
        drop(start);
        drop(memory);
        drop(exports);
        drop(imports);
        drop(module);
        drop(guest);
        let weak_driver = Rc::downgrade(&driver);
        let weak_store = store.inner.downgrade();
        drop(driver); // actual owner is the surviving public Store, not this probe
        drop(store);
        assert!(
            weak_store.upgrade().is_some(),
            "public env/instance still own the Store"
        );
        wasi_env_delete(Some(env));
        assert!(
            weak_store.upgrade().is_some(),
            "the last instance still owns its actual Store"
        );
        drop(instance); // last public handle: real Instance field, then Store completion
        assert!(weak_store.upgrade().is_none());
        assert!(weak_driver.upgrade().is_none());
        drop(engine);
        eprintln!("canonical-v8-public-env-import-start-args-env-write-pending-cleanup-complete");
    }
}

#[cfg(test)]
mod reentry_tests {
    use super::*;
    use crate::wasm_c_api::{
        engine::{
            wasm_config_new, wasm_config_set_backend, wasm_engine_new_with_config, wasm_engine_t,
            wasmer_backend_t,
        },
        externals::{
            wasm_extern_as_func, wasm_extern_copy, wasm_extern_t, wasm_extern_vec_t,
            wasm_func_as_extern, wasm_func_call, wasm_func_copy, wasm_func_new_with_env,
            wasm_func_t,
        },
        instance::{wasm_instance_exports, wasm_instance_new},
        module::{wasm_module_new, wasm_module_t},
        store::{wasm_store_new, wasm_store_t},
        trap::wasm_trap_t,
        types::{wasm_byte_vec_t, wasm_functype_t, wasm_valkind_enum},
        value::{wasm_val_inner, wasm_val_t, wasm_val_vec_t},
        wasi::{
            wasi_config_new, wasi_env_delete, wasi_env_initialize_instance, wasi_env_new,
            wasi_get_imports,
        },
    };
    use std::{
        ffi::{CString, c_void},
        sync::atomic::{AtomicI32, AtomicUsize, Ordering},
    };

    fn owned_child(name: &str, variable: &str) -> bool {
        if std::env::var_os(variable).is_some() {
            return true;
        }
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Owned(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env(variable, "1")
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            match child.0.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "V8 reentry child failed: {status}");
                    return false;
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                status => panic!("V8 reentry did not finish: {status:?}"),
            }
        }
    }
    fn public_store() -> (Box<wasm_engine_t>, Box<wasm_store_t>) {
        let mut config = wasm_config_new();
        wasm_config_set_backend(&mut config, wasmer_backend_t::V8);
        let engine = wasm_engine_new_with_config(Some(config)).unwrap();
        let store = unsafe { wasm_store_new(Some(&engine)) }.unwrap();
        (engine, store)
    }
    fn module(store: &mut wasm_store_t, source: &str) -> Box<wasm_module_t> {
        let bytes: wasm_byte_vec_t = wat::parse_str(source).unwrap().into();
        unsafe { wasm_module_new(Some(store), Some(&bytes)) }.unwrap()
    }
    fn result() -> wasm_val_vec_t {
        vec![wasm_val_t {
            kind: wasm_valkind_enum::WASM_I32 as _,
            of: wasm_val_inner { int32_t: 0 },
        }]
        .into()
    }
    fn call(function: &mut wasm_func_t) -> i32 {
        let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
        call_with_args(function, &args)
    }
    fn call_with_args(function: &mut wasm_func_t, args: &wasm_val_vec_t) -> i32 {
        let mut result = result();
        let trap = unsafe { wasm_func_call(Some(function), Some(args), &mut result) };
        assert!(
            trap.is_none(),
            "public V8 call trapped: {:?}",
            trap.map(|trap| trap.inner.to_string())
        );
        unsafe { result.as_slice()[0].of.int32_t }
    }

    struct Callback {
        nested: *mut wasm_func_t,
        survivor: *mut wasm_func_t,
        calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        final_value: Arc<AtomicI32>,
        final_traps: Arc<std::sync::Mutex<Vec<Box<wasm_trap_t>>>>,
    }
    unsafe extern "C" fn nested_callback(
        data: *mut c_void,
        _: &wasm_val_vec_t,
        output: &mut wasm_val_vec_t,
    ) -> Option<Box<wasm_trap_t>> {
        let data = unsafe { &*data.cast::<Callback>() };
        data.calls.fetch_add(1, Ordering::SeqCst);
        let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
        let mut result = result();
        if let Some(trap) =
            unsafe { wasm_func_call(Some(&mut *data.nested), Some(&args), &mut result) }
        {
            return Some(trap);
        }
        let value = unsafe { result.as_slice()[0].of.int32_t };
        let Some(slot) = output.as_uninit_slice().first_mut() else {
            return Some(Box::new(wasm_trap_t {
                inner: RuntimeError::new("missing C callback result slot"),
            }));
        };
        slot.write(wasm_val_t {
            kind: wasm_valkind_enum::WASM_I32 as _,
            of: wasm_val_inner { int32_t: value + 1 },
        });
        None
    }
    unsafe extern "C" fn delete_callback(data: *mut c_void) {
        let data = unsafe { Box::from_raw(data.cast::<Callback>()) };
        let args: wasm_val_vec_t = Vec::<wasm_val_t>::new().into();
        let mut result = result();
        let trap = unsafe { wasm_func_call(Some(&mut *data.survivor), Some(&args), &mut result) };
        if let Some(trap) = trap {
            // Keep an actual error owned until Rust assertions outside C ABI.
            data.final_traps
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(trap);
        } else {
            data.final_value
                .store(unsafe { result.as_slice()[0].of.int32_t }, Ordering::SeqCst);
        }
        data.drops.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn public_c_callback_nested_wasi_timer_restores_ambient_runtime_and_drops_into_live_store() {
        if !owned_child(
            "wasm_c_api::wasi::v8::reentry_tests::public_c_callback_nested_wasi_timer_restores_ambient_runtime_and_drops_into_live_store",
            "WASMER_CAPI_V8_NESTED_WASI_CHILD",
        ) {
            return;
        }
        let (live_engine, mut live_store) = public_store();
        let live_module = module(
            &mut live_store,
            "(module (func (export \"run\") (result i32) i32.const 37))",
        );
        let empty: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        let live_instance = unsafe {
            wasm_instance_new(
                Some(&mut live_store),
                Some(&live_module),
                Some(&empty),
                None,
            )
        }
        .unwrap();
        let mut live_exports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        unsafe {
            wasm_instance_exports(&live_instance, &mut live_exports);
        }
        let mut survivor =
            wasm_func_copy(wasm_extern_as_func(live_exports.as_slice()[0].as_deref()).unwrap());

        let (engine, mut store) = public_store();
        let name = CString::new("nested-v8-wasi").unwrap();
        let config = unsafe { wasi_config_new(name.as_ptr()) }.unwrap();
        let mut env = unsafe { wasi_env_new(Some(&mut store), config) }.unwrap();
        let timer_module = module(
            &mut store,
            r#"(module
            (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                i32.const 0 i64.const 17 i64.store
                i32.const 16 i32.const 1 i32.store
                i32.const 24 i64.const 50000000 i64.store
                i32.const 32 i64.const 1 i64.store
                i32.const 256 i32.const 0 i32.store
                i32.const 0 i32.const 128 i32.const 1 i32.const 256 call $poll if unreachable end
                i32.const 256 i32.load i32.const 1 i32.ne if unreachable end
                i32.const 41))"#,
        );
        let mut imports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        assert!(unsafe {
            wasi_get_imports(
                Some(&store),
                Some(&mut env),
                Some(&timer_module),
                &mut imports,
            )
        });
        let mut timer_instance = unsafe {
            wasm_instance_new(Some(&mut store), Some(&timer_module), Some(&imports), None)
        }
        .unwrap();
        assert!(unsafe { wasi_env_initialize_instance(&mut env, &mut store, &mut timer_instance) });
        let mut timer_exports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        unsafe {
            wasm_instance_exports(&timer_instance, &mut timer_exports);
        }
        let mut timer =
            wasm_func_copy(wasm_extern_as_func(timer_exports.as_slice()[1].as_deref()).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let final_value = Arc::new(AtomicI32::new(0));
        let final_traps = Arc::new(std::sync::Mutex::new(Vec::new()));
        // Borrowed C handles stay actually owned outside the Store allocation;
        // the userdata neither owns a StoreRef nor retains a Store cycle.
        let userdata = Box::into_raw(Box::new(Callback {
            nested: &mut *timer,
            survivor: &mut *survivor,
            calls: calls.clone(),
            drops: drops.clone(),
            final_value: final_value.clone(),
            final_traps: final_traps.clone(),
        }));
        let signature =
            wasm_functype_t::new(wasmer_api::FunctionType::new([], [wasmer_api::Type::I32]));
        let callback = unsafe {
            wasm_func_new_with_env(
                Some(&mut store),
                Some(&signature),
                Some(nested_callback),
                userdata.cast(),
                Some(delete_callback),
            )
        }
        .unwrap();
        let nested_module = module(
            &mut store,
            r#"(module
            (import "host" "nested" (func $nested (result i32)))
            (func $boot call $nested drop) (start $boot)
            (func (export "run") (result i32) call $nested))"#,
        );
        let callback_imports: wasm_extern_vec_t = vec![Some(unsafe {
            wasm_extern_copy(wasm_func_as_extern(Some(&callback)).unwrap())
        })]
        .into();
        let nested_instance = unsafe {
            wasm_instance_new(
                Some(&mut store),
                Some(&nested_module),
                Some(&callback_imports),
                None,
            )
        }
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "actual Wasm start must enter the C callback"
        );
        let mut nested_exports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        unsafe {
            wasm_instance_exports(&nested_instance, &mut nested_exports);
        }
        let mut run =
            wasm_func_copy(wasm_extern_as_func(nested_exports.as_slice()[0].as_deref()).unwrap());
        let driver = store.inner.v8_driver().unwrap();
        let weak_store = store.inner.downgrade();
        let weak_driver = Rc::downgrade(&driver);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let original = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                19
            });
            let before = driver.pending_imports();
            assert_eq!(call(&mut run), 42);
            assert!(
                driver.pending_imports() > before,
                "nested timer import must actually return Pending"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(
                tokio::runtime::Handle::current().runtime_flavor(),
                tokio::runtime::RuntimeFlavor::CurrentThread
            );
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            drop(run);
            drop(nested_exports);
            drop(nested_instance);
            drop(callback_imports);
            drop(nested_module);
            drop(callback);
            drop(timer);
            drop(timer_exports);
            drop(timer_instance);
            drop(imports);
            drop(timer_module);
            wasi_env_delete(Some(env));
            drop(driver);
            drop(store); // actual userdata Drop calls the still-live unrelated S
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            let traps = final_traps.lock().unwrap().drain(..).collect::<Vec<_>>();
            assert!(
                traps.is_empty(),
                "live-Store finalizer reentry trapped: {:?}",
                traps
                    .into_iter()
                    .map(|trap| trap.inner.to_string())
                    .collect::<Vec<_>>()
            );
            assert_eq!(final_value.load(Ordering::SeqCst), 37);
            assert!(weak_store.upgrade().is_none());
            assert!(weak_driver.upgrade().is_none());
            assert_eq!(
                tokio::runtime::Handle::current().runtime_flavor(),
                tokio::runtime::RuntimeFlavor::CurrentThread
            );
            assert_eq!(original.await.unwrap(), 19);
        });
        assert_eq!(call(&mut survivor), 37);
        drop(runtime);
        drop(engine);
        drop(survivor);
        drop(live_exports);
        drop(live_instance);
        drop(live_module);
        drop(empty);
        drop(live_store);
        drop(live_engine);
    }

    #[test]
    fn public_v8_on_called_reborrows_the_checked_store_then_replays_without_a_guard() {
        if !owned_child(
            "wasm_c_api::wasi::v8::reentry_tests::public_v8_on_called_reborrows_the_checked_store_then_replays_without_a_guard",
            "WASMER_CAPI_V8_ON_CALLED_CHILD",
        ) {
            return;
        }
        let (engine, mut store) = public_store();
        let module = module(
            &mut store,
            r#"(module
            (global $calls (mut i32) (i32.const 0))
            (func (export "run") (param i32) (result i32)
                local.get 0 i32.const 29 i32.ne if unreachable end
                global.get $calls i32.const 1 i32.add global.set $calls global.get $calls))"#,
        );
        let imports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        let instance =
            unsafe { wasm_instance_new(Some(&mut store), Some(&module), Some(&imports), None) }
                .unwrap();
        let mut exports: wasm_extern_vec_t = Vec::<Option<Box<wasm_extern_t>>>::new().into();
        unsafe {
            wasm_instance_exports(&instance, &mut exports);
        }
        let mut run =
            wasm_func_copy(wasm_extern_as_func(exports.as_slice()[0].as_deref()).unwrap());
        let target = store
            .inner
            .with_mut(|store| Function::new_typed(store, || 73i32))
            .unwrap();
        let weak = store.inner.downgrade();
        let callbacks = Arc::new(AtomicUsize::new(0));
        let nested_result = Arc::new(AtomicI32::new(0));
        let observed = callbacks.clone();
        let nested_observed = nested_result.clone();
        store
            .inner
            .with_mut(|store| {
                store.on_called(move |mut current| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let nested: Result<Box<[wasmer_api::Value]>, RuntimeError> =
                        current.parked(|| {
                            weak.upgrade()
                                .ok_or_else(|| RuntimeError::new("checked Store expired"))?
                                .with_mut(|checked| target.call(checked, &[]))?
                        });
                    let nested = nested?;
                    nested_observed.store(nested[0].i32().unwrap_or(-1), Ordering::SeqCst);
                    current.on_called(move |_| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(wasmer_types::OnCalledAction::Finish)
                    });
                    Ok(wasmer_types::OnCalledAction::InvokeAgain)
                });
            })
            .unwrap();
        let args: wasm_val_vec_t = vec![wasm_val_t {
            kind: wasm_valkind_enum::WASM_I32 as _,
            of: wasm_val_inner { int32_t: 29 },
        }]
        .into();
        let original_arguments = args.data;
        assert_eq!(
            call_with_args(&mut run, &args),
            2,
            "both physical guest entries must receive the same nonempty argument"
        );
        assert_eq!(args.data, original_arguments);
        assert_eq!(args.size, 1);
        assert_eq!(args.as_slice()[0].kind, wasm_valkind_enum::WASM_I32 as u8);
        assert_eq!(unsafe { args.as_slice()[0].of.int32_t }, 29);
        assert_eq!(callbacks.load(Ordering::SeqCst), 2);
        assert_eq!(nested_result.load(Ordering::SeqCst), 73);
        assert_eq!(
            call_with_args(&mut run, &args),
            3,
            "one-shot callback and actual guard must be gone"
        );
        assert_eq!(args.data, original_arguments);
        assert_eq!(args.size, 1);
        assert_eq!(args.as_slice()[0].kind, wasm_valkind_enum::WASM_I32 as u8);
        assert_eq!(unsafe { args.as_slice()[0].of.int32_t }, 29);
        drop(args);
        drop(run);
        drop(exports);
        drop(instance);
        drop(module);
        drop(imports);
        drop(store);
        drop(engine);
    }
}
