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
            wasm_extern_as_memory, wasm_extern_vec_t, wasm_func_call, wasm_memory_copy,
            wasm_memory_data,
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
                i32.const 37))"#).unwrap().into();
        let module = unsafe { wasm_module_new(Some(&mut store), Some(&guest)) }.unwrap();
        let mut imports = wasm_extern_vec_t::default();
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
        let mut exports = wasm_extern_vec_t::default();
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
        let args = wasm_val_vec_t::default();
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
