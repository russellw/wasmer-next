//! Store-local C API bindings for the WASIX v2 execution lifecycle.

use wasixv2_exec::{ExecEnv, InstanceAttachment, InstantiationHook};
use wasmer_api::{FunctionEnv, Imports, Instance, Memory, Module, RuntimeError, StoreMut};

use crate::{WasmCapiRuntimeHooks, WasmCapiSession, provides_wasm_c_api_import};

impl<S: 'static> InstantiationHook<S> for WasmCapiRuntimeHooks {
    fn provides_import(&self, namespace: &str, name: &str) -> bool {
        provides_wasm_c_api_import(namespace, name)
    }

    fn prepare_imports(
        &self,
        module: &Module,
        store: &mut StoreMut<'_>,
        _env: &FunctionEnv<ExecEnv<S>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        let state = self
            .add_imports(module, store, imports)
            .map_err(|error| RuntimeError::user(error.into()))?;
        Ok(state
            .session
            .map(|session| Box::new(Attachment(session)) as Box<dyn InstanceAttachment>))
    }
}

struct Attachment(WasmCapiSession);

impl InstanceAttachment for Attachment {
    fn configure(
        &mut self,
        _module: &Module,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        self.0
            .configure_instance(store, instance, Some(memory))
            .map_err(|error| RuntimeError::user(error.into()))
    }

    fn deactivate(&mut self, store: &mut StoreMut<'_>) {
        self.0.deactivate(store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::wasixv2::{Machine, ProcessConfig, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wasmer_api::{AsStoreMut, Function, Store};

    #[tokio::test]
    async fn original_wasix_c_api_guest_runs_on_v2() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let engine = wasmer_api::Engine::default();
                let calls = Arc::new(AtomicUsize::new(0));
                let hooks = WasmCapiRuntimeHooks::new().with_resolve_module_sync({
                    let calls = calls.clone();
                    move |bytes| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(Module::new(&engine, bytes)?)
                    }
                });
                let machine = Machine::builder()
                    .instantiation_hook(Arc::new(hooks))
                    .build();
                let wasm = wat::parse_str(crate::tests::WASIX_GUEST).unwrap();
                for _ in 0..2 {
                    assert_eq!(machine.run_process(&wasm, config()).await.unwrap(), 0);
                }
                assert_eq!(calls.load(Ordering::SeqCst), 2);
            })
            .await;
    }

    fn config() -> ProcessConfig {
        ProcessConfig {
            args: vec!["wasm-c-api".into()],
            env: vec![],
            stdio: Stdio::from_fns(|_| {}, |_| {}),
        }
    }

    #[tokio::test]
    async fn imported_memory_is_bound_before_engine_start() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let machine = Machine::builder()
                    .instantiation_hook(Arc::new(WasmCapiRuntimeHooks::new()))
                    .build();
                let wasm = wat::parse_str(
                    r#"(module
                (import "env" "memory" (memory 1 1))
                (import "wasm_c_api_v0" "wasm_byte_vec_new" (func $new (param i32 i32 i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
                (data (i32.const 16) "\ff\ff\ff\ff\ff\ff\ff\ff")
                (func $init (call $new (i32.const 16) (i32.const 0) (i32.const 0)))
                (start $init)
                (func (export "_start")
                    (call $exit (i32.or (i32.load (i32.const 16)) (i32.load (i32.const 20))))))"#,
                )
                .unwrap();
                assert_eq!(machine.run_process(&wasm, config()).await.unwrap(), 0);
            })
            .await;
    }

    #[test]
    fn declarations_match_registered_imports() {
        let mut store = Store::default();
        let module = Module::new(
            &store,
            r#"(module
            (import "wasm_c_api_v0" "wasm_engine_new" (func (result i32))))"#,
        )
        .unwrap();
        let (imports, _) = WasmCapiRuntimeHooks::new()
            .additional_imports(&module, &mut store.as_store_mut())
            .unwrap();
        for ((namespace, name), _) in imports.into_iter() {
            assert!(provides_wasm_c_api_import(&namespace, &name));
        }
        assert!(!provides_wasm_c_api_import(
            "wasm_c_api_v1",
            "wasm_engine_new"
        ));
        assert!(!provides_wasm_c_api_import("wasm_c_api_v0", "missing"));
    }

    #[test]
    fn partial_preparation_releases_resolver_roots() {
        let mut store = Store::default();
        let module = Module::new(
            &store,
            r#"(module
            (import "env" "memory" (memory 1))
            (import "wasm_c_api_v0" "wasm_engine_new" (func (result i32))))"#,
        )
        .unwrap();
        let root = Arc::new(());
        let hooks = WasmCapiRuntimeHooks::new().with_resolve_module_sync({
            let root = root.clone();
            move |_| {
                let _ = &root;
                anyhow::bail!("unused")
            }
        });
        let mut imports = Imports::new();
        imports.define("env", "memory", Function::new_typed(&mut store, || {}));
        assert!(
            hooks
                .add_imports(&module, &mut store.as_store_mut(), &mut imports)
                .is_err()
        );
        drop(hooks);
        assert_eq!(Arc::strong_count(&root), 1);
    }

    #[test]
    fn deactivation_clears_configured_and_partial_state() {
        let mut store = Store::default();
        let module = Module::new(
            &store,
            r#"(module
            (import "env" "memory" (memory 1))
            (import "wasm_c_api_v0" "wasm_engine_new" (func (result i32)))
            (export "memory" (memory 0))
            (func (export "malloc") (param i32) (result i32) i32.const 64)
            (func (export "free") (param i32)))"#,
        )
        .unwrap();
        for configure in [false, true] {
            let hooks = WasmCapiRuntimeHooks::new();
            let (imports, state) = hooks
                .additional_imports(&module, &mut store.as_store_mut())
                .unwrap();
            let mut attachment = Attachment(state.session.unwrap());
            let env = attachment.0.func_env().unwrap().unwrap();
            if configure {
                let instance = Instance::new(&mut store, &module, &imports).unwrap();
                let memory = instance.exports.get_memory("memory").unwrap();
                attachment
                    .configure(&module, &mut store.as_store_mut(), &instance, memory)
                    .unwrap();
                assert!(env.as_ref(&store).malloc_fn.is_some());
            }
            env.as_mut(&mut store)
                .state
                .insert(crate::WasmObject::Engine);
            attachment.deactivate(&mut store.as_store_mut());
            attachment.deactivate(&mut store.as_store_mut());
            let data = env.as_ref(&store);
            assert!(data.state.objects.is_empty());
            assert!(data.state.memory_shadows.is_empty());
            assert!(data.memory.is_none());
            assert!(data.table.is_none());
            assert!(data.malloc_fn.is_none());
            assert!(data.free_fn.is_none());
            assert!(data.func_env.is_none());
            assert!(data.resolve_module_sync.is_none());
        }
    }
}
