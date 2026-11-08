//! Running a WASI compiled WebAssembly module with Wasmer.
//!
//! This example adds custom imports and instance setup to the common WASI runner:
//!
//!   1. Register an instantiation hook alongside the canonical WASI imports.
//!   2. Configure the actual instance before its WASI entry runs.
//!   3. Let the Machine own execution and release the attachment afterward.
//!
//! You can run the example directly by executing in Wasmer root:
//!
//! ```shell
//! cargo run --example wasi-manual-setup --release --features "cranelift,tokio,wasi"
//! ```
//!
//! Ready?

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use wasixv2::{
    ExecEnv, InstanceAttachment, InstantiationHook, Machine, MachineSyscalls, ProcessConfig, Stdio,
    load,
};
use wasmer::{
    Function, FunctionEnv, Imports, Instance, Memory, Module, RuntimeError, StoreMut, wat2wasm,
};

const HELLO_WASI_WAT: &[u8] = br#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "host" "answer" (func $answer (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\10\00\00\00\0e\00\00\00")
  (data (i32.const 16) "Hello, world!\0a")
  (func (export "_start")
    call $answer
    i32.const 42
    i32.ne
    if unreachable end
    i32.const 1
    i32.const 0
    i32.const 1
    i32.const 8
    call $fd_write
    drop))
"#;

struct Setup(Arc<AtomicUsize>);

impl InstantiationHook<MachineSyscalls> for Setup {
    fn provides_import(&self, namespace: &str, name: &str) -> bool {
        namespace == "host" && name == "answer"
    }

    fn prepare_imports(
        &self,
        _: &Module,
        store: &mut StoreMut<'_>,
        _: &FunctionEnv<ExecEnv<MachineSyscalls>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        println!("Adding custom imports alongside WASI...");
        let phase = self.0.clone();
        imports.define(
            "host",
            "answer",
            Function::new_typed(store, move || {
                if phase.load(Ordering::SeqCst) == 1 {
                    42i32
                } else {
                    -1
                }
            }),
        );
        Ok(Some(Box::new(Setup(self.0.clone()))))
    }
}

impl InstanceAttachment for Setup {
    fn configure(
        &mut self,
        _: &Module,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        println!("Configuring the actual instance and its WASI memory...");
        assert!(memory.is_from_store(store));
        instance
            .exports
            .get_function("_start")
            .map_err(|error| RuntimeError::new(error.to_string()))?;
        self.0.store(1, Ordering::SeqCst);
        Ok(())
    }

    fn deactivate(&mut self, _: &mut StoreMut<'_>) {
        self.0.store(2, Ordering::SeqCst);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wasm_bytes = wat2wasm(HELLO_WASI_WAT)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let phase = Arc::new(AtomicUsize::new(0));
    let machine = Machine::builder()
        .instantiation_hook(Arc::new(Setup(phase.clone())))
        .build();
    let engine = wasmer::Engine::default();
    let module = load(&engine, &wasm_bytes)?;
    let output = Arc::new(Mutex::new(Vec::new()));
    let captured = output.clone();
    let stdio = Stdio::from_fns(
        move |bytes| captured.lock().unwrap().extend_from_slice(bytes),
        |bytes| eprint!("{}", String::from_utf8_lossy(bytes)),
    );
    let status = runtime.block_on(tokio::task::LocalSet::new().run_until(machine.run_module(
        &engine,
        &module,
        ProcessConfig {
            args: vec!["hello".into()],
            env: vec![],
            stdio,
        },
    )))?;
    assert_eq!(status, 0);
    assert_eq!(phase.load(Ordering::SeqCst), 2);
    let output = output.lock().unwrap();
    assert_eq!(output.as_slice(), b"Hello, world!\n");
    print!("{}", String::from_utf8_lossy(&output));

    Ok(())
}

#[test]
#[cfg(feature = "wasi")]
fn test_wasi() -> Result<(), Box<dyn std::error::Error>> {
    main()
}
