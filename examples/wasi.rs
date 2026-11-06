//! Running a WASI compiled WebAssembly module with Wasmer.
//!
//! This example illustrates how to run WASI modules with
//! Wasmer.
//!
//! If you need more manual control over the instantiation, including custom
//! imports, then check out the ./wasi_manual_setup.rs example.
//!
//! You can run the example directly by executing in Wasmer root:
//!
//! ```shell
//! cargo run --example wasi --release --features "cranelift,wasi"
//! ```
//!
//! Ready?

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use wasixv2::{Machine, ProcessConfig, Stdio, load};

const HELLO_WASI_WAT: &[u8] = br#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\10\00\00\00\0e\00\00\00")
  (data (i32.const 16) "Hello, world!\0a")
  (func (export "_start")
    i32.const 1
    i32.const 0
    i32.const 1
    i32.const 8
    call $fd_write
    drop))
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wasm_bytes = wasmer::wat2wasm(HELLO_WASI_WAT)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _guard = runtime.enter();
    let machine = Machine::new();
    let engine = wasmer::Engine::default();

    println!("Compiling module...");
    let module = load(&engine, &wasm_bytes)?;
    let output = Arc::new(Mutex::new(Vec::new()));
    let captured = output.clone();
    let stdio = Stdio::from_fns(
        move |bytes| captured.lock().unwrap().extend_from_slice(bytes),
        |bytes| std::io::stderr().write_all(bytes).unwrap(),
    );

    println!("Running module...");
    let status = runtime.block_on(machine.run_module(
        &engine,
        &module,
        ProcessConfig {
            args: vec!["hello".into()],
            env: vec![],
            stdio,
        },
    ))?;
    assert_eq!(status, 0);

    println!("Run complete - reading output");
    let buf = String::from_utf8(output.lock().unwrap().clone())?;
    println!("Output: {buf}");
    assert_eq!(buf, "Hello, world!\n");
    Ok(())
}

#[test]
#[cfg(feature = "wasi")]
fn test_wasi() -> Result<(), Box<dyn std::error::Error>> {
    main()
}
