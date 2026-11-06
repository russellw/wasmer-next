//! Piping to and from a WASI compiled WebAssembly module with Wasmer.
//!
//! This example builds on the WASI example, showing how you can pipe to and
//! from a WebAssembly module.
//!
//! You can run the example directly by executing in Wasmer root:
//!
//! ```shell
//! cargo run --example wasi-pipes --release --features "cranelift,tokio,backend,wasi"
//! ```
//!
//! Ready?

use std::{
    io::{Read, Write, pipe},
    sync::{Arc, Mutex},
};

use wasixv2::{BlockingSource, Machine, ProcessConfig, Stdio, load};

const REVERSE_WASI_WAT: &[u8] = br#"
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\20\00\00\00\60\00\00\00")
  (data (i32.const 8) "\80\00\00\00\00\00\00\00")
  (func (export "_start")
    (local $n i32)
    (local $i i32)
    i32.const 0
    i32.const 0
    i32.const 1
    i32.const 16
    call $fd_read
    drop
    i32.const 16
    i32.load
    local.set $n
    local.get $n
    i32.const 0
    i32.gt_u
    i32.const 31
    local.get $n
    i32.add
    i32.load8_u
    i32.const 10
    i32.eq
    i32.and
    if
      local.get $n
      i32.const 1
      i32.sub
      local.set $n
    end
    block $done
      loop $copy
        local.get $i
        local.get $n
        i32.ge_u
        br_if $done
        i32.const 128
        local.get $i
        i32.add
        i32.const 32
        local.get $n
        i32.add
        i32.const 1
        i32.sub
        local.get $i
        i32.sub
        i32.load8_u
        i32.store8
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $copy
      end
    end
    i32.const 12
    local.get $n
    i32.store
    i32.const 1
    i32.const 8
    i32.const 1
    i32.const 20
    call $fd_write
    drop))
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wasm_bytes = wasmer::wat2wasm(REVERSE_WASI_WAT)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _guard = runtime.enter();
    let machine = Machine::new();
    let engine = wasmer::Engine::default();

    println!("Compiling module...");
    let module = load(&engine, &wasm_bytes)?;

    let msg = "racecar go zoom";
    println!("Writing \"{msg}\" to the WASI stdin...");
    let (stdin_reader, mut stdin_writer) = pipe()?;
    let (mut stdout_reader, stdout_writer) = pipe()?;
    writeln!(stdin_writer, "{msg}")?;
    drop(stdin_writer);
    let captured = Mutex::new(stdout_writer);
    let mut stdio = Stdio::from_fns(
        move |bytes| captured.lock().unwrap().write_all(bytes).unwrap(),
        |bytes| std::io::stderr().write_all(bytes).unwrap(),
    );
    // BlockingSource adapts a host reader without blocking the guest executor.
    stdio.stdin = Arc::new(BlockingSource::new(stdin_reader));

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
    // Release the guest streams before reading the pipe through end of stream.
    drop(machine);
    let mut buf = String::new();
    stdout_reader.read_to_string(&mut buf)?;
    println!("Read \"{}\" from the WASI stdout!", buf.trim());
    assert_eq!(buf.trim(), "mooz og racecar");
    Ok(())
}

#[test]
#[cfg(feature = "wasi")]
fn test_wasi() -> Result<(), Box<dyn std::error::Error>> {
    main()
}
