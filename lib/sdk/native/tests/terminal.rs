//! Canonical-console replacement for the recovered TerminalBridge behavior proof.
//! The ioctl/read/write fixture follows lib/wasix/api/tests/console.rs.
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use wasmer_sdk::{CacheConfig, PackageSource, Result, TerminalOptions, Wasmer, WasmerConfig};
const TERMINAL_WAT: &str = r#"
(module
  (import "wasixv2" "read" (func $read (param i32 i32 i32)(result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32)(result i32)))
  (import "wasixv2" "ioctl" (func $ioctl (param i32 i32 i32)(result i32)))
  (import "wasixv2" "exit_group" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "ready\nraw\n")
  (func $check (param $bad i32)
    (if(local.get $bad)(then(call $exit(i32.const 99)))))
  (func (export "_start") (local $n i32)
    ;; Every stdio descriptor is a terminal, with the requested initial size.
    (call $check(call $ioctl(i32.const 0)(i32.const 0x5413)(i32.const 136)))
    (call $check(i32.ne(i32.load16_u(i32.const 136))(i32.const 40)))
    (call $check(i32.ne(i32.load16_u(i32.const 138))(i32.const 120)))
    (call $check(call $ioctl(i32.const 1)(i32.const 0x5413)(i32.const 136)))
    (call $check(call $ioctl(i32.const 2)(i32.const 0x5413)(i32.const 136)))
    (call $check(call $ioctl(i32.const 0)(i32.const 0x5401)(i32.const 200)))
    (call $check(i32.ne(i32.and(i32.load(i32.const 212))(i32.const 10))(i32.const 10)))
    (drop(call $write(i32.const 1)(i32.const 16)(i32.const 6)))
    (local.set $n(call $read(i32.const 0)(i32.const 64)(i32.const 32)))
    (drop(call $write(i32.const 1)(i32.const 64)(local.get $n)))
    ;; Disable ECHO and ICANON through the guest; a single byte must now arrive
    ;; without a newline and must appear exactly once (the guest's own write).
    (i32.store(i32.const 212)(i32.and(i32.load(i32.const 212))(i32.const -11)))
    (call $check(call $ioctl(i32.const 0)(i32.const 0x5402)(i32.const 200)))
    (drop(call $write(i32.const 1)(i32.const 22)(i32.const 4)))
    (local.set $n(call $read(i32.const 0)(i32.const 64)(i32.const 1)))
    (call $check(i32.ne(local.get $n)(i32.const 1)))
    (drop(call $write(i32.const 1)(i32.const 64)(local.get $n)))
    (call $check(call $ioctl(i32.const 0)(i32.const 0x5413)(i32.const 136)))
    (call $check(i32.ne(i32.load16_u(i32.const 138))(i32.const 90)))
    (call $exit(i32.load16_u(i32.const 136)))unreachable))
"#;
#[tokio::test(flavor = "multi_thread")]
async fn guest_terminal_updates_drive_the_line_discipline() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let state = tempfile::TempDir::new()?;
        let client = Wasmer::with_config(WasmerConfig {
            cache: CacheConfig {
                root: state.path().join("cache"),
            },
            output_bytes: 1024,
        })?;
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(wat::parse_str(TERMINAL_WAT).unwrap()))
            .await?;
        let mut process = sandbox
            .command("main")
            .terminal(TerminalOptions::new(120, 40))
            .spawn()
            .await?;
        let mut keyboard = process.take_stdin().unwrap();
        let mut screen = BufReader::new(process.take_stdout().unwrap());
        let mut shown = Vec::new();
        screen.read_until(b'\n', &mut shown).await?;
        assert_eq!(shown, b"ready\r\n");
        process.resize_terminal(90, 30)?;
        keyboard.write_all(b"hix\x7f\r").await?;
        while !shown.ends_with(b"raw\r\n") {
            screen.read_until(b'\n', &mut shown).await?;
        }
        keyboard.write_all(b"z").await?;
        let (result, output) = tokio::join!(screen.read_to_end(&mut shown), process.wait());
        result?;
        let output = output?;
        assert_eq!(output.status.code(), 30);
        assert_eq!(shown, b"ready\r\nhix\x08 \x08\r\nhi\r\nraw\r\nz");
        assert_eq!(output.stdout.bytes(), shown);
        client.shutdown().await?;
        Ok(())
    })
    .await
    .expect("SDK terminal guest made progress")
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_output_capture_exceeds_the_live_pipe_bound_without_a_reader() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let state = tempfile::TempDir::new()?;
        let client = Wasmer::with_config(WasmerConfig {
            cache: CacheConfig {
                root: state.path().join("cache"),
            },
            output_bytes: 1024,
        })?;
        let bytes = wat::parse_str(
            r#"(module
            (import "wasixv2" "write" (func $write(param i32 i32 i32)(result i32)))
            (memory(export "memory")1)
            (data(i32.const 16)"abcdefghijklmnopqrstuvwxyz0123456789\n")
            (func(export "_start")
              (drop(call $write(i32.const 1)(i32.const 16)(i32.const 37)))))"#,
        )
        .unwrap();
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(bytes))
            .await?;
        let output = sandbox
            .command("main")
            .terminal(TerminalOptions::default())
            .stream_bytes(16)
            .output()
            .await?;
        assert!(output.ok());
        assert_eq!(
            output.stdout.bytes(),
            b"abcdefghijklmnopqrstuvwxyz0123456789\r\n"
        );
        client.shutdown().await?;
        Ok(())
    })
    .await
    .expect("terminal capture must not depend on an unread live pipe")
}
