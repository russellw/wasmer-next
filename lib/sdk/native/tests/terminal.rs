//! Canonical-console replacement for the recovered TerminalBridge behavior proof.
//! The ioctl/read/write fixture follows lib/wasix/api/tests/console.rs.
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use wasmer_sdk::{
    CacheConfig, ExitReason, PackageSource, Result, Stdio, TerminalOptions, Wasmer, WasmerConfig,
};
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
            (import "wasixv2" "exit_group" (func $exit(param i32)))
            (memory(export "memory")1)
            (data(i32.const 16)"abcdefghijklmnopqrstuvwxyz0123456789\n")
            (func(export "_start")
              (drop(call $write(i32.const 1)(i32.const 16)(i32.const 37)))
              (call $exit(i32.const 0))))"#,
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

// Like TERMINAL_WAT, use the guest's real read/write path. A second read proves
// persistent finite EOF rather than one injected VEOF character or SIGHUP.
const FINITE_CANONICAL_WAT: &str = r#"
(module
  (import "wasixv2" "read" (func $read(param i32 i32 i32)(result i32)))
  (import "wasixv2" "write" (func $write(param i32 i32 i32)(result i32)))
  (import "wasixv2" "exit_group" (func $exit(param i32)))
  (memory(export "memory")1)
  (data(i32.const 16)"read:\nerr\n")
  (func(export "_start") (local $n i32)
    (local.set $n(call $read(i32.const 0)(i32.const 64)(i32.const 128)))
    (if(i32.lt_s(local.get $n)(i32.const 0))(then(call $exit(i32.const 99))))
    (drop(call $write(i32.const 1)(i32.const 16)(i32.const 5)))
    (drop(call $write(i32.const 1)(i32.const 64)(local.get $n)))
    (drop(call $write(i32.const 1)(i32.const 21)(i32.const 1)))
    (drop(call $write(i32.const 2)(i32.const 22)(i32.const 4)))
    (if(call $read(i32.const 0)(i32.const 256)(i32.const 1))
      (then(call $exit(i32.const 99))))
    (call $exit(i32.const 0))))
"#;

#[tokio::test(flavor = "multi_thread")]
async fn finite_terminal_input_delivers_empty_and_partial_canonical_lines() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let state = tempfile::TempDir::new()?;
        let client = terminal_client(&state)?;
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(
                wat::parse_str(FINITE_CANONICAL_WAT).unwrap(),
            ))
            .await?;
        let partial = b"partial canonical input beyond sixteen bytes";
        assert!(partial.len() > 16);
        for input in [b"".as_slice(), partial.as_slice()] {
            let output = sandbox
                .command("main")
                .terminal(TerminalOptions::default())
                .stream_bytes(16)
                .input(input.to_vec())
                .output()
                .await?;
            assert_eq!(output.reason, ExitReason::Exited);
            assert_eq!(output.status.code(), 0);
            assert!(!output.stdout.truncated());
            assert!(!output.stderr.truncated());
            // Canonical echo precedes the guest's explicitly prefixed copy.
            assert_eq!(
                output.stdout.bytes(),
                [input, b"read:", input, b"\r\n"].concat()
            );
            assert_eq!(output.stderr.bytes(), b"err\r\n");
        }
        sandbox.close().await?;
        client.shutdown().await?;
        Ok(())
    })
    .await
    .expect("finite empty and partial canonical terminal input must finish")
}

const RAW_VMIN_WAT: &str = r#"
(module
  (import "wasixv2" "read" (func $read(param i32 i32 i32)(result i32)))
  (import "wasixv2" "write" (func $write(param i32 i32 i32)(result i32)))
  (import "wasixv2" "ioctl" (func $ioctl(param i32 i32 i32)(result i32)))
  (import "wasixv2" "exit_group" (func $exit(param i32)))
  (memory(export "memory")1)
  (data(i32.const 16)"ready\nraw:\nerr\n")
  (func $check(param $bad i32)
    (if(local.get $bad)(then(call $exit(i32.const 99)))))
  (func(export "_start") (local $n i32)
    (call $check(call $ioctl(i32.const 0)(i32.const 0x5401)(i32.const 200)))
    ;; Linux Termios: c_lflag at +12, c_cc at +17; VTIME=5 and VMIN=6.
    (i32.store(i32.const 212)(i32.and(i32.load(i32.const 212))(i32.const -11)))
    (i32.store8(i32.const 222)(i32.const 0))
    (i32.store8(i32.const 223)(i32.const 4))
    (call $check(call $ioctl(i32.const 0)(i32.const 0x5402)(i32.const 200)))
    (drop(call $write(i32.const 1)(i32.const 16)(i32.const 6)))
    (drop(call $write(i32.const 2)(i32.const 27)(i32.const 4)))
    (local.set $n(call $read(i32.const 0)(i32.const 64)(i32.const 32)))
    (call $check(i32.lt_s(local.get $n)(i32.const 0)))
    (drop(call $write(i32.const 1)(i32.const 22)(i32.const 4)))
    (drop(call $write(i32.const 1)(i32.const 64)(local.get $n)))
    (drop(call $write(i32.const 1)(i32.const 26)(i32.const 1)))
    (call $check(call $read(i32.const 0)(i32.const 128)(i32.const 1)))
    (call $exit(i32.const 0))))
"#;

#[tokio::test(flavor = "multi_thread")]
async fn raw_terminal_vmin_keeps_finite_eof_and_cancel_distinct() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let state = tempfile::TempDir::new()?;
        let client = terminal_client(&state)?;
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(wat::parse_str(RAW_VMIN_WAT).unwrap()))
            .await?;
        let mut completed = Vec::new();
        // A canceled private terminal must not poison the next run in this sandbox.
        for canceled in [true, false] {
            let mut process = sandbox
                .command("main")
                .terminal(TerminalOptions::default())
                .stream_bytes(16)
                .stderr(Stdio::Capture)
                .spawn()
                .await?;
            let mut keyboard = process.take_stdin().unwrap();
            let mut screen = BufReader::new(process.take_stdout().unwrap());
            let mut shown = Vec::new();
            screen.read_until(b'\n', &mut shown).await?;
            assert_eq!(shown, b"ready\r\n");
            // The guest set raw mode before announcing readiness, so input cannot
            // race the initial canonical ECHO setting. Three bytes cannot meet VMIN=4.
            keyboard.write_all(b"abc").await?;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), process.wait())
                    .await
                    .is_err(),
                "VMIN=4 must keep three bytes pending while the source is open"
            );
            if canceled {
                process.kill()?;
            } else {
                keyboard.close().await?;
            }
            let (read, output) = tokio::join!(screen.read_to_end(&mut shown), process.wait());
            read?;
            let output = output?;
            if canceled {
                assert_eq!(output.reason, ExitReason::Terminated);
                assert_eq!(output.status.code(), 137);
                assert_eq!(shown, b"ready\r\n");
            } else {
                assert_eq!(output.reason, ExitReason::Exited);
                assert_eq!(output.status.code(), 0);
                assert_eq!(shown, b"ready\r\nraw:abc\r\n");
            }
            assert_eq!(output.stdout.bytes(), shown);
            assert_eq!(output.stderr.bytes(), b"err\r\n");
            assert!(!output.stdout.truncated());
            assert!(!output.stderr.truncated());
            drop(keyboard);
            assert_eq!(process.wait().await?, output);
            completed.push((process, output));
        }
        sandbox.close().await?;
        client.shutdown().await?;
        for (mut process, output) in completed {
            assert_eq!(process.wait().await?, output);
        }
        Ok(())
    })
    .await
    .expect("raw VMIN terminal EOF and cancellation must retire their runs")
}

fn terminal_client(state: &tempfile::TempDir) -> Result<Wasmer> {
    Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().join("cache"),
        },
        output_bytes: 1024,
    })
}
