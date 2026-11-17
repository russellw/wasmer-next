//! Threads, futexes, signals, processes and the terminal of WASIX v1 guests, hand-written in
//! WAT, run on a `wasixv2::Machine`. Each guest reports through its exit status: 0, or the
//! number of the check that failed.

#![recursion_limit = "256"]

use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use wasixv2::{
    ByteSink, ByteSource, Console, EmptySource, LocalFuture, Machine, ProcessConfig, Stdio,
    WindowSize,
};

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

/// Runs `wat`, with the host directory `programs` at `/prog` if given; returns its exit status
/// and stdout.
fn run(wat: &str, programs: Option<&Path>) -> (i32, Vec<u8>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let machine = Machine::new();
        if let Some(dir) = programs {
            machine.mount_host_dir("/prog", dir, false).await.unwrap();
        }
        let stdout = Arc::new(Capture::default());
        let config = ProcessConfig {
            args: vec!["test".to_string()],
            env: vec!["GREETING=hi".to_string()],
            stdio: Stdio {
                stdin: Arc::new(EmptySource),
                stdout: stdout.clone(),
                stderr: Arc::new(Capture::default()),
            },
        };
        let wasm = wat::parse_str(wat).unwrap();
        let status = machine.run_process(&wasm, config).await.unwrap();
        let out = stdout.0.lock().unwrap().clone();
        (status, out)
    })
}

fn status(wat: &str) -> i32 {
    run(wat, None).0
}

/// A host directory with `programs` compiled from WAT, removed on drop.
struct Programs(PathBuf);

impl Programs {
    fn new(name: &str, programs: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!("wasix1-proc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (file, wat) in programs {
            let path = dir.join(file);
            std::fs::write(&path, wat::parse_str(wat).unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        Self(dir)
    }
}

impl Drop for Programs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Signals reach `__wasm_signal` once libc named it, are held back while it names something
/// it does not export, and are delivered when it names the callback again. Signals whose
/// default is to be ignored are not delivered.
const SIGNALS: &str = r#"
(module
  (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
  (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
  (import "wasix_32v1" "thread_signal" (func $thread_signal (param i32 i32) (result i32)))
  (import "wasix_32v1" "proc_signal" (func $proc_signal (param i32 i32) (result i32)))
  (import "wasix_32v1" "thread_id" (func $thread_id (param i32) (result i32)))
  (import "wasix_32v1" "proc_id" (func $proc_id (param i32) (result i32)))
  (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "__wasm_signal")
  (data (i32.const 48) "__wasm_signal_blocked")
  (global $count (mut i32) (i32.const 0))
  (global $last (mut i32) (i32.const 0))
  (func (export "__wasm_signal") (param $sig i32)
    (global.set $count (i32.add (global.get $count) (i32.const 1)))
    (global.set $last (local.get $sig)))
  (func $deliver (call $callback (i32.const 16) (i32.const 13)))
  (func $hold (call $callback (i32.const 48) (i32.const 21)))
  (func (export "_start")
    (call $deliver)
    (if (call $raise (i32.const 10)) (then (call $exit (i32.const 1))))
    (if (i32.ne (global.get $last) (i32.const 10)) (then (call $exit (i32.const 2))))
    ;; held back until the callback is named again
    (call $hold)
    (if (call $raise (i32.const 12)) (then (call $exit (i32.const 3))))
    (if (i32.ne (global.get $count) (i32.const 1)) (then (call $exit (i32.const 4))))
    (call $deliver)
    (if (i32.ne (global.get $last) (i32.const 12)) (then (call $exit (i32.const 5))))
    ;; to the calling thread by tid, and to the process
    (drop (call $thread_id (i32.const 0)))
    (if (call $thread_signal (i32.load (i32.const 0)) (i32.const 2)) (then (call $exit (i32.const 6))))
    (if (i32.ne (global.get $last) (i32.const 2)) (then (call $exit (i32.const 7))))
    (drop (call $proc_id (i32.const 4)))
    (if (call $proc_signal (i32.load (i32.const 4)) (i32.const 15)) (then (call $exit (i32.const 8))))
    (if (i32.ne (global.get $last) (i32.const 15)) (then (call $exit (i32.const 9))))
    ;; SIGCHLD keeps its default: ignored
    (if (call $raise (i32.const 17)) (then (call $exit (i32.const 10))))
    (if (i32.ne (global.get $count) (i32.const 4)) (then (call $exit (i32.const 11))))
    (call $exit (i32.const 0))))
"#;

#[test]
fn signals() {
    assert_eq!(status(SIGNALS), 0);
}

/// V1 mapped a failing registered signal callback to exit(INTR), not a fatal
/// execution fault. Older libc's corrupted/default handler indices hit this path.
#[test]
fn trapping_signal_callback_exits_with_the_legacy_status() {
    assert_eq!(
        status(
            r#"(module
      (type $handler (func (param i32)))
      (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
      (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
      (memory (export "memory") 1)
      (table 1 funcref)
      (data (i32.const 16) "__wasm_signal")
      (func (export "__wasm_signal") (param $sig i32)
        (call_indirect (type $handler) (local.get $sig) (i32.const 100)))
      (func (export "_start")
        (call $callback (i32.const 16) (i32.const 13))
        (drop (call $raise (i32.const 15)))
        unreachable))"#
        ),
        27
    );
}

#[test]
fn signal_callback_syscall_exit_preserves_its_status() {
    assert_eq!(
        status(
            r#"(module
      (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 16) "__wasm_signal")
      (func (export "__wasm_signal") (param i32) (call $exit (i32.const 23)))
      (func (export "_start")
        (call $callback (i32.const 16) (i32.const 13))
        (drop (call $raise (i32.const 15)))
        unreachable))"#
        ),
        23
    );
}

/// An exported callback is a capability, not a registration on a fresh pthread.
/// v1 discarded sibling copies of process signals in such instances.
#[test]
fn fresh_thread_does_not_run_an_unregistered_signal_callback() {
    assert_eq!(
        status(
            r#"(module
      (import "env" "memory" (memory 1 1 shared))
      (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
      (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
      (import "wasix_32v1" "thread_signal" (func $signal (param i32 i32) (result i32)))
      (import "wasix_32v1" "thread_join" (func $join (param i32) (result i32)))
      (import "wasi_snapshot_preview1" "sched_yield" (func $yield (result i32)))
      (data (i32.const 16) "__wasm_signal")
      (func (export "__wasm_signal") (param i32) unreachable)
      (func (export "wasi_thread_start") (param i32 i32)
        (i32.atomic.store (i32.const 200) (i32.const 1))
        (loop $wait
          (br_if $wait (i32.eqz (i32.atomic.load (i32.const 204)))))
        (drop (call $yield)))
      (func (export "_start")
        (call $callback (i32.const 16) (i32.const 13))
        (if (call $spawn (i32.const 100) (i32.const 104)) (then unreachable))
        (loop $ready (br_if $ready (i32.eqz (i32.atomic.load (i32.const 200)))))
        (if (call $signal (i32.load (i32.const 104)) (i32.const 15)) (then unreachable))
        (i32.atomic.store (i32.const 204) (i32.const 1))
        (if (call $join (i32.load (i32.const 104))) (then unreachable))))"#
        ),
        0
    );
}

/// wasix-libc before v2026-07-30.1 holds signals back in `pthread_create` and never ends the
/// hold (its `__restore_sigs` is compiled out). The spawn ends it, for the creating thread and
/// the new one: both still take signals afterwards.
const SPAWN_HOLD: &str = r#"
(module
  (import "env" "memory" (memory 1 1 shared))
  (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
  (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
  (import "wasix_32v1" "thread_signal" (func $thread_signal (param i32 i32) (result i32)))
  (import "wasix_32v1" "futex_wait" (func $wait (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
  (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
  (data (i32.const 16) "__wasm_signal")
  (data (i32.const 48) "__wasm_signal_blocked")
  ;; The signals each thread took, at 200 (main) and 204 (the thread).
  (func (export "__wasm_signal") (param $sig i32)
    (i32.store (i32.const 200) (local.get $sig)))
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    (i32.atomic.store (i32.const 208) (local.get $tid))
    (drop (memory.atomic.notify (i32.const 208) (i32.const 1)))
    ;; Like v1, an instance must register its callback before it can run a handler.
    (call $callback (i32.const 16) (i32.const 13))
    ;; Waits until the main thread signalled it; the handler's mark is the proof.
    (block $done
      (loop $again
        (br_if $done (i32.load (i32.const 200)))
        (drop (call $wait (i32.const 212) (i32.const 0) (i32.const 0) (i32.const 300)))
        (br $again)))
    (i32.atomic.store (i32.const 204) (i32.load (i32.const 200)))
    (drop (memory.atomic.notify (i32.const 204) (i32.const 1))))
  (func (export "_start")
    (call $callback (i32.const 16) (i32.const 13))
    ;; pthread_create's hold, then the spawn
    (call $callback (i32.const 48) (i32.const 21))
    (if (call $spawn (i32.const 100) (i32.const 104)) (then (call $exit (i32.const 1))))
    (if (call $raise (i32.const 10)) (then (call $exit (i32.const 2))))
    (if (i32.ne (i32.load (i32.const 200)) (i32.const 10)) (then (call $exit (i32.const 3))))
    (i32.store (i32.const 200) (i32.const 0))
    ;; the thread takes SIGUSR2
    (block $started
      (loop $again
        (br_if $started (i32.atomic.load (i32.const 208)))
        (drop (memory.atomic.wait32 (i32.const 208) (i32.const 0) (i64.const 1000000)))
        (br $again)))
    (if (call $thread_signal (i32.atomic.load (i32.const 208)) (i32.const 12)) (then (call $exit (i32.const 4))))
    (block $taken
      (loop $again
        (br_if $taken (i32.atomic.load (i32.const 204)))
        (drop (memory.atomic.wait32 (i32.const 204) (i32.const 0) (i64.const 1000000)))
        (br $again)))
    (if (i32.ne (i32.atomic.load (i32.const 204)) (i32.const 12)) (then (call $exit (i32.const 5))))
    (call $exit (i32.const 0))))
"#;

#[test]
fn the_spawn_ends_pthread_creates_hold_on_signals() {
    assert_eq!(status(SPAWN_HOLD), 0);
}

#[test]
fn thread_join_waits_for_the_spawned_thread_and_allows_unknown_tids() {
    assert_eq!(
        status(
            r#"
(module
  (import "env" "memory" (memory 1 1 shared))
  (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
  (import "wasix_32v1" "thread_join" (func $join (param i32) (result i32)))
  (import "wasix_32v1" "thread_sleep" (func $sleep (param i64) (result i32)))
  (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
  (func (export "wasi_thread_start") (param i32 i32)
    (drop (call $sleep (i64.const 1000000)))
    (i32.atomic.store (i32.const 200) (i32.const 37)))
  (func (export "_start")
    (if (call $spawn (i32.const 100) (i32.const 104)) (then (call $exit (i32.const 1))))
    (if (call $join (i32.load (i32.const 104))) (then (call $exit (i32.const 2))))
    (if (i32.ne (i32.atomic.load (i32.const 200)) (i32.const 37)) (then (call $exit (i32.const 3))))
    (if (call $join (i32.const -1)) (then (call $exit (i32.const 4))))
    (call $exit (i32.const 0))))
"#
        ),
        0
    );
}

/// Before libc names its callback, signals take their default action.
#[test]
fn signals_before_the_callback_terminate() {
    let wat = r#"
    (module
      (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (drop (call $raise (i32.const 15)))
        (call $exit (i32.const 1))))
    "#;
    assert_eq!(status(wat), 128 + 15);
}

/// A module that names a callback it does not export, and has no `__wasm_signal` either, has
/// nothing to run handlers through: its signals take their default action.
#[test]
fn signals_without_any_callback_terminate() {
    let wat = r#"
    (module
      (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
      (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 16) "no_such_export")
      (func (export "_start")
        (call $callback (i32.const 16) (i32.const 14))
        (drop (call $raise (i32.const 15)))
        (call $exit (i32.const 1))))
    "#;
    assert_eq!(status(wat), 128 + 15);
}

/// `proc_raise_interval` arms `ITIMER_REAL`: `SIGALRM` interrupts a sleep, which returns
/// `INTR` (27) once the handler ran. Disarming another signal succeeds independently.
#[test]
fn alarm() {
    let wat = r#"
    (module
      (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
      (import "wasix_32v1" "proc_raise_interval" (func $interval (param i32 i64 i32) (result i32)))
      (import "wasix_32v1" "thread_sleep" (func $sleep (param i64) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 16) "__wasm_signal")
      (global $last (mut i32) (i32.const 0))
      (func (export "__wasm_signal") (param $sig i32) (global.set $last (local.get $sig)))
      (func (export "_start")
        (call $callback (i32.const 16) (i32.const 13))
        (if (call $interval (i32.const 14) (i64.const 1000000) (i32.const 0))
          (then (call $exit (i32.const 1))))
        (if (i32.ne (call $sleep (i64.const 10000000000)) (i32.const 27))
          (then (call $exit (i32.const 2))))
        (if (i32.ne (global.get $last) (i32.const 14)) (then (call $exit (i32.const 3))))
        (if (call $interval (i32.const 10) (i64.const 0) (i32.const 0))
          (then (call $exit (i32.const 4))))
        ;; a short sleep without a timer completes
        (if (call $sleep (i64.const 1000)) (then (call $exit (i32.const 5))))
        (call $exit (i32.const 0))))
    "#;
    assert_eq!(status(wat), 0);
}

/// A thread starts at `wasi_thread_start(tid, start_arg)` on the shared memory, publishes
/// `start_arg + 1` and wakes the main thread, which waits on the futex. Then the futex
/// timeout (not woken), a stale expected value (woken) and a wake with no waiters.
const THREADS: &str = r#"
(module
  (import "env" "memory" (memory 1 1 shared))
  (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
  (import "wasi" "thread-spawn" (func $wasi_spawn (param i32) (result i32)))
  (import "wasix_32v1" "futex_wait" (func $wait (param i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "futex_wake" (func $wake (param i32 i32) (result i32)))
  (import "wasix_32v1" "futex_wake_all" (func $wake_all (param i32 i32) (result i32)))
  (import "wasix_32v1" "thread_parallelism" (func $parallelism (param i32) (result i32)))
  (import "wasix_32v1" "thread_id" (func $thread_id (param i32) (result i32)))
  (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    (i32.atomic.store (local.get $arg) (local.get $tid))
    (i32.atomic.store (i32.const 200) (i32.add (i32.atomic.load (i32.const 200)) (i32.const 1)))
    (drop (call $wake_all (i32.const 200) (i32.const 308))))
  ;; Waits until the counter at 200 reaches `n`.
  (func $await (param $n i32)
    (block $done
      (loop $again
        (br_if $done (i32.ge_u (i32.atomic.load (i32.const 200)) (local.get $n)))
        (if (call $wait (i32.const 200) (i32.atomic.load (i32.const 200)) (i32.const 0) (i32.const 304))
          (then (call $exit (i32.const 20))))
        (br $again))))
  (func (export "_start")
    (if (call $spawn (i32.const 100) (i32.const 104)) (then (call $exit (i32.const 1))))
    (call $await (i32.const 1))
    ;; the tid the call returned is the one the thread started with
    (if (i32.ne (i32.atomic.load (i32.const 100)) (i32.load (i32.const 104)))
      (then (call $exit (i32.const 2))))
    (drop (call $thread_id (i32.const 108)))
    (if (i32.eq (i32.load (i32.const 104)) (i32.load (i32.const 108)))
      (then (call $exit (i32.const 3))))
    ;; wasi-threads' form returns the tid
    (if (i32.le_s (call $wasi_spawn (i32.const 112)) (i32.const 0)) (then (call $exit (i32.const 4))))
    (call $await (i32.const 2))
    ;; a timeout of 1ms: not woken
    (i32.store8 (i32.const 408) (i32.const 1))
    (i64.store (i32.const 416) (i64.const 1000000))
    (if (call $wait (i32.const 400) (i32.const 0) (i32.const 408) (i32.const 304))
      (then (call $exit (i32.const 5))))
    (if (i32.load8_u (i32.const 304)) (then (call $exit (i32.const 6))))
    ;; the value is not the expected one: woken
    (if (call $wait (i32.const 400) (i32.const 1) (i32.const 0) (i32.const 304))
      (then (call $exit (i32.const 7))))
    (if (i32.eqz (i32.load8_u (i32.const 304))) (then (call $exit (i32.const 8))))
    ;; v1 reports a successful wake even when nobody waits
    (if (call $wake (i32.const 400) (i32.const 304)) (then (call $exit (i32.const 9))))
    (if (i32.eqz (i32.load8_u (i32.const 304))) (then (call $exit (i32.const 10))))
    (if (call $parallelism (i32.const 312)) (then (call $exit (i32.const 11))))
    (if (i32.eqz (i32.load (i32.const 312))) (then (call $exit (i32.const 12))))
    (call $exit (i32.const 0))))
"#;

#[test]
fn threads_and_futexes() {
    assert_eq!(status(THREADS), 0);
}

/// v1 libc's __wake loops until woken_out is true, even during single-threaded
/// mutex teardown. Zero kernel waiters must not turn a successful wake into a retry.
#[test]
fn futex_wakes_without_waiters_report_success_to_legacy_libc() {
    assert_eq!(
        status(
            r#"(module
      (import "wasix_32v1" "futex_wake" (func $wake (param i32 i32) (result i32)))
      (import "wasix_32v1" "futex_wake_all" (func $all (param i32 i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (call $wake (i32.const 400) (i32.const 304)) (then unreachable))
        (if (i32.ne (i32.load8_u (i32.const 304)) (i32.const 1)) (then unreachable))
        (i32.store8 (i32.const 304) (i32.const 0))
        (if (call $all (i32.const 400) (i32.const 304)) (then unreachable))
        (if (i32.ne (i32.load8_u (i32.const 304)) (i32.const 1)) (then unreachable))
        (call $exit (i32.const 0))))"#
        ),
        0
    );
}

/// `memory.atomic.wait32` and `wait64` wait on the kernel's futexes: `SIGALRM` interrupts a
/// timed wait, which returns as woken once the handler ran (v1's handlers do not restart; an
/// untimed wait would go on, as the instruction cannot fail), and timed waits and stale values
/// return 2 and 1. A thread waiting in the instruction is woken by
/// `futex_wake`, and one waiting in `futex_wait` by `memory.atomic.notify`, which also wakes the
/// main thread's `futex_wait` on the thread's steps.
const ATOMIC_WAITS: &str = r#"
(module
  (import "env" "memory" (memory 1 1 shared))
  (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
  (import "wasix_32v1" "proc_raise_interval" (func $interval (param i32 i64 i32) (result i32)))
  (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
  (import "wasix_32v1" "futex_wait" (func $wait (param i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "futex_wake" (func $wake (param i32 i32) (result i32)))
  (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
  (data (i32.const 16) "__wasm_signal")
  (global $last (mut i32) (i32.const 0))
  (func (export "__wasm_signal") (param $sig i32) (global.set $last (local.get $sig)))
  ;; Counts its steps at 200, and fails with a status left at 700.
  (func $step (param $n i32)
    (i32.atomic.store (i32.const 200) (local.get $n))
    (drop (memory.atomic.notify (i32.const 200) (i32.const 1))))
  (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
    (call $step (i32.const 1))
    (if (memory.atomic.wait32 offset=8 (i32.const 592) (i32.const 0) (i64.const -1))
      (then (i32.atomic.store (i32.const 700) (i32.const 30))))
    (call $step (i32.const 2))
    (if (call $wait (i32.const 604) (i32.const 0) (i32.const 0) (i32.const 300))
      (then (i32.atomic.store (i32.const 700) (i32.const 31))))
    (call $step (i32.const 3)))
  (func $await (param $n i32)
    (block $done
      (loop $again
        (br_if $done (i32.ge_u (i32.atomic.load (i32.const 200)) (local.get $n)))
        (drop (call $wait (i32.const 200) (i32.atomic.load (i32.const 200)) (i32.const 0) (i32.const 304)))
        (br $again))))
  (func (export "_start")
    (call $callback (i32.const 16) (i32.const 13))
    (if (call $interval (i32.const 14) (i64.const 1000000) (i32.const 0))
      (then (call $exit (i32.const 1))))
    (if (memory.atomic.wait32 (i32.const 400) (i32.const 0) (i64.const 10000000000))
      (then (call $exit (i32.const 2))))
    (if (i32.ne (global.get $last) (i32.const 14)) (then (call $exit (i32.const 3))))
    (if (i32.ne (memory.atomic.wait32 (i32.const 400) (i32.const 0) (i64.const 1000000)) (i32.const 2))
      (then (call $exit (i32.const 4))))
    (if (i32.ne (memory.atomic.wait32 (i32.const 400) (i32.const 1) (i64.const -1)) (i32.const 1))
      (then (call $exit (i32.const 5))))
    (i64.store (i32.const 408) (i64.const 0x100000000))
    (if (i32.ne (memory.atomic.wait64 (i32.const 408) (i64.const 0x100000000) (i64.const 0)) (i32.const 2))
      (then (call $exit (i32.const 6))))
    (if (i32.ne (memory.atomic.wait64 (i32.const 408) (i64.const 0) (i64.const -1)) (i32.const 1))
      (then (call $exit (i32.const 7))))
    ;; v1 reports a successful wake even when nobody waits
    (if (memory.atomic.notify (i32.const 400) (i32.const 1)) (then (call $exit (i32.const 8))))
    (if (call $spawn (i32.const 100) (i32.const 104)) (then (call $exit (i32.const 9))))
    (call $await (i32.const 1))
    ;; the syscall wakes the instruction's waiter, once it waits
    (block $woken
      (loop $again
        (if (call $wake (i32.const 600) (i32.const 304)) (then (call $exit (i32.const 10))))
        (br_if $woken (i32.load8_u (i32.const 304)))
        (br $again)))
    (call $await (i32.const 2))
    ;; and the instruction the syscall's
    (block $woken
      (loop $again
        (br_if $woken (memory.atomic.notify (i32.const 604) (i32.const 1)))
        (br $again)))
    (call $await (i32.const 3))
    (call $exit (i32.atomic.load (i32.const 700)))))
"#;

#[test]
fn atomic_waits() {
    assert_eq!(status(ATOMIC_WAITS), 0);
}

/// A thread blocked in `memory.atomic.wait32` ends with its group: by `proc_exit2`, and by a
/// signal whose default action kills the process.
#[test]
fn the_group_ends_threads_blocked_in_atomic_waits() {
    let wat = |end: &str| {
        format!(
            r#"
    (module
      (import "env" "memory" (memory 1 1 shared))
      (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (func (export "wasi_thread_start") (param $tid i32) (param $arg i32)
        (i32.atomic.store (i32.const 200) (i32.const 1))
        (drop (memory.atomic.wait32 (i32.const 400) (i32.const 0) (i64.const -1))))
      (func (export "_start")
        (if (call $spawn (i32.const 100) (i32.const 104)) (then (call $exit (i32.const 1))))
        (block $started
          (loop $again
            (br_if $started (i32.atomic.load (i32.const 200)))
            (br $again)))
        {end}
        (call $exit (i32.const 2))))
    "#
        )
    };
    assert_eq!(status(&wat("(call $exit (i32.const 7))")), 7);
    assert_eq!(
        status(&wat("(drop (call $raise (i32.const 15)))")),
        128 + 15
    );
}

/// `proc_fork_env` continues as the child, whose `proc_exit2` returns in the parent;
/// `proc_join` then reports the child's status, and `CHILD` (12) once there are no children.
const VFORK_EXIT_AND_JOIN: &str = r#"
    (module
      (import "wasix_32v1" "proc_fork_env" (func $vfork (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
      (import "wasix_32v1" "proc_id" (func $proc_id (param i32) (result i32)))
      (import "wasix_32v1" "proc_parent" (func $proc_parent (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (drop (call $proc_id (i32.const 96)))
        (if (call $vfork (i32.const 100)) (then (call $exit (i32.const 1))))
        ;; the child: its own pid, whose parent is the caller
        (drop (call $proc_id (i32.const 104)))
        (if (i32.ne (i32.load (i32.const 104)) (i32.load (i32.const 100))) (then (call $exit (i32.const 2))))
        (if (call $proc_parent (i32.load (i32.const 104)) (i32.const 108)) (then (call $exit (i32.const 3))))
        (if (i32.ne (i32.load (i32.const 108)) (i32.load (i32.const 96))) (then (call $exit (i32.const 4))))
        (call $exit (i32.const 5))
        ;; the parent again
        ;; a child's parent remains visible while the child is a zombie
        (if (call $proc_parent (i32.load (i32.const 100)) (i32.const 108))
          (then (call $exit (i32.const 12))))
        (if (i32.ne (i32.load (i32.const 108)) (i32.load (i32.const 96)))
          (then (call $exit (i32.const 13))))
        (i32.store8 (i32.const 200) (i32.const 1))
        (i32.store (i32.const 204) (i32.load (i32.const 100)))
        (if (call $join (i32.const 200) (i32.const 0) (i32.const 220)) (then (call $exit (i32.const 6))))
        (if (i32.ne (i32.load8_u (i32.const 220)) (i32.const 1)) (then (call $exit (i32.const 7))))
        (if (i32.ne (i32.load16_u (i32.const 222)) (i32.const 5)) (then (call $exit (i32.const 8))))
        (if (i32.ne (i32.load (i32.const 204)) (i32.load (i32.const 100))) (then (call $exit (i32.const 9))))
        (i32.store8 (i32.const 200) (i32.const 0))
        (if (i32.ne (call $join (i32.const 200) (i32.const 1) (i32.const 220)) (i32.const 12))
          (then (call $exit (i32.const 10))))
        ;; a reaped child and an unknown pid have no parent handle
        (if (i32.ne (call $proc_parent (i32.load (i32.const 100)) (i32.const 108)) (i32.const 8))
          (then (call $exit (i32.const 14))))
        (if (i32.ne (call $proc_parent (i32.add (i32.load (i32.const 96)) (i32.const 1000)) (i32.const 108)) (i32.const 8))
          (then (call $exit (i32.const 11))))
        (call $exit (i32.const 0))))
    "#;

#[test]
fn vfork_exit_and_join() {
    assert_eq!(status(VFORK_EXIT_AND_JOIN), 0);
}

mod parent_pidfd {
    use super::*;
    use wasixv2_abi::{Errno, FcntlCmd, Fd, GuestPtr, IoctlRequest, PidfdInfo, PidfdInfoMask};
    use wasixv2_kernel::{Dispatch, HostClock, Kernel, SyscallEntry};
    use wasixv2_syscalls::{
        Caller, Layer, Layered, MaybeFuture, SysErr, SysResult, Syscall, SyscallRet, Syscalls,
        read_value,
    };

    #[derive(Default)]
    struct Probe {
        query_error: Mutex<Option<SysErr>>,
        close_error: Mutex<Option<SysErr>>,
        missing_pid: bool,
        opened: Mutex<Vec<Fd>>,
        closed: Mutex<Vec<Fd>>,
    }

    struct ProbeLayer(Arc<Probe>);

    impl Layer<Kernel> for ProbeLayer {
        fn call<'a>(
            &'a self,
            caller: &'a Caller<'_>,
            call: Syscall,
            next: &'a Kernel,
        ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
            MaybeFuture::Future(Box::pin(async move {
                match call {
                    // No proc mount, and even an attempted open must fail.
                    Syscall::Openat { .. } => return Err(Errno::EACCES.into()),
                    Syscall::Ioctl { fd, cmd, arg } if cmd == IoctlRequest::PIDFD_GET_INFO => {
                        assert!(self.0.opened.lock().unwrap().contains(&fd));
                        let info: PidfdInfo =
                            read_value(caller.memory(), GuestPtr::new(arg)).await?;
                        assert_eq!(info.mask, PidfdInfoMask::PIDFD_INFO_PID.0);
                        if let Some(err) = self.0.query_error.lock().unwrap().take() {
                            return Err(err);
                        }
                        if self.0.missing_pid {
                            caller.memory().write(arg, &[0; 8]).await?;
                            return Ok(SyscallRet::Ioctl(0));
                        }
                    }
                    Syscall::Close { fd } if self.0.opened.lock().unwrap().contains(&fd) => {
                        let ret = Dispatch.call(caller, call, next).await;
                        // Verify the real table, not just that close was called.
                        assert_eq!(
                            next.fcntl64(caller, fd, FcntlCmd::F_GETFD, 0).await,
                            Err(SysErr::Errno(Errno::EBADF))
                        );
                        self.0.closed.lock().unwrap().push(fd);
                        return if let Some(err) = self.0.close_error.lock().unwrap().take() {
                            Err(err)
                        } else {
                            ret
                        };
                    }
                    _ => {}
                }
                let ret = Dispatch.call(caller, call, next).await;
                if let Ok(SyscallRet::PidfdOpen(fd)) = ret {
                    self.0.opened.lock().unwrap().push(fd);
                }
                ret
            }))
        }
    }

    async fn run(wat: &str, probe: Arc<Probe>) -> i32 {
        let host: Arc<dyn wasixv2::Host> = Arc::new(wasixv2::TokioHost::default());
        let root = Arc::new(wasixv2_vfs_mem::MemFs::new(
            Arc::new(HostClock(host.clone())),
            0o777,
            1,
            1,
        ));
        let mut abis = wasixv2_exec::Abis::new();
        abis.push(Arc::new(wasixv2_wasix1::Wasix1::new()));
        let abis = Arc::new(abis);
        let kernel = Kernel::new(host.clone(), root).with_binfmt(abis.clone());
        let task = kernel
            .spawn(ProcessConfig {
                args: vec!["parent".to_owned()],
                env: Vec::new(),
                stdio: Stdio::from_fns(|_| {}, |_| {}),
            })
            .unwrap();
        let syscalls = Arc::new(Layered::new(SyscallEntry(ProbeLayer(probe)), kernel));
        let store = wasmer::Store::default();
        let module = wasixv2_exec::load(store.engine(), &wat::parse_str(wat).unwrap()).unwrap();
        wasixv2_exec::run_with_abis(store, &module, syscalls, task, host, abis)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn proc_parent_without_procfs() {
        let probe = Arc::new(Probe::default());
        assert_eq!(run(VFORK_EXIT_AND_JOIN, probe.clone()).await, 0);
        assert_eq!(*probe.opened.lock().unwrap(), *probe.closed.lock().unwrap());
        assert_eq!(probe.opened.lock().unwrap().len(), 1);
    }

    fn query_error_guest(errno: u16) -> String {
        format!(
            r#"(module
              (import "wasix_32v1" "proc_fork_env" (func $vfork (param i32) (result i32)))
              (import "wasix_32v1" "proc_parent" (func $parent (param i32 i32) (result i32)))
              (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
              (memory (export "memory") 1)
              (func (export "_start")
                (if (call $vfork (i32.const 100)) (then (call $exit (i32.const 1))))
                (call $exit (i32.const 0))
                (i32.store (i32.const 104) (i32.const -1))
                (if (i32.ne (call $parent (i32.load (i32.const 100)) (i32.const 104)) (i32.const {errno}))
                  (then (call $exit (i32.const 2))))
                (if (i32.ne (i32.load (i32.const 104)) (i32.const -1)) (then (call $exit (i32.const 3))))
                (call $exit (i32.const 0))))"#
        )
    }

    #[tokio::test]
    async fn proc_parent_closes_pidfd_on_query_error() {
        for errno in [Errno::EIO, Errno::ESRCH, Errno::ENOSYS, Errno::ENOTTY] {
            let probe = Arc::new(Probe {
                query_error: Mutex::new(Some(SysErr::Errno(errno))),
                ..Probe::default()
            });
            let expected = if errno == Errno::ESRCH {
                wasixv2_wasix1::abi::Errno::BADF
            } else {
                wasixv2_wasix1::abi::Errno::from_linux(errno)
            };
            assert_eq!(run(&query_error_guest(expected.0), probe.clone()).await, 0);
            assert_eq!(*probe.opened.lock().unwrap(), *probe.closed.lock().unwrap());
            assert_eq!(probe.opened.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn proc_parent_does_not_restart_a_released_close() {
        for error in [
            SysErr::Restart,
            SysErr::RestartNoIntr,
            SysErr::RestartNoHand,
            SysErr::RestartBlock,
        ] {
            let probe = Arc::new(Probe {
                close_error: Mutex::new(Some(error)),
                ..Probe::default()
            });
            let wat = query_error_guest(wasixv2_wasix1::abi::Errno::INTR.0);
            assert_eq!(run(&wat, probe.clone()).await, 0);
            assert_eq!(*probe.opened.lock().unwrap(), *probe.closed.lock().unwrap());
            assert_eq!(probe.opened.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn proc_parent_restarts_the_query_with_a_fresh_pidfd() {
        let probe = Arc::new(Probe {
            query_error: Mutex::new(Some(SysErr::Restart)),
            ..Probe::default()
        });
        assert_eq!(run(VFORK_EXIT_AND_JOIN, probe.clone()).await, 0);
        assert_eq!(*probe.opened.lock().unwrap(), *probe.closed.lock().unwrap());
        assert_eq!(probe.opened.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn proc_parent_requires_returned_pid_information() {
        let probe = Arc::new(Probe {
            missing_pid: true,
            ..Probe::default()
        });
        let wat = query_error_guest(wasixv2_wasix1::abi::Errno::IO.0);
        assert_eq!(run(&wat, probe.clone()).await, 0);
        assert_eq!(*probe.opened.lock().unwrap(), *probe.closed.lock().unwrap());
        assert_eq!(probe.opened.lock().unwrap().len(), 1);
    }
}

/// Writes "child" to fd 1 and exits with 3 plus the number of signals it inherited as
/// ignored.
const CHILD: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "proc_signals_sizes_get" (func $count (param i32) (result i32)))
  (import "wasix_32v1" "proc_signals_get" (func $signals (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "\10\00\00\00\05\00\00\00")
  (data (i32.const 16) "child")
  (func (export "_start") (local $i i32) (local $ignored i32)
    (drop (call $fd_write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 32)))
    (drop (call $count (i32.const 40)))
    (drop (call $signals (i32.const 64)))
    ;; (signal, disposition) pairs; IGNORE is 1
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (i32.load (i32.const 40))))
        (if (i32.eq (i32.load8_u (i32.add (i32.const 65) (i32.shl (local.get $i) (i32.const 1)))) (i32.const 1))
          (then (local.set $ignored (i32.add (local.get $ignored) (i32.const 1)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (call $exit (i32.add (i32.const 3) (local.get $ignored)))))
"#;

/// `proc_spawn2`: a child found directly and through the search path, one with its stdout
/// redirected to a file and `SIGUSR1` ignored, and a missing program (`NOENT`, 44).
const SPAWN: &str = r#"
(module
  (import "wasix_32v1" "proc_spawn2" (func $spawn
    (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
  (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 1000) "/prog/child.wasm")
  (data (i32.const 1032) "child\n")
  (data (i32.const 1040) "child.wasm")
  (data (i32.const 1056) "/nope:/prog")
  (data (i32.const 1072) "/prog/missing")
  (data (i32.const 1088) "/prog/out.txt")
  ;; the open action (56 bytes at 2000): OPEN 2, fd 1, path, CREAT|TRUNC, FD_WRITE, follow
  (data (i32.const 2000) "\02")
  (data (i32.const 2004) "\01")
  (data (i32.const 2012) "\40\04\00\00\0d\00\00\00\01\00\00\00\09\00")
  (data (i32.const 2032) "\40")
  ;; signal dispositions at 2100: SIGUSR1 ignored
  (data (i32.const 2100) "\0a\01")
  ;; Waits for the child at 100 and returns its exit code.
  (func $wait_child (result i32)
    (i32.store8 (i32.const 200) (i32.const 1))
    (i32.store (i32.const 204) (i32.load (i32.const 100)))
    (if (call $join (i32.const 200) (i32.const 0) (i32.const 220)) (then (call $exit (i32.const 90))))
    (if (i32.ne (i32.load8_u (i32.const 220)) (i32.const 1)) (then (call $exit (i32.const 91))))
    (i32.load16_u (i32.const 222)))
  (func (export "_start")
    (if (call $spawn (i32.const 1000) (i32.const 16) (i32.const 1032) (i32.const 6) (i32.const 0) (i32.const 0)
                     (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                     (i32.const 100))
      (then (call $exit (i32.const 1))))
    (if (i32.ne (call $wait_child) (i32.const 3)) (then (call $exit (i32.const 2))))
    (if (call $spawn (i32.const 1040) (i32.const 10) (i32.const 1032) (i32.const 6) (i32.const 0) (i32.const 0)
                     (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 1056) (i32.const 11)
                     (i32.const 100))
      (then (call $exit (i32.const 3))))
    (if (i32.ne (call $wait_child) (i32.const 3)) (then (call $exit (i32.const 4))))
    (if (call $spawn (i32.const 1000) (i32.const 16) (i32.const 1032) (i32.const 6) (i32.const 0) (i32.const 0)
                     (i32.const 2000) (i32.const 1) (i32.const 2100) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0)
                     (i32.const 100))
      (then (call $exit (i32.const 5))))
    (if (i32.ne (call $wait_child) (i32.const 4)) (then (call $exit (i32.const 6))))
    (if (i32.ne (call $spawn (i32.const 1072) (i32.const 13) (i32.const 1032) (i32.const 6) (i32.const 0) (i32.const 0)
                     (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                     (i32.const 100))
                (i32.const 44))
      (then (call $exit (i32.const 7))))
    ;; the failed child was reaped
    (i32.store8 (i32.const 200) (i32.const 0))
    (if (i32.ne (call $join (i32.const 200) (i32.const 1) (i32.const 220)) (i32.const 12))
      (then (call $exit (i32.const 8))))
    (call $exit (i32.const 0))))
"#;

#[test]
fn spawn() {
    let programs = Programs::new("spawn", &[("child.wasm", CHILD)]);
    let (status, stdout) = run(SPAWN, Some(&programs.0));
    assert_eq!(status, 0);
    // The first two children wrote to the inherited stdout, the third to the file.
    assert_eq!(stdout, b"childchild");
    assert_eq!(std::fs::read(programs.0.join("out.txt")).unwrap(), b"child");
}

/// Spawn retains the parent's context; neither its child nor a failed exec can
/// turn a guest fork/vfork into a supported operation in that context.
#[test]
fn spawn_from_a_nonmain_context_preserves_guest_fork_restrictions() {
    let programs = Programs::new("context-spawn", &[("child.wasm", CHILD)]);
    let wat = SPAWN
        .replace(
            r#"  (memory (export "memory") 1)"#,
            r#"
  (import "wasix_32v1" "context_create" (func $create (param i32 i32) (result i32)))
  (import "wasix_32v1" "context_switch" (func $switch (param i64) (result i32)))
  (import "wasix_32v1" "context_destroy" (func $destroy (param i64) (result i32)))
  (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
  (import "wasix_32v1" "proc_fork_env" (func $vfork (param i32) (result i32)))
  (memory (export "memory") 1)
  (table 2 funcref)
  (elem (i32.const 1) $context)
  (func $check_fork
    (if (i32.ne (call $fork (i32.const 1) (i32.const 300)) (i32.const 58))
      (then (call $exit (i32.const 81))))
    (if (i32.ne (call $vfork (i32.const 300)) (i32.const 58))
      (then (call $exit (i32.const 82)))))
  (func (export "_start")
    (if (call $create (i32.const 400) (i32.const 1)) (then (call $exit (i32.const 83))))
    (if (call $switch (i64.load (i32.const 400))) (then (call $exit (i32.const 84))))
    (if (call $destroy (i64.load (i32.const 400))) (then (call $exit (i32.const 85))))
    (call $exit (i32.const 0)))
"#,
        )
        .replace(
            "  (func (export \"_start\")\n    (if (call $spawn",
            r#"  (func $context (local $kept i64)
    (local.set $kept (i64.const 0x123456789abcdef))
    (call $check_fork)
    (if (call $spawn"#,
        )
        .replace(
            "    (call $exit (i32.const 0))))",
            r#"    (call $check_fork)
    (if (i64.ne (local.get $kept) (i64.const 0x123456789abcdef))
      (then (call $exit (i32.const 86))))
    (if (call $switch (i64.const 0)) (then (call $exit (i32.const 87))))
    unreachable))"#,
        );
    let (status, stdout) = run(&wat, Some(&programs.0));
    assert_eq!(status, 0);
    assert_eq!(stdout, b"childchild");
    assert_eq!(std::fs::read(programs.0.join("out.txt")).unwrap(), b"child");
}

#[cfg(not(target_arch = "wasm32"))]
mod spawn_cancellation {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use wasixv2_kernel::{Dispatch, HostClock, Kernel, SyscallEntry};
    use wasixv2_syscalls::{
        Caller, Control, Layer, Layered, MaybeFuture, PidView, SysResult, Syscall, SyscallRet,
    };

    #[derive(Default)]
    struct Probe {
        child: AtomicU32,
        dropped: AtomicBool,
    }
    struct PendingAction(Arc<Probe>);
    impl Drop for PendingAction {
        fn drop(&mut self) {
            self.0.dropped.store(true, Ordering::Release);
        }
    }
    struct BlockChdir(Arc<Probe>);
    impl Layer<Kernel> for BlockChdir {
        fn call<'a>(
            &'a self,
            caller: &'a Caller<'_>,
            call: Syscall,
            next: &'a Kernel,
        ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
            MaybeFuture::Future(Box::pin(async move {
                if matches!(call, Syscall::Chdir { .. }) {
                    let _pending = PendingAction(self.0.clone());
                    self.0.child.store(caller.task().0, Ordering::Release);
                    return std::future::pending().await;
                }
                Dispatch.call(caller, call, next).await
            }))
        }
    }

    /// The real kernel must forget the child, including its pid and vfork wait,
    /// after the retained import is canceled during child-only file actions.
    #[tokio::test]
    async fn pending_file_action_cancellation_reaps_the_exact_child() {
        tokio::task::LocalSet::new().run_until(async {
            let probe = Arc::new(Probe::default());
            let host: Arc<dyn wasixv2::Host> = Arc::new(wasixv2::TokioHost::default());
            let root = Arc::new(wasixv2_vfs_mem::MemFs::new(Arc::new(HostClock(host.clone())), 0o777, 1, 1));
            let mut abis = wasixv2_exec::Abis::new();
            abis.push(Arc::new(wasixv2_wasix1::Wasix1::new()));
            let abis = Arc::new(abis);
            let kernel = Kernel::new(host.clone(), root).with_binfmt(abis.clone());
            let config = || ProcessConfig { args: vec!["spawn-cancel".into()], env: vec![], stdio: Stdio::from_fns(|_| {}, |_| {}) };
            let parent = kernel.spawn(config()).unwrap();
            let observer = kernel.spawn(config()).unwrap();
            let syscalls = Arc::new(Layered::new(SyscallEntry(BlockChdir(probe.clone())), kernel));
            let source = r#"(module
              (import "wasix_32v1" "proc_spawn2" (func $spawn
                (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
              (import "wasix_32v1" "context_create" (func $create (param i32 i32) (result i32)))
              (import "wasix_32v1" "context_switch" (func $switch (param i64) (result i32)))
              (memory (export "memory") 1)
              (table 2 funcref)
              (elem (i32.const 1) $context)
              (data (i32.const 16) "/missing")
              (data (i32.const 32) "/")
              (data (i32.const 128) "\03")
              (data (i32.const 140) "\20\00\00\00\01\00\00\00")
              (func $context
                (drop (call $spawn (i32.const 16) (i32.const 8) (i32.const 0) (i32.const 0)
                  (i32.const 0) (i32.const 0) (i32.const 128) (i32.const 1)
                  (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 300)))
                unreachable)
              (func (export "_start")
                (if (call $create (i32.const 400) (i32.const 1)) (then unreachable))
                (drop (call $switch (i64.load (i32.const 400)))) unreachable))"#;
            let store = wasmer::Store::default();
            let module = wasixv2_exec::load(store.engine(), &wat::parse_str(source).unwrap()).unwrap();
            let mut run = Box::pin(wasixv2_exec::run_with_abis(store, &module, syscalls.clone(), parent, host, abis));
            let child = tokio::time::timeout(std::time::Duration::from_secs(5), std::future::poll_fn(|cx| {
                assert!(run.as_mut().poll(cx).is_pending(), "spawn must be suspended in the child");
                let child = probe.child.load(Ordering::Acquire);
                if child == 0 { std::task::Poll::Pending } else { std::task::Poll::Ready(wasixv2_syscalls::TaskId(child)) }
            })).await.unwrap();
            assert_ne!(child, parent);
            assert_ne!(syscalls.pid_in(observer, child), 0);
            drop(run);
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !probe.dropped.load(Ordering::Acquire) || syscalls.pid_in(observer, child) != 0 {
                    tokio::task::yield_now().await;
                }
            }).await.expect("physical import retirement and exact child reap");
            assert_eq!(syscalls.take_pending(child), None);
            syscalls.fault(parent, 9); syscalls.release(parent);
            syscalls.fault(observer, 9); syscalls.release(observer);
        }).await;
    }
}

/// The Rust-style legacy call has three independent pipes and drops every empty CR/LF
/// argument. The child observes the requested cwd and inherited environment, echoes its
/// stdin to stdout/stderr, then exits with 7.
const LEGACY_CHILD: &str = r#"
(module
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $argc (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_get" (func $argv (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get" (func $envc (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_get" (func $env (param i32 i32) (result i32)))
  (import "wasix_32v1" "getcwd" (func $cwd (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 400) "\00\02\00\00\01\00\00\00")
  (func (export "_start")
    (if (call $argc (i32.const 0) (i32.const 4)) (then (call $exit (i32.const 20))))
    (if (i32.ne (i32.load (i32.const 0)) (i32.const 3)) (then (call $exit (i32.const 21))))
    (if (call $argv (i32.const 8) (i32.const 32)) (then (call $exit (i32.const 22))))
    (if (i32.ne (i32.load (i32.load (i32.const 8))) (i32.const 0x30677261)) (then (call $exit (i32.const 23))))
    (if (i32.ne (i32.load (i32.load (i32.const 12))) (i32.const 0x31677261)) (then (call $exit (i32.const 24))))
    (if (i32.ne (i32.load (i32.load (i32.const 16))) (i32.const 0x32677261)) (then (call $exit (i32.const 25))))
    (if (call $envc (i32.const 0) (i32.const 4)) (then (call $exit (i32.const 26))))
    (if (i32.ne (i32.load (i32.const 0)) (i32.const 1)) (then (call $exit (i32.const 27))))
    (if (call $env (i32.const 8) (i32.const 32)) (then (call $exit (i32.const 28))))
    (if (i32.ne (i32.load8_u (i32.add (i32.load (i32.const 8)) (i32.const 9))) (i32.const 104)) (then (call $exit (i32.const 29))))
    (i32.store (i32.const 0) (i32.const 32))
    (if (call $cwd (i32.const 32) (i32.const 0)) (then (call $exit (i32.const 30))))
    (if (i32.ne (i32.load (i32.const 0)) (i32.const 5)) (then (call $exit (i32.const 31))))
    (if (i32.ne (i32.load (i32.const 32)) (i32.const 0x6f72702f)) (then (call $exit (i32.const 32))))
    (if (call $read (i32.const 0) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 33))))
    (if (i32.ne (i32.load (i32.const 408)) (i32.const 1)) (then (call $exit (i32.const 34))))
    (if (call $write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 35))))
    (if (call $write (i32.const 2) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 36))))
    (call $exit (i32.const 7))))
"#;

const LEGACY_SPAWN: &str = r#"
(module
  (import "wasix_32v1" "proc_spawn" (func $spawn
    (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 1000) "child.wasm")
  (data (i32.const 1032) "\r\narg0\n\narg1\rarg2\r\n")
  (data (i32.const 1088) "/prog")
  (data (i32.const 400) "\00\02\00\00\01\00\00\00")
  (data (i32.const 512) "x")
  (func $check_pipe (param $at i32)
    (if (i32.ne (i32.load8_u (local.get $at)) (i32.const 1)) (then (call $exit (i32.const 10))))
    (if (i32.lt_u (i32.load offset=4 (local.get $at)) (i32.const 3)) (then (call $exit (i32.const 11)))))
  (func (export "_start")
    ;; CLOSE_STDIO
    (if (call $spawn (i32.const 1000) (i32.const 10) (i32.const 0)
                    (i32.const 1032) (i32.const 19) (i32.const 0) (i32.const 0)
                    (i32.const 0) (i32.const 0) (i32.const 0)
                    (i32.const 1088) (i32.const 5) (i32.const 100))
      (then (call $exit (i32.const 1))))
    (if (i32.eqz (i32.load (i32.const 100))) (then (call $exit (i32.const 2))))
    (call $check_pipe (i32.const 104))
    (call $check_pipe (i32.const 112))
    (call $check_pipe (i32.const 120))
    (if (call $write (i32.load (i32.const 108)) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 3))))
    (drop (call $close (i32.load (i32.const 108))))
    (if (call $read (i32.load (i32.const 116)) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 4))))
    (if (i32.ne (i32.load (i32.const 408)) (i32.const 1)) (then (call $exit (i32.const 5))))
    (if (i32.ne (i32.load8_u (i32.const 512)) (i32.const 120)) (then (call $exit (i32.const 6))))
    (if (call $read (i32.load (i32.const 124)) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 7))))
    (if (i32.ne (i32.load (i32.const 408)) (i32.const 1)) (then (call $exit (i32.const 8))))
    (i32.store8 (i32.const 200) (i32.const 1))
    (i32.store (i32.const 204) (i32.load (i32.const 100)))
    (if (call $join (i32.const 200) (i32.const 0) (i32.const 220)) (then (call $exit (i32.const 9))))
    (if (i32.ne (i32.load16_u (i32.const 222)) (i32.const 7)) (then (call $exit (i32.load16_u (i32.const 222)))))
    ;; No parent copy of the child's write end can keep either pipe alive.
    (if (call $read (i32.load (i32.const 116)) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 12))))
    (if (i32.load (i32.const 408)) (then (call $exit (i32.const 13))))
    (if (call $read (i32.load (i32.const 124)) (i32.const 400) (i32.const 1) (i32.const 408)) (then (call $exit (i32.const 14))))
    (if (i32.load (i32.const 408)) (then (call $exit (i32.const 15))))
    (call $exit (i32.const 0))))
"#;

#[test]
fn legacy_spawn_pipes_args_cwd_and_wait() {
    let programs = Programs::new("legacy-pipes", &[("child.wasm", LEGACY_CHILD)]);
    assert_eq!(run(LEGACY_SPAWN, Some(&programs.0)).0, 0);
    let closed = LEGACY_SPAWN.replace(";; CLOSE_STDIO", "(drop (call $close (i32.const 0))) (drop (call $close (i32.const 1))) (drop (call $close (i32.const 2)))");
    assert_eq!(run(&closed, Some(&programs.0)).0, 0);
}

#[test]
fn legacy_spawn_inherit_null_and_failures() {
    let wat = r#"
    (module
      (import "wasix_32v1" "proc_spawn" (func $spawn
        (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
      (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
      (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 1000) "/prog/child.wasm")
      (data (i32.const 1032) "child\n")
      (data (i32.const 1056) "\r\n")
      (data (i32.const 1072) "/prog/missing")
      (data (i32.const 1088) ".")
      (data (i32.const 1104) "/prog/closed.wasm")
      (func $launch (param $root i32) (param $preopen i32) (param $mode i32) (param $name i32) (param $len i32) (result i32)
        (call $spawn (local.get $name) (local.get $len) (local.get $root)
                     (i32.const 1032) (i32.const 6) (local.get $preopen) (i32.const 2)
                     (local.get $mode) (local.get $mode) (local.get $mode)
                     (i32.const 1088) (i32.const 1) (i32.const 100)))
      (func $wait
        (i32.store8 (i32.const 200) (i32.const 1))
        (i32.store (i32.const 204) (i32.load (i32.const 100)))
        (if (call $join (i32.const 200) (i32.const 0) (i32.const 220)) (then (call $exit (i32.const 90))))
        (if (i32.ne (i32.load16_u (i32.const 222)) (i32.const 3)) (then (call $exit (i32.load16_u (i32.const 222))))))
      (func $none
        (if (i32.or (i32.or (i32.load8_u (i32.const 104)) (i32.load8_u (i32.const 112))) (i32.load8_u (i32.const 120))) (then (call $exit (i32.const 92))))
        (if (i32.ne (i32.and (i32.and (i32.load (i32.const 108)) (i32.load (i32.const 116))) (i32.load (i32.const 124))) (i32.const -1)) (then (call $exit (i32.const 93)))))
      (func (export "_start")
        ;; Empty CR/LF-only preopens are accepted; Inherit produces no extra handles.
        (if (call $launch (i32.const 0) (i32.const 1056) (i32.const 1) (i32.const 1000) (i32.const 16)) (then (call $exit (i32.const 1))))
        (call $none) (call $wait)
        ;; Null and Log historically close stdio, so the child's ignored write fails.
        (if (call $launch (i32.const 0) (i32.const 1056) (i32.const 2) (i32.const 1104) (i32.const 17)) (then (call $exit (i32.const 2))))
        (call $none) (call $wait)
        (if (call $launch (i32.const 0) (i32.const 1056) (i32.const 3) (i32.const 1104) (i32.const 17)) (then (call $exit (i32.const 3))))
        (call $none) (call $wait)
        (i32.store (i32.const 100) (i32.const -1))
        (if (i32.ne (call $launch (i32.const 1) (i32.const 1056) (i32.const 0) (i32.const 1000) (i32.const 16)) (i32.const 58)) (then (call $exit (i32.const 4))))
        (if (i32.ne (call $launch (i32.const 0) (i32.const 1000) (i32.const 0) (i32.const 1000) (i32.const 16)) (i32.const 58)) (then (call $exit (i32.const 5))))
        (if (i32.ne (i32.load (i32.const 100)) (i32.const -1)) (then (call $exit (i32.const 6))))
        ;; A failed exec closes all parent-created descriptors and reaps the child.
        (if (call $pipe (i32.const 300) (i32.const 304)) (then (call $exit (i32.const 7))))
        (drop (call $close (i32.load (i32.const 300))))
        (drop (call $close (i32.load (i32.const 304))))
        (if (i32.ne (call $launch (i32.const 0) (i32.const 1056) (i32.const 0) (i32.const 1072) (i32.const 13)) (i32.const 44)) (then (call $exit (i32.const 8))))
        (if (i32.ne (i32.load (i32.const 100)) (i32.const -1)) (then (call $exit (i32.const 9))))
        (if (call $pipe (i32.const 308) (i32.const 312)) (then (call $exit (i32.const 10))))
        (if (i32.ne (i32.load (i32.const 300)) (i32.load (i32.const 308))) (then (call $exit (i32.const 11))))
        (if (i32.ne (i32.load (i32.const 304)) (i32.load (i32.const 312))) (then (call $exit (i32.const 12))))
        (i32.store8 (i32.const 200) (i32.const 0))
        (if (i32.ne (call $join (i32.const 200) (i32.const 1) (i32.const 220)) (i32.const 12)) (then (call $exit (i32.const 13))))
        (call $exit (i32.const 0))))
    "#;
    let closed = r#"
    (module
      (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (i32.ne (call $stat (i32.const 0) (i32.const 100)) (i32.const 8)) (then (call $exit (i32.const 40))))
        (if (i32.ne (call $stat (i32.const 1) (i32.const 100)) (i32.const 8)) (then (call $exit (i32.const 41))))
        (if (i32.ne (call $stat (i32.const 2) (i32.const 100)) (i32.const 8)) (then (call $exit (i32.const 42))))
        (call $exit (i32.const 3))))
    "#;
    let programs = Programs::new(
        "legacy-inherit",
        &[("child.wasm", CHILD), ("closed.wasm", closed)],
    );
    let (status, stdout) = run(wat, Some(&programs.0));
    assert_eq!(status, 0);
    assert_eq!(stdout, b"child");
}

/// vfork, then `proc_exec3` in the child: the call returns 0 in the parent, whose `proc_join`
/// sees the new image's exit. A failing `proc_exec3` returns its errno to the child.
#[test]
fn vfork_and_exec() {
    let wat = r#"
    (module
      (import "wasix_32v1" "proc_fork_env" (func $vfork (param i32) (result i32)))
      (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
      (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 1000) "/prog/child.wasm")
      (data (i32.const 1032) "child\n")
      (data (i32.const 1072) "/prog/missing")
      (func (export "_start")
        (if (call $vfork (i32.const 100)) (then (call $exit (i32.const 1))))
        ;; the child: a missing program fails here, the real one returns in the parent
        (if (i32.ne (call $exec (i32.const 1072) (i32.const 13) (i32.const 1032) (i32.const 6)
                                (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))
                    (i32.const 44))
          (then (call $exit (i32.const 2))))
        (if (call $exec (i32.const 1000) (i32.const 16) (i32.const 1032) (i32.const 6)
                        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))
          (then (call $exit (i32.const 3))))
        (i32.store8 (i32.const 200) (i32.const 1))
        (i32.store (i32.const 204) (i32.load (i32.const 100)))
        (if (call $join (i32.const 200) (i32.const 0) (i32.const 220)) (then (call $exit (i32.const 4))))
        (if (i32.ne (i32.load16_u (i32.const 222)) (i32.const 3)) (then (call $exit (i32.const 5))))
        (call $exit (i32.const 0))))
    "#;
    let programs = Programs::new("exec", &[("child.wasm", CHILD)]);
    let (status, stdout) = run(wat, Some(&programs.0));
    assert_eq!(status, 0);
    assert_eq!(stdout, b"child");
}

/// Preparing a host namespace needs no guest memory. Its live descriptor metadata,
/// rather than the original bootstrap fd list, survives the runner's actual exec handoff.
#[test]
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
fn prepared_host_namespace_survives_exec_with_live_names_rights_and_new_arguments() {
    use wasixv2::{DirectoryBootstrap, NamespaceBootstrap};
    use wasixv2_exec::{HostEnvironment, local_cleanup_runner, run_with_abis};
    use wasixv2_wasix1::{PreopenRights, StartupDescriptors, StartupInput, abi::fs::Rights};
    use wasmer::{AsStoreAsync, AsStoreMut, Module, Store};

    let reduced = (Rights::PATH_OPEN
        | Rights::FD_READDIR
        | Rights::FD_FILESTAT_GET
        | Rights::FD_FDSTAT_SET_FLAGS)
        .0;
    let module = |body: &str| {
        format!(
            r#"(module
      (import "wasix_32v1" "proc_exec3" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
      (import "wasix_32v1" "proc_fork_env" (func $vfork (param i32) (result i32)))
      (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
      (import "wasix_32v1" "fd_renumber" (func $renumber (param i32 i32) (result i32)))
      (import "wasix_32v1" "fd_close" (func $close (param i32) (result i32)))
      (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
      (import "wasix_32v1" "fd_fdflags_set" (func $setflags (param i32 i32) (result i32)))
      (import "wasix_32v1" "fd_fdflags_get" (func $getflags (param i32 i32) (result i32)))
      (import "wasix_32v1" "fd_fdstat_set_rights" (func $reduce (param i32 i64 i64) (result i32)))
      (import "wasix_32v1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
      (import "wasix_32v1" "fd_prestat_get" (func $prestat (param i32 i32) (result i32)))
      (import "wasix_32v1" "fd_prestat_dir_name" (func $name (param i32 i32 i32) (result i32)))
      (import "wasix_32v1" "fd_readdir" (func $readdir (param i32 i32 i32 i64 i32) (result i32)))
      (import "wasix_32v1" "args_sizes_get" (func $argc (param i32 i32) (result i32)))
      (import "wasix_32v1" "args_get" (func $argv (param i32 i32) (result i32)))
      (import "wasix_32v1" "environ_sizes_get" (func $envc (param i32 i32) (result i32)))
      (import "wasix_32v1" "environ_get" (func $env (param i32 i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 3000) "/opaque//alias")
      (data (i32.const 3040) "/prog/child.wasm")
      (data (i32.const 3080) "child\n")
      (data (i32.const 3100) "NEW=yes\n")
      (data (i32.const 3140) "/prog/grand.wasm")
      (data (i32.const 3180) "again\n")
      (data (i32.const 3200) "NEXT=ok\n")
      (data (i32.const 3240) "OLD=kernel")
      (func $check (param $step i32) (param $actual i32) (param $expected i32)
        (if (i32.ne (local.get $actual) (local.get $expected))
          (then (call $exit (local.get $step)))))
      (func $bytes (param $step i32) (param $actual i32) (param $expected i32) (param $len i32)
        (local $i i32)
        (loop $next
          (if (i32.lt_u (local.get $i) (local.get $len)) (then
            (call $check (local.get $step)
              (i32.load8_u (i32.add (local.get $actual) (local.get $i)))
              (i32.load8_u (i32.add (local.get $expected) (local.get $i))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $next)))))
      (func (export "_start")
        {body}
        (call $exit (i32.const 0))))"#
        )
    };
    let parent = module(&format!(
        r#"
        ;; Directory duplicates retain their name and their own reduced rights/flags.
        (call $check (i32.const 1) (call $renumber (i32.const 4) (i32.const 20)) (i32.const 0))
        (call $check (i32.const 2) (call $reduce (i32.const 20) (i64.const {reduced}) (i64.const 0)) (i32.const 0))
        (call $check (i32.const 3) (call $setflags (i32.const 20) (i32.const 1)) (i32.const 0))
        ;; Stdio's object kind follows a duplicate at any number, and remains replaceable.
        (call $check (i32.const 4) (call $renumber (i32.const 0) (i32.const 21)) (i32.const 0))
        (call $check (i32.const 5) (call $renumber (i32.const 4) (i32.const 21)) (i32.const 0))
        (call $check (i32.const 6) (call $renumber (i32.const 0) (i32.const 22)) (i32.const 0))
        (call $check (i32.const 7) (call $setflags (i32.const 22) (i32.const 1)) (i32.const 0))
        (call $check (i32.const 8) (call $renumber (i32.const 4) (i32.const 0)) (i32.const 0))
        ;; dup2 validates the source before rejecting a protected target.
        (call $check (i32.const 14) (call $renumber (i32.const -1) (i32.const 0)) (i32.const 8))
        ;; A directory at fd0 is still protected, unlike a stdio object at fd22.
        (call $check (i32.const 9) (call $renumber (i32.const 1) (i32.const 0)) (i32.const 58))
        ;; Ordinary descriptors retain the kernel's real CLOEXEC behavior.
        (call $check (i32.const 10) (call $pipe (i32.const 0) (i32.const 4)) (i32.const 0))
        (call $check (i32.const 11) (call $renumber (i32.load (i32.const 0)) (i32.const 30)) (i32.const 0))
        (call $check (i32.const 12) (call $setflags (i32.const 30) (i32.const 1)) (i32.const 0))
        (drop (call $close (i32.load (i32.const 0))))
        (drop (call $close (i32.load (i32.const 4))))
        (drop (call $exec (i32.const 3040) (i32.const 16) (i32.const 3080) (i32.const 6)
          (i32.const 3100) (i32.const 8) (i32.const 0) (i32.const 0) (i32.const 0)))
        (call $exit (i32.const 13))"#
    ));
    let child = module(&format!(
        r#"
        (call $check (i32.const 40) (call $argc (i32.const 0) (i32.const 4)) (i32.const 0))
        (call $check (i32.const 41) (i32.load (i32.const 0)) (i32.const 1))
        (call $check (i32.const 42) (i32.load (i32.const 4)) (i32.const 6))
        (call $check (i32.const 43) (call $argv (i32.const 8) (i32.const 64)) (i32.const 0))
        (call $bytes (i32.const 44) (i32.load (i32.const 8)) (i32.const 3080) (i32.const 5))
        (call $check (i32.const 45) (call $envc (i32.const 0) (i32.const 4)) (i32.const 0))
        (call $check (i32.const 46) (i32.load (i32.const 0)) (i32.const 2))
        (call $check (i32.const 47) (i32.load (i32.const 4)) (i32.const 19))
        (call $check (i32.const 48) (call $env (i32.const 8) (i32.const 64)) (i32.const 0))
        (call $bytes (i32.const 49) (i32.load (i32.const 8)) (i32.const 3240) (i32.const 10))
        (call $bytes (i32.const 100) (i32.load (i32.const 12)) (i32.const 3100) (i32.const 7))
        (call $check (i32.const 50) (call $readdir (i32.const 3) (i32.const 1000) (i32.const 256) (i64.const 0) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 51) (i32.load (i32.const 0)) (i32.const 38))
        (call $check (i32.const 52) (i32.load (i32.const 1016)) (i32.const 14))
        (call $bytes (i32.const 53) (i32.const 1024) (i32.const 3000) (i32.const 14))
        (call $check (i32.const 54) (call $prestat (i32.const 20) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 55) (i32.load (i32.const 4)) (i32.const 13))
        (call $check (i32.const 56) (call $name (i32.const 20) (i32.const 64) (i32.const 13)) (i32.const 0))
        (call $bytes (i32.const 57) (i32.const 64) (i32.const 3001) (i32.const 13))
        (call $check (i32.const 58) (call $stat (i32.const 20) (i32.const 128)) (i32.const 0))
        (if (i64.ne (i64.load (i32.const 136)) (i64.const {reduced})) (then (call $exit (i32.const 59))))
        (if (i64.ne (i64.load (i32.const 144)) (i64.const 0)) (then (call $exit (i32.const 60))))
        (call $check (i32.const 61) (call $getflags (i32.const 20) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 62) (i32.load16_u (i32.const 0)) (i32.const 1))
        (call $check (i32.const 63) (call $getflags (i32.const 4) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 64) (i32.load16_u (i32.const 0)) (i32.const 0))
        (call $check (i32.const 65) (call $prestat (i32.const 0) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 66) (call $prestat (i32.const 21) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 67) (call $prestat (i32.const 22) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 68) (i32.load (i32.const 4)) (i32.const 5))
        (call $check (i32.const 69) (call $name (i32.const 22) (i32.const 64) (i32.const 5)) (i32.const 54))
        (call $check (i32.const 70) (call $close (i32.const 22)) (i32.const 0))
        (call $check (i32.const 71) (call $stat (i32.const 22) (i32.const 128)) (i32.const 8))
        (call $check (i32.const 72) (call $stat (i32.const 30) (i32.const 128)) (i32.const 8))
        ;; Reusing a former stdio slot must not resurrect its previous announced name.
        (call $check (i32.const 73) (call $pipe (i32.const 0) (i32.const 4)) (i32.const 0))
        (call $check (i32.const 74) (call $renumber (i32.load (i32.const 0)) (i32.const 22)) (i32.const 0))
        (call $check (i32.const 75) (call $prestat (i32.const 22) (i32.const 64)) (i32.const 8))
        (drop (call $exec (i32.const 3140) (i32.const 16) (i32.const 3180) (i32.const 6)
          (i32.const 3200) (i32.const 8) (i32.const 0) (i32.const 0) (i32.const 0)))
        (call $exit (i32.const 76))"#
    ));
    let grandchild = module(&format!(
        r#"
        (call $check (i32.const 80) (call $argc (i32.const 0) (i32.const 4)) (i32.const 0))
        (call $check (i32.const 81) (i32.load (i32.const 0)) (i32.const 1))
        (call $check (i32.const 82) (call $argv (i32.const 8) (i32.const 64)) (i32.const 0))
        (call $bytes (i32.const 83) (i32.load (i32.const 8)) (i32.const 3180) (i32.const 5))
        (call $check (i32.const 84) (call $envc (i32.const 0) (i32.const 4)) (i32.const 0))
        (call $check (i32.const 85) (i32.load (i32.const 0)) (i32.const 3))
        (call $check (i32.const 101) (i32.load (i32.const 4)) (i32.const 27))
        (call $check (i32.const 86) (call $env (i32.const 8) (i32.const 64)) (i32.const 0))
        (call $bytes (i32.const 102) (i32.load (i32.const 8)) (i32.const 3240) (i32.const 10))
        (call $bytes (i32.const 103) (i32.load (i32.const 12)) (i32.const 3100) (i32.const 7))
        (call $bytes (i32.const 87) (i32.load (i32.const 16)) (i32.const 3200) (i32.const 7))
        (call $check (i32.const 88) (call $readdir (i32.const 3) (i32.const 1000) (i32.const 256) (i64.const 0) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 89) (i32.load (i32.const 0)) (i32.const 38))
        (call $bytes (i32.const 90) (i32.const 1024) (i32.const 3000) (i32.const 14))
        (call $check (i32.const 91) (call $name (i32.const 20) (i32.const 64) (i32.const 13)) (i32.const 0))
        (call $bytes (i32.const 92) (i32.const 64) (i32.const 3001) (i32.const 13))
        (call $check (i32.const 93) (call $stat (i32.const 20) (i32.const 128)) (i32.const 0))
        (if (i64.ne (i64.load (i32.const 136)) (i64.const {reduced})) (then (call $exit (i32.const 94))))
        (if (i64.ne (i64.load (i32.const 144)) (i64.const 0)) (then (call $exit (i32.const 95))))
        (call $check (i32.const 96) (call $getflags (i32.const 20) (i32.const 0)) (i32.const 0))
        (call $check (i32.const 97) (i32.load16_u (i32.const 0)) (i32.const 1))
        (call $check (i32.const 98) (call $prestat (i32.const 22) (i32.const 0)) (i32.const 8))
        (call $check (i32.const 99) (call $stat (i32.const 30) (i32.const 128)) (i32.const 8))"#
    ));
    let programs = Programs::new(
        "prepared-exec",
        &[("child.wasm", &child), ("grand.wasm", &grandchild)],
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
      for vfork in [false, true] {
        let parent = if vfork {
            parent.replace("(drop (call $exec", "(call $check (i32.const 15) (call $vfork (i32.const 400)) (i32.const 0)) (drop (call $exec")
                .replace("(call $exit (i32.const 13))", r#"
                    (i32.store8 (i32.const 420) (i32.const 1))
                    (i32.store (i32.const 424) (i32.load (i32.const 400)))
                    (call $check (i32.const 16) (call $join (i32.const 420) (i32.const 0) (i32.const 440)) (i32.const 0))
                    (call $check (i32.const 17) (i32.load16_u (i32.const 442)) (i32.const 0))
                    (call $exit (i32.const 0))"#)
        } else { parent.clone() };
        let machine = Arc::new(Machine::new());
        let source = machine.capture_host_directory(&programs.0, false).unwrap();
        let (mut process, boot) = machine
            .start_embedding_with_namespace(
                ProcessConfig {
                    args: vec!["kernel-parent".into()],
                    env: vec!["OLD=kernel".into()],
                    stdio: Stdio::from_fns(|_| {}, |_| {}),
                },
                NamespaceBootstrap {
                    directories: vec![DirectoryBootstrap {
                        source,
                        lookup_name: Some(b"prog".to_vec()),
                        attachment: Some(
                            PreopenRights::ALL
                                .named_attachment(b"opaque//alias")
                                .unwrap(),
                        ),
                    }],
                    root_attachment: Some(PreopenRights::ALL.named_attachment(b"/").unwrap()),
                    root_fallback: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            boot.descriptors.iter().map(|fd| fd.0).collect::<Vec<_>>(),
            [3, 4]
        );
        let wasi = process.wasix1().unwrap();
        let mut store = Store::default();
        let owner = wasmer::sys::NativeCleanupOwner::new();
        let mut generation = wasmer::sys::NativeInvocationScope::bind_with_cleanup(
            &mut store, Some(owner),
        ).unwrap();
        let environment = HostEnvironment::new(
            &mut store.as_store_mut(),
            process.syscalls(),
            process.task(),
            process.host(),
            process.abis(),
        );
        environment.set_binding(&mut store.as_store_mut(), wasi.unattached());
        assert!(environment.environment().as_ref(&store).memory().is_none());
        let asynchronous = store.into_async();
        let input = StartupInput {
            args: vec![b"explicit-old".to_vec()],
            env: vec![b"OLD=explicit".to_vec()],
            preopens: vec![(vec![], b"/".to_vec()), (vec![], b"opaque//alias".to_vec())],
        };
        let descriptors = StartupDescriptors {
            virtual_root: Some(boot.descriptors[0]),
            descriptors: boot.descriptors,
            binding: boot.binding,
        };
        let foreign = Store::default().into_async();
        assert!(matches!(
            wasi.configure_and_prepare_startup(
                &foreign,
                &environment,
                input.clone(),
                descriptors.clone()
            )
            .await,
            Err(wasixv2_wasix1::StartupPreparationError::Configuration(
                wasixv2_abi::Errno::EINVAL
            ))
        ));
        drop(foreign);
        let unrelated = wasixv2_wasix1::Wasix1::new().host_process(process.task());
        assert!(matches!(
            unrelated
                .configure_and_prepare_startup(
                    &asynchronous,
                    &environment,
                    input.clone(),
                    descriptors.clone()
                )
                .await,
            Err(wasixv2_wasix1::StartupPreparationError::Configuration(
                wasixv2_abi::Errno::EINVAL
            ))
        ));
        drop(unrelated);
        wasi.configure_and_prepare_startup(&asynchronous, &environment, input, descriptors)
            .await
            .unwrap();
        assert_eq!(
            wasi.set_startup_input(StartupInput::default()),
            Err(wasixv2_abi::Errno::EBUSY)
        );
        let cleanup =
            local_cleanup_runner(&asynchronous, environment.loader_cleanup().clone()).unwrap();
        cleanup
            .run(async {
                let mut guard = asynchronous.write_lock().await;
                assert!(environment.environment().as_ref(&guard).memory().is_none());
                environment.deactivate(&mut guard.as_store_mut());
            })
            .await;
        drop(environment);
        generation.close_and_wait_for_cleanup().await;
        drop(asynchronous.write_lock().await);
        drop(generation);
        let store = asynchronous
            .into_store()
            .expect("preparation retains no async Store");
        // Native generations permanently tag their original Store. This runner
        // fixture transfers prepared process policy to a fresh image Store,
        // exactly as exec images do; it does not emulate the public C API driver.
        let engine = store.engine().clone();
        drop(store);
        let store = Store::new(engine);
        let module = Module::new(&store, wat::parse_str(parent).unwrap()).unwrap();
        let result = run_with_abis(
            store,
            &module,
            process.syscalls(),
            process.task(),
            process.host(),
            process.abis(),
        )
        .await;
        process.close();
        machine.shutdown().await;
        assert_eq!(result.unwrap(), 0, "vfork child: {vfork}");
      }
    });
}

/// Without a terminal on stdio, `tty_get` reports none and v1's default size; the modes
/// `tty_set` stores come back.
#[test]
fn tty() {
    let wat = r#"
    (module
      (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
      (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 1))))
        (if (i32.ne (i32.load (i32.const 100)) (i32.const 80)) (then (call $exit (i32.const 2))))
        (if (i32.ne (i32.load (i32.const 104)) (i32.const 25)) (then (call $exit (i32.const 3))))
        (if (i32.load8_u (i32.const 117)) (then (call $exit (i32.const 4))))
        ;; echo on
        (i32.store8 (i32.const 119) (i32.const 1))
        (if (call $set (i32.const 100)) (then (call $exit (i32.const 5))))
        (i32.store8 (i32.const 119) (i32.const 0))
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 6))))
        (if (i32.ne (i32.load8_u (i32.const 119)) (i32.const 1)) (then (call $exit (i32.const 7))))
        (call $exit (i32.const 0))))
    "#;
    assert_eq!(status(wat), 0);
}

/// On the console, a terminal, `tty_get` reports it on every stdio descriptor with its size
/// and the terminal's modes, which `tty_set` changes: canonical mode and echo, on by default.
#[test]
fn tty_on_the_console() {
    let wat = r#"
    (module
      (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
      (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 1))))
        (if (i32.ne (i32.load (i32.const 100)) (i32.const 132)) (then (call $exit (i32.const 2))))
        (if (i32.ne (i32.load (i32.const 104)) (i32.const 43)) (then (call $exit (i32.const 3))))
        ;; stdin, stdout and stderr are terminals; echo and line buffering are on
        (if (i32.ne (i32.load (i32.const 116)) (i32.const 0x01010101))
          (then (call $exit (i32.const 4))))
        (if (i32.eqz (i32.load8_u (i32.const 120))) (then (call $exit (i32.const 5))))
        ;; raw: echo and line buffering off
        (i32.store16 (i32.const 119) (i32.const 0))
        (if (call $set (i32.const 100)) (then (call $exit (i32.const 6))))
        (i32.store16 (i32.const 119) (i32.const 0x0101))
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 7))))
        (if (i32.load16_u (i32.const 119)) (then (call $exit (i32.const 8))))
        (call $exit (i32.const 0))))
    "#;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let status = tokio::task::LocalSet::new().block_on(&runtime, async {
        let screen = Arc::new(Capture::default());
        // Nothing is typed: the input never ends, which would hang the console up.
        let console = Console {
            input: Arc::new(Silence),
            output: screen,
            size: WindowSize {
                rows: 43,
                cols: 132,
                xpixel: 0,
                ypixel: 0,
            },
        };
        let machine = Machine::builder().console(console, [true; 3]).build();
        let stdio = Stdio {
            stdin: Arc::new(EmptySource),
            stdout: Arc::new(Capture::default()),
            stderr: Arc::new(Capture::default()),
        };
        machine
            .run(&wat::parse_str(wat).unwrap(), stdio)
            .await
            .unwrap()
    });
    assert_eq!(status, 0);
}

/// Guest and host sizing share terminal state; v1 leaves SIGWINCH default-ignored.
/// Kernel TTY tests cover actual notification and same-size signal suppression.
#[test]
fn tty_resize_and_host_resize_share_the_console_state() {
    let wat = r#"
    (module
      (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
      (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
      (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 16) "__wasm_signal")
      (data (i32.const 64) "x")
      (global $resizes (mut i32) (i32.const 0))
      (func (export "__wasm_signal") (param $sig i32)
        (if (i32.eq (local.get $sig) (i32.const 28))
          (then (global.set $resizes (i32.add (global.get $resizes) (i32.const 1))))))
      (func $check (param $condition i32) (param $status i32)
        (if (i32.eqz (local.get $condition)) (then (call $exit (local.get $status)) unreachable)))
      (func (export "_start")
        (call $callback (i32.const 16) (i32.const 13))
        (call $check (i32.eqz (call $get (i32.const 100))) (i32.const 1))
        ;; Real zero dimensions stay zero, including rows/columns and unknown pixels.
        (call $check (i32.eqz (i32.load (i32.const 100))) (i32.const 2))
        (call $check (i32.eqz (i32.load (i32.const 104))) (i32.const 3))
        (call $check (i32.eqz (i32.load (i32.const 108))) (i32.const 4))
        (call $check (i32.eqz (i32.load (i32.const 112))) (i32.const 5))
        ;; Guest tty_set updates the console; v1 keeps SIGWINCH default-ignored.
        (i32.store (i32.const 100) (i32.const 120))
        (i32.store (i32.const 104) (i32.const 40))
        (i32.store (i32.const 108) (i32.const 960))
        (i32.store (i32.const 112) (i32.const 640))
        (call $check (i32.eqz (call $set (i32.const 100))) (i32.const 6))
        (call $check (i32.eq (global.get $resizes) (i32.const 0)) (i32.const 7))
        (call $check (i32.eqz (call $get (i32.const 100))) (i32.const 8))
        (call $check (i32.eq (i32.load (i32.const 100)) (i32.const 120)) (i32.const 9))
        (call $check (i32.eq (i32.load (i32.const 104)) (i32.const 40)) (i32.const 10))
        (call $check (i32.eq (i32.load (i32.const 108)) (i32.const 960)) (i32.const 11))
        (call $check (i32.eq (i32.load (i32.const 112)) (i32.const 640)) (i32.const 12))
        ;; A real output call asks the host to resize the same console to 90x30.
        (i32.store (i32.const 200) (i32.const 64))
        (i32.store (i32.const 204) (i32.const 1))
        (call $check (i32.eqz (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208))) (i32.const 13))
        (call $check (i32.eq (global.get $resizes) (i32.const 0)) (i32.const 14))
        (call $check (i32.eqz (call $get (i32.const 100))) (i32.const 15))
        (call $check (i32.eq (i32.load (i32.const 100)) (i32.const 90)) (i32.const 16))
        (call $check (i32.eq (i32.load (i32.const 104)) (i32.const 30)) (i32.const 17))
        (call $check (i32.eq (i32.load (i32.const 108)) (i32.const 720)) (i32.const 18))
        (call $check (i32.eq (i32.load (i32.const 112)) (i32.const 480)) (i32.const 19))
        ;; Same-size host and guest updates also leave v1's callback quiet.
        (call $check (i32.eqz (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208))) (i32.const 20))
        (call $check (i32.eqz (call $set (i32.const 100))) (i32.const 21))
        (call $check (i32.eq (global.get $resizes) (i32.const 0)) (i32.const 22))
        (call $exit (i32.const 0))))
    "#;
    struct ResizeOnWrite(Mutex<std::sync::Weak<wasixv2::Signaller>>);
    impl ByteSink for ResizeOnWrite {
        fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
            let signaller = self.0.lock().unwrap().upgrade().unwrap();
            signaller.console_resize(WindowSize {
                cols: 90,
                rows: 30,
                xpixel: 720,
                ypixel: 480,
            });
            Box::pin(async move { Ok(data.len()) })
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let status = tokio::task::LocalSet::new().block_on(&runtime, async {
        let output = Arc::new(ResizeOnWrite(Mutex::default()));
        let console = Console {
            input: Arc::new(Silence),
            output: output.clone(),
            size: WindowSize::default(),
        };
        let machine = Machine::builder().console(console, [true; 3]).build();
        let signaller = Arc::new(machine.signaller());
        *output.0.lock().unwrap() = Arc::downgrade(&signaller);
        let stdio = Stdio {
            stdin: Arc::new(EmptySource),
            stdout: Arc::new(Capture::default()),
            stderr: Arc::new(Capture::default()),
        };
        machine
            .run(&wat::parse_str(wat).unwrap(), stdio)
            .await
            .unwrap()
    });
    assert_eq!(status, 0);
}

/// Public u32 sizes are admitted; the actual terminal exposes the documented low 16 bits.
#[test]
fn tty_dimensions_use_the_shared_linux_projection() {
    let wat = r#"
    (module
      (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
      (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func $round_trip (param $value i32) (param $expected i32) (param $status i32)
        (i32.store (i32.const 100) (local.get $value))
        (i32.store (i32.const 104) (local.get $value))
        (i32.store (i32.const 108) (local.get $value))
        (i32.store (i32.const 112) (local.get $value))
        (if (call $set (i32.const 100)) (then (call $exit (local.get $status))))
        (if (call $get (i32.const 100)) (then (call $exit (i32.add (local.get $status) (i32.const 1)))))
        (if (i32.ne (i32.load (i32.const 100)) (local.get $expected))
          (then (call $exit (i32.add (local.get $status) (i32.const 2)))))
        (if (i32.ne (i32.load (i32.const 104)) (local.get $expected))
          (then (call $exit (i32.add (local.get $status) (i32.const 3)))))
        (if (i32.ne (i32.load (i32.const 108)) (local.get $expected))
          (then (call $exit (i32.add (local.get $status) (i32.const 4)))))
        (if (i32.ne (i32.load (i32.const 112)) (local.get $expected))
          (then (call $exit (i32.add (local.get $status) (i32.const 5))))))
      (func (export "_start")
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 1))))
        (call $round_trip (i32.const 65535) (i32.const 65535) (i32.const 10))
        (call $round_trip (i32.const 65536) (i32.const 0) (i32.const 20))
        (call $round_trip (i32.const -1) (i32.const 65535) (i32.const 30))
        (call $round_trip (i32.const 0) (i32.const 0) (i32.const 40))
        (call $exit (i32.const 0))))
    "#;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let status = tokio::task::LocalSet::new().block_on(&runtime, async {
        let console = Console {
            input: Arc::new(Silence),
            output: Arc::new(Capture::default()),
            size: WindowSize::default(),
        };
        let machine = Machine::builder().console(console, [true; 3]).build();
        let stdio = Stdio {
            stdin: Arc::new(EmptySource),
            stdout: Arc::new(Capture::default()),
            stderr: Arc::new(Capture::default()),
        };
        machine
            .run(&wat::parse_str(wat).unwrap(), stdio)
            .await
            .unwrap()
    });
    assert_eq!(status, 0);
}

/// Without any terminal, dimensions remain the v1 defaults even after a wide request.
#[test]
fn tty_dimensions_without_a_terminal_remain_v1_defaults() {
    let wat = r#"
    (module
      (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
      (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 1))))
        (i32.store (i32.const 100) (i32.const 65535))
        (i32.store (i32.const 104) (i32.const 65536))
        (i32.store (i32.const 108) (i32.const -1))
        (i32.store (i32.const 112) (i32.const 0))
        (if (call $set (i32.const 100)) (then (call $exit (i32.const 2))))
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 3))))
        (if (i32.ne (i32.load (i32.const 100)) (i32.const 80)) (then (call $exit (i32.const 4))))
        (if (i32.ne (i32.load (i32.const 104)) (i32.const 25)) (then (call $exit (i32.const 5))))
        (if (i32.ne (i32.load (i32.const 108)) (i32.const 800)) (then (call $exit (i32.const 6))))
        (if (i32.ne (i32.load (i32.const 112)) (i32.const 600)) (then (call $exit (i32.const 7))))
        (if (i32.load8_u (i32.const 116)) (then (call $exit (i32.const 8))))
        (if (i32.load8_u (i32.const 117)) (then (call $exit (i32.const 9))))
        (if (i32.load8_u (i32.const 118)) (then (call $exit (i32.const 10))))
        (call $exit (i32.const 0))))
    "#;
    assert_eq!(status(wat), 0);
}

/// A terminal nobody types on.
struct Silence;

impl ByteSource for Silence {
    fn poll_read(
        &self,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Pending
    }
}

/// The compat state a shim finds is the calling process's, though the parent's pid is cached
/// in the instance its vfork children run in: each child changes the terminal modes of its own
/// copy, and the parent and its next child still see the parent's.
#[test]
fn vfork_children_have_their_own_compat_state() {
    let wat = r#"
    (module
      (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
      (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
      (import "wasix_32v1" "proc_fork_env" (func $vfork (param i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      ;; A vfork child: sees the parent's echo, turns it off in its own state and exits.
      (func $child
        (if (call $get (i32.const 300)) (then (call $exit (i32.const 20))))
        (if (i32.ne (i32.load8_u (i32.const 319)) (i32.const 1)) (then (call $exit (i32.const 21))))
        (i32.store8 (i32.const 319) (i32.const 0))
        (if (call $set (i32.const 300)) (then (call $exit (i32.const 22))))
        (if (call $get (i32.const 300)) (then (call $exit (i32.const 23))))
        (if (i32.load8_u (i32.const 319)) (then (call $exit (i32.const 24))))
        (call $exit (i32.const 0)))
      (func (export "_start")
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 1))))
        (i32.store8 (i32.const 119) (i32.const 1))
        (if (call $set (i32.const 100)) (then (call $exit (i32.const 2))))
        (if (call $vfork (i32.const 200)) (then (call $exit (i32.const 3))))
        ;; the parent resumes from the child's `proc_exit2`, at the end of `$child`
        (call $child)
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 4))))
        (if (i32.ne (i32.load8_u (i32.const 119)) (i32.const 1)) (then (call $exit (i32.const 5))))
        (if (call $vfork (i32.const 200)) (then (call $exit (i32.const 6))))
        (call $child)
        (if (call $get (i32.const 100)) (then (call $exit (i32.const 7))))
        (if (i32.ne (i32.load8_u (i32.const 119)) (i32.const 1)) (then (call $exit (i32.const 8))))
        (call $exit (i32.const 0))))
    "#;
    assert_eq!(status(wat), 0);
}

/// `stack_checkpoint` needs the asyncify build configuration: `NOTSUP` (58) otherwise, and so
/// is `proc_fork` without a memory copy; a real fork is the kernel's `NOSYS` (52).
#[test]
fn asyncify_calls_without_asyncify() {
    let wat = r#"
    (module
      (import "wasix_32v1" "stack_checkpoint" (func $checkpoint (param i32 i32) (result i32)))
      (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
      (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (i32.ne (call $checkpoint (i32.const 100) (i32.const 200)) (i32.const 58))
          (then (call $exit (i32.const 1))))
        (if (i32.ne (call $fork (i32.const 0) (i32.const 200)) (i32.const 58))
          (then (call $exit (i32.const 2))))
        (if (i32.ne (call $fork (i32.const 1) (i32.const 200)) (i32.const 52))
          (then (call $exit (i32.const 3))))
        (call $exit (i32.const 0))))
    "#;
    assert_eq!(status(wat), 0);
}

/// Host selection accepts incomplete/private modules, but no unsupported spawn
/// may reach kernel clone or fault a newly created child and its parent group.
#[tokio::test]
async fn unavailable_selected_thread_entries_fail_before_kernel_thread_creation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wasixv2_kernel::{Dispatch, HostClock, Kernel, SyscallEntry};
    use wasixv2_syscalls::{Caller, Layer, Layered, MaybeFuture, SysResult, Syscall, SyscallRet};
    struct Count(Arc<AtomicUsize>);
    impl Layer<Kernel> for Count {
        fn call<'a>(
            &'a self,
            caller: &'a Caller<'_>,
            call: Syscall,
            next: &'a Kernel,
        ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
            if matches!(&call, Syscall::ThreadSpawn { .. }) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            Dispatch.call(caller, call, next)
        }
    }
    for (shared, entry, expected) in [
        (true, "", 76),
        (
            true,
            "(func (export \"wasi_thread_start\") (param i64))",
            76,
        ),
        (false, "", 76),
        (
            false,
            "(func (export \"wasi_thread_start\") (param i64))",
            76,
        ),
        (
            false,
            "(func (export \"wasi_thread_start\") (param i32 i32))",
            78,
        ),
    ] {
        let source = format!(
            r#"(module
            (import "env" "memory" (memory 1 1 {memory}))
            (import "wasix_32v1" "thread_spawn_v2" (func $spawn (param i32 i32) (result i32)))
            (import "wasi" "thread-spawn" (func $wasi_spawn (param i32) (result i32)))
            (import "wasix_32v1" "proc_exit2" (func $exit (param i32)))
            {entry}
            (func (export "_start")
                i32.const 104 i32.const 12345 i32.store
                (if (i32.ne (call $spawn (i32.const 36) (i32.const 104)) (i32.const {expected}))
                    (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.load (i32.const 104)) (i32.const 12345))
                    (then (call $exit (i32.const 2))))
                (if (i32.ne (call $wasi_spawn (i32.const 36)) (i32.const -{expected}))
                    (then (call $exit (i32.const 3))))
                (call $exit (i32.const 0))))"#,
            memory = if shared { "shared" } else { "" }
        );
        let host: Arc<dyn wasixv2::Host> = Arc::new(wasixv2::TokioHost::default());
        let root = Arc::new(wasixv2_vfs_mem::MemFs::new(
            Arc::new(HostClock(host.clone())),
            0o777,
            1,
            1,
        ));
        let mut abis = wasixv2_exec::Abis::new();
        abis.push(Arc::new(wasixv2_wasix1::Wasix1::new()));
        let abis = Arc::new(abis);
        let kernel = Kernel::new(host.clone(), root).with_binfmt(abis.clone());
        let task = kernel
            .spawn(ProcessConfig {
                args: vec!["preflight".into()],
                env: vec![],
                stdio: Stdio::from_fns(|_| {}, |_| {}),
            })
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let syscalls = Arc::new(Layered::new(SyscallEntry(Count(calls.clone())), kernel));
        let store = wasmer::Store::default();
        let module = wasixv2_exec::load(store.engine(), &wat::parse_str(source).unwrap()).unwrap();
        let result = wasixv2_exec::run_with_abis(store, &module, syscalls, task, host, abis).await;
        assert_eq!(result.unwrap(), 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "preflight precedes kernel thread creation"
        );
    }
}
