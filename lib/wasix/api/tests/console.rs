//! A machine with the host's console: programs read what is typed through the kernel's line
//! discipline, and `^C` interrupts the console's foreground process group.

#![recursion_limit = "256"]

use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::sync::mpsc;
use wasixv2::{
    ByteSink, ByteSource, Console, EmptySource, LocalFuture, Machine, Stdio, WindowSize,
};

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl Capture {
    fn contents(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

/// The host's terminal: what the test types.
struct Keyboard(Mutex<mpsc::UnboundedReceiver<Vec<u8>>>);

impl ByteSource for Keyboard {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut input = self.0.lock().unwrap();
        let Some(data) = std::task::ready!(input.poll_recv(cx)) else {
            return Poll::Ready(Ok(0));
        };
        buf[..data.len()].copy_from_slice(&data);
        Poll::Ready(Ok(data.len()))
    }
}

/// A machine whose console shows on `screen` what the returned sender types.
fn console_machine(screen: &Arc<Capture>) -> (Machine, mpsc::UnboundedSender<Vec<u8>>) {
    let (keys, input) = mpsc::unbounded_channel();
    let console = Console {
        input: Arc::new(Keyboard(Mutex::new(input))),
        output: screen.clone(),
        size: WindowSize {
            rows: 33,
            cols: 100,
            xpixel: 0,
            ypixel: 0,
        },
    };
    let machine = Machine::builder().console(console, [true; 3]).build();
    (machine, keys)
}

/// Stdio that must not be used: the console takes descriptors 0 to 2.
fn unused_stdio() -> (Stdio, Arc<Capture>) {
    let unused = Arc::new(Capture::default());
    let stdio = Stdio {
        stdin: Arc::new(EmptySource),
        stdout: unused.clone(),
        stderr: unused.clone(),
    };
    (stdio, unused)
}

/// Writes `ready\n`, reads a line from descriptor 0 and writes it back to descriptor 1, then
/// exits with the console's row count if it is its controlling terminal with its own group
/// in the foreground, or 99.
const LINE_WAT: &str = r#"
  (module
    (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
    (import "wasixv2" "ioctl" (func $ioctl (param i32 i32 i32) (result i32)))
    (import "wasixv2" "getpid" (func $getpid (result i32)))
    (import "wasixv2" "exit_group" (func $exit_group (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 16) "ready\n")
    (func (export "_start") (local $n i32)
      (drop (call $write (i32.const 1) (i32.const 16) (i32.const 6)))
      (local.set $n (call $read (i32.const 0) (i32.const 64) (i32.const 32)))
      (drop (call $write (i32.const 1) (i32.const 64) (local.get $n)))
      ;; TIOCGPGRP into 128, TIOCGWINSZ into 136.
      (if (i32.or
            (call $ioctl (i32.const 0) (i32.const 0x540f) (i32.const 128))
            (i32.ne (i32.load (i32.const 128)) (call $getpid)))
        (then (call $exit_group (i32.const 99))))
      (drop (call $ioctl (i32.const 2) (i32.const 0x5413) (i32.const 136)))
      (call $exit_group (i32.load16_u (i32.const 136)))
      unreachable))
"#;

async fn shown(screen: &Capture, what: &[u8]) {
    while !screen.contents().ends_with(what) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// What the host types is echoed and edited by the kernel and read as a line; the program's
/// output gets CR LF; the console is the program's controlling terminal, with its size.
#[tokio::test]
async fn a_program_reads_what_is_typed_on_the_console() {
    let screen = Arc::new(Capture::default());
    let (machine, keys) = console_machine(&screen);
    let wasm = wat::parse_str(LINE_WAT).unwrap();
    let (stdio, unused) = unused_stdio();
    let typing = async {
        shown(&screen, b"ready\r\n").await;
        keys.send(b"hix\x7f\r".to_vec()).unwrap();
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(machine.run(&wasm, stdio), typing)
    })
    .await
    .expect("the program read its line");

    assert_eq!(status.unwrap(), 33);
    assert_eq!(screen.contents(), b"ready\r\nhix\x08 \x08\r\nhi\r\n");
    assert!(unused.contents().is_empty());
}

/// Writes `ready\n` and waits for input forever.
const WAIT_WAT: &str = r#"
  (module
    (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 16) "ready\n")
    (func (export "_start")
      (drop (call $write (i32.const 1) (i32.const 16) (i32.const 6)))
      (loop $forever
        (drop (call $read (i32.const 0) (i32.const 64) (i32.const 32)))
        (br $forever))))
"#;

/// `^C` typed on the console kills a program with SIGINT's default action, and is echoed.
#[tokio::test]
async fn ctrl_c_on_the_console_interrupts_the_program() {
    let screen = Arc::new(Capture::default());
    let (machine, keys) = console_machine(&screen);
    let wasm = wat::parse_str(WAIT_WAT).unwrap();
    let (stdio, _) = unused_stdio();
    let typing = async {
        shown(&screen, b"ready\r\n").await;
        keys.send(b"\x03".to_vec()).unwrap();
        // The discipline signals the foreground group before it writes the echo, as Linux's
        // n_tty does (`isig`, then `echo_char`), so the program can be gone before it shows.
        shown(&screen, b"^C").await;
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(machine.run(&wasm, stdio), typing)
    })
    .await
    .expect("the program died");

    assert_eq!(status.unwrap(), 128 + 2);
    assert_eq!(screen.contents(), b"ready\r\n^C");
}

/// A terminal that shows each write only `delay` after it was made, as a slow line does.
struct SlowScreen {
    shown: Capture,
    delay: Duration,
}

impl ByteSink for SlowScreen {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.shown.write(data).await
        })
    }
}

/// The echo of the `^C` that ends a program reaches the host before the run returns, however
/// slowly the host takes it, as Linux's close of a console waits for its output to be sent
/// (`hvc_close`, `tty_wait_until_sent`): an embedder that exits right after loses nothing.
#[tokio::test]
async fn the_run_ends_once_the_echo_of_ctrl_c_is_shown() {
    let screen = Arc::new(SlowScreen {
        shown: Capture::default(),
        delay: Duration::from_millis(300),
    });
    let (keys, input) = mpsc::unbounded_channel();
    let console = Console {
        input: Arc::new(Keyboard(Mutex::new(input))),
        output: screen.clone(),
        size: WindowSize::default(),
    };
    let machine = Machine::builder().console(console, [true; 3]).build();
    let wasm = wat::parse_str(WAIT_WAT).unwrap();
    let (stdio, _) = unused_stdio();
    let typing = async {
        shown(&screen.shown, b"ready\r\n").await;
        keys.send(b"\x03".to_vec()).unwrap();
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(machine.run(&wasm, stdio), typing)
    })
    .await
    .expect("the program died");

    assert_eq!(status.unwrap(), 128 + 2);
    assert_eq!(screen.shown.contents(), b"ready\r\n^C");
}

/// The signaller's terminal signals go to the console's foreground process group, and a
/// hangup of the console sends its session leader SIGHUP.
#[tokio::test]
async fn the_signaller_reaches_the_console() {
    for (sig, status) in [(Some(3), 128 + 3), (None, 128 + 1)] {
        let screen = Arc::new(Capture::default());
        let (machine, _keys) = console_machine(&screen);
        let signaller = machine.signaller();
        let wasm = wat::parse_str(WAIT_WAT).unwrap();
        let (stdio, _) = unused_stdio();
        let signalling = async {
            shown(&screen, b"ready\r\n").await;
            match sig {
                Some(sig) => assert!(signaller.signal_foreground(sig).unwrap()),
                None => signaller.console_hangup(),
            }
        };
        let (run, ()) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(machine.run(&wasm, stdio), signalling)
        })
        .await
        .expect("the program died");
        assert_eq!(run.unwrap(), status);
    }
}

/// Observing the guest exit is distinct from waiting for terminal delivery.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[tokio::test]
async fn admitted_observer_preserves_exit_while_console_delivery_is_pending() {
    use std::sync::atomic::{AtomicBool, Ordering};
    #[derive(Default)]
    struct GuestGate(Mutex<Option<wasixv2::ThreadStart>>);
    impl wasixv2::Executor for GuestGate {
        fn spawn_local(&self, future: LocalFuture<'static, ()>) {
            wasixv2::Executor::spawn_local(&wasixv2::TokioHost::default(), future);
        }
        fn spawn_thread(&self, start: wasixv2::ThreadStart) -> io::Result<()> {
            assert!(self.0.lock().unwrap().replace(start).is_none());
            Ok(())
        }
        fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
            wasixv2::Executor::spawn_blocking(&wasixv2::TokioHost::default(), work)
        }
    }

    struct GatedScreen {
        entered: AtomicBool,
        released: AtomicBool,
        changed: tokio::sync::Notify,
    }
    impl ByteSink for GatedScreen {
        fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
            Box::pin(async move {
                self.entered.store(true, Ordering::Release);
                loop {
                    let changed = self.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if self.released.load(Ordering::Acquire) {
                        break;
                    }
                    changed.await;
                }
                Ok(data.len())
            })
        }
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            let screen = Arc::new(GatedScreen {
                entered: AtomicBool::new(false),
                released: AtomicBool::new(false),
                changed: tokio::sync::Notify::new(),
            });
            let (keys, input) = mpsc::unbounded_channel();
            let console = Console {
                input: Arc::new(Keyboard(Mutex::new(input))),
                output: screen.clone(),
                size: WindowSize::default(),
            };
            let gate = Arc::new(GuestGate::default());
            let machine = Arc::new(
                Machine::builder()
                    .task_executor(gate.clone())
                    .console(console, [true; 3])
                    .build(),
            );
            let engine = wasmer::Engine::default();
            let wasm = wat::parse_str(
                r#"(module
            (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
            (import "wasixv2" "exit_group" (func $exit (param i32)))
            (memory (export "memory") 1)
            (func (export "_start")
                (drop(call $read (i32.const 0)(i32.const 16)(i32.const 16)))
                (call $exit (i32.const 0))))"#,
            )
            .unwrap();
            let module = wasixv2::load(&engine, &wasm).unwrap();
            let (stdio, _) = unused_stdio();
            let run = wasixv2::spawn(
                machine.clone(),
                engine,
                module,
                wasixv2::ProcessConfig {
                    args: vec![],
                    env: vec![],
                    stdio,
                },
            )
            .await
            .unwrap();
            let observer = run.observer();
            // Admit the process, but let the input pump take the echo buffer
            // before the guest can compete for it in Tty::read::flush_echoes.
            keys.send(b"done\n".to_vec()).unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                while !screen.entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("console pump entered the gated echo write");
            let factory = gate.0.lock().unwrap().take().unwrap();
            wasixv2::Executor::spawn_thread(&wasixv2::TokioHost::default(), factory).unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                while observer.observed_result().is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("guest exited while only console delivery was pending");
            assert_eq!(observer.observed_result().unwrap().unwrap(), 0);
            let mut waiting = Box::pin(run.wait());
            assert!(futures_util::poll!(&mut waiting).is_pending());
            run.signaller().signal(9).unwrap();
            assert_eq!(observer.observed_result().unwrap().unwrap(), 0);
            assert!(futures_util::poll!(&mut waiting).is_pending());
            screen.released.store(true, Ordering::Release);
            screen.changed.notify_waiters();
            assert_eq!(waiting.await.unwrap(), 0);
            machine.shutdown().await;
        })
        .await;
}

/// Console output processing is retained while each process owns its original
/// stdout/stderr destinations; echo belongs only to the host console.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[tokio::test]
async fn console_stdio_outputs_use_each_admissions_original_sinks_and_keep_echo_separate() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let screen = Arc::new(Capture::default());
            let (keys, input) = mpsc::unbounded_channel();
            let machine = Arc::new(
                Machine::builder()
                    .console(
                        Console {
                            input: Arc::new(Keyboard(Mutex::new(input))),
                            output: screen.clone(),
                            size: WindowSize::default(),
                        },
                        [true; 3],
                    )
                    .console_stdio_outputs(true)
                    .build(),
            );
            let engine = wasmer::Engine::default();
            let wasm = wat::parse_str(
                r#"(module
                (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
                (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
                (import "wasixv2" "exit_group" (func $exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 16) "ready\nerror\n")
                (func (export "_start") (local $n i32)
                    (drop(call $write (i32.const 1)(i32.const 16)(i32.const 6)))
                    (drop(call $write (i32.const 2)(i32.const 22)(i32.const 6)))
                    (local.set $n (call $read (i32.const 0)(i32.const 64)(i32.const 32)))
                    (drop(call $write (i32.const 1)(i32.const 64)(local.get $n)))
                    (call $exit (i32.const 0))))"#,
            )
            .unwrap();
            let module = wasixv2::load(&engine, &wasm).unwrap();
            let mut retained = Vec::new();
            for line in [b"first\n".as_slice(), b"second\n".as_slice()] {
                let stdout = Arc::new(Capture::default());
                let stderr = Arc::new(Capture::default());
                let run = wasixv2::spawn(
                    machine.clone(),
                    engine.clone(),
                    module.clone(),
                    wasixv2::ProcessConfig {
                        args: vec![],
                        env: vec![],
                        stdio: Stdio {
                            stdin: Arc::new(EmptySource),
                            stdout: stdout.clone(),
                            stderr: stderr.clone(),
                        },
                    },
                )
                .await
                .unwrap();
                tokio::time::timeout(Duration::from_secs(10), async {
                    shown(&stdout, b"ready\r\n").await;
                    shown(&stderr, b"error\r\n").await;
                    keys.send(line.to_vec()).unwrap();
                    assert_eq!(run.wait().await.unwrap(), 0);
                })
                .await
                .expect("admitted guest must read the console and retire its output");
                let expected = [b"ready\r\n".as_slice(), &line[..line.len() - 1], b"\r\n"].concat();
                assert_eq!(stdout.contents(), expected);
                assert_eq!(stderr.contents(), b"error\r\n");
                retained.push((stdout, expected, stderr));
            }
            assert_eq!(screen.contents(), b"first\r\nsecond\r\n");
            for (stdout, expected, stderr) in retained {
                assert_eq!(
                    stdout.contents(),
                    expected,
                    "a later admission must not reuse an earlier sink"
                );
                assert_eq!(stderr.contents(), b"error\r\n");
            }
            machine.shutdown().await;
        })
        .await;
}

/// Root layering reboots the kernel; both console policies must survive that
/// reboot, while an unselected descriptor keeps ordinary Stdio semantics.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[tokio::test]
async fn finite_console_input_and_selected_stdio_outputs_survive_root_layering() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let screen = Arc::new(Capture::default());
            let mut machine = Machine::builder()
                .console_input_eof(wasixv2::ConsoleInputEof::Finite)
                .console_stdio_outputs(true)
                .console(
                    Console {
                        input: Arc::new(EmptySource),
                        output: screen.clone(),
                        size: WindowSize::default(),
                    },
                    [true, true, false],
                )
                .build();
            let wasm = wat::parse_str(
                r#"(module
                (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
                (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
                (import "wasixv2" "exit_group" (func $exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 16) "out\nerr\n")
                (func (export "_start")
                    (if (call $read (i32.const 0)(i32.const 64)(i32.const 32))
                        (then(call $exit (i32.const 99))))
                    (drop(call $write (i32.const 1)(i32.const 16)(i32.const 4)))
                    (drop(call $write (i32.const 2)(i32.const 20)(i32.const 4)))
                    (call $exit (i32.const 42))))"#,
            )
            .unwrap();
            let layer = machine
                .commands_layer([("eof".into(), wasm.into())])
                .unwrap()
                .unwrap();
            machine.mount_root_layers([layer]).await.unwrap();
            let machine = Arc::new(machine);
            let stdout = Arc::new(Capture::default());
            let stderr = Arc::new(Capture::default());
            let run = wasixv2::spawn_file(
                machine.clone(),
                wasmer::Engine::default(),
                "/bin/eof".into(),
                wasixv2::ProcessConfig {
                    args: vec!["eof".into()],
                    env: vec![],
                    stdio: Stdio {
                        stdin: Arc::new(EmptySource),
                        stdout: stdout.clone(),
                        stderr: stderr.clone(),
                    },
                },
            )
            .await
            .unwrap();
            let status = tokio::time::timeout(Duration::from_secs(10), run.wait())
                .await
                .expect("finite console input must reach EOF without SIGHUP")
                .unwrap();
            assert_eq!(status, 42);
            assert_eq!(stdout.contents(), b"out\r\n");
            assert_eq!(stderr.contents(), b"err\n");
            assert!(screen.contents().is_empty());
            machine.shutdown().await;
        })
        .await;
}

/// A canonical console-open failure must retire both the ordinary admission and
/// the pre-spawn sink clones; canceling the live owner releases its routes too.
#[cfg(all(feature = "sys", not(target_arch = "wasm32")))]
#[tokio::test]
async fn console_output_admission_failure_and_owner_cancel_release_process_sinks() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let screen = Arc::new(Capture::default());
            let (_keys, input) = mpsc::unbounded_channel();
            let machine = Arc::new(Machine::builder()
                .max_guest_tasks(Some(2))
                .console(Console {
                    input: Arc::new(Keyboard(Mutex::new(input))),
                    output: screen.clone(),
                    size: WindowSize::default(),
                }, [true; 3])
                .console_stdio_outputs(true)
                .build());
            let engine = wasmer::Engine::default();
            let wasm = wat::parse_str(r#"(module
                (import "wasixv2" "ioctl" (func $ioctl (param i32 i32 i32) (result i32)))
                (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
                (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 16) "ready\n")
                (func (export "_start")
                    ;; TIOCEXCL: further canonical opens fail for the default nonadmin user.
                    (drop(call $ioctl (i32.const 0)(i32.const 0x540c)(i32.const 0)))
                    (drop(call $write (i32.const 1)(i32.const 16)(i32.const 6)))
                    (drop(call $read (i32.const 0)(i32.const 64)(i32.const 32)))))"#).unwrap();
            let module = wasixv2::load(&engine, &wasm).unwrap();
            let stdout = Arc::new(Capture::default());
            let stderr = Arc::new(Capture::default());
            let live_stdout = Arc::downgrade(&stdout);
            let live_stderr = Arc::downgrade(&stderr);
            let owner = wasixv2::spawn(machine.clone(), engine.clone(), module.clone(),
                wasixv2::ProcessConfig {
                    args: vec![], env: vec![],
                    stdio: Stdio { stdin: Arc::new(EmptySource), stdout: stdout.clone(), stderr: stderr.clone() },
                }).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), shown(&stdout, b"ready\r\n"))
                .await.expect("live guest must establish exclusive console access");
            for _ in 0..2 {
                let stdout = Arc::new(Capture::default());
                let stderr = Arc::new(Capture::default());
                let failed_stdout = Arc::downgrade(&stdout);
                let failed_stderr = Arc::downgrade(&stderr);
                let result = wasixv2::spawn(machine.clone(), engine.clone(), module.clone(),
                    wasixv2::ProcessConfig { args: vec![], env: vec![],
                        stdio: Stdio { stdin: Arc::new(EmptySource), stdout, stderr },
                    }).await;
                assert!(matches!(result, Err(wasixv2::RunError::Console(error)) if error.raw_os_error() == Some(16)),
                    "the second slot must reach canonical EBUSY again, without a leaked admission");
                assert!(failed_stdout.upgrade().is_none());
                assert!(failed_stderr.upgrade().is_none());
            }
            drop(stdout);
            drop(stderr);
            drop(owner);
            tokio::time::timeout(Duration::from_secs(10), async {
                machine.shutdown().await;
                while live_stdout.upgrade().is_some() || live_stderr.upgrade().is_some() {
                    tokio::task::yield_now().await;
                }
            }).await.expect("canceled owner must release all process sinks");
            assert!(screen.contents().is_empty());
        }).await;
}
