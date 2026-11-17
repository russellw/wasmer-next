//! Initial compiled commands and plain command files use the ordinary exec and hook machinery.
#![cfg(all(
    feature = "sys",
    feature = "tokio",
    feature = "wasix1",
    not(target_arch = "wasm32")
))]

use std::{
    io,
    sync::{Arc, Mutex},
};
use wasixv2::{
    ByteSink, EmptySource, Engine, ExecEnv, InstanceAttachment, InstantiationHook, LocalFuture,
    Machine, MachineSyscalls, OwnedBuffer, ProcessConfig, Stdio,
};
use wasmer::{Function, FunctionEnv, Imports, Instance, Memory, Module, RuntimeError, StoreMut};

const RAW: &str = r#"(module (memory (export "memory") 1) (func (export "_start")))"#;
const CONFIGURED_RAW: &str = r#"(module
    (memory (export "memory") 1)
    (func (export "_start")
      (if (i32.ne (i32.load (i32.const 0)) (i32.const 41)) (then unreachable))
      (i32.store (i32.const 0) (i32.const 42))))"#;

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);
impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

fn config(stdout: Arc<Capture>) -> ProcessConfig {
    ProcessConfig {
        args: vec!["initial".into()],
        env: vec![],
        stdio: Stdio {
            stdin: Arc::new(EmptySource),
            stdout,
            stderr: Arc::new(Capture::default()),
        },
    }
}

// Match console.rs: the owner remains live until actual execution and console delivery end.
async fn compiled(machine: Machine, source: &str) -> Result<i32, String> {
    let engine = Engine::default();
    let bytes = wat::parse_str(source).unwrap();
    let module = wasixv2::load(&engine, &bytes).unwrap();
    let machine = Arc::new(machine);
    let run = wasixv2::spawn(
        machine.clone(),
        engine,
        module,
        config(Arc::new(Capture::default())),
    )
    .await
    .map_err(|error| error.to_string())?;
    let result = run.wait().await;
    machine.shutdown().await;
    drop(run);
    result
}

type Events = Arc<Mutex<Vec<(&'static str, Option<u32>)>>>;
#[derive(Clone, Copy)]
enum Mode {
    Track,
    Provide,
    Deny,
    Replace,
    ReplaceWrongType,
}
struct Hook {
    mode: Mode,
    events: Events,
}
struct Attachment {
    events: Events,
    memory: Option<Memory>,
}
impl InstantiationHook<MachineSyscalls> for Hook {
    fn provides_import(&self, namespace: &str, name: &str) -> bool {
        matches!(self.mode, Mode::Provide)
            && matches!((namespace, name), ("custom", "value") | ("env", "memory"))
    }

    fn prepare_imports(
        &self,
        _: &Module,
        store: &mut StoreMut<'_>,
        _: &FunctionEnv<ExecEnv<MachineSyscalls>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        self.events.lock().unwrap().push(("prepare", None));
        match self.mode {
            Mode::Deny => return Err(RuntimeError::new("initial command denied by hook")),
            Mode::Replace | Mode::ReplaceWrongType => {
                assert!(imports.get_export("wasixv2-exec", "preempt").is_some());
                let replacement = match self.mode {
                    Mode::Replace => Function::new_typed(store, || -> i32 { 0 }),
                    Mode::ReplaceWrongType => Function::new_typed(store, |_: i32| -> i32 { 0 }),
                    _ => unreachable!(),
                };
                imports.define("wasixv2-exec", "preempt", replacement);
            }
            Mode::Provide => imports.define(
                "custom",
                "value",
                Function::new_typed(store, || -> i32 { 7 }),
            ),
            Mode::Track => (),
        }
        Ok(Some(Box::new(Attachment {
            events: self.events.clone(),
            memory: None,
        })))
    }
}
impl InstanceAttachment for Attachment {
    fn configure(
        &mut self,
        module: &Module,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        if module.imports().memories().next().is_none() {
            assert_eq!(instance.exports.get_memory("memory").unwrap(), memory);
        }
        memory.view(&*store).write(0, &41u32.to_le_bytes()).unwrap();
        self.memory = Some(memory.clone());
        self.events.lock().unwrap().push(("configure", Some(41)));
        Ok(())
    }
    fn deactivate(&mut self, store: &mut StoreMut<'_>) {
        let value = self.memory.take().map(|memory| {
            let mut bytes = [0; 4];
            memory.view(&*store).read(0, &mut bytes).unwrap();
            u32::from_le_bytes(bytes)
        });
        self.events.lock().unwrap().push(("deactivate", value));
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.events.lock().unwrap().push(("drop", None));
    }
}

#[tokio::test]
async fn import_free_initial_entry_is_default_off_and_explicitly_opted_in() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let error = compiled(Machine::new(), RAW).await.unwrap_err();
            assert!(
                error.contains("no registered ABI serves this module"),
                "{error}"
            );
            assert_eq!(
                compiled(Machine::builder().wasix1_initial_command(true).build(), RAW).await,
                Ok(0)
            );
        })
        .await;
}

#[tokio::test]
async fn initial_entry_configures_the_actual_memory_and_retires_its_attachment() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let events = Events::default();
            let machine = Machine::builder()
                .wasix1_initial_command(true)
                .instantiation_hook(Arc::new(Hook {
                    mode: Mode::Track,
                    events: events.clone(),
                }))
                .build();
            assert_eq!(compiled(machine, CONFIGURED_RAW).await, Ok(0));
            assert_eq!(
                *events.lock().unwrap(),
                vec![
                    ("prepare", None),
                    ("configure", Some(41)),
                    ("deactivate", Some(42)),
                    ("drop", None),
                ]
            );
        })
        .await;
}

#[tokio::test]
async fn initial_entry_preserves_hook_denial_and_protected_internal_imports() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for mode in [Mode::Deny, Mode::Replace, Mode::ReplaceWrongType] {
                let events = Events::default();
                let machine = Machine::builder()
                    .wasix1_initial_command(true)
                    .instantiation_hook(Arc::new(Hook {
                        mode,
                        events: events.clone(),
                    }))
                    .build();
                let error = compiled(machine, CONFIGURED_RAW).await.unwrap_err();
                if matches!(mode, Mode::Deny) {
                    assert!(error.contains("initial command denied by hook"), "{error}");
                    assert_eq!(*events.lock().unwrap(), vec![("prepare", None)]);
                } else {
                    assert!(
                        error.contains("an instantiation hook replaced an earlier import"),
                        "{error}"
                    );
                    assert_eq!(
                        *events.lock().unwrap(),
                        vec![("prepare", None), ("deactivate", None), ("drop", None),]
                    );
                }
            }
        })
        .await;
}

#[tokio::test]
async fn initial_entry_uses_the_real_entry_signature_and_retires_after_call_failure() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let events = Events::default();
            let machine = Machine::builder()
                .wasix1_initial_command(true)
                .instantiation_hook(Arc::new(Hook {
                    mode: Mode::Track,
                    events: events.clone(),
                }))
                .build();
            let status = compiled(
                machine,
                r#"(module
            (memory (export "memory") 1)
            (func (export "_start") (param i32)
              (i32.store (i32.const 0) (i32.const 99))))"#,
            )
            .await
            .unwrap();
            assert!(
                status >= 128,
                "an entry requiring an argument must fault: {status}"
            );
            assert_eq!(
                *events.lock().unwrap(),
                vec![
                    ("prepare", None),
                    ("configure", Some(41)),
                    ("deactivate", Some(41)),
                    ("drop", None),
                ],
                "the real call must reject the signature before the guest writes 99"
            );
        })
        .await;
}

#[tokio::test]
async fn initial_entry_opt_in_does_not_claim_unrelated_custom_imports() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let events = Events::default();
            let machine = Machine::builder()
                .wasix1_initial_command(true)
                .instantiation_hook(Arc::new(Hook {
                    mode: Mode::Track,
                    events: events.clone(),
                }))
                .build();
            let error = compiled(
                machine,
                r#"(module
            (import "custom" "value" (func (result i32)))
            (memory (export "memory") 1) (func (export "_start")))"#,
            )
            .await
            .unwrap_err();
            assert!(
                error.contains("no registered ABI serves this module"),
                "{error}"
            );
            assert!(
                events.lock().unwrap().is_empty(),
                "no instance was prepared"
            );
        })
        .await;
}

// Match commands.rs::an_image_nothing_serves_fails_execve_with_enoexec. The caller
// writes only after execve returned, proving that rejection did not replace its image.
const EXEC_RAW: &str = r#"(module
    (import "wasixv2" "execve" (func $exec (param i32 i32 i32) (result i32)))
    (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
    (import "wasixv2" "exit_group" (func $exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 16) "/bin/raw\00")
    (data (i32.const 32) "kept")
    (func (export "_start") (local $ret i32)
      (local.set $ret (call $exec (i32.const 16) (i32.const 0) (i32.const 0)))
      (drop (call $write (i32.const 1) (i32.const 32) (i32.const 4)))
      (call $exit (i32.sub (i32.const 0) (local.get $ret))) unreachable))"#;

#[tokio::test]
async fn initial_entry_opt_in_does_not_admit_raw_files_or_guest_execve() {
    tokio::task::LocalSet::new().run_until(async {
        let mut machine = Machine::builder().wasix1_initial_command(true).build();
        machine.install_commands([
            ("raw".into(), OwnedBuffer::from(wat::parse_str(RAW).unwrap())),
            ("exec".into(), OwnedBuffer::from(wat::parse_str(EXEC_RAW).unwrap())),
        ]).await.unwrap();
        let engine = Engine::default();
        let stdout = Arc::new(Capture::default());
        let status = machine.run_file(&engine, "/bin/exec", config(stdout.clone())).await.unwrap();
        assert_eq!(status, 8, "guest execve still returns ENOEXEC");
        assert_eq!(*stdout.0.lock().unwrap(), b"kept");
        let error = machine.run_file(&engine, "/bin/raw", config(stdout)).await.unwrap_err();
        assert!(matches!(error, wasixv2::RunError::Execve { ref err, .. } if err.raw_os_error() == Some(8)), "{error}");
        machine.shutdown().await;
    }).await;
}

#[tokio::test]
async fn initial_entry_opt_in_preserves_normal_v1_and_v2_abi_selection() {
    tokio::task::LocalSet::new().run_until(async {
        for (source, expected) in [
            (r#"(module (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
                (memory (export "memory") 1) (func (export "_start") (call $exit (i32.const 23))))"#, 23),
            (r#"(module (import "wasixv2" "exit_group" (func $exit (param i32)))
                (memory (export "memory") 1) (func (export "_start") (call $exit (i32.const 24))))"#, 24),
        ] {
            assert_eq!(compiled(Machine::builder().wasix1_initial_command(true).build(), source).await, Ok(expected));
        }
    }).await;
}

#[tokio::test]
async fn plain_files_and_execve_return_the_command_status() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut machine = Machine::builder().plain_commands(true).build();
            let raw = r#"(module (func (export "_start") (result i32) i32.const 23))"#;
            let trap = r#"(module (func (export "_start") unreachable))"#;
            machine
                .install_commands([("raw", raw), ("exec", EXEC_RAW), ("trap", trap)].map(
                    |(name, wat)| (name.into(), OwnedBuffer::from(wat::parse_str(wat).unwrap())),
                ))
                .await
                .unwrap();
            let stdout = Arc::new(Capture::default());
            for (path, expected) in [("/bin/raw", 23), ("/bin/exec", 23), ("/bin/trap", 132)] {
                let status = machine
                    .run_file(&Engine::default(), path, config(stdout.clone()))
                    .await
                    .unwrap();
                assert_eq!(status, expected, "{path}");
            }
            assert!(
                stdout.0.lock().unwrap().is_empty(),
                "execve replaced its caller"
            );
            machine.shutdown().await;
        })
        .await;
}

#[cfg(unix)]
struct InterruptHook(Arc<Mutex<Option<wasmer::Interrupter>>>);

#[cfg(unix)]
impl InstantiationHook<MachineSyscalls> for InterruptHook {
    fn prepare_imports(
        &self,
        _: &Module,
        store: &mut StoreMut<'_>,
        _: &FunctionEnv<ExecEnv<MachineSyscalls>>,
        _: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        use wasmer::AsStoreMut;

        *self.0.lock().unwrap() = Some(store.objects_mut().interrupter());
        Ok(None)
    }
}

#[cfg(unix)]
#[test]
fn atomic_wait_keeps_fatal_signal_after_store_interrupt() {
    // The native debug build needs a larger host stack for exec admission.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            tokio::task::LocalSet::new().block_on(&runtime, check_atomic_wait_interrupt());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(unix)]
async fn check_atomic_wait_interrupt() {
    use std::time::{Duration, Instant};

    // Waits on the second memory are left as native instructions, so the engine
    // interrupt can end the invocation before WASIX takes the process signal.
    const WAIT: &str = r#"(module
        (import "wasi_snapshot_preview1" "fd_write"
            (func $write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (memory $wait_mem 1 1 shared)
        (data (i32.const 16) "waiting\0a")
        (data (i32.const 32) "\10\00\00\00\08\00\00\00")
        (func (export "_start")
            (drop (call $write (i32.const 1) (i32.const 32) (i32.const 1) (i32.const 48)))
            (drop (memory.atomic.wait32 $wait_mem (i32.const 0) (i32.const 0) (i64.const 5000000000)))
            unreachable))"#;

    let interrupter = Arc::new(Mutex::new(None));
    let mut machine = Machine::builder()
        .instantiation_hook(Arc::new(InterruptHook(interrupter.clone())))
        .build();
    machine
        .install_commands([(
            "wait".into(),
            OwnedBuffer::from(wat::parse_str(WAIT).unwrap()),
        )])
        .await
        .unwrap();
    let engine = Engine::default();
    let timeout = Duration::from_secs(10);
    for (signal, expected) in [(Some(9), 128 + 9), (Some(15), 128 + 15), (None, 128 + 9)] {
        let stdout = Arc::new(Capture::default());
        let signaller = machine.signaller();
        let interrupt = tokio::task::spawn_blocking({
            let (stdout, interrupter) = (stdout.clone(), interrupter.clone());
            move || {
                let deadline = Instant::now() + timeout;
                while stdout.0.lock().unwrap().as_slice() != b"waiting\n" {
                    assert!(Instant::now() < deadline, "guest reached the atomic wait");
                    std::thread::sleep(Duration::from_millis(5));
                }
                if let Some(signal) = signal {
                    signaller.signal(signal).unwrap();
                }
                interrupter.lock().unwrap().take().unwrap().interrupt();
            }
        });
        let status = Box::pin(machine.run_file(&engine, "/bin/wait", config(stdout)))
            .await
            .unwrap();
        interrupt.await.unwrap();
        assert_eq!(status, expected, "pending signal: {signal:?}");
    }
    machine.shutdown().await;
}

#[tokio::test]
async fn plain_hook_imports_configure_memory_before_wasm_start() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for memory in [
                r#"(memory (export "memory") 1)"#,
                r#"(import "env" "memory" (memory 1 2 shared))"#,
            ] {
                let events = Events::default();
                let mut machine = Machine::builder()
                    .plain_commands(true)
                    .instantiation_hook(Arc::new(Hook {
                        mode: Mode::Provide,
                        events: events.clone(),
                    }))
                    .build();
                let raw = format!(
                    r#"(module
                    (import "custom" "value" (func $value (result i32)))
                    {memory}
                    (func $start
                        (if (i32.ne (i32.load (i32.const 0)) (i32.const 41)) (then unreachable))
                        (i32.store (i32.const 0) (i32.const 42)))
                    (start $start)
                    (func (export "_start") (result i32) call $value))"#
                );
                machine
                    .install_commands([(
                        "raw".into(),
                        OwnedBuffer::from(wat::parse_str(raw).unwrap()),
                    )])
                    .await
                    .unwrap();
                let status = machine
                    .run_file(
                        &Engine::default(),
                        "/bin/raw",
                        config(Arc::new(Capture::default())),
                    )
                    .await
                    .unwrap();
                assert_eq!(status, 7);
                assert_eq!(
                    *events.lock().unwrap(),
                    [
                        ("prepare", None),
                        ("configure", Some(41)),
                        ("deactivate", Some(42)),
                        ("drop", None),
                    ]
                );
                machine.shutdown().await;
            }
        })
        .await;
}

#[tokio::test]
async fn plain_files_require_opt_in_and_a_declaration_for_every_import() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for (enabled, source) in [
                (false, RAW),
                (false, r#"(module (import "custom" "value" (func (result i32))) (func (export "_start")))"#),
                (true, r#"(module (import "custom" "value" (func (result i32))) (import "custom" "missing" (func)) (func (export "_start")))"#),
            ] {
                let events = Events::default();
                let mut machine = Machine::builder()
                    .plain_commands(enabled)
                    .instantiation_hook(Arc::new(Hook {
                        mode: Mode::Provide,
                        events: events.clone(),
                    }))
                    .build();
                machine
                    .install_commands([("raw".into(), OwnedBuffer::from(wat::parse_str(source).unwrap()))])
                    .await
                    .unwrap();
                let error = machine
                    .run_file(&Engine::default(), "/bin/raw", config(Arc::new(Capture::default())))
                    .await
                    .unwrap_err();
                assert!(matches!(error, wasixv2::RunError::Execve { ref err, .. } if err.raw_os_error() == Some(8)), "{error}");
                assert!(events.lock().unwrap().is_empty());
                machine.shutdown().await;
            }
        })
        .await;
}

#[tokio::test]
async fn plain_commands_preserve_native_wasixv2_selection() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut machine = Machine::builder().plain_commands(true).build();
            let raw = r#"(module
                (import "wasixv2" "exit_group" (func $exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start") (call $exit (i32.const 24)) unreachable))"#;
            machine
                .install_commands([(
                    "native".into(),
                    OwnedBuffer::from(wat::parse_str(raw).unwrap()),
                )])
                .await
                .unwrap();
            let status = machine
                .run_file(
                    &Engine::default(),
                    "/bin/native",
                    config(Arc::new(Capture::default())),
                )
                .await
                .unwrap();
            assert_eq!(status, 24);
            machine.shutdown().await;
        })
        .await;
}
