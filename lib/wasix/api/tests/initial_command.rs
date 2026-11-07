//! Initial compiled commands use the ordinary ABI, hook and admitted-run machinery.
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
        _: &Module,
        store: &mut StoreMut<'_>,
        instance: &Instance,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        assert_eq!(instance.exports.get_memory("memory").unwrap(), memory);
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
