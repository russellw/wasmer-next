//! Custom binding state belongs to each actual main/side instance, independent of its ABI.
#![cfg(all(feature = "sys", feature = "tokio", not(target_arch = "wasm32")))]

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use wasixv2::{
    ExecEnv, InstanceAttachment, InstantiationHook, Machine, MachineSyscalls, ProcessConfig, Stdio,
};
use wasmer::{
    Function, FunctionEnv, FunctionEnvMut, Global, Imports, Instance, Memory, Module, RuntimeError,
    StoreMut, Value,
};

type Events = Arc<Mutex<Vec<(usize, &'static str)>>>;
type ThreadEvents = Arc<Mutex<Vec<(&'static str, std::thread::ThreadId)>>>;
type CleanupGate = Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>;
#[derive(Clone)]
struct ThreadProbe {
    events: ThreadEvents,
    barrier: Option<Arc<std::sync::Barrier>>,
    cleanup_gate: Option<CleanupGate>,
}
impl ThreadProbe {
    fn record(&self, phase: &'static str) {
        self.events
            .lock()
            .unwrap()
            .push((phase, std::thread::current().id()));
    }
}
struct Hook {
    next: AtomicUsize,
    events: Events,
    omit: bool,
    thread: Option<ThreadProbe>,
}
struct State {
    id: usize,
    configured: bool,
    events: Events,
    thread: Option<ThreadProbe>,
    cleanup: Option<std::sync::Weak<wasixv2_host::LoaderCleanup>>,
}
struct Attachment {
    env: FunctionEnv<State>,
    exec: FunctionEnv<ExecEnv<MachineSyscalls>>,
}
impl InstantiationHook<MachineSyscalls> for Hook {
    fn requires_owning_thread(&self) -> bool {
        self.thread.is_some()
    }

    fn provides_import(&self, namespace: &str, name: &str) -> bool {
        namespace == "env" && matches!(name, "value" | "binding_bias")
    }

    fn prepare_imports(
        &self,
        module: &Module,
        store: &mut StoreMut<'_>,
        exec: &FunctionEnv<ExecEnv<MachineSyscalls>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        if let Some(thread) = &self.thread {
            thread.record("inspect");
        }
        let cleanup = exec.as_ref(store).loader_cleanup().map(Arc::downgrade);
        let requested = module
            .imports()
            .filter(|import| {
                import.module() == "custom" || self.provides_import(import.module(), import.name())
            })
            .map(|import| {
                (
                    import.module().to_string(),
                    import.name().to_string(),
                    matches!(import.ty(), wasmer::ExternType::Global(_)),
                )
            })
            .collect::<Vec<_>>();
        if requested.is_empty() {
            return Ok(None);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push((id, "prepare"));
        if let Some(thread) = &self.thread {
            thread.record("prepare");
        }
        let env = FunctionEnv::new(
            store,
            State {
                id,
                configured: false,
                events: self.events.clone(),
                thread: self.thread.clone(),
                cleanup,
            },
        );
        for (namespace, name, global) in requested {
            if self.omit || imports.get_export(&namespace, &name).is_some() {
                continue;
            }
            if global {
                imports.define(&namespace, &name, Global::new(store, Value::I32(41)));
                continue;
            }
            imports.define(
                &namespace,
                &name,
                Function::new_typed_with_env(
                    store,
                    &env,
                    |env: FunctionEnvMut<State>| -> Result<i32, RuntimeError> {
                        if !env.data().configured {
                            return Err(RuntimeError::new("binding not configured"));
                        }
                        env.data()
                            .events
                            .lock()
                            .unwrap()
                            .push((env.data().id, "call"));
                        if let Some(thread) = &env.data().thread {
                            thread.record("call");
                            if let Some(barrier) = &thread.barrier {
                                barrier.wait();
                            }
                        }
                        Ok(env.data().id as i32)
                    },
                ),
            );
        }
        Ok(Some(Box::new(Attachment {
            env,
            exec: exec.clone(),
        })))
    }
}
impl InstanceAttachment for Attachment {
    fn configure(
        &mut self,
        _: &Module,
        store: &mut StoreMut<'_>,
        _: &Instance,
        _: &Memory,
    ) -> Result<(), RuntimeError> {
        let _ = self.exec.as_ref(&*store).task();
        let state = self.env.as_mut(store);
        state.configured = true;
        state.events.lock().unwrap().push((state.id, "configure"));
        if let Some(thread) = &state.thread {
            thread.record("configure");
        }
        Ok(())
    }
    fn deactivate(&mut self, store: &mut StoreMut<'_>) {
        let _ = self.exec.as_ref(&*store).task();
        let state = self.env.as_mut(store);
        state.configured = false;
        state.events.lock().unwrap().push((state.id, "deactivate"));
        if let Some(thread) = &state.thread {
            thread.record("deactivate");
            let thread = thread.clone();
            let scope = state.cleanup.as_ref().unwrap().upgrade().unwrap();
            assert!(
                scope
                    .submit(Box::new(move || Box::pin(async move {
                        let gate = thread
                            .cleanup_gate
                            .as_ref()
                            .and_then(|gate| gate.lock().unwrap().take());
                        if let Some(gate) = gate {
                            thread.record("cleanup waiting");
                            let _ = gate.await;
                        }
                        thread.record("cleanup");
                    })))
                    .is_ok()
            );
        }
    }
}

fn leb(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        out.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
// Match api::retirement and wasix1::dynamic's source-built dylink.0 fixtures.
fn pic(wat: &str, needed: &[&str]) -> Vec<u8> {
    pic_with_weak_imports(wat, needed, &[])
}

fn pic_with_weak_imports(wat: &str, needed: &[&str], weak: &[&str]) -> Vec<u8> {
    let mut wasm = wat::parse_str(wat).unwrap();
    let mut data = vec![8];
    data.extend_from_slice(b"dylink.0");
    let mut info = Vec::new();
    for value in [512, 0, 0, 0] {
        leb(value, &mut info);
    }
    data.push(1);
    leb(info.len() as u32, &mut data);
    data.extend(info);
    if !needed.is_empty() {
        let mut names = Vec::new();
        leb(needed.len() as u32, &mut names);
        for name in needed {
            leb(name.len() as u32, &mut names);
            names.extend_from_slice(name.as_bytes());
        }
        data.push(2);
        leb(names.len() as u32, &mut data);
        data.extend(names);
    }
    if !weak.is_empty() {
        let mut flags = Vec::new();
        leb(weak.len() as u32, &mut flags);
        for name in weak {
            for name in ["env", name] {
                leb(name.len() as u32, &mut flags);
                flags.extend_from_slice(name.as_bytes());
            }
            leb(0x11, &mut flags); // UNDEFINED | BINDING_WEAK
        }
        data.push(4);
        leb(flags.len() as u32, &mut data);
        data.extend(flags);
    }
    wasm.push(0);
    leb(data.len() as u32, &mut wasm);
    wasm.extend(data);
    wasm
}

struct Programs(PathBuf);
impl Drop for Programs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Custom,
    Env,
    Global,
    NamespacedStack,
    Guest,
    WrongGuest,
    Missing,
}

async fn run(name: &str, main_binding: bool) -> Events {
    let (result, events) = run_case(name, main_binding, Variant::Custom).await;
    assert_eq!(result.unwrap(), 0);
    events
}

async fn run_case(
    name: &str,
    main_binding: bool,
    variant: Variant,
) -> (Result<i32, wasixv2::RunError>, Events) {
    run_case_with_thread(name, main_binding, variant, None, false).await
}

async fn run_case_with_thread(
    name: &str,
    main_binding: bool,
    variant: Variant,
    thread: Option<ThreadProbe>,
    file: bool,
) -> (Result<i32, wasixv2::RunError>, Events) {
    run_case_with_admission(name, main_binding, variant, thread, file, false).await
}

async fn run_case_with_admission(
    name: &str,
    main_binding: bool,
    variant: Variant,
    thread: Option<ThreadProbe>,
    file: bool,
    admitted: bool,
) -> (Result<i32, wasixv2::RunError>, Events) {
    let programs = Programs(std::env::temp_dir().join(format!(
        "wasixv2-custom-binding-{name}-{}",
        std::process::id()
    )));
    std::fs::create_dir_all(&programs.0).unwrap();
    let namespace = if variant == Variant::Custom {
        "custom"
    } else {
        "env"
    };
    let side_import = if variant == Variant::NamespacedStack {
        "(import \"custom\" \"__stack_pointer\" (global $bias i32))".to_string()
    } else if variant == Variant::Global {
        "(import \"env\" \"binding_bias\" (global $bias i32))".to_string()
    } else {
        format!("(import \"{namespace}\" \"value\" (func $value (result i32)))")
    };
    let side_body = if matches!(variant, Variant::Global | Variant::NamespacedStack) {
        "global.get $bias"
    } else {
        "call $value"
    };
    let side = pic(
        &format!(
            r#"(module
        (import "env" "memory" (memory 1 65536 shared))
        (import "env" "__indirect_function_table" (table 0 funcref))
        (import "env" "__memory_base" (global i32))
        (import "env" "__table_base" (global i32))
        {side_import}
        (func (export "side_value") (result i32) {side_body}))"#
        ),
        &[],
    );
    std::fs::write(programs.0.join("side.so"), side).unwrap();
    let custom = if main_binding {
        "(import \"custom\" \"value\" (func $value (result i32)))"
    } else {
        ""
    };
    let expected = match variant {
        Variant::Global | Variant::NamespacedStack => 41,
        Variant::Guest => 79,
        _ => 1,
    };
    let body = if main_binding {
        "call $value call $side i32.eq".to_string()
    } else {
        format!("call $side i32.const {expected} i32.ne")
    };
    let guest = match variant {
        Variant::Guest => "(func (export \"value\") (result i32) i32.const 79)",
        Variant::WrongGuest => "(func (export \"value\") (result i64) i64.const 79)",
        _ => "",
    };
    let main = pic(
        &format!(
            r#"(module
        (import "env" "memory" (memory 1 65536 shared))
        (import "env" "__indirect_function_table" (table 3 funcref))
        (import "env" "__stack_pointer" (global (mut i32)))
        (import "env" "__memory_base" (global i32))
        (import "env" "__table_base" (global i32))
        (import "env" "side_value" (func $side (result i32)))
        (import "wasixv2" "exit_group" (func $exit (param i32)))
        {custom}
        {guest}
        (export "__indirect_function_table" (table 0))
        (func (export "_start") {body} call $exit))"#
        ),
        &["side.so"],
    );
    if file {
        let path = programs.0.join("main.wasm");
        std::fs::write(&path, &main).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let machine = Machine::builder()
        .instantiation_hook(Arc::new(Hook {
            next: AtomicUsize::new(1),
            events: events.clone(),
            omit: variant == Variant::Missing,
            thread,
        }))
        .build();
    machine
        .mount_host_dir("/prog", &programs.0, false)
        .await
        .unwrap();
    let config = ProcessConfig {
        args: vec!["custom-binding".into()],
        env: vec!["LD_LIBRARY_PATH=/prog".into()],
        stdio: Stdio::from_fns(|_| {}, |_| {}),
    };
    let status = if admitted {
        let machine = Arc::new(machine);
        let engine = wasmer::Engine::default();
        let run = if file {
            wasixv2::spawn_file(machine, engine, "/prog/main.wasm".into(), config).await
        } else {
            let module = wasixv2::load(&engine, &main).expect("valid admitted fixture");
            wasixv2::spawn(machine, engine, module, config).await
        }
        .expect("admitted custom-binding process");
        Ok(run
            .wait()
            .await
            .expect("admitted custom-binding completion"))
    } else if file {
        machine
            .run_file(&wasmer::Engine::default(), "/prog/main.wasm", config)
            .await
    } else {
        machine.run_process(&main, config).await
    };
    (status, events)
}

#[tokio::test]
async fn main_and_side_module_use_distinct_bindings_in_the_same_store() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let events = run("paired", true).await;
            let events = events.lock().unwrap();
            let calls: Vec<_> = events
                .iter()
                .filter(|(_, event)| *event == "call")
                .map(|(id, _)| *id)
                .collect();
            assert_eq!(calls.len(), 2);
            assert_ne!(calls[0], calls[1]);
            let retired: Vec<_> = events
                .iter()
                .filter(|(_, event)| *event == "deactivate")
                .map(|(id, _)| *id)
                .collect();
            assert_eq!(retired, [2, 1]);
        })
        .await;
}

#[tokio::test]
async fn side_module_only_imports_get_their_own_custom_binding() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let events = run("side-only", false).await;
            assert_eq!(
                *events.lock().unwrap(),
                [
                    (1, "prepare"),
                    (1, "configure"),
                    (1, "call"),
                    (1, "deactivate")
                ]
            );
        })
        .await;
}

#[tokio::test]
async fn declared_env_helpers_and_globals_reach_real_side_module_preparation() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for (name, variant) in [
                ("declared-env", Variant::Env),
                ("declared-global", Variant::Global),
                ("namespaced-stack", Variant::NamespacedStack),
            ] {
                let (result, events) = run_case(name, false, variant).await;
                assert_eq!(result.unwrap(), 0);
                let events = events.lock().unwrap();
                assert_eq!(
                    events
                        .iter()
                        .filter(|(_, event)| *event == "configure")
                        .count(),
                    1
                );
                assert_eq!(
                    events
                        .iter()
                        .filter(|(_, event)| *event == "deactivate")
                        .count(),
                    1
                );
            }
        })
        .await;
}

#[tokio::test]
async fn guest_definition_precedes_declared_host_fallback_and_type_errors_stay_errors() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (result, events) = run_case("guest-precedence", false, Variant::Guest).await;
            assert_eq!(result.unwrap(), 0);
            assert!(
                !events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(_, event)| *event == "call")
            );
            let (result, events) = run_case("guest-type-error", false, Variant::WrongGuest).await;
            assert!(
                !matches!(result, Ok(0)),
                "a matching guest definition's type mismatch must not fall back to the host"
            );
            assert!(events.lock().unwrap().is_empty());
        })
        .await;
}

#[tokio::test]
async fn standalone_weak_main_keeps_guest_precedence_and_declared_host_fallback() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for (guest, expected, host_calls) in [
                ("", 1, 1),
                (
                    r#"(func (export "value") (result i32) i32.const 79)"#,
                    79,
                    0,
                ),
                (
                    r#"(func (export "value") (result i64) i64.const 79)"#,
                    -1,
                    0,
                ),
            ] {
                let main = pic_with_weak_imports(
                    &format!(
                        r#"(module
        (import "env" "memory" (memory 1 65536 shared))
        (import "env" "__indirect_function_table" (table 3 funcref))
        (import "env" "__stack_pointer" (global (mut i32)))
        (import "env" "__memory_base" (global i32))
        (import "env" "__table_base" (global i32))
        (import "env" "value" (func $value (result i32)))
        (import "wasixv2" "exit_group" (func $exit (param i32)))
        {guest}
        (func (export "_start")
          (call $exit (i32.ne (call $value) (i32.const {expected})))))"#
                    ),
                    &[],
                    &["value"],
                );
                let events = Arc::new(Mutex::new(Vec::new()));
                let machine = Machine::builder()
                    .instantiation_hook(Arc::new(Hook {
                        next: AtomicUsize::new(1),
                        events: events.clone(),
                        omit: false,
                        thread: None,
                    }))
                    .build();
                let result = machine
                    .run_process(
                        &main,
                        ProcessConfig {
                            args: vec!["standalone-weak".into()],
                            env: vec![],
                            stdio: Stdio::from_fns(|_| {}, |_| {}),
                        },
                    )
                    .await;
                if expected == -1 {
                    assert!(
                        result.is_err(),
                        "wrong guest type must reject host fallback"
                    );
                } else {
                    assert_eq!(result.unwrap(), 0);
                }
                assert_eq!(
                    events
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|(_, event)| *event == "call")
                        .count(),
                    host_calls
                );
            }
        })
        .await;
}

#[tokio::test]
async fn declaration_without_a_prepared_value_fails_admission_and_deactivates() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (result, events) = run_case("missing-declared", false, Variant::Missing).await;
            assert!(
                !matches!(result, Ok(0)),
                "a declaration must never synthesize an import value"
            );
            assert_eq!(*events.lock().unwrap(), [(1, "prepare"), (1, "deactivate")]);
        })
        .await;
}

// Match the API's async_sync_borrow owned subprocess boundary: a broken
// factory could block the caller on the two-root meeting barrier.
fn owning_thread_subprocess(name: &str) -> bool {
    const CHILD: &str = "WASIXV2_OWNING_THREAD_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, "1")
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "owning-thread proof failed: {status}");
                return false;
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            result => panic!("owning-thread proof did not finish: {result:?}"),
        }
    }
}

#[tokio::test]
async fn side_only_bindings_construct_and_retire_on_their_owning_thread() {
    if !owning_thread_subprocess("side_only_bindings_construct_and_retire_on_their_owning_thread") {
        return;
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            for (name, file) in [("owner-side-bytes", false), ("owner-side-file", true)] {
                let caller = std::thread::current().id();
                let events: ThreadEvents = Arc::default();
                let (result, _) = run_case_with_thread(
                    name,
                    false,
                    Variant::Env,
                    Some(ThreadProbe {
                        events: events.clone(),
                        barrier: None,
                        cleanup_gate: None,
                    }),
                    file,
                )
                .await;
                assert_eq!(result.unwrap(), 0);
                let events = events.lock().unwrap();
                let owner = events
                    .iter()
                    .find(|(phase, _)| *phase == "prepare")
                    .unwrap()
                    .1;
                assert_ne!(owner, caller);
                assert!(events.iter().all(|(_, thread)| *thread == owner));
                assert!(
                    events
                        .iter()
                        .filter(|(phase, _)| *phase == "inspect")
                        .count()
                        >= 2
                );
                assert_eq!(events.last().unwrap().0, "cleanup");
                for phase in ["prepare", "configure", "call", "deactivate", "cleanup"] {
                    assert_eq!(events.iter().filter(|(seen, _)| *seen == phase).count(), 1);
                }
            }
        })
        .await;
}

/// The common owner must preserve the same side-only binding profile as the
/// synchronous facade, including file exec and its loader cleanup fence.
#[tokio::test]
async fn admitted_side_bindings_keep_the_existing_owning_thread_lifecycle() {
    if !owning_thread_subprocess("admitted_side_bindings_keep_the_existing_owning_thread_lifecycle")
    {
        return;
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            for (name, file) in [
                ("admitted-owner-bytes", false),
                ("admitted-owner-file", true),
            ] {
                let caller = std::thread::current().id();
                let events: ThreadEvents = Arc::default();
                let (status, _) = run_case_with_admission(
                    name,
                    false,
                    Variant::Env,
                    Some(ThreadProbe {
                        events: events.clone(),
                        barrier: None,
                        cleanup_gate: None,
                    }),
                    file,
                    true,
                )
                .await;
                assert_eq!(status.unwrap(), 0);
                let events = events.lock().unwrap();
                let owner = events
                    .iter()
                    .find(|(phase, _)| *phase == "prepare")
                    .unwrap()
                    .1;
                assert_ne!(owner, caller);
                assert!(events.iter().all(|(_, thread)| *thread == owner));
                assert_eq!(events.last().unwrap().0, "cleanup");
                for phase in ["prepare", "configure", "call", "deactivate", "cleanup"] {
                    assert_eq!(events.iter().filter(|(seen, _)| *seen == phase).count(), 1);
                }
            }
        })
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn file_exit_status_is_available_before_loader_cleanup_drains() {
    use std::{os::unix::fs::PermissionsExt, time::Duration};
    use tokio::sync::oneshot;

    tokio::task::LocalSet::new()
        .run_until(async {
            let programs = tempfile::tempdir().unwrap();
            let path = programs.path().join("main.wasm");
            let wasm = wat::parse_str(
                r#"(module
                    (import "custom" "value" (func $value (result i32)))
                    (import "wasixv2" "exit_group" (func $exit (param i32)))
                    (memory (export "memory") 1)
                    (func (export "_start") call $value i32.const 41 i32.add call $exit))"#,
            )
            .unwrap();
            std::fs::write(&path, wasm).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

            let events: ThreadEvents = Arc::default();
            let (release, cleanup_gate) = oneshot::channel();
            let machine = Machine::builder()
                .instantiation_hook(Arc::new(Hook {
                    next: AtomicUsize::new(1),
                    events: Arc::default(),
                    omit: false,
                    thread: Some(ThreadProbe {
                        events: events.clone(),
                        barrier: None,
                        cleanup_gate: Some(Arc::new(Mutex::new(Some(cleanup_gate)))),
                    }),
                }))
                .build();
            machine
                .mount_host_dir("/prog", programs.path(), false)
                .await
                .unwrap();

            let engine = wasmer::Engine::default();
            let config = ProcessConfig {
                args: vec![],
                env: vec![],
                stdio: Stdio::from_fns(|_| {}, |_| {}),
            };
            let (publish, exit) = oneshot::channel();
            let exit_events = events.clone();
            let mut run = std::pin::pin!(machine.run_file_with_exit_status(
                &engine,
                "/prog/main.wasm",
                config,
                move |status| {
                    exit_events.lock().unwrap().push(("exit", std::thread::current().id()));
                    let _ = publish.send(status);
                },
            ));

            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::select! {
                    status = exit => assert_eq!(status.unwrap(), 42),
                    result = &mut run => panic!("run completed before cleanup was released: {result:?}"),
                }
                assert!(futures_util::poll!(&mut run).is_pending());
                release.send(()).unwrap();
                assert_eq!(run.await.unwrap(), 42);
            })
            .await
            .unwrap();
            let events = events.lock().unwrap();
            let phases: Vec<_> = events.iter().map(|(phase, _)| *phase).collect();
            assert!(phases.ends_with(&["exit", "deactivate", "cleanup waiting", "cleanup"]));
        })
        .await;
}

#[cfg(unix)]
#[test]
fn file_exit_status_is_available_before_stdio_closes() {
    use std::os::unix::fs::PermissionsExt;

    // Debug builds need more stack for the inline guest's syscall futures.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            tokio::task::LocalSet::new().block_on(&runtime, async {
                let programs = tempfile::tempdir().unwrap();
                let path = programs.path().join("main.wasm");
                let wasm = wat::parse_str(
                    r#"(module
                    (import "wasixv2" "exit_group" (func $exit (param i32)))
                    (memory (export "memory") 1)
                    (func (export "_start") i32.const 42 call $exit))"#,
                )
                .unwrap();
                std::fs::write(&path, wasm).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

                let machine = Machine::builder().build();
                machine
                    .mount_host_dir("/prog", programs.path(), false)
                    .await
                    .unwrap();

                let stdio = Stdio::from_fns(|_| {}, |_| {});
                let stdout = Arc::downgrade(&stdio.stdout);
                let config = ProcessConfig {
                    args: vec![],
                    env: vec![],
                    stdio,
                };
                let (publish, exit) = tokio::sync::oneshot::channel();
                let status = machine
                    .run_file_with_exit_status(
                        &wasmer::Engine::default(),
                        "/prog/main.wasm",
                        config,
                        move |status| {
                            let _ = publish.send((status, stdout.strong_count() > 0));
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(status, 42);
                assert_eq!(exit.await.unwrap(), (42, true));
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::test]
async fn independent_binding_roots_use_distinct_owning_threads() {
    if !owning_thread_subprocess("independent_binding_roots_use_distinct_owning_threads") {
        return;
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let first: ThreadEvents = Arc::default();
            let second: ThreadEvents = Arc::default();
            let (left, right) = tokio::join!(
                run_case_with_thread(
                    "owner-first",
                    false,
                    Variant::Env,
                    Some(ThreadProbe {
                        events: first.clone(),
                        barrier: Some(barrier.clone()),
                        cleanup_gate: None,
                    }),
                    false
                ),
                run_case_with_thread(
                    "owner-second",
                    false,
                    Variant::Env,
                    Some(ThreadProbe {
                        events: second.clone(),
                        barrier: Some(barrier),
                        cleanup_gate: None,
                    }),
                    false
                ),
            );
            assert_eq!(left.0.unwrap(), 0);
            assert_eq!(right.0.unwrap(), 0);
            let first = first.lock().unwrap();
            let second = second.lock().unwrap();
            let left = first.iter().find(|(phase, _)| *phase == "call").unwrap().1;
            let right = second.iter().find(|(phase, _)| *phase == "call").unwrap().1;
            assert_ne!(left, right);
            assert_eq!(first.last().unwrap().0, "cleanup");
            assert_eq!(second.last().unwrap().0, "cleanup");
        })
        .await;
}

// Keep the engine-neutral kernel reservation and native backing pin on the same
// actual import path; neither a test allocator nor an unattached kernel is used.
struct HostLeaseHook(Arc<AtomicUsize>);
impl InstantiationHook<MachineSyscalls> for HostLeaseHook {
    fn requires_owning_thread(&self) -> bool {
        true
    }

    fn prepare_imports(
        &self,
        _: &Module,
        store: &mut StoreMut<'_>,
        exec: &FunctionEnv<ExecEnv<MachineSyscalls>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        let calls = self.0.clone();
        imports.define(
            "custom",
            "host_lease",
            Function::new_typed_with_env_async(
                store,
                exec,
                move |env: wasmer::AsyncFunctionEnvMut<ExecEnv<MachineSyscalls>>| {
                    let calls = calls.clone();
                    async move {
                        use wasixv2_syscalls::{Caller, LoaderControl, Syscalls, WASM_PAGE_SIZE};
                        let (syscalls, task) = {
                            let read = env.read().await;
                            (read.data().syscalls().clone(), read.data().task())
                        };
                        let memory = wasixv2_exec::GuestMemory::new(&env);
                        let caller = Caller::new(task, &memory);
                        let lease = syscalls.loader_reserve_host(&caller, 17, 64).await.unwrap();
                        let address = lease.address();
                        assert_eq!(address % 64, 0);
                        assert_eq!(lease.length(), 17);
                        // SAFETY: this exact native lease exclusively owns the bytes;
                        // the guest is suspended and no other test thread accesses them.
                        unsafe {
                            assert_eq!(lease.as_ptr().read(), 0);
                            lease.as_ptr().write(42);
                        }
                        assert_eq!(
                            syscalls
                                .mprotect(
                                    &caller,
                                    address,
                                    WASM_PAGE_SIZE as u32,
                                    wasixv2_abi::ProtFlags::PROT_READ,
                                )
                                .await,
                            Err(wasixv2_syscalls::Errno::EBUSY.into()),
                        );
                        assert_eq!(
                            syscalls
                                .munmap(&caller, address, WASM_PAGE_SIZE as u32)
                                .await,
                            Err(wasixv2_syscalls::Errno::EBUSY.into()),
                        );
                        // A real guest read reaches the same pinned native allocation.
                        let read = env.read().await;
                        let memory = read.data().memory().unwrap().clone();
                        let mut byte = [0];
                        memory
                            .view(&read)
                            .read(u64::from(address), &mut byte)
                            .unwrap();
                        assert_eq!(byte, [42]);
                        drop(read);
                        lease.release().await;
                        let replacement =
                            syscalls.loader_reserve_host(&caller, 17, 64).await.unwrap();
                        assert_eq!(replacement.address(), address);
                        // SAFETY: the replacement owns fresh anonymous backing.
                        unsafe {
                            assert_eq!(replacement.as_ptr().read(), 0);
                        }
                        drop(replacement);
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<i32, RuntimeError>(42)
                    }
                },
            ),
        );
        Ok(None)
    }
}

#[tokio::test]
async fn a_custom_import_owns_protected_native_kernel_reservations() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let machine = Machine::builder()
                .instantiation_hook(Arc::new(HostLeaseHook(calls.clone())))
                .build();
            let main = pic(
                r#"(module
            (import "env" "memory" (memory 1 65536 shared))
            (import "env" "__indirect_function_table" (table 3 funcref))
            (import "env" "__stack_pointer" (global (mut i32)))
            (import "env" "__memory_base" (global i32))
            (import "env" "__table_base" (global i32))
            (import "custom" "host_lease" (func $lease (result i32)))
            (import "wasixv2" "exit_group" (func $exit (param i32)))
            (export "__indirect_function_table" (table 0))
            (func (export "_start") call $lease i32.const 42 i32.ne call $exit))"#,
                &[],
            );
            let result = machine
                .run_process(
                    &main,
                    ProcessConfig {
                        args: vec!["native-host-lease".into()],
                        env: vec![],
                        stdio: Stdio::from_fns(|_| {}, |_| {}),
                    },
                )
                .await;
            assert_eq!(result.unwrap(), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        })
        .await;
}

// Like HostLeaseHook, but keep the real kernel pin through startup and retire it
// with the instance attachment on success, start trap, or a pending start import.
#[derive(Default)]
struct StartProbe {
    events: Mutex<Vec<(&'static str, std::thread::ThreadId)>>,
    lease: Mutex<Option<Box<dyn wasixv2_syscalls::HostMemoryLease>>>,
    entered: tokio::sync::Notify,
    retired: tokio::sync::Notify,
}
impl StartProbe {
    fn record(&self, phase: &'static str) {
        self.events
            .lock()
            .unwrap()
            .push((phase, std::thread::current().id()));
    }
}
struct StartHook {
    probe: Arc<StartProbe>,
    pending: bool,
}
struct StartState {
    memory: Option<Memory>,
    probe: Arc<StartProbe>,
}
struct StartAttachment {
    state: FunctionEnv<StartState>,
    exec: FunctionEnv<ExecEnv<MachineSyscalls>>,
}
impl InstantiationHook<MachineSyscalls> for StartHook {
    fn requires_owning_thread(&self) -> bool {
        true
    }
    fn prepare_imports(
        &self,
        _: &Module,
        store: &mut StoreMut<'_>,
        exec: &FunctionEnv<ExecEnv<MachineSyscalls>>,
        imports: &mut Imports,
    ) -> Result<Option<Box<dyn InstanceAttachment>>, RuntimeError> {
        let state = FunctionEnv::new(
            store,
            StartState {
                memory: None,
                probe: self.probe.clone(),
            },
        );
        imports.define(
            "custom",
            "memory",
            Function::new_typed_with_env(store, &state, |env: FunctionEnvMut<StartState>| -> i32 {
                let data = env.data();
                let memory = data.memory.as_ref().expect("configured before start");
                let mut byte = [0];
                memory.view(&env).read(0, &mut byte).unwrap();
                assert_eq!(byte, [42]);
                memory.view(&env).write(0, &[43]).unwrap();
                data.probe.record("memory");
                43
            }),
        );
        let probe = self.probe.clone();
        let pending = self.pending;
        imports.define(
            "custom",
            "lease",
            Function::new_typed_with_env_async(
                store,
                exec,
                move |env: wasmer::AsyncFunctionEnvMut<ExecEnv<MachineSyscalls>>| {
                    let probe = probe.clone();
                    async move {
                        use wasixv2_syscalls::{Caller, LoaderControl};
                        let (syscalls, task) = {
                            let read = env.read().await;
                            (read.data().syscalls().clone(), read.data().task())
                        };
                        let memory = wasixv2_exec::GuestMemory::new(&env);
                        let caller = Caller::new(task, &memory);
                        let lease = syscalls
                            .loader_reserve_host(&caller, 17, 64)
                            .await
                            .map_err(|e| RuntimeError::new(format!("start lease: {e:?}")))?;
                        // SAFETY: the exact lease exclusively owns this protected range.
                        unsafe {
                            lease.as_ptr().write(79);
                        }
                        *probe.lease.lock().unwrap() = Some(lease);
                        probe.record("lease");
                        probe.entered.notify_one();
                        if pending {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), RuntimeError>(())
                    }
                },
            ),
        );
        Ok(Some(Box::new(StartAttachment {
            state,
            exec: exec.clone(),
        })))
    }
}
impl InstanceAttachment for StartAttachment {
    fn configure(
        &mut self,
        _: &Module,
        store: &mut StoreMut<'_>,
        _: &Instance,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        assert_eq!(self.exec.as_ref(store).memory(), Some(memory));
        let mut byte = [0];
        memory.view(&*store).read(0, &mut byte).unwrap();
        assert_eq!(byte, [41]); // active data was applied before configuration
        memory.view(&*store).write(0, &[42]).unwrap();
        let state = self.state.as_mut(store);
        state.memory = Some(memory.clone());
        state.probe.record("configure");
        Ok(())
    }
    fn deactivate(&mut self, store: &mut StoreMut<'_>) {
        let state = self.state.as_mut(store);
        let lease = state.probe.lease.lock().unwrap().take();
        if let Some(lease) = lease {
            // SAFETY: the lease remained live throughout start and ABI entry.
            assert_eq!(unsafe { lease.as_ptr().read() }, 79);
            drop(lease);
        }
        state.memory = None;
        state.probe.record("deactivate");
        state.probe.retired.notify_one();
    }
}
fn start_guest(tail: &str) -> Vec<u8> {
    start_guest_layout(tail, "")
}
fn start_guest_layout(tail: &str, layout: &str) -> Vec<u8> {
    start_guest_memory(tail, layout, true)
}
fn start_guest_memory(tail: &str, layout: &str, shared: bool) -> Vec<u8> {
    let shared = if shared { "shared" } else { "" };
    wat::parse_str(format!(
        r#"(module
        (import "env" "memory" (memory 1 16 {shared}))
        (import "wasixv2" "exit_group" (func $exit (param i32)))
        (import "custom" "memory" (func $memory (result i32)))
        (import "custom" "lease" (func $lease))
        {layout}
        (data (i32.const 0) "\29")
        (global $count (mut i32) (i32.const 0))
        (func $init
          i32.const 4 call $memory i32.store
          global.get $count i32.const 1 i32.add global.set $count
          call $lease {tail})
        (start $init)
        (func (export "_start")
          i32.const 4 i32.load i32.const 43 i32.ne
          global.get $count i32.const 1 i32.ne i32.or call $exit))"#
    ))
    .unwrap()
}
fn start_config() -> ProcessConfig {
    ProcessConfig {
        args: vec!["start-hook".into()],
        env: vec![],
        stdio: Stdio::from_fns(|_| {}, |_| {}),
    }
}
#[tokio::test]
async fn start_imports_use_configured_memory_and_retained_protected_leases() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for (tail, shared, status) in [
                ("", true, Some(0)),
                ("", false, Some(0)),
                ("i32.const 5 call $exit", true, Some(5)),
                ("unreachable", true, None),
                ("unreachable", false, None),
            ] {
                let probe = Arc::new(StartProbe::default());
                let machine = Machine::builder()
                    .instantiation_hook(Arc::new(StartHook {
                        probe: probe.clone(),
                        pending: false,
                    }))
                    .build();
                let result = machine
                    .run_process(&start_guest_memory(tail, "", shared), start_config())
                    .await;
                if let Some(status) = status {
                    assert_eq!(result.unwrap(), status);
                } else {
                    assert!(result.unwrap_err().to_string().contains("unreachable"));
                }
                assert!(probe.lease.lock().unwrap().is_none());
                let events = probe.events.lock().unwrap();
                assert_eq!(
                    events.iter().map(|(phase, _)| *phase).collect::<Vec<_>>(),
                    ["configure", "memory", "lease", "deactivate"]
                );
                assert!(events.iter().all(|(_, thread)| *thread == events[0].1));
            }
        })
        .await;
}
#[tokio::test]
async fn canceling_start_retires_its_original_attachment_and_pin() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for pending in [true, false] {
                let probe = Arc::new(StartProbe::default());
                let machine = Machine::builder()
                    .instantiation_hook(Arc::new(StartHook {
                        probe: probe.clone(),
                        pending,
                    }))
                    .build();
                let guest = start_guest(if pending { "" } else { "(loop br 0)" });
                let mut run = Box::pin(machine.run_process(&guest, start_config()));
                tokio::select! {
                    _ = probe.entered.notified() => (),
                    result = &mut run => panic!("pending start completed: {result:?}"),
                }
                drop(run);
                tokio::time::timeout(std::time::Duration::from_secs(10), probe.retired.notified())
                    .await
                    .unwrap();
                assert!(probe.lease.lock().unwrap().is_none());
                assert_eq!(probe.events.lock().unwrap().last().unwrap().0, "deactivate");
            }
        })
        .await;
}

#[tokio::test]
async fn killed_looping_start_reports_the_signal_status() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let probe = Arc::new(StartProbe::default());
            let machine = Machine::builder()
                .instantiation_hook(Arc::new(StartHook {
                    probe: probe.clone(),
                    pending: false,
                }))
                .build();
            let guest = start_guest("(loop br 0)");
            let run = machine.run_process(&guest, start_config());
            let kill = async {
                probe.entered.notified().await;
                machine.signal(wasixv2_abi::Signal::SIGKILL.0).unwrap();
            };
            let (status, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(run, kill)
            })
            .await
            .unwrap();
            assert_eq!(status.unwrap(), 137);
        })
        .await;
}

#[tokio::test]
async fn start_cannot_replace_already_bound_memory_layout() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let probe = Arc::new(StartProbe::default());
            let machine = Machine::builder()
                .instantiation_hook(Arc::new(StartHook {
                    probe: probe.clone(),
                    pending: false,
                }))
                .build();
            let guest = start_guest_layout(
                "i32.const 65552 global.set $heap",
                r#"
            (global (export "__data_start") i32 (i32.const 0))
            (global (export "__data_end") i32 (i32.const 32))
            (global (export "__stack_pointer") (mut i32) (i32.const 32768))
            (global $heap (export "__heap_base") (mut i32) (i32.const 65536))"#,
            );
            let error = machine
                .run_process(&guest, start_config())
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("start changed bound ABI memory layout"),
                "{error}"
            );
            assert!(probe.lease.lock().unwrap().is_none());
            assert_eq!(probe.events.lock().unwrap().last().unwrap().0, "deactivate");
        })
        .await;
}
