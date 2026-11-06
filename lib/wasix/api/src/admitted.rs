//! Target-independent ownership of an admitted initial process.
use crate::{Engine, Executor, Machine, ProcessConfig, RunError};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use wasixv2_wait::{NoInterrupt, PollMask, WaitQueue, Waiter};
use wasmer::Module;

#[derive(Default)]
struct Completion {
    finished: AtomicBool,
    result: Mutex<Option<Result<i32, String>>>,
    changed: WaitQueue,
}

/// The owner of one admitted run, independently of its wait subscriptions.
/// Keep the Machine private to this run when using [`Self::kill`]: it ends the
/// Machine's complete process tree, including fork descendants.
///
/// Completion covers the initial process and console delivery. The embedder
/// still shuts down descendants and drains its providers and output streams.
/// Neither completion nor cancellation promises an OS-thread join.
pub struct Run {
    machine: Arc<Machine>,
    completion: Arc<Completion>,
    pid: u32,
}

/// An immutable-result observer with no process, Machine or executor ownership.
#[derive(Clone)]
pub struct RunObserver {
    completion: Arc<Completion>,
}
impl RunObserver {
    /// The initial execution result once observed, before console delivery ends.
    /// This is not a cleanup or completion fence; retain and wait on the Run.
    pub fn observed_result(&self) -> Option<Result<i32, String>> {
        self.completion.result.lock().unwrap().clone()
    }
}

impl Run {
    pub fn observer(&self) -> RunObserver {
        RunObserver {
            completion: self.completion.clone(),
        }
    }
    /// Kernel PID of the admitted initial process.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Wait repeatedly or concurrently for the cached final result. Dropping a
    /// wait unregisters only that subscription; the run owner remains live.
    pub async fn wait(&self) -> Result<i32, String> {
        let waiter = Waiter::new();
        let _registration = waiter.register(&self.completion.changed, PollMask::empty());
        loop {
            if self.completion.finished.load(Ordering::Acquire) {
                return self
                    .completion
                    .result
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("finished admitted run has a result");
            }
            waiter.sleep(&NoInterrupt, None).await;
        }
    }

    /// Kill and reap the Machine's running process tree before resolving.
    pub async fn kill(&self) -> Result<i32, String> {
        self.machine.shutdown().await;
        self.wait().await
    }

    pub fn signaller(&self) -> crate::Signaller {
        self.machine.signaller()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if self.completion.result.lock().unwrap().is_none() {
            let _ = self.machine.signal(9);
        }
    }
}

/// Admit a compiled module on the Machine's configured guest executor.
/// Only Engine/Module and engine-free run state cross its thread factory.
///
/// Call from the Host's local service executor when bindings require an owning
/// thread. Its supervisor delegates to the existing execution-layer factory,
/// which constructs and retires the Store on that one guest thread. Factory
/// refusal then appears in [`Run::wait`] after admission. The Host executors
/// must remain live until admitted runs and their cleanup finish.
pub async fn spawn(
    machine: Arc<Machine>,
    engine: Engine,
    module: Module,
    config: ProcessConfig,
) -> Result<Run, RunError> {
    let host = machine.task_host.clone();
    spawn_program(
        machine,
        host.executor(),
        Program::Module { engine, module },
        config,
    )
    .await
}

/// Admit a guest file through ordinary VFS exec semantics, including scripts,
/// the Machine's loader and `/proc/self/exe`. Uses [`spawn`]'s owner and executor
/// contract; the file and its arguments are resolved by the existing exec path.
pub async fn spawn_file(
    machine: Arc<Machine>,
    engine: Engine,
    path: String,
    config: ProcessConfig,
) -> Result<Run, RunError> {
    let host = machine.task_host.clone();
    spawn_program(
        machine,
        host.executor(),
        Program::file(engine, path, &config),
        config,
    )
    .await
}

pub(super) enum Program {
    Module {
        engine: Engine,
        module: Module,
    },
    File {
        engine: Engine,
        path: String,
        args: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    },
}

impl Program {
    pub(super) fn file(engine: Engine, path: String, config: &ProcessConfig) -> Self {
        let bytes = |strings: &[String]| strings.iter().map(|s| s.as_bytes().to_vec()).collect();
        Self::File {
            engine,
            path,
            args: bytes(&config.args),
            env: bytes(&config.env),
        }
    }
}

pub(super) async fn spawn_program(
    machine: Arc<Machine>,
    executor: &dyn Executor,
    program: Program,
    config: ProcessConfig,
) -> Result<Run, RunError> {
    if let Program::Module { module, .. } = &program {
        crate::preflight(module)?;
    }
    machine.check_thread_profile()?;
    // Publish before returning so an immediate kill sees the actual process.
    let (task, admission) = machine.start(config).await?;
    let admission = admission.into_owned(machine.clone());
    let pid = wasixv2_syscalls::PidView::pid_in(&machine.syscalls.inner, task, task) as u32;
    let completion = Arc::new(Completion::default());
    let output = completion.clone();
    let running = machine.clone();
    let owning = machine.abis.requires_owning_thread();
    let start: crate::ThreadStart = Box::new(move || {
        Box::pin(async move {
            // No guest image exists yet: respect pending kernel entry work before
            // constructing a Store or committing the first exec image.
            let result = match initial_entry(&running.syscalls.inner, task).await {
                Err(error) => {
                    drop(admission);
                    Err(error)
                }
                Ok(status) => {
                    let result = if let Some(status) = status {
                        Ok(status)
                    } else {
                        match program {
                            Program::Module { engine, module } if owning => {
                                wasixv2_exec::run_on_owning_thread(
                                    engine,
                                    &module,
                                    running.syscalls.clone(),
                                    task,
                                    running.task_host.clone(),
                                    running.abis.clone(),
                                )
                                .await
                                .map_err(RunError::Exec)
                            }
                            Program::Module { engine, module } => {
                                running
                                    .run_image(wasmer::Store::new(engine), &module, task)
                                    .await
                            }
                            Program::File {
                                engine,
                                path,
                                args,
                                env,
                            } => running.exec_file(&engine, task, &path, args, env).await,
                        }
                    };
                    admission.released();
                    result.map_err(|error| error.to_string())
                }
            };
            *output.result.lock().unwrap() = Some(result);
            running.console_sent().await;
            output.finished.store(true, Ordering::Release);
            output.changed.wake(PollMask::empty());
        })
    });
    if owning {
        // This is only a service future. The exec layer alone starts and
        // authorizes the guest's owning thread; no Store exists on this caller.
        machine.host.executor().spawn_local(start());
    } else {
        executor.spawn_thread(start).map_err(RunError::Spawn)?;
    }
    Ok(Run {
        machine,
        completion,
        pid,
    })
}

// This applies only to a newly admitted task, before any guest instruction,
// signal handler registration, fork, or image replacement can have occurred.
async fn initial_entry(
    kernel: &crate::Kernel,
    task: wasixv2_syscalls::TaskId,
) -> Result<Option<i32>, String> {
    use wasixv2_syscalls::{Control, GroupStop, GuestAction};
    loop {
        match kernel.take_pending(task) {
            None => return Ok(None),
            Some(GuestAction::Exit(status)) => {
                kernel.release(task);
                return Ok(Some(status));
            }
            Some(GuestAction::Stopped) => kernel.stop_wait(task).await,
            Some(
                action @ (GuestAction::StartThread { .. }
                | GuestAction::Signal(_)
                | GuestAction::Exec { .. }
                | GuestAction::SwitchTask { .. }
                | GuestAction::Fork { .. }
                | GuestAction::VforkReturn { .. }
                | GuestAction::ExitMm { .. }
                | GuestAction::StartImage { .. }),
            ) => {
                return Err(format!(
                    "unexpected work before initial guest entry: {action:?}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalFuture, Stdio, ThreadStart};
    use std::io;

    #[derive(Default)]
    struct Gate(Mutex<Option<ThreadStart>>);

    impl Executor for Gate {
        fn spawn_local(&self, _: LocalFuture<'static, ()>) {
            panic!("guest factory must not use the local service path");
        }

        fn spawn_thread(&self, start: ThreadStart) -> io::Result<()> {
            assert!(self.0.lock().unwrap().replace(start).is_none());
            Ok(())
        }

        fn spawn_blocking(&self, _: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
            panic!("guest admission must not use the blocking pool");
        }
    }

    struct Refuse;

    impl Executor for Refuse {
        fn spawn_local(&self, _: LocalFuture<'static, ()>) {
            panic!("unexpected service admission");
        }

        fn spawn_thread(&self, _: ThreadStart) -> io::Result<()> {
            Err(io::Error::other("test factory refusal"))
        }

        fn spawn_blocking(&self, _: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
            panic!("unexpected blocking admission");
        }
    }

    async fn admit(machine: Arc<Machine>) -> Result<Run, RunError> {
        let engine = Engine::default();
        let wasm = wat::parse_str(
            r#"(module
              (import "wasixv2" "exit_group" (func $exit (param i32)))
              (memory (export "memory") 1)
              (func (export "_start") (call $exit (i32.const 0))))"#,
        )
        .unwrap();
        let module = crate::load(&engine, &wasm).unwrap();
        spawn(
            machine,
            engine,
            module,
            ProcessConfig {
                args: vec![],
                env: vec![],
                stdio: Stdio::from_fns(|_| {}, |_| {}),
            },
        )
        .await
    }

    #[tokio::test]
    async fn immediate_signal_targets_admitted_pid_before_factory_runs() {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let run = admit(machine.clone()).await.unwrap();
        assert!(run.id() > 0);
        assert_eq!(machine.running.lock().unwrap().len(), 1);
        run.signaller().signal(15).unwrap();
        let start = gate.0.lock().unwrap().take().unwrap();
        tokio::task::LocalSet::new().run_until(start()).await;
        assert_eq!(run.wait().await.unwrap(), 143);
        assert!(machine.running.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn owner_drop_kills_before_the_factory_runs() {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let owner = admit(machine.clone()).await.unwrap();
        let completion = owner.completion.clone();
        drop(owner);
        let start = gate.0.lock().unwrap().take().unwrap();
        tokio::task::LocalSet::new().run_until(start()).await;
        assert_eq!(
            completion
                .result
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap(),
            &137
        );
        assert!(machine.running.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ordinary_initial_entry_runs_normally() {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let run = admit(machine.clone()).await.unwrap();
        let start = gate.0.lock().unwrap().take().unwrap();
        tokio::task::LocalSet::new().run_until(start()).await;
        assert_eq!(run.wait().await.unwrap(), 0);
        assert!(machine.running.lock().unwrap().is_empty());
    }

    async fn stopped_then(signal: i32, expected: i32) {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let run = admit(machine.clone()).await.unwrap();
        run.signaller().signal(19).unwrap();
        let start = gate.0.lock().unwrap().take().unwrap();
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut factory = start();
                assert!(futures_util::poll!(&mut factory).is_pending());
                assert!(run.completion.result.lock().unwrap().is_none());
                assert_eq!(machine.running.lock().unwrap().len(), 1);
                run.signaller().signal(signal).unwrap();
                factory.await;
            })
            .await;
        assert_eq!(run.wait().await.unwrap(), expected);
        assert!(machine.running.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stopped_initial_entry_waits_for_continue() {
        stopped_then(18, 0).await;
    }

    #[tokio::test]
    async fn killed_stopped_initial_entry_never_runs_guest() {
        stopped_then(9, 137).await;
    }

    #[tokio::test]
    async fn canceled_stopped_factory_retires_admission() {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let run = admit(machine.clone()).await.unwrap();
        run.signaller().signal(19).unwrap();
        let start = gate.0.lock().unwrap().take().unwrap();
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut factory = start();
                assert!(futures_util::poll!(&mut factory).is_pending());
                drop(factory);
            })
            .await;
        assert!(machine.running.lock().unwrap().is_empty());
        drop(run);
        machine.shutdown().await;
    }

    #[tokio::test]
    async fn missing_source_reports_error_and_releases_admission() {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let run = spawn_file(
            machine.clone(),
            Engine::default(),
            "/missing".into(),
            ProcessConfig {
                args: vec![],
                env: vec![],
                stdio: Stdio::from_fns(|_| {}, |_| {}),
            },
        )
        .await
        .unwrap();
        let start = gate.0.lock().unwrap().take().unwrap();
        tokio::task::LocalSet::new().run_until(start()).await;
        assert!(run.wait().await.unwrap_err().contains("/missing"));
        assert!(machine.running.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn refused_factory_releases_the_real_admission() {
        let machine = Arc::new(Machine::builder().task_executor(Arc::new(Refuse)).build());
        let error = admit(machine.clone()).await.err().expect("factory refused");
        assert!(matches!(error, RunError::Spawn(_)));
        assert!(error.to_string().contains("test factory refusal"));
        assert!(machine.running.lock().unwrap().is_empty());
        machine.shutdown().await;
    }

    #[tokio::test]
    async fn unpolled_factory_retains_and_then_retires_admission() {
        let gate = Arc::new(Gate::default());
        let machine = Arc::new(Machine::builder().task_executor(gate.clone()).build());
        let owner = admit(machine.clone()).await.unwrap();
        assert_eq!(machine.running.lock().unwrap().len(), 1);
        drop(gate.0.lock().unwrap().take().unwrap());
        assert!(machine.running.lock().unwrap().is_empty());
        drop(owner);
        machine.shutdown().await;
    }
}
