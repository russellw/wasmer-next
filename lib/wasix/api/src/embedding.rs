//! External ownership of a process whose instances are supplied by an embedder.

use std::sync::Arc;

use wasixv2_exec::Abis;
use wasixv2_host::Host;
use wasixv2_syscalls::TaskId;

use crate::{Machine, MachineSyscalls, ProcessConfig, RunError, Running};

pub use wasixv2_kernel::{BootstrappedProcess, DirectoryBootstrap, NamespaceBootstrap};

/// One process started through the Machine's ordinary configuration path.
///
/// This owner contains no Store or instance. The embedder retains and settles its
/// guest invocations before closing it; closing retires only this process. Other
/// processes and their Machine remain usable.
pub struct EmbeddingProcess {
    machine: Arc<Machine>,
    task: TaskId,
    registration: Option<Running>,
    #[cfg(feature = "wasix1")]
    wasix1: Option<wasixv2_wasix1::HostProcessState>,
}

impl Machine {
    /// Starts a process without selecting or running an instance or entry point.
    /// Drive this future on the executor configured for this Machine.
    pub async fn start_embedding(
        self: &Arc<Self>,
        config: ProcessConfig,
    ) -> Result<EmbeddingProcess, RunError> {
        self.check_thread_profile()?;
        let (task, registration) = self.start(config).await?;
        Ok(EmbeddingProcess::new(self.clone(), task, registration))
    }

    /// Starts a process in an explicitly granted filesystem namespace. Descriptor
    /// identity comes from the kernel's completed bootstrap; no path is reopened.
    pub async fn start_embedding_with_namespace(
        self: &Arc<Self>,
        config: ProcessConfig,
        namespace: NamespaceBootstrap,
    ) -> Result<(EmbeddingProcess, BootstrappedProcess), RunError> {
        self.check_thread_profile()?;
        let (task, registration, bootstrap) = self
            .start_with(|| async {
                self.syscalls
                    .inner
                    .spawn_with_namespace(config, namespace)
                    .await
                    .map(|bootstrap| (bootstrap.task, bootstrap))
            })
            .await?;
        Ok((
            EmbeddingProcess::new(self.clone(), task, registration),
            bootstrap,
        ))
    }
}

impl EmbeddingProcess {
    fn new(machine: Arc<Machine>, task: TaskId, registration: Running) -> Self {
        #[cfg(feature = "wasix1")]
        let wasix1 = Some(machine.wasix1.abi.host_process(task));
        Self {
            machine,
            task,
            registration: Some(registration),
            #[cfg(feature = "wasix1")]
            wasix1,
        }
    }

    pub fn task(&self) -> TaskId {
        self.task
    }

    pub fn syscalls(&self) -> Arc<MachineSyscalls> {
        self.machine.syscalls.clone()
    }

    /// The Machine's guest-task executor and clocks, including a configured
    /// executor override rather than its underlying host executor.
    pub fn host(&self) -> Arc<dyn Host> {
        self.machine.task_host.clone()
    }

    pub fn abis(&self) -> Arc<Abis<MachineSyscalls>> {
        self.machine.abis.clone()
    }

    /// The process state of the exact Wasix1 ABI registered in this Machine.
    /// Returns None after this process owner has been closed.
    #[cfg(feature = "wasix1")]
    pub fn wasix1(&self) -> Option<&wasixv2_wasix1::HostProcessState> {
        self.wasix1.as_ref()
    }

    /// Retires this process once. Settle its guest invocations before calling.
    pub fn close(&mut self) {
        drop(self.registration.take());
        #[cfg(feature = "wasix1")]
        drop(self.wasix1.take());
    }
}

impl Drop for EmbeddingProcess {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;
    use crate::Stdio;
    use wasixv2_abi::{Errno, Signal};

    fn config() -> ProcessConfig {
        ProcessConfig {
            args: vec!["embedded".into()],
            env: vec![],
            stdio: Stdio::inherit(),
        }
    }

    #[tokio::test]
    async fn closing_one_embedding_process_keeps_its_sibling_live() {
        let machine = Arc::new(Machine::new());
        let mut first = machine.start_embedding(config()).await.unwrap();
        let second = machine.start_embedding(config()).await.unwrap();
        let first_task = first.task();
        let second_task = second.task();
        assert_ne!(first_task, second_task);
        assert!(Arc::ptr_eq(&first.syscalls(), &second.syscalls()));
        assert!(Arc::ptr_eq(&first.abis(), &machine.abis));
        assert!(Arc::ptr_eq(&first.host(), &machine.task_host));

        first.close();
        first.close();
        assert_eq!(
            machine.syscalls.inner.kill(first_task, Signal(0)),
            Err(Errno::ESRCH)
        );
        assert_eq!(machine.syscalls.inner.kill(second_task, Signal(0)), Ok(()));
        assert_eq!(*machine.running.lock().unwrap(), vec![second_task]);
        #[cfg(feature = "wasix1")]
        assert!(first.wasix1().is_none());

        drop(second);
        assert_eq!(
            machine.syscalls.inner.kill(second_task, Signal(0)),
            Err(Errno::ESRCH)
        );
        assert!(machine.running.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_embedding_setup_releases_its_process_registration() {
        let mut machine = Machine::new();
        machine.set_working_dir("/missing");
        let machine = Arc::new(machine);
        assert!(matches!(
            machine.start_embedding(config()).await,
            Err(RunError::WorkingDir(_))
        ));
        assert!(machine.running.lock().unwrap().is_empty());
    }
}
