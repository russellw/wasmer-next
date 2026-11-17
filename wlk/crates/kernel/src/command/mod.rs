//! The boot-time registry of host images and the filesystem that exposes them.

pub(crate) mod context;
mod fs;
pub(crate) mod run;

use std::sync::Arc;

use wasixv2_syscalls::{Errno, LocalFuture};
use wasixv2_vfs::{CommandMark, Filesystem, NAME_MAX, PATH_MAX};

pub use context::{CommandContext, CommandCred, CommandFile, TaskFs};

/// A host implementation of an executable file.
pub trait VirtualCommand: Send + Sync + 'static {
    /// The task's `comm` while the command runs, truncated to 15 bytes.
    fn name(&self) -> &str;

    /// Runs as the task that exec'd this command. The future may be dropped at any await
    /// when the task is killed, its group exits, or the machine shuts down.
    fn run<'a>(&'a self, cx: CommandContext<'a>) -> LocalFuture<'a, CommandOutcome>;
}

pub enum CommandOutcome {
    /// Exit the thread group with this status.
    Exit(i32),
    /// Continue with a new image in the same task.
    Exec(Executed),
}

/// Proof that a context passed exec's point of no return.
pub struct Executed(pub(crate) Option<wasixv2_syscalls::Image>);

pub struct CommandSpec {
    pub command: Arc<dyn VirtualCommand>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub(crate) struct Entry {
    pub(crate) spec: CommandSpec,
    registry: Arc<()>,
}

/// The machine's commands, fixed before boot and shared by its kernels.
#[derive(Clone)]
pub struct Commands {
    fs: Arc<fs::CommandFs>,
    registry: Arc<()>,
}

impl Default for Commands {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Commands {
    pub fn builder() -> CommandsBuilder {
        CommandsBuilder {
            fs: fs::CommandFs::new(),
            registry: Arc::new(()),
        }
    }

    /// The read-only filesystem containing the registered executable files.
    pub fn filesystem(&self) -> Arc<dyn Filesystem> {
        self.fs.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.fs.is_empty()
    }

    pub(crate) fn recognise(&self, mark: CommandMark) -> Option<Arc<Entry>> {
        let entry = mark.0.downcast::<Entry>().ok()?;
        Arc::ptr_eq(&entry.registry, &self.registry).then_some(entry)
    }
}

pub struct CommandsBuilder {
    fs: fs::CommandFs,
    registry: Arc<()>,
}

impl CommandsBuilder {
    /// Registers a root-owned command with mode 0755.
    pub fn register(&mut self, path: &str, command: Arc<dyn VirtualCommand>) -> Result<(), Errno> {
        self.register_spec(
            path,
            CommandSpec {
                command,
                mode: 0o755,
                uid: 0,
                gid: 0,
            },
        )
    }

    /// Registers an absolute, normalized path. Implied parent directories are root-owned.
    pub fn register_spec(&mut self, path: &str, spec: CommandSpec) -> Result<(), Errno> {
        if spec.mode & !0o1777 != 0 {
            return Err(Errno::EINVAL);
        }
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let path = path.strip_prefix('/').ok_or(Errno::EINVAL)?;
        let parts: Vec<_> = path.as_bytes().split(|&b| b == b'/').collect();
        for part in &parts {
            if matches!(*part, b"" | b"." | b"..") || part.contains(&0) {
                return Err(Errno::EINVAL);
            }
            if part.len() > NAME_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
        }
        self.fs.insert(
            &parts,
            Arc::new(Entry {
                spec,
                registry: self.registry.clone(),
            }),
        )
    }

    pub fn build(self) -> Commands {
        Commands {
            fs: Arc::new(self.fs),
            registry: self.registry,
        }
    }
}
