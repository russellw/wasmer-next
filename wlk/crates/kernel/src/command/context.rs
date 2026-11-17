//! File operations and exec as the task that owns a virtual command.

use std::{cell::RefCell, future::poll_fn, sync::Arc, task::Poll};

use wasixv2_abi::{AtFd, AtFlags, Errno, Fd, OpenFlags};
use wasixv2_syscalls::{
    Caller, Fault, LocalFuture, SysErr, SysResult, Syscalls, TaskId, UserMemory, UserSlice,
    UserSliceMut,
};
use wasixv2_vfs::{File, MntNs, Path, SharedContents, Vfs};

use crate::{
    Kernel,
    fs::{build_open_flags, build_open_how},
    process::ExecTarget,
};

use super::Executed;

pub struct CommandContext<'a> {
    pub(super) kernel: &'a Kernel,
    pub(super) task: TaskId,
    pub(super) args: Vec<Vec<u8>>,
    pub(super) env: Vec<Vec<u8>>,
}

pub struct CommandCred {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub groups: Vec<u32>,
}

pub struct TaskFs {
    pub vfs: Arc<Vfs>,
    pub root: Path,
    pub cwd: Path,
    pub namespace: Arc<MntNs>,
}

impl CommandContext<'_> {
    pub fn task(&self) -> TaskId {
        self.task
    }

    pub fn pid(&self) -> i32 {
        self.kernel.pids.own_nr(self.task.0)
    }

    pub fn args(&self) -> &[Vec<u8>] {
        &self.args
    }

    pub fn env(&self) -> &[Vec<u8>] {
        &self.env
    }

    pub fn credentials(&self) -> CommandCred {
        let cred = self.kernel.task_cred(self.task);
        let ns = &cred.user_ns;
        CommandCred {
            uid: ns.munged_uid(cred.user.real),
            gid: ns.munged_gid(cred.group.real),
            euid: ns.munged_uid(cred.user.effective),
            egid: ns.munged_gid(cred.group.effective),
            groups: cred.groups.iter().map(|&gid| ns.munged_gid(gid)).collect(),
        }
    }

    pub async fn cwd(&self) -> Result<Vec<u8>, Errno> {
        let fs = self.fs();
        if fs.cwd.dentry.is_unlinked() {
            return Err(Errno::ENOENT);
        }
        Ok(fs.vfs.d_path(&fs.cwd, &fs.root))
    }

    pub async fn read(&self, fd: Fd, buf: &mut [u8]) -> Result<usize, Errno> {
        let len = buf.len().min(i32::MAX as usize) as u32;
        let memory = Buffer::Output(RefCell::new(buf));
        let caller = Caller::new(self.task, &memory);
        restart(|| self.kernel.read(&caller, fd, UserSliceMut::new(0, len)))
            .await
            .map(|n| n as usize)
    }

    pub async fn write(&self, fd: Fd, buf: &[u8]) -> Result<usize, Errno> {
        let len = buf.len().min(i32::MAX as usize) as u32;
        let memory = Buffer::Input(buf);
        let caller = Caller::new(self.task, &memory);
        restart(|| self.kernel.write(&caller, fd, UserSlice::new(0, len)))
            .await
            .map(|n| n as usize)
    }

    pub async fn write_all(&self, fd: Fd, mut buf: &[u8]) -> Result<(), Errno> {
        while !buf.is_empty() {
            let written = self.write(fd, buf).await?;
            if written == 0 {
                return Err(Errno::EIO);
            }
            buf = &buf[written..];
        }
        Ok(())
    }

    /// Opens a guest path for reading without allocating a task descriptor.
    pub async fn open(&self, path: &[u8], flags: OpenFlags) -> Result<CommandFile, Errno> {
        if flags.intersects(
            OpenFlags::O_ACCMODE
                | OpenFlags::O_CREAT
                | OpenFlags::__O_TMPFILE
                | OpenFlags::O_TRUNC
                | OpenFlags::O_EMPTYPATH,
        ) {
            return Err(Errno::EINVAL);
        }
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.contains(&0) {
            return Err(Errno::EINVAL);
        }
        if path.len() >= wasixv2_vfs::PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let (flags, lookup) = build_open_flags(&build_open_how(flags, 0))?;
        restart(|| async {
            let env = self.kernel.task_env(self.task);
            let file = self
                .kernel
                .vfs
                .open(
                    &env.cx(),
                    &env.fs.cwd,
                    path,
                    &wasixv2_vfs::OpenHow {
                        flags,
                        mode: 0,
                        lookup,
                    },
                )
                .await
                .map_err(|err| env.error(err))?;
            let size = self.kernel.vfs.stat(&file.path).await?.size;
            Ok(CommandFile { file, size })
        })
        .await
    }

    /// The task's root, cwd and mount namespace for privileged host operations.
    pub fn fs(&self) -> TaskFs {
        let env = self.kernel.task_env(self.task);
        TaskFs {
            vfs: self.kernel.vfs.clone(),
            root: env.fs.root,
            cwd: env.fs.cwd,
            namespace: self.kernel.task_ns(self.task).mnt.tree.clone(),
        }
    }

    /// Executes a guest path with ordinary exec permissions and without searching PATH.
    pub async fn exec(
        self,
        path: &[u8],
        args: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<Executed, (Self, Errno)> {
        if path.len() >= wasixv2_vfs::PATH_MAX {
            return Err((self, Errno::ENAMETOOLONG));
        }
        if path.contains(&0) {
            return Err((self, Errno::EINVAL));
        }
        self.exec_target(
            ExecTarget::At(Fd(AtFd::AT_FDCWD.0), path.to_vec(), AtFlags(0)),
            args,
            env,
        )
        .await
    }

    /// Executes an open file with the checks of `execveat(AT_EMPTY_PATH)`.
    pub async fn exec_file(
        self,
        file: &File,
        args: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<Executed, (Self, Errno)> {
        if !Arc::ptr_eq(file.vfs(), &self.kernel.vfs) {
            return Err((self, Errno::EXDEV));
        }
        self.exec_target(ExecTarget::Path(file.path.clone()), args, env)
            .await
    }

    async fn exec_target(
        self,
        target: ExecTarget,
        args: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<Executed, (Self, Errno)> {
        self.kernel
            .exec_host(self.task, target, args, env)
            .await
            .map_err(|err| (self, err))
    }
}

pub struct CommandFile {
    file: File,
    size: u64,
}

impl CommandFile {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub async fn read_at(&self, buf: &mut [u8], at: u64) -> Result<usize, Errno> {
        self.file.read_at(buf, at).await
    }

    pub async fn shared_contents(&self) -> Option<SharedContents> {
        self.file.shared_contents().await
    }

    pub fn file(&self) -> &File {
        &self.file
    }
}

pub(crate) fn errno(err: SysErr) -> Errno {
    match err {
        SysErr::Errno(errno) => errno,
        SysErr::NamespaceBoundary => Errno::ENOENT,
        SysErr::NamespaceMutation => Errno::EACCES,
        _ => Errno::EINTR,
    }
}

/// No caught handlers survive exec. Give the driver a poll to deliver a stop or exit
/// before retrying a restartable syscall.
async fn restart<T, F: Future<Output = SysResult<T>>>(
    mut op: impl FnMut() -> F,
) -> Result<T, Errno> {
    loop {
        match op().await {
            Err(SysErr::Restart | SysErr::RestartNoIntr | SysErr::RestartNoHand) => {
                let mut yielded = false;
                poll_fn(|cx| {
                    if std::mem::replace(&mut yielded, true) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
            }
            result => return result.map_err(errno),
        }
    }
}

/// A short-lived copy capability for the normal syscall I/O paths. Never attached to the mm.
enum Buffer<'a> {
    Input(&'a [u8]),
    Output(RefCell<&'a mut [u8]>),
}

impl UserMemory for Buffer<'_> {
    fn read<'a>(&'a self, addr: u32, buf: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let Self::Input(data) = self else {
                return Err(Fault);
            };
            let start = addr as usize;
            let end = start.checked_add(buf.len()).ok_or(Fault)?;
            buf.copy_from_slice(data.get(start..end).ok_or(Fault)?);
            Ok(())
        })
    }

    fn write<'a>(&'a self, addr: u32, data: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let Self::Output(buf) = self else {
                return Err(Fault);
            };
            let start = addr as usize;
            let end = start.checked_add(data.len()).ok_or(Fault)?;
            buf.borrow_mut()
                .get_mut(start..end)
                .ok_or(Fault)?
                .copy_from_slice(data);
            Ok(())
        })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        Box::pin(async {
            match self {
                Self::Input(data) => data.len() as u64,
                Self::Output(buf) => buf.borrow().len() as u64,
            }
        })
    }

    fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}
