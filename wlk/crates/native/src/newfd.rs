use wasixv2_abi::{FcntlCmd, Fd, FdPair, OpenFlags, Ulong};
use wasixv2_kernel::Kernel;
use wasixv2_syscalls::{Control, Syscall, TaskId};

use crate::{BridgeMemory, platform::Request};

pub(super) enum Translation {
    Call(Syscall),
    Return(i64),
}

pub(super) fn translate(
    request: Request,
    memory: &mut BridgeMemory,
    kernel: &Kernel,
    task: TaskId,
) -> Option<Translation> {
    let fd = Fd(request.args[0] as i32);
    match request.nr {
        libc::SYS_dup => Some(Translation::Call(Syscall::Dup { fildes: fd })),
        libc::SYS_dup2 => {
            let newfd = Fd(request.args[1] as i32);
            if fd == newfd {
                return Some(Translation::Return(match fd_error(kernel, task, fd) {
                    Some(error) => error,
                    None => i64::from(fd.0),
                }));
            }
            Some(Translation::Call(Syscall::Dup3 {
                oldfd: fd,
                newfd,
                flags: OpenFlags::empty(),
            }))
        }
        libc::SYS_dup3 => Some(Translation::Call(Syscall::Dup3 {
            oldfd: fd,
            newfd: Fd(request.args[1] as i32),
            flags: OpenFlags(request.args[2] as u32),
        })),
        libc::SYS_fcntl => Some(translate_fcntl(request, kernel, task, fd)),
        libc::SYS_pipe | libc::SYS_pipe2 => {
            let guest_fds = match memory.map(request.args[0], 2 * size_of::<i32>(), false, true) {
                Ok(addr) => addr,
                Err(_) => return Some(Translation::Return(-(libc::EFAULT as i64))),
            };
            let flags = if request.nr == libc::SYS_pipe {
                OpenFlags::empty()
            } else {
                OpenFlags(request.args[1] as u32)
            };
            Some(Translation::Call(Syscall::Pipe2 {
                fildes: FdPair::new(guest_fds),
                flags,
            }))
        }
        _ => None,
    }
}

fn translate_fcntl(request: Request, kernel: &Kernel, task: TaskId, fd: Fd) -> Translation {
    let cmd = match request.args[1] as i32 {
        libc::F_DUPFD => FcntlCmd::F_DUPFD,
        libc::F_DUPFD_CLOEXEC => FcntlCmd::F_DUPFD_CLOEXEC,
        libc::F_GETFD => FcntlCmd::F_GETFD,
        libc::F_SETFD => FcntlCmd::F_SETFD,
        libc::F_GETFL => FcntlCmd::F_GETFL,
        libc::F_SETFL => FcntlCmd::F_SETFL,
        _ => {
            // TODO(native): convert native x86_64 flock layouts before supporting pointerful fcntl commands.
            return Translation::Return(
                fd_error(kernel, task, fd).unwrap_or(-(libc::ENOSYS as i64)),
            );
        }
    };
    Translation::Call(Syscall::Fcntl64 {
        fd,
        cmd,
        arg: request.args[2] as Ulong,
    })
}

fn fd_error(kernel: &Kernel, task: TaskId, fd: Fd) -> Option<i64> {
    match kernel.snapshot_descriptors(task, &[fd]) {
        Ok(set) if set.get(fd).is_some_and(|descriptor| descriptor.present) => None,
        Ok(_) => Some(-(libc::EBADF as i64)),
        Err(error) => Some(-(error.0 as i64)),
    }
}
