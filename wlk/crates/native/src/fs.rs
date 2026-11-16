//! Linux x86_64 filesystem syscall translation for the native tracee.

use std::{cell::RefCell, io};
use wasixv2_abi::{
    AccessMode, AtFlags, Buf, ConstKernelTimespecArray, Cstr, Fd, GuestLayout, LinuxDirent64Ptr,
    RenameFlags, Statx, StatxMask, StatxPtr,
};
use wasixv2_kernel::{Dispatch, Kernel, SyscallEntry};
use wasixv2_syscalls::{Caller, Fault, Layer, LocalFuture, SysErr, Syscall, TaskId, UserMemory};

use crate::{BridgeMemory, platform::Request};

const PATH_BYTES: usize = 4096;

/// Translate filesystem syscalls whose Linux and WLK result layouts are compatible.
///
/// Stat-family calls need a statx-to-`struct stat` output conversion and are handled by the
/// caller's separate post-dispatch path.
pub fn translate(request: Request, memory: &mut BridgeMemory) -> io::Result<Option<Syscall>> {
    let a = request.args;
    let at_fdcwd = Fd(libc::AT_FDCWD);
    let call = match request.nr {
        21 => Some(Syscall::Faccessat {
            dfd: at_fdcwd,
            filename: cstr(memory, a[0])?,
            mode: AccessMode(a[1] as u32),
        }),
        80 => Some(Syscall::Chdir {
            filename: cstr(memory, a[0])?,
        }),
        81 => Some(Syscall::Fchdir {
            fd: Fd(a[0] as i32),
        }),
        82 => Some(Syscall::Renameat2 {
            olddfd: at_fdcwd,
            oldname: cstr(memory, a[0])?,
            newdfd: at_fdcwd,
            newname: cstr(memory, a[1])?,
            flags: RenameFlags(0),
        }),
        83 | 258 => Some(Syscall::Mkdirat {
            dfd: if request.nr == 83 {
                at_fdcwd
            } else {
                Fd(a[0] as i32)
            },
            pathname: cstr(memory, a[if request.nr == 83 { 0 } else { 1 }])?,
            mode: a[if request.nr == 83 { 1 } else { 2 }] as u32,
        }),
        84 => Some(Syscall::Unlinkat {
            dfd: at_fdcwd,
            pathname: cstr(memory, a[0])?,
            flag: AtFlags(libc::AT_REMOVEDIR as u32),
        }),
        87 => Some(Syscall::Unlinkat {
            dfd: at_fdcwd,
            pathname: cstr(memory, a[0])?,
            flag: AtFlags(0),
        }),
        88 => Some(Syscall::Symlinkat {
            oldname: cstr(memory, a[0])?,
            newdfd: at_fdcwd,
            newname: cstr(memory, a[1])?,
        }),
        89 => Some(readlinkat(memory, at_fdcwd, a[0], a[1], a[2])?),
        90 => Some(Syscall::Fchmodat {
            dfd: at_fdcwd,
            filename: cstr(memory, a[0])?,
            mode: a[1] as u32,
        }),
        91 => Some(Syscall::Fchmod {
            fd: Fd(a[0] as i32),
            mode: a[1] as u32,
        }),
        217 => {
            let count = crate::bounded_len(a[2]);
            let addr = memory.map(a[1], count, false, true)?;
            Some(Syscall::Getdents64 {
                fd: Fd(a[0] as i32),
                dirent: LinuxDirent64Ptr::new(addr),
                count: count as u32,
            })
        }
        263 => Some(Syscall::Unlinkat {
            dfd: Fd(a[0] as i32),
            pathname: cstr(memory, a[1])?,
            flag: AtFlags(a[2] as u32),
        }),
        264 => Some(Syscall::Renameat2 {
            olddfd: Fd(a[0] as i32),
            oldname: cstr(memory, a[1])?,
            newdfd: Fd(a[2] as i32),
            newname: cstr(memory, a[3])?,
            flags: RenameFlags(0),
        }),
        266 => Some(Syscall::Symlinkat {
            oldname: cstr(memory, a[0])?,
            newdfd: Fd(a[1] as i32),
            newname: cstr(memory, a[2])?,
        }),
        267 => Some(readlinkat(memory, Fd(a[0] as i32), a[1], a[2], a[3])?),
        268 => Some(Syscall::Fchmodat {
            dfd: Fd(a[0] as i32),
            filename: cstr(memory, a[1])?,
            mode: a[2] as u32,
        }),
        269 => Some(Syscall::Faccessat {
            dfd: Fd(a[0] as i32),
            filename: cstr(memory, a[1])?,
            mode: AccessMode(a[2] as u32),
        }),
        280 => {
            let times = if a[2] == 0 {
                ConstKernelTimespecArray::new(0)
            } else {
                ConstKernelTimespecArray::new(memory.map(a[2], 32, true, false)?)
            };
            Some(Syscall::UtimensatTime64 {
                dfd: Fd(a[0] as i32),
                filename: cstr(memory, a[1])?,
                utimes: times,
                flags: AtFlags(a[3] as u32),
            })
        }
        316 => Some(Syscall::Renameat2 {
            olddfd: Fd(a[0] as i32),
            oldname: cstr(memory, a[1])?,
            newdfd: Fd(a[2] as i32),
            newname: cstr(memory, a[3])?,
            flags: RenameFlags(a[4] as u32),
        }),
        439 => Some(Syscall::Faccessat2 {
            dfd: Fd(a[0] as i32),
            filename: cstr(memory, a[1])?,
            mode: AccessMode(a[2] as u32),
            flags: AtFlags(a[3] as u32),
        }),
        452 => Some(Syscall::Fchmodat2 {
            dfd: Fd(a[0] as i32),
            filename: cstr(memory, a[1])?,
            mode: a[2] as u32,
            flags: AtFlags(a[3] as u32),
        }),
        332 => {
            let path = cstr(memory, a[1])?;
            let buffer = StatxPtr::new(memory.map(a[4], 256, false, true)?);
            Some(Syscall::Statx {
                dfd: Fd(a[0] as i32),
                filename: path,
                flags: AtFlags(a[2] as u32),
                mask: StatxMask(a[3] as u32),
                buffer,
            })
        }
        _ => None,
    };
    Ok(call)
}

fn cstr(memory: &mut BridgeMemory, host_addr: u64) -> io::Result<Cstr> {
    Ok(Cstr::new(memory.map(host_addr, PATH_BYTES, true, false)?))
}

fn readlinkat(
    memory: &mut BridgeMemory,
    dfd: Fd,
    path: u64,
    buffer: u64,
    requested: u64,
) -> io::Result<Syscall> {
    let count = crate::bounded_len(requested).min(i32::MAX as usize);
    let path = cstr(memory, path)?;
    let buffer = Buf::new(memory.map(buffer, count, false, true)?);
    Ok(Syscall::Readlinkat {
        dfd,
        pathname: path,
        buf: buffer,
        bufsiz: count as i32,
    })
}

const STAT_PATH_ADDR: u32 = 0x1000;
const STAT_OUT_ADDR: u32 = 0x2000;
const STATX_BYTES: usize = 256;

/// A `stat`-family request that needs WLK statx output converted to Linux x86_64 `struct stat`.
// TODO: Replace this adapter if the kernel exposes the native x86_64 `struct stat` ABI directly.
///
/// The bridge dispatches [`Self::syscall`] with [`Self::memory`] as the caller memory, then calls
/// [`Self::copy_back`] only when WLK returns success.
pub struct StatRequest {
    call: Syscall,
    memory: StatMemory,
    native_addr: u64,
}

impl StatRequest {
    pub fn syscall(&self) -> Syscall {
        self.call
    }

    pub fn memory(&self) -> &StatMemory {
        &self.memory
    }

    /// Convert the WLK statx result to the host Linux x86_64 `struct stat` and copy it to the
    /// original tracee pointer. `-EFAULT` indicates that the native output pointer was invalid.
    pub fn copy_back(&self) -> Result<(), i64> {
        let bytes = *self.memory.output.borrow();
        let statx = Statx::read_from(&bytes).ok_or(-(libc::EIO as i64))?;
        let mut native: libc::stat = unsafe { std::mem::zeroed() };
        native.st_dev = libc::makedev(statx.stx_dev_major, statx.stx_dev_minor);
        native.st_ino = statx.stx_ino as libc::ino_t;
        native.st_nlink = statx.stx_nlink as libc::nlink_t;
        native.st_mode = statx.stx_mode as libc::mode_t;
        native.st_uid = statx.stx_uid;
        native.st_gid = statx.stx_gid;
        native.st_rdev = libc::makedev(statx.stx_rdev_major, statx.stx_rdev_minor);
        native.st_size = statx.stx_size as libc::off_t;
        native.st_blksize = statx.stx_blksize as libc::blksize_t;
        native.st_blocks = statx.stx_blocks as libc::blkcnt_t;
        native.st_atime = statx.stx_atime.tv_sec as libc::time_t;
        native.st_atime_nsec = i64::from(statx.stx_atime.tv_nsec);
        native.st_mtime = statx.stx_mtime.tv_sec as libc::time_t;
        native.st_mtime_nsec = i64::from(statx.stx_mtime.tv_nsec);
        native.st_ctime = statx.stx_ctime.tv_sec as libc::time_t;
        native.st_ctime_nsec = i64::from(statx.stx_ctime.tv_nsec);

        // SAFETY: `libc::stat` contains only integer fields on Linux x86_64. The value was
        // zero-initialized before assigning fields, so its padding is initialized as well.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&native as *const libc::stat).cast::<u8>(),
                std::mem::size_of::<libc::stat>(),
            )
        };
        if write_remote(self.memory.pid, self.native_addr, bytes) {
            Ok(())
        } else {
            Err(-(libc::EFAULT as i64))
        }
    }
}

/// Handle one Linux stat-family syscall through WLK and copy its result to native `struct stat`.
pub async fn handle_stat(
    request: Request,
    kernel: &Kernel,
    task: TaskId,
    trace: bool,
    program: &str,
) -> io::Result<Option<crate::platform::Action>> {
    let Some(stat) = translate_stat(request) else {
        return Ok(None);
    };
    let call = stat.syscall();
    let caller = Caller::new(task, stat.memory()).with_process_fork_allowed(false);
    let result = SyscallEntry(Dispatch).call(&caller, call, kernel).await;
    let mut raw = match result {
        Ok(value) => value.to_raw(),
        Err(SysErr::Errno(errno)) => -(errno.0 as i64),
        Err(SysErr::NamespaceBoundary) => -(libc::ENOENT as i64),
        Err(SysErr::NamespaceMutation) => -(libc::EACCES as i64),
        Err(
            SysErr::Restart
            | SysErr::RestartNoIntr
            | SysErr::RestartNoHand
            | SysErr::RestartBlock
            | SysErr::GuestUnwind,
        ) => -(libc::EINTR as i64),
    };
    if raw == 0
        && let Err(errno) = stat.copy_back()
    {
        raw = errno;
    }
    if trace {
        eprintln!("[wlk-native] {program}: {call:?} -> {raw}");
    }
    Ok(Some(crate::platform::Action::Return(raw)))
}

/// Return a stat-family call that requires native `struct stat` result conversion.
pub fn translate_stat(request: Request) -> Option<StatRequest> {
    let a = request.args;
    let at_fdcwd = Fd(libc::AT_FDCWD);
    let (dfd, path, flags, native_addr) = match request.nr {
        4 => (at_fdcwd, Some(a[0]), AtFlags(0), a[1]), // stat
        5 => (
            Fd(a[0] as i32),
            None,
            AtFlags(libc::AT_EMPTY_PATH as u32),
            a[1],
        ), // fstat
        6 => (
            at_fdcwd,
            Some(a[0]),
            AtFlags(libc::AT_SYMLINK_NOFOLLOW as u32),
            a[1],
        ), // lstat
        262 => (Fd(a[0] as i32), Some(a[1]), AtFlags(a[3] as u32), a[2]), // newfstatat
        _ => return None,
    };

    let call = Syscall::Statx {
        dfd,
        filename: Cstr::new(STAT_PATH_ADDR),
        flags,
        mask: StatxMask(0x7ff), // STATX_BASIC_STATS
        buffer: StatxPtr::new(STAT_OUT_ADDR),
    };
    Some(StatRequest {
        call,
        memory: StatMemory {
            pid: request.pid,
            path_host: path,
            output: RefCell::new([0; STATX_BYTES]),
        },
        native_addr,
    })
}

/// The small address space used for a single statx translation. Paths are read from the stopped
/// tracee; the statx result is kept locally until it is converted back to native `struct stat`.
pub struct StatMemory {
    pid: libc::pid_t,
    path_host: Option<u64>,
    output: RefCell<[u8; STATX_BYTES]>,
}

impl UserMemory for StatMemory {
    fn read<'a>(&'a self, addr: u32, bytes: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            if bytes.is_empty() {
                return Ok(());
            }
            let start = addr as u64;
            let end = start.checked_add(bytes.len() as u64).ok_or(Fault)?;
            if start >= u64::from(STAT_PATH_ADDR)
                && end <= u64::from(STAT_PATH_ADDR) + PATH_BYTES as u64
            {
                let Some(host) = self.path_host else {
                    bytes.fill(0);
                    return Ok(());
                };
                let remote = host
                    .checked_add(start - u64::from(STAT_PATH_ADDR))
                    .ok_or(Fault)?;
                return read_remote(self.pid, remote, bytes)
                    .then_some(())
                    .ok_or(Fault);
            }
            let out_start = u64::from(STAT_OUT_ADDR);
            if start >= out_start && end <= out_start + STATX_BYTES as u64 {
                let output = self.output.borrow();
                let offset = (start - out_start) as usize;
                bytes.copy_from_slice(output.get(offset..offset + bytes.len()).ok_or(Fault)?);
                return Ok(());
            }
            Err(Fault)
        })
    }

    fn write<'a>(&'a self, addr: u32, bytes: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            if bytes.is_empty() {
                return Ok(());
            }
            let start = u64::from(addr);
            let end = start.checked_add(bytes.len() as u64).ok_or(Fault)?;
            let out_start = u64::from(STAT_OUT_ADDR);
            if start < out_start || end > out_start + STATX_BYTES as u64 {
                return Err(Fault);
            }
            let mut output = self.output.borrow_mut();
            let offset = (start - out_start) as usize;
            output
                .get_mut(offset..offset + bytes.len())
                .ok_or(Fault)?
                .copy_from_slice(bytes);
            Ok(())
        })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        Box::pin(async { (STAT_OUT_ADDR + STATX_BYTES as u32) as u64 })
    }

    fn grow(&self, _pages: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}

fn read_remote(pid: libc::pid_t, address: u64, bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) == bytes.len() as isize }
}

fn write_remote(pid: libc::pid_t, address: u64, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) == bytes.len() as isize }
}
