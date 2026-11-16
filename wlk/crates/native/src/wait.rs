//! Native Linux `wait4` translation through WLK's virtual child table.

use std::cell::RefCell;
use std::io;

use wasixv2_abi::{GuestLayout, Idtype, RusagePtr, Siginfo, SiginfoPtr, WaitOptions};
use wasixv2_kernel::{Dispatch, Kernel, SyscallEntry};
use wasixv2_syscalls::{Caller, Fault, Layer, LocalFuture, SysErr, Syscall, TaskId, UserMemory};

use crate::platform::{Action, Request};

const SIGINFO_ADDR: u32 = 0x1000;
const SIGINFO_BYTES: usize = Siginfo::SIZE;
const WAIT4_OPTIONS: u32 = libc::WNOHANG as u32 | libc::WUNTRACED as u32 | libc::WCONTINUED as u32;

/// Handle native `wait4` (syscall 61), translating WLK child events into Linux wait status.
pub async fn handle(
    request: Request,
    kernel: &Kernel,
    task: TaskId,
    trace: bool,
    program: &str,
) -> io::Result<Option<Action>> {
    if request.nr != libc::SYS_wait4 {
        return Ok(None);
    }

    let args = request.args;
    if args[3] != 0 {
        // TODO(native): convert WLK Rusage into native x86_64 struct rusage for wait4 callers.
        return Ok(Some(Action::Return(-(libc::ENOSYS as i64))));
    }

    let (which, upid) = match args[0] as i32 {
        -1 => (Idtype::P_ALL, 0),
        0 => (Idtype::P_PGID, 0),
        pid if pid > 0 => (Idtype::P_PID, pid),
        pid => match pid.checked_neg() {
            Some(pgid) => (Idtype::P_PGID, pgid),
            None => return Ok(Some(Action::Return(-(libc::EINVAL as i64)))),
        },
    };

    let raw_options = args[2] as u32;
    if raw_options & !WAIT4_OPTIONS != 0 {
        return Ok(Some(Action::Return(-(libc::EINVAL as i64))));
    }

    let mut options = WaitOptions::WEXITED.0;
    if raw_options & libc::WNOHANG as u32 != 0 {
        options |= WaitOptions::WNOHANG.0;
    }
    if raw_options & libc::WUNTRACED as u32 != 0 {
        options |= WaitOptions::WSTOPPED.0;
    }
    if raw_options & libc::WCONTINUED as u32 != 0 {
        options |= WaitOptions::WCONTINUED.0;
    }

    let memory = WaitMemory {
        output: RefCell::new([0; SIGINFO_BYTES]),
    };
    let call = Syscall::Waitid {
        which,
        upid,
        infop: SiginfoPtr::new(SIGINFO_ADDR),
        options: WaitOptions(options),
        ru: RusagePtr::NULL,
    };
    let caller = Caller::new(task, &memory).with_process_fork_allowed(false);
    let result = SyscallEntry(Dispatch).call(&caller, call, kernel).await;
    let mut raw = match result {
        Ok(value) => value.to_raw(),
        Err(SysErr::Errno(errno)) => -(errno.0 as i64),
        Err(
            SysErr::Restart
            | SysErr::RestartNoIntr
            | SysErr::RestartNoHand
            | SysErr::RestartBlock
            | SysErr::GuestUnwind,
        ) => -(libc::EINTR as i64),
    };

    if raw == 0 {
        let info = memory.siginfo();
        let child_pid = siginfo_i32(&info, 0);
        if child_pid > 0 {
            let Some(status) = wait_status(info.si_code, siginfo_i32(&info, 8)) else {
                return Ok(Some(Action::Return(-(libc::EIO as i64))));
            };
            if args[1] != 0 && !write_remote_i32(request.pid, args[1], status) {
                raw = -(libc::EFAULT as i64);
            } else {
                raw = i64::from(child_pid);
            }
        }
    }

    if trace {
        eprintln!("[wlk-native] {program}: {call:?} -> {raw}");
    }
    Ok(Some(Action::Return(raw)))
}

fn siginfo_i32(info: &Siginfo, offset: usize) -> i32 {
    i32::from_le_bytes([
        info.sifields[offset],
        info.sifields[offset + 1],
        info.sifields[offset + 2],
        info.sifields[offset + 3],
    ])
}

fn wait_status(code: i32, status: i32) -> Option<i32> {
    Some(match code {
        1 => (status & 0xff) << 8,              // CLD_EXITED
        2 => status & 0x7f,                     // CLD_KILLED
        3 => (status & 0x7f) | 0x80,            // CLD_DUMPED
        4 | 5 => ((status & 0x7f) << 8) | 0x7f, // CLD_TRAPPED / CLD_STOPPED
        6 => 0xffff,                            // CLD_CONTINUED
        _ => return None,
    })
}

fn write_remote_i32(pid: libc::pid_t, address: u64, value: i32) -> bool {
    let bytes = value.to_ne_bytes();
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

/// Local, fixed-size WLK memory for the siginfo output. Native wait status is copied to the
/// tracee only after Waitid reports a child event.
struct WaitMemory {
    output: RefCell<[u8; SIGINFO_BYTES]>,
}

impl WaitMemory {
    fn siginfo(&self) -> Siginfo {
        Siginfo::read_from(&self.output.borrow()[..]).expect("fixed-size siginfo buffer")
    }
}

impl UserMemory for WaitMemory {
    fn read<'a>(&'a self, addr: u32, bytes: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            if bytes.is_empty() {
                return Ok(());
            }
            let start = u64::from(addr);
            let end = start.checked_add(bytes.len() as u64).ok_or(Fault)?;
            let base = u64::from(SIGINFO_ADDR);
            let limit = base + SIGINFO_BYTES as u64;
            if start < base || end > limit {
                return Err(Fault);
            }
            let offset = (start - base) as usize;
            bytes.copy_from_slice(&self.output.borrow()[offset..offset + bytes.len()]);
            Ok(())
        })
    }

    fn write<'a>(&'a self, addr: u32, bytes: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            if bytes.is_empty() {
                return Ok(());
            }
            let start = u64::from(addr);
            let end = start.checked_add(bytes.len() as u64).ok_or(Fault)?;
            let base = u64::from(SIGINFO_ADDR);
            let limit = base + SIGINFO_BYTES as u64;
            if start < base || end > limit {
                return Err(Fault);
            }
            let offset = (start - base) as usize;
            self.output.borrow_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        Box::pin(async { u64::from(SIGINFO_ADDR) + SIGINFO_BYTES as u64 })
    }

    fn grow(&self, _pages: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}
