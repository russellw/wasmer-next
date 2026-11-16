use std::{io, mem};

const WAIT_ALL: libc::c_int = 0x4000_0000;
const PTRACE_EVENT_SECCOMP: u32 = 7;
const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
const SYSCALL_INFO_ENTRY: u8 = 1;
const SYSCALL_INFO_EXIT: u8 = 2;
const SYSCALL_INFO_SECCOMP: u8 = 3;

#[repr(C, align(8))]
struct SyscallInfo {
    op: u8,
    padding: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 16],
}

pub(crate) struct Injection {
    pid: libc::pid_t,
    original: libc::user_regs_struct,
    instruction: u64,
    finished: bool,
}

impl Injection {
    /// Suppress the syscall at the current seccomp stop and leave the tracee stopped at its exit.
    pub(crate) fn begin(pid: libc::pid_t) -> io::Result<Self> {
        let original = get_regs(pid)?;
        let instruction = original
            .rip
            .checked_sub(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "syscall site underflow"))?;
        let mut opcode = [0; 2];
        if !read_remote(pid, instruction, &mut opcode) || opcode != [0x0f, 0x05] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native syscall instruction is not available for injection",
            ));
        }

        let mut skipped = original;
        skipped.orig_rax = u64::MAX;
        set_regs(pid, &mut skipped)?;
        if let Err(error) = resume_until_exit(pid) {
            let mut restore = original;
            let _ = set_regs(pid, &mut restore);
            return Err(error);
        }

        Ok(Self {
            pid,
            original,
            instruction,
            finished: false,
        })
    }

    pub(crate) fn syscall_site(&self) -> u64 {
        self.instruction
    }

    /// Execute one syscall through the validated syscall instruction, consuming all its ptrace
    /// stops synchronously on the thread that owns this tracee.
    pub(crate) fn call(&mut self, nr: i64, args: [u64; 6]) -> io::Result<i64> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "injection session is already finished",
            ));
        }

        let mut regs = self.original;
        regs.rip = self.instruction;
        regs.orig_rax = nr as u64;
        regs.rax = nr as u64;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        set_regs(self.pid, &mut regs)?;

        ptrace_checked(libc::PTRACE_SYSCALL, self.pid, 0, 0)?;
        wait_for_seccomp(self.pid)?;
        ptrace_checked(libc::PTRACE_SYSCALL, self.pid, 0, 0)?;
        wait_for_exit(self.pid)
    }

    /// Restore the full native register image at the current stopped syscall-exit boundary.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if !self.finished {
            set_regs(self.pid, &mut self.original)?;
            self.finished = true;
        }
        Ok(())
    }
}

impl Drop for Injection {
    fn drop(&mut self) {
        if !self.finished {
            // TODO(native): interrupted injected syscalls fail closed; restore registers best-effort
            // and let the supervisor tear down the tracee rather than running a signal handler here.
            let _ = set_regs(self.pid, &mut self.original);
        }
    }
}

pub(crate) fn write_remote(pid: libc::pid_t, address: u64, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        let local = libc::iovec {
            iov_base: bytes[written..].as_ptr() as *mut libc::c_void,
            iov_len: bytes.len() - written,
        };
        let remote = libc::iovec {
            iov_base: (address + written as u64) as *mut libc::c_void,
            iov_len: bytes.len() - written,
        };
        // SAFETY: both iovecs describe live local/tracee buffers for the duration of the call.
        let count = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        written += count as usize;
    }
    Ok(())
}

fn resume_until_exit(pid: libc::pid_t) -> io::Result<()> {
    ptrace_checked(libc::PTRACE_SYSCALL, pid, 0, 0)?;
    wait_for_exit(pid).map(|_| ())
}

fn wait_for_seccomp(pid: libc::pid_t) -> io::Result<()> {
    for _ in 0..8 {
        let status = wait_stopped(pid)?;
        let event = (status as u32) >> 16;
        if event == PTRACE_EVENT_SECCOMP {
            return Ok(());
        }
        if libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80) {
            match syscall_info_op(pid)? {
                SYSCALL_INFO_ENTRY => ptrace_checked(libc::PTRACE_SYSCALL, pid, 0, 0)?,
                SYSCALL_INFO_SECCOMP => return Ok(()),
                _ => {
                    return Err(injection_error(
                        "injected syscall exited before seccomp stop",
                    ));
                }
            }
            continue;
        }
        return Err(unexpected_stop(status));
    }
    Err(injection_error(
        "too many stops before injected seccomp event",
    ))
}

fn wait_for_exit(pid: libc::pid_t) -> io::Result<i64> {
    for _ in 0..8 {
        let status = wait_stopped(pid)?;
        let event = (status as u32) >> 16;
        if event == PTRACE_EVENT_SECCOMP {
            ptrace_checked(libc::PTRACE_SYSCALL, pid, 0, 0)?;
            continue;
        }
        if libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80) {
            match syscall_info_op(pid)? {
                SYSCALL_INFO_EXIT => return Ok(get_regs(pid)?.rax as i64),
                SYSCALL_INFO_ENTRY | SYSCALL_INFO_SECCOMP => {
                    ptrace_checked(libc::PTRACE_SYSCALL, pid, 0, 0)?;
                }
                _ => return Err(injection_error("unexpected injected syscall stop")),
            }
            continue;
        }
        return Err(unexpected_stop(status));
    }
    Err(injection_error(
        "too many stops waiting for injected syscall exit",
    ))
}

fn wait_stopped(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status = 0;
    loop {
        // SAFETY: waitpid writes the child status to the supplied live pointer.
        let result = unsafe { libc::waitpid(pid, &mut status, WAIT_ALL) };
        if result == pid {
            break;
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
    if libc::WIFSTOPPED(status) {
        Ok(status)
    } else {
        Err(injection_error("tracee exited during injected syscall"))
    }
}

fn syscall_info_op(pid: libc::pid_t) -> io::Result<u8> {
    let mut info = SyscallInfo {
        op: 0,
        padding: [0; 3],
        arch: 0,
        instruction_pointer: 0,
        stack_pointer: 0,
        data: [0; 16],
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            mem::size_of::<SyscallInfo>() as *mut libc::c_void,
            &mut info as *mut SyscallInfo as *mut libc::c_void,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.op)
}

fn unexpected_stop(status: libc::c_int) -> io::Error {
    let signal = libc::WSTOPSIG(status);
    // TODO(native): propagate signal-delivery stops after restoring the guest context; currently
    // any such stop fails closed so the guest cannot execute untraced during injection.
    io::Error::new(
        io::ErrorKind::Interrupted,
        format!("tracee stopped by signal {signal} during syscall injection"),
    )
}

fn get_regs(pid: libc::pid_t) -> io::Result<libc::user_regs_struct> {
    let mut regs = unsafe { mem::zeroed::<libc::user_regs_struct>() };
    ptrace_checked(
        libc::PTRACE_GETREGS,
        pid,
        0,
        &mut regs as *mut libc::user_regs_struct as usize,
    )?;
    Ok(regs)
}

fn set_regs(pid: libc::pid_t, regs: &mut libc::user_regs_struct) -> io::Result<()> {
    ptrace_checked(
        libc::PTRACE_SETREGS,
        pid,
        0,
        regs as *mut libc::user_regs_struct as usize,
    )
}

fn ptrace_checked(
    request: libc::c_uint,
    pid: libc::pid_t,
    address: usize,
    data: usize,
) -> io::Result<()> {
    // SAFETY: ptrace's request-specific pointers are passed as raw addresses by Linux ABI.
    let result = unsafe {
        libc::ptrace(
            request,
            pid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn read_remote(pid: libc::pid_t, address: u64, bytes: &mut [u8]) -> bool {
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: both iovecs describe live buffers for the duration of the call.
    unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) == bytes.len() as isize }
}

fn injection_error(message: &str) -> io::Error {
    io::Error::other(message)
}
