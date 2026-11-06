//! Synchronous Linux x86_64 seccomp and ptrace events. All ptrace calls stay on the
//! thread that forked the tracee; the async scheduler polls this interface from that thread.

use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    io, mem, ptr,
};

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub pid: libc::pid_t,
    pub nr: i64,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Native,
    /// Execute the native syscall and report its syscall-exit stop to the scheduler.
    NativeSyscall([u64; 6]),
    Return(i64),
    Signal(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BirthKind {
    Fork,
    Vfork,
    Clone,
}

#[derive(Clone, Copy, Debug)]
pub enum Event {
    Seccomp(Request),
    Birth {
        parent: libc::pid_t,
        child: libc::pid_t,
        kind: BirthKind,
    },
    SyscallExit {
        pid: libc::pid_t,
        result: i64,
    },
    Exec {
        pid: libc::pid_t,
    },
    ExitStop {
        pid: libc::pid_t,
        wait_status: i32,
    },
    SignalStop {
        pid: libc::pid_t,
        signal: i32,
    },
    NewbornStop {
        pid: libc::pid_t,
    },
    Gone {
        pid: libc::pid_t,
        status: i32,
    },
}

pub struct Child {
    pid: libc::pid_t,
    tids: HashSet<libc::pid_t>,
    active: bool,
    exec_seen: bool,
    initial_exec_attempted: bool,
}

const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const PTRACE_O_TRACEFORK: usize = 0x0000_0002;
const PTRACE_O_TRACEVFORK: usize = 0x0000_0004;
const PTRACE_O_TRACECLONE: usize = 0x0000_0008;
const PTRACE_O_TRACEEXEC: usize = 0x0000_0010;
const PTRACE_O_EXITKILL: usize = 0x0010_0000;
const PTRACE_O_TRACESECCOMP: usize = 0x0000_0080;
const PTRACE_O_TRACEEXIT: usize = 0x0000_0040;
const PTRACE_O_TRACESYSGOOD: usize = 0x0000_0001;
const PTRACE_EVENT_FORK: u32 = 1;
const PTRACE_EVENT_VFORK: u32 = 2;
const PTRACE_EVENT_CLONE: u32 = 3;
const PTRACE_EVENT_EXEC: u32 = 4;
const PTRACE_EVENT_EXIT: u32 = 6;
const PTRACE_EVENT_SECCOMP: u32 = 7;
const WAIT_ALL: libc::c_int = 0x4000_0000; // __WALL

impl Child {
    pub fn spawn(program: &CStr, argv: &[CString], env: &[CString]) -> io::Result<Self> {
        let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
        argv_ptrs.push(ptr::null());
        let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|item| item.as_ptr()).collect();
        env_ptrs.push(ptr::null());
        let mut filter = syscall_filter();
        // SAFETY: the forked child uses only prebuilt buffers and async-signal-safe syscalls before
        // execve. Static launches fork before Tokio starts; dynamic launches fork after runtime
        // startup, so keep this branch free of allocation, locks, and non-signal-safe Rust code.
        // TODO(native): replace the post-runtime dynamic fork with a pre-runtime launch handshake.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    ptr::null_mut::<libc::c_void>(),
                    ptr::null_mut::<libc::c_void>(),
                ) == -1
                {
                    libc::_exit(126);
                }
                if libc::kill(libc::getpid(), libc::SIGSTOP) == -1 {
                    libc::_exit(126);
                }
                if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                    libc::_exit(126);
                }
                let mut filter_program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_mut_ptr(),
                };
                if libc::prctl(
                    PR_SET_SECCOMP,
                    SECCOMP_MODE_FILTER,
                    &mut filter_program as *mut libc::sock_fprog as libc::c_ulong,
                ) == -1
                {
                    libc::_exit(126);
                }
                libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
                libc::_exit(127);
            }
        }

        let mut status = 0;
        if let Err(err) = waitpid(pid, &mut status) {
            kill_and_reap(pid);
            return Err(err);
        }
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
            kill_and_reap(pid);
            return Err(io::Error::other(format!(
                "child {pid} missed its initial SIGSTOP"
            )));
        }
        let mut child = Self {
            pid,
            tids: HashSet::from([pid]),
            active: true,
            exec_seen: false,
            initial_exec_attempted: false,
        };
        child.set_options(pid)?;
        Ok(child)
    }

    pub fn root_pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn poll_event(&mut self) -> io::Result<Option<Event>> {
        loop {
            let mut status = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, WAIT_ALL | libc::WNOHANG) };
            if tid == 0 {
                return Ok(None);
            }
            if tid < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.active = false;
                    return Ok(None);
                }
                return Err(error);
            }
            if libc::WIFEXITED(status) {
                self.tids.remove(&tid);
                if self.tids.is_empty() {
                    self.active = false;
                }
                return Ok(Some(Event::Gone {
                    pid: tid,
                    status: libc::WEXITSTATUS(status),
                }));
            }
            if libc::WIFSIGNALED(status) {
                self.tids.remove(&tid);
                if self.tids.is_empty() {
                    self.active = false;
                }
                return Ok(Some(Event::Gone {
                    pid: tid,
                    status: 128 + libc::WTERMSIG(status),
                }));
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }

            let signal = libc::WSTOPSIG(status);
            let event = (status as u32) >> 16;
            if signal == libc::SIGTRAP && event == PTRACE_EVENT_EXEC {
                self.exec_seen = true;
                return Ok(Some(Event::Exec { pid: tid }));
            }
            if signal == libc::SIGTRAP && event == PTRACE_EVENT_SECCOMP {
                let regs = get_regs(tid)?;
                let nr = regs.orig_rax as i64;
                let is_exit = nr == libc::SYS_exit || nr == libc::SYS_exit_group;
                if !self.exec_seen && nr == libc::SYS_execve {
                    self.initial_exec_attempted = true;
                    self.resume(tid, Action::Native)?;
                    continue;
                }
                if !self.exec_seen && self.initial_exec_attempted && is_exit {
                    self.resume(tid, Action::Native)?;
                    continue;
                }
                return Ok(Some(Event::Seccomp(Request {
                    pid: tid,
                    nr,
                    args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
                })));
            }
            if signal == libc::SIGTRAP && event == PTRACE_EVENT_FORK {
                let child = event_message(tid)? as libc::pid_t;
                self.tids.insert(child);
                return Ok(Some(Event::Birth {
                    parent: tid,
                    child,
                    kind: BirthKind::Fork,
                }));
            }
            if signal == libc::SIGTRAP && event == PTRACE_EVENT_VFORK {
                let child = event_message(tid)? as libc::pid_t;
                self.tids.insert(child);
                return Ok(Some(Event::Birth {
                    parent: tid,
                    child,
                    kind: BirthKind::Vfork,
                }));
            }
            if signal == libc::SIGTRAP && event == PTRACE_EVENT_CLONE {
                let child = event_message(tid)? as libc::pid_t;
                self.tids.insert(child);
                return Ok(Some(Event::Birth {
                    parent: tid,
                    child,
                    kind: BirthKind::Clone,
                }));
            }
            if signal == libc::SIGTRAP && event == PTRACE_EVENT_EXIT {
                return Ok(Some(Event::ExitStop {
                    pid: tid,
                    wait_status: event_message(tid)? as i32,
                }));
            }
            if event == 128 || (tid != self.pid && signal == libc::SIGSTOP) {
                return Ok(Some(Event::NewbornStop { pid: tid }));
            }
            if signal == (libc::SIGTRAP | 0x80) {
                let regs = get_regs(tid)?;
                return Ok(Some(Event::SyscallExit {
                    pid: tid,
                    result: regs.rax as i64,
                }));
            }
            return Ok(Some(Event::SignalStop { pid: tid, signal }));
        }
    }

    pub fn resume(&mut self, pid: libc::pid_t, action: Action) -> io::Result<()> {
        match action {
            Action::Native => ptrace_checked(libc::PTRACE_CONT, pid, 0, 0),
            Action::Signal(signal) => ptrace_checked(libc::PTRACE_CONT, pid, 0, signal as usize),
            Action::Return(value) => {
                let mut regs = get_regs(pid)?;
                set_result_and_continue(pid, &mut regs, value)
            }
            Action::NativeSyscall(args) => {
                let mut regs = get_regs(pid)?;
                let mut args = args;
                if regs.orig_rax == libc::SYS_fork as u64 {
                    // TODO(native): run fork children as supervisor children so the tracer can reap them
                    // after WLK's virtual wait4 consumes the corresponding process status.
                    regs.orig_rax = libc::SYS_clone as u64;
                    args = [(libc::SIGCHLD | libc::CLONE_PARENT) as u64, 0, 0, 0, 0, 0];
                } else if regs.orig_rax == libc::SYS_clone as u64
                    && args[0] & libc::CLONE_VM as u64 == 0
                {
                    // TODO(native): preserve guest parentage in WLK while making the tracer the host parent.
                    args[0] |= libc::CLONE_PARENT as u64;
                }
                [
                    &mut regs.rdi,
                    &mut regs.rsi,
                    &mut regs.rdx,
                    &mut regs.r10,
                    &mut regs.r8,
                    &mut regs.r9,
                ]
                .into_iter()
                .zip(args)
                .for_each(|(register, value)| *register = value);
                set_regs(pid, &mut regs)?;
                ptrace_checked(libc::PTRACE_SYSCALL, pid, 0, 0)
            }
        }
    }

    pub fn set_syscall_result(&mut self, pid: libc::pid_t, value: i64) -> io::Result<()> {
        let mut regs = get_regs(pid)?;
        regs.rax = value as u64;
        set_regs(pid, &mut regs)?;
        ptrace_checked(libc::PTRACE_CONT, pid, 0, 0)
    }

    pub fn exec_image(&mut self, pid: libc::pid_t, path: &CStr) -> io::Result<()> {
        self.exec_image_with_argv(pid, path, None)
    }

    pub fn exec_image_with_argv(
        &mut self,
        pid: libc::pid_t,
        path: &CStr,
        replacement_argv: Option<&[CString]>,
    ) -> io::Result<()> {
        // TODO(native): monitor exec failure after WLK image commit and terminate the stale native image.
        let mut regs = get_regs(pid)?;
        let (mut argv, envp) = if regs.orig_rax == libc::SYS_execveat as u64 {
            (regs.rdx, regs.r10)
        } else {
            (regs.rsi, regs.rdx)
        };
        // TODO(native): reserve a dedicated tracee scratch mapping instead of borrowing stack space.
        let mut bytes = path.to_bytes_with_nul().to_vec();
        let path_offset = 0usize;
        let argv_offset = if let Some(args) = replacement_argv {
            let mut string_offsets = Vec::with_capacity(args.len());
            for argument in args {
                string_offsets.push(bytes.len());
                bytes.extend_from_slice(argument.as_bytes_with_nul());
            }
            let aligned = bytes
                .len()
                .checked_add(7)
                .ok_or_else(|| io::Error::other("native exec argument layout overflows"))?
                & !7;
            bytes.resize(aligned, 0);
            let argv_offset = aligned;
            for offset in string_offsets {
                // The base address is computed below; reserve one pointer slot per argument.
                bytes.extend_from_slice(&(offset as u64).to_le_bytes());
            }
            bytes.extend_from_slice(&0u64.to_le_bytes());
            Some(argv_offset)
        } else {
            None
        };
        let remote = regs
            .rsp
            .checked_sub(bytes.len() as u64 + 256)
            .map(|address| address & !7)
            .ok_or_else(|| io::Error::other("tracee stack address underflow"))?;
        if let (Some(argv_offset), Some(args)) = (argv_offset, replacement_argv) {
            argv = remote + argv_offset as u64;
            for index in 0..args.len() {
                let stored_offset = u64::from_le_bytes(
                    bytes[argv_offset + index * 8..argv_offset + (index + 1) * 8]
                        .try_into()
                        .expect("reserved exec argv pointer"),
                );
                bytes[argv_offset + index * 8..argv_offset + (index + 1) * 8]
                    .copy_from_slice(&(remote + stored_offset).to_le_bytes());
            }
        }
        let local = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: remote as usize as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        // SAFETY: the local strings and pointer table stay alive through the copy.
        let written = unsafe { libc::process_vm_writev(pid, &local, 1, &remote_iov, 1, 0) };
        if written != bytes.len() as isize {
            return Err(io::Error::last_os_error());
        }
        regs.orig_rax = libc::SYS_execve as u64;
        regs.rdi = remote + path_offset as u64;
        regs.rsi = argv;
        regs.rdx = envp;
        set_regs(pid, &mut regs)
    }

    pub fn continue_exit(&mut self, pid: libc::pid_t) -> io::Result<()> {
        ptrace_checked(libc::PTRACE_CONT, pid, 0, 0)
    }

    pub fn continue_syscall(&mut self, pid: libc::pid_t) -> io::Result<()> {
        ptrace_checked(libc::PTRACE_SYSCALL, pid, 0, 0)
    }

    pub fn is_done(&self) -> bool {
        !self.active
    }

    fn set_options(&mut self, tid: libc::pid_t) -> io::Result<()> {
        let options = PTRACE_O_TRACESECCOMP
            | PTRACE_O_TRACEEXEC
            | PTRACE_O_EXITKILL
            | PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXIT;
        ptrace_checked(libc::PTRACE_SETOPTIONS, tid, 0, options)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.active {
            for tid in self.tids.iter().copied() {
                unsafe { libc::kill(tid, libc::SIGKILL) };
            }
            while !self.tids.is_empty() {
                let mut status = 0;
                let tid = unsafe { libc::waitpid(-1, &mut status, WAIT_ALL) };
                if tid < 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    break;
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.tids.remove(&tid);
                } else if libc::WIFSTOPPED(status) {
                    let _ = ptrace_checked(libc::PTRACE_CONT, tid, 0, libc::SIGKILL as usize);
                }
            }
        }
    }
}

fn syscall_filter() -> [libc::sock_filter; 7] {
    [
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, AUDIT_ARCH_X86_64),
        instruction(0x06, 0, 0, SECCOMP_RET_KILL_PROCESS),
        instruction(0x20, 0, 0, 0),
        instruction(0x45, 0, 1, X32_SYSCALL_BIT),
        instruction(0x06, 0, 0, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        instruction(0x06, 0, 0, SECCOMP_RET_TRACE),
    ]
}

const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn waitpid(pid: libc::pid_t, status: &mut libc::c_int) -> io::Result<()> {
    loop {
        let result = unsafe { libc::waitpid(pid, status, 0) };
        if result == pid {
            return Ok(());
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

fn kill_and_reap(pid: libc::pid_t) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    let _ = waitpid(pid, &mut status);
}

fn event_message(pid: libc::pid_t) -> io::Result<usize> {
    let mut message = 0usize;
    ptrace_checked(
        libc::PTRACE_GETEVENTMSG,
        pid,
        0,
        &mut message as *mut usize as usize,
    )?;
    Ok(message)
}

fn get_regs(pid: libc::pid_t) -> io::Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
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

fn set_result_and_continue(
    pid: libc::pid_t,
    regs: &mut libc::user_regs_struct,
    value: i64,
) -> io::Result<()> {
    regs.orig_rax = u64::MAX;
    regs.rax = value as u64;
    set_regs(pid, regs)?;
    ptrace_checked(libc::PTRACE_CONT, pid, 0, 0)
}

fn ptrace_checked(
    request: libc::c_uint,
    pid: libc::pid_t,
    addr: usize,
    data: usize,
) -> io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            request,
            pid,
            addr as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
