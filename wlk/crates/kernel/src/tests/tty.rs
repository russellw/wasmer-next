//! Terminals: the host's console as a process's controlling terminal, its line discipline as
//! the host types, and job control against its foreground process group.

use std::{
    collections::VecDeque,
    task::{Context, Poll, Waker},
    time::Instant,
};

use futures::FutureExt as _;
use wasixv2_abi::{
    FcntlCmd, FileMode, Idtype, IoctlRequest, OpenFlags, Pid, RusagePtr, SiginfoPtr, Signal, Statx,
    StatxMask, Termios, TermiosCcIndex, TermiosLflag, TermiosOflag, WaitOptions, Winsize,
};
use wasixv2_host::WindowSize;
use wasixv2_syscalls::{read_value, write_value};
use wasixv2_vfs::MountFlags;

use super::{
    ipc::{errno, get, put},
    mapping::open,
    proc::ForkableMemory,
    signal::ignore,
    *,
};
use crate::ConsoleInputEof;

/// Test input accepts typed bytes, then ends with EOF or a source error.
#[derive(Default)]
struct Keyboard(Mutex<Keys>);

#[derive(Default)]
struct Keys {
    typed: VecDeque<u8>,
    gone: bool,
    failed: bool,
    waker: Option<Waker>,
}

impl Keyboard {
    fn type_in(&self, bytes: &[u8]) {
        let mut keys = self.0.lock_or_recover();
        keys.typed.extend(bytes);
        if let Some(waker) = keys.waker.take() {
            waker.wake();
        }
    }

    fn unplug(&self) {
        let mut keys = self.0.lock_or_recover();
        keys.gone = true;
        if let Some(waker) = keys.waker.take() {
            waker.wake();
        }
    }

    fn fail(&self) {
        let mut keys = self.0.lock_or_recover();
        keys.failed = true;
        if let Some(waker) = keys.waker.take() {
            waker.wake();
        }
    }
}

impl ByteSource for Keyboard {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut keys = self.0.lock_or_recover();
        if !keys.typed.is_empty() {
            let n = buf.len().min(keys.typed.len());
            for (dst, src) in buf.iter_mut().zip(keys.typed.drain(..n)) {
                *dst = src;
            }
            return Poll::Ready(Ok(n));
        }
        if keys.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if keys.gone {
            return Poll::Ready(Ok(0));
        }
        keys.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// [`TestHost`] with threads, where the console's input pump runs.
struct ThreadHost;

impl Host for ThreadHost {
    fn realtime(&self) -> Duration {
        TestHost.realtime()
    }

    fn monotonic(&self) -> Duration {
        TestHost.monotonic()
    }

    fn sleep(&self, d: Duration) -> LocalFuture<'_, ()> {
        TestHost.sleep(d)
    }

    fn sleep_until(&self, d: Duration) -> LocalFuture<'_, ()> {
        TestHost.sleep_until(d)
    }

    fn random(&self, buf: &mut [u8]) {
        TestHost.random(buf)
    }

    fn executor(&self) -> &dyn Executor {
        self
    }
}

impl Executor for ThreadHost {
    fn spawn_local(&self, _: LocalFuture<'static, ()>) {
        unimplemented!("the console's pump runs on a thread")
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
        Box::pin(async move { work() })
    }

    fn spawn_thread(&self, start: wasixv2_host::ThreadStart) -> io::Result<()> {
        std::thread::spawn(move || block_on(start()));
        Ok(())
    }
}

/// A machine whose console the test types on and reads, and its first process, which has
/// the console as descriptors 0, 1 and 2 and its controlling terminal.
struct Console {
    kernel: Kernel,
    leader: TaskId,
    keyboard: Arc<Keyboard>,
    screen: Arc<Capture>,
}

const ROWS: u16 = 24;
const COLS: u16 = 80;

fn console() -> Console {
    console_with_input_eof(None)
}

fn finite_console() -> Console {
    console_with_input_eof(Some(ConsoleInputEof::Finite))
}

fn console_with_input_eof(input_eof: Option<ConsoleInputEof>) -> Console {
    console_with_outputs(input_eof, [None, None, None], Arc::new(ThreadHost))
}

fn console_with_outputs(
    input_eof: Option<ConsoleInputEof>,
    outputs: [Option<Arc<dyn ByteSink>>; 3],
    host: Arc<dyn Host>,
) -> Console {
    console_with_options(input_eof, outputs, host, true)
}

fn console_with_options(
    input_eof: Option<ConsoleInputEof>,
    outputs: [Option<Arc<dyn ByteSink>>; 3],
    host: Arc<dyn Host>,
    output_processing: bool,
) -> Console {
    let keyboard = Arc::new(Keyboard::default());
    let screen = Arc::new(Capture::default());
    let clock = Arc::new(HostClock(host.clone()));
    let root = MemFs::new(clock.clone(), 0o755, 1, 1);
    let shm = MemFs::new(clock.clone(), 0o1777, 0, 0);
    let console = wasixv2_host::Console {
        input: keyboard.clone(),
        output: screen.clone(),
        size: WindowSize {
            rows: ROWS,
            cols: COLS,
            xpixel: 0,
            ypixel: 0,
        },
    };
    let builder = Kernel::new(host, Arc::new(root))
        .with_shm(Arc::new(shm))
        .with_init();
    let kernel = match (input_eof, output_processing) {
        (None, true) => builder.with_console(console),
        (Some(input_eof), true) => builder.with_console_eof(console, input_eof),
        (input_eof, false) => {
            builder.with_console_options(console, input_eof.unwrap_or_default(), false)
        }
    };
    let vfs = kernel.vfs().clone();
    block_on(vfs.mount(b"/proc", kernel.procfs(), MountFlags::default(), true)).unwrap();
    let dev = MemFs::new(clock, 0o755, 0, 0);
    block_on(vfs.mount(b"/dev", Arc::new(dev), MountFlags::default(), true)).unwrap();
    block_on(kernel.create_device_nodes(b"/dev")).unwrap();
    let stdin = Arc::new(Input(Mutex::new(Vec::new())));
    let (kernel, leader, _) = spawn_on(kernel, stdin, &[], &[]);
    if outputs.iter().all(Option::is_none) {
        block_on(kernel.attach_console(leader, [true; 3])).unwrap();
    } else {
        block_on(kernel.attach_console_outputs(leader, [true; 3], outputs)).unwrap();
    }
    Console {
        kernel,
        leader,
        keyboard,
        screen,
    }
}

fn memory() -> ForkableMemory {
    ForkableMemory(FlatMemory(RefCell::new(vec![0; 65536])))
}

impl Console {
    fn shown(&self) -> Vec<u8> {
        self.screen.0.lock_or_recover().clone()
    }

    fn fork(&self, caller: &Caller<'_>) -> TaskId {
        let flags = Signal::SIGCHLD.0 as u32;
        let clone = self
            .kernel
            .clone(caller, flags, 0, GuestPtrMut::NULL, 0, GuestPtrMut::NULL);
        let child = TaskId(block_on(clone).expect("fork") as u32);
        while self.kernel.take_pending(caller.task()).is_some() {}
        child
    }

    /// A child of the leader in a process group of its own: a background job.
    fn background_job(&self, caller: &Caller<'_>) -> TaskId {
        let child = self.fork(caller);
        let pid = child.0 as Pid;
        assert_eq!(block_on(self.kernel.setpgid(caller, pid, pid)), Ok(0));
        child
    }

    fn ioctl(
        &self,
        caller: &Caller<'_>,
        fd: i32,
        request: IoctlRequest,
        arg: u32,
    ) -> SysResult<i32> {
        block_on(self.kernel.ioctl(caller, Fd(fd), request, arg))
    }

    /// An `int` result of `request` on descriptor 0, through memory at 0x10.
    fn ioctl_int(&self, caller: &Caller<'_>, request: IoctlRequest) -> SysResult<i32> {
        self.ioctl(caller, 0, request, 0x10)?;
        Ok(block_on(read_value(caller.memory(), GuestPtr::new(0x10))).unwrap())
    }

    fn tcgetattr(&self, caller: &Caller<'_>) -> Termios {
        self.ioctl(caller, 0, IoctlRequest::TCGETS, 0x40).unwrap();
        block_on(read_value(caller.memory(), GuestPtr::new(0x40))).unwrap()
    }

    fn tcsetattr(&self, caller: &Caller<'_>, termios: &Termios) -> SysResult<i32> {
        block_on(write_value(
            caller.memory(),
            GuestPtrMut::new(0x40),
            termios,
        ))
        .unwrap();
        self.ioctl(caller, 0, IoctlRequest::TCSETS, 0x40)
    }

    fn tcsetpgrp(&self, caller: &Caller<'_>, pgrp: Pid) -> SysResult<i32> {
        block_on(write_value(caller.memory(), GuestPtrMut::new(0x10), &pgrp)).unwrap();
        self.ioctl(caller, 0, IoctlRequest::TIOCSPGRP, 0x10)
    }

    fn read(&self, caller: &Caller<'_>, len: u32) -> SysResult<Vec<u8>> {
        let n = block_on(
            self.kernel
                .read(caller, Fd(0), UserSliceMut::new(0x200, len)),
        )?;
        Ok(block_on_read(caller, n))
    }

    fn write(&self, caller: &Caller<'_>, fd: i32, data: &[u8]) -> SysResult<u32> {
        block_on(caller.memory().write(0x200, data)).unwrap();
        let len = data.len() as u32;
        block_on(
            self.kernel
                .write(caller, Fd(fd), UserSlice::new(0x200, len)),
        )
    }

    fn pending(&self, task: TaskId, sig: Signal) -> bool {
        self.kernel.task_signals(task).group().is_pending(sig.0)
    }
}

fn block_on_read(caller: &Caller<'_>, n: u32) -> Vec<u8> {
    let mut buf = vec![0; n as usize];
    block_on(caller.memory().read(0x200, &mut buf)).unwrap();
    buf
}

/// Waits for what the console's pump does on its thread.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(10), "never: {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn blocked(sig: Signal) -> u64 {
    1 << (sig.0 - 1)
}

/// The first process leads a session whose controlling terminal is the console, its group in
/// the foreground, and descriptors 0 to 2 are one read-write open file of it.
#[test]
fn the_console_is_the_first_process_controlling_terminal() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let pid = c.leader.0 as i32;

    assert_eq!(c.ioctl_int(&caller, IoctlRequest::TIOCGPGRP), Ok(pid));
    assert_eq!(c.ioctl_int(&caller, IoctlRequest::TIOCGSID), Ok(pid));
    assert_eq!(c.tcgetattr(&caller), crate::tty::ldisc::std_termios());
    let winsize: Winsize = {
        c.ioctl(&caller, 1, IoctlRequest::TIOCGWINSZ, 0x20).unwrap();
        block_on(read_value(caller.memory(), GuestPtr::new(0x20))).unwrap()
    };
    assert_eq!((winsize.ws_row, winsize.ws_col), (ROWS, COLS));
    // `TIOCGDEV`: hvc0, 229:0.
    assert_eq!(c.ioctl_int(&caller, IoctlRequest::TIOCGDEV), Ok(229 << 8));
    assert_eq!(
        block_on(c.kernel.statx(
            &caller,
            Fd(0),
            GuestPtr::NULL,
            AtFlags::AT_EMPTY_PATH,
            StatxMask::STATX_TYPE,
            GuestPtrMut::new(0x100),
        )),
        Ok(0)
    );
    let stat: Statx = block_on(read_value(&memory, GuestPtr::new(0x100))).unwrap();
    assert_eq!(
        FileMode(stat.stx_mode as u32) & FileMode::S_IFMT,
        FileMode::S_IFCHR
    );
    let flags = block_on(c.kernel.fcntl64(&caller, Fd(0), FcntlCmd::F_GETFL, 0)).unwrap();
    assert_eq!(
        OpenFlags(flags as u32) & OpenFlags::O_ACCMODE,
        OpenFlags::O_RDWR
    );
    let files = c.kernel.files(c.leader);
    let files = files.lock_or_recover();
    let file = files.get(Fd(0)).unwrap();
    assert!(Arc::ptr_eq(&file, &files.get(Fd(2)).unwrap()));
    assert_eq!(file.flags() & OpenFlags::O_ACCMODE, OpenFlags::O_RDWR);
}

/// Output processing turns each newline into CR LF, as a terminal needs it.
#[test]
fn writes_reach_the_host_post_processed() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    assert_eq!(c.write(&caller, 1, b"one\ntwo"), Ok(7));
    assert_eq!(c.shown(), b"one\r\ntwo");
}

#[test]
fn initial_console_output_processing_preserves_literal_lf_and_guest_termios_control() {
    let c = console_with_options(None, [None, None, None], Arc::new(ThreadHost), false);
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let mut expected = crate::tty::ldisc::std_termios();
    expected.c_oflag.0 &= !TermiosOflag::OPOST.0;
    assert_eq!(c.tcgetattr(&caller), expected);
    assert!(expected.c_oflag.contains(TermiosOflag::ONLCR));
    assert_eq!(c.write(&caller, 1, b"body\n"), Ok(5));
    assert_eq!(c.shown(), b"body\n");
    c.keyboard.type_in(b"echo\r");
    assert_eq!(c.read(&caller, 64), Ok(b"echo\n".to_vec()));
    eventually("literal LF echo", || c.shown().ends_with(b"echo\n"));
    assert_eq!(c.shown(), b"body\necho\n");
    expected.c_oflag.0 |= TermiosOflag::OPOST.0;
    assert_eq!(c.tcsetattr(&caller, &expected), Ok(0));
    assert_eq!(c.write(&caller, 1, b"processed\n"), Ok(10));
    assert!(c.shown().ends_with(b"processed\r\n"));
    c.keyboard.unplug();
}

/// What the host types is edited and echoed by the console, and a read gets the line.
#[test]
fn typed_lines_are_edited_echoed_and_read() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.keyboard.type_in(b"lsx\x7f -l\r");
    assert_eq!(c.read(&caller, 64), Ok(b"ls -l\n".to_vec()));
    eventually("the echo", || c.shown().ends_with(b"\r\n"));
    assert_eq!(c.shown(), b"lsx\x08 \x08 -l\r\n");
}

/// `^C` is SIGINT for the foreground process group only: a background job does not get it,
/// until it is moved to the foreground.
#[test]
fn ctrl_c_interrupts_the_foreground_group_only() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGINT));
    let job = c.background_job(&caller);
    c.kernel
        .task_signals(job)
        .replace_blocked(blocked(Signal::SIGINT));

    c.keyboard.type_in(b"\x03");
    eventually("SIGINT", || c.pending(c.leader, Signal::SIGINT));
    assert!(!c.pending(job, Signal::SIGINT));
    eventually("the echo", || c.shown() == b"^C");

    assert_eq!(c.tcsetpgrp(&caller, job.0 as Pid), Ok(0));
    c.keyboard.type_in(b"\x03");
    eventually("the job's SIGINT", || c.pending(job, Signal::SIGINT));
}

/// A background job that reads its controlling terminal stops with SIGTTIN and reads again
/// once continued; with SIGTTIN ignored, the read fails with `EIO`.
#[test]
fn a_background_read_stops_with_sigttin() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let job = c.background_job(&caller);
    let job_memory = self::memory();
    let job_caller = Caller::new(job, &job_memory);

    assert_eq!(c.read(&job_caller, 16), Err(SysErr::Restart));
    assert_eq!(c.kernel.take_pending(job), Some(GuestAction::Stopped));

    ignore(&c.kernel, &job_caller, Signal::SIGTTIN);
    assert_eq!(errno(c.read(&job_caller, 16)), Errno::EIO);
}

/// Changing the terminal from the background stops with SIGTTOU, unless SIGTTOU is ignored or
/// blocked; writing does only under `TOSTOP`.
#[test]
fn background_changes_and_tostop_writes_stop_with_sigttou() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let job = c.background_job(&caller);
    let job_memory = self::memory();
    let job_caller = Caller::new(job, &job_memory);
    let termios = c.tcgetattr(&job_caller);

    assert_eq!(c.tcsetattr(&job_caller, &termios), Err(SysErr::Restart));
    assert_eq!(c.kernel.take_pending(job), Some(GuestAction::Stopped));
    c.kernel.kill(job, Signal::SIGCONT).unwrap();
    assert_eq!(c.kernel.take_pending(job), None);

    assert_eq!(c.write(&job_caller, 1, b"bg"), Ok(2));
    let mut tostop = termios;
    tostop.c_lflag.0 |= TermiosLflag::TOSTOP.0;
    assert_eq!(c.tcsetattr(&caller, &tostop), Ok(0));
    assert_eq!(c.write(&job_caller, 1, b"bg"), Err(SysErr::Restart));
    assert_eq!(c.kernel.take_pending(job), Some(GuestAction::Stopped));
    c.kernel.kill(job, Signal::SIGCONT).unwrap();
    assert_eq!(c.kernel.take_pending(job), None);

    c.kernel
        .task_signals(job)
        .replace_blocked(blocked(Signal::SIGTTOU));
    assert_eq!(c.write(&job_caller, 1, b"bg"), Ok(2));
    assert_eq!(c.tcsetattr(&job_caller, &termios), Ok(0));
}

/// A process group with no parent in another group of its session (the first process's own)
/// cannot be stopped from the terminal: its background access fails with `EIO` instead.
#[test]
fn an_orphaned_background_group_gets_eio() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let job = c.background_job(&caller);
    assert_eq!(c.tcsetpgrp(&caller, job.0 as Pid), Ok(0));

    // The leader's own group, now in the background, is orphaned: init is its parent.
    assert_eq!(errno(c.read(&caller, 16)), Errno::EIO);
    assert_eq!(c.kernel.take_pending(c.leader), None);
}

/// `tcsetpgrp` takes a group of the caller's session, on the caller's controlling terminal.
#[test]
fn tcsetpgrp_checks_the_group_and_the_terminal() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    assert_eq!(errno(c.tcsetpgrp(&caller, -1)), Errno::EINVAL);
    assert_eq!(errno(c.tcsetpgrp(&caller, 9999)), Errno::ESRCH);
    // init's group is in another session.
    assert_eq!(errno(c.tcsetpgrp(&caller, 1)), Errno::EPERM);

    let child = c.fork(&caller);
    let child_memory = self::memory();
    let child_caller = Caller::new(child, &child_memory);
    assert_eq!(block_on(c.kernel.setsid(&child_caller)), Ok(child.0 as Pid));
    assert_eq!(
        errno(c.tcsetpgrp(&child_caller, child.0 as Pid)),
        Errno::ENOTTY
    );
    assert_eq!(
        errno(c.ioctl_int(&child_caller, IoctlRequest::TIOCGPGRP)),
        Errno::ENOTTY
    );
}

/// A new window size reaches the foreground group as SIGWINCH, from the host and from
/// `TIOCSWINSZ`; the same size again changes nothing.
#[test]
fn resizing_signals_sigwinch() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGWINCH));
    let size = WindowSize {
        rows: ROWS,
        cols: COLS,
        xpixel: 0,
        ypixel: 0,
    };
    c.kernel.console_resize(size);
    assert!(!c.pending(c.leader, Signal::SIGWINCH));
    c.kernel.console_resize(WindowSize { rows: 50, ..size });
    assert!(c.pending(c.leader, Signal::SIGWINCH));
    assert_eq!(c.ioctl(&caller, 0, IoctlRequest::TIOCGWINSZ, 0x20), Ok(0));
    let from_host: Winsize = block_on(read_value(caller.memory(), GuestPtr::new(0x20))).unwrap();
    assert_eq!((from_host.ws_row, from_host.ws_col), (50, COLS));
    // Unblocked, its default action drops it.
    let signals = c.kernel.task_signals(c.leader);
    signals.replace_blocked(0);
    assert_eq!(c.kernel.take_pending(c.leader), None);
    assert!(!c.pending(c.leader, Signal::SIGWINCH));
    signals.replace_blocked(blocked(Signal::SIGWINCH));

    let winsize = Winsize {
        ws_row: 10,
        ws_col: 20,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    block_on(write_value(
        caller.memory(),
        GuestPtrMut::new(0x20),
        &winsize,
    ))
    .unwrap();
    assert_eq!(c.ioctl(&caller, 0, IoctlRequest::TIOCSWINSZ, 0x20), Ok(0));
    assert!(c.pending(c.leader, Signal::SIGWINCH));
    assert_eq!(c.ioctl(&caller, 2, IoctlRequest::TIOCGWINSZ, 0x30), Ok(0));
    let from_guest: Winsize = block_on(read_value(caller.memory(), GuestPtr::new(0x30))).unwrap();
    assert_eq!(from_guest, winsize);
    signals.replace_blocked(0);
    assert_eq!(c.kernel.take_pending(c.leader), None);
    signals.replace_blocked(blocked(Signal::SIGWINCH));
    c.kernel.console_resize(WindowSize::from_u32(10, 20, 0, 0));
    assert!(
        !c.pending(c.leader, Signal::SIGWINCH),
        "host sees the guest's current size"
    );
    assert_eq!(c.ioctl(&caller, 0, IoctlRequest::TIOCSWINSZ, 0x20), Ok(0));
    assert!(
        !c.pending(c.leader, Signal::SIGWINCH),
        "same guest size changes nothing"
    );
}

/// `/dev/tty` is the caller's controlling terminal; a new session has none.
#[test]
fn dev_tty_is_the_controlling_terminal() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let fd = open(&c.kernel, &caller, b"/dev/tty", OpenFlags::O_RDWR);
    assert_eq!(c.ioctl(&caller, fd.0, IoctlRequest::TCGETS, 0x40), Ok(0));

    let child = c.fork(&caller);
    let child_memory = self::memory();
    let child_caller = Caller::new(child, &child_memory);
    let fd = open(&c.kernel, &child_caller, b"/dev/tty", OpenFlags::O_RDONLY);
    assert_eq!(
        c.ioctl(&child_caller, fd.0, IoctlRequest::TCGETS, 0x40),
        Ok(0)
    );
    assert_eq!(block_on(c.kernel.setsid(&child_caller)), Ok(child.0 as Pid));
    put(&child_memory.0, 0x800, b"/dev/tty\0");
    let reopen = c.kernel.openat(
        &child_caller,
        Fd(-100),
        GuestPtr::new(0x800),
        OpenFlags::O_RDWR,
        0,
    );
    assert_eq!(errno(block_on(reopen)), Errno::ENXIO);
}

/// A session leader acquires a terminal it opens that no session controls, unless it opens it
/// with `O_NOCTTY`; `TIOCSCTTY` takes one, `TIOCNOTTY` gives it back.
#[test]
fn a_session_leader_acquires_a_free_terminal() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    // The leader gives the console up; its group gets SIGHUP and SIGCONT.
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGHUP));
    assert_eq!(c.ioctl(&caller, 0, IoctlRequest::TIOCNOTTY, 0), Ok(0));
    assert!(c.pending(c.leader, Signal::SIGHUP));
    assert_eq!(
        errno(c.ioctl_int(&caller, IoctlRequest::TIOCGPGRP)),
        Errno::ENOTTY
    );

    let child = c.fork(&caller);
    let child_memory = self::memory();
    let child_caller = Caller::new(child, &child_memory);
    assert_eq!(block_on(c.kernel.setsid(&child_caller)), Ok(child.0 as Pid));
    let noctty = OpenFlags::O_RDWR | OpenFlags::O_NOCTTY;
    let fd = open(&c.kernel, &child_caller, b"/dev/hvc0", noctty);
    assert_eq!(
        errno(c.ioctl(&child_caller, fd.0, IoctlRequest::TIOCGPGRP, 0x10)),
        Errno::ENOTTY
    );
    assert_eq!(
        c.ioctl(&child_caller, fd.0, IoctlRequest::TIOCSCTTY, 0),
        Ok(0)
    );
    assert_eq!(
        c.ioctl(&child_caller, fd.0, IoctlRequest::TIOCGPGRP, 0x10),
        Ok(0)
    );
    let pgrp: i32 = block_on(read_value(&child_memory, GuestPtr::new(0x10))).unwrap();
    assert_eq!(pgrp, child.0 as i32);

    // The first leader cannot take it back from the child's session without stealing.
    let fd = open(&c.kernel, &caller, b"/dev/hvc0", OpenFlags::O_RDWR);
    assert_eq!(
        errno(c.ioctl(&caller, fd.0, IoctlRequest::TIOCSCTTY, 0)),
        Errno::EPERM
    );
}

/// The session leader's exit hangs the console up: its foreground group gets SIGHUP, and the
/// files open on it end (reads at end of file, writes with `EIO`). Opening it again works.
#[test]
fn the_session_leaders_exit_hangs_up_the_console() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let child = c.fork(&caller);
    let child_memory = self::memory();
    let child_caller = Caller::new(child, &child_memory);
    c.kernel
        .task_signals(child)
        .replace_blocked(blocked(Signal::SIGHUP));

    assert_eq!(block_on(c.kernel.exit_group(&caller, 0)), Ok(()));

    assert!(c.pending(child, Signal::SIGHUP));
    assert_eq!(c.read(&child_caller, 16), Ok(Vec::new()));
    assert_eq!(errno(c.write(&child_caller, 1, b"x")), Errno::EIO);
    assert_eq!(
        errno(c.ioctl(&child_caller, 0, IoctlRequest::TCGETS, 0x40)),
        Errno::EIO
    );
    let fd = open(&c.kernel, &child_caller, b"/dev/hvc0", OpenFlags::O_RDWR);
    assert_eq!(c.write(&child_caller, fd.0, b"x"), Ok(1));
}

/// The host's input ending is the line dropping: the session's leader gets SIGHUP.
#[test]
fn the_end_of_the_hosts_input_is_a_hangup() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGHUP));
    // A read waits for input, and ends with the hangup.
    let mut read = Box::pin(c.kernel.read(&caller, Fd(0), UserSliceMut::new(0x200, 16)));
    assert_eq!(read.as_mut().now_or_never(), None);

    c.keyboard.unplug();

    eventually("SIGHUP", || c.pending(c.leader, Signal::SIGHUP));
    assert_eq!(block_on(read), Ok(0));
}

/// Finite input commits a partial canonical line without adding a VEOF byte. Reads can drain
/// it in chunks and then report EOF; the terminal itself remains open for output.
#[test]
fn finite_console_eof_commits_a_long_partial_canonical_line() {
    let c = finite_console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let line = b"0123456789abcdefghijklmnopqrst";
    c.keyboard.type_in(line);
    c.keyboard.unplug();

    let file = c.kernel.file(c.leader, Fd(0)).unwrap();
    eventually("finite EOF commits the partial canonical line", || {
        wasixv2_wait::Pollable::poll(&*file, None).contains(wasixv2_wait::PollMask::READABLE)
    });
    assert_eq!(
        c.ioctl_int(&caller, IoctlRequest::TIOCINQ),
        Ok(line.len() as i32)
    );
    assert_eq!(c.read(&caller, 16), Ok(line[..16].to_vec()));
    assert_eq!(c.read(&caller, 16), Ok(line[16..].to_vec()));
    assert_eq!(c.read(&caller, 16), Ok(Vec::new()));
    assert!(!c.pending(c.leader, Signal::SIGHUP));

    assert_eq!(c.write(&caller, 1, b"after EOF\n"), Ok(10));
    assert!(c.shown().ends_with(b"after EOF\r\n"));
}

/// Empty finite input is readable EOF without tty hangup, and stdout still reaches the host.
#[test]
fn finite_console_empty_eof_does_not_hang_up_the_terminal() {
    let c = finite_console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let mut read = Box::pin(c.kernel.read(&caller, Fd(0), UserSliceMut::new(0x200, 16)));
    assert_eq!(read.as_mut().now_or_never(), None);
    c.keyboard.unplug();

    let file = c.kernel.file(c.leader, Fd(0)).unwrap();
    eventually("empty finite EOF is readable", || {
        wasixv2_wait::Pollable::poll(&*file, None).contains(wasixv2_wait::PollMask::READABLE)
    });
    let ready = wasixv2_wait::Pollable::poll(&*file, None);
    assert!(ready.contains(wasixv2_wait::PollMask::READABLE));
    assert!(!ready.contains(wasixv2_wait::PollMask::HUP));
    assert!(!ready.contains(wasixv2_wait::PollMask::ERR));
    // Readiness is published before the pump wakes registered readers. Await
    // this same pending read, including the real wakeup, instead of assuming
    // both publications finished by the first poll observation.
    assert_eq!(block_on(read), Ok(0));
    assert!(!c.pending(c.leader, Signal::SIGHUP));

    assert_eq!(c.write(&caller, 1, b"still open\n"), Ok(11));
    assert!(c.shown().ends_with(b"still open\r\n"));
}

/// A canceled raw read with VMIN still waits for enough bytes. Finite EOF wakes poll and lets a
/// later read return the bytes below VMIN, followed by zero once they are drained.
#[test]
fn finite_console_eof_wakes_raw_vmin_poll_after_read_cancellation() {
    let c = finite_console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let mut raw = c.tcgetattr(&caller);
    raw.c_lflag.0 &= !(TermiosLflag::ICANON.0 | TermiosLflag::ECHO.0 | TermiosLflag::ISIG.0);
    raw.c_cc[TermiosCcIndex::VMIN.0 as usize] = 3;
    raw.c_cc[TermiosCcIndex::VTIME.0 as usize] = 0;
    assert_eq!(c.tcsetattr(&caller, &raw), Ok(0));

    let canceled = Box::pin(c.kernel.read(&caller, Fd(0), UserSliceMut::new(0x200, 16)));
    assert_eq!(canceled.now_or_never(), None);

    c.keyboard.type_in(b"xy");
    eventually("raw input below VMIN", || {
        c.ioctl_int(&caller, IoctlRequest::TIOCINQ) == Ok(2)
    });
    let file = c.kernel.file(c.leader, Fd(0)).unwrap();
    assert!(!wasixv2_wait::Pollable::poll(&*file, None).contains(wasixv2_wait::PollMask::READABLE));

    c.keyboard.unplug();
    eventually("finite EOF makes sub-VMIN input readable", || {
        wasixv2_wait::Pollable::poll(&*file, None).contains(wasixv2_wait::PollMask::READABLE)
    });
    assert_eq!(c.read(&caller, 16), Ok(b"xy".to_vec()));
    assert_eq!(c.read(&caller, 16), Ok(Vec::new()));
    assert!(!c.pending(c.leader, Signal::SIGHUP));
}

/// Only `Ok(0)` is finite EOF. An input-source error still hangs up even under finite policy.
#[test]
fn finite_console_input_error_still_hangs_up() {
    let c = finite_console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGHUP));
    let mut read = Box::pin(c.kernel.read(&caller, Fd(0), UserSliceMut::new(0x200, 16)));
    assert_eq!(read.as_mut().now_or_never(), None);

    c.keyboard.fail();

    eventually("source error sends SIGHUP", || {
        c.pending(c.leader, Signal::SIGHUP)
    });
    assert_eq!(block_on(read), Ok(0));
    assert_eq!(errno(c.write(&caller, 1, b"x")), Errno::EIO);
}

/// Explicit hangup remains a hangup when the input source uses finite EOF semantics.
#[test]
fn finite_console_still_honors_explicit_hangup() {
    let c = finite_console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGHUP));

    c.kernel.console_hangup();

    assert!(c.pending(c.leader, Signal::SIGHUP));
    let file = c.kernel.file(c.leader, Fd(0)).unwrap();
    let poll = wasixv2_wait::Pollable::poll(&*file, None);
    assert!(poll.contains(wasixv2_wait::PollMask::HUP));
    assert!(poll.contains(wasixv2_wait::PollMask::ERR));
    assert_eq!(c.read(&caller, 16), Ok(Vec::new()));
    assert_eq!(errno(c.write(&caller, 1, b"x")), Errno::EIO);
}

/// `TIOCSTI` pushes input as if typed, for the terminal's own session.
#[test]
fn tiocsti_fakes_input() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    for &byte in b"hi\n" {
        put(&memory.0, 0x30, &[byte]);
        assert_eq!(c.ioctl(&caller, 0, IoctlRequest::TIOCSTI, 0x30), Ok(0));
    }
    assert_eq!(c.ioctl_int(&caller, IoctlRequest::TIOCINQ), Ok(3));
    assert_eq!(c.read(&caller, 16), Ok(b"hi\n".to_vec()));
}

/// Raw mode: `VMIN` 0 and `VTIME` 0 make a read return at once, with what there is.
#[test]
fn a_raw_read_with_vmin_zero_returns_at_once() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let mut raw = c.tcgetattr(&caller);
    raw.c_lflag.0 &= !(TermiosLflag::ICANON.0 | TermiosLflag::ECHO.0);
    raw.c_cc[TermiosCcIndex::VMIN.0 as usize] = 0;
    assert_eq!(c.tcsetattr(&caller, &raw), Ok(0));
    assert_eq!(c.read(&caller, 16), Ok(Vec::new()));
    c.keyboard.type_in(b"q");
    eventually("the input", || {
        c.ioctl_int(&caller, IoctlRequest::FIONREAD) == Ok(1)
    });
    assert_eq!(c.read(&caller, 16), Ok(b"q".to_vec()));
    assert!(c.shown().is_empty(), "no echo");
}

/// `/proc/<pid>/stat` names the controlling terminal and its foreground group.
#[test]
fn proc_stat_shows_the_controlling_terminal() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let fd = open(&c.kernel, &caller, b"/proc/self/stat", OpenFlags::O_RDONLY);
    let n = block_on(c.kernel.read(&caller, fd, UserSliceMut::new(0x400, 512))).unwrap();
    let stat = String::from_utf8(get(&memory.0, 0x400, n as usize)).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
    // state, ppid, pgrp, session, tty_nr, tpgid
    let pid = c.leader.0.to_string();
    assert_eq!(fields[4], (229 << 8).to_string());
    assert_eq!(fields[5], pid);
}

/// A foreground group that emptied stays the terminal's foreground group: `TIOCGPGRP` and
/// `/proc/<pid>/stat`'s tpgid still show its number, as `tty->ctrl.pgrp` holds its
/// `struct pid` (`tiocgpgrp`, `do_task_stat`).
#[test]
fn an_emptied_foreground_group_keeps_its_number() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let job = c.background_job(&caller);
    let pgrp = job.0 as Pid;
    assert_eq!(c.tcsetpgrp(&caller, pgrp), Ok(0));
    let job_memory = self::memory();
    let job_caller = Caller::new(job, &job_memory);
    assert_eq!(block_on(c.kernel.exit_group(&job_caller, 0)), Ok(()));
    // Reaped and released: nothing holds its pid or its group any more.
    let options = WaitOptions(WaitOptions::WEXITED.0);
    let wait = c.kernel.waitid(
        &caller,
        Idtype::P_PID,
        pgrp,
        SiginfoPtr::new(0x300),
        options,
        RusagePtr::new(0),
    );
    assert_eq!(block_on(wait), Ok(0));
    c.kernel.release(job);
    assert_eq!(
        errno(block_on(c.kernel.sys_kill(&caller, -pgrp, Signal(0)))),
        Errno::ESRCH
    );

    assert_eq!(c.ioctl_int(&caller, IoctlRequest::TIOCGPGRP), Ok(pgrp));
    let fd = open(&c.kernel, &caller, b"/proc/self/stat", OpenFlags::O_RDONLY);
    let n = block_on(c.kernel.read(&caller, fd, UserSliceMut::new(0x400, 512))).unwrap();
    let stat = String::from_utf8(get(&memory.0, 0x400, n as usize)).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
    assert_eq!(fields[5], pgrp.to_string());
}

/// `^S` stops output: a write waits, and `^Q`, echoed or not, lets it go on.
#[test]
fn ctrl_s_holds_writes_until_ctrl_q() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let file = c.kernel.file(c.leader, Fd(1)).unwrap();
    c.keyboard.type_in(b"\x13");
    eventually("output stopped", || {
        !wasixv2_wait::Pollable::poll(&*file, None).contains(wasixv2_wait::PollMask::WRITABLE)
    });
    block_on(memory.write(0x200, b"held")).unwrap();
    let mut write = Box::pin(c.kernel.write(&caller, Fd(1), UserSlice::new(0x200, 4)));
    assert_eq!(write.as_mut().now_or_never(), None);

    // An echo while output is stopped waits too, and must not keep `^Q` from coming through.
    c.keyboard.type_in(b"x");
    std::thread::sleep(Duration::from_millis(20));
    c.keyboard.type_in(b"\x11");

    let mut written = None;
    eventually("the write", || {
        written = write.as_mut().now_or_never();
        written.is_some()
    });
    assert_eq!(written, Some(Ok(4)));
    eventually("the echo", || c.shown().len() == 5);
    assert!(c.shown() == b"xheld" || c.shown() == b"heldx");
}

/// Script actual host writes while the kernel owns termios and descriptor routing.
#[derive(Clone, Copy)]
enum OutputStep {
    Take(usize),
    Block,
    Fail(io::ErrorKind),
    Report(usize),
}
#[derive(Default)]
struct ScriptedOutput(Mutex<OutputState>);
#[derive(Default)]
struct OutputState {
    steps: VecDeque<OutputStep>,
    accepted: Vec<u8>,
    requests: Vec<Vec<u8>>,
    waker: Option<Waker>,
}
impl ScriptedOutput {
    fn new(steps: impl IntoIterator<Item = OutputStep>) -> Self {
        Self(Mutex::new(OutputState {
            steps: steps.into_iter().collect(),
            ..Default::default()
        }))
    }
    fn release(&self) {
        let wake = {
            let mut state = self.0.lock_or_recover();
            assert!(matches!(state.steps.pop_front(), Some(OutputStep::Block)));
            state.waker.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    fn accepted(&self) -> Vec<u8> {
        self.0.lock_or_recover().accepted.clone()
    }
    fn requests(&self) -> Vec<Vec<u8>> {
        self.0.lock_or_recover().requests.clone()
    }
}
impl ByteSink for ScriptedOutput {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        Box::pin(futures::future::poll_fn(move |cx| {
            let mut state = self.0.lock_or_recover();
            if matches!(state.steps.front(), Some(OutputStep::Block)) {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let step = state
                .steps
                .pop_front()
                .unwrap_or(OutputStep::Take(usize::MAX));
            state.requests.push(data.to_vec());
            Poll::Ready(match step {
                OutputStep::Take(limit) => {
                    let count = limit.min(data.len());
                    state.accepted.extend_from_slice(&data[..count]);
                    Ok(count)
                }
                OutputStep::Report(count) => Ok(count),
                OutputStep::Fail(error) => Err(error.into()),
                OutputStep::Block => unreachable!(),
            })
        }))
    }
}

/// A controlled test timer: the console output fence cannot time out underneath
/// the blocked-output assertion. Execution and input pumping use the existing host.
struct PendingTimerHost;
impl Host for PendingTimerHost {
    fn realtime(&self) -> Duration {
        ThreadHost.realtime()
    }
    fn monotonic(&self) -> Duration {
        ThreadHost.monotonic()
    }
    fn sleep(&self, _: Duration) -> LocalFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn sleep_until(&self, _: Duration) -> LocalFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn random(&self, buffer: &mut [u8]) {
        ThreadHost.random(buffer);
    }
    fn executor(&self) -> &dyn Executor {
        &ThreadHost
    }
}

#[test]
fn console_output_overrides_preserve_echo_termios_and_descriptor_identity() {
    let errors = Arc::new(Capture::default());
    let c = console_with_outputs(
        None,
        [None, None, Some(errors.clone())],
        Arc::new(ThreadHost),
    );
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let stdin = c.kernel.file(c.leader, Fd(0)).unwrap();
    let stdout = c.kernel.file(c.leader, Fd(1)).unwrap();
    let stderr = c.kernel.file(c.leader, Fd(2)).unwrap();
    assert!(Arc::ptr_eq(&stdin, &stdout));
    assert!(!Arc::ptr_eq(&stdout, &stderr));
    assert_eq!(c.ioctl(&caller, 2, IoctlRequest::TCGETS, 0x40), Ok(0));
    let termios: Termios = block_on(read_value(caller.memory(), GuestPtr::new(0x40))).unwrap();
    assert!(termios.c_lflag.0 & TermiosLflag::ICANON.0 != 0);
    assert!(termios.c_lflag.0 & TermiosLflag::ECHO.0 != 0);
    c.keyboard.type_in(b"typed\r");
    eventually("console echo stays on its screen", || {
        c.shown() == b"typed\r\n"
    });
    assert_eq!(c.write(&caller, 1, b"stdout\n"), Ok(7));
    assert_eq!(c.write(&caller, 2, b"stderr\n"), Ok(7));
    assert_eq!(c.shown(), b"typed\r\nstdout\r\n");
    assert_eq!(*errors.0.lock_or_recover(), b"stderr\r\n");
    // dup3 with zero flags is dup2's replacement operation, and copies the
    // selected open-file identity rather than a numeric descriptor policy.
    assert_eq!(
        block_on(c.kernel.dup3(&caller, Fd(2), Fd(1), OpenFlags(0))),
        Ok(Fd(1))
    );
    assert_eq!(c.write(&caller, 1, b"dup\n"), Ok(4));
    let child = c.fork(&caller);
    let child_memory = self::memory();
    let child_caller = Caller::new(child, &child_memory);
    assert_eq!(c.write(&child_caller, 2, b"child\n"), Ok(6));
    assert_eq!(*errors.0.lock_or_recover(), b"stderr\r\ndup\r\nchild\r\n");
    assert_eq!(c.shown(), b"typed\r\nstdout\r\n");
    c.keyboard.unplug();
}

#[test]
fn default_console_keeps_one_open_file_and_ignores_unselected_overrides() {
    let c = console();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let stdin = c.kernel.file(c.leader, Fd(0)).unwrap();
    assert!(Arc::ptr_eq(
        &stdin,
        &c.kernel.file(c.leader, Fd(1)).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &stdin,
        &c.kernel.file(c.leader, Fd(2)).unwrap()
    ));
    let ignored = Arc::new(ScriptedOutput::new([OutputStep::Fail(
        io::ErrorKind::BrokenPipe,
    )]));
    block_on(c.kernel.attach_console_outputs(
        c.leader,
        [false, true, false],
        [None, None, Some(ignored.clone())],
    ))
    .unwrap();
    assert!(Arc::ptr_eq(
        &stdin,
        &c.kernel.file(c.leader, Fd(2)).unwrap()
    ));
    assert_eq!(c.write(&caller, 2, b"default\n"), Ok(8));
    assert_eq!(c.shown(), b"default\r\n");
    assert!(ignored.requests().is_empty());
    c.keyboard.unplug();
}

#[test]
fn exclusive_console_open_failure_preserves_existing_descriptors_and_output_routes() {
    let errors = Arc::new(Capture::default());
    let c = console_with_outputs(
        None,
        [None, None, Some(errors.clone())],
        Arc::new(ThreadHost),
    );
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    assert!(
        !c.kernel
            .cred(&caller)
            .capable_init(wasixv2_vfs::Cap::SysAdmin)
    );
    let old = [0, 1, 2].map(|fd| c.kernel.file(c.leader, Fd(fd)).unwrap());
    assert_eq!(c.ioctl(&caller, 0, IoctlRequest::TIOCEXCL, 0), Ok(0));
    assert_eq!(c.ioctl_int(&caller, IoctlRequest::TIOCGEXCL), Ok(1));
    let rejected = Arc::new(Capture::default());
    assert_eq!(
        block_on(c.kernel.attach_console_outputs(
            c.leader,
            [true; 3],
            [None, None, Some(rejected.clone())],
        )),
        Err(Errno::EBUSY)
    );
    for (fd, file) in old.iter().enumerate() {
        assert!(Arc::ptr_eq(
            file,
            &c.kernel.file(c.leader, Fd(fd as i32)).unwrap()
        ));
    }
    assert_eq!(c.write(&caller, 1, b"stdout\n"), Ok(7));
    assert_eq!(c.write(&caller, 2, b"stderr\n"), Ok(7));
    assert_eq!(c.shown(), b"stdout\r\n");
    assert_eq!(*errors.0.lock_or_recover(), b"stderr\r\n");
    assert!(rejected.0.lock_or_recover().is_empty());
    c.keyboard.type_in(b"input\n");
    assert_eq!(c.read(&caller, 6), Ok(b"input\n".to_vec()));
    c.keyboard.unplug();
}

#[test]
fn routed_console_completes_short_writes_after_one_output_processing_step() {
    let sink = Arc::new(ScriptedOutput::new([
        OutputStep::Take(1),
        OutputStep::Take(2),
        OutputStep::Take(2),
    ]));
    let c = console_with_outputs(None, [None, None, Some(sink.clone())], Arc::new(ThreadHost));
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    assert_eq!(c.write(&caller, 2, b"a\nb\n"), Ok(4));
    assert_eq!(sink.accepted(), b"a\r\nb\r\n");
    assert_eq!(
        sink.requests(),
        vec![
            b"a\r\nb\r\n".to_vec(),
            b"\r\nb\r\n".to_vec(),
            b"b\r\n".to_vec(),
            b"\n".to_vec()
        ]
    );
    c.keyboard.unplug();
}

#[test]
fn routed_console_short_writes_are_processed_once_and_never_replayed_after_error() {
    let errors = Arc::new(ScriptedOutput::new([
        OutputStep::Take(2),
        OutputStep::Fail(io::ErrorKind::BrokenPipe),
    ]));
    let c = console_with_outputs(
        None,
        [None, None, Some(errors.clone())],
        Arc::new(ThreadHost),
    );
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    c.kernel
        .task_signals(c.leader)
        .replace_blocked(blocked(Signal::SIGPIPE));
    assert_eq!(errno(c.write(&caller, 2, b"abcd")), Errno::EPIPE);
    assert!(c.pending(c.leader, Signal::SIGPIPE));
    ignore(&c.kernel, &caller, Signal::SIGPIPE);
    assert_eq!(errors.accepted(), b"ab");
    assert_eq!(c.write(&caller, 2, b"q\n"), Ok(2));
    assert_eq!(errors.accepted(), b"abq\r\n");
    assert_eq!(
        errors.requests(),
        vec![b"abcd".to_vec(), b"cd".to_vec(), b"q\r\n".to_vec()]
    );
    assert!(c.shown().is_empty());
    c.keyboard.unplug();
}

#[test]
fn routed_console_rejects_zero_and_oversized_host_write_counts() {
    for count in [0, usize::MAX] {
        let sink = Arc::new(ScriptedOutput::new([OutputStep::Report(count)]));
        let c = console_with_outputs(None, [None, Some(sink.clone()), None], Arc::new(ThreadHost));
        let memory = memory();
        let caller = Caller::new(c.leader, &memory);
        assert_eq!(errno(c.write(&caller, 1, b"x")), Errno::EIO);
        assert!(sink.accepted().is_empty());
        c.keyboard.unplug();
    }
}

#[test]
fn routed_console_blocked_write_holds_sent_fence_until_completion_or_cancellation() {
    for canceled in [false, true] {
        let sink = Arc::new(ScriptedOutput::new([
            OutputStep::Take(2),
            OutputStep::Block,
        ]));
        let c = console_with_outputs(
            None,
            [None, None, Some(sink.clone())],
            Arc::new(PendingTimerHost),
        );
        let memory = memory();
        let caller = Caller::new(c.leader, &memory);
        put(&memory.0, 0x200, b"abcd");
        let mut write = Box::pin(c.kernel.write(&caller, Fd(2), UserSlice::new(0x200, 4)));
        assert_eq!(write.as_mut().now_or_never(), None);
        assert_eq!(sink.accepted(), b"ab");
        let mut sent = Box::pin(c.kernel.console_wait_until_sent());
        assert_eq!(sent.as_mut().now_or_never(), None);
        if canceled {
            drop(write);
            sink.release();
        } else {
            sink.release();
            assert_eq!(write.as_mut().now_or_never(), Some(Ok(4)));
            drop(write);
        }
        assert_eq!(sent.as_mut().now_or_never(), Some(()));
        assert_eq!(c.write(&caller, 2, b"q"), Ok(1));
        if canceled {
            assert_eq!(sink.accepted(), b"abq");
            assert_eq!(sink.requests(), vec![b"abcd".to_vec(), b"q".to_vec()]);
        } else {
            assert_eq!(sink.accepted(), b"abcdq");
            assert_eq!(
                sink.requests(),
                vec![b"abcd".to_vec(), b"cd".to_vec(), b"q".to_vec()]
            );
        }
        c.keyboard.unplug();
    }
}

#[test]
fn routed_console_does_not_change_pty_output() {
    let errors = Arc::new(Capture::default());
    let c = console_with_outputs(
        None,
        [None, None, Some(errors.clone())],
        Arc::new(ThreadHost),
    );
    block_on(
        c.kernel
            .vfs()
            .mount(b"/dev/pts", c.kernel.devpts(), MountFlags::default(), true),
    )
    .unwrap();
    let memory = memory();
    let caller = Caller::new(c.leader, &memory);
    let flags = OpenFlags(OpenFlags::O_RDWR.0 | OpenFlags::O_NOCTTY.0);
    let master = open(&c.kernel, &caller, b"/dev/ptmx", flags);
    put(&memory.0, 0x10, &0i32.to_le_bytes());
    assert_eq!(
        c.ioctl(&caller, master.0, IoctlRequest::TIOCSPTLCK, 0x10),
        Ok(0)
    );
    let slave = open(&c.kernel, &caller, b"/dev/pts/0", flags);
    assert_eq!(c.write(&caller, slave.0, b"pty\n"), Ok(4));
    let n = block_on(c.kernel.read(&caller, master, UserSliceMut::new(0x300, 16))).unwrap();
    assert_eq!(get(&memory.0, 0x300, n as usize), b"pty\r\n");
    assert!(errors.0.lock_or_recover().is_empty());
    assert!(c.shown().is_empty());
    c.keyboard.unplug();
}
