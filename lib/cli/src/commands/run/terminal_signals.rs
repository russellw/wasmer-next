//! CLI job control. Tokio permanently installs signal handlers, so this policy belongs to
//! `wasmer run`, not the reusable terminal facade or embedders that only forward Ctrl-C.
//!
//! Tokio 1.53.1's Signal owns a global watch receiver, not a runtime handle (signal/mod.rs,
//! signal/unix.rs). Enabled runtime drivers broadcast the shared self-pipe. Move the same
//! receiver bundle between existing forwarders to preserve its consumed-event version.

use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard},
    task::{Context, Poll},
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    sync::{Notify, futures::OwnedNotified},
};

use super::terminal;

static COORDINATOR: LazyLock<Coordinator> = LazyLock::new(Coordinator::default);

#[derive(Default)]
struct Coordinator {
    state: Mutex<State>,
    installed: Condvar,
}
#[derive(Default)]
struct State {
    installing: bool,
    next_id: u64,
    owner: Option<u64>,
    participants: VecDeque<Participant>,
    available: Option<Receivers>,
    epoch: u64,
}
struct Participant {
    id: u64,
    notify: Arc<Notify>,
}
struct Receivers {
    stop: Signal,
    continued: Signal,
}
impl Coordinator {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn resized(&self) -> u64 {
        let (epoch, notifications) = {
            let mut state = self.lock();
            state.epoch += 1;
            (
                state.epoch,
                state
                    .participants
                    .iter()
                    .map(|p| p.notify.clone())
                    .collect::<Vec<_>>(),
            )
        };
        for notify in notifications {
            notify.notify_one();
        }
        epoch
    }
}

/// Publish a completed state before either partially installed receiver can be dropped.
struct Installing {
    armed: bool,
    stop: Option<Signal>,
    continued: Option<Signal>,
}
impl Drop for Installing {
    fn drop(&mut self) {
        if self.armed {
            COORDINATOR.lock().installing = false;
            COORDINATOR.installed.notify_all();
        }
        // Receiver/waker destruction follows this Drop, outside the coordinator lock.
    }
}

struct StopLease {
    id: u64,
    epoch: u64,
    notify: Arc<Notify>,
    notified: Pin<Box<OwnedNotified>>,
    receivers: Option<Receivers>,
}
impl StopLease {
    fn new() -> io::Result<Self> {
        let notify = Arc::new(Notify::new());
        // Arm before checking state; notify_one retains a permit even before the first poll.
        let notified = Box::pin(notify.clone().notified_owned());
        let mut state = COORDINATOR.lock();
        let mut installed = false;
        while state.installing {
            state = COORDINATOR
                .installed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.participants.is_empty() {
            state.installing = true;
            drop(state);
            let mut installation = Installing {
                armed: true,
                stop: None,
                continued: None,
            };
            installation.stop = Some(signal(SignalKind::from_raw(libc::SIGTSTP))?);
            installation.continued = Some(signal(SignalKind::from_raw(libc::SIGCONT))?);
            state = COORDINATOR.lock();
            state.available = Some(Receivers {
                stop: installation.stop.take().unwrap(),
                continued: installation.continued.take().unwrap(),
            });
            state.installing = false;
            installation.armed = false;
            // The installation guard is empty here; no receiver or waker is dropped.
            drop(installation);
            installed = true;
        }
        state.next_id += 1;
        let id = state.next_id;
        let epoch = state.epoch;
        state.participants.push_back(Participant {
            id,
            notify: notify.clone(),
        });
        if state.owner.is_none() {
            state.owner = Some(id);
        }
        let receivers = if state.owner == Some(id) {
            state.available.take()
        } else {
            None
        };
        drop(state);
        if installed {
            COORDINATOR.installed.notify_all();
        }
        Ok(Self {
            id,
            epoch,
            notify,
            notified,
            receivers,
        })
    }

    fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let epoch = {
                let mut state = COORDINATOR.lock();
                if state.owner == Some(self.id) && self.receivers.is_none() {
                    self.receivers = state.available.take();
                }
                state.epoch
            };
            if epoch != self.epoch {
                self.epoch = epoch;
                return Poll::Ready(Ok(()));
            }
            if let Some(receivers) = &mut self.receivers {
                if receivers.stop.poll_recv(cx).is_ready() {
                    terminal::suspend();
                    // No await between consuming TSTP and stopping/continuing: cancellation
                    // cannot transfer an already consumed stop to a successor.
                    // SAFETY: SIGSTOP to the calling thread stops the whole host process.
                    let stopped = unsafe { libc::raise(libc::SIGSTOP) };
                    let error = (stopped != 0).then(io::Error::last_os_error);
                    terminal::resume();
                    self.epoch = COORDINATOR.resized();
                    return Poll::Ready(error.map_or(Ok(()), Err));
                }
                if receivers.continued.poll_recv(cx).is_ready() {
                    terminal::resume();
                    self.epoch = COORDINATOR.resized();
                    return Poll::Ready(Ok(()));
                }
            }
            match self.notified.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => self.notified = Box::pin(self.notify.clone().notified_owned()),
            }
        }
    }
}
impl Drop for StopLease {
    fn drop(&mut self) {
        let (participant, successor, retired) = {
            let mut state = COORDINATOR.lock();
            let participant = state
                .participants
                .iter()
                .position(|p| p.id == self.id)
                .and_then(|index| state.participants.remove(index));
            let mut retired = None;
            let successor = if state.owner == Some(self.id) {
                // An elected successor may retire before ever polling its handoff.
                let receivers = self.receivers.take().or_else(|| state.available.take());
                if let Some(next) = state.participants.front() {
                    let id = next.id;
                    let notify = next.notify.clone();
                    state.owner = Some(id);
                    state.available = receivers;
                    Some(notify)
                } else {
                    state.owner = None;
                    retired = receivers;
                    None
                }
            } else {
                None
            };
            (participant, successor, retired)
        };
        // Publish successor/empty state before notifications or any receiver/waker drop.
        // A retired bundle is never polled again; reentrant registration may safely install
        // the next active bundle while this retired one is being destroyed.
        if let Some(notify) = successor {
            notify.notify_one();
        }
        drop(participant);
        drop(retired);
    }
}

/// Owned by an existing CLI forwarder, never by a temporary recv future. Dropping the
/// forwarder transfers process-stop custody; abort and await it before restoring raw mode.
pub(super) struct TerminalSignals {
    winch: Signal,
    stop: StopLease,
}
impl TerminalSignals {
    pub(super) fn new() -> io::Result<Self> {
        let winch = signal(SignalKind::from_raw(libc::SIGWINCH))?;
        let stop = StopLease::new()?;
        Ok(Self { winch, stop })
    }

    pub(super) async fn recv(&mut self) -> io::Result<()> {
        poll_fn(|cx| {
            if let Poll::Ready(result) = self.stop.poll_change(cx) {
                return Poll::Ready(result);
            }
            self.winch.poll_recv(cx).map(|_| Ok(()))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        io::{BufRead, BufReader, Write},
        os::{
            fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
            unix::{net::UnixStream, process::CommandExt},
        },
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    use wasixv2::terminal::Terminal;

    const CHILD: &str = "WASMER_TERMINAL_SIGNALS_CHILD";
    const TIMEOUT: Duration = Duration::from_secs(10);

    struct Pty {
        master: OwnedFd,
        slave: OwnedFd,
    }
    impl Pty {
        fn open() -> Self {
            let (mut master, mut slave) = (0, 0);
            // SAFETY: openpty fills two newly owned descriptors.
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master,
                        &mut slave,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            for fd in [master, slave] {
                // SAFETY: only the test's own explicit duplicates are inherited by its child.
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
            }
            Self {
                master: unsafe { OwnedFd::from_raw_fd(master) },
                slave: unsafe { OwnedFd::from_raw_fd(slave) },
            }
        }
        fn settings(&self) -> libc::termios {
            settings(self.slave.as_raw_fd())
        }
    }
    fn settings(fd: libc::c_int) -> libc::termios {
        let mut settings = std::mem::MaybeUninit::<libc::termios>::zeroed();
        // SAFETY: tcgetattr fills kernel fields; fields absent from its layout are already zero.
        assert_eq!(unsafe { libc::tcgetattr(fd, settings.as_mut_ptr()) }, 0);
        unsafe { settings.assume_init() }
    }
    fn same(a: &libc::termios, b: &libc::termios) -> bool {
        (a.c_iflag, a.c_oflag, a.c_cflag, a.c_lflag, a.c_cc)
            == (b.c_iflag, b.c_oflag, b.c_cflag, b.c_lflag, b.c_cc)
    }
    fn raw(settings: &libc::termios) -> bool {
        settings.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG) == 0
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn report(control: &Arc<Mutex<UnixStream>>, message: &str) {
        writeln!(control.lock().unwrap(), "{message}").unwrap();
    }
    fn next(control: &mut BufReader<UnixStream>) -> String {
        let mut line = String::new();
        assert!(
            control
                .read_line(&mut line)
                .expect("child made progress after one SIGCONT")
                > 0
        );
        line.trim().to_owned()
    }
    fn wait_for(control: &mut BufReader<UnixStream>, wanted: &str) {
        loop {
            let message = next(control);
            if message == wanted {
                return;
            }
            assert!(
                message.starts_with("resize:"),
                "unexpected child message: {message}"
            );
        }
    }
    fn wait_stopped(child: &Child) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let mut status = 0;
            // SAFETY: observe only our own child, without blocking beyond the deadline.
            let found = unsafe {
                libc::waitpid(
                    child.id() as _,
                    &mut status,
                    libc::WUNTRACED | libc::WNOHANG,
                )
            };
            if found != 0 {
                assert_eq!(found, child.id() as libc::pid_t);
                assert!(
                    libc::WIFSTOPPED(status),
                    "child stopped rather than exiting"
                );
                assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
                return;
            }
            assert!(Instant::now() < deadline, "child did not stop");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop_continue(
        child: &Child,
        pty: &Pty,
        cooked: &libc::termios,
        control: &mut BufReader<UnixStream>,
        participants: &[usize],
    ) {
        // SAFETY: signals to the process owned by this test.
        assert_eq!(unsafe { libc::kill(child.id() as _, libc::SIGTSTP) }, 0);
        wait_stopped(child);
        assert!(
            same(&pty.settings(), cooked),
            "restored while the actual process is stopped"
        );
        assert_eq!(unsafe { libc::kill(child.id() as _, libc::SIGCONT) }, 0);
        let mut seen = HashSet::new();
        while !participants.iter().all(|id| seen.contains(id)) {
            let message = next(control);
            let id = message
                .strip_prefix("resize:")
                .expect("actual forwarder resize notification")
                .parse::<usize>()
                .unwrap();
            seen.insert(id);
        }
        let deadline = Instant::now() + TIMEOUT;
        while !raw(&pty.settings()) {
            let mut status = 0;
            let found = unsafe {
                libc::waitpid(
                    child.id() as _,
                    &mut status,
                    libc::WUNTRACED | libc::WNOHANG,
                )
            };
            assert_eq!(found, 0, "one continuation must not require a second one");
            assert!(
                Instant::now() < deadline,
                "raw again after one continuation"
            );
            std::thread::yield_now();
        }
        let mut status = 0;
        let found = unsafe {
            libc::waitpid(
                child.id() as _,
                &mut status,
                libc::WUNTRACED | libc::WNOHANG,
            )
        };
        assert_eq!(found, 0, "no second stop from a sibling's stale TSTP");
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }
    fn worker(
        runtime: &tokio::runtime::Runtime,
        id: usize,
        control: Arc<Mutex<UnixStream>>,
        cancel_pending_receive: bool,
    ) -> tokio::task::JoinHandle<()> {
        use futures_util::FutureExt as _;
        let mut signals = {
            let _entered = runtime.enter();
            TerminalSignals::new().unwrap()
        };
        if cancel_pending_receive {
            runtime.block_on(async {
                // Before the first parent signal, cancellation must retain bundle custody.
                assert!(signals.recv().now_or_never().is_none());
            });
        }
        runtime.spawn(async move {
            loop {
                signals.recv().await.unwrap();
                report(&control, &format!("resize:{id}"));
            }
        })
    }
    fn child() {
        let control_fd: libc::c_int = std::env::var("WASMER_TERMINAL_CONTROL_FD")
            .unwrap()
            .parse()
            .unwrap();
        let terminal_fd: libc::c_int = std::env::var("WASMER_TERMINAL_FD")
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: these are the test's explicitly inherited, uniquely owned descriptors.
        let control = unsafe { UnixStream::from_raw_fd(control_fd) };
        let terminal_fd = unsafe { OwnedFd::from_raw_fd(terminal_fd) };
        let terminal = Terminal::duplicate(terminal_fd.as_fd()).unwrap();
        let cooked = settings(terminal_fd.as_raw_fd());
        let mut input = BufReader::new(control.try_clone().unwrap());
        let output = Arc::new(Mutex::new(control));
        let first_runtime = runtime();
        let second_runtime = runtime();
        let first = worker(&first_runtime, 1, output.clone(), true);
        let mut second = worker(&second_runtime, 2, output.clone(), true);
        let first_raw = terminal.raw().unwrap();
        let mut second_raw = terminal.raw().unwrap();
        report(&output, "ready");
        assert_eq!(next(&mut input), "handoff");
        first.abort();
        first_runtime.block_on(async {
            assert!(first.await.unwrap_err().is_cancelled());
        });
        drop(first_raw);
        drop(first_runtime);
        // The same bundle now depends on the remaining runtime's driver, not the old one.
        report(&output, "handed-off");
        for _ in 0..2 {
            assert_eq!(next(&mut input), "restart");
            second.abort();
            second_runtime.block_on(async {
                assert!(second.await.unwrap_err().is_cancelled());
            });
            drop(second_raw);
            assert!(same(&settings(terminal_fd.as_raw_fd()), &cooked));
            assert!(COORDINATOR.lock().participants.is_empty());
            second = worker(&second_runtime, 2, output.clone(), false);
            second_raw = terminal.raw().unwrap();
            report(&output, "restarted");
        }
        assert_eq!(next(&mut input), "finish");
        second.abort();
        second_runtime.block_on(async {
            assert!(second.await.unwrap_err().is_cancelled());
        });
        drop(second_raw);
        drop(second_runtime);
        assert!(same(&settings(terminal_fd.as_raw_fd()), &cooked));
        assert!(COORDINATOR.lock().participants.is_empty());
        report(&output, "finished");
    }

    /// Like run_tty.rs, this uses a real isolated process, PTY settings, WUNTRACED and
    /// one SIGCONT per stop. Child acknowledgements come from actual receiver callbacks.
    #[test]
    fn one_stop_owner_survives_handoff_runtime_drop_and_repeated_runs() {
        if std::env::var_os(CHILD).is_some() {
            child();
            return;
        }
        let pty = Pty::open();
        let cooked = pty.settings();
        let (control, child_control) = UnixStream::pair().unwrap();
        control.set_read_timeout(Some(TIMEOUT)).unwrap();
        control.set_write_timeout(Some(TIMEOUT)).unwrap();
        // High inherited descriptors cannot collide with Command's standard-stream setup.
        let inherited = |fd| {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128) };
            assert!(duplicate >= 0);
            unsafe { OwnedFd::from_raw_fd(duplicate) }
        };
        let child_control = inherited(child_control.as_raw_fd());
        let child_terminal = inherited(pty.slave.as_raw_fd());
        let (control_fd, terminal_fd) = (child_control.as_raw_fd(), child_terminal.as_raw_fd());
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "commands::run::terminal_signals::tests::one_stop_owner_survives_handoff_runtime_drop_and_repeated_runs", "--nocapture"])
            .env(CHILD, "1")
            .env("WASMER_TERMINAL_CONTROL_FD", control_fd.to_string())
            .env("WASMER_TERMINAL_FD", terminal_fd.to_string())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit());
        // SAFETY: only async-signal-safe descriptor/session operations before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(control_fd, libc::F_SETFD, 0) < 0
                    || libc::fcntl(terminal_fd, libc::F_SETFD, 0) < 0
                    || libc::setsid() < 0
                    || libc::ioctl(terminal_fd, libc::TIOCSCTTY as _, 0) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = ChildGuard(command.spawn().unwrap());
        drop(child_control);
        drop(child_terminal);
        let mut control = BufReader::new(control);
        wait_for(&mut control, "ready");
        assert!(raw(&pty.settings()));
        stop_continue(&child.0, &pty, &cooked, &mut control, &[1, 2]);
        writeln!(control.get_mut(), "handoff").unwrap();
        wait_for(&mut control, "handed-off");
        stop_continue(&child.0, &pty, &cooked, &mut control, &[2]);
        for _ in 0..2 {
            writeln!(control.get_mut(), "restart").unwrap();
            wait_for(&mut control, "restarted");
            stop_continue(&child.0, &pty, &cooked, &mut control, &[2]);
        }
        writeln!(control.get_mut(), "finish").unwrap();
        wait_for(&mut control, "finished");
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child did not retire its runtimes"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(same(&pty.settings(), &cooked));
        drop(pty.master);
    }

    #[test]
    fn receiver_and_old_waker_drops_can_reenter_registration_after_handoff() {
        use std::{
            sync::atomic::{AtomicBool, Ordering},
            task::{Wake, Waker},
        };
        const REENTRY_CHILD: &str = "WASMER_TERMINAL_SIGNALS_REENTRY_CHILD";
        if std::env::var_os(REENTRY_CHILD).is_none() {
            let mut child = ChildGuard(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "commands::run::terminal_signals::tests::receiver_and_old_waker_drops_can_reenter_registration_after_handoff", "--nocapture"])
                .env(REENTRY_CHILD, "1").spawn().unwrap());
            let deadline = Instant::now() + TIMEOUT;
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "reentrant receiver retirement did not finish"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            return;
        }
        struct Probe(Arc<AtomicBool>);
        #[allow(
            clippy::manual_noop_waker,
            reason = "observes the old signal waker destructor"
        )]
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                assert!(COORDINATOR.state.try_lock().is_ok());
                let nested = TerminalSignals::new().unwrap();
                drop(nested);
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for handoff in [true, false] {
            let first_runtime = runtime();
            let second_runtime = runtime();
            let dropped = Arc::new(AtomicBool::new(false));
            let mut first = {
                let _entered = first_runtime.enter();
                TerminalSignals::new().unwrap()
            };
            let waker = Waker::from(Arc::new(Probe(dropped.clone())));
            {
                let _entered = first_runtime.enter();
                let mut receive = Box::pin(first.recv());
                assert!(
                    receive
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            drop(waker);
            let mut survivor = if handoff {
                let _entered = second_runtime.enter();
                let unpolled = TerminalSignals::new().unwrap();
                let survivor = TerminalSignals::new().unwrap();
                drop(first);
                // The first successor returns custody before ever polling its receivers.
                drop(unpolled);
                Some(survivor)
            } else {
                let _entered = first_runtime.enter();
                drop(first);
                None
            };
            drop(first_runtime);
            if let Some(signals) = &mut survivor {
                second_runtime.block_on(async {
                    let mut receive = Box::pin(signals.recv());
                    assert!(
                        receive
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_pending()
                    );
                });
            }
            assert!(
                dropped.load(Ordering::SeqCst),
                "old waker retired without retaining its runtime"
            );
            {
                let _entered = second_runtime.enter();
                drop(survivor);
            }
            assert!(COORDINATOR.lock().participants.is_empty());
            drop(second_runtime);
        }
    }
}
