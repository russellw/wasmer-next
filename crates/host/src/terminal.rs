//! Native inherited host terminals and shared raw-mode leases.
//!
//! Handles own their descriptors, so closing or replacing standard input cannot redirect a
//! later restore. Leases on one terminal share its first saved settings; the last lease
//! restores them. Acquiring a lease does not install a panic hook or change an embedder's
//! panic policy; a caught panic leaves retained leases in force until their owners release
//! them after cleanup. Linux identifies terminals with `TIOCGDEV`, including `/dev/tty` aliases.
//! This is the inherited-terminal profile: independently mounted devpts instances can reuse
//! device numbers and are not a supported identity domain for this process-wide registry.

use std::{
    collections::HashMap,
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard},
};

use crate::WindowSize;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TerminalKey(libc::dev_t);

/// An owned handle to an inherited native host terminal.
#[derive(Clone)]
pub struct Terminal {
    fd: Arc<OwnedFd>,
    key: TerminalKey,
}

impl AsFd for Terminal {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Terminal {
    /// Duplicates a terminal descriptor. The caller may subsequently close or replace it.
    pub fn duplicate(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let fd = endpoint(fd)?;
        get(fd.as_raw_fd())?;
        let key = terminal_key(fd.as_raw_fd())?;
        Ok(Self {
            fd: Arc::new(fd),
            key,
        })
    }

    /// Whether both handles name the same terminal in the inherited-terminal profile.
    pub fn same_terminal(&self, other: &Self) -> bool {
        self.key == other.key
    }

    /// Whether the calling process belongs to this terminal's foreground process group.
    pub fn is_foreground(&self) -> bool {
        // SAFETY: the owned descriptor remains open throughout these calls.
        unsafe { libc::tcgetpgrp(self.fd.as_raw_fd()) == libc::getpgrp() }
    }

    /// The window size, zero where unknown.
    pub fn size(&self) -> WindowSize {
        window_size(self.fd.as_raw_fd())
    }

    /// Shares raw mode with other leases on this terminal until this lease is released.
    pub fn raw(&self) -> io::Result<RawMode> {
        RawMode::acquire(self.key, self.fd.as_fd().try_clone_to_owned()?)
    }
}

#[cfg(not(target_os = "macos"))]
fn endpoint(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    fd.try_clone_to_owned()
}

#[cfg(target_os = "macos")]
fn endpoint(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    use std::{ffi::CStr, os::unix::fs::MetadataExt};
    let owned = fd.try_clone_to_owned()?;
    let alias = std::fs::metadata("/dev/tty")?.rdev() as libc::dev_t;
    if rdev(owned.as_raw_fd())? != alias {
        return Ok(owned);
    }
    // XNU's /dev/tty resolves the process's current controlling terminal on every ioctl.
    // Reopen the real device instead of retaining that changing alias.
    unsafe extern "C" {
        fn devname_r(
            dev: libc::dev_t,
            mode: libc::mode_t,
            buf: *mut libc::c_char,
            len: libc::c_int,
        ) -> *mut libc::c_char;
    }
    // SAFETY: F_GETFL reads flags from our live descriptor.
    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    for _ in 0..3 {
        let device = controlling_device()?;
        let mut name = [0 as libc::c_char; 1024];
        // SAFETY: devname_r writes at most name.len() bytes into our buffer.
        if unsafe { devname_r(device, libc::S_IFCHR, name.as_mut_ptr(), name.len() as _) }.is_null()
        {
            return Err(io::Error::other("cannot name the controlling terminal"));
        }
        // SAFETY: a successful devname_r produces a NUL-terminated name.
        let name = unsafe { CStr::from_ptr(name.as_ptr()) };
        let path = std::ffi::CString::new([b"/dev/".as_slice(), name.to_bytes()].concat()).unwrap();
        // SAFETY: the path is terminated; open creates a new owned descriptor.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                (flags & libc::O_ACCMODE) | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open returned a new descriptor owned by us.
        let canonical = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        if rdev(canonical.as_raw_fd())? == device && controlling_device()? == device {
            return Ok(canonical);
        }
    }
    Err(io::Error::other(
        "controlling terminal changed while opening it",
    ))
}

#[cfg(target_os = "macos")]
fn controlling_device() -> io::Result<libc::dev_t> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    // SAFETY: proc_pidinfo writes at most size bytes into info.
    let read = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as _,
        )
    };
    if read != size as libc::c_int {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the complete structure was returned.
    let device = unsafe { info.assume_init() }.e_tdev as libc::dev_t;
    if device == !0 {
        return Err(io::Error::from_raw_os_error(libc::ENXIO));
    }
    Ok(device)
}

#[cfg(target_os = "linux")]
fn terminal_key(fd: RawFd) -> io::Result<TerminalKey> {
    let mut device: libc::c_uint = 0;
    // SAFETY: TIOCGDEV writes an unsigned device number, for the actual tty behind aliases.
    if unsafe { libc::ioctl(fd, libc::TIOCGDEV, &mut device) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TerminalKey(device as libc::dev_t))
}

#[cfg(not(target_os = "linux"))]
fn terminal_key(fd: RawFd) -> io::Result<TerminalKey> {
    rdev(fd).map(TerminalKey)
}

#[cfg(not(target_os = "linux"))]
fn rdev(fd: RawFd) -> io::Result<libc::dev_t> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat fills stat when it succeeds.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat initialized the complete structure.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return Err(io::Error::from_raw_os_error(libc::ENOTTY));
    }
    Ok(stat.st_rdev)
}

fn window_size(fd: RawFd) -> WindowSize {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ fills a winsize.
    unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    WindowSize {
        rows: ws.ws_row,
        cols: ws.ws_col,
        xpixel: ws.ws_xpixel,
        ypixel: ws.ws_ypixel,
    }
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::default);

#[derive(Default)]
struct Registry {
    state: Mutex<State>,
    changed: Condvar,
}
#[derive(Default)]
struct State {
    entries: HashMap<TerminalKey, Entry>,
    generation: u64,
    suspended: bool,
}
enum Entry {
    // The tombstone stays visible until the out-of-lock syscall and descriptor close finish.
    Transition(u64),
    Active(Active),
}
struct Active {
    generation: u64,
    leases: usize,
    fd: OwnedFd,
    saved: libc::termios,
    raw: libc::termios,
    // A failed settings change can leave an unknown mode, which the next request retries.
    cooked: Option<bool>,
}
impl Registry {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn wait<'a>(&self, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        #[cfg(test)]
        tests::WAITS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Attempt the latest requested mode before publishing; a failed change remains unknown
    /// so a later request retries it. Syscalls and the owned descriptor's destructor run
    /// outside the lock while the tombstone excludes competing transitions on this terminal.
    fn publish(&self, key: TerminalKey, mut active: Active, entering: bool) -> io::Result<()> {
        let mut error = None;
        let mut attempted = None;
        loop {
            let mut state = self.lock();
            let cooked = state.suspended;
            if active.cooked == Some(cooked) || attempted == Some(cooked) {
                state.entries.insert(key, Entry::Active(active));
                self.changed.notify_all();
                return error.map_or(Ok(()), Err);
            }
            drop(state);
            let result = if cooked {
                set(active.fd.as_raw_fd(), &active.saved, libc::TCSADRAIN)
            } else {
                set(active.fd.as_raw_fd(), &active.raw, libc::TCSANOW)
            };
            attempted = Some(cooked);
            match result {
                Ok(()) => active.cooked = Some(cooked),
                Err(err) => {
                    if entering {
                        let _ = set(active.fd.as_raw_fd(), &active.saved, libc::TCSADRAIN);
                        self.retire(key, active);
                        return Err(err);
                    }
                    active.cooked = None;
                    error.get_or_insert(err);
                }
            }
        }
    }

    fn retire(&self, key: TerminalKey, active: Active) {
        let generation = active.generation;
        drop(active);
        let mut state = self.lock();
        if matches!(state.entries.get(&key), Some(Entry::Transition(found)) if *found == generation)
        {
            state.entries.remove(&key);
        }
        self.changed.notify_all();
    }
}

/// One raw-mode lease. Releasing it twice is harmless; only the last lease restores the
/// settings captured by the first. Cancellation and unwinding release it through Drop.
pub struct RawMode(Option<(TerminalKey, u64)>);

impl RawMode {
    fn acquire(key: TerminalKey, fd: OwnedFd) -> io::Result<Self> {
        let generation = loop {
            let mut state = REGISTRY.lock();
            let cooked = state.suspended;
            match state.entries.get_mut(&key) {
                Some(Entry::Active(active)) => {
                    active.leases += 1;
                    let generation = active.generation;
                    if active.cooked != Some(cooked) {
                        let Entry::Active(active) = state
                            .entries
                            .insert(key, Entry::Transition(generation))
                            .unwrap()
                        else {
                            unreachable!()
                        };
                        drop(state);
                        let mut lease = Self(Some((key, generation)));
                        if let Err(err) = REGISTRY.publish(key, active, false) {
                            // Roll back only this reservation, retaining the original capture
                            // and every sibling's generation, even when the mode is unknown.
                            let _ = lease.restore();
                            return Err(err);
                        }
                        return Ok(lease);
                    }
                    drop(state);
                    return Ok(Self(Some((key, generation))));
                }
                Some(Entry::Transition(_)) => {
                    drop(REGISTRY.wait(state));
                }
                None => {
                    state.generation += 1;
                    let generation = state.generation;
                    state.entries.insert(key, Entry::Transition(generation));
                    break generation;
                }
            }
        };
        let saved = match get(fd.as_raw_fd()) {
            Ok(saved) => saved,
            Err(err) => {
                // Close before removing the transition, just as on the normal retirement path.
                drop(fd);
                let mut state = REGISTRY.lock();
                state.entries.remove(&key);
                REGISTRY.changed.notify_all();
                return Err(err);
            }
        };
        let mut raw = saved;
        // SAFETY: cfmakeraw changes a valid termios.
        unsafe { libc::cfmakeraw(&mut raw) };
        REGISTRY.publish(
            key,
            Active {
                generation,
                leases: 1,
                fd,
                saved,
                raw,
                cooked: Some(true),
            },
            true,
        )?;
        Ok(Self(Some((key, generation))))
    }

    #[cfg(test)]
    fn enter(fd: RawFd) -> io::Result<Self> {
        // SAFETY: the test retains its PTY descriptor for the duration of this call.
        Terminal::duplicate(unsafe { BorrowedFd::borrow_raw(fd) })?.raw()
    }

    /// Releases this lease. Siblings remain in raw mode; the last lease restores the
    /// original settings and reports any restoration error.
    pub fn restore(&mut self) -> io::Result<()> {
        let Some((key, generation)) = self.0.take() else {
            return Ok(());
        };
        let active = loop {
            let mut state = REGISTRY.lock();
            match state.entries.get_mut(&key) {
                Some(Entry::Transition(found)) if *found == generation => {
                    drop(REGISTRY.wait(state));
                }
                Some(Entry::Active(active)) if active.generation == generation => {
                    active.leases -= 1;
                    if active.leases != 0 {
                        return Ok(());
                    }
                    let Entry::Active(active) = state
                        .entries
                        .insert(key, Entry::Transition(generation))
                        .unwrap()
                    else {
                        unreachable!()
                    };
                    break active;
                }
                _ => return Ok(()),
            }
        };
        let result = set(active.fd.as_raw_fd(), &active.saved, libc::TCSADRAIN);
        REGISTRY.retire(key, active);
        result
    }
}
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Restores active terminals before the host process stops, retaining their lease counts.
pub fn suspend() {
    change_mode(true);
}

/// Reapplies raw mode after the host process continues.
pub fn resume() {
    change_mode(false);
}

fn change_mode(cooked: bool) {
    let mut state = REGISTRY.lock();
    state.suspended = cooked;
    let keys: Vec<_> = state.entries.keys().copied().collect();
    drop(state);
    for key in keys {
        let active = loop {
            let mut state = REGISTRY.lock();
            match state.entries.get(&key) {
                Some(Entry::Transition(_)) => {
                    drop(REGISTRY.wait(state));
                }
                Some(Entry::Active(active)) => {
                    let generation = active.generation;
                    let Entry::Active(active) = state
                        .entries
                        .insert(key, Entry::Transition(generation))
                        .unwrap()
                    else {
                        unreachable!()
                    };
                    break Some(active);
                }
                _ => break None,
            }
        };
        if let Some(active) = active {
            let _ = REGISTRY.publish(key, active, false);
        }
    }
}

fn get(fd: RawFd) -> io::Result<libc::termios> {
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr fills termios when it succeeds.
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call initialized termios.
    Ok(unsafe { termios.assume_init() })
}
fn set(fd: RawFd, termios: &libc::termios, when: libc::c_int) -> io::Result<()> {
    #[cfg(test)]
    {
        let hook = tests::SET_HOOK.lock().unwrap().take();
        if let Some(hook) = hook {
            hook()?;
        }
    }
    loop {
        // SAFETY: tcsetattr reads a valid termios from a live owned descriptor.
        if unsafe { libc::tcsetattr(fd, when, termios) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    type SetHook = Box<dyn FnOnce() -> io::Result<()> + Send>;
    pub(super) static SET_HOOK: Mutex<Option<SetHook>> = Mutex::new(None);
    pub(super) static WAITS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// Process-wide suspend/resume must not affect unrelated parallel host tests.
    fn isolated(name: &str) -> bool {
        const CHILD: &str = "WASIX_TERMINAL_TEST";
        if std::env::var(CHILD).as_deref() == Ok(name) {
            return true;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("terminal::tests::{name}"),
                "--nocapture",
            ])
            .env(CHILD, name)
            .status()
            .unwrap();
        assert!(status.success(), "terminal subprocess failed: {status}");
        false
    }

    /// A pseudo-terminal pair: its slave stands for the user's terminal.
    struct Pty {
        master: RawFd,
        slave: RawFd,
    }

    impl Pty {
        fn open() -> Self {
            let (mut master, mut slave) = (0, 0);
            // SAFETY: `openpty` fills both descriptors when it succeeds.
            let ret = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(ret, 0, "{}", io::Error::last_os_error());
            Self { master, slave }
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            // SAFETY: the pair's own descriptors.
            unsafe {
                libc::close(self.master);
                libc::close(self.slave);
            }
        }
    }

    fn same(a: &libc::termios, b: &libc::termios) -> bool {
        (a.c_iflag, a.c_oflag, a.c_cflag, a.c_lflag, a.c_cc)
            == (b.c_iflag, b.c_oflag, b.c_cflag, b.c_lflag, b.c_cc)
    }

    fn is_raw(termios: &libc::termios) -> bool {
        termios.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG) == 0
            && termios.c_oflag & libc::OPOST == 0
    }

    /// Normal completion, explicit job control and unwinding release the terminal.
    #[test]
    fn the_terminal_is_restored_on_every_way_out() {
        if !isolated("the_terminal_is_restored_on_every_way_out") {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        assert!(!is_raw(&cooked));

        let raw = RawMode::enter(pty.slave).unwrap();
        assert!(is_raw(&get(pty.slave).unwrap()));
        suspend();
        assert!(same(&get(pty.slave).unwrap(), &cooked), "stopped: restored");
        resume();
        assert!(is_raw(&get(pty.slave).unwrap()), "continued: raw again");
        drop(raw);
        assert!(same(&get(pty.slave).unwrap(), &cooked), "dropped: restored");

        // Unwinding through the scope releases its owned lease.
        // The former process-wide before-report hook is preserved as a reference fixture.
        let panicked = std::panic::catch_unwind(|| {
            let _raw = RawMode::enter(pty.slave).unwrap();
            assert!(is_raw(&get(pty.slave).unwrap()));
            panic!("the panic path");
        });
        assert!(panicked.is_err());
        assert!(same(&get(pty.slave).unwrap(), &cooked), "unwound: restored");

        let raw = RawMode::enter(pty.slave).unwrap();
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "a later run can use raw mode"
        );
        drop(raw);
        assert!(same(&get(pty.slave).unwrap(), &cooked));
    }

    #[test]
    fn suspend_intent_survives_an_empty_registry_and_last_lease_retirement() {
        if !isolated("suspend_intent_survives_an_empty_registry_and_last_lease_retirement") {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        suspend();
        let raw = RawMode::enter(pty.slave).unwrap();
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "suspended before first lease"
        );
        resume();
        assert!(is_raw(&get(pty.slave).unwrap()));
        suspend();
        drop(raw);
        let replacement = RawMode::enter(pty.slave).unwrap();
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "still suspended after last release"
        );
        resume();
        assert!(is_raw(&get(pty.slave).unwrap()));
        drop(replacement);
        assert!(same(&get(pty.slave).unwrap(), &cooked));
    }

    #[test]
    fn failed_suspend_and_resume_are_retried_on_the_next_request() {
        if !isolated("failed_suspend_and_resume_are_retried_on_the_next_request") {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let raw = RawMode::enter(pty.slave).unwrap();
        let fail_next_set = || {
            *SET_HOOK.lock().unwrap() = Some(Box::new(|| {
                assert!(
                    REGISTRY.state.try_lock().is_ok(),
                    "settings syscall outside registry lock"
                );
                Err(io::Error::from_raw_os_error(libc::EIO))
            }));
        };
        fail_next_set();
        suspend();
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "failed suspend did not retry in a loop"
        );
        suspend();
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "same suspend request retries"
        );
        fail_next_set();
        resume();
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "failed resume did not retry in a loop"
        );
        resume();
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "same resume request retries"
        );
        drop(raw);
        assert!(same(&get(pty.slave).unwrap(), &cooked));
    }

    #[test]
    fn acquiring_a_shared_lease_retries_a_failed_resume_without_recapturing_settings() {
        if !isolated(
            "acquiring_a_shared_lease_retries_a_failed_resume_without_recapturing_settings",
        ) {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let first = RawMode::enter(pty.slave).unwrap();
        suspend();
        // Another host may change settings while stopped. They must not replace the first
        // lease's original capture when a failed resume is retried by a joining run.
        let mut changed = cooked;
        changed.c_lflag ^= libc::ECHO;
        set(pty.slave, &changed, libc::TCSANOW).unwrap();
        *SET_HOOK.lock().unwrap() = Some(Box::new(|| {
            assert!(REGISTRY.state.try_lock().is_ok());
            Err(io::Error::from_raw_os_error(libc::EIO))
        }));
        resume();
        assert!(same(&get(pty.slave).unwrap(), &changed));
        let joining = RawMode::enter(pty.slave).unwrap();
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "joining run retried raw mode"
        );
        drop(first);
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "joining run retains its lease"
        );
        drop(joining);
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "first capture restored"
        );
    }

    #[test]
    fn a_failed_shared_acquisition_rolls_back_only_its_new_lease() {
        if !isolated("a_failed_shared_acquisition_rolls_back_only_its_new_lease") {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let first = RawMode::enter(pty.slave).unwrap();
        let sibling = RawMode::enter(pty.slave).unwrap();
        suspend();
        let fail_next_set = || {
            *SET_HOOK.lock().unwrap() = Some(Box::new(|| {
                assert!(REGISTRY.state.try_lock().is_ok());
                Err(io::Error::from_raw_os_error(libc::EIO))
            }));
        };
        fail_next_set();
        resume();
        assert!(same(&get(pty.slave).unwrap(), &cooked));
        fail_next_set();
        let error = match RawMode::enter(pty.slave) {
            Ok(_) => panic!("joining a terminal with a failed mode retry must fail"),
            Err(error) => error,
        };
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        // Make last-owner restoration observable even though the failed calls left the
        // terminal cooked. A leaked reservation or retired old entry leaves this raw.
        let mut raw = cooked;
        // SAFETY: cfmakeraw changes only the initialized termios flags.
        unsafe { libc::cfmakeraw(&mut raw) };
        set(pty.slave, &raw, libc::TCSANOW).unwrap();
        drop(first);
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "original sibling still owns the terminal"
        );
        drop(sibling);
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "no leaked joining lease or lost original capture"
        );
    }

    #[test]
    fn a_new_capture_waits_for_the_last_restore_to_finish() {
        if !isolated("a_new_capture_waits_for_the_last_restore_to_finish") {
            return;
        }
        use std::{
            sync::{atomic::Ordering, mpsc},
            time::{Duration, Instant},
        };
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let terminal = Terminal::duplicate(unsafe { BorrowedFd::borrow_raw(pty.slave) }).unwrap();
        let first = terminal.raw().unwrap();
        let (restoring, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *SET_HOOK.lock().unwrap() = Some(Box::new(move || {
            assert!(
                REGISTRY.state.try_lock().is_ok(),
                "restoration outside registry lock"
            );
            restoring.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok(())
        }));
        let last_drop = std::thread::spawn(move || drop(first));
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let waits = WAITS.load(Ordering::SeqCst);
        let (acquired, new_lease) = mpsc::channel();
        let acquisition =
            std::thread::spawn(move || acquired.send(terminal.raw().unwrap()).unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while WAITS.load(Ordering::SeqCst) == waits && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(
            WAITS.load(Ordering::SeqCst) > waits,
            "new capture reached the transition wait"
        );
        assert!(matches!(
            new_lease.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "last restoration is still blocked"
        );
        release.send(()).unwrap();
        last_drop.join().unwrap();
        let raw = new_lease.recv_timeout(Duration::from_secs(5)).unwrap();
        acquisition.join().unwrap();
        assert!(is_raw(&get(pty.slave).unwrap()));
        drop(raw);
        assert!(
            same(&get(pty.slave).unwrap(), &cooked),
            "new capture saved restored settings"
        );
    }

    #[test]
    fn sibling_leases_share_original_settings_and_restore_only_once() {
        if !isolated("sibling_leases_share_original_settings_and_restore_only_once") {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let mut first = RawMode::enter(pty.slave).unwrap();
        let second = RawMode::enter(pty.slave).unwrap();
        first.restore().unwrap();
        first.restore().unwrap();
        drop(first);
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "a sibling still owns raw mode"
        );
        drop(second);
        assert!(same(&get(pty.slave).unwrap(), &cooked));

        let first = RawMode::enter(pty.slave).unwrap();
        let second = RawMode::enter(pty.slave).unwrap();
        let panicked = std::panic::catch_unwind(move || {
            let _failed_run = second;
            panic!("shared panic path");
        });
        assert!(panicked.is_err());
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "unwinding released only the failed run"
        );
        drop(first);
        assert!(same(&get(pty.slave).unwrap(), &cooked));
    }

    #[test]
    fn caught_panic_retains_raw_mode_through_cleanup_without_cooking_a_sibling() {
        if !isolated("caught_panic_retains_raw_mode_through_cleanup_without_cooking_a_sibling") {
            return;
        }
        use std::cell::Cell;
        struct Cleanup<'a> {
            fd: RawFd,
            observed_raw: &'a Cell<Option<bool>>,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                self.observed_raw
                    .set(Some(get(self.fd).is_ok_and(|settings| is_raw(&settings))));
            }
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let sibling = RawMode::enter(pty.slave).unwrap();
        let failed_run = RawMode::enter(pty.slave).unwrap();
        let cleanup_mode = Cell::new(None);
        let cleanup = Cleanup {
            fd: pty.slave,
            observed_raw: &cleanup_mode,
        };
        let panicked = std::panic::catch_unwind(|| panic!("caught guest panic"));
        assert!(panicked.is_err());
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "catching did not change retained leases"
        );
        drop(cleanup);
        assert_eq!(
            cleanup_mode.get(),
            Some(true),
            "raw lease retained through cleanup"
        );
        drop(failed_run);
        assert!(
            is_raw(&get(pty.slave).unwrap()),
            "retiring the failed run leaves its sibling raw"
        );
        drop(sibling);
        assert!(same(&get(pty.slave).unwrap(), &cooked));
    }

    #[test]
    fn an_unwound_run_restores_its_terminal_without_changing_another_terminal() {
        if !isolated("an_unwound_run_restores_its_terminal_without_changing_another_terminal") {
            return;
        }
        let first = Pty::open();
        let second = Pty::open();
        let cooked = get(first.slave).unwrap();
        let other_cooked = get(second.slave).unwrap();
        let sibling = RawMode::enter(first.slave).unwrap();
        let failed_run = RawMode::enter(second.slave).unwrap();
        let panicked = std::panic::catch_unwind(move || {
            let _owned = failed_run;
            panic!("unwound guest panic");
        });
        assert!(panicked.is_err());
        assert!(same(&get(second.slave).unwrap(), &other_cooked));
        assert!(
            is_raw(&get(first.slave).unwrap()),
            "unrelated terminal remains raw"
        );
        drop(sibling);
        assert!(same(&get(first.slave).unwrap(), &cooked));
    }

    #[test]
    fn an_unrelated_joined_thread_panic_does_not_change_live_terminals() {
        if !isolated("an_unrelated_joined_thread_panic_does_not_change_live_terminals") {
            return;
        }
        let first = Pty::open();
        let second = Pty::open();
        let cooked = get(first.slave).unwrap();
        let other_cooked = get(second.slave).unwrap();
        let a = RawMode::enter(first.slave).unwrap();
        let b = RawMode::enter(second.slave).unwrap();
        assert!(
            std::thread::spawn(|| panic!("unrelated host thread"))
                .join()
                .is_err()
        );
        assert!(is_raw(&get(first.slave).unwrap()));
        assert!(is_raw(&get(second.slave).unwrap()));
        drop(a);
        assert!(same(&get(first.slave).unwrap(), &cooked));
        assert!(is_raw(&get(second.slave).unwrap()));
        drop(b);
        assert!(same(&get(second.slave).unwrap(), &other_cooked));
    }

    #[test]
    fn unrelated_terminals_do_not_restore_each_other() {
        if !isolated("unrelated_terminals_do_not_restore_each_other") {
            return;
        }
        let first = Pty::open();
        let second = Pty::open();
        let cooked = get(first.slave).unwrap();
        let other_cooked = get(second.slave).unwrap();
        let a = RawMode::enter(first.slave).unwrap();
        let b = RawMode::enter(second.slave).unwrap();
        drop(a);
        assert!(same(&get(first.slave).unwrap(), &cooked));
        assert!(is_raw(&get(second.slave).unwrap()));
        suspend();
        assert!(same(&get(second.slave).unwrap(), &other_cooked));
        resume();
        assert!(is_raw(&get(second.slave).unwrap()));
        drop(b);
        assert!(same(&get(second.slave).unwrap(), &other_cooked));
    }

    #[test]
    fn restoring_uses_the_owned_endpoint_after_the_callers_fd_is_replaced() {
        if !isolated("restoring_uses_the_owned_endpoint_after_the_callers_fd_is_replaced") {
            return;
        }
        let first = Pty::open();
        let second = Pty::open();
        let cooked = get(first.slave).unwrap();
        // SAFETY: duplicate returns a newly owned descriptor.
        let fd = unsafe { libc::dup(first.slave) };
        assert!(fd >= 0);
        let raw = RawMode::enter(fd).unwrap();
        let other_cooked = get(second.slave).unwrap();
        // SAFETY: replace only the test's duplicate with another live descriptor.
        assert_eq!(unsafe { libc::dup2(second.slave, fd) }, fd);
        drop(raw);
        assert!(same(&get(first.slave).unwrap(), &cooked));
        assert!(same(&get(second.slave).unwrap(), &other_cooked));
        // SAFETY: the test owns this duplicate.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn controlling_terminal_aliases_share_one_lease_set() {
        if !isolated("controlling_terminal_aliases_share_one_lease_set") {
            return;
        }
        use std::os::fd::AsFd;
        // This isolated process may establish its own controlling terminal.
        assert!(unsafe { libc::setsid() } >= 0);
        let pty = Pty::open();
        // SAFETY: give this new session its own PTY slave as the controlling terminal.
        assert_eq!(
            unsafe { libc::ioctl(pty.slave, libc::TIOCSCTTY as _, 0) },
            0
        );
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .unwrap();
        let direct = Terminal::duplicate(unsafe { BorrowedFd::borrow_raw(pty.slave) }).unwrap();
        let alias = Terminal::duplicate(tty.as_fd()).unwrap();
        assert!(direct.same_terminal(&alias));
        let cooked = get(pty.slave).unwrap();
        let first = alias.raw().unwrap();
        let second = direct.raw().unwrap();
        drop(first);
        assert!(is_raw(&get(pty.slave).unwrap()));
        drop(second);
        assert!(same(&get(pty.slave).unwrap(), &cooked));
        // Avoid a controlling-terminal hangup when the PTY master closes below.
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    }

    #[test]
    fn concurrent_last_release_and_new_capture_preserve_original_settings() {
        if !isolated("concurrent_last_release_and_new_capture_preserve_original_settings") {
            return;
        }
        let pty = Pty::open();
        let cooked = get(pty.slave).unwrap();
        let terminal = Terminal::duplicate(unsafe { BorrowedFd::borrow_raw(pty.slave) }).unwrap();
        for _ in 0..200 {
            let first = terminal.raw().unwrap();
            let peer = terminal.clone();
            let gate = Arc::new(std::sync::Barrier::new(2));
            let peer_gate = gate.clone();
            let thread = std::thread::spawn(move || {
                peer_gate.wait();
                let raw = peer.raw().unwrap();
                assert!(is_raw(&get(peer.fd.as_raw_fd()).unwrap()));
                drop(raw);
            });
            gate.wait();
            drop(first);
            thread.join().unwrap();
            assert!(same(&get(pty.slave).unwrap(), &cooked));
        }
    }

    /// Raw libc reference: XNU defers canonical reinput until a read-availability query.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_empty_pty_reinput_query_preserves_termios_snapshot() {
        let pty = Pty::open();
        let snapshot = || {
            let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: tcgetattr writes this live PTY's termios on success.
            assert_eq!(
                unsafe { libc::tcgetattr(pty.slave, termios.as_mut_ptr()) },
                0,
                "{}",
                io::Error::last_os_error()
            );
            // SAFETY: the successful native call initialized the structure.
            unsafe { termios.assume_init() }
        };
        let fields = |t: &libc::termios| {
            (
                t.c_iflag, t.c_oflag, t.c_cflag, t.c_lflag, t.c_cc, t.c_ispeed, t.c_ospeed,
            )
        };
        let cooked = snapshot();
        eprintln!("native termios fields (iflag, oflag, cflag, lflag, cc, ispeed, ospeed)");
        eprintln!("native empty PTY initial={:x?}", fields(&cooked));
        assert_ne!(
            cooked.c_lflag,
            cooked.c_lflag | libc::PENDIN,
            "a fresh empty PTY has no pending reinput"
        );
        let mut raw = cooked;
        // SAFETY: cfmakeraw changes the initialized local termios.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: the descriptor stays live and raw is a valid termios.
        assert_eq!(
            unsafe { libc::tcsetattr(pty.slave, libc::TCSANOW, &raw) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let actual_raw = snapshot();
        eprintln!("native empty PTY raw={:x?}", fields(&actual_raw));
        assert!(is_raw(&actual_raw));
        // SAFETY: restore through libc alone; no registry or lease is involved.
        assert_eq!(
            unsafe { libc::tcsetattr(pty.slave, libc::TCSADRAIN, &cooked) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let restored = snapshot();
        eprintln!("native empty PTY restored={:x?}", fields(&restored));
        eprintln!(
            "native restored flag XORs={:x?}; cc actual/expected={:x?}/{:x?}; speeds actual/expected={:?}/{:?}",
            (
                restored.c_iflag ^ cooked.c_iflag,
                restored.c_oflag ^ cooked.c_oflag,
                restored.c_cflag ^ cooked.c_cflag,
                restored.c_lflag ^ cooked.c_lflag,
            ),
            restored.c_cc,
            cooked.c_cc,
            (restored.c_ispeed, restored.c_ospeed),
            (cooked.c_ispeed, cooked.c_ospeed),
        );
        let mut pending = cooked;
        pending.c_lflag |= libc::PENDIN;
        assert_eq!(
            fields(&restored),
            fields(&pending),
            "native raw-to-canonical restoration differs only by PENDIN"
        );
        let mut available: libc::c_int = -1;
        // SAFETY: FIONREAD writes one int; this test has queued no PTY input.
        assert_eq!(
            unsafe { libc::ioctl(pty.slave, libc::FIONREAD, &mut available) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        assert_eq!(available, 0, "the private PTY is empty");
        let settled = snapshot();
        eprintln!("native empty PTY after FIONREAD={:x?}", fields(&settled));
        assert_eq!(
            fields(&settled),
            fields(&cooked),
            "FIONREAD completes empty canonical reinput without a read or flush"
        );
    }
}
