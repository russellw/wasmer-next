//! Native host-terminal policy for a machine's Console.
//!
//! Standard input becomes the console when it is a foreground terminal. The kernel's line
//! discipline handles echo, line editing and signals while the host terminal is raw. Native
//! descriptor ownership and shared raw-mode leases live in the engine-independent host crate.

use crate::{ByteSink, Console, LocalFuture, Stdio, WindowSize};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
    sync::Arc,
};
pub use wasixv2_host::terminal::{RawMode, Terminal, resume, suspend};

/// The foreground terminal inherited on standard input, and its standard-output routing.
#[derive(Clone)]
pub struct HostTerminal {
    terminal: Terminal,
    fds: [bool; 3],
}

impl HostTerminal {
    /// Detects standard input's terminal only when this process is in its foreground group.
    /// Taking a background terminal would stop the process with SIGTTOU.
    pub fn detect() -> Option<Self> {
        let stdin = io::stdin();
        let terminal = Terminal::duplicate(stdin.as_fd()).ok()?;
        if !terminal.is_foreground() {
            return None;
        }
        let on_it = |fd: BorrowedFd<'_>| {
            Terminal::duplicate(fd).is_ok_and(|other| terminal.same_terminal(&other))
        };
        let stdout = io::stdout();
        let stderr = io::stderr();
        let fds = [true, on_it(stdout.as_fd()), on_it(stderr.as_fd())];
        Some(Self { terminal, fds })
    }

    /// Builds the console and identifies which of descriptors 0, 1 and 2 are on it.
    /// Output uses stdout, then stderr, then the controlling terminal, preserving redirected
    /// program output while still displaying the kernel's terminal echo and editing.
    pub fn console(&self, stdio: &Stdio) -> io::Result<(Console, [bool; 3])> {
        let output: Arc<dyn ByteSink> = match self.fds {
            [_, true, _] => stdio.stdout.clone(),
            [_, _, true] => stdio.stderr.clone(),
            _ => Arc::new(TtyWriter::open()?),
        };
        Ok((
            Console {
                input: stdio.stdin.clone(),
                output,
                size: self.size(),
            },
            self.fds,
        ))
    }

    /// Acquires a shared raw-mode lease. The last lease restores the first saved settings.
    pub fn raw(&self) -> io::Result<RawMode> {
        self.terminal.raw()
    }

    pub fn size(&self) -> WindowSize {
        self.terminal.size()
    }
}

/// Console output when the program's standard output and error are redirected.
struct TtyWriter(tokio::sync::Mutex<tokio::fs::File>);
impl TtyWriter {
    fn open() -> io::Result<Self> {
        let tty = std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
        // On macOS this also replaces the changing /dev/tty alias with its owned endpoint.
        let endpoint = Terminal::duplicate(tty.as_fd())?;
        let tty = std::fs::File::from(endpoint.as_fd().try_clone_to_owned()?);
        Ok(Self(tokio::sync::Mutex::new(tokio::fs::File::from_std(
            tty,
        ))))
    }
}
impl ByteSink for TtyWriter {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        use tokio::io::AsyncWriteExt as _;
        Box::pin(async move {
            let mut tty = self.0.lock().await;
            let n = tty.write(data).await?;
            tty.flush().await?;
            Ok(n)
        })
    }
}
