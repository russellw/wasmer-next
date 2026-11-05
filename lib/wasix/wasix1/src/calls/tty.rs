//! `tty_get`, `tty_set`: v1's one terminal state for the process, which wasix-libc reads for
//! `isatty` (per stdio descriptor) and `tcgetattr`, and writes for `tcsetattr`.
//!
//! The state comes from Linux's terminal ioctls on descriptors 0, 1 and 2: `TIOCGWINSZ` says
//! whether each is a terminal and how big the first one is, and `TCGETS`/`TCSETS` on the first
//! one carry `ECHO` and `ICANON`. `tty_set` sends dimensions to that same terminal through
//! `TIOCSWINSZ`, using the shared Linux-size projection. Real zero dimensions remain zero.
//! Without a terminal, those modes are compat state that
//! `tty_set` keeps, starting at v1's defaults, and the size is v1's default 80x25.
//!
//! "Line feeds" is always compat state: wasix-libc derives it from `c_lflag & IGNCR`, an input
//! flag's value tested against the local flags (where it is `NOFLSH`), so it says nothing about
//! the terminal, and v1 never applied it. It round-trips for `tcgetattr` and nothing more.

use std::sync::Mutex;

use wasixv2_abi::{Fd, IoctlRequest, Termios, TermiosLflag, Winsize};
use wasixv2_host::WindowSize;
use wasixv2_syscalls::{Control, SysErr, Syscalls};
use wasmer::RuntimeError;

use crate::{
    abi::{Bool, proc::Tty},
    errno::V1Result,
    shim::{self, Env, Frame},
};

/// The terminal modes v1 knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modes {
    pub echo: bool,
    pub line_buffered: bool,
    pub line_feeds: bool,
}

impl Default for Modes {
    /// v1's defaults.
    fn default() -> Self {
        Self {
            echo: false,
            line_buffered: false,
            line_feeds: true,
        }
    }
}

/// The modes `tty_set` stored for a process without a terminal.
#[derive(Debug, Default)]
pub struct State {
    modes: Mutex<Modes>,
}

impl State {
    pub(crate) fn fork(&self) -> Self {
        Self {
            modes: Mutex::new(*self.modes.lock().unwrap()),
        }
    }
}

const DEFAULT_COLS: u32 = 80;
const DEFAULT_ROWS: u32 = 25;
const DEFAULT_WIDTH: u32 = 800;
const DEFAULT_HEIGHT: u32 = 600;

fn bool(value: bool) -> Bool {
    if value { Bool::TRUE } else { Bool::FALSE }
}

/// Which of the stdio descriptors are terminals, and the window size of the first that is.
async fn stdio<S: Syscalls + Control + 'static>(
    frame: &Frame<'_, S>,
) -> V1Result<([bool; 3], Option<(Fd, Winsize)>)> {
    let mut ttys = [false; 3];
    let mut first = None;
    for fd in 0..3 {
        let ws = frame.mem.alloc_mut::<Winsize>()?;
        match frame
            .syscalls
            .ioctl(&frame.caller(), Fd(fd), IoctlRequest::TIOCGWINSZ, ws.addr())
            .await
        {
            Ok(_) => {
                ttys[fd as usize] = true;
                first.get_or_insert((Fd(fd), frame.mem.take(ws)));
            }
            Err(SysErr::Errno(_)) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok((ttys, first))
}

async fn tcgets<S: Syscalls + Control + 'static>(
    frame: &Frame<'_, S>,
    fd: Fd,
) -> V1Result<Termios> {
    let termios = frame.mem.alloc_mut::<Termios>()?;
    frame
        .syscalls
        .ioctl(&frame.caller(), fd, IoctlRequest::TCGETS, termios.addr())
        .await?;
    Ok(frame.mem.take(termios))
}

/// The modes of a terminal in `termios`, with the compat state's `line_feeds`.
fn modes_of(termios: &Termios, line_feeds: bool) -> Modes {
    Modes {
        echo: termios.c_lflag.0 & TermiosLflag::ECHO.0 != 0,
        line_buffered: termios.c_lflag.0 & TermiosLflag::ICANON.0 != 0,
        line_feeds,
    }
}

fn set_flag(bits: &mut u32, flag: u32, on: bool) {
    if on {
        *bits |= flag;
    } else {
        *bits &= !flag;
    }
}

/// `modes` on a terminal's `termios`; line feeds are not the terminal's.
fn apply(termios: &mut Termios, modes: Modes) {
    set_flag(&mut termios.c_lflag.0, TermiosLflag::ECHO.0, modes.echo);
    set_flag(
        &mut termios.c_lflag.0,
        TermiosLflag::ICANON.0,
        modes.line_buffered,
    );
}

/// The v1 terminal state for `ttys`, the first terminal's window size, and `modes`.
fn tty_state(ttys: [bool; 3], winsize: Option<&Winsize>, modes: Modes) -> Tty {
    let (cols, rows, width, height) = match winsize {
        Some(ws) => (
            u32::from(ws.ws_col),
            u32::from(ws.ws_row),
            u32::from(ws.ws_xpixel),
            u32::from(ws.ws_ypixel),
        ),
        None => (DEFAULT_COLS, DEFAULT_ROWS, DEFAULT_WIDTH, DEFAULT_HEIGHT),
    };
    Tty {
        cols,
        rows,
        width,
        height,
        stdin_tty: bool(ttys[0]),
        stdout_tty: bool(ttys[1]),
        stderr_tty: bool(ttys[2]),
        echo: bool(modes.echo),
        line_buffered: bool(modes.line_buffered),
        line_feeds: bool(modes.line_feeds),
    }
}

pub(crate) async fn tty_get<S: Syscalls + Control + 'static>(
    env: Env<S>,
    out: i32,
) -> Result<i32, RuntimeError> {
    shim::errno(&env, async |frame| {
        frame.bind_descriptors(&[Fd(0), Fd(1), Fd(2)])?;
        let (ttys, first) = stdio(frame).await?;
        let kept = *frame.proc().await?.proc.tty.modes.lock().unwrap();
        let modes = match &first {
            Some((fd, _)) => modes_of(&tcgets(frame, *fd).await?, kept.line_feeds),
            None => kept,
        };
        let tty = tty_state(ttys, first.as_ref().map(|(_, ws)| ws), modes);
        frame.write(out as u32, &tty).await
    })
    .await
}

pub(crate) async fn tty_set<S: Syscalls + Control + 'static>(
    env: Env<S>,
    state: i32,
) -> Result<i32, RuntimeError> {
    shim::errno(&env, async |frame| {
        frame.bind_descriptors(&[Fd(0), Fd(1), Fd(2)])?;
        let tty: Tty = frame.read(state as u32).await?;
        let modes = Modes {
            echo: tty.echo == Bool::TRUE,
            line_buffered: tty.line_buffered == Bool::TRUE,
            line_feeds: tty.line_feeds == Bool::TRUE,
        };
        let (_, first) = stdio(frame).await?;
        match first {
            Some((fd, _)) => {
                let mut termios = tcgets(frame, fd).await?;
                apply(&mut termios, modes);
                let termios = frame.mem.alloc(&termios)?;
                frame
                    .syscalls
                    .ioctl(&frame.caller(), fd, IoctlRequest::TCSETS, termios.addr())
                    .await?;
                frame
                    .proc()
                    .await?
                    .proc
                    .tty
                    .modes
                    .lock()
                    .unwrap()
                    .line_feeds = modes.line_feeds;
                let size = WindowSize::from_u32(tty.rows, tty.cols, tty.width, tty.height);
                let winsize = Winsize {
                    ws_row: size.rows,
                    ws_col: size.cols,
                    ws_xpixel: size.xpixel,
                    ws_ypixel: size.ypixel,
                };
                let winsize = frame.mem.alloc(&winsize)?;
                frame
                    .syscalls
                    .ioctl(
                        &frame.caller(),
                        fd,
                        IoctlRequest::TIOCSWINSZ,
                        winsize.addr(),
                    )
                    .await?;
            }
            None => *frame.proc().await?.proc.tty.modes.lock().unwrap() = modes,
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use wasixv2_abi::{GuestLayout, TermiosIflag};

    use super::*;

    #[test]
    fn modes_round_trip_through_termios() {
        let mut termios = Termios::ZERO;
        let modes = Modes {
            echo: true,
            line_buffered: false,
            line_feeds: true,
        };
        apply(&mut termios, modes);
        assert_eq!(modes_of(&termios, true), modes);
        apply(&mut termios, Modes::default());
        assert_eq!(modes_of(&termios, true), Modes::default());
    }

    /// "Line feeds" never reaches the terminal: it set `IGNCR`, which makes the terminal drop
    /// every carriage return the user types, whenever libc saw the local flag of that value.
    #[test]
    fn line_feeds_leave_the_terminal_alone() {
        let mut termios = Termios::ZERO;
        for line_feeds in [true, false] {
            let modes = Modes {
                line_feeds,
                ..Modes::default()
            };
            apply(&mut termios, modes);
            assert_eq!(termios.c_iflag.0 & TermiosIflag::IGNCR.0, 0);
        }
        termios.c_iflag.0 |= TermiosIflag::IGNCR.0;
        apply(&mut termios, Modes::default());
        assert_ne!(termios.c_iflag.0 & TermiosIflag::IGNCR.0, 0);
    }

    #[test]
    fn no_terminal_is_v1_defaults() {
        let tty = tty_state([false; 3], None, Modes::default());
        assert_eq!((tty.cols, tty.rows), (80, 25));
        assert_eq!((tty.width, tty.height), (800, 600));
        assert_eq!(tty.stdout_tty, Bool::FALSE);
        assert_eq!(tty.line_feeds, Bool::TRUE);
        let ws = Winsize {
            ws_row: 50,
            ws_col: 132,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let tty = tty_state([false, true, false], Some(&ws), Modes::default());
        assert_eq!((tty.cols, tty.rows, tty.width, tty.height), (132, 50, 0, 0));
        assert_eq!(tty.stdout_tty, Bool::TRUE);
    }

    #[test]
    fn a_real_terminal_preserves_zero_dimensions() {
        let ws = Winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let tty = tty_state([true; 3], Some(&ws), Modes::default());
        assert_eq!((tty.cols, tty.rows, tty.width, tty.height), (0, 0, 0, 0));
        assert_eq!(tty.stdin_tty, Bool::TRUE);
        assert_eq!(tty.stdout_tty, Bool::TRUE);
        assert_eq!(tty.stderr_tty, Bool::TRUE);
    }
}
