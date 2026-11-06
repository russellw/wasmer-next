//! The host's console: a terminal whose device is a pair of host byte streams, such as the
//! terminal `wasmer run` was started on, in raw mode. Linux's `hvc0`, the console a hypervisor
//! gives a virtual machine: the host only moves bytes, and everything a terminal does with
//! them is the kernel's.
//!
//! Like getty, [`Kernel::attach_console`] opens it for a new process, which leads a session
//! and acquires it as its controlling terminal.

use std::{
    any::Any,
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use wasixv2_abi::{OpenFlags, Signal, Winsize};
use wasixv2_host::{ByteSink, ByteSource, WindowSize};
use wasixv2_syscalls::{Caller, Errno, Fd, SysErr, TaskId};
use wasixv2_vfs::{Device, LookupFlags, OpenHow};
use wasixv2_wait::{NoInterrupt, PollMask, WaitQueue, Waiter};

use super::{Driver, Tty, TtyFile};
use crate::{
    Kernel,
    file::{Backing, OpenFile},
    stdio::QueueWaker,
    sync::MutexExt,
};

/// `HVC_MAJOR`: the hypervisor consoles, `/dev/hvc0` first.
pub(crate) const HVC_MAJOR: u32 = 229;
const NAME: &str = "hvc0";

/// How much of the host's input the pump takes at once.
const INPUT_CHUNK: usize = 4096;

/// How long a run's end waits for the console's output to reach the host: `tty_port`'s
/// default `closing_wait` (`drivers/tty/tty_port.c`: `tty_port_init`), 30 seconds.
const CLOSING_WAIT: Duration = Duration::from_secs(30);

/// What end-of-input means for this configured console source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConsoleInputEof {
    /// A disconnected terminal hangs up, preserving the normal console policy.
    #[default]
    Hangup,
    /// A finite embedding input drains and returns EOF without disconnecting output.
    Finite,
}

/// The console's device: the host streams.
pub(crate) struct Console {
    eof_policy: ConsoleInputEof,
    input_ended: AtomicBool,
    input: Arc<dyn ByteSource>,
    output: Arc<dyn ByteSink>,
    /// The input pump waits here: for the source to have input, and for the discipline to
    /// have room for it.
    pump_wait: WaitQueue,
    waker: Waker,
    pumping: AtomicBool,
    /// Where `create_device_nodes` made the console's node, which `attach_console` opens.
    node: Mutex<Option<Vec<u8>>>,
}

impl Console {
    fn new(console: wasixv2_host::Console, eof_policy: ConsoleInputEof) -> Self {
        let pump_wait = WaitQueue::new();
        Self {
            eof_policy,
            input_ended: AtomicBool::new(false),
            input: console.input,
            output: console.output,
            waker: Waker::from(Arc::new(QueueWaker(pump_wait.clone()))),
            pump_wait,
            pumping: AtomicBool::new(false),
            node: Mutex::default(),
        }
    }

    /// Writes all of `data` to the host.
    pub(super) async fn write(&self, data: &[u8]) -> io::Result<()> {
        write_all(self.output.as_ref(), data).await
    }

    pub(super) fn unthrottle(&self) {
        self.pump_wait.wake(PollMask::READABLE);
    }
}

/// One bounded tty write step, including short-writing or failing host sinks.
/// A failed step is never replayed: each successful call advances its suffix.
pub(super) async fn write_all(sink: &dyn ByteSink, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let count = sink.write(data).await?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        data = data
            .get(count..)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    }
    Ok(())
}

fn winsize(size: WindowSize) -> Winsize {
    Winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.xpixel,
        ws_ypixel: size.ypixel,
    }
}

impl Tty {
    pub(super) fn finite_input_ended(&self) -> bool {
        matches!(&self.driver, Driver::Console(console) if console.input_ended.load(Ordering::Acquire))
    }

    fn console(&self) -> &Console {
        match &self.driver {
            Driver::Console(console) => console,
            _ => unreachable!("the console's terminal"),
        }
    }
}

/// Starts the console's input pump, once: the host's input goes through the line discipline
/// as it arrives, whether or not anyone reads, so `^C` interrupts a busy program. It runs on a
/// host thread of its own where the host has them.
fn start_pump(tty: &Arc<Tty>) {
    if tty.console().pumping.swap(true, Ordering::Relaxed) {
        return;
    }
    let weak = Arc::downgrade(tty);
    let start: wasixv2_host::ThreadStart = Box::new(move || Box::pin(pump(weak)));
    let executor = tty.host.executor();
    if executor.spawn_thread(start).is_err() {
        executor.spawn_local(Box::pin(pump(Arc::downgrade(tty))));
    }
}

/// The pump: reads the host's input and hands it to the discipline, holding what does not fit
/// until a reader makes room. The input's end means the terminal went away: a hangup.
async fn pump(tty: Weak<Tty>) {
    let waiter = Waiter::new();
    let _registration = match tty.upgrade() {
        Some(tty) => waiter.register(&tty.console().pump_wait, PollMask::empty()),
        None => return,
    };
    let mut held = Vec::new();
    let mut chunk = vec![0; INPUT_CHUNK];
    loop {
        let Some(live) = tty.upgrade() else { return };
        if held.is_empty() {
            let console = live.console();
            let mut cx = Context::from_waker(&console.waker);
            match console.input.poll_read(&mut cx, &mut chunk) {
                Poll::Ready(Ok(0)) => {
                    if console.eof_policy == ConsoleInputEof::Finite {
                        live.ldisc.lock_or_recover().finish_input();
                        console.input_ended.store(true, Ordering::Release);
                        live.received(super::ldisc::Received {
                            readable: true,
                            ..Default::default()
                        });
                    } else {
                        live.hangup(false);
                    }
                    return;
                }
                Poll::Ready(Err(_)) => {
                    live.hangup(false);
                    return;
                }
                Poll::Ready(Ok(n)) => held.extend_from_slice(&chunk[..n]),
                Poll::Pending => {
                    drop(live);
                    waiter.sleep(&NoInterrupt, None).await;
                    continue;
                }
            }
        }
        let taken = live.receive(&held).await;
        held.drain(..taken);
        if taken == 0 {
            drop(live);
            waiter.sleep(&NoInterrupt, None).await;
        }
    }
}

impl Kernel {
    /// Gives the kernel the host's console, `console`, a terminal (`/dev/hvc0`, device 229:0)
    /// with Linux's default settings and `console.size` as its window size. Processes reach it
    /// through [`Kernel::attach_console`]; [`Kernel::create_device_nodes`] makes its node.
    pub fn with_console(self, console: wasixv2_host::Console) -> Self {
        self.with_console_eof(console, ConsoleInputEof::Hangup)
    }

    /// Configures this source's EOF meaning before console admission. Explicit
    /// hangup and PTY peer closure retain their normal semantics under either policy.
    pub fn with_console_eof(
        mut self,
        console: wasixv2_host::Console,
        eof_policy: ConsoleInputEof,
    ) -> Self {
        let size = winsize(console.size);
        let driver = Driver::Console(Console::new(console, eof_policy));
        let device = Device {
            major: HVC_MAJOR,
            minor: 0,
        };
        let tty = Tty::new(
            device,
            super::ldisc::std_termios(),
            size,
            driver,
            self.jobs.clone(),
            self.host.clone(),
        );
        self.console = Some(Arc::new(tty));
        self
    }

    pub(crate) fn console(&self) -> Option<&Arc<Tty>> {
        self.console.as_ref()
    }

    /// Where the console's node goes in the directory `dir`, made by `create_device_nodes`.
    pub(crate) fn console_node(&self, dir: &[u8]) -> Option<(&'static str, Device)> {
        let console = self.console.as_ref()?;
        let mut path = dir.to_vec();
        if !path.ends_with(b"/") {
            path.push(b'/');
        }
        path.extend_from_slice(NAME.as_bytes());
        *console.console().node.lock_or_recover() = Some(path);
        Some((NAME, console.device()))
    }

    /// Opens the console for the process `task` as getty opens a terminal for a login: the
    /// descriptors `fds` names of 0, 1 and 2 become one open file of it, read-write, replacing
    /// what they were, and a session leader without a controlling terminal acquires it, its
    /// group in the foreground. Starts moving the host's input to the console. Fails with
    /// `ENODEV` without a console, and with `ENOENT` when its node was never made.
    pub async fn attach_console(&self, task: TaskId, fds: [bool; 3]) -> Result<(), Errno> {
        self.attach_console_outputs(task, fds, [None, None, None])
            .await
    }

    /// Attach the same console with optional per-open output sinks. Routed
    /// descriptors keep the console's line discipline, job control and ioctl
    /// identity; dup and fork carry their existing open-file sink identity.
    /// Echo always goes to the configured Console output. Unselected overrides
    /// are ignored. All canonical opens finish before any descriptor changes.
    pub async fn attach_console_outputs(
        &self,
        task: TaskId,
        fds: [bool; 3],
        outputs: [Option<Arc<dyn ByteSink>>; 3],
    ) -> Result<(), Errno> {
        let tty = self.console.as_ref().ok_or(Errno::ENODEV)?;
        let node = tty.console().node.lock_or_recover().clone();
        let node = node.ok_or(Errno::ENOENT)?;
        let memory = crate::process::NoMemory;
        let caller = Caller::new(task, &memory);
        let env = self.task_env(task);
        let how = OpenHow {
            flags: OpenFlags::O_RDWR,
            mode: 0,
            lookup: LookupFlags::follow(),
        };
        let shared: Vec<_> = (0..3)
            .filter(|&fd| fds[fd] && outputs[fd].is_none())
            .collect();
        let mut routes = Vec::new();
        // Preserve the old all-unselected attach's canonical open/acquisition,
        // and one shared open-file description for every default descriptor.
        if !shared.is_empty() || !fds.iter().any(|selected| *selected) {
            routes.push((shared, None));
        }
        for (fd, output) in outputs.into_iter().enumerate() {
            if fds[fd] && output.is_some() {
                routes.push((vec![fd], output));
            }
        }
        let mut prepared: [Option<Arc<OpenFile>>; 3] = [None, None, None];
        let mut unattached = None;
        for (descriptors, output) in routes {
            let file = self.vfs.open(&env.cx(), &env.fs.root, &node, &how).await?;
            let mut backing = self
                .attach(&caller, file, OpenFlags::O_RDWR)
                .await
                .map_err(|error| match error {
                    SysErr::Errno(errno) => errno,
                    _ => Errno::EINTR,
                })?;
            if let Some(output) = output {
                let Backing::Stream(object, _) = &mut backing else {
                    return Err(Errno::ENOTTY);
                };
                let object = Arc::get_mut(object).ok_or(Errno::EIO)?;
                let object: &mut dyn Any = object;
                let file = object.downcast_mut::<TtyFile>().ok_or(Errno::ENOTTY)?;
                if !Arc::ptr_eq(file.tty(), tty) {
                    return Err(Errno::ENOTTY);
                }
                file.console_output = Some(output);
            }
            let file = Arc::new(OpenFile::new(backing, OpenFlags::O_RDWR));
            if descriptors.is_empty() {
                unattached = Some(file.clone());
            }
            for fd in descriptors {
                prepared[fd] = Some(file.clone());
            }
        }
        let pid = self.process(task).pid;
        let replaced: Vec<_> = {
            let files = self.files(task);
            let mut files = files.lock_or_recover();
            prepared
                .into_iter()
                .enumerate()
                .filter_map(|(fd, file)| {
                    file.and_then(|file| files.install_at(Fd(fd as i32), file, false))
                })
                .collect()
        };
        for old in replaced {
            self.closed_by(pid, &old);
        }
        start_pump(tty);
        drop(unattached);
        Ok(())
    }

    /// The console's window changed to `size`: its foreground process group gets SIGWINCH.
    pub fn console_resize(&self, size: WindowSize) {
        if let Some(tty) = &self.console {
            tty.resize(winsize(size));
        }
    }

    /// The console went away, as a terminal whose line drops: it is hung up. Its session's
    /// leader gets SIGHUP and SIGCONT, and the files open on it end.
    pub fn console_hangup(&self) {
        if let Some(tty) = &self.console {
            tty.hangup(false);
        }
    }

    /// Sends `sig` to the console's foreground process group, as its line discipline sends
    /// the signal of `^C` (`kill_pgrp` with `SI_KERNEL`). Returns whether some process has it
    /// pending now. `ESRCH` without a console or a foreground group.
    pub fn console_signal(&self, sig: Signal) -> Result<bool, Errno> {
        let sig = crate::signal::check_signal(sig)?;
        let tty = self.console.as_ref().ok_or(Errno::ESRCH)?;
        let pgrp = tty.pgrp().ok_or(Errno::ESRCH)?.id();
        if tty.jobs.pgrp_groups(pgrp).is_empty() {
            return Err(Errno::ESRCH);
        }
        Ok(tty.jobs.kill_pgrp(pgrp, sig))
    }

    /// Whether `sig` is pending, not yet taken, for a process of the console's foreground
    /// process group.
    pub fn console_signal_pending(&self, sig: Signal) -> bool {
        let Some(pgrp) = self
            .console
            .as_ref()
            .and_then(|tty| tty.pgrp())
            .map(|p| p.id())
        else {
            return false;
        };
        self.jobs
            .pgrp_groups(pgrp)
            .iter()
            .any(|(_, group)| group.is_pending(sig.0))
    }

    /// Waits until what the console holds for the host has reached it: the write under way
    /// and the echoes of input the console received, such as the `^C` whose signal ended the
    /// program, which the input pump writes after it signals, as Linux's line discipline does.
    /// An embedder calls this when a run ends, before it exits, as Linux's `hvc_close` waits
    /// (`drivers/tty/hvc/hvc_console.c`, `tty_wait_until_sent`); the wait is bounded by
    /// `tty_port`'s default closing wait, 30 seconds, for a host that takes nothing. Returns at
    /// once without a console.
    pub async fn console_wait_until_sent(&self) {
        if let Some(tty) = &self.console {
            tty.wait_until_sent(CLOSING_WAIT).await;
        }
    }

    /// Whether the kernel has a console.
    pub fn has_console(&self) -> bool {
        self.console.is_some()
    }
}
