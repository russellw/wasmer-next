use std::{
    future::poll_fn,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
    task::{Context, Poll},
};

use wasixv2_syscalls::{CommandEnd, Control};

use super::*;

struct Probe {
    polls: AtomicUsize,
    done: AtomicBool,
    dropped: AtomicBool,
}

impl Probe {
    fn new(done: bool) -> Self {
        Self {
            polls: AtomicUsize::new(0),
            done: AtomicBool::new(done),
            dropped: AtomicBool::new(false),
        }
    }
}

impl VirtualCommand for Probe {
    fn name(&self) -> &str {
        "host-probe"
    }

    fn run<'a>(&'a self, cx: CommandContext<'a>) -> LocalFuture<'a, CommandOutcome> {
        Box::pin(async move {
            struct DropFlag<'a>(&'a AtomicBool);
            impl Drop for DropFlag<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Relaxed);
                }
            }
            let _guard = DropFlag(&self.dropped);
            assert_eq!(cx.args(), &[b"alias".to_vec()]);
            assert_eq!(cx.env(), &[b"A=B".to_vec()]);
            assert_eq!(cx.cwd().await.unwrap(), b"/");
            assert_eq!(cx.credentials().uid, 1);
            poll_fn(|_| {
                self.polls.fetch_add(1, Relaxed);
                if self.done.load(Relaxed) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            let mut bytes = [0; 8];
            let n = cx.read(Fd(0), &mut bytes).await.unwrap();
            cx.write_all(Fd(1), &bytes[..n]).await.unwrap();
            CommandOutcome::Exit(42)
        })
    }
}

fn kernel(commands: Commands, fs: Arc<dyn Filesystem>) -> (Kernel, TaskId, Arc<Capture>) {
    spawn_on(
        Kernel::new(Arc::new(TestHost), fs).with_commands(commands),
        Arc::new(Input(Mutex::new(b"stdin".to_vec()))),
        &[],
        &[],
    )
}

fn image(kernel: &Kernel, task: TaskId, path: &[u8]) -> Result<Image, Errno> {
    block_on(kernel.exec(task, path, vec![b"alias".to_vec()], vec![b"A=B".to_vec()]))
}

#[test]
fn command_identity_and_mode_are_checked_before_dispatch() {
    let cmd = Arc::new(Probe::new(true));
    let mut builder = Commands::builder();
    assert_eq!(
        builder.register("/bad//path", cmd.clone()),
        Err(Errno::EINVAL)
    );
    builder.register("/bin/probe", cmd.clone()).unwrap();
    assert_eq!(
        builder.register("/bin/probe", cmd.clone()),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        builder.register("/bin/probe/child", cmd.clone()),
        Err(Errno::ENOTDIR)
    );
    builder
        .register_spec(
            "/bin/denied",
            CommandSpec {
                command: cmd.clone(),
                mode: 0o700,
                uid: 0,
                gid: 0,
            },
        )
        .unwrap();
    let commands = builder.build();
    let fs = commands.filesystem();
    let (guest, task, output) = kernel(commands, fs.clone());
    assert!(matches!(
        image(&guest, task, b"/bin/denied"),
        Err(Errno::EACCES)
    ));
    let committed = image(&guest, task, b"/bin/probe").unwrap();
    assert!(committed.is_command());
    assert_eq!(
        guest.task_ref(task, |t| t.comm.name().to_vec()),
        b"host-probe"
    );
    assert!(matches!(
        block_on(guest.run_command(task, committed)),
        CommandEnd::Exited(42)
    ));
    assert_eq!(&*output.0.lock_or_recover(), b"stdin");
    let mut foreign = Commands::builder();
    foreign.register("/bin/probe", cmd).unwrap();
    let (guest, task, _) = kernel(foreign.build(), fs);
    assert!(matches!(
        image(&guest, task, b"/bin/probe"),
        Err(Errno::ENOEXEC)
    ));
}

#[test]
fn command_stop_continue_and_kill_choose_signals_before_polling() {
    let cmd = Arc::new(Probe::new(false));
    let mut builder = Commands::builder();
    builder.register("/probe", cmd.clone()).unwrap();
    let commands = builder.build();

    for kill in [false, true] {
        cmd.done.store(false, Relaxed);
        cmd.dropped.store(false, Relaxed);
        cmd.polls.store(0, Relaxed);
        let (guest, task, _) = kernel(commands.clone(), commands.filesystem());
        let mut run = guest.run_command(task, image(&guest, task, b"/probe").unwrap());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(run.as_mut().poll(&mut cx).is_pending());
        assert_eq!(cmd.polls.load(Relaxed), 1);

        guest.kill(task, Signal::SIGSTOP).unwrap();
        cmd.done.store(true, Relaxed);
        assert!(run.as_mut().poll(&mut cx).is_pending());
        assert_eq!(cmd.polls.load(Relaxed), 1);
        assert!(!cmd.dropped.load(Relaxed));
        if kill {
            guest.kill(task, Signal::SIGKILL).unwrap();
            assert!(matches!(
                run.as_mut().poll(&mut cx),
                Poll::Ready(CommandEnd::Exited(137))
            ));
            assert_eq!(cmd.polls.load(Relaxed), 1);
        } else {
            guest.kill(task, Signal::SIGCONT).unwrap();
            assert!(matches!(
                run.as_mut().poll(&mut cx),
                Poll::Ready(CommandEnd::Exited(42))
            ));
            assert_eq!(cmd.polls.load(Relaxed), 2);
        }
        assert!(cmd.dropped.load(Relaxed));
    }
}

#[test]
fn command_dispatch_obeys_noexec_and_landlock_execute() {
    use wasixv2_abi::PrctlOption;
    use wasixv2_vfs::MountFlags;

    let mut builder = Commands::builder();
    builder
        .register("/probe", Arc::new(Probe::new(true)))
        .unwrap();
    let commands = builder.build();
    let root = Arc::new(MemFs::new(
        Arc::new(HostClock(Arc::new(TestHost))),
        0o755,
        0,
        0,
    ));
    let (guest, task, _) = kernel(commands.clone(), root);
    block_on(guest.vfs.mount(
        b"/disabled",
        commands.filesystem(),
        MountFlags {
            noexec: true,
            ..MountFlags::default()
        },
        true,
    ))
    .unwrap();
    assert!(matches!(
        image(&guest, task, b"/disabled/probe"),
        Err(Errno::EACCES)
    ));

    block_on(guest.vfs.mount(
        b"/enabled",
        commands.filesystem(),
        MountFlags::default(),
        true,
    ))
    .unwrap();
    let memory = FlatMemory(RefCell::new(vec![0; 256]));
    let caller = Caller::new(task, &memory);
    block_on(guest.prctl(&caller, PrctlOption::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)).unwrap();
    let attr = 1u64.to_le_bytes(); // LANDLOCK_ACCESS_FS_EXECUTE
    super::ipc::put(&memory, 32, &attr);
    let ruleset =
        block_on(guest.landlock_create_ruleset(&caller, GuestPtr::new(32), 8, 0)).unwrap();
    block_on(guest.landlock_restrict_self(&caller, Fd(ruleset), 0)).unwrap();
    assert!(matches!(
        image(&guest, task, b"/enabled/probe"),
        Err(Errno::EACCES)
    ));
}

#[test]
fn vfork_child_can_exec_a_command_by_fd_and_report_its_exit() {
    use futures::FutureExt;
    use wasixv2_abi::{
        AtFlags, CloneFlags, Idtype, Pid, RusagePtr, S32Ptr, SiginfoPtr, WaitOptions,
    };

    let mut builder = Commands::builder();
    builder
        .register("/probe", Arc::new(Probe::new(true)))
        .unwrap();
    let commands = builder.build();
    let (guest, parent, output) = kernel(commands.clone(), commands.filesystem());
    let parent_memory = super::proc::forkable();
    let caller = Caller::new(parent, &parent_memory);
    let child_pid = block_on(guest.clone(
        &caller,
        CloneFlags::CLONE_VFORK.0 as u32 | Signal::SIGCHLD.0 as u32,
        0,
        S32Ptr::new(8),
        0,
        S32Ptr::new(16),
    ))
    .unwrap();
    let Some(GuestAction::Fork {
        child, vfork: true, ..
    }) = guest.take_pending(parent)
    else {
        panic!("expected a vfork child");
    };
    assert!(guest.vfork_wait(parent).now_or_never().is_none());

    let memory = FlatMemory(RefCell::new(vec![0; 256]));
    let child_caller = Caller::new(child, &memory);
    super::ipc::put(&memory, 16, b"/probe\0");
    super::ipc::put(&memory, 32, b"alias\0");
    super::ipc::put(&memory, 48, b"A=B\0");
    super::ipc::put(&memory, 64, &32u32.to_le_bytes());
    super::ipc::put(&memory, 80, &48u32.to_le_bytes());
    let fd = block_on(guest.openat(
        &child_caller,
        Fd(-100),
        GuestPtr::new(16),
        OpenFlags::O_PATH | OpenFlags::O_CLOEXEC,
        0,
    ))
    .unwrap();
    assert_eq!(
        block_on(guest.execveat(
            &child_caller,
            fd,
            GuestPtr::new(8),
            GuestPtr::new(64),
            GuestPtr::new(80),
            AtFlags::AT_EMPTY_PATH,
        )),
        Ok(0),
    );
    assert!(guest.vfork_wait(parent).now_or_never().is_some());
    assert!(matches!(
        guest.take_pending(child),
        Some(GuestAction::Exec { .. })
    ));
    assert!(matches!(guest.file(child, fd), Err(Errno::EBADF)));
    let image = guest.take_image(child).unwrap();
    assert!(matches!(
        block_on(guest.run_command(child, image)),
        CommandEnd::Exited(42)
    ));
    guest.release(child);
    let slot = wasixv2_syscalls::WaitCompletionSlot::default();
    let caller = caller.with_wait_completion(&slot);
    let result = block_on(guest.waitid(
        &caller,
        Idtype::P_PID,
        child_pid as Pid,
        SiginfoPtr::new(64),
        WaitOptions::WEXITED,
        RusagePtr::NULL,
    ));
    assert_eq!(result, Ok(0));
    let completion = slot.get().unwrap();
    assert_eq!(completion.code, wasixv2_abi::SiCode::CLD_EXITED);
    assert_eq!(completion.status, 42);
    assert_eq!(&*output.0.lock_or_recover(), b"stdin");
}
