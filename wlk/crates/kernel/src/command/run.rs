//! Drive a host command at the same signal boundaries as a guest image.

use futures_util::{FutureExt, pin_mut, select_biased};
use wasixv2_syscalls::{Caller, CommandEnd, Control, GuestAction, Image, TaskId};
use wasixv2_wait::{NoInterrupt, PollMask, Waiter};

use crate::{Kernel, process::NoMemory, sync::MutexExt};

use super::{CommandContext, CommandOutcome};

pub(crate) async fn run(kernel: &Kernel, task: TaskId, image: Image) -> CommandEnd {
    let Some(entry) = image.command_token().and_then(|token| {
        kernel
            .commands
            .recognise(wasixv2_vfs::CommandMark(token.clone()))
    }) else {
        return CommandEnd::Unsupported;
    };
    let Some(process) = kernel.task_process(task) else {
        return CommandEnd::Unsupported;
    };
    let signals = kernel.task_signals(task);
    let waiter = Waiter::new();
    // Register before the first signal check. A wake remains pending if the command was
    // polled between the check and a concurrent stop or kill.
    let _signal = waiter.register(signals.sent(), PollMask::empty());
    let _exit = waiter.register(&process.group.exited, PollMask::empty());
    let caller = Caller::new(task, &NoMemory);
    let outcome = {
        let mut command = None;
        loop {
            match kernel.take_pending(task) {
                Some(GuestAction::Exit(status)) => {
                    drop(command);
                    kernel.exit_mm(&caller).await;
                    return CommandEnd::Exited(status);
                }
                Some(GuestAction::Stopped) => {
                    kernel.stop_wait(task).await;
                    continue;
                }
                None if signals.held() => {
                    kernel.stop_wait(task).await;
                    continue;
                }
                // The task has no user handlers or Wasm instance after exec.
                None => {}
                Some(_) => return CommandEnd::Unsupported,
            }
            let command = command.get_or_insert_with(|| {
                entry.spec.command.run(CommandContext {
                    kernel,
                    task,
                    args: process.args.lock_or_recover().clone(),
                    env: process.env.lock_or_recover().clone(),
                })
            });
            let next = command.as_mut().fuse();
            let signaled = waiter.sleep(&NoInterrupt, None).fuse();
            pin_mut!(next, signaled);
            select_biased! {
                _ = signaled => {},
                end = next => break end,
            }
        }
    };
    match outcome {
        CommandOutcome::Exec(done) => {
            if let Some(image) = done.0 {
                return CommandEnd::Exec(image);
            }
        }
        CommandOutcome::Exit(code) => {
            // I/O within the final poll may generate SIGPIPE or another signal.
            loop {
                match kernel.take_pending(task) {
                    Some(GuestAction::Exit(status)) => {
                        kernel.exit_mm(&caller).await;
                        return CommandEnd::Exited(status);
                    }
                    Some(GuestAction::Stopped) => kernel.stop_wait(task).await,
                    _ => break,
                }
            }
            let _ = kernel.sys_exit_group(&caller, code).await;
        }
    }
    match kernel.take_pending(task) {
        Some(GuestAction::Exit(status)) => {
            kernel.exit_mm(&caller).await;
            CommandEnd::Exited(status)
        }
        _ => CommandEnd::Unsupported,
    }
}
