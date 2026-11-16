//! Async WLK dispatch loop for the synchronously ptraced native tasks.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use wasixv2_syscalls::{Control, GuestAction, Syscall};

use crate::{
    AliasRegistry, BridgeMemory, DispatchCompletion, exec, handle_request,
    platform::{self, Action, Event},
    scheduler::{self, Scheduler, SpawnKind},
};

/// Drive native ptrace events and WLK syscall futures on the tracer's original OS thread.
pub(super) async fn run_supervisor(
    child: &mut platform::Child,
    kernel: Arc<wasixv2_kernel::Kernel>,
    scheduler: &mut Scheduler,
    aliases: Arc<Mutex<AliasRegistry>>,
    trace: bool,
    program: String,
) -> io::Result<i32> {
    let mut work = tokio::task::JoinSet::new();
    let mut inflight = HashMap::<libc::pid_t, tokio::task::AbortHandle>::new();
    let mut images = HashMap::<libc::pid_t, exec::NativeImage>::new();
    let mut child_settid = HashMap::<libc::pid_t, bool>::new();
    let mut newborn_stops = HashSet::<libc::pid_t>::new();
    let mut pending_exit_mm = HashSet::new();
    let mut root_status = None;

    // Child::spawn consumed the initial SIGSTOP while installing ptrace options.
    child.resume(child.root_pid(), Action::Native)?;

    while !child.is_done() {
        let mut progressed = false;

        if let Some(event) = child.poll_event()? {
            progressed = true;
            match event {
                Event::Seccomp(request) => {
                    if images.contains_key(&request.pid) {
                        // TODO(native): restore the pre-exec WLK image if staging a committed
                        // native exec fails before Linux reports PTRACE_EVENT_EXEC.
                        return Err(io::Error::other(format!(
                            "native exec for task {} failed after WLK committed the new image",
                            request.pid
                        )));
                    }
                    let Some(record) = scheduler.task(request.pid) else {
                        child.resume(request.pid, Action::Return(-(libc::ENOSYS as i64)))?;
                        continue;
                    };
                    if matches!(request.nr, libc::SYS_execve | libc::SYS_execveat)
                        && !crate::exec_single_threaded(scheduler, record.mm_id)
                    {
                        child.resume(request.pid, Action::Return(-(libc::ENOSYS as i64)))?;
                        continue;
                    }
                    if inflight.contains_key(&request.pid) {
                        return Err(io::Error::other(format!(
                            "native task {} entered seccomp with WLK work still pending",
                            request.pid
                        )));
                    }

                    let kernel = kernel.clone();
                    let aliases = aliases.clone();
                    let program = program.clone();
                    let abort = work.spawn_local(async move {
                        handle_request(
                            kernel,
                            record.task,
                            record.mm_id,
                            aliases,
                            request,
                            trace,
                            program,
                        )
                        .await
                    });
                    inflight.insert(request.pid, abort);
                }
                Event::Birth {
                    parent,
                    child: native_child,
                    kind,
                } => {
                    let parent_record = scheduler
                        .task(parent)
                        .ok_or_else(|| io::Error::other("ptrace clone parent has no WLK task"))?;
                    let approval =
                        scheduler.birth(parent, native_child, kind).ok_or_else(|| {
                            io::Error::other("native clone did not match an approved WLK spawn")
                        })?;
                    if approval.kind == SpawnKind::Process {
                        aliases
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone_mm(parent_record.mm_id, native_child as u64);
                    }
                    if child_settid.remove(&parent).unwrap_or(false) {
                        write_child_tid(native_child, approval.native_args[3], approval.child_tid)?;
                    }
                    if newborn_stops.remove(&native_child) {
                        child.resume(native_child, Action::Native)?;
                    }
                    // Keep the syscall-exit stop so the host child ID can be replaced with WLK's ID.
                    child.resume(parent, Action::NativeSyscall(approval.native_args))?;
                }
                Event::SyscallExit { pid, result } => {
                    if images.contains_key(&pid) {
                        if result < 0 {
                            images.remove(&pid);
                            // Let ExitStop's normal cleanup synthesize the WLK exit, exit_mm,
                            // and release exactly once after the native task is stopped.
                            child.resume(pid, Action::Signal(libc::SIGKILL))?;
                        } else {
                            child.continue_syscall(pid)?;
                        }
                    } else if let Some(approval) = scheduler.syscall_exit(pid) {
                        if result < 0 {
                            kernel.abort_thread(approval.child_task);
                        }
                        child.set_syscall_result(
                            pid,
                            if result < 0 {
                                result
                            } else {
                                i64::from(approval.returned_id)
                            },
                        )?;
                    } else if result < 0 {
                        if let Some(approval) = scheduler.failed_syscall(pid) {
                            kernel.abort_thread(approval.child_task);
                        }
                        child.set_syscall_result(pid, result)?;
                    } else {
                        child.continue_syscall(pid)?;
                    }
                }
                Event::Exec { pid } => {
                    if images.remove(&pid).is_some()
                        && let Some(record) = scheduler.task(pid)
                    {
                        aliases
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clear_mm(record.mm_id);
                    }
                    child.resume(pid, Action::Native)?;
                }
                Event::ExitStop { pid, wait_status } => {
                    if let Some(record) = scheduler.task(pid) {
                        scheduler.mark_exit(pid);
                        // cleanup_kernel_task drains remaining WLK work and performs exit_mm
                        // while the native address space is still available at this ptrace stop.
                        pending_exit_mm.remove(&record.task);
                        crate::cleanup_kernel_task(
                            &kernel,
                            pid,
                            record,
                            aliases.clone(),
                            wait_status_code(wait_status),
                        )
                        .await;
                    }
                    child.continue_exit(pid)?;
                }
                Event::NewbornStop { pid } => {
                    if scheduler.task(pid).is_some() {
                        child.resume(pid, Action::Native)?;
                    } else {
                        // Linux may report the newborn's initial stop before the parent's birth event.
                        newborn_stops.insert(pid);
                    }
                }
                Event::SignalStop {
                    pid,
                    signal: libc::SIGCHLD,
                } => {
                    // TODO(native): synthesize virtual SIGCHLD from WLK child lifecycle events.
                    // WLK wait owns child status, so suppress the host's duplicate notification.
                    child.resume(pid, Action::Native)?;
                }
                Event::SignalStop { pid, signal } => {
                    child.resume(pid, Action::Signal(signal))?;
                }
                Event::Gone { pid, status } => {
                    if let Some(abort) = inflight.remove(&pid) {
                        abort.abort();
                    }
                    images.remove(&pid);
                    if scheduler.is_root(pid) {
                        root_status = Some(status);
                    }
                    scheduler.remove(pid);
                }
            }
        }

        while let Some(joined) = work.try_join_next() {
            progressed = true;
            match joined {
                Ok(Ok(completion)) => {
                    inflight.remove(&completion.native);
                    finish_dispatch(
                        completion,
                        child,
                        &kernel,
                        scheduler,
                        &aliases,
                        &mut images,
                        &mut child_settid,
                        &mut pending_exit_mm,
                    )
                    .await?;
                }
                Ok(Err(error)) => return Err(error),
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "WLK syscall worker failed: {error}"
                    )));
                }
            }
        }

        if child.is_done() {
            break;
        }
        if !progressed {
            // Tokio polls the local syscall futures while this same tracer thread waits briefly.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    work.abort_all();
    while work.join_next().await.is_some() {}
    if trace {
        eprintln!(
            "[wlk-native] supervised {} native task(s)",
            scheduler.tasks().count()
        );
    }
    root_status.ok_or_else(|| io::Error::other("native root process exited without a status"))
}

#[allow(clippy::too_many_arguments)]
async fn finish_dispatch(
    completion: DispatchCompletion,
    child: &mut platform::Child,
    kernel: &wasixv2_kernel::Kernel,
    scheduler: &mut Scheduler,
    aliases: &Arc<Mutex<AliasRegistry>>,
    images: &mut HashMap<libc::pid_t, exec::NativeImage>,
    child_settid: &mut HashMap<libc::pid_t, bool>,
    pending_exit_mm: &mut HashSet<wasixv2_syscalls::TaskId>,
) -> io::Result<()> {
    let DispatchCompletion {
        native,
        task,
        action,
        call,
        pending,
        spawn,
        image,
        exit_call,
    } = completion;
    let execing = image.is_some();

    if exit_call
        || pending
            .iter()
            .any(|action| matches!(action, GuestAction::Exit(_)))
    {
        scheduler.mark_exit(native);
    }

    for action in &pending {
        match *action {
            GuestAction::Exit(_) => {
                if let Some(native_task) = native_task_for(scheduler, task) {
                    scheduler.mark_exit(native_task);
                }
            }
            GuestAction::ExitMm { task: exiting } => {
                if native_task_for(scheduler, exiting).is_some() {
                    if execing && exiting == task {
                        if let Some(record) = scheduler.task(native) {
                            run_exit_mm(kernel, native, record, aliases.clone()).await;
                        }
                    } else {
                        pending_exit_mm.insert(exiting);
                    }
                } else {
                    return Err(io::Error::other(format!(
                        "WLK requested exit_mm for unknown task {}",
                        exiting.0
                    )));
                }
            }
            GuestAction::Exec { .. }
            | GuestAction::Fork { .. }
            | GuestAction::StartThread { .. } => {}
            _ => {
                // TODO(native): route remaining WLK signal and stop actions through native state.
            }
        }
    }

    if let Some(approval) = spawn {
        child_settid.insert(native, clone_requests_child_tid(call));
        scheduler.approve(native, approval);
    }

    let resume = if let Some(image) = image {
        if let Some(argv) = &image.launch_argv {
            child.exec_image_with_argv(native, &image.path, Some(argv))?;
        } else {
            child.exec_image(native, &image.path)?;
        }
        images.insert(native, image);
        return child.continue_syscall(native);
    } else {
        action
    };
    child.resume(native, resume)
}

fn clone_requests_child_tid(call: Option<Syscall>) -> bool {
    match call {
        Some(Syscall::Clone { clone_flags, .. }) => {
            clone_flags & libc::CLONE_CHILD_SETTID as u32 != 0
        }
        Some(Syscall::ThreadSpawn { flags, .. }) => flags & libc::CLONE_CHILD_SETTID as u32 != 0,
        _ => false,
    }
}

fn native_task_for(scheduler: &Scheduler, task: wasixv2_syscalls::TaskId) -> Option<libc::pid_t> {
    scheduler
        .tasks()
        .find_map(|(native, record)| (record.task == task).then_some(native))
}

async fn run_exit_mm(
    kernel: &wasixv2_kernel::Kernel,
    native: libc::pid_t,
    record: scheduler::TaskRecord,
    aliases: Arc<Mutex<AliasRegistry>>,
) {
    use wasixv2_syscalls::{Caller, ExitMm};

    let memory = BridgeMemory::new(native, record.mm_id, aliases);
    let caller = Caller::new(record.task, &memory).with_process_fork_allowed(false);
    kernel.exit_mm(&caller).await;
}

fn write_child_tid(pid: libc::pid_t, address: u64, tid: i32) -> io::Result<()> {
    if address == 0 {
        return Err(io::Error::other(
            "WLK requested CLONE_CHILD_SETTID without a native pointer",
        ));
    }
    let bytes = tid.to_ne_bytes();
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: the local bytes live through the call and ptrace stopped the child at its birth event.
    let written = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if written == bytes.len() as isize {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other(
            "short write while setting native child TID",
        ))
    }
}

fn wait_status_code(status: i32) -> i32 {
    let signal = status & 0x7f;
    if signal == 0 {
        (status >> 8) & 0xff
    } else {
        128 + signal
    }
}
