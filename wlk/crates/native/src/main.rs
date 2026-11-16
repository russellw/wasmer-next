#![cfg(target_os = "linux")]

use std::{
    ffi::{CString, OsStr},
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use wasixv2_abi::{Fd, GrndFlags, OpenFlags, S32Ptr, Ulong};
use wasixv2_host::{BlockingSource, Host, Stdio, TokioHost};
use wasixv2_kernel::{Dispatch, Kernel, ProcessConfig, SyscallEntry};
use wasixv2_syscalls::{
    Caller, Control, ExitMm, Fault, GuestAction, Layer, Syscall, UserMemory, UserSlice,
    UserSliceMut,
};

mod elf;
mod exec;
mod fs;
mod injection;
mod ioctl;
mod mapping;
mod memory;
mod net;
mod newfd;
mod platform;
mod runtime;
mod scheduler;
mod sync;
mod volumes;
mod wait;

const MAX_TRANSFER: usize = 16 * 1024 * 1024;
pub(crate) use memory::AliasRegistry;

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("wlk-native: {error}");
        std::process::exit(1);
    }
}

fn run_cli() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mut trace = false;
    let mut root = PathBuf::from("/");
    let mut volume_specs = Vec::new();
    let mut program = None;
    let mut guest_args = Vec::new();

    while let Some(arg) = args.next() {
        if program.is_none() && arg == "--trace" {
            trace = true;
        } else if program.is_none() && arg == "--root" {
            root = PathBuf::from(args.next().ok_or_else(usage)?);
        } else if program.is_none() && arg == "--volume" {
            volume_specs.push(volumes::parse(&args.next().ok_or_else(usage)?)?);
        } else if program.is_none() && arg == "--help" {
            println!("{}", usage());
            return Ok(());
        } else {
            program = Some(PathBuf::from(arg));
            guest_args.extend(args);
            break;
        }
    }

    let program = program.ok_or_else(usage)?;
    elf::validate(&program)?;
    let host_interpreter = elf::interpreter(&std::fs::read(&program)?)?;
    let dynamic_launch = host_interpreter.is_some();
    let program_c = cstring(program.as_os_str())?;
    let mut argv = Vec::with_capacity(guest_args.len() + 1);
    argv.push(program_c.clone());
    argv.extend(
        guest_args
            .iter()
            .map(|arg| cstring(arg.as_os_str()))
            .collect::<io::Result<Vec<_>>>()?,
    );
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut pair = key.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(value.as_bytes());
            CString::new(pair).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "environment contains NUL")
            })
        })
        .collect::<io::Result<Vec<_>>>()?;

    // Static launches keep the original early fork. Dynamic launches need their WLK-resolved
    // interpreter memfd, which is prepared after the virtual filesystem has mounted.
    let mut child = if dynamic_launch {
        None
    } else {
        Some(platform::Child::spawn(&program_c, &argv, &env)?)
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    let fs_root = root.clone();
    let fs_volumes = volume_specs.clone();
    let process_args = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let process_env = env
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    let (kernel, task) = local.block_on(&runtime, async move {
        let host: Arc<dyn Host> = Arc::new(TokioHost::default());
        let fs =
            wasixv2_vfs_host::open(&fs_root, host.clone(), wasixv2_vfs_host::Options::default())?;
        let network = net::network(host.clone())?;
        let kernel = Arc::new(
            Kernel::new(host.clone(), fs)
                .with_network(network)
                .with_binfmt(Arc::new(exec::NativeBinfmt))
                .with_init(),
        );
        volumes::mount(&kernel, host, &fs_volumes).await?;
        let stdio = host_stdio();
        let task = kernel
            .spawn(ProcessConfig {
                args: process_args,
                env: process_env,
                stdio,
            })
            .map_err(|errno| io::Error::other(format!("WLK process spawn failed: {errno:?}")))?;
        Ok::<_, io::Error>((kernel, task))
    })?;

    let mut staged_program = None;
    if dynamic_launch {
        let guest_program =
            exec::guest_path_for_host(&program, &root, &volume_specs)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "dynamic program must be visible under --root or a --volume mount",
                )
            })?;
        let native_args: Vec<Vec<u8>> = argv.iter().map(|arg| arg.as_bytes().to_vec()).collect();
        let native_env: Vec<Vec<u8>> = env.iter().map(|value| value.as_bytes().to_vec()).collect();
        let prepared = local.block_on(
            &runtime,
            exec::prepare_guest_program(
                &kernel,
                task,
                &guest_program,
                native_args.clone(),
                native_env,
            ),
        )?;
        let (launch_path, launch_argv) = if let (Some(loader), Some(interpreter_path)) =
            (&prepared.interpreter, &prepared.interpreter_path)
        {
            (
                loader.path.clone(),
                exec::loader_argv(loader, interpreter_path, &guest_program, &native_args)?,
            )
        } else {
            (prepared.main.path.clone(), argv.clone())
        };
        // TODO(native): dynamic bootstrap currently forks after WLK runtime startup; the child
        // path uses only async-signal-safe setup calls before execve.
        child = Some(platform::Child::spawn(&launch_path, &launch_argv, &env)?);
        staged_program = Some(prepared);
    }

    let aliases = Arc::new(Mutex::new(AliasRegistry::default()));
    let mut child = child.ok_or_else(|| io::Error::other("native child was not started"))?;
    let root_pid = child.root_pid();
    let mut scheduler = scheduler::Scheduler::default();
    scheduler.insert_root(root_pid, task);
    let cwd = guest_cwd(&root)?;
    local.block_on(
        &runtime,
        set_guest_cwd(&kernel, task, root_pid, aliases.clone(), &cwd),
    )?;

    // ptrace ownership is per thread on Linux: keep run() on the same thread that forked and
    // established TRACEME. LocalSet::block_on drives WLK's async syscall work at each stop.
    let label = program.display().to_string();
    let run_result = local.block_on(
        &runtime,
        runtime::run_supervisor(
            &mut child,
            kernel.clone(),
            &mut scheduler,
            aliases.clone(),
            trace,
            label,
        ),
    );
    local.block_on(
        &runtime,
        cleanup_kernel_tasks(&kernel, &mut scheduler, aliases),
    );
    drop(staged_program);
    let status = run_result?;
    std::process::exit(status);
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: wlk-native [--trace] [--root DIR] [--volume HOST:GUEST[:ro]] PROGRAM [ARGS...]",
    )
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL"))
}

fn host_stdio() -> Stdio {
    let output = Stdio::from_fns(
        |bytes| {
            use std::io::Write as _;
            // TODO(native): propagate host pipe errors through the WLK stdio sink.
            let _ = io::stdout().lock().write_all(bytes);
        },
        |bytes| {
            use std::io::Write as _;
            // TODO(native): propagate host pipe errors through the WLK stdio sink.
            let _ = io::stderr().lock().write_all(bytes);
        },
    );
    Stdio {
        stdin: Arc::new(BlockingSource::new(io::stdin())),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

struct DispatchCompletion {
    native: libc::pid_t,
    task: wasixv2_syscalls::TaskId,
    action: platform::Action,
    call: Option<Syscall>,
    pending: Vec<GuestAction>,
    spawn: Option<scheduler::SpawnApproval>,
    image: Option<exec::NativeImage>,
    exit_call: bool,
}

pub(crate) fn exec_single_threaded(scheduler: &scheduler::Scheduler, mm_id: u64) -> bool {
    // TODO(native): implement Linux de_thread semantics before allowing exec with sibling TIDs.
    scheduler
        .tasks()
        .filter(|(_, record)| record.mm_id == mm_id)
        .count()
        == 1
}

async fn handle_request(
    kernel: Arc<Kernel>,
    task: wasixv2_syscalls::TaskId,
    mm_id: u64,
    aliases: Arc<Mutex<AliasRegistry>>,
    request: platform::Request,
    trace: bool,
    program: String,
) -> io::Result<DispatchCompletion> {
    let exec_invocation = exec::native_invocation(request).ok().flatten();
    if request.nr == libc::SYS_execveat {
        let flags = request.args[4] as u32;
        if flags & wasixv2_abi::AtFlags::AT_EMPTY_PATH.0 != 0
            && exec_invocation
                .as_ref()
                .is_some_and(|invocation| invocation.path.is_empty())
        {
            // TODO(native): resolve dynamic AT_EMPTY_PATH through WLK descriptor identity before
            // supporting it; reject before the WLK exec commit so the old image remains intact.
            return Ok(unsupported_completion(request, task, &program, trace));
        }
        if let Some(invocation) = exec_invocation.as_ref()
            && request.args[0] as i32 != libc::AT_FDCWD
            && !invocation.path.starts_with(b"/")
        {
            let dfd = Fd(request.args[0] as i32);
            let bytes = match exec::read_guest_file_at(&kernel, task, dfd, &invocation.path).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    // TODO(native): resolve the dirfd target through WLK descriptor path metadata
                    // so unreadable static execveat files can retain their existing support.
                    return Ok(unsupported_completion(request, task, &program, trace));
                }
            };
            if matches!(elf::interpreter(&bytes), Ok(Some(_))) {
                // TODO(native): pass the dirfd-resolved guest pathname to explicit ld.so.
                // Returning ENOSYS here avoids committing a dynamic exec whose relative lookup
                // would otherwise lose its dirfd semantics.
                return Ok(unsupported_completion(request, task, &program, trace));
            }
        }
    }
    if native_startup_allowed(request) {
        return Ok(DispatchCompletion {
            native: request.pid,
            task,
            action: platform::Action::Native,
            call: None,
            pending: Vec::new(),
            spawn: None,
            image: None,
            exit_call: false,
        });
    }

    if request.nr == libc::SYS_mmap
        && let Some(action) =
            mapping::handle_mmap(request, &kernel, task, mm_id, aliases.clone()).await?
    {
        let memory = BridgeMemory::new(request.pid, mm_id, aliases);
        let caller = Caller::new(task, &memory).with_process_fork_allowed(false);
        kernel.run_task_work(&caller).await;
        return Ok(DispatchCompletion {
            native: request.pid,
            task,
            action,
            call: None,
            pending: take_pending(&kernel, task),
            spawn: None,
            image: None,
            exit_call: false,
        });
    }

    if let Some(action) = wait::handle(request, &kernel, task, trace, &program).await? {
        let memory = BridgeMemory::new(request.pid, mm_id, aliases);
        let caller = Caller::new(task, &memory).with_process_fork_allowed(false);
        kernel.run_task_work(&caller).await;
        return Ok(DispatchCompletion {
            native: request.pid,
            task,
            action,
            call: None,
            pending: take_pending(&kernel, task),
            spawn: None,
            image: None,
            exit_call: false,
        });
    }

    if let Some(action) = fs::handle_stat(request, &kernel, task, trace, &program).await? {
        let memory = BridgeMemory::new(request.pid, mm_id, aliases.clone());
        let caller = Caller::new(task, &memory).with_process_fork_allowed(false);
        kernel.run_task_work(&caller).await;
        return Ok(DispatchCompletion {
            native: request.pid,
            task,
            action,
            call: None,
            pending: take_pending(&kernel, task),
            spawn: None,
            image: None,
            exit_call: false,
        });
    }

    let mut memory = BridgeMemory::new(request.pid, mm_id, aliases.clone());
    let mut call = match ioctl::translate(request, &mut memory) {
        Ok(call) => call,
        Err(errno) => {
            let fd = Fd(request.args[0] as i32);
            let raw = match kernel.snapshot_descriptors(task, &[fd]) {
                Ok(set) if set.get(fd).is_some_and(|descriptor| descriptor.present) => errno,
                Ok(_) => -(libc::EBADF as i64),
                Err(error) => -(error.0 as i64),
            };
            return Ok(DispatchCompletion {
                native: request.pid,
                task,
                action: platform::Action::Return(raw),
                call: None,
                pending: Vec::new(),
                spawn: None,
                image: None,
                exit_call: false,
            });
        }
    };
    if call.is_none() {
        match newfd::translate(request, &mut memory, &kernel, task) {
            Some(newfd::Translation::Call(translated)) => call = Some(translated),
            Some(newfd::Translation::Return(raw)) => {
                return Ok(DispatchCompletion {
                    native: request.pid,
                    task,
                    action: platform::Action::Return(raw),
                    call: None,
                    pending: Vec::new(),
                    spawn: None,
                    image: None,
                    exit_call: false,
                });
            }
            None => {}
        }
    }
    if call.is_none() {
        let translated = exec::translate(request, &mut memory).and_then(|call| match call {
            Some(call) => Ok(Some(call)),
            None => fs::translate(request, &mut memory).and_then(|call| match call {
                Some(call) => Ok(Some(call)),
                None => net::translate(request, &mut memory).and_then(|call| match call {
                    Some(call) => Ok(Some(call)),
                    None => sync::translate(request, &mut memory),
                }),
            }),
        });
        call = match translated {
            Ok(call) => call,
            Err(_) => {
                return Ok(DispatchCompletion {
                    native: request.pid,
                    task,
                    action: platform::Action::Return(-(libc::EFAULT as i64)),
                    call: None,
                    pending: Vec::new(),
                    spawn: None,
                    image: None,
                    exit_call: false,
                });
            }
        };
    }
    let mut native_args = request.args;
    let mut spawn_kind = None;

    if call.is_none() {
        call = match request.nr {
            0 => {
                let len = bounded_len(request.args[2]);
                let addr = memory.map(request.args[1], len, false, true)?;
                Some(Syscall::Read {
                    fd: Fd(request.args[0] as i32),
                    buf: UserSliceMut::new(addr, len as u32),
                })
            }
            17 => {
                let len = bounded_len(request.args[2]);
                let addr = memory.map(request.args[1], len, false, true)?;
                Some(Syscall::Pread64 {
                    fd: Fd(request.args[0] as i32),
                    buf: UserSliceMut::new(addr, len as u32),
                    pos: request.args[3] as i64,
                })
            }
            1 => {
                let len = bounded_len(request.args[2]);
                let addr = memory.map(request.args[1], len, true, false)?;
                Some(Syscall::Write {
                    fd: Fd(request.args[0] as i32),
                    buf: UserSlice::new(addr, len as u32),
                })
            }
            2 | 257 => {
                let path = if request.nr == 2 {
                    request.args[0]
                } else {
                    request.args[1]
                };
                let addr = memory.map(path, 4096, true, false)?;
                Some(Syscall::Openat {
                    dfd: if request.nr == 2 {
                        Fd(libc::AT_FDCWD)
                    } else {
                        Fd(request.args[0] as i32)
                    },
                    filename: wasixv2_abi::Cstr::new(addr),
                    flags: OpenFlags(if request.nr == 2 {
                        request.args[1] as u32
                    } else {
                        request.args[2] as u32
                    }),
                    mode: if request.nr == 2 {
                        request.args[2] as u32
                    } else {
                        request.args[3] as u32
                    },
                })
            }
            3 => Some(Syscall::Close {
                fd: Fd(request.args[0] as i32),
            }),
            8 => Some(Syscall::Lseek {
                fd: Fd(request.args[0] as i32),
                offset: request.args[1] as i64,
                whence: wasixv2_abi::SeekWhence(request.args[2] as i32),
            }),
            19 | 20 => {
                let is_read = request.nr == 19;
                let (addr, count) = match map_iovecs(&mut memory, request, is_read)? {
                    Ok(value) => value,
                    Err(errno) => {
                        return Ok(DispatchCompletion {
                            native: request.pid,
                            task,
                            action: platform::Action::Return(errno),
                            call: None,
                            pending: Vec::new(),
                            spawn: None,
                            image: None,
                            exit_call: false,
                        });
                    }
                };
                let vec = wasixv2_abi::ConstIovecArray::new(addr);
                Some(if is_read {
                    Syscall::Readv {
                        fd: Fd(request.args[0] as i32),
                        vec,
                        vlen: count,
                    }
                } else {
                    Syscall::Writev {
                        fd: Fd(request.args[0] as i32),
                        vec,
                        vlen: count,
                    }
                })
            }
            39 => Some(Syscall::Getpid),
            56 | 57 => {
                let (flags, stack, parent_tid, tls, child_tid, thread) = if request.nr == 57 {
                    (libc::SIGCHLD as u64, 0, 0, 0, 0, false)
                } else {
                    let flags = request.args[0];
                    if flags > u64::from(u32::MAX) {
                        // TODO(native): the WLK syscall ABI currently represents clone flags as wasm32.
                        return Ok(unsupported_completion(request, task, &program, trace));
                    }
                    let thread = flags & libc::CLONE_THREAD as u64 != 0;
                    if request.args[1] != 0 && !thread {
                        // TODO(native): process fork with a custom child stack needs a native stack handoff.
                        return Ok(unsupported_completion(request, task, &program, trace));
                    }
                    if flags & libc::CLONE_VFORK as u64 != 0 {
                        // TODO(native): vfork requires WLK vfork parent/child instance switching.
                        return Ok(unsupported_completion(request, task, &program, trace));
                    }
                    (
                        flags,
                        request.args[1],
                        request.args[2],
                        request.args[4],
                        request.args[3],
                        thread,
                    )
                };
                if thread {
                    let required = libc::CLONE_VM as u64
                        | libc::CLONE_FS as u64
                        | libc::CLONE_FILES as u64
                        | libc::CLONE_SIGHAND as u64
                        | libc::CLONE_THREAD as u64;
                    if flags & required != required {
                        // TODO(native): reject unsupported Linux clone flag combinations explicitly.
                        return Ok(unsupported_completion(request, task, &program, trace));
                    }
                    let parent_tid_guest = if parent_tid == 0 {
                        0
                    } else {
                        memory.map_alias(parent_tid, 4, true, true)?
                    };
                    let child_tid_guest = if child_tid == 0 {
                        0
                    } else {
                        memory.map_alias(child_tid, 4, true, true)?
                    };
                    let tls_guest = if tls == 0 {
                        0
                    } else {
                        memory.map_alias(tls, 16, true, true)?
                    };
                    spawn_kind = Some(scheduler::SpawnKind::Thread);
                    native_args[0] &= !((libc::CLONE_PARENT_SETTID
                        | libc::CLONE_CHILD_SETTID
                        | libc::CLONE_CHILD_CLEARTID)
                        as u64);
                    Some(Syscall::ThreadSpawn {
                        flags: flags as Ulong,
                        start_arg: 0,
                        parent_tid: S32Ptr::new(parent_tid_guest),
                        tls: tls_guest,
                        child_tid: S32Ptr::new(child_tid_guest),
                    })
                } else {
                    if flags & libc::CLONE_VM as u64 != 0 || stack != 0 {
                        // TODO(native): process fork with shared/custom memory is not implemented.
                        return Ok(unsupported_completion(request, task, &program, trace));
                    }
                    let parent_tid_guest = if parent_tid == 0 {
                        0
                    } else {
                        memory.map_alias(parent_tid, 4, true, true)?
                    };
                    let child_tid_guest = if child_tid == 0 {
                        0
                    } else {
                        memory.map_alias(child_tid, 4, true, true)?
                    };
                    let tls_guest = if tls == 0 {
                        0
                    } else {
                        memory.map_alias(tls, 16, true, true)?
                    };
                    spawn_kind = Some(scheduler::SpawnKind::Process);
                    native_args[0] &= !((libc::CLONE_PARENT_SETTID
                        | libc::CLONE_CHILD_SETTID
                        | libc::CLONE_CHILD_CLEARTID)
                        as u64);
                    Some(Syscall::Clone {
                        clone_flags: flags as Ulong,
                        newsp: stack as u32,
                        parent_tidptr: S32Ptr::new(parent_tid_guest),
                        tls: tls_guest,
                        child_tidptr: S32Ptr::new(child_tid_guest),
                    })
                }
            }
            58 => {
                // TODO(native): vfork requires WLK vfork parent/child instance switching.
                return Ok(unsupported_completion(request, task, &program, trace));
            }
            60 | 231 => Some(if request.nr == 60 {
                Syscall::Exit {
                    error_code: request.args[0] as i32,
                }
            } else {
                Syscall::ExitGroup {
                    error_code: request.args[0] as i32,
                }
            }),
            79 => {
                let len = bounded_len(request.args[1]);
                let addr = memory.map(request.args[0], len, false, true)?;
                Some(Syscall::Getcwd {
                    buf: UserSliceMut::new(addr, len as u32),
                })
            }
            102 => Some(Syscall::Getuid),
            104 => Some(Syscall::Getgid),
            107 => Some(Syscall::Geteuid),
            108 => Some(Syscall::Getegid),
            110 => Some(Syscall::Getppid),
            109 => Some(Syscall::Setpgid {
                pid: request.args[0] as i32,
                pgid: request.args[1] as i32,
            }),
            111 => Some(Syscall::Getpgid { pid: 0 }),
            112 => Some(Syscall::Setsid),
            121 => Some(Syscall::Getpgid {
                pid: request.args[0] as i32,
            }),
            124 => Some(Syscall::Getsid {
                pid: request.args[0] as i32,
            }),
            186 => Some(Syscall::Gettid),
            318 => {
                let len = bounded_len(request.args[1]);
                let addr = memory.map(request.args[0], len, false, true)?;
                Some(Syscall::Getrandom {
                    ubuf: UserSliceMut::new(addr, len as u32),
                    flags: GrndFlags(request.args[2] as u32),
                })
            }
            _ => None,
        };
    }

    let Some(call) = call else {
        return Ok(unsupported_completion(request, task, &program, trace));
    };
    let process_fork = spawn_kind == Some(scheduler::SpawnKind::Process);
    let caller = Caller::new(task, &memory).with_process_fork_allowed(process_fork);
    let result = SyscallEntry(Dispatch).call(&caller, call, &kernel).await;
    let raw = match result {
        Ok(value) => value.to_raw(),
        Err(wasixv2_syscalls::SysErr::Errno(errno)) => -(errno.0 as i64),
        Err(_) => -(libc::EINTR as i64),
    };
    kernel.run_task_work(&caller).await;
    let pending = take_pending(&kernel, task);
    let mut spawn = None;
    let mut image = None;
    for action in &pending {
        match *action {
            GuestAction::Fork {
                child, pid, tid, ..
            } if spawn_kind == Some(scheduler::SpawnKind::Process) => {
                spawn = Some(scheduler::Scheduler::approval_from_request(
                    scheduler::SpawnKind::Process,
                    child,
                    pid,
                    tid,
                    native_args,
                    mm_id,
                ));
            }
            GuestAction::StartThread {
                task: child, tid, ..
            } if spawn_kind == Some(scheduler::SpawnKind::Thread) => {
                spawn = Some(scheduler::Scheduler::approval_from_request(
                    scheduler::SpawnKind::Thread,
                    child,
                    tid,
                    tid,
                    native_args,
                    mm_id,
                ));
            }
            GuestAction::Exec { .. } => {
                let wlk_image = kernel
                    .take_image(task)
                    .ok_or_else(|| io::Error::other("WLK exec action has no image"))?;
                image = Some(
                    exec::prepare_exec_image(&kernel, task, &wlk_image, exec_invocation.as_ref())
                        .await?,
                );
                aliases
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear_mm(mm_id);
            }
            _ => {}
        }
    }
    if trace {
        eprintln!("[wlk-native] {program}: {call:?} -> {raw}");
    }
    let exit_call = raw >= 0 && matches!(call, Syscall::Exit { .. } | Syscall::ExitGroup { .. });
    let action = if let Some(approval) = spawn {
        platform::Action::NativeSyscall(approval.native_args)
    } else if exit_call && raw >= 0 {
        platform::Action::Native
    } else {
        platform::Action::Return(raw)
    };
    Ok(DispatchCompletion {
        native: request.pid,
        task,
        action,
        call: Some(call),
        pending,
        spawn,
        image,
        exit_call,
    })
}

fn unsupported_completion(
    request: platform::Request,
    task: wasixv2_syscalls::TaskId,
    program: &str,
    trace: bool,
) -> DispatchCompletion {
    if trace {
        eprintln!(
            "[wlk-native] {program}: unsupported native syscall {} args={:#x?} -> -ENOSYS",
            request.nr, request.args
        );
    }
    DispatchCompletion {
        native: request.pid,
        task,
        action: platform::Action::Return(-(libc::ENOSYS as i64)),
        call: None,
        pending: Vec::new(),
        spawn: None,
        image: None,
        exit_call: false,
    }
}

fn take_pending(kernel: &Kernel, task: wasixv2_syscalls::TaskId) -> Vec<GuestAction> {
    let mut actions = Vec::new();
    while let Some(action) = kernel.take_pending(task) {
        actions.push(action);
    }
    actions
}

async fn cleanup_kernel_task(
    kernel: &Kernel,
    native: libc::pid_t,
    record: scheduler::TaskRecord,
    aliases: Arc<Mutex<AliasRegistry>>,
    status: i32,
) {
    let memory = BridgeMemory::new(native, record.mm_id, aliases);
    let caller = Caller::new(record.task, &memory).with_process_fork_allowed(false);
    if !record.exit_seen {
        let _ = SyscallEntry(Dispatch)
            .call(&caller, Syscall::ExitGroup { error_code: status }, kernel)
            .await;
    }
    kernel.run_task_work(&caller).await;
    for action in take_pending(kernel, record.task) {
        match action {
            GuestAction::ExitMm { task } if task == record.task => {}
            GuestAction::Exit(_) => {}
            _ => {
                // TODO(native): route any non-exit action emitted during teardown before releasing the task.
            }
        }
    }
    // ExitMm is centralized here so a pending ExitMm action cannot cause duplicate release.
    kernel.exit_mm(&caller).await;
    kernel.release(record.task);
}

async fn cleanup_kernel_tasks(
    kernel: &Kernel,
    scheduler: &mut scheduler::Scheduler,
    aliases: Arc<Mutex<AliasRegistry>>,
) {
    let remaining = scheduler.tasks().collect::<Vec<_>>();
    for (native, record) in remaining {
        cleanup_kernel_task(kernel, native, record, aliases.clone(), 1).await;
        scheduler.remove(native);
    }
}

fn native_startup_allowed(request: platform::Request) -> bool {
    let arg = request.args;
    match request.nr {
        // TODO(native): this explicit native startup allowlist is temporary; add native mm/TLS ABI handling.
        // Native anonymous mappings, heap setup and protection changes used by static libc.
        9 => arg[3] as i32 & libc::MAP_ANONYMOUS != 0,
        10 | 11 | 12 | 28 => true, // mprotect, munmap, brk, madvise
        25 => arg[3] as i32 & !(libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) == 0,
        // TLS and process startup bookkeeping.
        13 | 14 | 15 | 131 | 334 => true,
        158 => matches!(arg[0] as i32, 0x1001..=0x1004), // ARCH_*_FS/GS
        // Runtime limit queries only; do not let the tracee raise its host limits.
        302 => arg[0] as i32 == 0 && arg[2] == 0,
        _ => false,
    }
}

fn bounded_len(requested: u64) -> usize {
    // TODO(native): return a short successful count for transfers beyond this scratch limit.
    requested.min(MAX_TRANSFER as u64).min(u32::MAX as u64) as usize
}

fn guest_cwd(root: &Path) -> io::Result<Vec<u8>> {
    let root = std::fs::canonicalize(root)?;
    let cwd = std::env::current_dir()?;
    let relative = cwd.strip_prefix(&root).unwrap_or_else(|_| Path::new(""));
    let guest = if relative.as_os_str().is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", relative.display())
    };
    Ok(guest.into_bytes())
}

async fn set_guest_cwd(
    kernel: &Kernel,
    task: wasixv2_syscalls::TaskId,
    pid: libc::pid_t,
    aliases: Arc<Mutex<AliasRegistry>>,
    path: &[u8],
) -> io::Result<()> {
    let mut bytes = path.to_vec();
    bytes.push(0);
    bytes.resize((bytes.len() + 255) & !255, 0);
    let mut memory = BridgeMemory::new(pid, pid as u64, aliases);
    let addr = memory.map_local(bytes)?;
    let caller = Caller::new(task, &memory).with_process_fork_allowed(false);
    match SyscallEntry(Dispatch)
        .call(
            &caller,
            Syscall::Chdir {
                filename: wasixv2_abi::Cstr::new(addr),
            },
            kernel,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(wasixv2_syscalls::SysErr::Errno(errno)) => {
            Err(io::Error::other(format!("WLK chdir failed: {errno:?}")))
        }
        Err(_) => Err(io::Error::other("WLK chdir failed")),
    }
}

fn map_iovecs(
    memory: &mut BridgeMemory,
    request: platform::Request,
    writable: bool,
) -> io::Result<Result<(u32, u32), i64>> {
    let count = request.args[2].min(1024) as usize;
    if request.args[2] > 1024 {
        return Ok(Err(-(libc::EINVAL as i64)));
    }
    let mut native = vec![0u8; count * 16];
    if !native.is_empty() && !read_remote(request.pid, request.args[1], &mut native) {
        return Ok(Err(-(libc::EFAULT as i64)));
    }
    let mut compat = Vec::with_capacity(count * 8);
    let mut budget = MAX_TRANSFER;
    for entry in native.chunks_exact(16) {
        let base = u64::from_le_bytes(entry[0..8].try_into().expect("iovec base"));
        let requested = u64::from_le_bytes(entry[8..16].try_into().expect("iovec length"));
        let len = bounded_len(requested).min(budget);
        budget -= len;
        let addr = memory.map(base, len, !writable, writable)?;
        compat.extend_from_slice(&addr.to_le_bytes());
        compat.extend_from_slice(&(len as u32).to_le_bytes());
    }
    let table = memory.map_local(compat)?;
    Ok(Ok((table, count as u32)))
}

pub(crate) fn read_remote(pid: libc::pid_t, address: u64, bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: the local slice is valid and the remote pointer is copied by the kernel from
    // the stopped tracee rather than dereferenced in this process.
    unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) == bytes.len() as isize }
}

struct Region {
    guest: u32,
    host: u64,
    len: usize,
    read: bool,
    write: bool,
    local: Option<Arc<[u8]>>,
}

pub(crate) struct BridgeMemory {
    pid: libc::pid_t,
    mm_id: u64,
    aliases: Arc<Mutex<AliasRegistry>>,
    regions: Vec<Region>,
    next: u32,
    next_local: u32,
}

impl BridgeMemory {
    pub(crate) fn new(pid: libc::pid_t, mm_id: u64, aliases: Arc<Mutex<AliasRegistry>>) -> Self {
        Self {
            pid,
            mm_id,
            aliases,
            regions: Vec::new(),
            next: memory::transient_base(),
            next_local: memory::local_scratch_base(),
        }
    }

    pub(crate) fn map(
        &mut self,
        host: u64,
        len: usize,
        read: bool,
        write: bool,
    ) -> io::Result<u32> {
        let aligned = self
            .next
            .checked_add(255)
            .ok_or_else(|| io::Error::other("scratch address overflow"))?
            & !255;
        let span = len
            .max(256)
            .checked_add(256)
            .ok_or_else(|| io::Error::other("scratch length overflow"))?;
        self.next = aligned
            .checked_add(
                u32::try_from(span).map_err(|_| io::Error::other("scratch range too large"))?,
            )
            .ok_or_else(|| io::Error::other("scratch range overflow"))?;
        self.regions.push(Region {
            guest: aligned,
            host,
            len,
            read,
            write,
            local: None,
        });
        Ok(aligned)
    }

    pub(crate) fn map_alias(
        &mut self,
        host: u64,
        len: usize,
        read: bool,
        write: bool,
    ) -> io::Result<u32> {
        let guest = self
            .aliases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .alias(self.mm_id, host)?;
        self.regions.push(Region {
            guest,
            host,
            len,
            read,
            write,
            local: None,
        });
        Ok(guest)
    }

    pub(crate) fn map_local(&mut self, bytes: Vec<u8>) -> io::Result<u32> {
        let local: Arc<[u8]> = bytes.into();
        let len = local.len();
        let aligned = self
            .next_local
            .checked_add(255)
            .ok_or_else(|| io::Error::other("scratch address overflow"))?
            & !255;
        let span = len
            .max(256)
            .checked_add(256)
            .ok_or_else(|| io::Error::other("scratch length overflow"))?;
        self.next_local = aligned
            .checked_add(
                u32::try_from(span).map_err(|_| io::Error::other("scratch range too large"))?,
            )
            .ok_or_else(|| io::Error::other("scratch range overflow"))?;
        self.regions.push(Region {
            guest: aligned,
            host: 0,
            len,
            read: true,
            write: false,
            local: Some(local),
        });
        Ok(aligned)
    }

    fn transfer(&self, addr: u32, bytes: &mut [u8], write: bool) -> Result<(), Fault> {
        if bytes.is_empty() {
            return Ok(());
        }
        let region = self.regions.iter().find(|region| {
            let end = u64::from(region.guest) + region.len as u64;
            u64::from(addr) >= u64::from(region.guest)
                && u64::from(addr) + bytes.len() as u64 <= end
        });
        let remote_addr = if let Some(region) = region {
            if (write && !region.write) || (!write && !region.read) {
                return Err(Fault);
            }
            let offset = u64::from(addr - region.guest);
            if let Some(local) = &region.local {
                if write {
                    return Err(Fault);
                }
                let start = offset as usize;
                bytes.copy_from_slice(local.get(start..start + bytes.len()).ok_or(Fault)?);
                return Ok(());
            }
            region.host.checked_add(offset).ok_or(Fault)?
        } else {
            // TODO(native): retained sync-word aliases outlive a syscall's transient region list.
            self.aliases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resolve(self.mm_id, addr, bytes.len())
                .ok_or(Fault)?
        };
        if remote_addr == 0 {
            return Err(Fault);
        }
        // SAFETY: local points at a live Rust slice; the remote pointer is an address in the
        // stopped tracee, and process_vm_* copies without dereferencing it in this process.
        let local = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let remote = libc::iovec {
            iov_base: remote_addr as usize as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        let copied = unsafe {
            if write {
                libc::process_vm_writev(self.pid, &local, 1, &remote, 1, 0)
            } else {
                libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0)
            }
        };
        (copied == bytes.len() as isize).then_some(()).ok_or(Fault)
    }
}

impl UserMemory for BridgeMemory {
    fn read<'a>(
        &'a self,
        addr: u32,
        buf: &'a mut [u8],
    ) -> wasixv2_syscalls::LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move { self.transfer(addr, buf, false) })
    }

    fn write<'a>(
        &'a self,
        addr: u32,
        data: &'a [u8],
    ) -> wasixv2_syscalls::LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let mut copy = data.to_vec();
            self.transfer(addr, &mut copy, true)
        })
    }

    fn size(&self) -> wasixv2_syscalls::LocalFuture<'_, u64> {
        Box::pin(async { u32::MAX as u64 })
    }
    fn grow(&self, _pages: u32) -> wasixv2_syscalls::LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }

    fn can_duplicate(&self) -> wasixv2_syscalls::LocalFuture<'_, bool> {
        // TODO(native): Linux fork provides the real copy-on-write address space; WLK only sees
        // its bookkeeping task, while NativeMemory continues to proxy each host TID's memory.
        Box::pin(async { true })
    }
}
