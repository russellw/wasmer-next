//! Looking at and into other processes: `kcmp`, `pidfd_getfd`, Yama's ptrace scope and
//! `PR_SET_PTRACER`, I/O priorities, and the memory calls that only check or count (`mseal`,
//! `cachestat`, `process_madvise`), and `vhangup`.

use wasixv2_abi::{
    Cachestat, CachestatRange, EpollCreateFlags, EpollCtlOp, EpollEvent, FcntlCmd, IoprioClass,
    IoprioWho, KcmpEpollSlot, KcmpType, MadviseAdvice, MapFlags, PrctlOption, ProtFlags,
};
use wasixv2_syscalls::{read_value, write_value};

use super::{
    cred::{machine_as, set_caps},
    ipc::{errno, pipe, put},
    proc::{ForkableMemory, fork_child},
    *,
};

/// 64 KiB of memory a fork can duplicate.
fn memory() -> ForkableMemory {
    ForkableMemory(FlatMemory(RefCell::new(vec![0; 65536])))
}

fn kcmp(
    kernel: &Kernel,
    caller: &Caller<'_>,
    p1: TaskId,
    p2: TaskId,
    ty: KcmpType,
) -> SysResult<i32> {
    kcmp_idx(kernel, caller, (p1, 0), (p2, 0), ty)
}

fn kcmp_idx(
    kernel: &Kernel,
    caller: &Caller<'_>,
    (p1, idx1): (TaskId, u32),
    (p2, idx2): (TaskId, u32),
    ty: KcmpType,
) -> SysResult<i32> {
    block_on(kernel.kcmp(caller, p1.0 as i32, p2.0 as i32, ty.0, idx1, idx2))
}

const RESOURCES: [KcmpType; 6] = [
    KcmpType::KCMP_VM,
    KcmpType::KCMP_FILES,
    KcmpType::KCMP_FS,
    KcmpType::KCMP_SIGHAND,
    KcmpType::KCMP_IO,
    KcmpType::KCMP_SYSVSEM,
];

/// `kcmp`: a task shares everything with itself; a fork child shares no table with its parent,
/// but the files it inherited; the order of two different resources reverses with the
/// arguments.
#[test]
fn kcmp_compares_what_tasks_share() {
    let (kernel, parent, _) = setup(b"");
    let memory = memory();
    let caller = Caller::new(parent, &memory);
    let (rd, wr) = pipe(&kernel, &caller, OpenFlags::empty());
    let child = fork_child(&kernel, &caller);

    for ty in RESOURCES {
        assert_eq!(kcmp(&kernel, &caller, parent, parent, ty), Ok(0), "{ty:?}");
    }
    for ty in [
        KcmpType::KCMP_VM,
        KcmpType::KCMP_FILES,
        KcmpType::KCMP_FS,
        KcmpType::KCMP_SIGHAND,
    ] {
        let there = kcmp(&kernel, &caller, parent, child, ty).unwrap();
        let back = kcmp(&kernel, &caller, child, parent, ty).unwrap();
        assert!(
            matches!((there, back), (1, 2) | (2, 1)),
            "{ty:?}: {there} {back}"
        );
    }
    // Neither set an I/O priority or has semaphore adjustments: both have none, which is equal.
    assert_eq!(
        kcmp(&kernel, &caller, parent, child, KcmpType::KCMP_IO),
        Ok(0)
    );
    assert_eq!(
        kcmp(&kernel, &caller, parent, child, KcmpType::KCMP_SYSVSEM),
        Ok(0)
    );

    let file = KcmpType::KCMP_FILE;
    let same = kcmp_idx(
        &kernel,
        &caller,
        (parent, rd.0 as u32),
        (child, rd.0 as u32),
        file,
    );
    assert_eq!(same, Ok(0));
    let other = kcmp_idx(
        &kernel,
        &caller,
        (parent, rd.0 as u32),
        (child, wr.0 as u32),
        file,
    );
    assert!(matches!(other, Ok(1 | 2)));
    let closed = kcmp_idx(&kernel, &caller, (parent, 99), (child, rd.0 as u32), file);
    assert_eq!(errno(closed), Errno::EBADF);

    assert_eq!(
        errno(kcmp(&kernel, &caller, parent, parent, KcmpType(8))),
        Errno::EINVAL
    );
    assert_eq!(
        errno(kcmp(&kernel, &caller, TaskId(0), parent, KcmpType::KCMP_VM)),
        Errno::ESRCH
    );
    assert_eq!(
        errno(kcmp(
            &kernel,
            &caller,
            TaskId(999),
            parent,
            KcmpType::KCMP_VM
        )),
        Errno::ESRCH
    );
}

/// `KCMP_EPOLL_TFD`: a file against the target an epoll watches with a descriptor number, the
/// `toff`-th of those.
#[test]
fn kcmp_finds_a_file_an_epoll_watches() {
    let (kernel, task, _) = setup(b"");
    let memory = memory();
    let caller = Caller::new(task, &memory);
    let (rd, _wr) = pipe(&kernel, &caller, OpenFlags::empty());
    let epfd = block_on(kernel.epoll_create1(&caller, EpollCreateFlags::empty())).unwrap();
    let event = EpollEvent::default();
    block_on(write_value(&memory, GuestPtrMut::new(0x300), &event)).unwrap();
    let ctl = kernel.epoll_ctl(
        &caller,
        epfd,
        EpollCtlOp::EPOLL_CTL_ADD,
        rd,
        GuestPtr::new(0x300),
    );
    assert_eq!(block_on(ctl), Ok(0));

    let slot = |toff: u32| {
        let slot = KcmpEpollSlot {
            efd: epfd.0 as u32,
            tfd: rd.0 as u32,
            toff,
        };
        block_on(write_value(&memory, GuestPtrMut::new(0x400), &slot)).unwrap();
        kcmp_idx(
            &kernel,
            &caller,
            (task, rd.0 as u32),
            (task, 0x400),
            KcmpType::KCMP_EPOLL_TFD,
        )
    };
    assert_eq!(slot(0), Ok(0));
    assert_eq!(errno(slot(1)), Errno::ENOENT);
    // The epoll descriptor must be one.
    let slot = KcmpEpollSlot {
        efd: rd.0 as u32,
        tfd: rd.0 as u32,
        toff: 0,
    };
    block_on(write_value(&memory, GuestPtrMut::new(0x400), &slot)).unwrap();
    let not_epoll = kcmp_idx(
        &kernel,
        &caller,
        (task, rd.0 as u32),
        (task, 0x400),
        KcmpType::KCMP_EPOLL_TFD,
    );
    assert_eq!(errno(not_epoll), Errno::EINVAL);
}

/// `kcmp` needs `PTRACE_MODE_READ_REALCREDS` over both tasks: an unprivileged process may not
/// look into root's.
#[test]
fn kcmp_of_a_more_privileged_process_is_eperm() {
    let (kernel, root, _) = machine_as(0, 0);
    let memory = memory();
    let caller = Caller::new(root, &memory);
    let child = fork_child(&kernel, &caller);
    let child_memory = memory_flat();
    let child_caller = Caller::new(child, &child_memory);
    assert_eq!(
        block_on(kernel.setresuid(&child_caller, 1000, 1000, 1000)),
        Ok(0)
    );

    let vm = KcmpType::KCMP_VM;
    assert_eq!(
        errno(kcmp(&kernel, &child_caller, child, root, vm)),
        Errno::EPERM
    );
    assert!(kcmp(&kernel, &caller, child, root, vm).is_ok());
}

fn memory_flat() -> FlatMemory {
    FlatMemory(RefCell::new(vec![0; 65536]))
}

/// `pidfd_getfd`: a close-on-exec duplicate of another process's open file, for a caller that
/// may attach to it; Yama keeps a child from attaching to its parent unless the parent named it
/// with `PR_SET_PTRACER`.
#[test]
fn pidfd_getfd_duplicates_a_file_of_a_process_one_may_attach_to() {
    let (kernel, parent, _) = setup(b"");
    let memory = memory();
    let caller = Caller::new(parent, &memory);
    let child = fork_child(&kernel, &caller);
    let child_memory = memory_flat();
    let child_caller = Caller::new(child, &child_memory);
    let (rd, _wr) = pipe(&kernel, &child_caller, OpenFlags::empty());

    let pidfd = block_on(kernel.pidfd_open(&caller, child.0 as i32, 0)).unwrap();
    let fd = block_on(kernel.pidfd_getfd(&caller, pidfd, rd, 0)).unwrap();
    let same = kcmp_idx(
        &kernel,
        &caller,
        (parent, fd as u32),
        (child, rd.0 as u32),
        KcmpType::KCMP_FILE,
    );
    assert_eq!(same, Ok(0));
    let flags = block_on(kernel.fcntl64(&caller, Fd(fd), FcntlCmd::F_GETFD, 0)).unwrap();
    assert_eq!(flags, 1, "FD_CLOEXEC");

    assert_eq!(
        errno(block_on(kernel.pidfd_getfd(&caller, pidfd, rd, 1))),
        Errno::EINVAL
    );
    assert_eq!(
        errno(block_on(kernel.pidfd_getfd(&caller, pidfd, Fd(77), 0))),
        Errno::EBADF
    );
    assert_eq!(
        errno(block_on(kernel.pidfd_getfd(&caller, Fd(fd), rd, 0))),
        Errno::EBADF
    );

    // The child going the other way: its parent is no descendant of it.
    let up = block_on(kernel.pidfd_open(&child_caller, parent.0 as i32, 0)).unwrap();
    let (prd, _pwr) = pipe(&kernel, &caller, OpenFlags::empty());
    let attach = || block_on(kernel.pidfd_getfd(&child_caller, up, prd, 0));
    assert_eq!(errno(attach()), Errno::EPERM);
    let ptracer = kernel.prctl(&caller, PrctlOption::PR_SET_PTRACER, child.0, 0, 0, 0);
    assert_eq!(block_on(ptracer), Ok(0));
    assert!(attach().is_ok());
    let forget = kernel.prctl(&caller, PrctlOption::PR_SET_PTRACER, 0, 0, 0, 0);
    assert_eq!(block_on(forget), Ok(0));
    assert_eq!(errno(attach()), Errno::EPERM);
    let any = kernel.prctl(&caller, PrctlOption::PR_SET_PTRACER, u32::MAX, 0, 0, 0);
    assert_eq!(block_on(any), Ok(0));
    assert!(attach().is_ok());
    let nobody = kernel.prctl(&caller, PrctlOption::PR_SET_PTRACER, 4242, 0, 0, 0);
    assert_eq!(errno(block_on(nobody)), Errno::EINVAL);
}

/// With `ptrace_scope` 0 Yama adds nothing; with 3 nobody attaches, not even to a child.
#[test]
fn the_ptrace_scope_decides_who_attaches() {
    let (kernel, parent, _) = setup(b"");
    let memory = memory();
    let caller = Caller::new(parent, &memory);
    let child = fork_child(&kernel, &caller);
    let child_memory = memory_flat();
    let child_caller = Caller::new(child, &child_memory);
    let (rd, _wr) = pipe(&kernel, &caller, OpenFlags::empty());
    let up = block_on(kernel.pidfd_open(&child_caller, parent.0 as i32, 0)).unwrap();
    let down = block_on(kernel.pidfd_open(&caller, child.0 as i32, 0)).unwrap();

    kernel.yama.set_scope(0).unwrap();
    assert!(block_on(kernel.pidfd_getfd(&child_caller, up, rd, 0)).is_ok());
    kernel.yama.set_scope(3).unwrap();
    assert_eq!(
        errno(block_on(kernel.pidfd_getfd(&caller, down, rd, 0))),
        Errno::EPERM
    );
}

fn ioprio_get(kernel: &Kernel, caller: &Caller<'_>, who: IoprioWho, id: i32) -> SysResult<i32> {
    block_on(kernel.ioprio_get(caller, who.0, id))
}

fn ioprio(class: IoprioClass, level: i32) -> i32 {
    class.0 << 13 | level
}

/// `ioprio_set` and `ioprio_get`: a process reads the priority it set, `IOPRIO_DEFAULT` before
/// that; a group's best priority counts what each nice value gives a task that set none; fork
/// children inherit a priority that was set.
#[test]
fn io_priorities_are_set_read_and_inherited() {
    let (kernel, task, _) = setup(b"");
    let memory = memory();
    let caller = Caller::new(task, &memory);
    let process = IoprioWho::IOPRIO_WHO_PROCESS;
    assert_eq!(ioprio_get(&kernel, &caller, process, 0), Ok(0));
    // A group whose tasks set nothing: best effort, at nice 0's level 4.
    let be4 = ioprio(IoprioClass::IOPRIO_CLASS_BE, 4);
    assert_eq!(
        ioprio_get(&kernel, &caller, IoprioWho::IOPRIO_WHO_PGRP, 0),
        Ok(be4)
    );

    let idle = ioprio(IoprioClass::IOPRIO_CLASS_IDLE, 0);
    assert_eq!(
        block_on(kernel.ioprio_set(&caller, process.0, 0, idle)),
        Ok(0)
    );
    assert_eq!(ioprio_get(&kernel, &caller, process, 0), Ok(idle));
    let child = fork_child(&kernel, &caller);
    assert_eq!(
        ioprio_get(&kernel, &caller, process, child.0 as i32),
        Ok(idle)
    );
    // Each has a context of its own: no `CLONE_IO`.
    assert!(matches!(
        kcmp(&kernel, &caller, task, child, KcmpType::KCMP_IO),
        Ok(1 | 2)
    ));

    let set =
        |prio: i32, which: i32, who: i32| block_on(kernel.ioprio_set(&caller, which, who, prio));
    let rt = ioprio(IoprioClass::IOPRIO_CLASS_RT, 0);
    assert_eq!(
        errno(set(rt, process.0, 0)),
        Errno::EPERM,
        "RT needs CAP_SYS_NICE"
    );
    assert_eq!(
        errno(set(ioprio(IoprioClass::IOPRIO_CLASS_NONE, 1), process.0, 0)),
        Errno::EINVAL
    );
    assert_eq!(
        errno(set(
            ioprio(IoprioClass::IOPRIO_CLASS_INVALID, 0),
            process.0,
            0
        )),
        Errno::EINVAL
    );
    assert_eq!(errno(set(idle, 9, 0)), Errno::EINVAL);
    assert_eq!(errno(set(idle, process.0, 4242)), Errno::ESRCH);
    assert_eq!(
        errno(ioprio_get(&kernel, &caller, IoprioWho(0), 0)),
        Errno::EINVAL
    );
}

/// Another user's task needs `CAP_SYS_NICE`; root may raise to the real-time class.
#[test]
fn io_priorities_of_other_users_need_cap_sys_nice() {
    let (kernel, root, _) = machine_as(0, 0);
    let memory = memory();
    let caller = Caller::new(root, &memory);
    let child = fork_child(&kernel, &caller);
    let child_memory = memory_flat();
    let child_caller = Caller::new(child, &child_memory);
    let rt = ioprio(IoprioClass::IOPRIO_CLASS_RT, 2);
    let process = IoprioWho::IOPRIO_WHO_PROCESS.0;
    assert_eq!(block_on(kernel.ioprio_set(&caller, process, 0, rt)), Ok(0));
    assert_eq!(
        block_on(kernel.setresuid(&child_caller, 1000, 1000, 1000)),
        Ok(0)
    );
    let be = ioprio(IoprioClass::IOPRIO_CLASS_BE, 0);
    let theirs = kernel.ioprio_set(&child_caller, process, root.0 as i32, be);
    assert_eq!(errno(block_on(theirs)), Errno::EPERM);
    assert_eq!(
        block_on(kernel.ioprio_set(&caller, process, child.0 as i32, be)),
        Ok(0)
    );
}

/// `mseal` checks its arguments and that the range is mapped; a 32-bit kernel seals nothing.
#[test]
fn mseal_checks_and_seals_nothing_on_32_bit() {
    let (kernel, task, _) = setup(b"");
    let memory = memory_flat();
    let caller = Caller::new(task, &memory);
    let page = crate::mm::PAGE_SIZE as u32;
    let rw = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
    let anon = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
    let addr = block_on(kernel.mmap(&caller, 0, page, rw, anon, Fd(-1), 0)).unwrap();

    assert_eq!(block_on(kernel.mseal(&caller, addr, page, 0)), Ok(0));
    assert_eq!(
        errno(block_on(kernel.mseal(&caller, addr, page, 1))),
        Errno::EINVAL
    );
    assert_eq!(
        errno(block_on(kernel.mseal(&caller, addr + 1, page, 0))),
        Errno::EINVAL
    );
    assert_eq!(
        errno(block_on(kernel.mseal(&caller, addr, u32::MAX, 0))),
        Errno::EINVAL
    );
    assert_eq!(block_on(kernel.mseal(&caller, addr, 0, 0)), Ok(0));
    let past = kernel.mseal(&caller, addr + page, page, 0);
    assert_eq!(errno(block_on(past)), Errno::ENOMEM);
    // Nothing is sealed: the mapping still goes.
    assert_eq!(block_on(kernel.munmap(&caller, addr, page)), Ok(0));
}

/// `cachestat`: every page of the file's data in the range is cached and clean.
#[test]
fn cachestat_counts_the_files_pages() {
    let (kernel, task, _) = setup(b"");
    let memory = memory_flat();
    let caller = Caller::new(task, &memory);
    let page = crate::mm::PAGE_SIZE;
    let fd = super::mapping::open(
        &kernel,
        &caller,
        b"/f",
        OpenFlags::O_CREAT | OpenFlags::O_RDWR,
    );
    assert_eq!(
        block_on(kernel.ftruncate64(&caller, fd, (2 * page + 1) as i64)),
        Ok(0)
    );

    let stat = |off: u64, len: u64, flags: u32| {
        let range = CachestatRange { off, len };
        block_on(write_value(&memory, GuestPtrMut::new(0x100), &range)).unwrap();
        block_on(kernel.cachestat(
            &caller,
            fd,
            GuestPtr::new(0x100),
            GuestPtrMut::new(0x200),
            flags,
        ))?;
        let out: Cachestat = block_on(read_value(&memory, GuestPtr::new(0x200))).unwrap();
        Ok::<_, SysErr>(out)
    };
    assert_eq!(stat(0, 0, 0).unwrap().nr_cache, 3);
    assert_eq!(stat(page, page, 0).unwrap().nr_cache, 1);
    assert_eq!(stat(5 * page, 0, 0).unwrap().nr_cache, 0);
    let all = stat(0, 0, 0).unwrap();
    assert_eq!((all.nr_dirty, all.nr_writeback, all.nr_evicted), (0, 0, 0));
    assert_eq!(errno(stat(0, 0, 1)), Errno::EINVAL);
    assert_eq!(
        errno(block_on(kernel.cachestat(
            &caller,
            Fd(55),
            GuestPtr::new(0x100),
            GuestPtrMut::new(0x200),
            0
        ))),
        Errno::EBADF
    );
}

/// `process_madvise`: any advice on the caller's own memory (`PIDFD_SELF`), only the
/// non-destructive hints on another process's, with `CAP_SYS_NICE`.
#[test]
fn process_madvise_takes_hints_for_other_processes() {
    let (kernel, root, _) = machine_as(0, 0);
    let memory = memory();
    let caller = Caller::new(root, &memory);
    let page = crate::mm::PAGE_SIZE as u32;
    let rw = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
    let anon = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
    let addr = block_on(kernel.mmap(&caller, 0, page, rw, anon, Fd(-1), 0)).unwrap();
    put(&memory.0, 0x100, &addr.to_le_bytes());
    put(&memory.0, 0x104, &page.to_le_bytes());
    let vec = GuestPtr::new(0x100);
    let advise = |caller: &Caller<'_>, pidfd: Fd, advice: MadviseAdvice| {
        block_on(kernel.process_madvise(caller, pidfd, vec, 1, advice, 0))
    };
    let self_group = Fd(wasixv2_abi::PidfdSelf::PIDFD_SELF_THREAD_GROUP.0);
    assert_eq!(
        advise(&caller, self_group, MadviseAdvice::MADV_DONTNEED),
        Ok(page as i32)
    );

    let child = fork_child(&kernel, &caller);
    let pidfd = block_on(kernel.pidfd_open(&caller, child.0 as i32, 0)).unwrap();
    assert_eq!(
        errno(advise(&caller, pidfd, MadviseAdvice::MADV_DONTNEED)),
        Errno::EINVAL
    );
    assert_eq!(
        advise(&caller, pidfd, MadviseAdvice::MADV_WILLNEED),
        Ok(page as i32)
    );
    assert_eq!(
        errno(block_on(kernel.process_madvise(
            &caller,
            pidfd,
            vec,
            1,
            MadviseAdvice::MADV_COLD,
            1
        ))),
        Errno::EINVAL
    );

    // Without CAP_SYS_NICE (the parent keeps every other capability).
    set_caps(&kernel, &caller, &memory.0, !(1 << 23) & ((1 << 41) - 1));
    assert_eq!(
        errno(advise(&caller, pidfd, MadviseAdvice::MADV_WILLNEED)),
        Errno::EPERM
    );
}

/// `vhangup` needs `CAP_SYS_TTY_CONFIG`; without a controlling terminal it has nothing to do.
#[test]
fn vhangup_needs_cap_sys_tty_config() {
    let (kernel, task, _) = setup(b"");
    let memory = memory_flat();
    let caller = Caller::new(task, &memory);
    assert_eq!(errno(block_on(kernel.vhangup(&caller))), Errno::EPERM);
    let (kernel, root, _) = machine_as(0, 0);
    let caller = Caller::new(root, &memory);
    assert_eq!(block_on(kernel.vhangup(&caller)), Ok(0));
}

/// Memory other tasks may reach from any thread, as the execution layer hands over a shared
/// memory ([`SharedMappings::attach_memory`]): `len` bytes, the first `guard` of them not
/// writable.
pub(super) struct SyncMemory {
    bytes: Mutex<Vec<u8>>,
    guard: u32,
}

impl SyncMemory {
    pub(super) fn new(len: usize, guard: u32) -> Arc<Self> {
        Arc::new(Self {
            bytes: Mutex::new(vec![0; len]),
            guard,
        })
    }

    pub(super) fn put(&self, addr: u32, data: &[u8]) {
        self.bytes.lock().unwrap()[addr as usize..][..data.len()].copy_from_slice(data);
    }

    pub(super) fn get(&self, addr: u32, len: usize) -> Vec<u8> {
        self.bytes.lock().unwrap()[addr as usize..][..len].to_vec()
    }
}

impl UserMemory for SyncMemory {
    fn read<'a>(&'a self, addr: u32, buf: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        let bytes = self.bytes.lock().unwrap();
        let src = bytes.get(addr as usize..addr as usize + buf.len());
        let result = src.map(|src| buf.copy_from_slice(src)).ok_or(Fault);
        Box::pin(async move { result })
    }

    fn write<'a>(&'a self, addr: u32, data: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        let mut bytes = self.bytes.lock().unwrap();
        let result = match addr < self.guard {
            true => Err(Fault),
            false => bytes
                .get_mut(addr as usize..addr as usize + data.len())
                .map(|dst| dst.copy_from_slice(data))
                .ok_or(Fault),
        };
        Box::pin(async move { result })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        let size = self.bytes.lock().unwrap().len() as u64;
        Box::pin(async move { size })
    }

    fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}

/// `access_remote_vm` copies through the memory the execution layer handed over, a page at a
/// time up to the first fault, and nothing once the last task left the memory.
#[test]
fn remote_access_goes_through_the_attached_memory_until_mmput() {
    let (kernel, task, _) = setup(b"");
    let memory = memory_flat();
    let caller = Caller::new(task, &memory);
    let page = crate::mm::PAGE_SIZE as u32;
    let mm = kernel.mm(task);
    let mut buf = [0; 4];
    let read = |mm: &crate::mm::Mm, addr: u32, buf: &mut [u8]| {
        block_on(crate::ptrace::access_remote_vm(
            mm,
            addr,
            crate::ptrace::Access::Read(buf),
            true,
        ))
    };
    assert_eq!(read(&mm, 0, &mut buf), 0, "nothing attached");

    let shared = SyncMemory::new(2 * page as usize, 16);
    shared.put(page - 2, b"abcd");
    kernel.attach_memory(task, shared.clone());
    assert_eq!(read(&mm, page - 2, &mut buf), 4);
    assert_eq!(&buf, b"abcd");
    let mut long = vec![0; 8];
    assert_eq!(read(&mm, 2 * page - 4, &mut long), 4, "up to the end");
    let write = crate::ptrace::Access::Write(b"wxyz");
    assert_eq!(
        block_on(crate::ptrace::access_remote_vm(&mm, 0x100, write, true)),
        4
    );
    assert_eq!(shared.get(0x100, 4), b"wxyz");
    let guard = crate::ptrace::Access::Write(b"z");
    assert_eq!(
        block_on(crate::ptrace::access_remote_vm(&mm, 0, guard, true)),
        0
    );

    block_on(kernel.exit_mmap(&caller));
    assert_eq!(read(&mm, page - 2, &mut buf), 0, "the last user left");
}

/// `remap_file_pages`: a page of a shared file mapping shows another page of the file; a
/// private mapping, a `prot` or an empty range are `EINVAL`.
#[test]
fn remap_file_pages_shows_another_page_of_the_file() {
    let (kernel, task, _) = setup(b"");
    let memory = FlatMemory(RefCell::new(vec![0; 4 * 65536]));
    let caller = Caller::new(task, &memory);
    let page = crate::mm::PAGE_SIZE as u32;
    let fd = super::mapping::open(
        &kernel,
        &caller,
        b"/f",
        OpenFlags::O_CREAT | OpenFlags::O_RDWR,
    );
    for (i, byte) in [b'a', b'b', b'c'].into_iter().enumerate() {
        put(&memory, 0x100, &vec![byte; page as usize]);
        let write = kernel.pwrite64(
            &caller,
            fd,
            UserSlice::new(0x100, page),
            i64::from(page) * i as i64,
        );
        assert_eq!(block_on(write), Ok(page));
    }
    let rw = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
    let shared = MapFlags::MAP_SHARED;
    let addr = block_on(kernel.mmap(&caller, 0, 2 * page, rw, shared, fd, 0)).unwrap();
    assert_eq!(get_flat(&memory, addr + page, 1), b"b");

    let remap = |start: u32, size: u32, prot: u32, pgoff: u32| {
        block_on(kernel.remap_file_pages(&caller, start, size, prot, pgoff, 0))
    };
    assert_eq!(remap(addr + page, page, 0, 2), Ok(0));
    assert_eq!(get_flat(&memory, addr + page, 1), b"c");
    assert_eq!(get_flat(&memory, addr, 1), b"a", "the rest stays");
    assert_eq!(errno(remap(addr, page, 1, 2)), Errno::EINVAL);
    assert_eq!(errno(remap(addr, 0, 0, 2)), Errno::EINVAL);
    let private = MapFlags::MAP_PRIVATE;
    let other = block_on(kernel.mmap(&caller, 0, page, rw, private, fd, 0)).unwrap();
    assert_eq!(errno(remap(other, page, 0, 1)), Errno::EINVAL);
}

fn get_flat(memory: &FlatMemory, addr: u32, len: usize) -> Vec<u8> {
    super::ipc::get(memory, addr, len)
}

#[test]
fn process_mrelease_discards_dying_private_pages_and_keeps_shared_mappings() {
    let (kernel, parent, _) = setup(b"");
    let parent_memory = memory();
    let caller = Caller::new(parent, &parent_memory);
    let child = fork_child(&kernel, &caller);
    let child_memory = memory_flat();
    let child_caller = Caller::new(child, &child_memory);
    let page = crate::mm::PAGE_SIZE as u32;
    let fd = super::mapping::open(
        &kernel,
        &child_caller,
        b"/shared-reap",
        OpenFlags::O_CREAT | OpenFlags::O_RDWR,
    );
    assert_eq!(
        block_on(kernel.ftruncate64(&child_caller, fd, page.into())),
        Ok(0)
    );
    let shared_addr = block_on(kernel.mmap(
        &child_caller,
        0,
        page,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_SHARED,
        fd,
        0,
    ))
    .unwrap();
    let size = child_memory.0.borrow().len();
    let remote = SyncMemory::new(size, 0);
    remote.put(0, &child_memory.0.borrow());
    remote.put(0x100, b"private");
    remote.put(shared_addr, b"shared");
    kernel.attach_memory(child, remote.clone());
    let pidfd = block_on(kernel.pidfd_open(&caller, child.0 as i32, 0)).unwrap();
    assert_eq!(
        errno(block_on(kernel.process_mrelease(&caller, Fd(-1), 1))),
        Errno::EINVAL
    );
    assert_eq!(
        errno(block_on(kernel.process_mrelease(&caller, Fd(-1), 0))),
        Errno::EBADF
    );
    assert_eq!(
        errno(block_on(kernel.process_mrelease(&caller, pidfd, 0))),
        Errno::EINVAL
    );
    kernel.do_group_exit(child, 0);
    let regions = kernel.mm(child).regions();
    assert_eq!(block_on(kernel.process_mrelease(&caller, pidfd, 0)), Ok(0));
    assert_eq!(remote.get(0x100, 7), vec![0; 7]);
    assert_eq!(remote.get(shared_addr, 6), b"shared");
    assert_eq!(
        kernel.mm(child).regions(),
        regions,
        "reaping preserves VMAs"
    );
    assert_eq!(block_on(kernel.process_mrelease(&caller, pidfd, 0)), Ok(0));
    // Once every thread left its mm, Linux reports ESRCH even before wait reaps it.
    block_on(kernel.exit_mm(&Caller::new(child, &*remote)));
    assert_eq!(
        errno(block_on(kernel.process_mrelease(&caller, pidfd, 0))),
        Errno::ESRCH
    );
}

#[test]
fn process_mrelease_waits_for_shared_mm_users_and_core_dump() {
    use wasixv2_abi::{CloneFlags, Siginfo};
    let (kernel, parent, _) = setup(b"");
    let parent_memory = memory();
    let caller = Caller::new(parent, &parent_memory);
    let child = fork_child(&kernel, &caller);
    let remote = SyncMemory::new(65536, 0);
    kernel.attach_memory(child, remote.clone());
    let child_caller = Caller::new(child, &*remote);
    let pidfd = block_on(kernel.pidfd_open(&caller, child.0 as i32, 0)).unwrap();
    let shared_child = block_on(kernel.thread_spawn(
        &child_caller,
        (CloneFlags::CLONE_VM.0 | 17) as u32,
        0x40,
        GuestPtrMut::NULL,
        0,
        GuestPtrMut::NULL,
    ))
    .unwrap();
    while kernel.take_pending(child).is_some() {}
    // A core request stays visible until coredump_if_dumper has finished, preventing reaping.
    kernel.coredump_request(
        child,
        Siginfo {
            si_signo: Signal::SIGABRT.0,
            ..Default::default()
        },
    );
    kernel.do_group_exit(child, 0);
    assert_eq!(
        errno(block_on(kernel.process_mrelease(&caller, pidfd, 0))),
        Errno::EINVAL
    );
    block_on(kernel.coredump_if_dumper(&child_caller));
    // An unrelated thread group on the same mm remains alive.
    assert_eq!(
        errno(block_on(kernel.process_mrelease(&caller, pidfd, 0))),
        Errno::EINVAL
    );
    kernel.do_group_exit(TaskId(shared_child as u32), 0);
    assert_eq!(block_on(kernel.process_mrelease(&caller, pidfd, 0)), Ok(0));
}

#[test]
fn review_foreign_attach_keeps_first_handle_and_ignores_exited_memory() {
    let (kernel, task, _) = setup(b"");
    let memory = FlatMemory(RefCell::new(vec![0; 65536]));
    let first = SyncMemory::new(65536, 0);
    let second = SyncMemory::new(65536, 0);
    first.put(0x100, b"first");
    second.put(0x100, b"other");
    kernel.attach_memory(task, first);
    kernel.attach_memory(task, second.clone());
    let mm = kernel.mm(task);
    let mut bytes = [0; 5];
    block_on(mm.foreign().unwrap().read(0x100, &mut bytes)).unwrap();
    assert_eq!(&bytes, b"first");
    block_on(kernel.exit_mm(&Caller::new(task, &memory)));
    assert!(mm.foreign().is_none());
    kernel.attach_memory(task, second);
    assert!(
        mm.foreign().is_none(),
        "late instantiation must not resurrect an exited image"
    );
}

/// A selector resolves once; direct methods deliberately fault so accidental
/// per-method use cannot make the operation proof pass.
pub(super) struct ForeignSelector {
    current: Mutex<Arc<dyn UserMemory + Send + Sync>>,
    captures: std::sync::atomic::AtomicUsize,
    next: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl ForeignSelector {
    pub(super) fn new(current: Arc<dyn UserMemory + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(current),
            captures: Default::default(),
            next: Mutex::new(None),
        })
    }
    pub(super) fn publish(&self, next: Arc<dyn UserMemory + Send + Sync>) {
        let old = std::mem::replace(&mut *self.current.lock().unwrap(), next);
        drop(old);
    }
    pub(super) fn captures(&self) -> usize {
        self.captures.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub(super) fn after_capture(&self, callback: impl FnOnce() + Send + 'static) {
        assert!(
            self.next
                .lock()
                .unwrap()
                .replace(Box::new(callback))
                .is_none()
        );
    }
}
impl UserMemory for ForeignSelector {
    fn foreign_snapshot(&self) -> Option<Arc<dyn UserMemory + Send + Sync>> {
        let memory = { self.current.lock().unwrap().clone() };
        self.captures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let callback = { self.next.lock().unwrap().take() };
        if let Some(callback) = callback {
            callback();
        }
        Some(memory)
    }
    fn read<'a>(&'a self, _: u32, _: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async { Err(Fault) })
    }
    fn write<'a>(&'a self, _: u32, _: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async { Err(Fault) })
    }
    fn size(&self) -> LocalFuture<'_, u64> {
        Box::pin(async { 0 })
    }
    fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}

#[test]
fn foreign_snapshot_keeps_remote_copy_and_reaper_on_the_captured_backing() {
    for reap in [false, true] {
        let (kernel, parent, _) = setup(b"");
        let parent_memory = memory();
        let caller = Caller::new(parent, &parent_memory);
        let task = if reap {
            fork_child(&kernel, &caller)
        } else {
            parent
        };
        let page = crate::mm::PAGE_SIZE as u32;
        let first = SyncMemory::new(2 * page as usize, 0);
        let second = SyncMemory::new(2 * page as usize, 0);
        first.put(page - 2, b"old!");
        second.put(page - 2, b"new!");
        assert!(
            first.foreign_snapshot().is_none(),
            "ordinary memories stay concrete"
        );
        let selector = ForeignSelector::new(first.clone());
        kernel.attach_memory(task, selector.clone());
        let mm = kernel.mm(task);
        assert!(mm.has_foreign());
        assert!(!mm.loader_fresh());
        assert_eq!(
            selector.captures(),
            0,
            "presence checks do not select memory"
        );
        let publish = Arc::downgrade(&selector);
        let next = second.clone();
        let checked_mm = Arc::downgrade(&mm);
        selector.after_capture(move || {
            // This reacquires the slot: the snapshot hook must run outside it.
            assert!(checked_mm.upgrade().unwrap().has_foreign());
            publish.upgrade().unwrap().publish(next);
        });
        if reap {
            let target = Caller::new(task, &*first);
            block_on(kernel.mem_size(&target));
            let pidfd = block_on(kernel.pidfd_open(&caller, task.0 as i32, 0)).unwrap();
            kernel.do_group_exit(task, 0);
            assert_eq!(block_on(kernel.process_mrelease(&caller, pidfd, 0)), Ok(0));
            assert_eq!(first.get(page - 2, 4), b"\0\0\0\0");
            assert_eq!(second.get(page - 2, 4), b"new!");
            assert_eq!(selector.captures(), 1);
            assert_eq!(block_on(kernel.process_mrelease(&caller, pidfd, 0)), Ok(0));
            assert_eq!(second.get(page - 2, 4), b"\0\0\0\0");
        } else {
            let mut bytes = [0; 4];
            assert_eq!(
                block_on(crate::ptrace::access_remote_vm(
                    &mm,
                    page - 2,
                    crate::ptrace::Access::Read(&mut bytes),
                    true
                )),
                4
            );
            assert_eq!(&bytes, b"old!");
            assert_eq!(selector.captures(), 1);
            assert_eq!(
                block_on(crate::ptrace::access_remote_vm(
                    &mm,
                    page - 2,
                    crate::ptrace::Access::Read(&mut bytes),
                    true
                )),
                4
            );
            assert_eq!(&bytes, b"new!");
        }
        assert_eq!(selector.captures(), 2);
    }
}

#[test]
fn foreign_snapshot_retained_new_pages_capture_once_and_keep_old_page_identity() {
    let (kernel, task, _) = setup(b"");
    let page = crate::mm::PAGE_SIZE as u32;
    let local = FlatMemory(RefCell::new(vec![0; 3 * page as usize]));
    let caller = Caller::new(task, &local);
    let first = SyncMemory::new(3 * page as usize, 0);
    let second = SyncMemory::new(3 * page as usize, 0);
    for at in [0, page, 2 * page] {
        first.put(at, b"A");
        second.put(at, b"B");
    }
    let selector = ForeignSelector::new(first);
    kernel.attach_memory(task, selector.clone());
    let publish = Arc::downgrade(&selector);
    selector.after_capture(move || publish.upgrade().unwrap().publish(second));
    let held = block_on(kernel.retain_pages(&caller, 0, 2 * page)).unwrap();
    assert_eq!(selector.captures(), 1);
    let mut byte = [0];
    held.read_sync(0, &mut byte).unwrap();
    assert_eq!(&byte, b"A");
    held.read_sync(page, &mut byte).unwrap();
    assert_eq!(&byte, b"A");
    let old = block_on(kernel.retain_pages(&caller, 0, 1)).unwrap();
    old.read_sync(0, &mut byte).unwrap();
    assert_eq!(&byte, b"A");
    assert_eq!(
        selector.captures(),
        1,
        "existing physical page never reselects"
    );
    let fresh = block_on(kernel.retain_pages(&caller, 2 * page, 1)).unwrap();
    fresh.read_sync(0, &mut byte).unwrap();
    assert_eq!(&byte, b"B");
    assert_eq!(selector.captures(), 2);
}

#[test]
fn foreign_snapshot_retained_fallback_caches_absence_across_concurrent_attach() {
    let (kernel, task, _) = setup(b"");
    let kernel = Arc::new(kernel);
    let page = crate::mm::PAGE_SIZE as u32;
    let local = FlatMemory(RefCell::new(vec![b'L'; 2 * page as usize]));
    let caller = Caller::new(task, &local);
    let remote = SyncMemory::new(2 * page as usize, 0);
    remote.put(page, b"R");
    let (prepared, resume) = kernel.mm(task).test_pause_retained_commit();
    std::thread::scope(|scope| {
        let attaching = kernel.clone();
        let attach = scope.spawn(move || {
            prepared.recv_timeout(Duration::from_secs(5)).unwrap();
            attaching.attach_memory(task, remote);
            resume.send(()).unwrap();
        });
        let held = block_on(kernel.retain_pages(&caller, 0, 2 * page)).unwrap();
        attach.join().unwrap();
        let mut byte = [0];
        block_on(held.read(&local, page, &mut byte)).unwrap();
        assert_eq!(
            &byte, b"L",
            "the second new page keeps the original absent fallback"
        );
    });
}

#[test]
fn foreign_attachment_drop_runs_outside_task_slot_and_mm_operation_locks() {
    struct DropMemory {
        kernel: std::sync::Weak<Kernel>,
        mm: std::sync::Weak<crate::mm::Mm>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
        expect_attached: bool,
    }
    impl Drop for DropMemory {
        fn drop(&mut self) {
            let kernel = self.kernel.upgrade().unwrap();
            let mm = self.mm.upgrade().unwrap();
            assert!(
                kernel.state.0.try_write().is_ok(),
                "task state unlocked before backing Drop"
            );
            assert!(
                mm.op.try_lock().is_some(),
                "mm operation unlocked before backing Drop"
            );
            assert_eq!(mm.has_foreign(), self.expect_attached);
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl UserMemory for DropMemory {
        fn read<'a>(&'a self, _: u32, _: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            Box::pin(async { Err(Fault) })
        }
        fn write<'a>(&'a self, _: u32, _: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            Box::pin(async { Err(Fault) })
        }
        fn size(&self) -> LocalFuture<'_, u64> {
            Box::pin(async { 0 })
        }
        fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
            Box::pin(async { None })
        }
    }
    for rejected in [false, true] {
        let (kernel, task, _) = setup(b"");
        let kernel = Arc::new(kernel);
        let mm = kernel.mm(task);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        if rejected {
            kernel.attach_memory(task, SyncMemory::new(65536, 0));
        }
        kernel.attach_memory(
            task,
            Arc::new(DropMemory {
                kernel: Arc::downgrade(&kernel),
                mm: Arc::downgrade(&mm),
                drops: drops.clone(),
                expect_attached: rejected,
            }),
        );
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(rejected)
        );
        let local = memory_flat();
        block_on(kernel.exit_mm(&Caller::new(task, &local)));
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!mm.has_foreign());
    }
}

#[test]
fn foreign_snapshot_issued_view_outlives_mm_exit_without_resurrecting_it() {
    let (kernel, task, _) = setup(b"");
    let memory = memory_flat();
    let first = SyncMemory::new(65536, 0);
    first.put(0x100, b"held");
    let allocation = Arc::downgrade(&first);
    let selector = ForeignSelector::new(first);
    let registration = Arc::downgrade(&selector);
    kernel.attach_memory(task, selector.clone());
    let mm = kernel.mm(task);
    let issued = mm.foreign().unwrap();
    assert!(issued.foreign_snapshot().is_none());
    drop(selector);
    block_on(kernel.exit_mm(&Caller::new(task, &memory)));
    assert!(
        registration.upgrade().is_none(),
        "no host/operation pins the selector"
    );
    assert!(!mm.has_foreign());
    let mut bytes = [0; 4];
    block_on(issued.read(0x100, &mut bytes)).unwrap();
    assert_eq!(
        &bytes, b"held",
        "the issued concrete view keeps its full lifetime"
    );
    kernel.attach_memory(task, SyncMemory::new(65536, 0));
    assert!(
        !mm.has_foreign(),
        "late attachment cannot resurrect an exited mm"
    );
    assert!(allocation.upgrade().is_some());
    drop(issued);
    assert!(allocation.upgrade().is_none());
}

/// An opaque allocation owner, deliberately allowed to reenter kernel gates.
/// Tests retain no extra owner Arc: rotation leaves the real operation/page as
/// its last owner, so an early gated Drop cannot pass by accident.
pub(super) struct RetirementMemory {
    memory: Arc<SyncMemory>,
    _owner: Arc<RetirementOwner>,
}
struct RetirementOwner(Mutex<Option<Box<dyn FnOnce() + Send>>>);
impl Drop for RetirementOwner {
    fn drop(&mut self) {
        (self.0.get_mut().unwrap().take().unwrap())();
    }
}
impl RetirementMemory {
    pub(super) fn new(memory: Arc<SyncMemory>, drop: impl FnOnce() + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            memory,
            _owner: Arc::new(RetirementOwner(Mutex::new(Some(Box::new(drop))))),
        })
    }
}
impl UserMemory for RetirementMemory {
    fn read<'a>(&'a self, addr: u32, out: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        self.memory.read(addr, out)
    }
    fn write<'a>(&'a self, addr: u32, data: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        self.memory.write(addr, data)
    }
    fn size(&self) -> LocalFuture<'_, u64> {
        self.memory.size()
    }
    fn grow(&self, pages: u32) -> LocalFuture<'_, Option<u64>> {
        self.memory.grow(pages)
    }
}

#[test]
fn foreign_retirement_unmap_and_exit_release_the_actual_owner_after_mm_unlock() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for exit in [false, true] {
        let (kernel, task, _) = setup(b"");
        let local = memory();
        let caller = Caller::new(task, &local);
        let page = crate::mm::PAGE_SIZE as u32;
        let addr = block_on(kernel.mmap(
            &caller,
            0,
            page,
            ProtFlags(3),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            Fd(-1),
            0,
        ))
        .unwrap();
        let mm = kernel.mm(task);
        let first = SyncMemory::new(block_on(local.size()) as usize, 0);
        first.put(addr, b"old");
        let drops = Arc::new(AtomicUsize::new(0));
        let probe_mm = mm.clone();
        let probe_drops = drops.clone();
        let owner = RetirementMemory::new(first, move || {
            assert!(
                probe_mm.op.try_lock().is_some(),
                "actual allocation owner released outside mm.op"
            );
            probe_drops.fetch_add(1, Ordering::SeqCst);
        });
        let weak = Arc::downgrade(&owner);
        let selector = ForeignSelector::new(owner);
        kernel.attach_memory(task, selector.clone());
        let held = block_on(kernel.retain_pages(&caller, addr, 3)).unwrap();
        selector.publish(SyncMemory::new(block_on(local.size()) as usize, 0));
        assert!(
            weak.upgrade().is_some(),
            "actual retained Page owns A after rotation"
        );
        if exit {
            block_on(kernel.exit_mmap(&caller));
        } else {
            assert_eq!(block_on(kernel.munmap(&caller, addr, page)), Ok(0));
        }
        assert!(weak.upgrade().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let mut bytes = [0; 3];
        held.read_sync(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"old");
        drop(held);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
