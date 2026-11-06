use std::{
    cell::RefCell,
    io,
    sync::{Arc, Mutex},
};

use wasixv2_abi::{
    AtFlags, Cstr, FcntlCmd, Fd, FileMode, GuestLayout, OpenFlags, Statx, StatxMask, StatxPtr,
};
use wasixv2_kernel::{Dispatch, Kernel, SyscallEntry};
use wasixv2_syscalls::{
    Caller, Control, Fault, Layer, LocalFuture, SysErr, Syscall, TaskId, UserMemory, UserSliceMut,
};

use crate::{
    AliasRegistry,
    injection::{self, Injection},
    platform::{Action, Request},
};

const PAGE_SIZE: u64 = 4096;
const SCRATCH_BASE: u32 = 0x10000;
const CHUNK_SIZE: usize = 1024 * 1024;

/// Handles file-backed private mappings through WLK file descriptors and native address space.
/// `None` leaves anonymous mappings to the native startup path and unsupported shared mappings
/// to the caller's ENOSYS fallback.
pub(crate) async fn handle_mmap(
    request: Request,
    kernel: &Kernel,
    task: TaskId,
    _mm_id: u64,
    _aliases: Arc<Mutex<AliasRegistry>>,
) -> io::Result<Option<Action>> {
    if request.nr != libc::SYS_mmap {
        return Ok(None);
    }

    let address = request.args[0];
    let len = request.args[1];
    let prot = request.args[2] as u32;
    let flags = request.args[3] as u32;
    let fd = Fd(request.args[4] as i32);
    let offset = request.args[5];
    let supported_prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32;
    if prot & !supported_prot != 0 {
        return Ok(Some(Action::Return(-(libc::EINVAL as i64))));
    }
    if len == 0 {
        return Ok(Some(Action::Return(-(libc::EINVAL as i64))));
    }
    if flags & libc::MAP_ANONYMOUS as u32 != 0 {
        return Ok(None);
    }
    if flags & libc::MAP_TYPE as u32 != libc::MAP_PRIVATE as u32 {
        // TODO(native): shared file mappings need WLK page identity and cross-process dirty tracking.
        return Ok(None);
    }
    if !offset.is_multiple_of(PAGE_SIZE) {
        return Ok(Some(Action::Return(-(libc::EINVAL as i64))));
    }
    let Some(mapped_len) = len
        .checked_add(PAGE_SIZE - 1)
        .map(|size| size & !(PAGE_SIZE - 1))
    else {
        return Ok(Some(Action::Return(-(libc::ENOMEM as i64))));
    };
    if offset > i64::MAX as u64
        || offset
            .checked_add(mapped_len)
            .is_none_or(|end| end > i64::MAX as u64)
    {
        return Ok(Some(Action::Return(-(libc::EOVERFLOW as i64))));
    }

    let supported = (libc::MAP_TYPE
        | libc::MAP_FIXED
        | libc::MAP_FIXED_NOREPLACE
        | libc::MAP_32BIT
        | libc::MAP_NORESERVE
        | libc::MAP_POPULATE
        | libc::MAP_NONBLOCK
        | libc::MAP_STACK) as u32
        | libc::MAP_DENYWRITE as u32
        | libc::MAP_EXECUTABLE as u32;
    if flags & !supported != 0 {
        // TODO(native): implement other Linux mmap flags instead of forwarding a partial ABI.
        return Ok(Some(Action::Return(-(libc::ENOSYS as i64))));
    }
    if flags & ((libc::MAP_FIXED | libc::MAP_FIXED_NOREPLACE) as u32) != 0
        && !address.is_multiple_of(PAGE_SIZE)
    {
        return Ok(Some(Action::Return(-(libc::EINVAL as i64))));
    }

    let descriptors = match kernel.snapshot_descriptors(task, &[fd]) {
        Ok(descriptors) if descriptors.get(fd).is_some_and(|entry| entry.present) => descriptors,
        Ok(_) => return Ok(Some(Action::Return(-(libc::EBADF as i64)))),
        Err(error) => return Ok(Some(Action::Return(-(error.0 as i64)))),
    };
    let mode = match statx_mode(kernel, task, fd, &descriptors).await {
        Ok(mode) => mode,
        Err(error) => return Ok(Some(Action::Return(error))),
    };
    if mode & FileMode::S_IFMT.0 as u16 != FileMode::S_IFREG.0 as u16 {
        return Ok(Some(Action::Return(-(libc::ENODEV as i64))));
    }
    let open_flags = match fcntl_getfl(kernel, task, fd, &descriptors).await {
        Ok(flags) => flags,
        Err(error) => return Ok(Some(Action::Return(error))),
    };
    if open_flags.contains(OpenFlags::O_PATH)
        || open_flags & OpenFlags::O_ACCMODE == OpenFlags::O_WRONLY
    {
        return Ok(Some(Action::Return(-(libc::EBADF as i64))));
    }

    // Probe the first chunk before touching a MAP_FIXED range; the single descriptor snapshot is
    // reused for every later Pread64 so close/reuse cannot change the mapping's backing object.
    let first_len = mapped_len.min(CHUNK_SIZE as u64) as usize;
    let (first_bytes, first_read) =
        match pread_chunk(kernel, task, fd, offset, first_len, &descriptors).await {
            Ok(result) => result,
            Err(error) => return Ok(Some(Action::Return(error))),
        };

    let mut injection = match Injection::begin(request.pid) {
        Ok(injection) => injection,
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            return Ok(Some(Action::Return(-(libc::ENOSYS as i64))));
        }
        Err(error) => return Err(error),
    };
    if flags & libc::MAP_FIXED as u32 != 0 {
        let start = address & !(PAGE_SIZE - 1);
        let end = match start.checked_add(mapped_len) {
            Some(end) => end,
            None => {
                injection.finish()?;
                return Ok(Some(Action::Return(-(libc::EINVAL as i64))));
            }
        };
        let injection_page = injection.syscall_site() & !(PAGE_SIZE - 1);
        if start <= injection_page && injection_page < end {
            // TODO(native): use a supervisor-owned trampoline when MAP_FIXED would cover this syscall site.
            injection.finish()?;
            return Ok(Some(Action::Return(-(libc::ENOSYS as i64))));
        }
    }

    // TODO(native): anonymous snapshot pages do not reflect later backing-file writes, and EOF
    // pages stay zero after truncation instead of raising Linux SIGBUS for accesses beyond EOF.
    let mut native_flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u32;
    native_flags |= flags
        & (libc::MAP_FIXED
            | libc::MAP_FIXED_NOREPLACE
            | libc::MAP_32BIT
            | libc::MAP_NORESERVE
            | libc::MAP_POPULATE
            | libc::MAP_NONBLOCK
            | libc::MAP_STACK) as u32;
    // TODO(native): MAP_DENYWRITE and MAP_EXECUTABLE are ignored as Linux legacy hints when
    // backing the private copy with anonymous native pages.
    let native_mapping = injection.call(
        libc::SYS_mmap,
        [
            address,
            mapped_len,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            native_flags as u64,
            u64::MAX,
            0,
        ],
    )?;
    if is_errno(native_mapping) {
        injection.finish()?;
        return Ok(Some(Action::Return(native_mapping)));
    }
    let native_base = native_mapping as u64;

    if first_read != 0
        && let Err(error) =
            injection::write_remote(request.pid, native_base, &first_bytes[..first_read])
    {
        cleanup_mapping(&mut injection, native_base, mapped_len)?;
        injection.finish()?;
        return Err(error);
    }

    let mut copied = first_read as u64;
    while copied < mapped_len {
        let count = (mapped_len - copied).min(CHUNK_SIZE as u64) as usize;
        let pos = offset + copied;
        let (bytes, read) = match pread_chunk(kernel, task, fd, pos, count, &descriptors).await {
            Ok(result) => result,
            Err(error) => {
                cleanup_mapping(&mut injection, native_base, mapped_len)?;
                injection.finish()?;
                return Ok(Some(Action::Return(error)));
            }
        };
        if read == 0 {
            // Anonymous pages already provide Linux's zero-filled final partial-page tail.
            break;
        }
        if let Err(error) =
            injection::write_remote(request.pid, native_base + copied, &bytes[..read])
        {
            cleanup_mapping(&mut injection, native_base, mapped_len)?;
            injection.finish()?;
            return Err(error);
        }
        copied += read as u64;
    }

    let protected = injection.call(
        libc::SYS_mprotect,
        [native_base, mapped_len, prot as u64, 0, 0, 0],
    )?;
    if is_errno(protected) {
        cleanup_mapping(&mut injection, native_base, mapped_len)?;
        injection.finish()?;
        return Ok(Some(Action::Return(protected)));
    }
    injection.finish()?;
    Ok(Some(Action::Return(native_base as i64)))
}

async fn statx_mode(
    kernel: &Kernel,
    task: TaskId,
    fd: Fd,
    descriptors: &wasixv2_syscalls::DescriptorSet,
) -> Result<u16, i64> {
    let memory = ScratchMemory::zeroed(std::mem::size_of::<Statx>());
    let caller = Caller::new(task, &memory)
        .with_descriptors(descriptors)
        .with_process_fork_allowed(false);
    let result = SyscallEntry(Dispatch)
        .call(
            &caller,
            Syscall::Statx {
                dfd: fd,
                filename: Cstr::new(0),
                flags: AtFlags::AT_EMPTY_PATH,
                mask: StatxMask::STATX_TYPE,
                buffer: StatxPtr::new(SCRATCH_BASE),
            },
            kernel,
        )
        .await;
    match result {
        Ok(value) if value.to_raw() == 0 => {
            let bytes = memory.bytes.borrow();
            let statx = Statx::read_from(&bytes).ok_or(-(libc::EIO as i64))?;
            if statx.stx_mask.contains(StatxMask::STATX_TYPE) {
                Ok(statx.stx_mode)
            } else {
                Err(-(libc::EIO as i64))
            }
        }
        Ok(value) => Err(value.to_raw()),
        Err(error) => Err(errno(error)),
    }
}

async fn fcntl_getfl(
    kernel: &Kernel,
    task: TaskId,
    fd: Fd,
    descriptors: &wasixv2_syscalls::DescriptorSet,
) -> Result<OpenFlags, i64> {
    let memory = ScratchMemory::zeroed(0);
    let caller = Caller::new(task, &memory)
        .with_descriptors(descriptors)
        .with_process_fork_allowed(false);
    let result = SyscallEntry(Dispatch)
        .call(
            &caller,
            Syscall::Fcntl64 {
                fd,
                cmd: FcntlCmd::F_GETFL,
                arg: 0,
            },
            kernel,
        )
        .await;
    match result {
        Ok(value) if value.to_raw() >= 0 => Ok(OpenFlags(value.to_raw() as u32)),
        Ok(value) => Err(value.to_raw()),
        Err(error) => Err(errno(error)),
    }
}

async fn pread_chunk(
    kernel: &Kernel,
    task: TaskId,
    fd: Fd,
    pos: u64,
    len: usize,
    descriptors: &wasixv2_syscalls::DescriptorSet,
) -> Result<(Vec<u8>, usize), i64> {
    let pos = i64::try_from(pos).map_err(|_| -(libc::EOVERFLOW as i64))?;
    let memory = ScratchMemory::zeroed(len);
    let caller = Caller::new(task, &memory)
        .with_descriptors(descriptors)
        .with_process_fork_allowed(false);
    let result = SyscallEntry(Dispatch)
        .call(
            &caller,
            Syscall::Pread64 {
                fd,
                buf: UserSliceMut::new(SCRATCH_BASE, len as u32),
                pos,
            },
            kernel,
        )
        .await;
    match result {
        Ok(value) if value.to_raw() >= 0 => {
            let read = value.to_raw() as usize;
            if read > len {
                return Err(-(libc::EIO as i64));
            }
            Ok((memory.into_bytes(), read))
        }
        Ok(value) => Err(value.to_raw()),
        Err(error) => Err(errno(error)),
    }
}

fn cleanup_mapping(injection: &mut Injection, address: u64, len: u64) -> io::Result<()> {
    let result = injection.call(libc::SYS_munmap, [address, len, 0, 0, 0, 0])?;
    if is_errno(result) {
        // TODO(native): a failed cleanup leaves native pages until process teardown.
        return Err(io::Error::other(format!("munmap cleanup failed: {result}")));
    }
    Ok(())
}

fn errno(error: SysErr) -> i64 {
    match error {
        SysErr::Errno(errno) => -(errno.0 as i64),
        _ => -(libc::EINTR as i64),
    }
}

fn is_errno(result: i64) -> bool {
    (-4095..0).contains(&result)
}

struct ScratchMemory {
    bytes: RefCell<Vec<u8>>,
}

impl ScratchMemory {
    fn zeroed(len: usize) -> Self {
        Self {
            bytes: RefCell::new(vec![0; len]),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes.into_inner()
    }

    fn range(addr: u32, len: usize) -> Result<std::ops::Range<usize>, Fault> {
        let start = addr.checked_sub(SCRATCH_BASE).ok_or(Fault)? as usize;
        let end = start.checked_add(len).ok_or(Fault)?;
        Ok(start..end)
    }
}

impl UserMemory for ScratchMemory {
    fn read<'a>(&'a self, addr: u32, buf: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let range = Self::range(addr, buf.len())?;
            let bytes = self.bytes.borrow();
            buf.copy_from_slice(bytes.get(range).ok_or(Fault)?);
            Ok(())
        })
    }

    fn write<'a>(&'a self, addr: u32, data: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let range = Self::range(addr, data.len())?;
            let mut bytes = self.bytes.borrow_mut();
            bytes.get_mut(range).ok_or(Fault)?.copy_from_slice(data);
            Ok(())
        })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        let size = u64::from(SCRATCH_BASE) + self.bytes.borrow().len() as u64;
        Box::pin(async move { size })
    }

    fn grow(&self, _pages: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}
