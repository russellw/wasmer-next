//! Fixed resources and direct descriptors (`io_uring/rsrc.c`, `filetable.c`).

use std::sync::{Arc, Weak};

use wasixv2_abi::{
    GuestLayout, GuestPtr, GuestPtrMut, IoUringFileIndexRange, IoUringRsrcUpdate2, Iovec,
};
use wasixv2_syscalls::{Caller, Errno, Fd, SysResult, read_value, write_value};

use super::{Ctx, Resources, is_ring};
use crate::{Kernel, file::OpenFile, sync::MutexExt};

/// `io_rsrc_node`: the table and each request using this version own a reference.
/// Never release a table reference while holding `Ctx::state`: its last drop posts a CQE.
pub(super) struct Node<T> {
    item: Option<T>,
    tag: u64,
    ctx: Weak<Ctx>,
}

impl<T> Node<T> {
    pub(super) fn new(ctx: &Ctx, item: T, tag: u64) -> Arc<Self> {
        Arc::new(Self {
            item: Some(item),
            tag,
            ctx: ctx.me.clone(),
        })
    }
}

impl<T> Node<T> {
    pub(super) fn item(&self) -> &T {
        self.item.as_ref().expect("live resource node")
    }
}
impl<T> Drop for Node<T> {
    fn drop(&mut self) {
        let mut errors = crate::sync::DropErrors::new();
        errors.run(|| {
            if self.tag != 0
                && let Some(ctx) = self.ctx.upgrade()
            {
                ctx.post(self.tag, 0, 0, false);
            }
        });
        errors.run(|| drop(self.item.take()));
        errors.finish();
    }
}

pub(super) type FileNode = Arc<Node<Arc<OpenFile>>>;
pub(super) type BufferNode = Arc<Node<Arc<crate::mm::Retained>>>;

impl Ctx {
    /// Linux filetable.c:__io_fixed_fd_install/io_install_fixed_file. Explicit indices
    /// are one based; allocation returns the zero based index (ENFILE when full).
    pub(crate) fn install_direct_in(
        &self,
        file: Arc<OpenFile>,
        index: u32,
        retired: &mut Resources,
    ) -> Result<i32, Errno> {
        let candidate = retired.open_files.len();
        retired.open_files.push(Some(file));
        let alloc = index == u32::MAX;
        let (old, result) = {
            let mut state = self.state.lock_or_recover();
            let slot = if alloc {
                let start = state.file_alloc_start;
                let end = state.file_alloc_end;
                let hint = state.file_alloc_hint.clamp(start, end);
                let files = state.files.as_ref().ok_or(Errno::ENFILE)?;
                (hint..end)
                    .chain(start..hint)
                    .find(|&i| files[i as usize].is_none())
                    .ok_or(Errno::ENFILE)?
            } else {
                index.wrapping_sub(1)
            };
            if is_ring(retired.open_files[candidate].as_ref().unwrap()) {
                return Err(Errno::EBADF);
            }
            let files = state.files.as_mut().ok_or(Errno::ENXIO)?;
            let entry = files.get_mut(slot as usize).ok_or(Errno::EINVAL)?;
            let old = entry.replace(Node::new(
                self,
                retired.open_files[candidate].take().unwrap(),
                0,
            ));
            // filetable.h:io_file_bitmap_set, only when an empty slot is filled.
            if old.is_none() {
                state.file_alloc_hint = slot + 1;
            }
            (old, if alloc { slot as i32 } else { 0 })
        };
        retired.files.push(old);
        Ok(result)
    }

    pub(super) fn remove_direct_in(&self, slot: u32, retired: &mut Resources) -> Result<(), Errno> {
        let old = {
            let mut state = self.state.lock_or_recover();
            let files = state.files.as_mut().ok_or(Errno::ENXIO)?;
            let old = files
                .get_mut(slot as usize)
                .ok_or(Errno::EINVAL)?
                .take()
                .ok_or(Errno::EBADF)?;
            state.file_alloc_hint = slot;
            old
        };
        retired.files.push(Some(old));
        Ok(())
    }
}

impl Kernel {
    pub(super) async fn register_alloc_range(
        &self,
        caller: &Caller<'_>,
        ctx: &Ctx,
        arg: u32,
    ) -> SysResult<i32> {
        let range: IoUringFileIndexRange = read_value(caller.memory(), GuestPtr::new(arg)).await?;
        let end = range.off.checked_add(range.len).ok_or(Errno::EOVERFLOW)?;
        let mut state = ctx.state.lock_or_recover();
        if range.resv != 0 || end > state.files.as_ref().map_or(0, |f| f.len() as u32) {
            return Err(Errno::EINVAL.into());
        }
        state.file_alloc_start = range.off;
        state.file_alloc_end = end;
        state.file_alloc_hint = range.off;
        Ok(0)
    }

    /// `__io_register_rsrc_update`: partial success wins over a later failure. File
    /// updates remove the old slot before looking up its replacement; buffer updates
    /// validate their replacement first (`__io_sqe_{files,buffers}_update`).
    pub(super) async fn update_resources(
        &self,
        caller: &Caller<'_>,
        ctx: &Ctx,
        up: IoUringRsrcUpdate2,
        buffers: bool,
        retired: &mut Resources,
    ) -> SysResult<i32> {
        if up.nr == 0 || up.resv != 0 || up.resv2 != 0 {
            return Err(Errno::EINVAL.into());
        }
        let end = up.offset.checked_add(up.nr).ok_or(Errno::EOVERFLOW)?;
        let len = {
            let state = ctx.state.lock_or_recover();
            if buffers {
                state.buffers.as_ref().map(Vec::len)
            } else {
                state.files.as_ref().map(Vec::len)
            }
        }
        .ok_or(Errno::ENXIO)?;
        if end as usize > len {
            return Err(Errno::EINVAL.into());
        }
        for i in 0..up.nr {
            let result = self
                .update_resource(caller, ctx, &up, i, buffers, retired)
                .await;
            if let Err(err) = result {
                return if i == 0 { Err(err) } else { Ok(i as i32) };
            }
        }
        Ok(up.nr as i32)
    }

    async fn update_resource(
        &self,
        caller: &Caller<'_>,
        ctx: &Ctx,
        up: &IoUringRsrcUpdate2,
        i: u32,
        buffers: bool,
        retired: &mut Resources,
    ) -> SysResult<()> {
        let at = |base: u64, size: u32| -> Result<u32, Errno> {
            u32::try_from(
                base.checked_add(u64::from(i) * u64::from(size))
                    .ok_or(Errno::EFAULT)?,
            )
            .map_err(|_| Errno::EFAULT)
        };
        let slot = (up.offset + i) as usize;
        if buffers {
            let iov: Iovec = read_value(
                caller.memory(),
                GuestPtr::new(at(up.data, Iovec::SIZE as u32)?),
            )
            .await?;
            let tag = if up.tags == 0 {
                0
            } else {
                read_value(caller.memory(), GuestPtr::<u64>::new(at(up.tags, 8)?)).await?
            };
            let iov = super::register::validate_buffer(iov)?;
            if iov.is_none() && tag != 0 {
                return Err(Errno::EINVAL.into());
            }
            let candidate = retired.retained.len();
            retired.retained.push(None);
            retired.retained[candidate] = match iov {
                Some(iov) => Some(
                    self.retain_pages_in(caller, iov.iov_base, iov.iov_len, &mut retired.memory)
                        .await?,
                ),
                None => None,
            };
            let old = {
                let mut state = ctx.state.lock_or_recover();
                let table = state.buffers.as_mut().ok_or(Errno::ENXIO)?;
                let entry = table.get_mut(slot).ok_or(Errno::EINVAL)?;
                std::mem::replace(
                    entry,
                    retired.retained[candidate]
                        .take()
                        .map(|buffer| Node::new(ctx, buffer, tag)),
                )
            };
            retired.buffers.push(old);
        } else {
            let tag = if up.tags == 0 {
                0
            } else {
                read_value(caller.memory(), GuestPtr::<u64>::new(at(up.tags, 8)?)).await?
            };
            let fd: i32 = read_value(caller.memory(), GuestPtr::new(at(up.data, 4)?)).await?;
            if (fd == -1 || fd == -2) && tag != 0 {
                return Err(Errno::EINVAL.into());
            }
            if fd == -2 {
                return Ok(());
            }
            let old = {
                let mut state = ctx.state.lock_or_recover();
                let old = state
                    .files
                    .as_mut()
                    .ok_or(Errno::ENXIO)?
                    .get_mut(slot)
                    .ok_or(Errno::EINVAL)?
                    .take();
                if old.is_some() {
                    state.file_alloc_hint = slot as u32;
                }
                old
            };
            retired.files.push(old);
            let candidate = retired.open_files.len();
            retired.open_files.push(self.fixed_file(caller, fd)?);
            let old = {
                let mut state = ctx.state.lock_or_recover();
                let table = state.files.as_mut().ok_or(Errno::ENXIO)?;
                let filled = retired.open_files[candidate].is_some();
                let old = std::mem::replace(
                    table.get_mut(slot).ok_or(Errno::EINVAL)?,
                    retired.open_files[candidate]
                        .take()
                        .map(|file| Node::new(ctx, file, tag)),
                );
                if filled && old.is_none() {
                    state.file_alloc_hint = slot as u32 + 1;
                }
                old
            };
            retired.files.push(old);
        }
        Ok(())
    }

    /// `io_files_update_with_index_alloc`: installs files and writes allocated indices
    /// over the input fds. A failed writeback removes the new slot.
    pub(super) async fn alloc_file_indices(
        &self,
        caller: &Caller<'_>,
        ctx: &Ctx,
        addr: u64,
        nr: u32,
        retired: &mut Resources,
    ) -> SysResult<i32> {
        if ctx.state.lock_or_recover().files.is_none() {
            return Err(Errno::ENXIO.into());
        }
        for i in 0..nr {
            let result = async {
                let at = u32::try_from(addr.checked_add(u64::from(i) * 4).ok_or(Errno::EFAULT)?)
                    .map_err(|_| Errno::EFAULT)?;
                let fd: i32 = read_value(caller.memory(), GuestPtr::new(at)).await?;
                let file = self.caller_file(caller, Fd(fd))?;
                let slot = ctx.install_direct_in(file, u32::MAX, retired)?;
                if let Err(err) = write_value(caller.memory(), GuestPtrMut::new(at), &slot).await {
                    ctx.remove_direct_in(slot as u32, retired)?;
                    return Err(err.into());
                }
                Ok(())
            }
            .await;
            if let Err(err) = result {
                return if i == 0 { Err(err) } else { Ok(i as i32) };
            }
        }
        Ok(nr as i32)
    }
}
