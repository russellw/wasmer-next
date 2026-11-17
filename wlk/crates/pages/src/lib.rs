//! Shared pages: host memory that the linear memories of several processes map at once, as
//! Linux's shmem objects back `MAP_SHARED|MAP_ANONYMOUS`, SysV segments and tmpfs files
//! (`mm/shmem.c`).
//!
//! Wasm cannot share part of one module's memory with another module, but the host can: every
//! linear memory is one host mapping reserved to its maximum that never moves, so a range of it
//! can be replaced with a `MAP_SHARED` mapping of a host object. Each process that maps the
//! object then reads and writes the very same pages, with no copy and no synchronisation point,
//! and a futex keyed by the object and offset works across them.
//!
//! [`SharedPages`] is the object as the kernel sees it. [`Memfd`] is the host object where one
//! exists: a `memfd_create` file on Linux, an unlinked `shm_open` object on macOS. Elsewhere
//! there is none, and the kernel keeps its copies synchronised at defined points instead.
//! [`map_at`] and [`map_private_at`] are what the execution layer does with an object's
//! descriptor inside a linear memory. A [`Provider`] makes objects for whoever keeps data in
//! them, such as a memory filesystem whose files processes map.
//!
//! A separate crate because the VFS, the syscall interface, the kernel, the host and the
//! execution layer all need it, and none of them may depend on another for it.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(unix)]
use std::os::fd::BorrowedFd;

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
mod memfd;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub use memfd::Memfd;
#[cfg(unix)]
mod map;
#[cfg(unix)]
pub use map::{drop_private, map_at, map_private_at};

/// A shared memory object: bytes several processes map, which stay as long as anyone holds the
/// object.
///
/// Nothing may map the object past its [`size`](SharedPages::size): a host access to a page
/// wholly past the end of a file mapping raises `SIGBUS` in the host. Whoever maps it therefore
/// keeps the size at or above the end of every mapping.
pub trait SharedPages: Send + Sync {
    /// Names the object in futex keys; never reused by another object of this host process.
    fn id(&self) -> u64;

    /// The object's size in bytes.
    fn size(&self) -> u64;

    /// Sets the object's size. Pages past a smaller size are freed; pages a larger size adds
    /// read zero.
    fn resize(&self, size: u64) -> io::Result<()>;

    /// Fills `buf` from `offset`; bytes past the end read zero.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;

    /// Writes all of `data` at `offset`, which with the data must lie inside the object.
    fn write_at(&self, data: &[u8], offset: u64) -> io::Result<()>;

    /// Makes `len` bytes from `offset` read zero again, freeing their pages where the host can
    /// (`FALLOC_FL_PUNCH_HOLE`). The size does not change.
    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()>;

    /// Bytes of host memory the object holds now (`shm_rss`).
    fn allocated(&self) -> u64;

    /// `lseek` with `SEEK_DATA` or `SEEK_HOLE`: the first offset at or after `offset` that holds
    /// data, or that is a hole. Pages never written, and those [`punch_hole`] freed, are holes,
    /// and so is the end of the object. `None` when `offset` is at or past the end, or for
    /// [`Seek::Data`] when no data follows it (`ENXIO`). By default the whole object is data.
    ///
    /// [`punch_hole`]: SharedPages::punch_hole
    fn seek(&self, offset: u64, which: Seek) -> io::Result<Option<u64>> {
        let size = self.size();
        Ok((offset < size).then_some(match which {
            Seek::Data => offset,
            Seek::Hole => size,
        }))
    }

    /// The descriptor that maps the object, if the host can map it into linear memory.
    #[cfg(unix)]
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

/// What [`SharedPages::seek`] looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seek {
    /// `SEEK_DATA`.
    Data,
    /// `SEEK_HOLE`.
    Hole,
}

/// Makes shared memory objects for something that keeps data in them, so that mappings of that
/// data show the object itself: a memory filesystem's files, as tmpfs keeps every file in
/// shmem (`mm/shmem.c`).
pub trait Provider: Send + Sync {
    /// A new object of `size` bytes, all zero. [`io::ErrorKind::Unsupported`] where the host
    /// has none.
    fn shared_pages(&self, size: u64) -> io::Result<Arc<dyn SharedPages>>;
}

/// A fresh [`SharedPages::id`].
pub fn new_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A machine's memory reservation policy. Refused charges must leave the budget unchanged.
/// Callbacks must not block or re-enter filesystem/kernel operations: callers may hold locks.
pub trait MemoryBudget: Send + Sync {
    fn charge(&self, bytes: u64) -> Result<(), BudgetExceeded>;
    fn release(&self, bytes: u64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExceeded;

/// Shared objects charged by size, rather than by a memory filesystem's allocated blocks.
/// All resizing must go through this wrapper; the factory must return a fresh object.
pub struct BudgetedPages {
    // Fields drop in order: free the backing before returning its reservation.
    inner: Arc<dyn SharedPages>,
    reservation: Reservation,
}

struct Reservation {
    budget: Arc<dyn MemoryBudget>,
    charged: std::sync::Mutex<u64>,
}

impl BudgetedPages {
    /// Reserves before calling the allocation factory; failed allocations return the reservation.
    pub fn new(
        size: u64,
        budget: Arc<dyn MemoryBudget>,
        factory: impl FnOnce() -> io::Result<Arc<dyn SharedPages>>,
    ) -> io::Result<Self> {
        budget
            .charge(size)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let reservation = Reservation {
            budget,
            charged: std::sync::Mutex::new(size),
        };
        Ok(Self {
            inner: factory()?,
            reservation,
        })
    }
}

impl SharedPages for BudgetedPages {
    fn id(&self) -> u64 {
        self.inner.id()
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
    fn resize(&self, size: u64) -> io::Result<()> {
        let mut charged = self.reservation.charged.lock().unwrap();
        let growth = size.saturating_sub(*charged);
        if growth != 0 {
            self.reservation
                .budget
                .charge(growth)
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        }
        if let Err(err) = self.inner.resize(size) {
            if growth != 0 {
                self.reservation.budget.release(growth);
            }
            return Err(err);
        }
        if size < *charged {
            self.reservation.budget.release(*charged - size);
        }
        *charged = size;
        Ok(())
    }
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.inner.read_at(buf, offset)
    }
    fn write_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        self.inner.write_at(data, offset)
    }
    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.punch_hole(offset, len)
    }
    fn allocated(&self) -> u64 {
        self.inner.allocated()
    }
    fn seek(&self, offset: u64, which: Seek) -> io::Result<Option<u64>> {
        self.inner.seek(offset, which)
    }
    #[cfg(unix)]
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.inner.fd()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.release(*self.charged.get_mut().unwrap());
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    struct Budget {
        used: AtomicU64,
        limit: u64,
    }
    impl MemoryBudget for Budget {
        fn charge(&self, bytes: u64) -> Result<(), BudgetExceeded> {
            self.used
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    n.checked_add(bytes).filter(|&n| n <= self.limit)
                })
                .map(drop)
                .map_err(|_| BudgetExceeded)
        }
        fn release(&self, bytes: u64) {
            assert!(self.used.fetch_sub(bytes, Ordering::Relaxed) >= bytes);
        }
    }
    struct Pages(AtomicU64);
    impl SharedPages for Pages {
        fn id(&self) -> u64 {
            1
        }
        fn size(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
        fn resize(&self, size: u64) -> io::Result<()> {
            if size == 13 {
                return Err(io::ErrorKind::Other.into());
            }
            self.0.store(size, Ordering::Relaxed);
            Ok(())
        }
        fn read_at(&self, _: &mut [u8], _: u64) -> io::Result<()> {
            Ok(())
        }
        fn write_at(&self, _: &[u8], _: u64) -> io::Result<()> {
            Ok(())
        }
        fn punch_hole(&self, _: u64, _: u64) -> io::Result<()> {
            Ok(())
        }
        fn allocated(&self) -> u64 {
            0
        }
    }
    #[test]
    fn reserves_before_factory_and_rolls_back_failed_creation() {
        let b = Arc::new(Budget {
            used: AtomicU64::new(0),
            limit: 10,
        });
        assert!(BudgetedPages::new(11, b.clone(), || panic!("refused allocation")).is_err());
        assert_eq!(b.used.load(Ordering::Relaxed), 0);
        assert!(
            BudgetedPages::new(10, b.clone(), || {
                assert_eq!(b.used.load(Ordering::Relaxed), 10);
                Err(io::ErrorKind::Other.into())
            })
            .is_err()
        );
        assert_eq!(b.used.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn exact_resize_refusal_failure_and_last_reference_drop() {
        let b = Arc::new(Budget {
            used: AtomicU64::new(0),
            limit: 20,
        });
        let pages = Arc::new(
            BudgetedPages::new(4, b.clone(), || Ok(Arc::new(Pages(AtomicU64::new(4))))).unwrap(),
        );
        let clone = pages.clone();
        pages.resize(12).unwrap();
        assert_eq!(b.used.load(Ordering::Relaxed), 12);
        assert!(pages.resize(13).is_err()); // backing refusal rolls reservation back
        assert_eq!(b.used.load(Ordering::Relaxed), 12);
        assert_eq!(
            pages.resize(21).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(pages.size(), 12);
        pages.punch_hole(0, 12).unwrap(); // size, not RSS, is charged
        assert_eq!(b.used.load(Ordering::Relaxed), 12);
        pages.resize(2).unwrap();
        drop(pages);
        assert_eq!(b.used.load(Ordering::Relaxed), 2);
        drop(clone);
        assert_eq!(b.used.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn concurrent_resizes_keep_size_and_reservation_in_sync() {
        let b = Arc::new(Budget {
            used: AtomicU64::new(0),
            limit: 100,
        });
        let pages = Arc::new(
            BudgetedPages::new(0, b.clone(), || Ok(Arc::new(Pages(AtomicU64::new(0))))).unwrap(),
        );
        std::thread::scope(|scope| {
            for n in 1..8 {
                let pages = pages.clone();
                scope.spawn(move || {
                    for _ in 0..100 {
                        pages.resize(n).unwrap();
                    }
                });
            }
        });
        assert_eq!(b.used.load(Ordering::Relaxed), pages.size());
        drop(pages);
        assert_eq!(b.used.load(Ordering::Relaxed), 0);
    }
}
