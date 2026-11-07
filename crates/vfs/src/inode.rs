//! The VFS's own inode (Linux's in-core `struct inode` and the inode cache).
//!
//! A driver may hand out several `Node` values for one object (a host directory opens a new
//! descriptor per lookup). The VFS interns them per `(superblock, ino)`, so everything it keeps
//! per object lives in one place for as long as anything (a dentry, an open file) holds it: the
//! directory lock, the removed-directory and linkable flags, a directory's single dentry, a
//! file's seals, and the kernel object bound to it (a FIFO's pipe, a bound Unix socket).

use std::{
    any::Any,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicI32, AtomicU32, Ordering},
    },
};

use futures_util::lock::{Mutex as AsyncMutex, OwnedMutexGuard};

use wasixv2_abi::{Errno, SealFlags};

use crate::{
    dentry::Dentry,
    driver::Node,
    mount::Superblock,
    posix_acl::{AclKind, CachedAcl},
    types::{FileType, TMPFS_MAGIC},
};

/// Held while a directory's entries are looked up or changed, or while a sealable file changes
/// (`i_rwsem`).
pub(crate) type DirLock = OwnedMutexGuard<()>;

pub struct Inode {
    node: Arc<dyn Node>,
    sb: Arc<Superblock>,
    lock: Arc<AsyncMutex<()>>,
    state: Mutex<State>,
    /// A regular file of tmpfs, which can have seals.
    pub(crate) sealable: bool,
    /// Its seals (`SealFlags`), changed only under `lock`; see the `seals` module.
    pub(crate) seals: AtomicU32,
    /// Writable shared mappings of the file, or below zero once `F_SEAL_WRITE` denies them
    /// (`i_mmap_writable`).
    pub(crate) mmap_writable: AtomicI32,
    /// Open files and truncations that write the file (`i_writecount`).
    writecount: AtomicI32,
    /// Open files that only read it (`i_readcount`).
    readcount: AtomicI32,
}

#[derive(Default)]
struct State {
    /// A removed directory: nothing may be created in it (`S_DEAD`).
    dead: bool,
    /// An `O_TMPFILE` file that `linkat` may still give a name (`I_LINKABLE`).
    linkable: bool,
    /// The one dentry of a directory (Linux keeps a single alias per directory).
    alias: Weak<Dentry>,
    /// The dentry made last for the object, of any type (`d_find_any_alias`), so a file
    /// handle decodes to a name the object has.
    last: Weak<Dentry>,
    /// The access and default ACLs as last read or set (`i_acl`, `i_default_acl`).
    acls: [CachedAcl; 2],
    acl_version: u64,
    /// The kernel object bound to the inode: a FIFO's pipe (`i_pipe`) or a bound Unix socket.
    /// Weak: the object lives as long as its users (open FIFO ends, the bound socket, which in
    /// turn holds the inode through its path).
    bound: Option<Weak<dyn Any + Send + Sync>>,
}

/// A kernel object bound to an inode.
pub type Bound = Arc<dyn Any + Send + Sync>;

impl Inode {
    pub fn node(&self) -> &Arc<dyn Node> {
        &self.node
    }

    pub fn sb(&self) -> &Arc<Superblock> {
        &self.sb
    }

    pub fn ino(&self) -> u64 {
        self.node.ino()
    }

    pub fn file_type(&self) -> FileType {
        self.node.file_type()
    }

    /// Takes the directory lock.
    pub(crate) async fn lock(&self) -> DirLock {
        self.lock.clone().lock_owned().await
    }

    pub(crate) fn lock_ptr(&self) -> usize {
        Arc::as_ptr(&self.lock) as usize
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.state.lock().unwrap().dead || self.node.unlinked_directory()
    }

    pub(crate) fn set_dead(&self) {
        self.state.lock().unwrap().dead = true;
    }

    pub(crate) fn is_linkable(&self) -> bool {
        self.state.lock().unwrap().linkable
    }

    pub(crate) fn set_linkable(&self, linkable: bool) {
        self.state.lock().unwrap().linkable = linkable;
    }

    pub(crate) fn alias(&self) -> Option<Arc<Dentry>> {
        self.state.lock().unwrap().alias.upgrade()
    }

    pub(crate) fn set_alias(&self, dentry: &Arc<Dentry>) {
        self.state.lock().unwrap().alias = Arc::downgrade(dentry);
    }

    /// A live dentry of the object, preferring one that still has its name.
    pub(crate) fn any_alias(&self) -> Option<Arc<Dentry>> {
        let state = self.state.lock().unwrap();
        let alias = state.alias.upgrade().or_else(|| state.last.upgrade())?;
        Some(alias)
    }

    pub(crate) fn cached_acl(&self, kind: AclKind) -> CachedAcl {
        let mut state = self.state.lock().unwrap();
        let version = self.node.acl_version();
        if state.acl_version != version {
            state.acls = [CachedAcl::Unknown, CachedAcl::Unknown];
            state.acl_version = version;
        }
        state.acls[kind.index()].clone()
    }

    pub(crate) fn cache_acl(&self, kind: AclKind, acl: CachedAcl) {
        let mut state = self.state.lock().unwrap();
        let version = self.node.acl_version();
        if state.acl_version != version {
            state.acls = [CachedAcl::Unknown, CachedAcl::Unknown];
            state.acl_version = version;
        }
        state.acls[kind.index()] = acl;
    }

    pub(crate) fn set_last(&self, dentry: &Arc<Dentry>) {
        self.state.lock().unwrap().last = Arc::downgrade(dentry);
    }

    /// The live kernel object bound to this inode, if any.
    pub fn bound(&self) -> Option<Bound> {
        self.state.lock().unwrap().bound.as_ref()?.upgrade()
    }

    /// The bound object, or `make()`'s, bound now (a FIFO's first open allocates its pipe).
    pub fn bound_or_bind(&self, make: impl FnOnce() -> Bound) -> Bound {
        let mut state = self.state.lock().unwrap();
        if let Some(object) = state.bound.as_ref().and_then(Weak::upgrade) {
            return object;
        }
        let object = make();
        state.bound = Some(Arc::downgrade(&object));
        object
    }

    /// Like bound_or_bind, but a failed factory leaves the inode unbound.
    /// Holding the inode lock through the factory prevents duplicate allocations.
    pub fn try_bound_or_bind(
        &self,
        make: impl FnOnce() -> crate::FsResult<Bound>,
    ) -> crate::FsResult<Bound> {
        let mut state = self.state.lock().unwrap();
        if let Some(object) = state.bound.as_ref().and_then(Weak::upgrade) {
            return Ok(object);
        }
        let object = make()?;
        state.bound = Some(Arc::downgrade(&object));
        Ok(object)
    }

    /// Binds `object` unless a live one is bound already (`false`), as `bind` on a Unix socket
    /// path does.
    pub fn bind(&self, object: &Bound) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.bound.as_ref().is_some_and(|b| b.strong_count() > 0) {
            return false;
        }
        state.bound = Some(Arc::downgrade(object));
        true
    }
}

impl Inode {
    /// Whether anything has the file open for writing (`inode_is_open_for_write`).
    pub fn open_for_write(&self) -> bool {
        self.writecount.load(Ordering::SeqCst) > 0
    }

    /// `i_writecount` and `i_readcount`.
    pub(crate) fn open_counts(&self) -> (i32, i32) {
        (
            self.writecount.load(Ordering::SeqCst),
            self.readcount.load(Ordering::SeqCst),
        )
    }
}

/// What an open file, or a truncation while it runs, counts on its inode: write access
/// (`get_write_access`) or a read-only open (`i_readcount_inc`). Given back when dropped.
pub(crate) struct OpenAccess {
    inode: Arc<Inode>,
    write: bool,
}

impl OpenAccess {
    pub(crate) fn new(inode: &Arc<Inode>, write: bool) -> Result<Self, Errno> {
        let count = match write {
            true => &inode.writecount,
            false => &inode.readcount,
        };
        if write {
            // include/linux/fs.h get_write_access: atomic_inc_unless_negative.
            count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n >= 0).then_some(n + 1)
                })
                .map_err(|_| Errno::ETXTBSY)?;
        } else {
            count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(Self {
            inode: inode.clone(),
            write,
        })
    }
}

impl Drop for OpenAccess {
    fn drop(&mut self) {
        let count = match self.write {
            true => &self.inode.writecount,
            false => &self.inode.readcount,
        };
        count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An executable's deny_write_access, shared by exec preparation and mm->exe_file holders.
/// include/linux/fs.h deny_write_access/allow_write_access; fs/exec.c do_open_execat.
pub struct ExecAccess {
    inode: Arc<Inode>,
}

impl Inode {
    pub fn deny_write_access(self: &Arc<Self>) -> Result<Arc<ExecAccess>, Errno> {
        self.writecount
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n <= 0).then_some(n - 1)
            })
            .map_err(|_| Errno::ETXTBSY)?;
        Ok(Arc::new(ExecAccess {
            inode: self.clone(),
        }))
    }
}

impl Drop for ExecAccess {
    fn drop(&mut self) {
        self.inode.writecount.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for Inode {
    fn drop(&mut self) {
        let mut inodes = self.sb.inodes.lock().unwrap();
        let ino = self.node.ino();
        if inodes
            .get(&ino)
            .is_some_and(|weak| weak.strong_count() == 0)
        {
            inodes.remove(&ino);
        }
    }
}

impl Superblock {
    /// Look up an already-retained identity without admitting a new inode. The caller
    /// holds a genuine node from this superblock; retained nodes prevent inode-number reuse.
    pub(crate) fn retained_inode(&self, node: &Arc<dyn Node>) -> Option<Arc<Inode>> {
        self.inodes.lock().unwrap().get(&node.ino())?.upgrade()
    }

    /// A provisional inode for a genuine opened capability, before policy approval. It is
    /// not entered in the canonical cache and must never wrap a name observation.
    pub(crate) fn uncached_inode(self: &Arc<Self>, node: Arc<dyn Node>) -> Arc<Inode> {
        let sealable = self.info.magic == TMPFS_MAGIC && node.file_type() == FileType::Regular;
        Arc::new(Inode {
            node,
            sb: self.clone(),
            lock: Arc::default(),
            state: Mutex::default(),
            sealable,
            seals: AtomicU32::new(SealFlags::F_SEAL_SEAL.0),
            mmap_writable: AtomicI32::new(0),
            writecount: AtomicI32::new(0),
            readcount: AtomicI32::new(0),
        })
    }

    /// The VFS inode for `node` (`iget`): the live one with its inode number, else a new one.
    pub(crate) fn iget(self: &Arc<Self>, node: Arc<dyn Node>) -> Arc<Inode> {
        let ino = node.ino();
        let mut inodes = self.inodes.lock().unwrap();
        if let Some(inode) = inodes.get(&ino).and_then(Weak::upgrade) {
            return inode;
        }
        let inode = self.uncached_inode(node);
        inodes.insert(ino, Arc::downgrade(&inode));
        inode
    }
}

#[cfg(test)]
mod tests {
    use futures::{FutureExt, executor::block_on};
    use std::sync::atomic::AtomicBool;

    use super::*;
    use crate::{
        Attr, Filesystem, FsInfo, FsResult, FsWatcher, Perm, SetAttr, StatFs, Timestamp, Vfs,
        dentry::Dentry,
    };

    struct PolicyFs;
    struct PolicyNode(u64, FileType);
    #[async_trait::async_trait(?Send)]
    impl Filesystem for PolicyFs {
        fn info(&self) -> FsInfo {
            FsInfo {
                name: "policy",
                magic: TMPFS_MAGIC,
                name_max: 255,
                read_only: false,
                dev: None,
                has_btime: false,
                stable: false,
            }
        }
        fn root(&self) -> Arc<dyn Node> {
            Arc::new(PolicyNode(1, FileType::Directory))
        }
        async fn statfs(&self) -> FsResult<StatFs> {
            Ok(StatFs::default())
        }
    }
    #[async_trait::async_trait(?Send)]
    impl Node for PolicyNode {
        fn ino(&self) -> u64 {
            self.0
        }
        fn file_type(&self) -> FileType {
            self.1
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        async fn getattr(&self) -> FsResult<Attr> {
            Ok(Attr {
                ino: self.0,
                file_type: self.1,
                mode: 0o777,
                nlink: 1,
                uid: 1,
                gid: 1,
                rdev: Default::default(),
                size: 0,
                blocks: 0,
                blksize: 4096,
                atime: Timestamp::default(),
                mtime: Timestamp::default(),
                ctime: Timestamp::default(),
                btime: None,
                dev: None,
            })
        }
        async fn setattr(&self, _: &SetAttr) -> FsResult<Attr> {
            Err(Errno::EOPNOTSUPP)
        }
    }
    struct DenyAfterWait {
        expected: Arc<Inode>,
        release: Arc<AtomicBool>,
    }
    impl FsWatcher for DenyAfterWait {
        fn event(&self, _: &crate::FsEvent<'_>) {}
        fn permission(&self, path: &crate::Path, _: Perm) -> Option<crate::PermAnswer> {
            assert!(Arc::ptr_eq(path.dentry.inode(), &self.expected));
            let release = self.release.clone();
            Some(Box::pin(futures::future::poll_fn(move |_| {
                if release.load(Ordering::SeqCst) {
                    std::task::Poll::Ready(Err(Errno::EACCES))
                } else {
                    std::task::Poll::Pending
                }
            })))
        }
    }

    #[test]
    fn policy_views_never_publish_aliases_while_permission_is_pending_or_denied() {
        for kind in [FileType::Regular, FileType::Directory] {
            let node: Arc<dyn Node> = Arc::new(PolicyNode(2, kind));
            let vfs = Vfs::new(Arc::new(PolicyFs));
            let root = vfs.root();
            let held = {
                let _lock = block_on(root.dentry.inode().lock());
                root.dentry.child(b"held", node.clone())
            };
            let inode = held.inode().clone();
            let count = root.dentry.sb().inodes.lock().unwrap().len();
            let assert_unchanged = || {
                let state = inode.state.lock().unwrap();
                assert!(Arc::ptr_eq(&state.last.upgrade().unwrap(), &held));
                if kind == FileType::Directory {
                    assert!(Arc::ptr_eq(&state.alias.upgrade().unwrap(), &held));
                } else {
                    assert!(state.alias.upgrade().is_none());
                }
                assert!(Arc::ptr_eq(
                    &root.dentry.cached_child(b"held").unwrap(),
                    &held
                ));
                assert!(root.dentry.cached_child(b"candidate").is_none());
                assert_eq!(root.dentry.sb().inodes.lock().unwrap().len(), count);
            };
            let fresh = Dentry::provisional(&root.dentry, b"candidate", node);
            assert!(!Arc::ptr_eq(fresh.inode(), &inode));
            let policy = crate::Path {
                mnt: root.mnt.clone(),
                dentry: fresh.policy_view(),
            };
            let watcher = DenyAfterWait {
                expected: inode.clone(),
                release: Arc::new(AtomicBool::new(false)),
            };
            let mut answer = watcher.permission(&policy, Perm::Open).unwrap();
            assert!(answer.as_mut().now_or_never().is_none());
            assert_unchanged();
            watcher.release.store(true, Ordering::SeqCst);
            assert_eq!(answer.as_mut().now_or_never(), Some(Err(Errno::EACCES)));
            drop(answer);
            drop(policy);
            drop(fresh);
            assert_unchanged();

            // A real newly acquired object gets only an uncached policy identity.
            let node: Arc<dyn Node> = Arc::new(PolicyNode(3, kind));
            let fresh = Dentry::provisional(&root.dentry, b"new", node.clone());
            let policy = fresh.policy_view();
            assert!(Arc::ptr_eq(fresh.inode(), policy.inode()));
            assert!(root.dentry.sb().retained_inode(&node).is_none());
            let state = fresh.inode().state.lock().unwrap();
            assert!(state.alias.upgrade().is_none());
            assert!(state.last.upgrade().is_none());
            assert!(root.dentry.cached_child(b"new").is_none());
            drop(state);
            drop(policy);
            drop(fresh);
            assert_unchanged();
        }
    }
}
