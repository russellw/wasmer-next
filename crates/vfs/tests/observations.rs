//! A provider may observe a name without granting a retained inode. Only an actual
//! parent-relative open grant can enter the inode cache or perform data operations.
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use futures::executor::block_on;
use wasixv2_abi::OpenFlags;
use wasixv2_vfs::{
    Attr, Clock, Cred, Ctx, Errno, FileType, Filesystem, FsInfo, FsResult, Handle, LookupEntry,
    LookupFlags, NewKind, NewNode, Node, ObservedAttr, OpenHow, OpenOptions, ResolvedEntry,
    Security, SetAttr, StatFs, Timestamp, Vfs,
};
use wasixv2_vfs_mem::MemFs;

struct Epoch;
impl Clock for Epoch {
    fn now(&self) -> Timestamp {
        Timestamp::default()
    }
}

struct ObservingFs {
    memory: MemFs,
    root: Arc<ObservingRoot>,
}
struct ObservingRoot {
    inner: Arc<dyn Node>,
    mode_on_open: AtomicU32,
    prepared: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    pending: AtomicBool,
    replace_on_open: AtomicBool,
    observe: AtomicBool,
    pin_allowed: AtomicBool,
    acquiring: Arc<AtomicBool>,
}

impl ObservingFs {
    fn new() -> Arc<Self> {
        let memory = MemFs::new(Arc::new(Epoch), 0o777, 1, 1);
        let root = Arc::new(ObservingRoot {
            inner: memory.root(),
            mode_on_open: AtomicU32::new(u32::MAX),
            prepared: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            pending: AtomicBool::new(false),
            replace_on_open: AtomicBool::new(false),
            observe: AtomicBool::new(true),
            pin_allowed: AtomicBool::new(false),
            acquiring: Arc::new(AtomicBool::new(false)),
        });
        Arc::new(Self { memory, root })
    }

    fn add(&self, name: &[u8], mode: u32) -> Arc<dyn Node> {
        let new = NewNode {
            kind: NewKind::Regular,
            mode,
            uid: 1,
            gid: 1,
            umask: 0,
            task: 0,
            quota_exempt: false,
        };
        let (node, handle) = block_on(self.root.inner.create_open(
            name,
            &new,
            OpenOptions {
                write: true,
                ..Default::default()
            },
        ))
        .unwrap();
        block_on(handle.write_at(b"original", 0)).unwrap();
        node
    }
}

#[async_trait(?Send)]
impl Filesystem for ObservingFs {
    fn allow_hsm(&self) -> bool {
        true
    }
    fn info(&self) -> FsInfo {
        let mut info = self.memory.info();
        info.stable = false;
        info
    }
    fn root(&self) -> Arc<dyn Node> {
        self.root.clone()
    }
    async fn statfs(&self) -> FsResult<StatFs> {
        self.memory.statfs().await
    }
}

#[async_trait(?Send)]
impl Node for ObservingRoot {
    fn ino(&self) -> u64 {
        self.inner.ino()
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    async fn getattr(&self) -> FsResult<Attr> {
        self.inner.getattr().await
    }
    async fn setattr(&self, attr: &SetAttr) -> FsResult<Attr> {
        self.inner.setattr(attr).await
    }
    async fn lookup(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        if self.pin_allowed.load(Ordering::SeqCst) {
            self.inner.lookup(name).await
        } else {
            Err(Errno::EACCES)
        }
    }
    async fn lookup_entry(&self, name: &[u8]) -> FsResult<LookupEntry> {
        let node = self.inner.lookup(name).await?;
        if !self.observe.load(Ordering::SeqCst) {
            return Ok(LookupEntry::Pinned(node));
        }
        let attr = node.getattr().await?;
        Ok(LookupEntry::Observation(ObservedAttr::from(attr)))
    }
    async fn open_existing(
        &self,
        name: &[u8],
        options: OpenOptions,
    ) -> FsResult<(Arc<dyn Node>, Box<dyn Handle>)> {
        if self.replace_on_open.swap(false, Ordering::SeqCst) {
            self.inner
                .rename(
                    b"replacement",
                    &self.inner,
                    name,
                    wasixv2_vfs::RenameMode::Replace,
                )
                .await?;
        }
        let node = self.inner.lookup(name).await?;
        let mode = self.mode_on_open.load(Ordering::SeqCst);
        if mode != u32::MAX {
            node.setattr(&SetAttr {
                mode: Some(mode),
                ..Default::default()
            })
            .await?;
        }
        let handle = if matches!(
            node.file_type(),
            FileType::CharDevice | FileType::BlockDevice
        ) {
            Box::new(SpecialGrant) as Box<dyn Handle>
        } else {
            node.open(options).await?
        };
        self.active.fetch_add(1, Ordering::SeqCst);
        let grant: Box<dyn Handle> = Box::new(TrackedGrant {
            inner: handle,
            prepared: self.prepared.clone(),
            active: self.active.clone(),
            pending: self.pending.load(Ordering::SeqCst),
        });
        futures::future::poll_fn(|_| {
            if self.acquiring.load(Ordering::SeqCst) {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        Ok((node, grant))
    }
    async fn unlink(&self, name: &[u8]) -> FsResult<()> {
        self.inner.unlink(name).await
    }
    async fn rename(
        &self,
        name: &[u8],
        new_dir: &Arc<dyn Node>,
        new_name: &[u8],
        mode: wasixv2_vfs::RenameMode,
    ) -> FsResult<()> {
        let dir = new_dir
            .as_any()
            .downcast_ref::<ObservingRoot>()
            .ok_or(Errno::EXDEV)?;
        self.inner.rename(name, &dir.inner, new_name, mode).await
    }
    async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
        self.inner.open(options).await
    }
    async fn create_unnamed(
        &self,
        new: &NewNode<'_>,
        options: OpenOptions,
    ) -> FsResult<(Arc<dyn Node>, Box<dyn Handle>)> {
        self.inner.create_unnamed(new, options).await
    }
}

struct SpecialGrant;
#[async_trait(?Send)]
impl Handle for SpecialGrant {}

struct TrackedGrant {
    inner: Box<dyn Handle>,
    prepared: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    pending: bool,
}
impl Drop for TrackedGrant {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait(?Send)]
impl Handle for TrackedGrant {
    async fn prepare_open(&self) -> FsResult<()> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        if self.pending {
            futures::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> FsResult<usize> {
        self.inner.read_at(buf, offset).await
    }
    async fn write_at(&self, data: &[u8], offset: u64) -> FsResult<usize> {
        self.inner.write_at(data, offset).await
    }
    async fn set_size(&self, size: u64) -> FsResult<()> {
        self.inner.set_size(size).await
    }
}

#[test]
fn metadata_observation_needs_no_inode_grant_and_is_not_cached() {
    let fs = ObservingFs::new();
    fs.add(b"file", 0);
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let observed = block_on(vfs.lookup_entry(&cx, &root, b"file", LookupFlags::default()))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert!(matches!(observed, ResolvedEntry::Observation(_)));
    let attr = block_on(vfs.stat_entry(&observed)).unwrap();
    assert_eq!((attr.mode, attr.size), (0, 8));
    assert_eq!(block_on(vfs.access_entry(&cx, &observed, 0)), Ok(()));
    assert_eq!(
        block_on(vfs.access_entry(&cx, &observed, wasixv2_vfs::MAY_READ)),
        Err(Errno::EACCES)
    );
    assert_eq!(
        block_on(vfs.lookup(&cx, &root, b"file", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
}

#[test]
fn actual_open_grant_is_checked_before_truncation_and_cache_publication() {
    let fs = ObservingFs::new();
    let node = fs.add(b"file", 0o200);
    fs.root.mode_on_open.store(0, Ordering::SeqCst);
    let prepared = fs.root.prepared.clone();
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"file", &how))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
    assert_eq!(block_on(node.getattr()).unwrap().size, 8);
    assert_eq!(prepared.load(Ordering::SeqCst), 0);
    assert_eq!(
        block_on(vfs.lookup(&cx, &root, b"file", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
}

#[test]
fn write_only_observed_file_opens_and_truncates_through_its_granted_handle() {
    let fs = ObservingFs::new();
    let node = fs.add(b"file", 0o200);
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    let file = block_on(vfs.open(&cx, &root, b"file", &how))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(block_on(node.getattr()).unwrap().size, 0);
    assert_eq!(block_on(file.write_at(b"new", 0)), Ok(3));
    assert_eq!(block_on(node.getattr()).unwrap().size, 3);
}

#[test]
fn default_driver_lookup_entry_keeps_the_existing_pinned_contract() {
    let fs = MemFs::new(Arc::new(Epoch), 0o777, 1, 1);
    let root = fs.root();
    let new = NewNode {
        kind: NewKind::Regular,
        mode: 0,
        uid: 1,
        gid: 1,
        umask: 0,
        task: 0,
        quota_exempt: false,
    };
    let node = block_on(root.create(b"file", &new)).unwrap();
    match block_on(root.lookup_entry(b"file")).unwrap() {
        LookupEntry::Pinned(found) => assert_eq!(found.ino(), node.ino()),
        LookupEntry::Observation(_) => panic!("default adapter changed pinned behavior"),
    }
}

struct RefuseOpen;
impl wasixv2_vfs::Security for RefuseOpen {
    fn file_open(&self, path: &wasixv2_vfs::Path, _: u32, _: bool) -> FsResult<()> {
        assert_eq!(path.dentry.file_type(), FileType::Regular);
        Err(Errno::EPERM)
    }
    fn path_create(&self, _: &wasixv2_vfs::Path, _: FileType) -> FsResult<()> {
        Ok(())
    }
    fn path_remove(&self, _: &wasixv2_vfs::Path, _: &Arc<wasixv2_vfs::Dentry>) -> FsResult<()> {
        Ok(())
    }
    fn path_link(&self, _: &wasixv2_vfs::Path, _: &wasixv2_vfs::Path) -> FsResult<()> {
        Ok(())
    }
    fn path_rename(
        &self,
        _: &wasixv2_vfs::Path,
        _: &Arc<wasixv2_vfs::Dentry>,
        _: &wasixv2_vfs::Path,
        _: Option<&Arc<wasixv2_vfs::Dentry>>,
        _: bool,
    ) -> FsResult<()> {
        Ok(())
    }
    fn path_truncate(&self, _: &wasixv2_vfs::Path) -> FsResult<()> {
        Ok(())
    }
}

#[test]
fn security_denial_precedes_driver_completion_truncate_and_publication() {
    let fs = ObservingFs::new();
    let node = fs.add(b"file", 0o600);
    let prepared = fs.root.prepared.clone();
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let mut cred = Cred::user(1, 1);
    cred.security = Some(Arc::new(RefuseOpen));
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"file", &how))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EPERM)
    );
    assert_eq!(prepared.load(Ordering::SeqCst), 0);
    assert_eq!(block_on(node.getattr()).unwrap().size, 8);
    assert_eq!(
        block_on(vfs.lookup(&cx, &root, b"file", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
    // Existing security policies cannot accidentally authorize new observation mutations.
    assert_eq!(
        block_on(vfs.unlink(&cx, &root, b"file")).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EOPNOTSUPP)
    );
    assert!(
        block_on(vfs.lookup_entry(&cx, &root, b"file", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .is_ok()
    );
}

#[test]
fn parent_authorized_observed_unlink_and_replace_need_no_child_read_grant() {
    let fs = ObservingFs::new();
    fs.add(b"source", 0);
    fs.add(b"target", 0);
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    block_on(vfs.rename(
        &cx,
        &root,
        b"source",
        &root,
        b"target",
        wasixv2_vfs::RenameMode::Replace,
    ))
    .map_err(wasixv2_vfs::PathError::errno)
    .unwrap();
    assert_eq!(
        block_on(vfs.lookup_entry(&cx, &root, b"source", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::ENOENT)
    );
    block_on(vfs.unlink(&cx, &root, b"target"))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(
        block_on(vfs.lookup_entry(&cx, &root, b"target", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::ENOENT)
    );
}

#[test]
fn cancelling_grant_completion_drops_the_grant_without_data_or_publication() {
    use futures::FutureExt;
    let fs = ObservingFs::new();
    let node = fs.add(b"file", 0o600);
    fs.root.pending.store(true, Ordering::SeqCst);
    let active = fs.root.active.clone();
    let prepared = fs.root.prepared.clone();
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert!(vfs.open(&cx, &root, b"file", &how).now_or_never().is_none());
    assert_eq!(prepared.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(block_on(node.getattr()).unwrap().size, 8);
    assert_eq!(
        block_on(vfs.lookup(&cx, &root, b"file", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
}

#[test]
fn replacement_at_acquisition_uses_its_permissions_and_actual_inode() {
    for mode in [0, 0o600] {
        let fs = ObservingFs::new();
        let original = fs.add(b"file", 0o600);
        let replacement = fs.add(b"replacement", mode);
        assert_ne!(original.ino(), replacement.ino());
        fs.root.replace_on_open.store(true, Ordering::SeqCst);
        let prepared = fs.root.prepared.clone();
        let vfs = Vfs::new(fs);
        let root = vfs.root();
        let cred = Cred::user(1, 1);
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let how = OpenHow {
            flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
            mode: 0,
            lookup: LookupFlags::follow(),
        };
        let opened =
            block_on(vfs.open(&cx, &root, b"file", &how)).map_err(wasixv2_vfs::PathError::errno);
        if mode == 0 {
            assert_eq!(opened.err(), Some(Errno::EACCES));
            assert_eq!(prepared.load(Ordering::SeqCst), 0);
            assert_eq!(block_on(replacement.getattr()).unwrap().size, 8);
        } else {
            let file = opened.unwrap();
            assert_eq!(file.node().ino(), replacement.ino());
            assert_eq!(block_on(file.node().getattr()).unwrap().size, 0);
            assert_eq!(prepared.load(Ordering::SeqCst), 1);
        }
        assert_eq!(block_on(original.getattr()).unwrap().size, 8);
    }
}

#[test]
fn observed_regular_file_with_a_trailing_slash_never_becomes_a_data_grant() {
    let fs = ObservingFs::new();
    let original = fs.add(b"file", 0o600);
    let prepared = fs.root.prepared.clone();
    let vfs = Vfs::new(fs);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"file/", &how))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::ENOTDIR)
    );
    assert_eq!(prepared.load(Ordering::SeqCst), 0);
    assert_eq!(block_on(original.getattr()).unwrap().size, 8);
}

#[test]
fn observed_replacement_does_not_inherit_the_old_names_mount() {
    let fs = ObservingFs::new();
    fs.root.observe.store(false, Ordering::SeqCst);
    fs.root.pin_allowed.store(true, Ordering::SeqCst);
    fs.add(b"source", 0o600);
    let old = fs.add(b"point", 0o600);
    let vfs = Vfs::new(fs.clone());
    block_on(vfs.bind_mount(b"/source", b"/point", Default::default(), false)).unwrap();
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let no_xdev = LookupFlags {
        no_xdev: true,
        ..LookupFlags::follow()
    };
    assert_eq!(
        block_on(vfs.lookup_entry(&cx, &root, b"point", no_xdev))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EXDEV)
    );
    block_on(fs.root.inner.rename(
        b"point",
        &fs.root.inner,
        b"old",
        wasixv2_vfs::RenameMode::Replace,
    ))
    .unwrap();
    let replacement = fs.add(b"point", 0);
    assert_ne!(old.ino(), replacement.ino());
    fs.root.observe.store(true, Ordering::SeqCst);
    fs.root.pin_allowed.store(false, Ordering::SeqCst);
    for flags in [LookupFlags::follow(), no_xdev] {
        assert_eq!(
            block_on(vfs.lookup_entry(&cx, &root, b"point", flags))
                .map_err(wasixv2_vfs::PathError::errno)
                .err(),
            Some(Errno::EACCES)
        );
    }
    let how = OpenHow {
        flags: OpenFlags::O_RDONLY,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"point", &how))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
    assert_eq!(
        block_on(vfs.unlink(&cx, &root, b"point")).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EACCES)
    );
    assert_eq!(
        block_on(fs.root.inner.lookup(b"point")).unwrap().ino(),
        replacement.ino()
    );
    assert_eq!(
        block_on(fs.root.inner.lookup(b"old")).unwrap().ino(),
        old.ino()
    );
    block_on(replacement.setattr(&SetAttr {
        mode: Some(0o600),
        ..Default::default()
    }))
    .unwrap();
    fs.root.observe.store(false, Ordering::SeqCst);
    fs.root.pin_allowed.store(true, Ordering::SeqCst);
    let entry = block_on(vfs.lookup_entry(&cx, &root, b"point", no_xdev))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(
        block_on(vfs.stat_entry(&entry)).unwrap().ino,
        replacement.ino()
    );
    let opened = block_on(vfs.open(&cx, &root, b"point", &how))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(opened.node().ino(), replacement.ino());
    block_on(vfs.unlink(&cx, &root, b"point"))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(
        block_on(fs.root.inner.lookup(b"point")).err(),
        Some(Errno::ENOENT)
    );
}

#[test]
fn pending_acquisition_serializes_guest_unlink_and_rename_through_publication() {
    use futures::FutureExt;
    for rename in [false, true] {
        let fs = ObservingFs::new();
        let original = fs.add(b"file", 0o600);
        fs.add(b"target", 0o600);
        fs.root.acquiring.store(true, Ordering::SeqCst);
        let vfs = Vfs::new(fs.clone());
        let root = vfs.root();
        let cred = Cred::user(1, 1);
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let how = OpenHow {
            flags: OpenFlags::O_RDONLY,
            mode: 0,
            lookup: LookupFlags::follow(),
        };
        let mut opening = Box::pin(vfs.open(&cx, &root, b"file", &how));
        assert!(opening.as_mut().now_or_never().is_none());
        assert_eq!(fs.root.active.load(Ordering::SeqCst), 1);
        if rename {
            let mut moving = Box::pin(vfs.rename(
                &cx,
                &root,
                b"file",
                &root,
                b"target",
                wasixv2_vfs::RenameMode::Replace,
            ));
            assert!(moving.as_mut().now_or_never().is_none());
            fs.root.acquiring.store(false, Ordering::SeqCst);
            let opened = opening.as_mut().now_or_never().unwrap().unwrap();
            assert_eq!(opened.node().ino(), original.ino());
            fs.root.observe.store(false, Ordering::SeqCst);
            fs.root.pin_allowed.store(true, Ordering::SeqCst);
            assert_eq!(
                block_on(moving).map_err(wasixv2_vfs::PathError::errno),
                Ok(())
            );
            assert_eq!(vfs.d_path(&opened.path, &root), b"/target");
        } else {
            let mut removing = Box::pin(vfs.unlink(&cx, &root, b"file"));
            assert!(removing.as_mut().now_or_never().is_none());
            fs.root.acquiring.store(false, Ordering::SeqCst);
            let opened = opening.as_mut().now_or_never().unwrap().unwrap();
            assert_eq!(opened.node().ino(), original.ino());
            fs.root.observe.store(false, Ordering::SeqCst);
            fs.root.pin_allowed.store(true, Ordering::SeqCst);
            assert_eq!(
                block_on(removing).map_err(wasixv2_vfs::PathError::errno),
                Ok(())
            );
            assert_eq!(vfs.d_path(&opened.path, &root), b"/file (deleted)");
        }
        assert_eq!(
            block_on(fs.root.inner.lookup(b"file")).err(),
            Some(Errno::ENOENT)
        );
    }
}

struct PermissionWait;
#[async_trait(?Send)]
impl wasixv2_vfs::LeaseWait for PermissionWait {
    fn now(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn break_time(&self) -> Option<std::time::Duration> {
        None
    }
    async fn wait<'a>(
        &'a self,
        changed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>,
        _: Option<std::time::Duration>,
    ) -> FsResult<()> {
        changed.await;
        Ok(())
    }
}
struct PendingPolicy {
    hsm: bool,
    requested: AtomicUsize,
}
impl wasixv2_vfs::FsWatcher for PendingPolicy {
    fn event(&self, _: &wasixv2_vfs::FsEvent<'_>) {}
    fn permission(
        &self,
        path: &wasixv2_vfs::Path,
        perm: wasixv2_vfs::Perm,
    ) -> Option<wasixv2_vfs::PermAnswer> {
        let selected = if self.hsm {
            matches!(perm, wasixv2_vfs::Perm::PreAccess { .. })
        } else {
            perm == wasixv2_vfs::Perm::Open
        };
        if !selected {
            return None;
        }
        assert_eq!(path.dentry.file_type(), FileType::Regular);
        self.requested.fetch_add(1, Ordering::SeqCst);
        Some(Box::pin(futures::future::pending()))
    }
}

#[test]
fn pending_open_and_hsm_policy_hold_parent_lock_and_cancel_without_truncation() {
    use futures::FutureExt;
    for hsm in [false, true] {
        let fs = ObservingFs::new();
        let original = fs.add(b"file", 0o600);
        let vfs = Vfs::new(fs.clone());
        let policy = Arc::new(PendingPolicy {
            hsm,
            requested: AtomicUsize::new(0),
        });
        vfs.set_watcher(policy.clone());
        let root = vfs.root();
        let cred = Cred::user(1, 1);
        let wait = PermissionWait;
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: Some(&wait),
        };
        let how = OpenHow {
            flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
            mode: 0,
            lookup: LookupFlags::follow(),
        };
        let mut opening = Box::pin(vfs.open(&cx, &root, b"file", &how));
        assert!(opening.as_mut().now_or_never().is_none());
        assert_eq!(policy.requested.load(Ordering::SeqCst), 1);
        assert_eq!(fs.root.active.load(Ordering::SeqCst), 1);
        assert_eq!(fs.root.prepared.load(Ordering::SeqCst), 0);
        let mut removing = Box::pin(vfs.unlink(&cx, &root, b"file"));
        assert!(removing.as_mut().now_or_never().is_none());
        drop(opening);
        assert_eq!(
            block_on(removing).map_err(wasixv2_vfs::PathError::errno),
            Ok(())
        );
        assert_eq!(fs.root.active.load(Ordering::SeqCst), 0);
        assert_eq!(fs.root.prepared.load(Ordering::SeqCst), 0);
        assert_eq!(block_on(original.getattr()).unwrap().size, 8);
    }
}

#[test]
fn acquired_replacement_uses_nonowner_acl_before_grant_completion() {
    use wasixv2_vfs::{AclEntry, PosixAcl, XATTR_NAME_POSIX_ACL_ACCESS, XattrSet};
    let fs = ObservingFs::new();
    let original = fs.add(b"file", 0o666);
    let replacement = fs.add(b"replacement", 0o666);
    let acl = PosixAcl(
        [
            (1, 6, u32::MAX),
            (2, 0, 2),
            (4, 6, u32::MAX),
            (16, 6, u32::MAX),
            (32, 6, u32::MAX),
        ]
        .into_iter()
        .map(|(tag, perm, id)| AclEntry { tag, perm, id })
        .collect(),
    );
    block_on(replacement.setxattr(XATTR_NAME_POSIX_ACL_ACCESS, &acl.to_stored(), XattrSet::Any))
        .unwrap();
    fs.root.replace_on_open.store(true, Ordering::SeqCst);
    let vfs = Vfs::new(fs.clone());
    let root = vfs.root();
    let cred = Cred::user(2, 2);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"file", &how)).err(),
        Some(Errno::EACCES.into())
    );
    assert_eq!(fs.root.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(fs.root.active.load(Ordering::SeqCst), 0);
    assert_eq!(block_on(original.getattr()).unwrap().size, 8);
    assert_eq!(block_on(replacement.getattr()).unwrap().size, 8);
}

#[test]
fn acquired_object_type_and_mount_policy_precede_grant_completion() {
    use wasixv2_vfs::{Device, MountFlags};
    for case in 0..4 {
        let fs = ObservingFs::new();
        let original = fs.add(b"file", 0o777);
        let (flags, mount, kind, expected) = match case {
            0 => (
                OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY,
                MountFlags::default(),
                NewKind::Regular,
                Errno::ENOTDIR,
            ),
            1 => (
                wasixv2_vfs::FMODE_EXEC,
                MountFlags {
                    noexec: true,
                    ..Default::default()
                },
                NewKind::Regular,
                Errno::EACCES,
            ),
            2 => (
                OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
                MountFlags {
                    read_only: true,
                    ..Default::default()
                },
                NewKind::Regular,
                Errno::EROFS,
            ),
            _ => (
                OpenFlags::O_RDONLY,
                MountFlags {
                    nodev: true,
                    ..Default::default()
                },
                NewKind::CharDevice(Device::default()),
                Errno::EACCES,
            ),
        };
        let replacement = block_on(fs.root.inner.create(
            b"replacement",
            &NewNode {
                kind,
                mode: 0o777,
                uid: 1,
                gid: 1,
                umask: 0,
                task: 0,
                quota_exempt: false,
            },
        ))
        .unwrap();
        fs.root.replace_on_open.store(true, Ordering::SeqCst);
        let base = Arc::new(MemFs::new(Arc::new(Epoch), 0o777, 1, 1));
        block_on(base.root().create(
            b"m",
            &NewNode {
                kind: NewKind::Directory,
                mode: 0o777,
                uid: 1,
                gid: 1,
                umask: 0,
                task: 0,
                quota_exempt: false,
            },
        ))
        .unwrap();
        let vfs = Vfs::new(base);
        block_on(vfs.mount(b"/m", fs.clone(), mount, false)).unwrap();
        let root = vfs.root();
        let cred = Cred::user(1, 1);
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let how = OpenHow {
            flags,
            mode: 0,
            lookup: LookupFlags::follow(),
        };
        assert_eq!(
            block_on(vfs.open(&cx, &root, b"/m/file", &how)).err(),
            Some(expected.into())
        );
        assert_eq!(fs.root.prepared.load(Ordering::SeqCst), 0);
        assert_eq!(fs.root.active.load(Ordering::SeqCst), 0);
        assert_eq!(block_on(original.getattr()).unwrap().size, 8);
        assert_eq!(block_on(replacement.getattr()).unwrap().size, 0);
    }
}

#[test]
fn existing_canonical_seals_block_observed_truncate_before_handle_completion() {
    use wasixv2_abi::SealFlags;
    let fs = ObservingFs::new();
    let vfs = Vfs::new(fs.clone());
    let root = vfs.root();
    let new = NewNode {
        kind: NewKind::Regular,
        mode: 0o600,
        uid: 1,
        gid: 1,
        umask: 0,
        task: 0,
        quota_exempt: false,
    };
    let held = block_on(vfs.open_unnamed(&root.mnt, b"sealed", &new, SealFlags(0))).unwrap();
    assert_eq!(block_on(held.write_at(b"original", 0)), Ok(8));
    block_on(vfs.add_seals(&held, SealFlags::F_SEAL_SHRINK)).unwrap();
    block_on(fs.root.inner.link(b"file", held.node())).unwrap();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"file", &how)).err(),
        Some(Errno::EPERM.into())
    );
    assert_eq!(fs.root.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(fs.root.active.load(Ordering::SeqCst), 0);
    assert_eq!(block_on(held.node().getattr()).unwrap().size, 8);
    assert_eq!(
        held.path.dentry.inode().seals(),
        Some(SealFlags::F_SEAL_SHRINK)
    );
}

#[test]
fn observation_walks_preserve_namespace_fallback_and_boundary_provenance() {
    use futures::FutureExt;
    use wasixv2_vfs::{NamespaceDirectory, PathError};
    for fallback in [None, Some(0)] {
        let fs = ObservingFs::new();
        let original = fs.add(b"file", 0o600);
        let vfs = Vfs::new(fs.clone());
        let source = vfs.open_tree(vfs.namespace(), &vfs.root(), true).unwrap();
        let boot = vfs
            .bootstrap_namespace(
                vfs.namespace(),
                vfs.namespace().owner().clone(),
                &[NamespaceDirectory {
                    source,
                    lookup_name: Some(b"named".to_vec()),
                }],
                fallback,
            )
            .unwrap();
        let cred = Cred::user(1, 1);
        let cx = Ctx {
            cred: &cred,
            root: &boot.root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let named =
            block_on(vfs.lookup_entry(&cx, &boot.root, b"/named/file", LookupFlags::follow()))
                .unwrap();
        assert_eq!(
            block_on(vfs.stat_entry(&named)).unwrap().ino,
            original.ino()
        );
        let entry = block_on(vfs.lookup_entry(&cx, &boot.root, b"/file", LookupFlags::follow()));
        if fallback.is_some() {
            assert_eq!(
                block_on(vfs.stat_entry(&entry.unwrap())).unwrap().ino,
                original.ino()
            );
            let how = OpenHow {
                flags: OpenFlags::O_CREAT | OpenFlags::O_WRONLY,
                mode: 0o600,
                lookup: LookupFlags::follow(),
            };
            fs.root.acquiring.store(true, Ordering::SeqCst);
            let mut opening = Box::pin(vfs.open(&cx, &boot.root, b"file", &how));
            assert!(opening.as_mut().now_or_never().is_none());
            let mut removing = Box::pin(vfs.unlink(&cx, &boot.root, b"/named/file"));
            assert!(removing.as_mut().now_or_never().is_none());
            drop(removing);
            fs.root.acquiring.store(false, Ordering::SeqCst);
            let file = block_on(opening).unwrap();
            assert_eq!(file.node().ino(), original.ino());
        } else {
            assert!(matches!(entry, Err(PathError::NamespaceBoundary)));
            assert_eq!(
                block_on(vfs.lookup_entry(
                    &cx,
                    &boot.root,
                    b"/missing/file",
                    LookupFlags::follow()
                ))
                .err()
                .unwrap(),
                PathError::NamespaceBoundary
            );
        }
        assert_eq!(
            block_on(vfs.unlink(&cx, &boot.root, b"named")),
            Err(PathError::NamespaceMutation)
        );
        assert_eq!(
            block_on(fs.root.inner.lookup(b"file")).unwrap().ino(),
            original.ino()
        );
    }
}

struct NamePolicy {
    deny: bool,
    checked: AtomicUsize,
}
impl wasixv2_vfs::Security for NamePolicy {
    fn file_open(&self, path: &wasixv2_vfs::Path, access: u32, truncate: bool) -> FsResult<()> {
        RefuseOpen.file_open(path, access, truncate)
    }
    fn path_create(&self, dir: &wasixv2_vfs::Path, kind: FileType) -> FsResult<()> {
        RefuseOpen.path_create(dir, kind)
    }
    fn path_remove(
        &self,
        dir: &wasixv2_vfs::Path,
        victim: &Arc<wasixv2_vfs::Dentry>,
    ) -> FsResult<()> {
        RefuseOpen.path_remove(dir, victim)
    }
    fn path_link(&self, old: &wasixv2_vfs::Path, new: &wasixv2_vfs::Path) -> FsResult<()> {
        RefuseOpen.path_link(old, new)
    }
    fn path_rename(
        &self,
        dir: &wasixv2_vfs::Path,
        old: &Arc<wasixv2_vfs::Dentry>,
        new_dir: &wasixv2_vfs::Path,
        new: Option<&Arc<wasixv2_vfs::Dentry>>,
        exchange: bool,
    ) -> FsResult<()> {
        RefuseOpen.path_rename(dir, old, new_dir, new, exchange)
    }
    fn path_truncate(&self, path: &wasixv2_vfs::Path) -> FsResult<()> {
        RefuseOpen.path_truncate(path)
    }
    fn path_remove_observation(&self, entry: wasixv2_vfs::NameView<'_>) -> FsResult<()> {
        assert_eq!(entry.name, b"target");
        assert_eq!(entry.attr.mode, 0);
        assert!(entry.directory.dentry.is_dir());
        self.checked.fetch_add(1, Ordering::SeqCst);
        if self.deny { Err(Errno::EPERM) } else { Ok(()) }
    }
    fn path_rename_observations(
        &self,
        old: wasixv2_vfs::NameView<'_>,
        new_directory: &wasixv2_vfs::Path,
        new_name: &[u8],
        target: Option<wasixv2_vfs::NameView<'_>>,
        exchange: bool,
    ) -> FsResult<()> {
        assert_eq!(old.name, b"source");
        assert_eq!(old.attr.mode, 0);
        assert_eq!(new_name, b"target");
        assert_eq!(target.unwrap().attr.mode, 0);
        assert!(new_directory.dentry.is_dir());
        assert!(!exchange);
        self.checked.fetch_add(1, Ordering::SeqCst);
        if self.deny { Err(Errno::EPERM) } else { Ok(()) }
    }
}

#[test]
fn explicit_observation_security_hooks_authorize_or_reject_name_mutations() {
    for deny in [false, true] {
        let fs = ObservingFs::new();
        let source = fs.add(b"source", 0);
        let target = fs.add(b"target", 0);
        let vfs = Vfs::new(fs.clone());
        let root = vfs.root();
        let policy = Arc::new(NamePolicy {
            deny,
            checked: AtomicUsize::new(0),
        });
        let mut cred = Cred::user(1, 1);
        cred.security = Some(policy.clone());
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let expected = if deny {
            Err(Errno::EPERM.into())
        } else {
            Ok(())
        };
        assert_eq!(
            block_on(vfs.rename(
                &cx,
                &root,
                b"source",
                &root,
                b"target",
                wasixv2_vfs::RenameMode::Replace
            )),
            expected
        );
        let selected = block_on(fs.root.inner.lookup(b"target")).unwrap();
        assert_eq!(
            selected.ino(),
            if deny { target.ino() } else { source.ino() }
        );
        assert_eq!(block_on(vfs.unlink(&cx, &root, b"target")), expected);
        assert_eq!(block_on(fs.root.inner.lookup(b"target")).is_ok(), deny);
        assert_eq!(block_on(fs.root.inner.lookup(b"source")).is_ok(), deny);
        assert_eq!(policy.checked.load(Ordering::SeqCst), 2);
    }
}
