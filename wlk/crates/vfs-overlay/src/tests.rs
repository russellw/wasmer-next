use futures::executor::block_on;
use wasixv2_vfs::{Clock, Timestamp};
use wasixv2_vfs_mem::MemFs;

use super::*;

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::new(1_700_000_000, 0)
    }
}

fn mem() -> Arc<dyn Filesystem> {
    Arc::new(MemFs::new(Arc::new(FixedClock), 0o755, 1, 1))
}

fn new(kind: NewKind<'_>) -> NewNode<'_> {
    NewNode {
        umask: 0,
        kind,
        mode: 0o644,
        uid: 1,
        gid: 1,
        task: 0,
        quota_exempt: false,
    }
}

fn write(dir: &Arc<dyn Node>, name: &[u8], data: &[u8]) -> Arc<dyn Node> {
    let file = block_on(dir.create(name, &new(NewKind::Regular))).unwrap();
    let handle = block_on(file.open(OpenOptions {
        write: true,
        ..OpenOptions::default()
    }))
    .unwrap();
    block_on(handle.write_at(data, 0)).unwrap();
    file
}

fn mkdir(dir: &Arc<dyn Node>, name: &[u8]) -> Arc<dyn Node> {
    block_on(dir.create(name, &new(NewKind::Directory))).unwrap()
}

fn lookup(dir: &Arc<dyn Node>, name: &[u8]) -> FsResult<Arc<dyn Node>> {
    block_on(dir.lookup(name))
}

fn read(node: &Arc<dyn Node>) -> Vec<u8> {
    let handle = block_on(node.open(OpenOptions {
        read: true,
        ..OpenOptions::default()
    }))
    .unwrap();
    let mut buf = vec![0; 64];
    let n = block_on(handle.read_at(&mut buf, 0)).unwrap();
    buf.truncate(n);
    buf
}

struct Names(Vec<(Vec<u8>, u64, u64)>, usize);

impl DirSink for Names {
    fn push(&mut self, entry: DirEntry<'_>) -> bool {
        if self.0.len() == self.1 {
            return false;
        }
        self.0.push((entry.name.to_vec(), entry.ino, entry.next));
        true
    }
}

fn list(dir: &Arc<dyn Node>) -> Vec<Vec<u8>> {
    let handle = block_on(dir.open(OpenOptions::default())).unwrap();
    let mut names = Names(Vec::new(), usize::MAX);
    block_on(handle.readdir(0, &mut names)).unwrap();
    let mut names: Vec<_> = names.0.into_iter().map(|(name, _, _)| name).collect();
    names.sort();
    names
}

/// A lower layer with `d/f` = "hello" carrying xattr `user.x`, under an empty upper layer.
fn setup() -> (
    Arc<dyn Filesystem>,
    Arc<dyn Filesystem>,
    Arc<dyn Filesystem>,
) {
    let lower = mem();
    let d = mkdir(&lower.root(), b"d");
    let f = write(&d, b"f", b"hello");
    block_on(f.setxattr(b"user.x", b"1", XattrSet::Any)).unwrap();
    let upper = mem();
    let overlay = OverlayFs::new(Some(upper.clone()), vec![lower.clone()]);
    (overlay, upper, lower)
}

#[test]
fn write_copies_up_file_and_parents_keeping_ino() {
    let (overlay, upper, lower) = setup();
    let d = lookup(&overlay.root(), b"d").unwrap();
    let f = lookup(&d, b"f").unwrap();
    let ino = f.ino();
    let reader = block_on(f.open(OpenOptions {
        read: true,
        ..OpenOptions::default()
    }))
    .unwrap();

    let writer = block_on(f.open(OpenOptions {
        write: true,
        ..OpenOptions::default()
    }))
    .unwrap();
    block_on(writer.write_at(b"J", 0)).unwrap();

    let upper_f = lookup(&lookup(&upper.root(), b"d").unwrap(), b"f").unwrap();
    assert_eq!(read(&upper_f), b"Jello");
    assert_eq!(block_on(upper_f.getxattr(b"user.x")), Ok(b"1".to_vec()));
    let lower_f = lookup(&lookup(&lower.root(), b"d").unwrap(), b"f").unwrap();
    assert_eq!(read(&lower_f), b"hello");
    // A reader opened before the copy-up sees the copy.
    let mut buf = [0; 5];
    assert_eq!(block_on(reader.read_at(&mut buf, 0)), Ok(5));
    assert_eq!(&buf, b"Jello");
    let again = lookup(&d, b"f").unwrap();
    assert_eq!(
        (again.ino(), block_on(again.getattr()).unwrap().ino),
        (ino, ino)
    );
}

#[test]
fn lower_hard_links_are_separate_objects_with_their_own_inos() {
    let (overlay, _upper, lower) = setup();
    let lower_d = lookup(&lower.root(), b"d").unwrap();
    let lower_f = lookup(&lower_d, b"f").unwrap();
    block_on(lower_d.link(b"g", &lower_f)).unwrap();

    let d = lookup(&overlay.root(), b"d").unwrap();
    let (f, g) = (lookup(&d, b"f").unwrap(), lookup(&d, b"g").unwrap());
    assert_ne!(f.ino(), g.ino());
    let ino = f.ino();
    block_on(f.setattr(&SetAttr::default())).unwrap();
    assert_eq!(lookup(&d, b"f").unwrap().ino(), ino);
    assert_eq!(lookup(&d, b"g").unwrap().ino(), g.ino());
    assert_ne!(ino, g.ino());
}

#[test]
fn setattr_and_xattr_copy_up() {
    let (overlay, upper, _) = setup();
    let f = lookup(&lookup(&overlay.root(), b"d").unwrap(), b"f").unwrap();
    let attr = block_on(f.setattr(&SetAttr {
        size: Some(2),
        ..SetAttr::default()
    }))
    .unwrap();
    assert_eq!(attr.size, 2);
    block_on(f.setxattr(b"user.y", b"2", XattrSet::Any)).unwrap();
    let upper_f = lookup(&lookup(&upper.root(), b"d").unwrap(), b"f").unwrap();
    assert_eq!(read(&upper_f), b"he");
    assert_eq!(block_on(upper_f.getxattr(b"user.y")), Ok(b"2".to_vec()));
}

#[test]
fn unlink_of_lower_file_leaves_whiteout() {
    let (overlay, upper, lower) = setup();
    let d = lookup(&overlay.root(), b"d").unwrap();

    block_on(d.unlink(b"f")).unwrap();

    assert_eq!(lookup(&d, b"f").err(), Some(Errno::ENOENT));
    assert!(list(&d).is_empty());
    let whiteout = lookup(&lookup(&upper.root(), b"d").unwrap(), b"f").unwrap();
    assert_eq!(whiteout.file_type(), FileType::CharDevice);
    assert!(lookup(&lookup(&lower.root(), b"d").unwrap(), b"f").is_ok());
    // Creating the name again replaces the whiteout.
    let f = write(&d, b"f", b"new");
    assert_eq!(read(&f), b"new");
    assert_eq!(list(&d), vec![b"f".to_vec()]);
}

#[test]
fn rmdir_needs_emptiness_across_layers() {
    let (overlay, _, _) = setup();
    let root = overlay.root();
    let d = lookup(&root, b"d").unwrap();
    write(&d, b"g", b"upper");

    assert_eq!(block_on(root.rmdir(b"d")), Err(Errno::ENOTEMPTY));
    block_on(d.unlink(b"g")).unwrap();
    assert_eq!(block_on(root.rmdir(b"d")), Err(Errno::ENOTEMPTY));
    block_on(d.unlink(b"f")).unwrap();
    block_on(root.rmdir(b"d")).unwrap();

    assert_eq!(lookup(&root, b"d").err(), Some(Errno::ENOENT));
    assert!(list(&root).is_empty());
}

#[test]
fn directory_recreated_over_whiteout_is_opaque() {
    let (overlay, upper, _) = setup();
    let root = overlay.root();
    block_on(lookup(&root, b"d").unwrap().unlink(b"f")).unwrap();
    block_on(root.rmdir(b"d")).unwrap();

    let d = mkdir(&root, b"d");

    assert!(list(&d).is_empty());
    assert_eq!(lookup(&d, b"f").err(), Some(Errno::ENOENT));
    let upper_d = lookup(&upper.root(), b"d").unwrap();
    assert_eq!(
        block_on(upper_d.getxattr(b"trusted.overlay.opaque")),
        Ok(b"y".to_vec())
    );
    // Overlay xattrs are hidden.
    assert_eq!(
        block_on(d.getxattr(b"trusted.overlay.opaque")),
        Err(Errno::EOPNOTSUPP)
    );
    assert!(block_on(d.listxattr()).unwrap().is_empty());
}

#[test]
fn readdir_merges_layers_with_matching_inos_and_cookies() {
    let top = mem();
    write(&top.root(), b"a", b"");
    write(&top.root(), b"b", b"top");
    mkdir(&top.root(), b"sub");
    let bottom = mem();
    write(&bottom.root(), b"b", b"bottom");
    write(&bottom.root(), b"c", b"");
    write(&mkdir(&bottom.root(), b"sub"), b"x", b"");
    let upper = mem();
    mkdir(&upper.root(), b"sub");
    write(&upper.root(), b"u", b"");
    let overlay = OverlayFs::new(Some(upper), vec![top, bottom]);
    let root = overlay.root();

    let handle = block_on(root.open(OpenOptions::default())).unwrap();
    let mut first = Names(Vec::new(), 2);
    block_on(handle.readdir(0, &mut first)).unwrap();
    let mut rest = Names(Vec::new(), usize::MAX);
    block_on(handle.readdir(first.0[1].2, &mut rest)).unwrap();
    let mut all: Vec<_> = first.0.into_iter().chain(rest.0).collect();
    all.sort();

    let names: Vec<&[u8]> = all.iter().map(|(name, _, _)| name.as_slice()).collect();
    assert_eq!(names, [&b"a"[..], b"b", b"c", b"sub", b"u"]);
    for (name, ino, _) in &all {
        assert_eq!(lookup(&root, name).unwrap().ino(), *ino);
    }
    assert_eq!(read(&lookup(&root, b"b").unwrap()), b"top");
    let sub = lookup(&root, b"sub").unwrap();
    assert_eq!(list(&sub), vec![b"x".to_vec()]);
    assert_eq!(block_on(sub.getattr()).unwrap().nlink, 1);
}

#[test]
fn renaming_lower_directory_is_exdev_and_files_move() {
    let (overlay, _, _) = setup();
    let root = overlay.root();
    assert_eq!(
        block_on(root.rename(b"d", &root, b"e", RenameMode::Replace)),
        Err(Errno::EXDEV)
    );

    let d = lookup(&root, b"d").unwrap();
    block_on(d.rename(b"f", &root, b"g", RenameMode::Replace)).unwrap();

    assert_eq!(read(&lookup(&root, b"g").unwrap()), b"hello");
    assert_eq!(lookup(&d, b"f").err(), Some(Errno::ENOENT));
}

#[test]
fn read_only_overlay_refuses_changes() {
    let (_, _, lower) = setup();
    let overlay = OverlayFs::new(None, vec![lower]);
    let root = overlay.root();
    let f = lookup(&lookup(&root, b"d").unwrap(), b"f").unwrap();

    assert!(overlay.info().read_only);
    assert_eq!(read(&f), b"hello");
    assert_eq!(
        block_on(root.create(b"n", &new(NewKind::Regular))).err(),
        Some(Errno::EROFS)
    );
    assert_eq!(
        block_on(f.setattr(&SetAttr::default())).err(),
        Some(Errno::EROFS)
    );
    let write = OpenOptions {
        write: true,
        ..OpenOptions::default()
    };
    assert_eq!(block_on(f.open(write)).err(), Some(Errno::EROFS));
    assert_eq!(block_on(root.rmdir(b"d")), Err(Errno::ENOTEMPTY));
}

#[test]
fn copy_up_of_an_unlinked_open_file_stays_unnamed() {
    let (overlay, upper, _lower) = setup();
    let d = lookup(&overlay.root(), b"d").unwrap();
    let f = lookup(&d, b"f").unwrap();
    let reader = block_on(f.open(OpenOptions {
        read: true,
        ..OpenOptions::default()
    }))
    .unwrap();
    block_on(d.unlink(b"f")).unwrap();

    // `fchmod` on the still-open file copies it up without giving it its old name back.
    let chmod = SetAttr {
        mode: Some(0o600),
        ..SetAttr::default()
    };
    assert_eq!(block_on(f.setattr(&chmod)).unwrap().mode, 0o600);
    assert_eq!(lookup(&d, b"f").err(), Some(Errno::ENOENT));
    assert!(list(&d).is_empty());
    assert_eq!(list(&lookup(&upper.root(), b"d").unwrap()), [b"f".to_vec()]);
    let mut buf = [0; 5];
    assert_eq!(block_on(reader.read_at(&mut buf, 0)), Ok(5));
    assert_eq!(&buf, b"hello");
}

#[test]
fn opening_for_truncation_copies_up_no_data() {
    let (overlay, upper, _lower) = setup();
    let f = lookup(&lookup(&overlay.root(), b"d").unwrap(), b"f").unwrap();

    let writer = block_on(f.open(OpenOptions {
        write: true,
        truncate: true,
        ..OpenOptions::default()
    }))
    .unwrap();
    block_on(writer.write_at(b"new", 0)).unwrap();

    let upper_f = lookup(&lookup(&upper.root(), b"d").unwrap(), b"f").unwrap();
    assert_eq!(read(&upper_f), b"new");
    // The rest of the copy is metadata: xattrs, mode and times.
    assert_eq!(block_on(upper_f.getxattr(b"user.x")), Ok(b"1".to_vec()));
    assert_eq!(block_on(upper_f.getattr()).unwrap().mode, 0o644);
}

#[test]
fn whiteouts_replacing_upper_entries_leave_no_temporary_names() {
    let (overlay, upper, _lower) = setup();
    let d = lookup(&overlay.root(), b"d").unwrap();
    let f = lookup(&d, b"f").unwrap();
    block_on(f.setattr(&SetAttr {
        mode: Some(0o600),
        ..SetAttr::default()
    }))
    .unwrap();

    block_on(d.unlink(b"f")).unwrap();
    assert_eq!(lookup(&d, b"f").err(), Some(Errno::ENOENT));
    assert!(list(&d).is_empty());
    // The upper directory holds only the whiteout, under the removed name.
    assert_eq!(list(&lookup(&upper.root(), b"d").unwrap()), [b"f".to_vec()]);
}

fn named_acl() -> Vec<u8> {
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 7),
        (4, 0, u32::MAX),
        (16, 4, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&perm.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    acl
}

#[test]
fn copy_up_preserves_file_flags_protection_and_posix_acls() {
    use wasixv2_vfs::{
        XATTR_NAME_POSIX_ACL_ACCESS as ACCESS, XATTR_NAME_POSIX_ACL_DEFAULT as DEFAULT,
    };
    let (overlay, upper, lower) = setup();
    let lower_dir = lookup(&lower.root(), b"d").unwrap();
    let lower_file = lookup(&lower_dir, b"f").unwrap();
    let flags = Fl::FS_NOATIME_FL.0 | Fl::FS_NODUMP_FL.0 | PROT_FLAGS;
    block_on(lower_file.fileattr_set(&FileKattr::from_flags(flags))).unwrap();
    block_on(lower_dir.fileattr_set(&FileKattr::from_flags(Fl::FS_NOATIME_FL.0))).unwrap();
    let acl = named_acl();
    block_on(lower_file.setxattr(ACCESS, &acl, XattrSet::Any)).unwrap();
    block_on(lower_dir.setxattr(DEFAULT, &acl, XattrSet::Any)).unwrap();
    let dir = lookup(&overlay.root(), b"d").unwrap();
    let file = lookup(&dir, b"f").unwrap();
    block_on(file.setattr(&SetAttr {
        mode: Some(0o640),
        ..SetAttr::default()
    }))
    .unwrap();
    let upper_dir = lookup(&upper.root(), b"d").unwrap();
    let upper_file = lookup(&upper_dir, b"f").unwrap();
    assert_eq!(block_on(upper_file.getxattr(ACCESS)), Ok(acl.clone()));
    assert_eq!(block_on(upper_dir.getxattr(DEFAULT)), Ok(acl));
    let physical = block_on(upper_file.fileattr_get()).unwrap().flags;
    assert_eq!(
        physical & (COPY_FLAGS | PROT_FLAGS | Fl::FS_NODUMP_FL.0),
        Fl::FS_NOATIME_FL.0
    );
    assert_eq!(
        block_on(upper_file.getxattr(b"trusted.overlay.protattr")),
        Ok(b"ai".to_vec())
    );
    assert_eq!(file.inode_flags() & PROT_FLAGS, PROT_FLAGS);
    assert_eq!(
        block_on(file.fileattr_get()).unwrap().flags & PROT_FLAGS,
        PROT_FLAGS
    );
    let restored = OverlayFs::new(Some(upper.clone()), vec![]);
    let restored_file = lookup(&lookup(&restored.root(), b"d").unwrap(), b"f").unwrap();
    assert_eq!(
        block_on(restored_file.fileattr_get()).unwrap().flags & PROT_FLAGS,
        PROT_FLAGS
    );
    block_on(restored_file.fileattr_set(&FileKattr::from_flags(Fl::FS_NOATIME_FL.0))).unwrap();
    assert_eq!(restored_file.inode_flags() & PROT_FLAGS, 0);
    assert_eq!(
        block_on(upper_file.getxattr(b"trusted.overlay.protattr")),
        Err(Errno::ENODATA)
    );
    // A preexisting protection xattr on the synchronous root loads before VFS checks flags.
    block_on(
        upper
            .root()
            .setxattr(b"trusted.overlay.protattr", b"i", XattrSet::Any),
    )
    .unwrap();
    let restored = OverlayFs::new(Some(upper), vec![]);
    block_on(restored.root().getattr()).unwrap();
    assert_eq!(
        restored.root().inode_flags() & PROT_FLAGS,
        Fl::FS_IMMUTABLE_FL.0
    );
}

#[test]
fn copy_up_requires_posix_acls_even_when_upper_ignores_unknown_xattrs() {
    struct NoXattr(Arc<dyn Node>);
    #[async_trait(?Send)]
    impl Node for NoXattr {
        fn ino(&self) -> u64 {
            self.0.ino()
        }
        fn file_type(&self) -> FileType {
            self.0.file_type()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        async fn getattr(&self) -> FsResult<Attr> {
            self.0.getattr().await
        }
        async fn setattr(&self, attr: &SetAttr) -> FsResult<Attr> {
            self.0.setattr(attr).await
        }
        async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
            self.0.open(options).await
        }
    }
    let lower = mem();
    let file = write(&lower.root(), b"f", b"data");
    block_on(file.setxattr(b"user.unknown", b"value", XattrSet::Any)).unwrap();
    let upper: Arc<dyn Node> = Arc::new(NoXattr(write(&mem().root(), b"f", b"")));
    assert_eq!(block_on(copy_xattrs(&file, &upper)), Ok(()));
    block_on(file.setxattr(
        wasixv2_vfs::XATTR_NAME_POSIX_ACL_ACCESS,
        &named_acl(),
        XattrSet::Any,
    ))
    .unwrap();
    assert_eq!(block_on(copy_xattrs(&file, &upper)), Err(Errno::EOPNOTSUPP));
}

#[test]
fn persisted_root_protection_applies_to_the_first_metadata_change() {
    use wasixv2_vfs::{Cred, Ctx, Vfs};
    // Each operation starts with a fresh synchronous root, before any getattr or lookup
    // has initialized its persisted overlay.protattr state.
    for value in [b"i".as_slice(), b"a".as_slice()] {
        for operation in 0..5 {
            let upper = mem();
            block_on(
                upper
                    .root()
                    .setxattr(b"trusted.overlay.protattr", value, XattrSet::Any),
            )
            .unwrap();
            let fs = OverlayFs::new(Some(upper), vec![]);
            let vfs = Vfs::new(fs);
            let root = vfs.root();
            let cred = Cred::root();
            let cx = Ctx {
                cred: &cred,
                root: &root,
                umask: 0,
                task: 0,
                leases: None,
            };
            let result = match operation {
                0 => block_on(vfs.chmod(&cx, &root, 0o700)),
                1 => block_on(vfs.chown(&cx, &root, Some(2), Some(2))),
                2 => {
                    block_on(vfs.utimes(&cx, &root, Some(TimeSet::At(Timestamp::default())), None))
                }
                3 => block_on(vfs.setxattr(&cx, &root, b"user.test", b"x", XattrSet::Any)),
                _ => block_on(vfs.setxattr(
                    &cx,
                    &root,
                    wasixv2_vfs::XATTR_NAME_POSIX_ACL_ACCESS,
                    &named_acl(),
                    XattrSet::Any,
                )),
            };
            assert_eq!(
                result,
                Err(Errno::EPERM),
                "protection {value:?}, operation {operation}"
            );
        }
    }
}

#[test]
fn persisted_file_protection_blocks_link_before_any_getattr() {
    use wasixv2_vfs::{Cred, Ctx, LookupFlags, Vfs};
    for value in [b"i".as_slice(), b"a".as_slice()] {
        let upper = mem();
        let file = write(&upper.root(), b"f", b"data");
        block_on(file.setxattr(b"trusted.overlay.protattr", value, XattrSet::Any)).unwrap();
        let vfs = Vfs::new(OverlayFs::new(Some(upper), vec![]));
        let root = vfs.root();
        let cred = Cred::root();
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        assert_eq!(
            block_on(vfs.link(&cx, &root, b"f", LookupFlags::follow(), &root, b"alias"))
                .map_err(wasixv2_vfs::PathError::errno),
            Err(Errno::EPERM)
        );
    }
}

/// A layer whose ordinary lookup can retain objects, but whose entry API explicitly
/// reports selected names as observations. Overlay must not bypass that distinction.
struct InspectLayer {
    backing: Arc<dyn Filesystem>,
    state: Arc<Inspection>,
}
#[derive(Default)]
struct Inspection {
    observed: Mutex<HashSet<Vec<u8>>>,
    fault_names: Mutex<HashSet<Vec<u8>>>,
    fault: Mutex<Option<Errno>>,
    fault_trusted_only: AtomicBool,
    acquisitions: std::sync::atomic::AtomicUsize,
}
struct InspectNode {
    inner: Arc<dyn Node>,
    name: Vec<u8>,
    state: Arc<Inspection>,
}
impl InspectLayer {
    fn new(backing: Arc<dyn Filesystem>, names: &[&[u8]]) -> Arc<Self> {
        let state = Arc::new(Inspection::default());
        state
            .observed
            .lock()
            .unwrap()
            .extend(names.iter().map(|name| name.to_vec()));
        Arc::new(Self { backing, state })
    }
    fn wrap(&self, inner: Arc<dyn Node>, name: &[u8]) -> Arc<dyn Node> {
        Arc::new(InspectNode {
            inner,
            name: name.to_vec(),
            state: self.state.clone(),
        })
    }
}
#[async_trait(?Send)]
impl Filesystem for InspectLayer {
    fn info(&self) -> FsInfo {
        self.backing.info()
    }
    fn root(&self) -> Arc<dyn Node> {
        self.wrap(self.backing.root(), b"/")
    }
    async fn statfs(&self) -> FsResult<StatFs> {
        self.backing.statfs().await
    }
}
impl InspectNode {
    fn wrap(&self, inner: Arc<dyn Node>, name: &[u8]) -> Arc<dyn Node> {
        Arc::new(Self {
            inner,
            name: name.to_vec(),
            state: self.state.clone(),
        })
    }
}
#[async_trait(?Send)]
impl Node for InspectNode {
    fn ino(&self) -> u64 {
        self.inner.ino()
    }
    fn file_type(&self) -> FileType {
        self.inner.file_type()
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
        Ok(self.wrap(self.inner.lookup(name).await?, name))
    }
    async fn lookup_entry(&self, name: &[u8]) -> FsResult<LookupEntry> {
        let node = self.lookup(name).await?;
        let observed = self.state.observed.lock().unwrap().contains(name);
        if observed {
            Ok(LookupEntry::Observation(node.getattr().await?.into()))
        } else {
            Ok(LookupEntry::Pinned(node))
        }
    }
    async fn check_entry_permission(
        &self,
        _: &[u8],
        _: &wasixv2_vfs::Cred,
        _: u32,
        _: &Attr,
        _: u32,
    ) -> FsResult<()> {
        Err(Errno::EPERM)
    }
    async fn open_existing(
        &self,
        name: &[u8],
        options: OpenOptions,
    ) -> FsResult<(Arc<dyn Node>, Box<dyn Handle>)> {
        self.state.acquisitions.fetch_add(1, Ordering::SeqCst);
        let node = self.lookup(name).await?;
        let handle = node.open(options).await?;
        Ok((node, handle))
    }
    async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
        self.inner.open(options).await
    }
    async fn getxattr(&self, name: &[u8]) -> FsResult<Vec<u8>> {
        if (!self.state.fault_trusted_only.load(Ordering::SeqCst) || name.starts_with(b"trusted."))
            && self.state.fault_names.lock().unwrap().contains(&self.name)
            && let Some(error) = *self.state.fault.lock().unwrap()
        {
            return Err(error);
        }
        self.inner.getxattr(name).await
    }
}

#[test]
fn unknown_private_metadata_refuses_selection_existence_listing_and_mutations() {
    use wasixv2_abi::OpenFlags;
    use wasixv2_vfs::{Cred, Ctx, LookupFlags, OpenHow, Vfs};
    let upper = mem();
    let root = upper.root();
    let marker = write(&root, b"marker", b"");
    block_on(marker.setxattr(b"trusted.overlay.whiteout", b"y", XattrSet::Any)).unwrap();
    let plain = write(&root, b"plain", b"");
    let protected = write(&root, b"protected", b"data");
    block_on(protected.setxattr(b"trusted.overlay.protattr", b"i", XattrSet::Any)).unwrap();
    let append = write(&root, b"append", b"append");
    block_on(append.setxattr(b"trusted.overlay.protattr", b"a", XattrSet::Any)).unwrap();
    write(&root, b"source", b"source");
    let layer = InspectLayer::new(
        upper.clone(),
        &[b"marker", b"plain", b"protected", b"append"],
    );
    let lower = mem();
    write(&lower.root(), b"marker", b"must not leak");
    let overlay = OverlayFs::new(Some(layer.clone()), vec![lower]);
    let vfs = Vfs::new(overlay.clone());
    let at = vfs.root();
    let cred = Cred::root();
    let cx = Ctx {
        cred: &cred,
        root: &at,
        umask: 0,
        task: 0,
        leases: None,
    };
    for name in [b"marker".as_slice(), b"plain", b"protected", b"append"] {
        assert_eq!(
            block_on(vfs.lookup_entry(&cx, &at, name, LookupFlags::follow()))
                .map_err(wasixv2_vfs::PathError::errno)
                .err(),
            Some(Errno::EACCES)
        );
        assert_eq!(
            block_on(vfs.unlink(&cx, &at, name)).map_err(wasixv2_vfs::PathError::errno),
            Err(Errno::EACCES)
        );
        let how = OpenHow {
            flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
            mode: 0,
            lookup: LookupFlags::follow(),
        };
        assert_eq!(
            block_on(vfs.open(&cx, &at, name, &how))
                .map_err(wasixv2_vfs::PathError::errno)
                .err(),
            Some(Errno::EACCES)
        );
        let exclusive = OpenHow {
            flags: OpenFlags::O_WRONLY | OpenFlags::O_CREAT | OpenFlags::O_EXCL,
            ..how
        };
        assert_eq!(
            block_on(vfs.open(&cx, &at, name, &exclusive))
                .map_err(wasixv2_vfs::PathError::errno)
                .err(),
            Some(Errno::EACCES)
        );
        assert_eq!(
            block_on(vfs.rename(&cx, &at, b"source", &at, name, RenameMode::Replace))
                .map_err(wasixv2_vfs::PathError::errno),
            Err(Errno::EACCES)
        );
    }
    let handle = block_on(overlay.root().open(OpenOptions::default())).unwrap();
    let mut sink = Names(Vec::new(), usize::MAX);
    assert_eq!(block_on(handle.readdir(0, &mut sink)), Err(Errno::EACCES));
    assert!(sink.0.is_empty());
    assert_eq!(layer.state.acquisitions.load(Ordering::SeqCst), 0);
    assert!(
        overlay
            .as_ref()
            .root()
            .as_any()
            .downcast_ref::<OverlayNode>()
            .unwrap()
            .shared
            .nodes
            .lock()
            .unwrap()
            .is_empty()
    );
    assert_eq!(read(&protected), b"data");
    assert_eq!(read(&append), b"append");
    assert_eq!(block_on(plain.getattr()).unwrap().size, 0);
    assert!(block_on(root.lookup(b"marker")).is_ok());
    assert_eq!(read(&block_on(root.lookup(b"source")).unwrap()), b"source");
}

#[test]
fn observed_upper_directory_never_hides_unproved_lower_contents_or_opacity() {
    for (nonempty, opaque) in [(false, false), (true, false), (true, true)] {
        let upper = mem();
        let upper_dir = mkdir(&upper.root(), b"d");
        if opaque {
            block_on(upper_dir.setxattr(b"trusted.overlay.opaque", b"y", XattrSet::Any)).unwrap();
        }
        let lower = mem();
        let lower_dir = mkdir(&lower.root(), b"d");
        if nonempty {
            write(&lower_dir, b"child", b"lower");
        }
        let layer = InspectLayer::new(upper.clone(), &[b"d"]);
        let overlay = OverlayFs::new(Some(layer), vec![lower]);
        assert_eq!(block_on(overlay.root().rmdir(b"d")), Err(Errno::EACCES));
        assert_eq!(
            block_on(overlay.root().lookup_search(b"d")).err(),
            Some(Errno::EACCES)
        );
        assert!(block_on(upper.root().lookup(b"d")).is_ok());
        if nonempty {
            assert_eq!(
                read(&block_on(lower_dir.lookup(b"child")).unwrap()),
                b"lower"
            );
        }
    }
}

#[test]
fn mixed_observed_directory_rename_refuses_replace_and_exchange_before_copy_up() {
    for mode in [RenameMode::Replace, RenameMode::Exchange] {
        for source_directory in [false, true] {
            let upper = mem();
            if source_directory {
                mkdir(&upper.root(), b"source");
            } else {
                write(&upper.root(), b"source", b"source");
            }
            let lower = mem();
            let target = mkdir(&lower.root(), b"target");
            write(&target, b"child", b"lower");
            let lower_layer = InspectLayer::new(lower.clone(), &[b"target"]);
            let overlay = OverlayFs::new(Some(upper.clone()), vec![lower_layer]);
            let root = overlay.root();
            assert_eq!(
                block_on(root.rename(b"source", &root, b"target", mode)),
                Err(Errno::EACCES)
            );
            assert!(block_on(upper.root().lookup(b"source")).is_ok());
            assert_eq!(
                block_on(upper.root().lookup(b"target")).err(),
                Some(Errno::ENOENT)
            );
            assert_eq!(read(&block_on(target.lookup(b"child")).unwrap()), b"lower");
        }
    }
}

#[test]
fn unknown_acquisition_never_publishes_a_partial_directory_composition() {
    let upper = mem();
    let upper_dir = mkdir(&upper.root(), b"d");
    write(&upper_dir, b"upper", b"upper");
    let lower = mem();
    let lower_dir = mkdir(&lower.root(), b"d");
    write(&lower_dir, b"lower", b"lower");
    let layer = InspectLayer::new(upper, &[b"d"]);
    let overlay = OverlayFs::new(Some(layer.clone()), vec![lower]);
    let root = overlay.root();
    assert_eq!(
        block_on(root.open_existing(
            b"d",
            OpenOptions {
                read: true,
                ..Default::default()
            }
        ))
        .err(),
        Some(Errno::EACCES)
    );
    assert_eq!(layer.state.acquisitions.load(Ordering::SeqCst), 0);
    assert!(
        root.as_any()
            .downcast_ref::<OverlayNode>()
            .unwrap()
            .shared
            .nodes
            .lock()
            .unwrap()
            .is_empty()
    );
    layer.state.observed.lock().unwrap().clear();
    let directory = lookup(&root, b"d").unwrap();
    assert_eq!(list(&directory), vec![b"lower".to_vec(), b"upper".to_vec()]);
    assert_eq!(read(&lookup(&directory, b"lower").unwrap()), b"lower");
}

#[test]
fn unknown_lower_directory_after_a_pinned_upper_is_not_silently_omitted() {
    let upper = mem();
    mkdir(&upper.root(), b"d");
    let lower = mem();
    mkdir(&lower.root(), b"d");
    let layer = InspectLayer::new(lower, &[b"d"]);
    let overlay = OverlayFs::new(Some(upper), vec![layer]);
    assert_eq!(lookup(&overlay.root(), b"d").err(), Some(Errno::EACCES));
}

#[test]
fn private_metadata_errors_propagate_and_protection_loading_can_retry() {
    for error in [Errno::EACCES, Errno::EPERM, Errno::EIO] {
        let upper = mem();
        let file = write(&upper.root(), b"protected", b"data");
        block_on(file.setxattr(b"user.overlay.protattr", b"i", XattrSet::Any)).unwrap();
        let layer = InspectLayer::new(upper, &[]);
        layer.state.fault_trusted_only.store(true, Ordering::SeqCst);
        layer
            .state
            .fault_names
            .lock()
            .unwrap()
            .insert(b"protected".to_vec());
        *layer.state.fault.lock().unwrap() = Some(error);
        let overlay = OverlayFs::new(Some(layer.clone()), vec![]);
        let node = lookup(&overlay.root(), b"protected").unwrap();
        assert_eq!(block_on(node.getattr()).err(), Some(error));
        let inode = node.as_any().downcast_ref::<OverlayNode>().unwrap();
        assert!(!inode.protattr_loaded.load(Ordering::Acquire));
        assert_eq!(inode.protattr.load(Ordering::Acquire), 0);
        *layer.state.fault.lock().unwrap() = None;
        assert!(block_on(node.getattr()).is_ok());
        assert_ne!(node.inode_flags() & PROT_FLAGS, 0);
    }
}

#[test]
fn private_marker_and_opacity_errors_never_become_absence_or_lower_fallback() {
    for error in [Errno::EACCES, Errno::EPERM, Errno::EIO] {
        for directory in [false, true] {
            let upper = mem();
            if directory {
                mkdir(&upper.root(), b"d");
            } else {
                write(&upper.root(), b"d", b"");
            }
            let lower = mem();
            write(&lower.root(), b"d", b"hidden");
            let layer = InspectLayer::new(upper.clone(), &[]);
            layer
                .state
                .fault_names
                .lock()
                .unwrap()
                .insert(b"d".to_vec());
            *layer.state.fault.lock().unwrap() = Some(error);
            let overlay = OverlayFs::new(Some(layer), vec![lower]);
            assert_eq!(lookup(&overlay.root(), b"d").err(), Some(error));
            assert_eq!(block_on(overlay.root().unlink(b"d")), Err(error));
            assert!(block_on(upper.root().lookup(b"d")).is_ok());
        }
    }
}

#[test]
fn definitive_absence_and_no_xattr_facility_remain_distinct_supported_results() {
    for error in [Errno::ENODATA, Errno::EOPNOTSUPP] {
        let upper = mem();
        let directory = mkdir(&upper.root(), b"d");
        write(&directory, b"file", b"data");
        let layer = InspectLayer::new(upper, &[]);
        layer
            .state
            .fault_names
            .lock()
            .unwrap()
            .insert(b"d".to_vec());
        *layer.state.fault.lock().unwrap() = Some(error);
        let node = block_on(layer.root().lookup(b"d")).unwrap();
        let value = block_on(get_overlay_xattr(&node, OPAQUE)).unwrap();
        assert!(match error {
            Errno::ENODATA => matches!(value, PrivateXattr::Absent),
            _ => matches!(value, PrivateXattr::Unsupported),
        });
        let overlay = OverlayFs::new(Some(layer), vec![]);
        assert_eq!(
            read(&lookup(&lookup(&overlay.root(), b"d").unwrap(), b"file").unwrap()),
            b"data"
        );
    }
}

#[test]
fn unknown_lower_presence_and_whiteout_cleanup_fail_before_namespace_mutation() {
    let upper = mem();
    write(&upper.root(), b"f", b"upper");
    let lower = mem();
    write(&lower.root(), b"f", b"lower");
    let observed_lower = InspectLayer::new(lower.clone(), &[b"f"]);
    let overlay = OverlayFs::new(Some(upper.clone()), vec![observed_lower]);
    assert_eq!(block_on(overlay.root().unlink(b"f")), Err(Errno::EACCES));
    assert_eq!(read(&lookup(&upper.root(), b"f").unwrap()), b"upper");
    assert_eq!(read(&lookup(&lower.root(), b"f").unwrap()), b"lower");

    let upper = mem();
    let marker = write(&upper.root(), b"marker", b"");
    block_on(marker.setxattr(b"trusted.overlay.whiteout", b"y", XattrSet::Any)).unwrap();
    let observed_upper = InspectLayer::new(upper.clone(), &[b"marker"]);
    let overlay = OverlayFs::new(Some(observed_upper), vec![]);
    let root = overlay.root();
    let node = root.as_any().downcast_ref::<OverlayNode>().unwrap();
    let native = node.upper_node().unwrap();
    assert_eq!(
        block_on(node.clear_whiteout(&native, b"marker")),
        Err(Errno::EACCES)
    );
    assert_eq!(block_on(node.clear_upper_whiteouts()), Err(Errno::EACCES));
    assert!(lookup(&upper.root(), b"marker").is_ok());
}

#[test]
fn rename_preflights_unknown_lower_before_copy_up_or_destination_whiteout_removal() {
    for whiteout_target in [false, true] {
        let upper = mem();
        let lower = mem();
        if whiteout_target {
            write(&upper.root(), b"source", b"source");
            let marker = write(&upper.root(), b"target", b"");
            block_on(marker.setxattr(b"trusted.overlay.whiteout", b"y", XattrSet::Any)).unwrap();
        } else {
            write(&lower.root(), b"source", b"source");
            write(&upper.root(), b"target", b"target");
        }
        write(&lower.root(), b"target", b"hidden lower");
        let before = list(&upper.root());
        let layer = InspectLayer::new(lower.clone(), &[b"target"]);
        let overlay = OverlayFs::new(Some(upper.clone()), vec![layer]);
        let root = overlay.root();
        assert_eq!(
            block_on(root.rename(b"source", &root, b"target", RenameMode::Replace)),
            Err(Errno::EACCES)
        );
        assert_eq!(list(&upper.root()), before);
        let target = lookup(&upper.root(), b"target").unwrap();
        if whiteout_target {
            assert_eq!(read(&target), b"");
            assert_eq!(
                block_on(target.getxattr(b"trusted.overlay.whiteout")),
                Ok(b"y".to_vec())
            );
            assert_eq!(read(&lookup(&upper.root(), b"source").unwrap()), b"source");
        } else {
            assert_eq!(read(&target), b"target");
            assert_eq!(read(&lookup(&lower.root(), b"source").unwrap()), b"source");
        }
        assert_eq!(
            read(&lookup(&lower.root(), b"target").unwrap()),
            b"hidden lower"
        );
    }
}

#[test]
fn ordinary_listing_entries_need_no_unrelated_inode_grant() {
    let upper = mem();
    let directory = mkdir(&upper.root(), b"d");
    write(&directory, b"file", b"data");
    let layer = InspectLayer::new(upper, &[b"file"]);
    let overlay = OverlayFs::new(Some(layer), vec![]);
    let directory = lookup(&overlay.root(), b"d").unwrap();
    assert_eq!(list(&directory), vec![b"file".to_vec()]);
    assert_eq!(lookup(&directory, b"file").err(), Some(Errno::EACCES));
}

#[test]
fn private_metadata_prefix_precedence_preserves_definitive_negative_fallback() {
    for negative in [Errno::ENODATA, Errno::EOPNOTSUPP] {
        let upper = mem();
        let directory = mkdir(&upper.root(), b"d");
        block_on(directory.setxattr(b"user.overlay.opaque", b"y", XattrSet::Any)).unwrap();
        let layer = InspectLayer::new(upper, &[]);
        layer
            .state
            .fault_names
            .lock()
            .unwrap()
            .insert(b"d".to_vec());
        layer.state.fault_trusted_only.store(true, Ordering::SeqCst);
        *layer.state.fault.lock().unwrap() = Some(negative);
        let node = block_on(layer.root().lookup(b"d")).unwrap();
        assert_eq!(block_on(dir_flags(&node)), Ok((true, false)));
    }
    let upper = mem();
    let directory = mkdir(&upper.root(), b"d");
    block_on(directory.setxattr(b"trusted.overlay.opaque", b"y", XattrSet::Any)).unwrap();
    block_on(directory.setxattr(b"user.overlay.opaque", b"x", XattrSet::Any)).unwrap();
    assert_eq!(block_on(dir_flags(&directory)), Ok((true, false)));
}

#[test]
fn root_upper_changes_survive_overlay_reconstruction() {
    let lower = mem();
    let lower_root = lower.root();
    write(&lower_root, b"copy", b"lower");
    write(&lower_root, b"gone", b"lower");
    mkdir(&lower_root, b"empty");
    let upper = mem();
    {
        let overlay = OverlayFs::new(Some(upper.clone()), vec![lower.clone()]);
        let root = overlay.root();
        write(&root, b"new", b"created");
        let copy = lookup(&root, b"copy").unwrap();
        let handle = block_on(copy.open(OpenOptions {
            write: true,
            ..OpenOptions::default()
        }))
        .unwrap();
        block_on(handle.write_at(b"UPPER", 0)).unwrap();
        block_on(root.unlink(b"gone")).unwrap();
        block_on(root.rmdir(b"empty")).unwrap();
        mkdir(&root, b"empty");
    }
    // A new lower revision cannot override copy-ups or reveal entries under an opaque dir.
    write(&lookup(&lower_root, b"empty").unwrap(), b"later", b"hidden");
    let overlay = OverlayFs::new(Some(upper), vec![lower]);
    let root = overlay.root();
    assert_eq!(read(&lookup(&root, b"new").unwrap()), b"created");
    assert_eq!(read(&lookup(&root, b"copy").unwrap()), b"UPPER");
    assert_eq!(lookup(&root, b"gone").err(), Some(Errno::ENOENT));
    assert!(list(&lookup(&root, b"empty").unwrap()).is_empty());
    assert_eq!(read(&lookup(&lower_root, b"copy").unwrap()), b"lower");
    assert!(lookup(&lower_root, b"gone").is_ok());
}

#[test]
fn live_append_refreshes_cached_directories_without_changing_inodes_or_cookies() {
    let upper = mem();
    let upper_dir = mkdir(&upper.root(), b"d");
    write(&upper_dir, b"old", b"upper");
    let (fs, append) = OverlayFs::new_appendable(Some(upper.clone()), Vec::new());
    let root = fs.root();
    let dir = lookup(&root, b"d").unwrap();
    let handle = block_on(dir.open(OpenOptions::default())).unwrap();
    let mut first = Names(Vec::new(), 1);
    block_on(handle.readdir(0, &mut first)).unwrap();
    assert_eq!(first.0[0].0, b"old");
    let ino = dir.ino();

    let lower = mem();
    let lower_dir = mkdir(&lower.root(), b"d");
    write(&lower_dir, b"old", b"shadowed");
    write(&lower_dir, b"new", b"tail");
    block_on(append.append_lower(lower)).unwrap();

    let mut remaining = Names(Vec::new(), usize::MAX);
    block_on(handle.readdir(first.0[0].2, &mut remaining)).unwrap();
    assert!(remaining.0.is_empty(), "the open stream keeps its snapshot");
    block_on(handle.readdir(0, &mut remaining)).unwrap();
    assert_eq!(remaining.0.len(), 2, "rewind refreshes the stream");
    assert_eq!(read(&lookup(&dir, b"new").unwrap()), b"tail");
    assert_eq!(read(&lookup(&dir, b"old").unwrap()), b"upper");
    assert_eq!(lookup(&upper_dir, b"new").err(), Some(Errno::ENOENT));
    assert_eq!(block_on(dir.getattr()).unwrap().ino, ino);
    drop(handle);
    drop(dir);
    assert_eq!(lookup(&root, b"d").unwrap().ino(), ino);
    let root_handle = block_on(root.open(OpenOptions::default())).unwrap();
    let mut parents = Names(Vec::new(), usize::MAX);
    block_on(root_handle.readdir(0, &mut parents)).unwrap();
    assert_eq!(
        (parents.0[0].0.as_slice(), parents.0[0].1),
        (b"d".as_slice(), ino)
    );
}

#[test]
fn live_append_honors_whiteouts_and_opaque_and_nondirectory_barriers() {
    let upper = mem();
    let lower = mem();
    let barrier = mem();
    let merge = mkdir(&lower.root(), b"merged");
    mkdir(&lower.root(), b"opaque");
    mkdir(&lower.root(), b"stopped");
    write(&merge, b"whiteout", b"base");
    write(&barrier.root(), b"stopped", b"non-directory barrier");

    let (fs, append) = OverlayFs::new_appendable(Some(upper), vec![lower, barrier]);
    let root = fs.root();
    let merge = lookup(&root, b"merged").unwrap();
    let stopped = lookup(&root, b"stopped").unwrap();
    block_on(merge.unlink(b"whiteout")).unwrap();
    write(&merge, b"upper-only", b"previous upper");
    block_on(merge.unlink(b"upper-only")).unwrap();
    block_on(root.rmdir(b"opaque")).unwrap();
    let opaque = mkdir(&root, b"opaque");

    let lower = mem();
    let tail = mkdir(&lower.root(), b"merged");
    write(&tail, b"upper-only", b"new package");
    write(&tail, b"whiteout", b"still hidden");
    for name in [b"opaque".as_slice(), b"stopped"] {
        write(&mkdir(&lower.root(), name), b"hidden", b"barrier");
    }
    block_on(append.append_lower(lower)).unwrap();

    assert_eq!(lookup(&merge, b"whiteout").err(), Some(Errno::ENOENT));
    assert_eq!(
        read(&lookup(&merge, b"upper-only").unwrap()),
        b"new package"
    );
    for dir in [opaque, stopped] {
        assert_eq!(lookup(&dir, b"hidden").err(), Some(Errno::ENOENT));
        assert!(list(&dir).is_empty());
    }
}

#[test]
fn live_append_serializes_with_rename_and_rmdir() {
    use std::task::Context;

    for rename in [false, true] {
        for append_first in [false, true] {
            let upper = mem();
            mkdir(&upper.root(), b"old");
            let (fs, append) = OverlayFs::new_appendable(Some(upper), Vec::new());
            let root = fs.root();
            let old = lookup(&root, b"old").unwrap();
            let lower = mem();
            write(&mkdir(&lower.root(), b"old"), b"new", b"tail");
            if rename {
                write(&mkdir(&lower.root(), b"moved"), b"new", b"target");
            }

            let outcome = block_on(async {
                let node = root.as_any().downcast_ref::<OverlayNode>().unwrap();
                let guard = node.shared.write_lock.lock().await;
                let mut mutating = Box::pin(async {
                    if rename {
                        root.rename(b"old", &root, b"moved", RenameMode::Replace)
                            .await
                    } else {
                        root.rmdir(b"old").await
                    }
                });
                let mut appending = Box::pin(append.append_lower(lower));
                let mut cx = Context::from_waker(std::task::Waker::noop());
                assert!(appending.as_mut().poll(&mut cx).is_pending());
                assert!(mutating.as_mut().poll(&mut cx).is_pending());
                drop(guard);
                if append_first {
                    appending.await.unwrap();
                    mutating.await
                } else {
                    let outcome = mutating.await;
                    appending.await.unwrap();
                    outcome
                }
            });
            if append_first {
                assert_eq!(
                    outcome,
                    Err(if rename {
                        Errno::EXDEV
                    } else {
                        Errno::ENOTEMPTY
                    })
                );
                assert_eq!(read(&lookup(&old, b"new").unwrap()), b"tail");
            } else {
                outcome.unwrap();
                let supplied = lookup(&root, b"old").unwrap();
                assert_ne!(old.ino(), supplied.ino());
                assert_eq!(read(&lookup(&supplied, b"new").unwrap()), b"tail");
                if rename {
                    assert_eq!(lookup(&root, b"moved").unwrap().ino(), old.ino());
                    assert_eq!(read(&lookup(&old, b"new").unwrap()), b"target");
                } else {
                    assert_eq!(lookup(&old, b"new").err(), Some(Errno::ENOENT));
                    assert!(list(&old).is_empty());
                }
            }
        }
    }
}

#[test]
fn live_append_respects_prefixes_and_layer_capacity() {
    let (fs, append) = OverlayFs::new_appendable(Some(mem()), Vec::new());
    let lower = mem();
    write(&lower.root(), b"file", b"hello");
    let prefixed = PrefixFs::new(b"some/place", lower).unwrap();
    block_on(append.append_lower(prefixed)).unwrap();
    let some = lookup(&fs.root(), b"some").unwrap();
    let place = lookup(&some, b"place").unwrap();
    let file = lookup(&place, b"file").unwrap();
    assert_eq!(read(&file), b"hello");
    assert_ne!(place.ino(), some.ino());
    assert_ne!(file.ino(), place.ino());

    for _ in 1..MAX_LOWERS {
        block_on(append.append_lower(mem())).unwrap();
    }
    assert_eq!(append.lower_count(), MAX_LOWERS);
    assert_eq!(block_on(append.append_lower(mem())), Err(Errno::ENOSPC));
    drop(file);
    drop(place);
    drop(some);
    drop(fs);
    assert_eq!(block_on(append.append_lower(mem())), Err(Errno::ESTALE));
}
