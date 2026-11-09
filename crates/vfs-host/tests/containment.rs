//! A host directory mounted into a memory root: data passes through, and nothing outside the
//! mapped directory is reachable, whatever symlinks or `..` the guest uses.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, os::unix::fs::symlink, sync::Arc, time::Duration};

use futures::executor::block_on;
use wasixv2_abi::OpenFlags;
use wasixv2_host::{Executor, Host, LocalFuture};
use wasixv2_vfs::{Clock, Cred, Ctx, Errno, LookupFlags, MountFlags, OpenHow, Timestamp, Vfs};
use wasixv2_vfs_mem::MemFs;

struct InlineHost;

impl Host for InlineHost {
    fn realtime(&self) -> Duration {
        Duration::ZERO
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn sleep(&self, _: Duration) -> LocalFuture<'_, ()> {
        Box::pin(async {})
    }
    fn random(&self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn executor(&self) -> &dyn Executor {
        self
    }
}

impl Executor for InlineHost {
    fn spawn_local(&self, _: LocalFuture<'static, ()>) {
        unimplemented!()
    }
    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send>) -> LocalFuture<'static, ()> {
        Box::pin(async move { work() })
    }
}

struct Epoch;

impl Clock for Epoch {
    fn now(&self) -> Timestamp {
        Timestamp::default()
    }
}

struct Setup {
    vfs: Arc<Vfs>,
    _dir: tempfile::TempDir,
    outside: std::path::PathBuf,
}

/// `<tmp>/inside` mounted at `/mnt`, next to `<tmp>/outside/secret`.
fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let inside = dir.path().join("inside");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), b"secret").unwrap();
    fs::write(inside.join("data"), b"inside").unwrap();
    symlink("../outside/secret", inside.join("up")).unwrap();
    symlink(outside.join("secret"), inside.join("abs")).unwrap();
    symlink("/", inside.join("root")).unwrap();

    let vfs = Vfs::new(Arc::new(MemFs::new(Arc::new(Epoch), 0o755, 1, 1)));
    let host = wasixv2_vfs_host::open(&inside, Arc::new(InlineHost), Default::default()).unwrap();
    block_on(vfs.mount(b"/mnt", host, MountFlags::default(), true)).unwrap();
    Setup {
        vfs,
        _dir: dir,
        outside,
    }
}

fn read(setup: &Setup, path: &[u8]) -> Result<Vec<u8>, Errno> {
    let cred = Cred::user(1, 1);
    let root = setup.vfs.root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0o022,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags: OpenFlags::O_RDONLY,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    let file =
        block_on(setup.vfs.open(&cx, &root, path, &how)).map_err(wasixv2_vfs::PathError::errno)?;
    let mut buf = vec![0; 64];
    let n = block_on(file.read_at(&mut buf, 0))?;
    buf.truncate(n);
    Ok(buf)
}

#[test]
fn files_pass_through() {
    let setup = setup();
    assert_eq!(read(&setup, b"/mnt/data"), Ok(b"inside".to_vec()));
}

#[test]
fn dotdot_and_symlinks_stay_in_the_guest_tree() {
    let setup = setup();

    // `..` from the mount root is the guest's `/`, which has no `outside`.
    assert_eq!(read(&setup, b"/mnt/../outside/secret"), Err(Errno::ENOENT));
    assert_eq!(read(&setup, b"/mnt/up"), Err(Errno::ENOENT));
    // Absolute targets resolve against the guest root, not the host's.
    let host_path = setup.outside.join("secret");
    assert!(read(&setup, host_path.as_os_str().as_encoded_bytes()).is_err());
    assert_eq!(read(&setup, b"/mnt/abs"), Err(Errno::ENOENT));
    assert_eq!(read(&setup, b"/mnt/root/mnt/data"), Ok(b"inside".to_vec()));
}

#[test]
fn guest_changes_reach_the_host() {
    let setup = setup();
    let cred = Cred::user(1, 1);
    let root = setup.vfs.root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0o022,
        task: 0,
        leases: None,
    };

    block_on(setup.vfs.mkdir(&cx, &root, b"/mnt/new", 0o750)).unwrap();
    block_on(setup.vfs.rename(
        &cx,
        &root,
        b"/mnt/data",
        &root,
        b"/mnt/new/moved",
        wasixv2_vfs::RenameMode::Replace,
    ))
    .unwrap();

    let inside = setup.outside.parent().unwrap().join("inside");
    assert_eq!(fs::read(inside.join("new/moved")).unwrap(), b"inside");
    let attr = block_on(
        setup
            .vfs
            .lookup(&cx, &root, b"/mnt/new", LookupFlags::follow()),
    )
    .map(|path| block_on(setup.vfs.stat(&path)).unwrap())
    .unwrap();
    assert_eq!((attr.mode, attr.uid), (0o750, 1));
}

fn lookup(setup: &Setup, path: &[u8]) -> Result<wasixv2_vfs::Path, Errno> {
    let cred = Cred::user(1, 1);
    let root = setup.vfs.root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0o022,
        task: 0,
        leases: None,
    };
    block_on(setup.vfs.lookup(&cx, &root, path, LookupFlags::default()))
        .map_err(wasixv2_vfs::PathError::errno)
}

#[test]
fn directories_renamed_on_the_host_keep_their_one_dentry() {
    let setup = setup();
    let inside = setup.outside.parent().unwrap().join("inside");
    fs::create_dir(inside.join("old")).unwrap();
    let cwd = lookup(&setup, b"/mnt/old").unwrap();

    fs::rename(inside.join("old"), inside.join("new")).unwrap();
    let found = lookup(&setup, b"/mnt/new").unwrap();

    assert!(Arc::ptr_eq(&cwd.dentry, &found.dentry));
    assert_eq!(setup.vfs.d_path(&cwd, &setup.vfs.root()), b"/mnt/new");

    fs::remove_dir(inside.join("new")).unwrap();
    assert_eq!(lookup(&setup, b"/mnt/new").err(), Some(Errno::ENOENT));
    assert_eq!(
        setup.vfs.d_path(&cwd, &setup.vfs.root()),
        b"/mnt/new (deleted)"
    );
}

#[test]
fn host_device_numbers_stay_on_the_host() {
    use std::os::unix::fs::MetadataExt;

    let setup = setup();
    let stat = |path: &[u8]| block_on(setup.vfs.stat(&lookup(&setup, path).unwrap())).unwrap();
    let (root, mnt, data) = (stat(b"/"), stat(b"/mnt"), stat(b"/mnt/data"));
    let inside = setup.outside.parent().unwrap().join("inside");
    let host = fs::metadata(inside.join("data")).unwrap();

    assert_eq!(data.ino, host.ino());
    assert_eq!(mnt.dev, data.dev);
    assert_ne!(root.dev, mnt.dev);
    assert_eq!(mnt.dev.unwrap().major, 0);
}

fn open(
    setup: &Setup,
    path: &[u8],
    flags: OpenFlags,
    mode: u32,
) -> Result<wasixv2_vfs::File, Errno> {
    let cred = Cred::user(1, 1);
    let root = setup.vfs.root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0o022,
        task: 0,
        leases: None,
    };
    let how = OpenHow {
        flags,
        mode,
        lookup: LookupFlags::follow(),
    };
    block_on(setup.vfs.open(&cx, &root, path, &how)).map_err(wasixv2_vfs::PathError::errno)
}

/// What `open(O_CREAT)` grants is the access asked for, whatever the new file's mode (git's
/// read-only objects, `tar x` and `install -m 0444`); the host must not check the mode again.
#[test]
fn a_file_created_read_only_is_writable_through_its_creating_open() {
    use std::os::unix::fs::PermissionsExt;

    let setup = setup();
    let flags = OpenFlags::O_CREAT | OpenFlags::O_EXCL | OpenFlags::O_RDWR;
    let file = open(&setup, b"/mnt/obj", flags, 0o444).unwrap();
    assert_eq!(block_on(file.write_at(b"object", 0)), Ok(6));
    assert_eq!(block_on(file.append(b"!")), Ok((7, 1)));
    // ftruncate needs the open file's write access, not the mode bits.
    assert_eq!(block_on(file.set_size(3)), Ok(()));
    drop(file);

    let host = setup.outside.parent().unwrap().join("inside/obj");
    assert_eq!(fs::read(&host).unwrap(), b"obj");
    assert_eq!(
        fs::metadata(&host).unwrap().permissions().mode() & 0o777,
        0o444
    );
    // Reopening is checked against the mode, by the VFS and the host alike.
    assert_eq!(
        open(&setup, b"/mnt/obj", OpenFlags::O_WRONLY, 0).err(),
        Some(Errno::EACCES)
    );
}

#[test]
fn a_writable_open_survives_chmod_to_read_only() {
    let setup = setup();
    let file = open(&setup, b"/mnt/data", OpenFlags::O_RDWR, 0).unwrap();
    let cred = Cred::user(1, 1);
    let root = setup.vfs.root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0o022,
        task: 0,
        leases: None,
    };
    block_on(setup.vfs.chmod(&cx, &file.path, 0o444)).unwrap();

    assert_eq!(block_on(file.set_size(0)), Ok(()));
    assert_eq!(block_on(file.append(b"new")), Ok((3, 3)));
    assert_eq!(read(&setup, b"/mnt/data"), Ok(b"new".to_vec()));
}

#[cfg(target_os = "linux")]
#[test]
fn an_unnamed_read_only_file_is_writable_and_linkable() {
    let setup = setup();
    let flags = OpenFlags::__O_TMPFILE | OpenFlags::O_RDWR;
    let file = open(&setup, b"/mnt", flags, 0o400).unwrap();
    assert_eq!(block_on(file.write_at(b"tmp", 0)), Ok(3));

    let cred = Cred::user(1, 1);
    let root = setup.vfs.root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0o022,
        task: 0,
        leases: None,
    };
    let empty = LookupFlags {
        empty: true,
        ..LookupFlags::default()
    };
    block_on(
        setup
            .vfs
            .link(&cx, &file.path, b"", empty, &root, b"/mnt/named"),
    )
    .unwrap();
    let host = setup.outside.parent().unwrap().join("inside/named");
    assert_eq!(fs::read(host).unwrap(), b"tmp");
}

/// A host whose wall clock reads a fixed time, as a machine's set clock would.
struct Wall(Duration);

impl Host for Wall {
    fn realtime(&self) -> Duration {
        self.0
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn sleep(&self, _: Duration) -> LocalFuture<'_, ()> {
        Box::pin(async {})
    }
    fn random(&self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn executor(&self) -> &dyn Executor {
        &InlineHost
    }
}

/// `utimensat(UTIME_NOW)` stamps the machine's time, which need not be the host's.
#[test]
fn now_is_the_machines_wall_clock() {
    let dir = tempfile::tempdir().unwrap();
    let wall = Duration::new(1_000_000_000, 5);
    let fs = wasixv2_vfs_host::open(dir.path(), Arc::new(Wall(wall)), Default::default());
    let root = fs.unwrap().root();
    let now = wasixv2_vfs::SetAttr {
        mtime: Some(wasixv2_vfs::TimeSet::Now),
        ..Default::default()
    };
    let attr = block_on(root.setattr(&now)).unwrap();
    assert_eq!(attr.mtime, Timestamp::new(1_000_000_000, 5));
    let modified = fs::metadata(dir.path()).unwrap().modified().unwrap();
    assert_eq!(
        modified.duration_since(std::time::UNIX_EPOCH).unwrap(),
        wall
    );
}

/// Linux fs/utimes.c:do_utimes_path/vfs_utimes updates the symlink itself.
#[test]
fn symlink_times_update_the_pinned_inode_without_following_its_target() {
    use std::os::unix::fs::MetadataExt;
    use wasixv2_vfs::{SetAttr, TimeSet};

    let s = setup();
    let inside = s._dir.path().join("inside");
    symlink("data", inside.join("link")).unwrap();
    symlink("missing", inside.join("dangling")).unwrap();
    let wall = Duration::new(1_300_000_000, 31);
    let host = wasixv2_vfs_host::open(&inside, Arc::new(Wall(wall)), Default::default()).unwrap();
    let root = host.root();
    let target = fs::metadata(inside.join("data")).unwrap();
    let outside = fs::metadata(s.outside.join("secret")).unwrap();
    let atime = Timestamp::new(1_100_000_000, 17);
    let mtime = Timestamp::new(1_200_000_000, 29);

    for name in [b"link".as_slice(), b"dangling", b"abs"] {
        let node = block_on(root.lookup(name)).unwrap();
        let attr = block_on(node.setattr(&SetAttr {
            atime: Some(TimeSet::At(atime)),
            mtime: Some(TimeSet::At(mtime)),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!((attr.atime, attr.mtime), (atime, mtime));
        let attr = block_on(node.setattr(&SetAttr {
            mtime: Some(TimeSet::Now),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(attr.atime, atime);
        assert_eq!(attr.mtime, Timestamp::new(wall.as_secs() as i64, 31));
        let meta = fs::symlink_metadata(inside.join(std::str::from_utf8(name).unwrap())).unwrap();
        assert_eq!((meta.atime(), meta.atime_nsec()), (atime.sec, 17));
        assert_eq!(
            (meta.mtime(), meta.mtime_nsec()),
            (wall.as_secs() as i64, 31)
        );
    }

    let node = block_on(root.lookup(b"link")).unwrap();
    fs::rename(inside.join("link"), inside.join("moved")).unwrap();
    symlink("data", inside.join("link")).unwrap();
    let replacement = fs::symlink_metadata(inside.join("link")).unwrap();
    block_on(node.setattr(&SetAttr {
        mtime: Some(TimeSet::At(mtime)),
        ..Default::default()
    }))
    .unwrap();
    let moved = fs::symlink_metadata(inside.join("moved")).unwrap();
    assert_eq!((moved.mtime(), moved.mtime_nsec()), (mtime.sec, 29));
    let current = fs::symlink_metadata(inside.join("link")).unwrap();
    assert_eq!(current.modified().unwrap(), replacement.modified().unwrap());
    fs::remove_file(inside.join("moved")).unwrap();
    let attr = block_on(node.setattr(&SetAttr {
        mtime: Some(TimeSet::Now),
        ..Default::default()
    }))
    .unwrap();
    assert_eq!(attr.mtime, Timestamp::new(wall.as_secs() as i64, 31));
    let current = fs::metadata(inside.join("data")).unwrap();
    assert_eq!(current.modified().unwrap(), target.modified().unwrap());
    assert_eq!(current.accessed().unwrap(), target.accessed().unwrap());
    let current = fs::metadata(s.outside.join("secret")).unwrap();
    assert_eq!(current.modified().unwrap(), outside.modified().unwrap());
    assert_eq!(current.accessed().unwrap(), outside.accessed().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn host_file_handles_use_native_exports_without_pinning_exported_files() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use wasixv2_vfs::HandleKind;
    let s = setup();
    let real = s._dir.path().join("inside/data");
    let name = std::ffi::CString::new(real.as_os_str().as_encoded_bytes()).unwrap();
    // Probe host support independently so a missing driver implementation cannot make
    // this regression test skip itself. Some hosts mount filesystems without export ops.
    // SAFETY: NUL-terminated path and an aligned file_handle header plus 128 data bytes.
    let raw = unsafe { libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    assert!(raw >= 0);
    // SAFETY: open returned an owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut native = [0u64; 17];
    native[0] = 128;
    let mut mount = 0i32;
    // SAFETY: initialized buffers have the full UAPI sizes.
    let result = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            fd.as_raw_fd(),
            c"".as_ptr(),
            native.as_mut_ptr(),
            &mut mount,
            libc::AT_EMPTY_PATH,
        )
    };
    if result < 0 {
        let err = std::io::Error::last_os_error().raw_os_error().unwrap();
        assert!(
            [libc::EOPNOTSUPP, libc::ENOSYS].contains(&err),
            "native export failed: {err}"
        );
        return;
    }
    // A real file descriptor is also a valid mount anchor; Linux fdget rejects
    // O_PATH anchors even though name_to_handle_at accepts them for encoding.
    let anchor = fs::File::open(&real).unwrap();
    // SAFETY: native contains the successful export above and anchor stays open.
    let native_fd = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            anchor.as_raw_fd(),
            native.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    let native_allowed = if native_fd >= 0 {
        // SAFETY: open_by_handle_at returned an owned descriptor.
        drop(unsafe { OwnedFd::from_raw_fd(native_fd as _) });
        true
    } else {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM),
            "native decode requires a valid anchor and CAP_DAC_READ_SEARCH"
        );
        false
    };
    let root = s.vfs.root();
    let cred = Cred::root();
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    let path = block_on(
        s.vfs
            .lookup(&cx, &root, b"/mnt/data", LookupFlags::follow()),
    )
    .unwrap();
    let handle = s.vfs.encode_fh(&path, HandleKind::Decodable).unwrap();
    assert!(handle.data.len() <= wasixv2_vfs::MAX_HANDLE_SZ);
    let fs = &path.dentry.sb().fs;
    match block_on(fs.fh_to_node(&handle)) {
        Ok(decoded) => {
            assert!(native_allowed);
            assert_eq!(decoded.ino(), path.dentry.node().ino());
        }
        Err(Errno::EPERM) if !native_allowed => {} // Host lacks CAP_DAC_READ_SEARCH.
        Err(err) => panic!("native decode failed: {err:?}"),
    }
    // Only mount roots are retained by the export machinery, not this ordinary inode.
    let weak = Arc::downgrade(path.dentry.node());
    drop(path);
    assert!(weak.upgrade().is_none());
}

#[test]
fn pinned_symlink_reads_keep_identity_and_report_host_unlink_behavior() {
    let s = setup();
    let inside = s._dir.path().join("inside");
    let host = wasixv2_vfs_host::open(&inside, Arc::new(InlineHost), Default::default()).unwrap();
    let root = host.root();
    let link = block_on(root.lookup(b"up")).unwrap();
    fs::rename(inside.join("up"), inside.join("moved")).unwrap();
    symlink("data", inside.join("up")).unwrap();
    assert_eq!(block_on(link.readlink()).unwrap(), b"../outside/secret");
    fs::remove_file(inside.join("moved")).unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(block_on(link.readlink()).unwrap(), b"../outside/secret");
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CStr, mem::MaybeUninit, os::fd::AsRawFd};

        let directory = fs::File::open(&inside).unwrap();
        let mut filesystem = MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), filesystem.as_mut_ptr()) },
            0
        );
        let filesystem = unsafe { filesystem.assume_init() };
        let kind = unsafe { CStr::from_ptr(filesystem.f_fstypename.as_ptr()) };
        let body = block_on(link.readlink());
        if kind == c"apfs" {
            // APFS discards the removed link's body even while its descriptor is held.
            assert_eq!(body, Err(Errno::EINVAL));
        } else if let Ok(body) = body {
            // Other host filesystems may retain it, but must never read the replacement.
            assert_eq!(body, b"../outside/secret");
        } else {
            // V1 host readlink did not promise removed-link body recovery.
            eprintln!("removed symlink body unavailable on {kind:?}: {body:?}");
        }
    }
    assert_eq!(
        block_on(block_on(root.lookup(b"up")).unwrap().readlink()).unwrap(),
        b"data"
    );
}

#[test]
fn opened_handles_keep_their_inode_after_host_rename_and_unlink() {
    let s = setup();
    let file = open(&s, b"/mnt/data", OpenFlags::O_RDWR, 0).unwrap();
    let inside = s._dir.path().join("inside");
    fs::rename(inside.join("data"), inside.join("moved")).unwrap();
    fs::write(inside.join("data"), b"replacement").unwrap();
    fs::remove_file(inside.join("moved")).unwrap();
    assert_eq!(block_on(file.write_at(b"IN", 0)), Ok(2));
    assert_eq!(block_on(file.append(b"!")), Ok((7, 1)));
    let mut data = [0; 7];
    assert_eq!(block_on(file.read_at(&mut data, 0)), Ok(7));
    assert_eq!(&data, b"INside!");
    assert_eq!(fs::read(inside.join("data")).unwrap(), b"replacement");
}

#[test]
fn read_only_host_mapping_rejects_direct_driver_mutations() {
    use wasixv2_vfs::{NewKind, NewNode, OpenOptions, RenameMode, SetAttr, XattrSet};
    let s = setup();
    let host = wasixv2_vfs_host::open(
        &s._dir.path().join("inside"),
        Arc::new(InlineHost),
        wasixv2_vfs_host::Options {
            read_only: true,
            owner: (23, 24),
        },
    )
    .unwrap();
    let root = host.root();
    let node = block_on(root.lookup(b"data")).unwrap();
    let attr = block_on(node.getattr()).unwrap();
    assert_eq!((attr.uid, attr.gid), (23, 24));
    let write = OpenOptions {
        write: true,
        ..Default::default()
    };
    assert_eq!(block_on(node.open(write)).err(), Some(Errno::EROFS));
    assert_eq!(
        block_on(node.setattr(&SetAttr {
            mode: Some(0o600),
            ..Default::default()
        }))
        .err(),
        Some(Errno::EROFS)
    );
    assert_eq!(
        block_on(node.setxattr(b"user.example", b"value", XattrSet::Any)),
        Err(Errno::EROFS)
    );
    assert_eq!(
        block_on(node.removexattr(b"user.example")),
        Err(Errno::EROFS)
    );
    assert_eq!(block_on(root.unlink(b"data")), Err(Errno::EROFS));
    assert_eq!(
        block_on(root.rename(b"data", &root, b"new", RenameMode::Replace)),
        Err(Errno::EROFS)
    );
    let new = NewNode {
        umask: 0,
        kind: NewKind::Regular,
        mode: 0o600,
        uid: 23,
        gid: 24,
        task: 0,
        quota_exempt: false,
    };
    assert_eq!(
        block_on(root.create_open(b"new", &new, write)).err(),
        Some(Errno::EROFS)
    );
    assert_eq!(
        fs::read(s._dir.path().join("inside/data")).unwrap(),
        b"inside"
    );
}

#[test]
fn directory_cookies_resume_across_small_sink_and_host_directory_rename() {
    use std::collections::HashSet;
    use wasixv2_vfs::{DirEntry, DirSink, OpenOptions};
    struct Names(Vec<(Vec<u8>, u64)>, usize);
    impl DirSink for Names {
        fn push(&mut self, entry: DirEntry<'_>) -> bool {
            if self.0.len() == self.1 {
                return false;
            }
            self.0.push((entry.name.to_vec(), entry.next));
            true
        }
    }
    let s = setup();
    let inside = s._dir.path().join("inside");
    fs::create_dir(inside.join("dir")).unwrap();
    for i in 0..300 {
        fs::write(inside.join(format!("dir/{i}")), []).unwrap();
    }
    let host = wasixv2_vfs_host::open(&inside, Arc::new(InlineHost), Default::default()).unwrap();
    let dir = block_on(host.root().lookup(b"dir")).unwrap();
    let handle = block_on(dir.open(OpenOptions {
        read: true,
        ..Default::default()
    }))
    .unwrap();
    let mut names = HashSet::new();
    let mut cookie = 0;
    loop {
        let mut batch = Names(Vec::new(), 7);
        block_on(handle.readdir(cookie, &mut batch)).unwrap();
        if batch.0.is_empty() {
            break;
        }
        for (name, next) in batch.0 {
            assert!(names.insert(name));
            cookie = next;
        }
        if names.len() == 7 {
            fs::rename(inside.join("dir"), inside.join("moved")).unwrap();
        }
    }
    assert_eq!(names.len(), 300);
}

/// V1 host symlink_metadata uses lstat, which does not need file read permission.
#[cfg(target_os = "macos")]
#[test]
fn unreadable_host_files_remain_available_for_metadata_lookup() {
    use std::{io, os::unix::fs::PermissionsExt, path::PathBuf};
    use wasixv2_vfs::FileType;

    struct RestorePermissions(PathBuf);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            fs::set_permissions(&self.0, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    let uid = unsafe { libc::geteuid() };
    eprintln!("host metadata permission probe: effective uid={uid}");
    assert_ne!(
        uid, 0,
        "this permission proof requires an unprivileged host"
    );
    let dir = tempfile::tempdir().unwrap();
    let host =
        wasixv2_vfs_host::open(dir.path(), Arc::new(InlineHost), Default::default()).unwrap();
    let root = host.root();
    for (name, mode) in [("no-access", 0), ("write-only", 0o200)] {
        let path = dir.path().join(name);
        fs::write(&path, b"metadata only").unwrap();
        let _restore = RestorePermissions(path.clone());
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, mode);
        assert_eq!(
            fs::File::open(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let entry = block_on(root.lookup_entry(name.as_bytes()))
            .unwrap_or_else(|error| panic!("metadata lookup of mode {mode:o} failed: {error:?}"));
        let attr = match entry {
            wasixv2_vfs::LookupEntry::Pinned(node) => block_on(node.getattr()).unwrap(),
            wasixv2_vfs::LookupEntry::Observation(metadata) => metadata.attr,
        };
        assert_eq!(attr.file_type, FileType::Regular);
        assert_eq!(attr.mode, mode);
        assert_eq!(attr.size, metadata.len());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn searchable_host_directories_do_not_require_a_listing_grant() {
    use std::{io, os::unix::fs::PermissionsExt};
    use wasixv2_vfs::{NewKind, NewNode, OpenOptions};
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "permission proof requires an unprivileged host"
    );
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("search");
    fs::create_dir(&child).unwrap();
    struct RestoreDirectory(std::path::PathBuf);
    impl Drop for RestoreDirectory {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    let _restore = RestoreDirectory(child.clone());
    fs::write(child.join("file"), b"data").unwrap();
    let nested = child.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("file"), b"nested").unwrap();
    let _restore_nested = RestoreDirectory(nested.clone());
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o111)).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o111)).unwrap();
    assert_eq!(
        fs::read_dir(&child).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let host =
        wasixv2_vfs_host::open(temp.path(), Arc::new(InlineHost), Default::default()).unwrap();
    let root = host.root();
    let observed = block_on(root.lookup_entry(b"search")).unwrap();
    let attr = match observed {
        wasixv2_vfs::LookupEntry::Pinned(node) => block_on(node.getattr()).unwrap(),
        wasixv2_vfs::LookupEntry::Observation(metadata) => metadata.attr,
    };
    assert_eq!(attr.mode, 0o111);
    let directory = block_on(root.lookup_search(b"search")).unwrap();
    // The same search grant can anchor an explicitly mapped execute-only root.
    let search_root =
        wasixv2_vfs_host::open(&child, Arc::new(InlineHost), Default::default()).unwrap();
    assert_eq!(block_on(search_root.root().getattr()).unwrap().mode, 0o111);
    assert!(block_on(search_root.root().lookup(b"file")).is_ok());
    let file = block_on(directory.lookup(b"file")).unwrap();
    assert_eq!(block_on(file.getattr()).unwrap().size, 4);
    let reader = block_on(file.open(OpenOptions {
        read: true,
        ..Default::default()
    }))
    .unwrap();
    let mut bytes = [0; 4];
    assert_eq!(block_on(reader.read_at(&mut bytes, 0)), Ok(4));
    assert_eq!(&bytes, b"data");
    let writer = block_on(file.open(OpenOptions {
        write: true,
        ..Default::default()
    }))
    .unwrap();
    assert_eq!(block_on(writer.write_at(b"edit", 0)), Ok(4));
    let mapped_nested = block_on(search_root.root().lookup_search(b"nested")).unwrap();
    let nested_file = block_on(mapped_nested.lookup(b"file")).unwrap();
    let nested_reader = block_on(nested_file.open(OpenOptions {
        read: true,
        ..Default::default()
    }))
    .unwrap();
    let mut bytes = [0; 6];
    assert_eq!(block_on(nested_reader.read_at(&mut bytes, 0)), Ok(6));
    assert_eq!(&bytes, b"nested");
    assert_eq!(
        block_on(directory.open(OpenOptions {
            read: true,
            ..Default::default()
        }))
        .err(),
        Some(Errno::EACCES)
    );
    // Search plus write permits creation without granting directory listing.
    fs::set_permissions(&child, fs::Permissions::from_mode(0o333)).unwrap();
    let new = NewNode {
        kind: NewKind::Regular,
        mode: 0o600,
        uid: 1,
        gid: 1,
        umask: 0,
        task: 0,
        quota_exempt: false,
    };
    block_on(directory.create_open(
        b"new",
        &new,
        OpenOptions {
            write: true,
            ..Default::default()
        },
    ))
    .unwrap();
    assert!(fs::symlink_metadata(child.join("new")).is_ok());
    fs::set_permissions(child, fs::Permissions::from_mode(0o700)).unwrap();
}
