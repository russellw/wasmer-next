//! A host directory as the upper layer of an overlay, with the host user unprivileged: copy-up
//! and whiteouts work whatever the copied objects' permission bits.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

use futures::executor::block_on;
use wasixv2_host::{Executor, Host, LocalFuture};
use wasixv2_vfs::{
    Clock, Errno, Filesystem, NewKind, NewNode, Node, OpenOptions, SetAttr, Timestamp,
};
use wasixv2_vfs_mem::MemFs;
use wasixv2_vfs_overlay::OverlayFs;

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

fn add_file(dir: &Arc<dyn Node>, name: &[u8], data: &[u8], mode: u32) {
    let new = NewNode {
        umask: 0,
        kind: NewKind::Regular,
        mode,
        uid: 1,
        gid: 1,
        task: 0,
        quota_exempt: false,
    };
    let write = OpenOptions {
        write: true,
        ..OpenOptions::default()
    };
    let (_, handle) = block_on(dir.create_open(name, &new, write)).unwrap();
    block_on(handle.write_at(data, 0)).unwrap();
}

/// A memory lower layer with read-only `ro` and `ro2` and writable `gone`, under a host upper.
fn overlay() -> (tempfile::TempDir, Arc<dyn Filesystem>) {
    let lower = MemFs::new(Arc::new(Epoch), 0o755, 1, 1);
    let lower_root = lower.root();
    add_file(&lower_root, b"ro", b"lower data", 0o444);
    add_file(&lower_root, b"ro2", b"more", 0o444);
    add_file(&lower_root, b"gone", b"x", 0o644);
    let dir = tempfile::tempdir().unwrap();
    let upper = wasixv2_vfs_host::open(dir.path(), Arc::new(InlineHost), Default::default());
    let overlay = OverlayFs::new(Some(upper.unwrap()), vec![Arc::new(lower)]);
    (dir, overlay)
}

#[test]
fn read_only_lower_files_copy_up() {
    let (dir, overlay) = overlay();
    let root = overlay.root();

    let ro = block_on(root.lookup(b"ro")).unwrap();
    let chmod = SetAttr {
        mode: Some(0o640),
        ..SetAttr::default()
    };
    block_on(ro.setattr(&chmod)).unwrap();
    let host = dir.path().join("ro");
    assert_eq!(fs::read(&host).unwrap(), b"lower data");
    assert_eq!(
        fs::metadata(&host).unwrap().permissions().mode() & 0o777,
        0o640
    );

    // Opened for writing (as a privileged guest may): the copy keeps its read-only bits.
    let ro2 = block_on(root.lookup(b"ro2")).unwrap();
    let write = OpenOptions {
        write: true,
        ..OpenOptions::default()
    };
    let handle = block_on(ro2.open(write)).unwrap();
    block_on(handle.write_at(b"MORE", 0)).unwrap();
    let host = dir.path().join("ro2");
    assert_eq!(fs::read(&host).unwrap(), b"MORE");
    assert_eq!(
        fs::metadata(&host).unwrap().permissions().mode() & 0o777,
        0o444
    );
}

#[test]
fn removing_a_lower_file_leaves_a_whiteout() {
    let (_dir, overlay) = overlay();
    let root = overlay.root();

    block_on(root.unlink(b"gone")).unwrap();
    assert_eq!(block_on(root.lookup(b"gone")).err(), Some(Errno::ENOENT));
}

#[cfg(target_os = "macos")]
#[test]
fn unreadable_host_upper_refuses_unknown_private_metadata_without_affecting_direct_stat() {
    use wasixv2_abi::OpenFlags;
    use wasixv2_vfs::{Cred, Ctx, LookupEntry, LookupFlags, OpenHow, RenameMode, Vfs};
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "permission proof requires an unprivileged host"
    );
    let dir = tempfile::tempdir().unwrap();
    for (name, mode, bytes) in [
        ("zero", 0, b"".as_slice()),
        ("source", 0, b"source".as_slice()),
        ("target", 0, b"target".as_slice()),
        ("write", 0o200, b"original".as_slice()),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    let lower = MemFs::new(Arc::new(Epoch), 0o755, 1, 1);
    add_file(&lower.root(), b"zero", b"hidden lower", 0o644);
    let upper =
        wasixv2_vfs_host::open(dir.path(), Arc::new(InlineHost), Default::default()).unwrap();
    // Direct host metadata keeps its required operation-scoped observation behavior.
    let entry = block_on(upper.root().lookup_entry(b"zero")).unwrap();
    let attr = match entry {
        LookupEntry::Pinned(node) => block_on(node.getattr()).unwrap(),
        LookupEntry::Observation(metadata) => metadata.attr,
    };
    assert_eq!((attr.mode, attr.size), (0, 0));
    let overlay = OverlayFs::new(Some(upper), vec![Arc::new(lower)]);
    let vfs = Vfs::new(overlay);
    let root = vfs.root();
    let cred = Cred::user(1, 1);
    let cx = Ctx {
        cred: &cred,
        root: &root,
        umask: 0,
        task: 0,
        leases: None,
    };
    assert_eq!(
        block_on(vfs.lookup_entry(&cx, &root, b"zero", LookupFlags::default()))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
    let exclusive = OpenHow {
        flags: OpenFlags::O_CREAT | OpenFlags::O_EXCL | OpenFlags::O_WRONLY,
        mode: 0o600,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"zero", &exclusive))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
    let how = OpenHow {
        flags: OpenFlags::O_WRONLY | OpenFlags::O_TRUNC,
        mode: 0,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(vfs.open(&cx, &root, b"write", &how))
            .map_err(wasixv2_vfs::PathError::errno)
            .err(),
        Some(Errno::EACCES)
    );
    assert_eq!(
        block_on(vfs.rename(&cx, &root, b"source", &root, b"target", RenameMode::Replace))
            .map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EACCES)
    );
    assert_eq!(
        block_on(vfs.unlink(&cx, &root, b"zero")).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EACCES)
    );
    for (name, expected) in [
        ("zero", b"".as_slice()),
        ("source", b"source".as_slice()),
        ("target", b"target".as_slice()),
        ("write", b"original".as_slice()),
    ] {
        let path = dir.path().join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(path).unwrap(), expected);
    }
}
