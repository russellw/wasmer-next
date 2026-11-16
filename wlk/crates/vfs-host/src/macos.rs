//! macOS vnode descriptors; no path string authorizes access to an existing node.

use std::{
    any::Any,
    collections::HashMap,
    ffi::{CStr, CString},
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    path::{Component, Path, PathBuf},
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock},
};

use async_trait::async_trait;
use wasixv2_abi::Errno;
use wasixv2_host::Host;
use wasixv2_vfs::{
    AclKind, Attr, Device, DirEntry, DirSink, FileType, Filesystem, FsInfo, FsResult, Handle,
    LookupEntry, MAX_DIR_COOKIE, NAME_MAX, NewKind, NewNode, Node, ObservedAttr, OpenOptions,
    RenameMode, SeekHole, SetAttr, StatFs, TimeSet, Timestamp, XattrSet,
};

use crate::Options;

const DEV_SHIFT: u32 = 48;
const MAX_FOLDED_DEVS: u64 = (1 << (63 - DEV_SHIFT)) - 1;
const OVERFLOW_INO: u64 = 1 << 63;
const XATTR_SIZE_MAX: usize = 65536;

type ReadLink = unsafe extern "C" fn(libc::c_int, *mut libc::c_char, libc::size_t) -> libc::c_int;

/// Resolve the macOS 13 symbol at runtime so older hosts can still load the embedding binary.
fn readlink_function() -> Option<ReadLink> {
    static FUNCTION: OnceLock<Option<ReadLink>> = OnceLock::new();
    *FUNCTION.get_or_init(|| {
        // SAFETY: dlsym returns the named libSystem function or null; the signature is the
        // freadlink declaration in sys/unistd.h. No pathname fallback preserves vnode identity.
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"freadlink".as_ptr()) };
        if symbol.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut libc::c_void, ReadLink>(symbol) })
        }
    })
}

/// Darwin and the guest use different errno tables. Unknown host errors fail as EIO.
fn errno(raw: i32) -> Errno {
    match raw {
        libc::EPERM => Errno::EPERM,
        libc::ENOENT => Errno::ENOENT,
        libc::ESRCH => Errno::ESRCH,
        libc::EINTR => Errno::EINTR,
        libc::EIO => Errno::EIO,
        libc::ENXIO => Errno::ENXIO,
        libc::E2BIG => Errno::E2BIG,
        libc::ENOEXEC => Errno::ENOEXEC,
        libc::EBADF => Errno::EBADF,
        libc::ECHILD => Errno::ECHILD,
        libc::EDEADLK => Errno::EDEADLK,
        libc::ENOMEM => Errno::ENOMEM,
        libc::EACCES => Errno::EACCES,
        libc::EFAULT => Errno::EFAULT,
        libc::EBUSY => Errno::EBUSY,
        libc::EEXIST => Errno::EEXIST,
        libc::EXDEV => Errno::EXDEV,
        libc::ENODEV => Errno::ENODEV,
        libc::ENOTDIR => Errno::ENOTDIR,
        libc::EISDIR => Errno::EISDIR,
        libc::EINVAL => Errno::EINVAL,
        libc::ENFILE => Errno::ENFILE,
        libc::EMFILE => Errno::EMFILE,
        libc::ENOTTY => Errno::ENOTTY,
        libc::ETXTBSY => Errno::ETXTBSY,
        libc::EFBIG => Errno::EFBIG,
        libc::ENOSPC => Errno::ENOSPC,
        libc::ESPIPE => Errno::ESPIPE,
        libc::EROFS => Errno::EROFS,
        libc::EMLINK => Errno::EMLINK,
        libc::EPIPE => Errno::EPIPE,
        libc::EDOM => Errno::EDOM,
        libc::ERANGE => Errno::ERANGE,
        libc::EAGAIN => Errno::EAGAIN,
        libc::EINPROGRESS => Errno::EINPROGRESS,
        libc::EALREADY => Errno::EALREADY,
        libc::ENOTSOCK => Errno::ENOTSOCK,
        libc::EDESTADDRREQ => Errno::EDESTADDRREQ,
        libc::EMSGSIZE => Errno::EMSGSIZE,
        libc::EPROTOTYPE => Errno::EPROTOTYPE,
        libc::ENOPROTOOPT => Errno::ENOPROTOOPT,
        libc::EPROTONOSUPPORT => Errno::EPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT => Errno::ESOCKTNOSUPPORT,
        libc::EOPNOTSUPP => Errno::EOPNOTSUPP,
        libc::EPFNOSUPPORT => Errno::EPFNOSUPPORT,
        libc::EAFNOSUPPORT => Errno::EAFNOSUPPORT,
        libc::EADDRINUSE => Errno::EADDRINUSE,
        libc::EADDRNOTAVAIL => Errno::EADDRNOTAVAIL,
        libc::ENETDOWN => Errno::ENETDOWN,
        libc::ENETUNREACH => Errno::ENETUNREACH,
        libc::ENETRESET => Errno::ENETRESET,
        libc::ECONNABORTED => Errno::ECONNABORTED,
        libc::ECONNRESET => Errno::ECONNRESET,
        libc::ENOBUFS => Errno::ENOBUFS,
        libc::EISCONN => Errno::EISCONN,
        libc::ENOTCONN => Errno::ENOTCONN,
        libc::ESHUTDOWN => Errno::ESHUTDOWN,
        libc::ETOOMANYREFS => Errno::ETOOMANYREFS,
        libc::ETIMEDOUT => Errno::ETIMEDOUT,
        libc::ECONNREFUSED => Errno::ECONNREFUSED,
        libc::ELOOP => Errno::ELOOP,
        libc::ENAMETOOLONG => Errno::ENAMETOOLONG,
        libc::EHOSTDOWN => Errno::EHOSTDOWN,
        libc::EHOSTUNREACH => Errno::EHOSTUNREACH,
        libc::ENOTEMPTY => Errno::ENOTEMPTY,
        libc::EDQUOT => Errno::EDQUOT,
        libc::ESTALE => Errno::ESTALE,
        libc::ENOLCK => Errno::ENOLCK,
        libc::ENOSYS => Errno::ENOSYS,
        libc::EOVERFLOW => Errno::EOVERFLOW,
        libc::ECANCELED => Errno::ECANCELED,
        libc::EILSEQ => Errno::EILSEQ,
        libc::ENOMSG => Errno::ENOMSG,
        libc::EIDRM => Errno::EIDRM,
        libc::EPROTO => Errno::EPROTO,
        libc::ENODATA => Errno::ENODATA,
        libc::ENOATTR => Errno::ENODATA,
        libc::ENOTSUP => Errno::EOPNOTSUPP,
        _ => Errno::EIO,
    }
}

fn last_errno() -> Errno {
    errno(
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

fn cvt(ret: libc::c_int) -> FsResult<libc::c_int> {
    if ret < 0 { Err(last_errno()) } else { Ok(ret) }
}

fn cvt_size(ret: isize) -> FsResult<usize> {
    if ret < 0 {
        Err(last_errno())
    } else {
        Ok(ret as usize)
    }
}

fn cstring(bytes: &[u8]) -> FsResult<CString> {
    CString::new(bytes).map_err(|_| Errno::EINVAL)
}

fn open_at(dir: RawFd, name: &CStr, flags: libc::c_int, mode: u32) -> FsResult<OwnedFd> {
    // SAFETY: name is NUL-terminated and a successful descriptor is newly owned. The
    // variadic mode argument needs integer promotion; Darwin's mode_t is only 16 bits.
    let fd = cvt(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn duplicate(fd: RawFd) -> FsResult<OwnedFd> {
    // SAFETY: fcntl returns a new owned descriptor and preserves the original open grant.
    let fd = cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_fd(fd: RawFd) -> FsResult<libc::stat> {
    let mut st = MaybeUninit::uninit();
    // SAFETY: fstat initializes st on success, including for O_SYMLINK descriptors.
    cvt(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    Ok(unsafe { st.assume_init() })
}

fn stat_at(dir: RawFd, name: &CStr) -> FsResult<libc::stat> {
    let mut st = MaybeUninit::uninit();
    // Metadata on one final name requires directory search, not file read access.
    cvt(unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(unsafe { st.assume_init() })
}

fn file_type(mode: libc::mode_t) -> FileType {
    FileType::from_mode(u32::from(mode)).unwrap_or(FileType::Regular)
}

fn descriptor_path(fd: RawFd) -> FsResult<PathBuf> {
    let mut path = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes including the trailing NUL.
    cvt(unsafe { libc::fcntl(fd, libc::F_GETPATH, path.as_mut_ptr()) })?;
    let path = CStr::from_bytes_until_nul(&path).map_err(|_| Errno::ESTALE)?;
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
}

/// F_GETPATH supplies a candidate only. Every component is opened beneath the pinned root
/// without symlink traversal; the final descriptor must name the pinned vnode before use.
fn reopen(root: RawFd, pinned: RawFd, flags: i32) -> FsResult<OwnedFd> {
    let root_path = descriptor_path(root).map_err(|_| Errno::ESTALE)?;
    let candidate = descriptor_path(pinned).map_err(|_| Errno::ESTALE)?;
    let relative = candidate
        .strip_prefix(root_path)
        .map_err(|_| Errno::ESTALE)?;
    reopen_candidate(root, pinned, relative, flags)
}

fn reopen_candidate(root: RawFd, pinned: RawFd, relative: &Path, flags: i32) -> FsResult<OwnedFd> {
    // Opening a candidate must not change its contents before the identity check.
    if flags & (libc::O_TRUNC | libc::O_CREAT | libc::O_EXCL) != 0 {
        return Err(Errno::EINVAL);
    }
    let mut parts = relative.components().peekable();
    let mut dir = duplicate(root)?;
    let file = if parts.peek().is_none() {
        open_at(dir.as_raw_fd(), c".", flags | libc::O_NOFOLLOW, 0)?
    } else {
        loop {
            let Some(Component::Normal(name)) = parts.next() else {
                return Err(Errno::ESTALE);
            };
            let name = cstring(name.as_encoded_bytes())?;
            if parts.peek().is_none() {
                break open_at(
                    dir.as_raw_fd(),
                    &name,
                    flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
                    0,
                )?;
            }
            dir = open_at(dir.as_raw_fd(), &name, libc::O_SEARCH | libc::O_NOFOLLOW, 0)
                .map_err(|_| Errno::ESTALE)?;
        }
    };
    let expected = stat_fd(pinned)?;
    let actual = stat_fd(file.as_raw_fd())?;
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) {
        return Err(Errno::ESTALE);
    }
    Ok(file)
}

fn data_flags(options: OpenOptions) -> i32 {
    // Darwin pwrite ignores O_APPEND (XNU vn_write), whereas write atomically appends. Keep
    // that grant on the original descriptor so append never rechecks changed permissions.
    let access = match (options.read, options.write) {
        (_, false) => libc::O_RDONLY,
        (false, true) => libc::O_WRONLY | libc::O_APPEND,
        (true, true) => libc::O_RDWR | libc::O_APPEND,
    };
    access | if options.sync { libc::O_SYNC } else { 0 }
}

fn set_new_attrs(fd: RawFd, mode: u32, uid: u32, gid: u32) -> FsResult<()> {
    // SAFETY: descriptor-only metadata operations; ownership is best effort as on Linux.
    unsafe {
        libc::fchown(fd, uid, gid);
        cvt(libc::fchmod(fd, mode as libc::mode_t)).map(drop)
    }
}

struct Shared {
    host: Arc<dyn Host>,
    options: Options,
    host_uid: u32,
    host_gid: u32,
    root_dev: libc::dev_t,
    root: Arc<OwnedFd>,
    other_devs: Mutex<Vec<libc::dev_t>>,
    overflow: Mutex<HashMap<(libc::dev_t, u64), u64>>,
}

impl Shared {
    async fn blocking<T, F>(&self, work: F) -> T
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.host.executor().run_blocking(work).await
    }

    fn writable(&self) -> FsResult<()> {
        if self.options.read_only {
            return Err(Errno::EROFS);
        }
        Ok(())
    }

    fn to_guest(&self, uid: u32, gid: u32) -> (u32, u32) {
        let uid = if uid == self.host_uid {
            self.options.owner.0
        } else {
            uid
        };
        let gid = if gid == self.host_gid {
            self.options.owner.1
        } else {
            gid
        };
        (uid, gid)
    }

    fn to_host(&self, uid: Option<u32>, gid: Option<u32>) -> (u32, u32) {
        let map = |id: Option<u32>, guest: u32, host: u32| match id {
            None => u32::MAX,
            Some(id) if id == guest => host,
            Some(id) => id,
        };
        (
            map(uid, self.options.owner.0, self.host_uid),
            map(gid, self.options.owner.1, self.host_gid),
        )
    }

    /// The inode number the VFS sees. Inode numbers are only unique per host device, and the
    /// VFS needs them unique per filesystem, so objects on another host device than the mapped
    /// directory get the device's index in the high bits, as overlayfs's `xino` does. Numbers
    /// that do not leave room for it (64-bit numbers on XFS, NFS, FUSE or an `xino` overlay) get
    /// one from a counter instead, in a range of their own.
    fn ino(&self, dev: libc::dev_t, ino: u64) -> u64 {
        if ino < 1 << DEV_SHIFT {
            if dev == self.root_dev {
                return ino;
            }
            let mut devs = self.other_devs.lock().unwrap();
            let index = match devs.iter().position(|&d| d == dev) {
                Some(index) => index,
                None => {
                    devs.push(dev);
                    devs.len() - 1
                }
            };
            if (index as u64) < MAX_FOLDED_DEVS {
                return (index as u64 + 1) << DEV_SHIFT | ino;
            }
        }
        let mut overflow = self.overflow.lock().unwrap();
        let next = OVERFLOW_INO | overflow.len() as u64;
        *overflow.entry((dev, ino)).or_insert(next)
    }

    fn attr(&self, st: &libc::stat) -> Attr {
        let (uid, gid) = self.to_guest(st.st_uid, st.st_gid);
        let device = |dev: libc::dev_t| Device {
            major: libc::major(dev) as u32,
            minor: libc::minor(dev) as u32,
        };
        Attr {
            ino: self.ino(st.st_dev, st.st_ino),
            file_type: file_type(st.st_mode),
            mode: u32::from(st.st_mode) & 0o7777,
            nlink: st.st_nlink as u32,
            uid,
            gid,
            rdev: device(st.st_rdev),
            size: st.st_size as u64,
            blocks: st.st_blocks as u64,
            blksize: st.st_blksize as u32,
            atime: Timestamp::new(st.st_atime, st.st_atime_nsec as u32),
            mtime: Timestamp::new(st.st_mtime, st.st_mtime_nsec as u32),
            ctime: Timestamp::new(st.st_ctime, st.st_ctime_nsec as u32),
            btime: Some(Timestamp::new(st.st_birthtime, st.st_birthtime_nsec as u32)),
            // Objects on other host devices keep a device of their own, which the VFS maps to
            // one of its anonymous devices.
            dev: (st.st_dev != self.root_dev).then(|| device(st.st_dev)),
        }
    }
}

/// A host directory as a filesystem, with every node retained by its vnode descriptor.
pub struct HostFs {
    shared: Arc<Shared>,
    root: Arc<HostNode>,
}

impl HostFs {
    pub fn new(root: &Path, host: Arc<dyn Host>, options: Options) -> io::Result<Self> {
        if readlink_function().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host vnode symlink reads require macOS freadlink (macOS 13 or later)",
            ));
        }
        let path = CString::new(root.as_os_str().as_encoded_bytes())?;
        // SAFETY: path is NUL-terminated. This initial embedder-selected root may be a symlink.
        let mut raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_EVTONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            // A readable directory and a searchable directory are separate host grants.
            raw = unsafe { libc::open(path.as_ptr(), libc::O_SEARCH | libc::O_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let mut st = MaybeUninit::uninit();
        // SAFETY: st is written on success.
        if unsafe { libc::fstat(raw, st.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let st = unsafe { st.assume_init() };
        // SAFETY: plain getters.
        let (host_uid, host_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let shared = Arc::new(Shared {
            host,
            options,
            host_uid,
            host_gid,
            root_dev: st.st_dev,
            root: fd.clone(),
            other_devs: Mutex::default(),
            overflow: Mutex::default(),
        });
        let root = HostNode::new(&shared, fd, &st);
        Ok(Self { shared, root })
    }
}

#[async_trait(?Send)]
impl Filesystem for HostFs {
    fn limits_file_size(&self) -> bool {
        true
    }

    fn info(&self) -> FsInfo {
        FsInfo {
            name: "9p",
            magic: 0x0102_1997,
            name_max: NAME_MAX,
            read_only: self.shared.options.read_only,
            dev: None,
            has_btime: true,
            stable: false,
        }
    }

    fn root(&self) -> Arc<dyn Node> {
        self.root.clone()
    }

    async fn statfs(&self) -> FsResult<StatFs> {
        self.root
            .run(|fd| {
                let mut st = MaybeUninit::uninit();
                // SAFETY: st is written on success.
                cvt(unsafe { libc::fstatfs(fd, st.as_mut_ptr()) })?;
                let st = unsafe { st.assume_init() };
                Ok(StatFs {
                    block_size: st.f_bsize,
                    blocks: st.f_blocks,
                    blocks_free: st.f_bfree,
                    blocks_avail: st.f_bavail,
                    files: st.f_files,
                    files_free: st.f_ffree,
                    name_max: NAME_MAX as u32,
                    fragment_size: st.f_bsize,
                })
            })
            .await
    }

    async fn sync(&self) -> FsResult<()> {
        // Darwin has no syncfs; fsync the mapped directory without flushing unrelated mounts.
        self.root
            .run(|fd| cvt(unsafe { libc::fsync(fd) }).map(drop))
            .await
    }
}

pub struct HostNode {
    fd: Arc<OwnedFd>,
    shared: Arc<Shared>,
    ino: u64,
    dev: libc::dev_t,
    file_type: FileType,
}

impl HostNode {
    fn new(shared: &Arc<Shared>, fd: Arc<OwnedFd>, st: &libc::stat) -> Arc<Self> {
        Arc::new(Self {
            fd,
            shared: shared.clone(),
            ino: shared.ino(st.st_dev, st.st_ino),
            dev: st.st_dev,
            file_type: file_type(st.st_mode),
        })
    }

    fn downcast<'a>(&self, node: &'a Arc<dyn Node>) -> FsResult<&'a Self> {
        let node = node.as_any().downcast_ref::<Self>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&node.shared, &self.shared) {
            return Err(Errno::EXDEV);
        }
        Ok(node)
    }

    async fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(RawFd) -> FsResult<T> + Send + 'static,
    ) -> FsResult<T> {
        let fd = self.fd.clone();
        self.shared.blocking(move || op(fd.as_raw_fd())).await
    }

    async fn at<T: Send + 'static>(
        &self,
        name: &[u8],
        op: impl FnOnce(RawFd, &CStr) -> FsResult<T> + Send + 'static,
    ) -> FsResult<T> {
        let name = cstring(name)?;
        self.run(move |dir| op(dir, &name)).await
    }

    fn handle(&self, file: OwnedFd) -> Box<dyn Handle> {
        Box::new(HostHandle {
            file: Arc::new(file),
            shared: self.shared.clone(),
            dev: self.dev,
            position: Arc::default(),
            dir: Arc::default(),
        })
    }
}

fn timespec(time: Option<TimeSet>, now: Timestamp) -> libc::timespec {
    match time {
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        Some(time) => {
            let time = match time {
                TimeSet::Now => now,
                TimeSet::At(time) => time,
            };
            libc::timespec {
                tv_sec: time.sec,
                tv_nsec: time.nsec.into(),
            }
        }
    }
}

#[async_trait(?Send)]
impl Node for HostNode {
    fn ino(&self) -> u64 {
        self.ino
    }
    fn file_type(&self) -> FileType {
        self.file_type
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn getattr(&self) -> FsResult<Attr> {
        self.run(stat_fd).await.map(|st| self.shared.attr(&st))
    }

    async fn setattr(&self, attr: &SetAttr) -> FsResult<Attr> {
        self.shared.writable()?;
        let attr = attr.clone();
        let root = self.shared.root.clone();
        let now = self.shared.host.realtime();
        let now = Timestamp::new(now.as_secs() as i64, now.subsec_nanos());
        let (uid, gid) = self.shared.to_host(attr.uid, attr.gid);
        let st = self
            .run(move |fd| {
                // Obtain any required data grant before changing metadata, and verify identity
                // before ftruncate. Metadata itself never uses a candidate pathname.
                let data = attr
                    .size
                    .map(|_| reopen(root.as_raw_fd(), fd, libc::O_WRONLY))
                    .transpose()?;
                if attr.uid.is_some() || attr.gid.is_some() {
                    cvt(unsafe { libc::fchown(fd, uid, gid) })?;
                }
                if let Some(mode) = attr.mode {
                    cvt(unsafe { libc::fchmod(fd, mode as libc::mode_t) })?;
                }
                if let (Some(size), Some(data)) = (attr.size, data) {
                    let size = i64::try_from(size).map_err(|_| Errno::EFBIG)?;
                    cvt(unsafe { libc::ftruncate(data.as_raw_fd(), size) })?;
                }
                if attr.atime.is_some() || attr.mtime.is_some() {
                    let times = [timespec(attr.atime, now), timespec(attr.mtime, now)];
                    // libSystem futimens uses fsetattrlist, retaining symlink vnode identity too.
                    cvt(unsafe { libc::futimens(fd, times.as_ptr()) })?;
                }
                stat_fd(fd)
            })
            .await?;
        Ok(self.shared.attr(&st))
    }

    async fn lookup(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        let (fd, st) = self
            .at(name, |dir, name| {
                // O_SYMLINK itself suppresses traversal (XNU vn_open_auth); unlike O_NOFOLLOW,
                // it permits opening the link vnode, including a dangling link.
                let fd = open_at(dir, name, libc::O_EVTONLY | libc::O_SYMLINK, 0)?;
                let st = stat_fd(fd.as_raw_fd())?;
                Ok((fd, st))
            })
            .await?;
        Ok(Self::new(&self.shared, Arc::new(fd), &st))
    }

    async fn lookup_entry(&self, name: &[u8]) -> FsResult<LookupEntry> {
        let (pinned, st) = self
            .at(name, |dir, name| {
                let observed = stat_at(dir, name)?;
                match open_at(
                    dir,
                    name,
                    libc::O_EVTONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_NOCTTY,
                    0,
                ) {
                    Ok(fd) => {
                        let st = stat_fd(fd.as_raw_fd())?;
                        Ok((Some(fd), st))
                    }
                    // The metadata syscall already succeeded. Its sample is useful without
                    // pretending that this failed capability acquisition retained the object.
                    Err(_) => Ok((None, observed)),
                }
            })
            .await?;
        match pinned {
            Some(fd) => Ok(LookupEntry::Pinned(Self::new(
                &self.shared,
                Arc::new(fd),
                &st,
            ))),
            None => {
                let mut flags = 0;
                if st.st_flags & (libc::UF_IMMUTABLE | libc::SF_IMMUTABLE) != 0 {
                    flags |= wasixv2_vfs::FS_IMMUTABLE_FL;
                }
                if st.st_flags & (libc::UF_APPEND | libc::SF_APPEND) != 0 {
                    flags |= wasixv2_vfs::FS_APPEND_FL;
                }
                Ok(LookupEntry::Observation(ObservedAttr {
                    attr: self.shared.attr(&st),
                    inode_flags: flags,
                }))
            }
        }
    }

    async fn lookup_search(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        let (fd, st) = self
            .at(name, |dir, name| {
                let fd = open_at(dir, name, libc::O_SEARCH | libc::O_NOFOLLOW, 0)?;
                let st = stat_fd(fd.as_raw_fd())?;
                Ok((fd, st))
            })
            .await?;
        Ok(Self::new(&self.shared, Arc::new(fd), &st))
    }

    async fn open_existing(
        &self,
        name: &[u8],
        options: OpenOptions,
    ) -> FsResult<(Arc<dyn Node>, Box<dyn Handle>)> {
        if options.write {
            self.shared.writable()?;
        }
        let (file, pinned, st) = self
            .at(name, move |dir, name| {
                // openat selects the current name. No previous observation is an identity
                // proof; the VFS checks this actual fd before any I/O or truncation.
                let file = open_at(
                    dir,
                    name,
                    data_flags(options) | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
                    0,
                )?;
                let st = stat_fd(file.as_raw_fd())?;
                let pinned = duplicate(file.as_raw_fd())?;
                Ok((file, pinned, st))
            })
            .await?;
        let node = Self::new(&self.shared, Arc::new(pinned), &st);
        let handle = node.handle(file);
        Ok((node, handle))
    }

    async fn create(&self, name: &[u8], new: &NewNode<'_>) -> FsResult<Arc<dyn Node>> {
        self.shared.writable()?;
        if matches!(new.kind, NewKind::Regular) {
            return self
                .create_open(
                    name,
                    new,
                    OpenOptions {
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .map(|(node, _)| node);
        }
        let mode = new.mode;
        let kind = match new.kind {
            NewKind::Directory => 1,
            NewKind::Symlink(_) => 2,
            NewKind::Fifo => 3,
            NewKind::Socket => 4,
            _ => return Err(Errno::EPERM),
        };
        let target = match new.kind {
            NewKind::Symlink(target) => Some(cstring(target)?),
            _ => None,
        };
        let (uid, gid) = self.shared.to_host(Some(new.uid), Some(new.gid));
        let (fd, st) = self
            .at(name, move |dir, name| {
                unsafe {
                    match kind {
                        1 => cvt(libc::mkdirat(dir, name.as_ptr(), mode as libc::mode_t))?,
                        2 => cvt(libc::symlinkat(
                            target.as_ref().unwrap().as_ptr(),
                            dir,
                            name.as_ptr(),
                        ))?,
                        3 => cvt(libc::mkfifoat(dir, name.as_ptr(), mode as libc::mode_t))?,
                        _ => cvt(libc::mknodat(
                            dir,
                            name.as_ptr(),
                            libc::S_IFSOCK | mode as libc::mode_t,
                            0,
                        ))?,
                    };
                }
                let fd = open_at(dir, name, libc::O_EVTONLY | libc::O_SYMLINK, 0)?;
                if kind == 2 {
                    // Newly created symlinks keep host symlink mode, as on Linux.
                    unsafe {
                        libc::fchown(fd.as_raw_fd(), uid, gid);
                    }
                } else {
                    set_new_attrs(fd.as_raw_fd(), mode, uid, gid)?;
                }
                let st = stat_fd(fd.as_raw_fd())?;
                Ok((fd, st))
            })
            .await?;
        Ok(Self::new(&self.shared, Arc::new(fd), &st))
    }

    async fn create_open(
        &self,
        name: &[u8],
        new: &NewNode<'_>,
        options: OpenOptions,
    ) -> FsResult<(Arc<dyn Node>, Box<dyn Handle>)> {
        self.shared.writable()?;
        let mode = new.mode;
        let (uid, gid) = self.shared.to_host(Some(new.uid), Some(new.gid));
        let (file, pinned, st) = self
            .at(name, move |dir, name| {
                let flags = libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_RDWR
                    | libc::O_APPEND
                    | if options.sync { libc::O_SYNC } else { 0 };
                let file = open_at(dir, name, flags, mode)?;
                set_new_attrs(file.as_raw_fd(), mode, uid, gid)?;
                let pinned = duplicate(file.as_raw_fd())?;
                let st = stat_fd(file.as_raw_fd())?;
                Ok((file, pinned, st))
            })
            .await?;
        let node = Self::new(&self.shared, Arc::new(pinned), &st);
        let handle = node.handle(file);
        Ok((node, handle))
    }

    async fn create_unnamed(
        &self,
        _new: &NewNode<'_>,
        _options: OpenOptions,
    ) -> FsResult<(Arc<dyn Node>, Box<dyn Handle>)> {
        self.shared.writable()?;
        Err(Errno::EOPNOTSUPP)
    }

    async fn link(&self, _name: &[u8], _target: &Arc<dyn Node>) -> FsResult<()> {
        self.shared.writable()?;
        // Darwin has no link-by-descriptor primitive. A pathname check followed by linkat
        // could link a replacement vnode, even if a later check notices the race.
        Err(Errno::EOPNOTSUPP)
    }

    async fn unlink(&self, name: &[u8]) -> FsResult<()> {
        self.shared.writable()?;
        self.at(name, |dir, name| {
            cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) }).map(drop)
        })
        .await
    }

    async fn rmdir(&self, name: &[u8]) -> FsResult<()> {
        self.shared.writable()?;
        self.at(name, |dir, name| {
            cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) }).map(drop)
        })
        .await
    }

    async fn rename(
        &self,
        name: &[u8],
        new_dir: &Arc<dyn Node>,
        new_name: &[u8],
        mode: RenameMode,
    ) -> FsResult<()> {
        self.shared.writable()?;
        let flags = match mode {
            RenameMode::Replace => 0,
            RenameMode::NoReplace => libc::RENAME_EXCL,
            RenameMode::Exchange => libc::RENAME_SWAP,
            RenameMode::Whiteout => return Err(Errno::EINVAL),
        };
        let new_dir = self.downcast(new_dir)?.fd.clone();
        let new_name = cstring(new_name)?;
        self.at(name, move |dir, name| {
            cvt(unsafe {
                libc::renameatx_np(
                    dir,
                    name.as_ptr(),
                    new_dir.as_raw_fd(),
                    new_name.as_ptr(),
                    flags,
                )
            })
            .map(drop)
        })
        .await
    }

    async fn readlink(&self) -> FsResult<Vec<u8>> {
        let readlink = readlink_function().ok_or(Errno::EOPNOTSUPP)?;
        self.run(move |fd| {
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let len = cvt(unsafe { readlink(fd, buf.as_mut_ptr().cast(), buf.len()) })?;
            buf.truncate(len as usize);
            Ok(buf)
        })
        .await
    }

    async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
        if options.write {
            self.shared.writable()?;
        }
        let root = self.shared.root.clone();
        let directory = self.file_type == FileType::Directory;
        let file = self
            .run(move |fd| {
                if directory {
                    // A directory can reopen itself directly, even after rename/unlink.
                    open_at(
                        fd,
                        c".",
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        0,
                    )
                } else {
                    reopen(root.as_raw_fd(), fd, data_flags(options))
                }
            })
            .await?;
        Ok(self.handle(file))
    }

    async fn getxattr(&self, name: &[u8]) -> FsResult<Vec<u8>> {
        if AclKind::of_xattr(name).is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        let name = cstring(name)?;
        self.run(move |fd| {
            read_sized(|buf, len| unsafe {
                libc::fgetxattr(fd, name.as_ptr(), buf.cast(), len, 0, 0)
            })
        })
        .await
    }

    async fn setxattr(&self, name: &[u8], value: &[u8], how: XattrSet) -> FsResult<()> {
        self.shared.writable()?;
        if AclKind::of_xattr(name).is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        let name = cstring(name)?;
        let value = value.to_vec();
        let flags = match how {
            XattrSet::Any => 0,
            XattrSet::Create => libc::XATTR_CREATE,
            XattrSet::Replace => libc::XATTR_REPLACE,
        };
        self.run(move |fd| {
            cvt(unsafe {
                libc::fsetxattr(
                    fd,
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    flags,
                )
            })
            .map(drop)
        })
        .await
    }

    async fn listxattr(&self) -> FsResult<Vec<Vec<u8>>> {
        self.run(|fd| {
            let names = read_sized(|buf, len| unsafe { libc::flistxattr(fd, buf.cast(), len, 0) })?;
            Ok(names
                .split(|&b| b == 0)
                .filter(|name| !name.is_empty())
                .map(<[u8]>::to_vec)
                .collect())
        })
        .await
    }

    async fn removexattr(&self, name: &[u8]) -> FsResult<()> {
        self.shared.writable()?;
        if AclKind::of_xattr(name).is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        let name = cstring(name)?;
        self.run(move |fd| cvt(unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) }).map(drop))
            .await
    }
}

fn read_sized(read: impl Fn(*mut u8, usize) -> isize) -> FsResult<Vec<u8>> {
    loop {
        let len = cvt_size(read(std::ptr::null_mut(), 0))?.min(XATTR_SIZE_MAX);
        let mut buf = vec![0; len];
        match cvt_size(read(buf.as_mut_ptr(), len)) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(Errno::ERANGE) if len < XATTR_SIZE_MAX => continue,
            Err(err) => return Err(err),
        }
    }
}
/// A libc directory stream, accessed only while its enclosing mutex is held. Keeping the
/// stream alive also keeps telldir/seekdir cookies valid across calls and name changes.
struct DirStream(NonNull<libc::DIR>);

// SAFETY: ownership may move between blocking executor threads; the enclosing mutex prevents
// concurrent access. No pointer into a readdir buffer leaves the locked operation.
unsafe impl Send for DirStream {}

impl Drop for DirStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0.as_ptr());
        }
    }
}

#[derive(Default)]
struct DirState {
    stream: Option<DirStream>,
    offsets: Vec<libc::c_long>,
}

struct HostDirent {
    name: Vec<u8>,
    ino: u64,
    file_type: FileType,
    next: u64,
}

impl DirState {
    fn read(&mut self, fd: RawFd, index: usize) -> FsResult<Vec<HostDirent>> {
        if self.stream.is_none() {
            let copy = duplicate(fd)?;
            // fdopendir consumes the descriptor on success only.
            let ptr = unsafe { libc::fdopendir(copy.as_raw_fd()) };
            let ptr = NonNull::new(ptr).ok_or_else(last_errno)?;
            let _ = copy.into_raw_fd();
            self.stream = Some(DirStream(ptr));
        }
        let dir = self.stream.as_ref().unwrap().0.as_ptr();
        let at = match index {
            0 => 0,
            n => *self.offsets.get(n - 1).ok_or(Errno::EINVAL)?,
        };
        unsafe {
            libc::seekdir(dir, at);
        }
        let mut entries = Vec::new();
        let mut index = index;
        while entries.len() < 128 {
            // Darwin readdir leaves errno alone at EOF.
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                if unsafe { *libc::__error() } != 0 {
                    return Err(last_errno());
                }
                break;
            }
            let entry = unsafe { &*entry };
            let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let file_type = match FileType::from_mode(u32::from(entry.d_type) << 12) {
                Some(t) => t,
                None => {
                    let name = cstring(name)?;
                    let mut st = MaybeUninit::uninit();
                    let result = cvt(unsafe {
                        libc::fstatat(
                            fd,
                            name.as_ptr(),
                            st.as_mut_ptr(),
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    });
                    match result {
                        Ok(_) => file_type(unsafe { st.assume_init() }.st_mode),
                        Err(Errno::ENOENT) => continue,
                        Err(err) => return Err(err),
                    }
                }
            };
            let at = unsafe { libc::telldir(dir) };
            self.offsets.truncate(index);
            self.offsets.push(at);
            index += 1;
            entries.push(HostDirent {
                name: name.to_vec(),
                ino: entry.d_ino,
                file_type,
                next: (index as u64).min(MAX_DIR_COOKIE),
            });
        }
        Ok(entries)
    }
}

struct HostHandle {
    file: Arc<OwnedFd>,
    shared: Arc<Shared>,
    dev: libc::dev_t,
    position: Arc<Mutex<()>>,
    dir: Arc<Mutex<DirState>>,
}

impl HostHandle {
    async fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(RawFd) -> FsResult<T> + Send + 'static,
    ) -> FsResult<T> {
        let file = self.file.clone();
        self.shared.blocking(move || op(file.as_raw_fd())).await
    }
}

#[async_trait(?Send)]
impl Handle for HostHandle {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> FsResult<usize> {
        let offset = i64::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let len = buf.len();
        let data = self
            .run(move |fd| {
                let mut data = vec![0; len];
                let n = cvt_size(unsafe {
                    libc::pread(fd, data.as_mut_ptr().cast(), data.len(), offset)
                })?;
                data.truncate(n);
                Ok(data)
            })
            .await?;
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }

    async fn write_at(&self, data: &[u8], offset: u64) -> FsResult<usize> {
        let offset = i64::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let data = data.to_vec();
        self.run(move |fd| {
            cvt_size(unsafe { libc::pwrite(fd, data.as_ptr().cast(), data.len(), offset) })
        })
        .await
    }

    async fn append(&self, data: &[u8]) -> FsResult<(u64, usize)> {
        let position = self.position.clone();
        let data = data.to_vec();
        self.run(move |fd| {
            let _position = position.lock().unwrap();
            let n = cvt_size(unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) })?;
            let end = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
            if end < 0 {
                return Err(last_errno());
            }
            Ok((end as u64 - n as u64, n))
        })
        .await
    }

    async fn set_size(&self, size: u64) -> FsResult<()> {
        let size = i64::try_from(size).map_err(|_| Errno::EFBIG)?;
        self.run(move |fd| cvt(unsafe { libc::ftruncate(fd, size) }).map(drop))
            .await
    }

    async fn sync(&self, _data_only: bool) -> FsResult<()> {
        self.run(|fd| cvt(unsafe { libc::fsync(fd) }).map(drop))
            .await
    }

    async fn seek_hole(&self, offset: u64, _size: u64, which: SeekHole) -> FsResult<u64> {
        let offset = i64::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let whence = match which {
            SeekHole::Data => libc::SEEK_DATA,
            SeekHole::Hole => libc::SEEK_HOLE,
        };
        let position = self.position.clone();
        self.run(move |fd| {
            let _position = position.lock().unwrap();
            let at = unsafe { libc::lseek(fd, offset, whence) };
            if at < 0 {
                Err(last_errno())
            } else {
                Ok(at as u64)
            }
        })
        .await
    }

    async fn readdir(&self, cookie: u64, sink: &mut dyn DirSink) -> FsResult<()> {
        let mut index = usize::try_from(cookie).map_err(|_| Errno::EINVAL)?;
        loop {
            let dir = self.dir.clone();
            let entries = self
                .run(move |fd| dir.lock().unwrap().read(fd, index))
                .await?;
            if entries.is_empty() {
                return Ok(());
            }
            for entry in entries {
                if !sink.push(DirEntry {
                    name: &entry.name,
                    ino: self.shared.ino(self.dev, entry.ino),
                    file_type: entry.file_type,
                    next: entry.next,
                }) {
                    return Ok(());
                }
                index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn pinned(path: &Path) -> OwnedFd {
        let path = cstring(path.as_os_str().as_encoded_bytes()).unwrap();
        open_at(libc::AT_FDCWD, &path, libc::O_EVTONLY | libc::O_SYMLINK, 0).unwrap()
    }

    #[test]
    fn candidate_reopens_reject_replacement_symlinks_and_wrong_inodes_before_io() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("mapped");
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("file"), b"original").unwrap();
        fs::write(temp.path().join("outside"), b"outside").unwrap();
        let root = pinned(&root_path);
        let file = pinned(&root_path.join("file"));
        let candidate = Path::new("file");
        fs::rename(root_path.join("file"), root_path.join("moved")).unwrap();
        symlink(temp.path().join("outside"), root_path.join("file")).unwrap();
        assert_eq!(
            reopen_candidate(
                root.as_raw_fd(),
                file.as_raw_fd(),
                candidate,
                libc::O_WRONLY
            )
            .err(),
            Some(Errno::ELOOP)
        );
        fs::remove_file(root_path.join("file")).unwrap();
        fs::write(root_path.join("file"), b"replacement").unwrap();
        assert_eq!(
            reopen_candidate(
                root.as_raw_fd(),
                file.as_raw_fd(),
                candidate,
                libc::O_WRONLY
            )
            .err(),
            Some(Errno::ESTALE)
        );
        assert_eq!(
            reopen_candidate(
                root.as_raw_fd(),
                file.as_raw_fd(),
                candidate,
                libc::O_WRONLY | libc::O_TRUNC
            )
            .err(),
            Some(Errno::EINVAL)
        );
        assert_eq!(fs::read(root_path.join("file")).unwrap(), b"replacement");
        assert_eq!(fs::read(temp.path().join("outside")).unwrap(), b"outside");
        let reopened = reopen(root.as_raw_fd(), file.as_raw_fd(), libc::O_RDONLY).unwrap();
        assert_eq!(
            stat_fd(reopened.as_raw_fd()).unwrap().st_ino,
            stat_fd(file.as_raw_fd()).unwrap().st_ino
        );
        fs::rename(root_path.join("moved"), temp.path().join("escaped")).unwrap();
        assert_eq!(
            reopen(root.as_raw_fd(), file.as_raw_fd(), libc::O_RDONLY).err(),
            Some(Errno::ESTALE)
        );
    }

    #[test]
    fn candidate_walk_refuses_intermediate_symlinks_and_parent_components() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("dir")).unwrap();
        fs::write(temp.path().join("dir/file"), b"data").unwrap();
        let root = pinned(temp.path());
        let file = pinned(&temp.path().join("dir/file"));
        fs::rename(temp.path().join("dir"), temp.path().join("moved")).unwrap();
        symlink("moved", temp.path().join("dir")).unwrap();
        assert_eq!(
            reopen_candidate(
                root.as_raw_fd(),
                file.as_raw_fd(),
                Path::new("dir/file"),
                libc::O_RDONLY
            )
            .err(),
            Some(Errno::ESTALE)
        );
        assert_eq!(
            reopen_candidate(
                root.as_raw_fd(),
                file.as_raw_fd(),
                Path::new("../file"),
                libc::O_RDONLY
            )
            .err(),
            Some(Errno::ESTALE)
        );
        fs::remove_file(temp.path().join("dir")).unwrap();
        fs::rename(temp.path().join("moved"), temp.path().join("dir")).unwrap();
        let moved = temp.path().with_extension("renamed");
        fs::rename(temp.path(), &moved).unwrap();
        assert!(reopen(root.as_raw_fd(), file.as_raw_fd(), libc::O_RDONLY).is_ok());
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn apfs_unlinked_symlink_bodies_are_unavailable_even_through_normal_descriptors() {
        let temp = tempfile::tempdir().unwrap();
        let root = pinned(temp.path());
        let mut filesystem = MaybeUninit::uninit();
        cvt(unsafe { libc::fstatfs(root.as_raw_fd(), filesystem.as_mut_ptr()) }).unwrap();
        let filesystem = unsafe { filesystem.assume_init() };
        let kind = unsafe { CStr::from_ptr(filesystem.f_fstypename.as_ptr()) };
        if kind != c"apfs" {
            // This regression describes observed APFS behavior, not a universal filesystem
            // requirement that discarded links must become unreadable.
            return;
        }
        let readlink = readlink_function().unwrap();
        for (name, flags) in [
            (c"event", libc::O_EVTONLY | libc::O_SYMLINK),
            (c"normal", libc::O_RDONLY | libc::O_SYMLINK),
        ] {
            let path = temp.path().join(name.to_str().unwrap());
            symlink("missing-target", &path).unwrap();
            let fd = open_at(root.as_raw_fd(), name, flags, 0).unwrap();
            let mut body = [0u8; 64];
            let len =
                cvt(unsafe { readlink(fd.as_raw_fd(), body.as_mut_ptr().cast(), body.len()) })
                    .unwrap();
            assert_eq!(&body[..len as usize], b"missing-target");
            fs::remove_file(path).unwrap();
            assert_eq!(
                cvt(unsafe { readlink(fd.as_raw_fd(), body.as_mut_ptr().cast(), body.len()) }),
                Err(Errno::EINVAL)
            );
        }
    }

    #[test]
    fn darwin_errno_values_are_mapped_to_guest_values() {
        assert_eq!(errno(libc::EAGAIN), Errno::EAGAIN);
        assert_eq!(errno(libc::ELOOP), Errno::ELOOP);
        assert_eq!(errno(libc::ENOTEMPTY), Errno::ENOTEMPTY);
        assert_eq!(errno(libc::ENOATTR), Errno::ENODATA);
        assert_eq!(errno(libc::ENOTSUP), Errno::EOPNOTSUPP);
    }
}
