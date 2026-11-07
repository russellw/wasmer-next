//! Closed, private storage for Directory. Every operation reaches only this
//! Vfs/MemFs, user credentials and SystemTimeClock: no mounts, shared pages,
//! watchers, security/lease callbacks, user clocks or escaping VFS guards.
//! Pending can only be a canonical memory lock held by another fully driven
//! OS thread. The same pinned future is polled and parked without entering a
//! futures/Tokio executor. Do not reuse this driver for provider callbacks.

use std::{
    future::Future,
    path::Path,
    pin::pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bytes::Bytes;
use wasixv2_abi::{Errno, OpenFlags};
use wasixv2_vfs::{
    Attr, Clock, Cred, Ctx, DirEntry, DirSink, File as VfsFile, FileType as Kind,
    FsResult as VfsResult, LookupFlags, OpenHow, PathError, PathResult, RenameMode, TimeSet,
    Timestamp, Vfs,
};
use wasixv2_vfs_mem::{Limits, MemFs};

use crate::provider_fs::{
    DirectoryEntry, File, FileMetadata, FileOpenOptions, FileSystem, FileSystemCapabilities,
    FileType, FsError, FsResult, RelativePath,
};

struct SystemTimeClock;
impl Clock for SystemTimeClock {
    fn now(&self) -> Timestamp {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp::new(
            elapsed.as_secs().min(i64::MAX as u64) as i64,
            elapsed.subsec_nanos(),
        )
    }
}

struct MemoryStorage {
    vfs: Arc<Vfs>,
    cred: Cred,
}
impl std::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStorage").finish_non_exhaustive()
    }
}

// Deliberately private to this module's closed memory operations. In contrast
// to futures::executor::block_on, parking has no executor-enter/reentry state.
fn complete<T>(future: impl Future<Output = VfsResult<T>>) -> FsResult<T> {
    let (parker, unparker) = parking::pair();
    let waker = Waker::from(unparker);
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(result) => return result.map_err(map_error),
            Poll::Pending => {
                #[cfg(test)]
                PENDING_HOOK.with(|hook| {
                    if let Some(hook) = hook.borrow_mut().take() {
                        hook();
                    }
                });
                parker.park();
            }
        }
    }
}

fn complete_path<T>(future: impl Future<Output = PathResult<T>>) -> FsResult<T> {
    // This closed provider exposes errno-based filesystem errors, not guest
    // namespace verdicts. Use the VFS's deliberate projection at this boundary.
    complete(async { future.await.map_err(PathError::errno) })
}

#[cfg(test)]
thread_local! {
    // Only tests coordinate actual canonical lock contention at the park gap.
    static PENDING_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn map_error(error: Errno) -> FsError {
    match error {
        Errno::ENOENT => FsError::NotFound,
        Errno::EEXIST => FsError::AlreadyExists,
        Errno::EACCES | Errno::EPERM | Errno::EROFS | Errno::EBADF => FsError::PermissionDenied,
        Errno::ENOTDIR => FsError::NotDirectory,
        Errno::EISDIR => FsError::NotFile,
        Errno::ENOTEMPTY => FsError::DirectoryNotEmpty,
        Errno::EINVAL | Errno::ENAMETOOLONG | Errno::EBUSY => {
            FsError::InvalidInput(format!("{error:?}"))
        }
        Errno::EOPNOTSUPP | Errno::ENOSYS => FsError::Unsupported,
        _ => FsError::Io(format!("{error:?}")),
    }
}
fn nanos(time: Timestamp) -> u64 {
    (time.sec.max(0) as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(time.nsec))
}
fn time(ns: u64) -> TimeSet {
    TimeSet::At(Timestamp::new(
        (ns / 1_000_000_000) as i64,
        (ns % 1_000_000_000) as u32,
    ))
}
fn metadata(attr: Attr) -> FileMetadata {
    FileMetadata {
        file_type: if attr.file_type == Kind::Directory {
            FileType::Directory
        } else {
            FileType::File
        },
        len: attr.size,
        readonly: attr.mode & 0o222 == 0,
        accessed: nanos(attr.atime),
        modified: nanos(attr.mtime),
        created: nanos(attr.btime.unwrap_or(attr.ctime)),
    }
}
fn absolute(path: &RelativePath) -> Vec<u8> {
    let mut bytes = vec![b'/'];
    bytes.extend_from_slice(path.as_path().as_os_str().as_encoded_bytes());
    bytes
}
impl MemoryStorage {
    fn new() -> Self {
        // Directory was unbounded private host storage, not a guest tmpfs.
        // MemFs::new would silently impose its default 2 GiB/inode quota.
        let root = Arc::new(MemFs::with_limits(
            Arc::new(SystemTimeClock),
            0o755,
            1,
            1,
            Limits::UNLIMITED,
        ));
        Self {
            vfs: Vfs::new(root),
            cred: Cred::user(1, 1),
        }
    }
    fn context<'a>(&'a self, root: &'a wasixv2_vfs::Path) -> Ctx<'a> {
        Ctx {
            cred: &self.cred,
            root,
            umask: 0,
            task: 0,
            leases: None,
        }
    }
    fn stat(&self, path: &RelativePath) -> FsResult<FileMetadata> {
        let root = self.vfs.root();
        complete(async {
            let path = self
                .vfs
                .lookup(
                    &self.context(&root),
                    &root,
                    &absolute(path),
                    LookupFlags::follow(),
                )
                .await
                .map_err(PathError::errno)?;
            self.vfs.stat(&path).await.map(metadata)
        })
    }
    fn mkdir_all(&self, path: &RelativePath) -> FsResult<()> {
        let root = self.vfs.root();
        complete_path(self.vfs.mkdir_all(&self.context(&root), &absolute(path)))
    }
    fn mkdir(&self, path: &RelativePath) -> FsResult<()> {
        let root = self.vfs.root();
        complete_path(
            self.vfs
                .mkdir(&self.context(&root), &root, &absolute(path), 0o755),
        )
    }
    fn open(
        self: &Arc<Self>,
        path: &RelativePath,
        options: FileOpenOptions,
    ) -> FsResult<MemoryFile> {
        let write = options.write || options.append;
        if !write && (!options.read || options.create || options.create_new || options.truncate) {
            return Err(FsError::InvalidInput("invalid file open options".into()));
        }
        let mut flags = match (options.read, write) {
            (true, true) => OpenFlags::O_RDWR,
            (false, true) => OpenFlags::O_WRONLY,
            _ => OpenFlags::O_RDONLY,
        };
        if options.create || options.create_new {
            flags |= OpenFlags::O_CREAT;
        }
        if options.create_new {
            flags |= OpenFlags::O_EXCL;
        }
        if options.truncate {
            flags |= OpenFlags::O_TRUNC;
        }
        if options.append {
            flags |= OpenFlags::O_APPEND;
        }
        let root = self.vfs.root();
        let file = complete_path(self.vfs.open(
            &self.context(&root),
            &root,
            &absolute(path),
            &OpenHow {
                flags,
                mode: 0o666,
                lookup: LookupFlags::follow(),
            },
        ))?;
        if file.file_type() != Kind::Regular {
            return Err(FsError::NotFile);
        }
        Ok(MemoryFile {
            storage: self.clone(),
            file: Mutex::new(Some(file)),
            append: options.append,
        })
    }
    fn entries(&self, path: &[u8]) -> FsResult<Vec<(Vec<u8>, FileMetadata)>> {
        struct Names(Vec<Vec<u8>>);
        impl DirSink for Names {
            fn push(&mut self, entry: DirEntry<'_>) -> bool {
                if entry.name != b"." && entry.name != b".." {
                    self.0.push(entry.name.to_vec());
                }
                true
            }
        }
        let root = self.vfs.root();
        complete(async {
            let cx = self.context(&root);
            let file = self
                .vfs
                .open(
                    &cx,
                    &root,
                    path,
                    &OpenHow {
                        flags: OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY,
                        mode: 0,
                        lookup: LookupFlags::follow(),
                    },
                )
                .await
                .map_err(PathError::errno)?;
            let mut names = Names(Vec::new());
            file.readdir(0, &mut names).await?;
            let mut entries = Vec::with_capacity(names.0.len());
            for name in names.0 {
                let entry = self
                    .vfs
                    .lookup(&cx, &file.path, &name, LookupFlags::follow())
                    .await
                    .map_err(PathError::errno)?;
                entries.push((name, metadata(self.vfs.stat(&entry).await?)));
            }
            Ok(entries)
        })
    }
    fn read_dir(&self, path: &RelativePath) -> FsResult<Vec<DirectoryEntry>> {
        Ok(self
            .entries(&absolute(path))?
            .into_iter()
            .map(|(name, metadata)| DirectoryEntry {
                name: String::from_utf8_lossy(&name).into_owned(),
                metadata,
            })
            .collect())
    }
    fn remove(&self, path: &RelativePath, recursive: bool) -> FsResult<()> {
        self.remove_entry(&absolute(path), recursive)
    }
    fn remove_entry(&self, name: &[u8], recursive: bool) -> FsResult<()> {
        let root = self.vfs.root();
        let directory = complete(async {
            let path = self
                .vfs
                .lookup(&self.context(&root), &root, name, LookupFlags::follow())
                .await
                .map_err(PathError::errno)?;
            Ok(self.vfs.stat(&path).await?.file_type == Kind::Directory)
        })?;
        if directory {
            if recursive {
                // Keep canonical raw entry names here; the public display name
                // may be lossy UTF-8 and must never select a different inode.
                for (child, _) in self.entries(name)? {
                    let mut path = name.to_vec();
                    path.push(b'/');
                    path.extend_from_slice(&child);
                    self.remove_entry(&path, true)?;
                }
            }
            complete_path(self.vfs.rmdir(&self.context(&root), &root, name))
        } else {
            complete_path(self.vfs.unlink(&self.context(&root), &root, name))
        }
    }
    fn rename(&self, from: &RelativePath, to: &RelativePath) -> FsResult<()> {
        let root = self.vfs.root();
        complete_path(self.vfs.rename(
            &self.context(&root),
            &root,
            &absolute(from),
            &root,
            &absolute(to),
            RenameMode::Replace,
        ))
    }
    fn set_times(
        &self,
        path: &RelativePath,
        atime: Option<u64>,
        mtime: Option<u64>,
        follow: bool,
    ) -> FsResult<()> {
        let root = self.vfs.root();
        complete(async {
            let cx = self.context(&root);
            let path = self
                .vfs
                .lookup(
                    &cx,
                    &root,
                    &absolute(path),
                    if follow {
                        LookupFlags::follow()
                    } else {
                        LookupFlags::nofollow()
                    },
                )
                .await
                .map_err(PathError::errno)?;
            self.vfs
                .utimes(&cx, &path, atime.map(time), mtime.map(time))
                .await
        })
    }
}

/// A portable, mutable in-memory external filesystem provider.
#[derive(Clone, Debug)]
pub struct Directory {
    inner: Arc<MemoryStorage>,
}
impl Default for Directory {
    fn default() -> Self {
        Self {
            inner: Arc::new(MemoryStorage::new()),
        }
    }
}
impl Directory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Write a complete file, creating parent directories as needed.
    ///
    /// # Errors
    /// Returns an error for invalid paths, denied rights or failed filesystem operations.
    pub async fn write(&self, path: impl AsRef<Path>, bytes: impl Into<Bytes>) -> FsResult<()> {
        let path = RelativePath::new(path)?;
        if let Some(parent) = path.as_path().parent() {
            self.inner.mkdir_all(&RelativePath::new(parent)?)?;
        }
        let file = self.inner.open(
            &path,
            FileOpenOptions {
                write: true,
                create: true,
                truncate: true,
                ..Default::default()
            },
        )?;
        let data = bytes.into();
        let mut written = 0;
        while written < data.len() {
            let count = file.positioned(written as u64, &data[written..])?;
            if count == 0 || count > data.len() - written {
                return Err(FsError::Io("invalid memory write count".into()));
            }
            written += count;
        }
        file.sync()?;
        file.close_now();
        Ok(())
    }
    /// Write UTF-8 text relative to the directory root.
    ///
    /// # Errors
    /// Returns an error for invalid paths, denied rights or failed filesystem operations.
    pub async fn write_text(
        &self,
        path: impl AsRef<Path>,
        text: impl Into<String>,
    ) -> FsResult<()> {
        self.write(path, Bytes::from(text.into())).await
    }
    /// Read a complete file relative to the directory root.
    ///
    /// # Errors
    /// Returns an error for invalid paths, denied rights or failed filesystem operations.
    pub async fn read(&self, path: impl AsRef<Path>) -> FsResult<Bytes> {
        let path = RelativePath::new(path)?;
        let file = self.inner.open(
            &path,
            FileOpenOptions {
                read: true,
                ..Default::default()
            },
        )?;
        let length = usize::try_from(file.stat()?.len)
            .map_err(|_| FsError::Io("file is too large for this target".into()))?;
        let bytes = file.read(0, length)?;
        file.close_now();
        Ok(bytes)
    }
    /// Read and decode UTF-8 text relative to the directory root.
    ///
    /// # Errors
    /// Returns an error for invalid paths, denied rights or failed filesystem operations.
    pub async fn read_text(&self, path: impl AsRef<Path>) -> FsResult<String> {
        String::from_utf8(self.read(path).await?.to_vec())
            .map_err(|error| FsError::Io(error.to_string()))
    }
}
#[async_trait]
impl FileSystem for Directory {
    fn capabilities(&self) -> FileSystemCapabilities {
        FileSystemCapabilities::READ_WRITE
    }
    async fn stat(&self, path: &RelativePath) -> FsResult<FileMetadata> {
        self.inner.stat(path)
    }
    async fn read_dir(&self, path: &RelativePath) -> FsResult<Vec<DirectoryEntry>> {
        self.inner.read_dir(path)
    }
    async fn open(&self, path: &RelativePath, options: FileOpenOptions) -> FsResult<Arc<dyn File>> {
        Ok(Arc::new(self.inner.open(path, options)?))
    }
    async fn create_dir(&self, path: &RelativePath) -> FsResult<()> {
        self.inner.mkdir(path)
    }
    async fn remove(&self, path: &RelativePath, recursive: bool) -> FsResult<()> {
        self.inner.remove(path, recursive)
    }
    async fn rename(&self, from: &RelativePath, to: &RelativePath) -> FsResult<()> {
        self.inner.rename(from, to)
    }
    async fn flush(&self) -> FsResult<()> {
        Ok(())
    }
    async fn set_times(
        &self,
        path: &RelativePath,
        atime: Option<u64>,
        mtime: Option<u64>,
        follow_symlinks: bool,
    ) -> FsResult<()> {
        self.inner.set_times(path, atime, mtime, follow_symlinks)
    }
}

struct MemoryFile {
    storage: Arc<MemoryStorage>,
    file: Mutex<Option<VfsFile>>,
    append: bool,
}
impl std::fmt::Debug for MemoryFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryFile").finish_non_exhaustive()
    }
}
impl MemoryFile {
    fn with<T>(&self, work: impl FnOnce(&VfsFile) -> FsResult<T>) -> FsResult<T> {
        let file = self.file.lock().unwrap();
        work(
            file.as_ref()
                .ok_or_else(|| FsError::Io("file is closed".into()))?,
        )
    }
    fn read(&self, offset: u64, length: usize) -> FsResult<Bytes> {
        self.with(|file| {
            if !file.readable {
                return Err(FsError::PermissionDenied);
            }
            let mut bytes = vec![0; length];
            let count = complete(file.read_at(&mut bytes, offset))?;
            bytes.truncate(count);
            Ok(bytes.into())
        })
    }
    fn positioned(&self, offset: u64, data: &[u8]) -> FsResult<usize> {
        self.with(|file| {
            if !file.writable {
                return Err(FsError::PermissionDenied);
            }
            complete(file.write_at_as(data, offset, &self.storage.cred))
        })
    }
    fn append(&self, data: &[u8]) -> FsResult<(u64, usize)> {
        self.with(|file| {
            if !file.writable {
                return Err(FsError::PermissionDenied);
            }
            let (end, count) = complete(file.append_as(data, &self.storage.cred))?;
            let start = end
                .checked_sub(count as u64)
                .ok_or_else(|| FsError::Io("invalid append offset".into()))?;
            Ok((start, count))
        })
    }
    fn stat(&self) -> FsResult<FileMetadata> {
        self.with(|file| complete(self.storage.vfs.stat(&file.path)).map(metadata))
    }
    fn sync(&self) -> FsResult<()> {
        self.with(|file| complete(file.sync(false)))
    }
    fn close_now(&self) {
        let file = self.file.lock().unwrap().take();
        drop(file);
    }
}
#[async_trait]
impl File for MemoryFile {
    async fn read_at(&self, offset: u64, length: usize) -> FsResult<Bytes> {
        self.read(offset, length)
    }
    async fn write_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
        if self.append {
            self.append(&data).map(|(_, count)| count)
        } else {
            self.positioned(offset, &data)
        }
    }
    async fn write_positioned_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
        self.positioned(offset, &data)
    }
    async fn try_atomic_append(&self, data: Bytes) -> FsResult<Option<(u64, usize)>> {
        self.append(&data).map(Some)
    }
    async fn set_len(&self, length: u64) -> FsResult<()> {
        self.with(|file| {
            if !file.writable {
                return Err(FsError::PermissionDenied);
            }
            complete(file.set_size(length))
        })
    }
    async fn flush(&self) -> FsResult<()> {
        self.sync()
    }
    async fn close(&self) -> FsResult<()> {
        self.close_now();
        Ok(())
    }
    async fn metadata(&self) -> FsResult<FileMetadata> {
        self.stat()
    }
    async fn set_times(&self, atime: Option<u64>, mtime: Option<u64>) -> FsResult<()> {
        self.with(|file| {
            let root = self.storage.vfs.root();
            complete(self.storage.vfs.utimes(
                &self.storage.context(&root),
                &file.path,
                atime.map(time),
                mtime.map(time),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    fn path(path: &str) -> RelativePath {
        RelativePath::new(path).unwrap()
    }
    fn directory_file(storage: &MemoryStorage, path: &str) -> VfsFile {
        let root = storage.vfs.root();
        complete_path(storage.vfs.open(
            &storage.context(&root),
            &root,
            path.as_bytes(),
            &OpenHow {
                flags: OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY,
                mode: 0,
                lookup: LookupFlags::follow(),
            },
        ))
        .unwrap()
    }
    fn roundtrip() {
        let directory = Directory::new();
        futures::executor::block_on(async {
            directory
                .write_text("nested/file", "content")
                .await
                .unwrap();
            let file = directory
                .open(
                    &path("nested/file"),
                    FileOpenOptions {
                        read: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            directory
                .rename(&path("nested"), &path("renamed"))
                .await
                .unwrap();
            directory
                .remove(&path("renamed/file"), false)
                .await
                .unwrap();
            assert_eq!(file.read_at(0, 64).await.unwrap().as_ref(), b"content");
            assert_eq!(
                file.write_positioned_at(0, Bytes::from_static(b"C"))
                    .await
                    .unwrap(),
                1
            );
            file.set_len(3).await.unwrap();
            file.set_times(Some(10), Some(20)).await.unwrap();
            let stat = file.metadata().await.unwrap();
            assert_eq!((stat.len, stat.accessed, stat.modified), (3, 10, 20));
            assert_eq!(file.read_at(0, 64).await.unwrap().as_ref(), b"Con");
            assert_eq!(
                directory.stat(&path("renamed/file")).await,
                Err(FsError::NotFound)
            );
            file.close().await.unwrap();
            file.close().await.unwrap();
            assert!(file.read_at(0, 1).await.is_err());
            directory
                .set_times(&path("renamed"), Some(100), Some(200), true)
                .await
                .unwrap();
            directory
                .set_times(&path("renamed"), None, Some(300), false)
                .await
                .unwrap();
            let stat = directory.stat(&path("renamed")).await.unwrap();
            assert_eq!((stat.accessed, stat.modified), (100, 300));
        });
    }
    #[test]
    fn private_memory_runs_inside_an_existing_futures_executor() {
        futures::executor::block_on(async {
            // No nested executor enter occurs in any actual memory operation.
            let directory = Directory::new();
            directory.write_text("file", "nested").await.unwrap();
            assert_eq!(directory.read_text("file").await.unwrap(), "nested");
        });
        roundtrip();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn private_memory_runs_inside_current_thread_tokio() {
        roundtrip();
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn private_memory_runs_inside_multithread_tokio() {
        roundtrip();
    }
    #[tokio::test]
    async fn private_memory_runs_inside_existing_services_callbacks() {
        let services = crate::service::Services::new().unwrap();
        services
            .callback(
                async {
                    roundtrip();
                },
                |()| async {},
            )
            .await
            .unwrap();
        services.close().await.unwrap();
    }

    #[test]
    fn canonical_directory_lock_wakes_memory_work_before_and_after_the_park_gap() {
        for wake_before_park in [true, false] {
            let directory = Directory::new();
            let storage = directory.inner.clone();
            let (held, ready) = mpsc::sync_channel(1);
            let (release, released) = mpsc::sync_channel(1);
            let (done, finished) = mpsc::sync_channel(1);
            let holder = thread::spawn(move || {
                let file = directory_file(&storage, "/");
                let guard = complete(file.write_guard()).unwrap();
                held.send(()).unwrap();
                released.recv().unwrap();
                if !wake_before_park {
                    thread::sleep(Duration::from_millis(25));
                }
                drop(guard);
                let _ = done.send(());
            });
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            PENDING_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    release.send(()).unwrap();
                    if wake_before_park {
                        finished.recv_timeout(Duration::from_secs(2)).unwrap();
                    }
                }))
            });
            // mkdir reaches prepare_create's real parent inode lock. No test
            // filesystem/node/waker substitutes for the canonical pending path.
            futures::executor::block_on(directory.create_dir(&path("created"))).unwrap();
            holder.join().unwrap();
            assert_eq!(
                directory.inner.stat(&path("created")).unwrap().file_type,
                FileType::Directory
            );
            PENDING_HOOK.with(|hook| assert!(hook.borrow().is_none()));
        }
    }
    #[test]
    fn canonical_cross_directory_renames_wait_on_the_same_superblock_lock() {
        let directory = Directory::new();
        futures::executor::block_on(async {
            for name in ["a/one", "b/seed", "c/two", "d/seed"] {
                directory.write_text(name, name).await.unwrap();
            }
        });
        let storage = directory.inner.clone();
        let (held, ready) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let holder = thread::spawn(move || {
            let file = directory_file(&storage, "/a");
            let guard = complete(file.write_guard()).unwrap();
            held.send(()).unwrap();
            released.recv().unwrap();
            drop(guard);
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let launch = |from: &'static str, to: &'static str| {
            let directory = directory.clone();
            let (pending, seen) = mpsc::sync_channel(1);
            let worker = thread::spawn(move || {
                PENDING_HOOK.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        pending.send(()).unwrap();
                    }))
                });
                futures::executor::block_on(directory.rename(&path(from), &path(to)))
            });
            (worker, seen)
        };
        let (first, first_pending) = launch("a/one", "b/one");
        let first_waited = first_pending.recv_timeout(Duration::from_secs(2));
        let (second, second_pending) = launch("c/two", "d/two");
        let second_waited = second_pending.recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        holder.join().unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        assert!(
            first_waited.is_ok() && second_waited.is_ok(),
            "both canonical rename locks must have been contended"
        );
        assert_eq!(
            futures::executor::block_on(directory.read_text("b/one")).unwrap(),
            "a/one"
        );
        assert_eq!(
            futures::executor::block_on(directory.read_text("d/two")).unwrap(),
            "c/two"
        );
    }

    // Preserve the earlier Directory atomic-append proof, now without its
    // VirtualFile append-open flag or post-write seek position.
    #[test]
    fn directory_append_and_positioned_writes_keep_canonical_offsets_under_races() {
        let directory = Directory::new();
        futures::executor::block_on(directory.write_text("append", "seed")).unwrap();
        let options = FileOpenOptions {
            write: true,
            ..Default::default()
        };
        let first = futures::executor::block_on(directory.open(&path("append"), options)).unwrap();
        let second = futures::executor::block_on(directory.open(
            &path("append"),
            FileOpenOptions {
                append: true,
                ..options
            },
        ))
        .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let launch = |file: Arc<dyn File>, byte| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                futures::executor::block_on(async {
                    let mut positions = Vec::new();
                    for _ in 0..100 {
                        positions.push(
                            file.try_atomic_append(Bytes::from(vec![byte]))
                                .await
                                .unwrap()
                                .unwrap(),
                        );
                    }
                    positions
                })
            })
        };
        let a = launch(first, b'a');
        let b = launch(second.clone(), b'b');
        let mut positions = a.join().unwrap();
        positions.extend(b.join().unwrap());
        positions.sort_unstable();
        assert_eq!(
            positions,
            (4..204).map(|offset| (offset, 1)).collect::<Vec<_>>()
        );
        futures::executor::block_on(async {
            // Existing direct append-open writes still append. Canonical
            // positioned writes can override it without any SDK cursor state.
            assert_eq!(
                second.write_at(0, Bytes::from_static(b"z")).await.unwrap(),
                1
            );
            assert_eq!(
                second
                    .write_positioned_at(0, Bytes::from_static(b"S"))
                    .await
                    .unwrap(),
                1
            );
            let bytes = directory.read("append").await.unwrap();
            assert_eq!(bytes.len(), 205);
            assert_eq!(bytes[0], b'S');
            assert_eq!(bytes[204], b'z');
            assert_eq!(bytes.iter().filter(|b| **b == b'a').count(), 100);
            assert_eq!(bytes.iter().filter(|b| **b == b'b').count(), 100);
            let readonly = directory
                .open(
                    &path("append"),
                    FileOpenOptions {
                        read: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                readonly.try_atomic_append(Bytes::from_static(b"no")).await,
                Err(FsError::PermissionDenied)
            );
        });
    }
}
