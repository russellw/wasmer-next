//! Live SDK provider mounts behind the canonical kernel VFS.
use crate::{
    DirectoryEntry, File, FileMetadata, FileOpenOptions, FileSystem, FileType, FsError, MountMode,
    RelativePath,
    provider_runtime::{OpenFile, ProviderRuntime},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    any::Any,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    time::{SystemTime, UNIX_EPOCH},
};
use wasixv2_abi::Errno;
use wasixv2_vfs::{
    Attr, Device, DirEntry, DirSink, FileType as Kind, Filesystem, FsInfo, FsResult as VfsResult,
    Handle, NewKind, NewNode, Node, OpenOptions, RenameMode, SetAttr, StatFs, TimeSet, Timestamp,
};

pub(crate) struct GuestFs {
    inner: Arc<Inner>,
    root: Arc<dyn Node>,
}
struct Inner {
    provider: Arc<dyn FileSystem>,
    runtime: ProviderRuntime,
    mode: MountMode,
    nodes: Mutex<(u64, HashMap<PathBuf, Weak<NodeState>>)>,
    namespace: tokio::sync::Mutex<()>,
}
struct NodeState {
    ino: u64,
    kind: Kind,
    path: Mutex<Option<PathBuf>>,
    metadata: Mutex<FileMetadata>,
    opened: Mutex<Weak<OpenFile>>,
}
#[derive(Clone)]
struct GuestNode {
    inner: Arc<Inner>,
    state: Arc<NodeState>,
}
struct GuestHandle {
    initial_len: u64,
    node: GuestNode,
    file: Option<Arc<OpenFile>>,
    entries: tokio::sync::Mutex<Option<Vec<DirectoryEntry>>>,
}
fn errno(error: FsError) -> Errno {
    match error {
        FsError::NotFound => Errno::ENOENT,
        FsError::AlreadyExists => Errno::EEXIST,
        FsError::PermissionDenied => Errno::EACCES,
        FsError::InvalidInput(_) => Errno::EINVAL,
        FsError::NotDirectory => Errno::ENOTDIR,
        FsError::NotFile => Errno::EISDIR,
        FsError::DirectoryNotEmpty => Errno::ENOTEMPTY,
        FsError::Unsupported => Errno::EOPNOTSUPP,
        FsError::Io(_) => Errno::EIO,
    }
}
fn kind(kind: FileType) -> Kind {
    match kind {
        FileType::File => Kind::Regular,
        FileType::Directory => Kind::Directory,
    }
}
fn timestamp(ns: u64) -> Timestamp {
    Timestamp {
        sec: (ns / 1_000_000_000) as i64,
        nsec: (ns % 1_000_000_000) as u32,
    }
}
fn nanos(time: TimeSet) -> u64 {
    match time {
        TimeSet::At(time) => (time.sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(u64::from(time.nsec)),
        TimeSet::Now => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64,
    }
}
impl GuestFs {
    pub(crate) async fn new(
        provider: Arc<dyn FileSystem>,
        mode: MountMode,
        runtime: ProviderRuntime,
    ) -> VfsResult<Arc<Self>> {
        let root = RelativePath::new("").map_err(errno)?;
        let storage = provider.clone();
        let metadata = runtime
            .call(async move { storage.stat(&root).await })
            .await
            .map_err(errno)?;
        if metadata.file_type != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        let inner = Arc::new(Inner {
            provider,
            runtime,
            mode,
            nodes: Mutex::new((1, HashMap::new())),
            namespace: tokio::sync::Mutex::new(()),
        });
        let root = inner.node(PathBuf::new(), metadata)?;
        Ok(Arc::new(Self { inner, root }))
    }
}
impl Inner {
    fn writable(&self) -> VfsResult<()> {
        if self.mode == MountMode::ReadOnly || !self.provider.capabilities().write {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }
    fn node(self: &Arc<Self>, path: PathBuf, metadata: FileMetadata) -> VfsResult<Arc<dyn Node>> {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.1.retain(|_, node| node.strong_count() != 0);
        // The public provider's open file is the retained data authority. A fresh
        // lookup must not redirect a held file to another open at the same name.
        if let Some(state) = nodes.1.get(&path).and_then(Weak::upgrade)
            && state.kind == kind(metadata.file_type)
            && state.opened.lock().unwrap().upgrade().is_none()
        {
            *state.metadata.lock().unwrap() = metadata;
            return Ok(Arc::new(GuestNode {
                inner: self.clone(),
                state,
            }));
        }
        let ino = nodes.0;
        nodes.0 = ino.checked_add(1).ok_or(Errno::ENOSPC)?;
        let state = Arc::new(NodeState {
            ino,
            kind: kind(metadata.file_type),
            path: Mutex::new(Some(path.clone())),
            metadata: Mutex::new(metadata),
            opened: Mutex::new(Weak::new()),
        });
        nodes.1.insert(path, Arc::downgrade(&state));
        Ok(Arc::new(GuestNode {
            inner: self.clone(),
            state,
        }))
    }
}
#[async_trait(?Send)]
impl Filesystem for GuestFs {
    fn limits_file_size(&self) -> bool {
        true
    }
    fn info(&self) -> FsInfo {
        FsInfo {
            name: "sdk-provider",
            magic: 0x53444b,
            name_max: 255,
            read_only: self.inner.mode == MountMode::ReadOnly
                || !self.inner.provider.capabilities().write,
            dev: None,
            has_btime: true,
            stable: false,
        }
    }
    fn root(&self) -> Arc<dyn Node> {
        self.root.clone()
    }
    async fn statfs(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            block_size: 4096,
            fragment_size: 4096,
            name_max: 255,
            ..StatFs::default()
        })
    }
    async fn sync(&self) -> VfsResult<()> {
        let provider = self.inner.provider.clone();
        self.inner
            .runtime
            .call(async move { provider.flush().await })
            .await
            .map_err(errno)
    }
}
impl GuestNode {
    fn path(&self) -> VfsResult<RelativePath> {
        RelativePath::new(
            self.state
                .path
                .lock()
                .unwrap()
                .as_ref()
                .ok_or(Errno::ENOENT)?,
        )
        .map_err(errno)
    }
    fn child(&self, name: &[u8]) -> VfsResult<RelativePath> {
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(Errno::EINVAL);
        }
        let name = std::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        RelativePath::new(self.path()?.as_path().join(name)).map_err(errno)
    }
    fn attr(&self, metadata: FileMetadata) -> Attr {
        let writable = !metadata.readonly;
        Attr {
            ino: self.state.ino,
            file_type: self.state.kind,
            mode: if writable { 0o777 } else { 0o555 },
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: Device::default(),
            size: metadata.len,
            blocks: metadata.len.div_ceil(512),
            blksize: 4096,
            atime: timestamp(metadata.accessed),
            mtime: timestamp(metadata.modified),
            ctime: timestamp(metadata.modified),
            btime: Some(timestamp(metadata.created)),
            dev: None,
        }
    }
    async fn metadata(&self) -> VfsResult<FileMetadata> {
        let opened = self.state.opened.lock().unwrap().upgrade();
        if let Some(file) = opened {
            match self
                .inner
                .runtime
                .call(async move { file.metadata().await })
                .await
            {
                Ok(metadata) => return Ok(metadata),
                Err(FsError::Unsupported) => return Ok(*self.state.metadata.lock().unwrap()),
                Err(error) => return Err(errno(error)),
            }
        }
        let provider = self.inner.provider.clone();
        let path = self.path()?;
        match self
            .inner
            .runtime
            .call(async move { provider.stat(&path).await })
            .await
        {
            Ok(metadata) => {
                *self.state.metadata.lock().unwrap() = metadata;
                Ok(metadata)
            }
            Err(FsError::NotFound) if self.state.opened.lock().unwrap().upgrade().is_some() => {
                Ok(*self.state.metadata.lock().unwrap())
            }
            Err(error) => Err(errno(error)),
        }
    }
    async fn opened(&self, options: FileOpenOptions) -> VfsResult<Arc<OpenFile>> {
        if options.write || options.truncate || options.append {
            self.inner.writable()?;
        }
        if options.read && !self.inner.provider.capabilities().read {
            return Err(Errno::EACCES);
        }
        let file = self
            .inner
            .runtime
            .open(self.inner.provider.clone(), self.path()?, options)
            .await
            .map_err(errno)?;
        if options.truncate {
            self.state.metadata.lock().unwrap().len = 0;
        }
        *self.state.opened.lock().unwrap() = Arc::downgrade(&file);
        Ok(file)
    }
}
#[async_trait(?Send)]
impl Node for GuestNode {
    fn ino(&self) -> u64 {
        self.state.ino
    }
    fn file_type(&self) -> Kind {
        self.state.kind
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    async fn getattr(&self) -> VfsResult<Attr> {
        Ok(self.attr(self.metadata().await?))
    }
    async fn setattr(&self, attr: &SetAttr) -> VfsResult<Attr> {
        self.inner.writable()?;
        if attr.mode.is_some() || attr.uid.is_some() || attr.gid.is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        if let Some(size) = attr.size {
            let held = self.state.opened.lock().unwrap().upgrade();
            let file = match held {
                Some(file) => file,
                None => {
                    self.opened(FileOpenOptions {
                        write: true,
                        ..Default::default()
                    })
                    .await?
                }
            };
            self.inner
                .runtime
                .call(async move { file.set_len(size).await })
                .await
                .map_err(errno)?;
            self.state.metadata.lock().unwrap().len = size;
        }
        if attr.atime.is_some() || attr.mtime.is_some() {
            let atime = attr.atime.map(nanos);
            let mtime = attr.mtime.map(nanos);
            let held = self.state.opened.lock().unwrap().upgrade();
            if let Some(file) = held {
                self.inner
                    .runtime
                    .call(async move { file.set_times(atime, mtime).await })
                    .await
                    .map_err(errno)?;
            } else {
                let provider = self.inner.provider.clone();
                let path = self.path()?;
                self.inner
                    .runtime
                    .call(async move { provider.set_times(&path, atime, mtime, true).await })
                    .await
                    .map_err(errno)?;
            }
            let mut metadata = self.state.metadata.lock().unwrap();
            if let Some(atime) = atime {
                metadata.accessed = atime;
            }
            if let Some(mtime) = mtime {
                metadata.modified = mtime;
            }
        }
        self.getattr().await
    }
    async fn lookup(&self, name: &[u8]) -> VfsResult<Arc<dyn Node>> {
        let _namespace = self.inner.namespace.lock().await;
        let path = self.child(name)?;
        let provider = self.inner.provider.clone();
        let queried = path.clone();
        let metadata = self
            .inner
            .runtime
            .call(async move { provider.stat(&queried).await })
            .await
            .map_err(errno)?;
        self.inner.node(path.as_path().to_path_buf(), metadata)
    }
    async fn create(&self, name: &[u8], new: &NewNode<'_>) -> VfsResult<Arc<dyn Node>> {
        self.inner.writable()?;
        let _namespace = self.inner.namespace.lock().await;
        let path = self.child(name)?;
        let provider = self.inner.provider.clone();
        let created = path.clone();
        match new.kind {
            NewKind::Directory => self
                .inner
                .runtime
                .call(async move { provider.create_dir(&created).await })
                .await
                .map_err(errno)?,
            NewKind::Regular => {
                drop(
                    self.inner
                        .runtime
                        .open(
                            provider,
                            created,
                            FileOpenOptions {
                                write: true,
                                create_new: true,
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(errno)?,
                );
            }
            _ => return Err(Errno::EOPNOTSUPP),
        }
        let provider = self.inner.provider.clone();
        let queried = path.clone();
        let metadata = self
            .inner
            .runtime
            .call(async move { provider.stat(&queried).await })
            .await
            .map_err(errno)?;
        self.inner.node(path.as_path().to_path_buf(), metadata)
    }
    async fn open(&self, options: OpenOptions) -> VfsResult<Box<dyn Handle>> {
        let initial_len = if options.truncate {
            0
        } else {
            self.metadata().await?.len
        };
        let file = if self.state.kind == Kind::Regular {
            Some(
                self.opened(FileOpenOptions {
                    read: options.read,
                    write: options.write,
                    append: options.append,
                    truncate: options.truncate,
                    ..Default::default()
                })
                .await?,
            )
        } else {
            None
        };
        Ok(Box::new(GuestHandle {
            initial_len,
            node: self.clone(),
            file,
            entries: tokio::sync::Mutex::new(None),
        }))
    }
    async fn unlink(&self, name: &[u8]) -> VfsResult<()> {
        self.remove(name, false).await
    }
    async fn rmdir(&self, name: &[u8]) -> VfsResult<()> {
        self.remove(name, true).await
    }
    async fn rename(
        &self,
        name: &[u8],
        new_dir: &Arc<dyn Node>,
        new_name: &[u8],
        mode: RenameMode,
    ) -> VfsResult<()> {
        self.inner.writable()?;
        if mode != RenameMode::Replace {
            return Err(Errno::EINVAL);
        }
        let target = new_dir
            .as_any()
            .downcast_ref::<Self>()
            .ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&self.inner, &target.inner) {
            return Err(Errno::EXDEV);
        }
        let _namespace = self.inner.namespace.lock().await;
        let from = self.child(name)?;
        let to = target.child(new_name)?;
        let provider = self.inner.provider.clone();
        let source = from.clone();
        let dest = to.clone();
        self.inner
            .runtime
            .call(async move { provider.rename(&source, &dest).await })
            .await
            .map_err(errno)?;
        let mut nodes = self.inner.nodes.lock().unwrap();
        let moved: Vec<_> = nodes
            .1
            .iter()
            .filter_map(|(path, node)| {
                path.strip_prefix(from.as_path())
                    .ok()
                    .map(|tail| (path.clone(), to.as_path().join(tail), node.clone()))
            })
            .collect();
        for (old, new, node) in moved {
            nodes.1.remove(&old);
            if let Some(node) = node.upgrade() {
                *node.path.lock().unwrap() = Some(new.clone());
                nodes.1.insert(new, Arc::downgrade(&node));
            }
        }
        Ok(())
    }
}
impl GuestNode {
    async fn remove(&self, name: &[u8], directory: bool) -> VfsResult<()> {
        self.inner.writable()?;
        let _namespace = self.inner.namespace.lock().await;
        let path = self.child(name)?;
        let provider = self.inner.provider.clone();
        let queried = path.clone();
        let metadata = self
            .inner
            .runtime
            .call(async move { provider.stat(&queried).await })
            .await
            .map_err(errno)?;
        if (metadata.file_type == FileType::Directory) != directory {
            return Err(if directory {
                Errno::ENOTDIR
            } else {
                Errno::EISDIR
            });
        }
        let provider = self.inner.provider.clone();
        let removed = path.clone();
        self.inner
            .runtime
            .call(async move { provider.remove(&removed, false).await })
            .await
            .map_err(errno)?;
        if let Some(node) = self
            .inner
            .nodes
            .lock()
            .unwrap()
            .1
            .remove(path.as_path())
            .and_then(|node| node.upgrade())
        {
            // Held file handles retain their provider File after this name goes away.
            *node.path.lock().unwrap() = None;
        }
        Ok(())
    }
}
#[async_trait(?Send)]
impl Handle for GuestHandle {
    fn initial_position(&self, append: bool) -> u64 {
        if append { self.initial_len } else { 0 }
    }
    async fn append_at_cursor_as(
        &self,
        data: &[u8],
        cursor: u64,
        _cred: &wasixv2_vfs::Cred,
    ) -> VfsResult<wasixv2_vfs::AppendOutcome> {
        self.node.inner.writable()?;
        let file = self.file.clone().ok_or(Errno::EISDIR)?;
        let bytes = Bytes::copy_from_slice(data);
        let outcome = self
            .node
            .inner
            .runtime
            .call(async move {
                match file.try_atomic_append(bytes.clone()).await? {
                    Some((start, count)) => {
                        Ok(wasixv2_vfs::AppendOutcome::Positioned { start, count })
                    }
                    None => file
                        .write_at(cursor, bytes)
                        .await
                        .map(|count| wasixv2_vfs::AppendOutcome::OffsetUnknown { count }),
                }
            })
            .await
            .map_err(errno)?;
        let count = match outcome {
            wasixv2_vfs::AppendOutcome::Positioned { count, .. }
            | wasixv2_vfs::AppendOutcome::OffsetUnknown { count } => count,
        };
        if count > data.len() {
            return Err(Errno::EIO);
        }
        let mut metadata = self.node.state.metadata.lock().unwrap();
        let start = match outcome {
            wasixv2_vfs::AppendOutcome::Positioned { start, .. } => start,
            wasixv2_vfs::AppendOutcome::OffsetUnknown { .. } => cursor,
        };
        metadata.len = metadata.len.max(start.saturating_add(count as u64));
        Ok(outcome)
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let file = self.file.clone().ok_or(Errno::EISDIR)?;
        let length = buf.len();
        let bytes = self
            .node
            .inner
            .runtime
            .call(async move { file.read_at(offset, length).await })
            .await
            .map_err(errno)?;
        if bytes.len() > buf.len() {
            return Err(Errno::EIO);
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    async fn write_at(&self, data: &[u8], offset: u64) -> VfsResult<usize> {
        self.node.inner.writable()?;
        let file = self.file.clone().ok_or(Errno::EISDIR)?;
        let bytes = Bytes::copy_from_slice(data);
        let count = self
            .node
            .inner
            .runtime
            .call(async move { file.write_positioned_at(offset, bytes).await })
            .await
            .map_err(errno)?;
        if count > data.len() {
            return Err(Errno::EIO);
        }
        let mut metadata = self.node.state.metadata.lock().unwrap();
        metadata.len = metadata.len.max(offset.saturating_add(count as u64));
        Ok(count)
    }
    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        let file = self.file.clone();
        let provider = self.node.inner.provider.clone();
        self.node
            .inner
            .runtime
            .call(async move {
                match file {
                    Some(file) => file.flush().await,
                    None => provider.flush().await,
                }
            })
            .await
            .map_err(errno)
    }
    async fn flush(&self, _owner: u64) -> VfsResult<()> {
        self.sync(false).await
    }
    async fn set_size(&self, size: u64) -> VfsResult<()> {
        self.node.inner.writable()?;
        let file = self.file.clone().ok_or(Errno::EISDIR)?;
        self.node
            .inner
            .runtime
            .call(async move { file.set_len(size).await })
            .await
            .map_err(errno)?;
        self.node.state.metadata.lock().unwrap().len = size;
        Ok(())
    }
    async fn readdir(&self, cookie: u64, sink: &mut dyn DirSink) -> VfsResult<()> {
        if self.node.state.kind != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let mut entries = self.entries.lock().await;
        if entries.is_none() {
            let provider = self.node.inner.provider.clone();
            let path = self.node.path()?;
            *entries = Some(
                self.node
                    .inner
                    .runtime
                    .call(async move { provider.read_dir(&path).await })
                    .await
                    .map_err(errno)?,
            );
        }
        let entries = entries.as_ref().unwrap();
        let start = usize::try_from(cookie).map_err(|_| Errno::EINVAL)?;
        for (i, entry) in entries.iter().enumerate().skip(start) {
            let child = self.node.child(entry.name.as_bytes())?;
            let node = self
                .node
                .inner
                .node(child.as_path().to_path_buf(), entry.metadata)?;
            if !sink.push(DirEntry {
                name: entry.name.as_bytes(),
                ino: node.ino(),
                file_type: kind(entry.metadata.file_type),
                next: (i + 1) as u64,
            }) {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replace the removed ProviderAdapter timestamp unit at the actual live
    /// SDK provider/guest boundary; readonly failures must not alter the provider.
    #[tokio::test]
    async fn provider_timestamps_stay_shared_and_readonly_guest_mounts_reject_updates() {
        let services = crate::service::Services::new().unwrap();
        let runtime = ProviderRuntime::new(services.clone());
        let directory = crate::Directory::new();
        directory.write_text("file", "contents").await.unwrap();
        directory
            .create_dir(&RelativePath::new("folder").unwrap())
            .await
            .unwrap();
        let provider: Arc<dyn FileSystem> = Arc::new(directory.clone());
        let writable = GuestFs::new(provider.clone(), MountMode::ReadWrite, runtime.clone())
            .await
            .unwrap();
        let readonly = GuestFs::new(provider, MountMode::ReadOnly, runtime.clone())
            .await
            .unwrap();
        assert!(readonly.info().read_only);
        for name in [b"file".as_slice(), b"folder".as_slice()] {
            let file = writable.root().lookup(name).await.unwrap();
            let protected = readonly.root().lookup(name).await.unwrap();
            file.setattr(&SetAttr {
                atime: Some(TimeSet::At(timestamp(10))),
                mtime: Some(TimeSet::At(timestamp(20))),
                ..Default::default()
            })
            .await
            .unwrap();
            file.setattr(&SetAttr {
                mtime: Some(TimeSet::At(timestamp(30))),
                ..Default::default()
            })
            .await
            .unwrap();
            let attr = protected.getattr().await.unwrap();
            assert_eq!(attr.atime, timestamp(10));
            assert_eq!(attr.mtime, timestamp(30));
            assert!(matches!(
                protected
                    .setattr(&SetAttr {
                        mtime: Some(TimeSet::At(timestamp(0))),
                        ..Default::default()
                    })
                    .await,
                Err(Errno::EROFS)
            ));
            assert_eq!(protected.getattr().await.unwrap().mtime, timestamp(30));
        }
        runtime.close().await.unwrap();
        services.close().await.unwrap();
    }
}
