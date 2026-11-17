//! Presents a lower filesystem below a chain of synthetic directories.

use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use wasixv2_abi::Errno;
use wasixv2_vfs::{
    Attr, Ctx, DirEntry, DirSink, FileKattr, FileType, Filesystem, FsInfo, FsResult, Handle, Link,
    LookupEntry, NAME_MAX, Node, OpenOptions, PATH_MAX, SetAttr, StatFs,
};

/// A filesystem under a relative prefix of synthetic root-owned directories.
pub struct PrefixFs {
    fs: Arc<dyn Filesystem>,
    root: Arc<dyn Node>,
    depth: usize,
}

impl PrefixFs {
    /// Presents `fs` read-only at `prefix`. The prefix is relative and normalized.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(prefix: &[u8], fs: Arc<dyn Filesystem>) -> FsResult<Arc<dyn Filesystem>> {
        if prefix.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let parts: Vec<_> = if prefix.is_empty() {
            Vec::new()
        } else {
            prefix.split(|&b| b == b'/').collect()
        };
        for part in &parts {
            if matches!(*part, b"" | b"." | b"..") || part.contains(&0) {
                return Err(Errno::EINVAL);
            }
            if part.len() > NAME_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
        }
        let depth = parts.len();
        let numbers = Arc::new(Numbers {
            depth: depth as u64,
            large: Mutex::default(),
        });
        let mut root: Arc<dyn Node> = Arc::new(Prefixed {
            node: fs.root(),
            numbers,
        });
        if root.file_type() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        if parts.is_empty() && fs.info().read_only {
            return Ok(fs);
        }
        for (i, part) in parts.into_iter().enumerate().rev() {
            root = Arc::new(Parent {
                ino: i as u64 + 1,
                name: Arc::from(part),
                child: root,
            });
        }
        Ok(Arc::new(Self { fs, root, depth }))
    }
}

#[async_trait(?Send)]
impl Filesystem for PrefixFs {
    fn info(&self) -> FsInfo {
        let mut info = self.fs.info();
        info.read_only = true;
        info.name_max = info.name_max.max(NAME_MAX);
        info
    }

    fn root(&self) -> Arc<dyn Node> {
        self.root.clone()
    }

    fn noexec(&self) -> bool {
        self.fs.noexec()
    }

    async fn statfs(&self) -> FsResult<StatFs> {
        let mut stat = self.fs.statfs().await?;
        stat.files = stat.files.saturating_add(self.depth as u64);
        stat.name_max = stat.name_max.max(NAME_MAX as u32);
        Ok(stat)
    }
}

struct Parent {
    ino: u64,
    name: Arc<[u8]>,
    child: Arc<dyn Node>,
}

#[async_trait(?Send)]
impl Node for Parent {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn file_type(&self) -> FileType {
        FileType::Directory
    }

    async fn getattr(&self) -> FsResult<Attr> {
        Ok(Attr {
            ino: self.ino,
            file_type: FileType::Directory,
            mode: 0o755,
            nlink: 3,
            uid: 0,
            gid: 0,
            rdev: Default::default(),
            size: 4096,
            blocks: 8,
            blksize: 4096,
            atime: Default::default(),
            mtime: Default::default(),
            ctime: Default::default(),
            btime: None,
            dev: None,
        })
    }

    async fn setattr(&self, _: &SetAttr) -> FsResult<Attr> {
        Err(Errno::EROFS)
    }

    async fn lookup(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        if name == &*self.name {
            Ok(self.child.clone())
        } else {
            Err(Errno::ENOENT)
        }
    }

    async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
        if options.write {
            return Err(Errno::EROFS);
        }
        Ok(Box::new(ParentHandle {
            name: self.name.clone(),
            ino: self.child.ino(),
        }))
    }
}

struct ParentHandle {
    ino: u64,
    name: Arc<[u8]>,
}

#[async_trait(?Send)]
impl Handle for ParentHandle {
    async fn readdir(&self, cookie: u64, sink: &mut dyn DirSink) -> FsResult<()> {
        if cookie == 0 {
            sink.push(DirEntry {
                name: &self.name,
                ino: self.ino,
                file_type: FileType::Directory,
                next: 1,
            });
        }
        Ok(())
    }
}

/// Inode numbers of synthetic parents and the lower filesystem share one namespace.
struct Numbers {
    depth: u64,
    large: Mutex<HashMap<u64, u64>>,
}

impl Numbers {
    fn ino(&self, ino: u64) -> u64 {
        const LARGE: u64 = 1 << 63;
        if ino < LARGE - self.depth - 1 {
            return ino + self.depth + 1;
        }
        let mut large = self.large.lock().unwrap();
        let next = LARGE + large.len() as u64;
        *large.entry(ino).or_insert(next)
    }
}

struct Prefixed {
    node: Arc<dyn Node>,
    numbers: Arc<Numbers>,
}

impl Prefixed {
    fn wrap(&self, node: Arc<dyn Node>) -> Arc<dyn Node> {
        Arc::new(Self {
            node,
            numbers: self.numbers.clone(),
        })
    }
}

#[async_trait(?Send)]
impl Node for Prefixed {
    fn ino(&self) -> u64 {
        self.numbers.ino(self.node.ino())
    }

    fn file_type(&self) -> FileType {
        self.node.file_type()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn inode_flags(&self) -> u32 {
        self.node.inode_flags()
    }

    async fn fileattr_get(&self) -> FsResult<FileKattr> {
        self.node.fileattr_get().await
    }

    async fn getattr(&self) -> FsResult<Attr> {
        let mut attr = self.node.getattr().await?;
        attr.ino = self.ino();
        Ok(attr)
    }

    async fn setattr(&self, _: &SetAttr) -> FsResult<Attr> {
        Err(Errno::EROFS)
    }

    async fn lookup(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        self.node.lookup(name).await.map(|node| self.wrap(node))
    }

    async fn lookup_entry(&self, name: &[u8]) -> FsResult<LookupEntry> {
        Ok(match self.node.lookup_entry(name).await? {
            LookupEntry::Pinned(node) => LookupEntry::Pinned(self.wrap(node)),
            LookupEntry::Observation(mut observed) => {
                observed.attr.ino = self.numbers.ino(observed.attr.ino);
                LookupEntry::Observation(observed)
            }
        })
    }

    async fn readlink(&self) -> FsResult<Vec<u8>> {
        self.node.readlink().await
    }

    async fn get_link(&self, cx: &Ctx<'_>) -> FsResult<Link> {
        self.node.get_link(cx).await
    }

    async fn getxattr(&self, name: &[u8]) -> FsResult<Vec<u8>> {
        self.node.getxattr(name).await
    }

    async fn listxattr(&self) -> FsResult<Vec<Vec<u8>>> {
        self.node.listxattr().await
    }

    async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
        if options.write {
            return Err(Errno::EROFS);
        }
        let handle = self.node.open(options).await?;
        Ok(if self.node.file_type() == FileType::Directory {
            Box::new(PrefixedDirectory {
                handle,
                numbers: self.numbers.clone(),
            })
        } else {
            handle
        })
    }
}

struct PrefixedDirectory {
    handle: Box<dyn Handle>,
    numbers: Arc<Numbers>,
}

#[async_trait(?Send)]
impl Handle for PrefixedDirectory {
    async fn readdir(&self, cookie: u64, sink: &mut dyn DirSink) -> FsResult<()> {
        struct Remap<'a>(&'a Numbers, &'a mut dyn DirSink);

        impl DirSink for Remap<'_> {
            fn push(&mut self, mut entry: DirEntry<'_>) -> bool {
                if entry.ino != 0 {
                    entry.ino = self.0.ino(entry.ino);
                }
                self.1.push(entry)
            }

            fn push_type(&mut self, mut entry: DirEntry<'_>, dtype: u8) -> bool {
                if entry.ino != 0 {
                    entry.ino = self.0.ino(entry.ino);
                }
                self.1.push_type(entry, dtype)
            }
        }

        self.handle
            .readdir(cookie, &mut Remap(&self.numbers, sink))
            .await
    }
}
