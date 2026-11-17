//! Stable, read-only inodes for virtual commands and their parent directories.

use std::{any::Any, collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use wasixv2_abi::Errno;
use wasixv2_vfs::{
    Attr, CommandMark, DirEntry, DirSink, FileType, Filesystem, FsInfo, FsResult, Handle, NAME_MAX,
    NewNode, Node, OpenOptions, RenameMode, SetAttr, StatFs,
};

use super::Entry;

const MAGIC: u32 = 0x636d_6466;
const BLOCK: u32 = 4096;

pub(super) struct CommandFs {
    root: Arc<CommandNode>,
    inodes: u64,
}

impl CommandFs {
    pub(super) fn new() -> Self {
        Self {
            root: Arc::new(CommandNode::directory(1)),
            inodes: 1,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.inodes == 1
    }

    pub(super) fn insert(&mut self, parts: &[&[u8]], entry: Arc<Entry>) -> FsResult<()> {
        let (name, parents) = parts.split_last().expect("validated nonempty path");
        let mut parent = Arc::get_mut(&mut self.root).expect("filesystem under construction");
        for &part in parents {
            let child = parent
                .children_mut()?
                .entry(part.to_vec())
                .or_insert_with(|| {
                    self.inodes += 1;
                    Arc::new(CommandNode::directory(self.inodes))
                });
            parent = Arc::get_mut(child).expect("filesystem under construction");
        }
        let children = parent.children_mut()?;
        if children.contains_key(*name) {
            return Err(Errno::EEXIST);
        }
        self.inodes += 1;
        children.insert(
            name.to_vec(),
            Arc::new(CommandNode {
                ino: self.inodes,
                kind: Kind::Command(entry),
            }),
        );
        Ok(())
    }
}

#[async_trait(?Send)]
impl Filesystem for CommandFs {
    fn info(&self) -> FsInfo {
        FsInfo {
            name: "command",
            magic: MAGIC,
            name_max: NAME_MAX,
            read_only: true,
            dev: None,
            has_btime: false,
            stable: true,
        }
    }

    fn root(&self) -> Arc<dyn Node> {
        self.root.clone()
    }

    async fn statfs(&self) -> FsResult<StatFs> {
        Ok(StatFs {
            block_size: BLOCK,
            fragment_size: BLOCK,
            files: self.inodes,
            name_max: NAME_MAX as u32,
            ..StatFs::default()
        })
    }
}

type Children = BTreeMap<Vec<u8>, Arc<CommandNode>>;

enum Kind {
    Directory(Arc<Children>),
    Command(Arc<Entry>),
}

struct CommandNode {
    ino: u64,
    kind: Kind,
}

impl CommandNode {
    fn directory(ino: u64) -> Self {
        Self {
            ino,
            kind: Kind::Directory(Arc::default()),
        }
    }

    fn children_mut(&mut self) -> FsResult<&mut Children> {
        match &mut self.kind {
            Kind::Directory(children) => {
                Ok(Arc::get_mut(children).expect("filesystem under construction"))
            }
            Kind::Command(_) => Err(Errno::ENOTDIR),
        }
    }
}

#[async_trait(?Send)]
impl Node for CommandNode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn file_type(&self) -> FileType {
        match self.kind {
            Kind::Directory(_) => FileType::Directory,
            Kind::Command(_) => FileType::Regular,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn getattr(&self) -> FsResult<Attr> {
        let (mode, uid, gid, nlink) = match &self.kind {
            Kind::Directory(children) => (
                0o755,
                0,
                0,
                2 + children
                    .values()
                    .filter(|node| node.file_type() == FileType::Directory)
                    .count() as u32,
            ),
            Kind::Command(entry) => (entry.spec.mode, entry.spec.uid, entry.spec.gid, 1),
        };
        Ok(Attr {
            ino: self.ino,
            file_type: self.file_type(),
            mode,
            uid,
            gid,
            nlink,
            size: 0,
            blocks: 0,
            blksize: BLOCK,
            rdev: Default::default(),
            atime: Default::default(),
            mtime: Default::default(),
            ctime: Default::default(),
            btime: None,
            dev: None,
        })
    }

    async fn lookup(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        let Kind::Directory(children) = &self.kind else {
            return Err(Errno::ENOTDIR);
        };
        children
            .get(name)
            .map(|entry| entry.clone() as Arc<dyn Node>)
            .ok_or(Errno::ENOENT)
    }

    async fn open(&self, options: OpenOptions) -> FsResult<Box<dyn Handle>> {
        if options.write {
            return Err(Errno::EROFS);
        }
        Ok(match &self.kind {
            Kind::Directory(children) => Box::new(Directory(children.clone())),
            Kind::Command(entry) => Box::new(CommandHandle(entry.clone())),
        })
    }

    async fn setattr(&self, _: &SetAttr) -> FsResult<Attr> {
        Err(Errno::EROFS)
    }

    async fn create(&self, _: &[u8], _: &NewNode<'_>) -> FsResult<Arc<dyn Node>> {
        Err(Errno::EROFS)
    }

    async fn link(&self, _: &[u8], _: &Arc<dyn Node>) -> FsResult<()> {
        Err(Errno::EROFS)
    }

    async fn unlink(&self, _: &[u8]) -> FsResult<()> {
        Err(Errno::EROFS)
    }

    async fn rmdir(&self, _: &[u8]) -> FsResult<()> {
        Err(Errno::EROFS)
    }

    async fn rename(&self, _: &[u8], _: &Arc<dyn Node>, _: &[u8], _: RenameMode) -> FsResult<()> {
        Err(Errno::EROFS)
    }
}

struct Directory(Arc<Children>);

#[async_trait(?Send)]
impl Handle for Directory {
    async fn readdir(&self, cookie: u64, sink: &mut dyn DirSink) -> FsResult<()> {
        for (index, (name, node)) in self.0.iter().enumerate().skip(cookie as usize) {
            if !sink.push(DirEntry {
                name,
                ino: node.ino(),
                file_type: node.file_type(),
                next: index as u64 + 1,
            }) {
                break;
            }
        }
        Ok(())
    }
}

struct CommandHandle(Arc<Entry>);

#[async_trait(?Send)]
impl Handle for CommandHandle {
    async fn read_at(&self, _: &mut [u8], _: u64) -> FsResult<usize> {
        Ok(0)
    }

    async fn virtual_command(&self) -> Option<CommandMark> {
        Some(CommandMark(self.0.clone()))
    }
}
