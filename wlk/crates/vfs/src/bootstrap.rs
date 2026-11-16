//! Trusted startup of a private namespace from already owned directory capabilities.

use std::{
    any::Any,
    collections::BTreeMap,
    sync::{Arc, OnceLock, Weak},
};

use async_trait::async_trait;

use crate::{
    Attr, Dentry, DirEntry, DirSink, Errno, File, FileType, Filesystem, FsInfo, FsResult, Handle,
    MntNs, NamespaceComponent, Node, OpenOptions, Path, PathError, PathResult, Propagation,
    SetAttr, StatFs, Timestamp, UserNs, Vfs,
};

pub struct NamespaceDirectory {
    /// The File retains its source namespace until the private copy has committed.
    pub source: File,
    pub lookup_name: Option<Vec<u8>>,
}

pub struct BootstrapNamespace {
    pub namespace: Arc<MntNs>,
    pub root: Path,
    pub directories: Vec<Path>,
}

impl Vfs {
    pub fn bootstrap_namespace(
        self: &Arc<Self>,
        source_namespace: &MntNs,
        owner: Arc<dyn UserNs>,
        directories: &[NamespaceDirectory],
        root_fallback: Option<usize>,
    ) -> FsResult<BootstrapNamespace> {
        if root_fallback.is_some_and(|index| index >= directories.len()) {
            return Err(Errno::EINVAL);
        }
        let mut visible = BTreeMap::new();
        let mut anchors = Vec::with_capacity(directories.len());
        for (index, directory) in directories.iter().enumerate() {
            if !directory.source.belongs_to(self)
                || directory.source.file_type() != FileType::Directory
            {
                return Err(Errno::EINVAL);
            }
            let node = Arc::new(Directory::new(index as u64 + 2, None));
            if let Some(name) = &directory.lookup_name {
                if name.is_empty()
                    || name == b"."
                    || name == b".."
                    || name.iter().any(|byte| *byte == b'/' || *byte == 0)
                {
                    return Err(Errno::EINVAL);
                }
                if visible.insert(name.clone(), node.clone()).is_some() {
                    return Err(Errno::EEXIST);
                }
            }
            anchors.push(node);
        }
        let root_node = Arc::new(Directory::new(1, Some(visible)));
        let fs = Arc::new(BootstrapFs {
            root: root_node.clone(),
        });
        let mount = self.kern_mount_owned(fs, owner.clone());
        let root = mount.root_path();
        let namespace = {
            let mut state = self.tree.lock();
            let namespace = MntNs::new(&self.tree, &mut state, mount.clone(), None, owner);
            state.add_link(&mount, namespace.id());
            namespace
        };
        let mut paths = Vec::with_capacity(directories.len());
        for (index, directory) in directories.iter().enumerate() {
            let anchor = Path {
                mnt: mount.clone(),
                dentry: match &directory.lookup_name {
                    Some(name) => root.dentry.child(name, anchors[index].clone()),
                    None => root.dentry.private_child(anchors[index].clone()),
                },
            };
            let copied = {
                let mut state = self.tree.lock();
                let copied = self.copy_for_loopback(
                    &mut state,
                    source_namespace,
                    &directory.source.path,
                    true,
                )?;
                for child in state.subtree(&copied) {
                    state.change_propagation(child.id, Propagation::Private);
                }
                if let Err(errno) = self.graft_tree(&mut state, &copied, &anchor) {
                    let gone = state.umount_tree(&copied, false);
                    drop(state);
                    drop(gone);
                    return Err(errno);
                }
                copied
            };
            if root_fallback == Some(index) {
                root_node
                    .fallback
                    .set(Arc::downgrade(&anchor.dentry))
                    .expect("one root fallback");
            }
            paths.push(copied.root_path());
        }
        Ok(BootstrapNamespace {
            namespace,
            root,
            directories: paths,
        })
    }
}

struct BootstrapFs {
    root: Arc<Directory>,
}

#[async_trait(?Send)]
impl Filesystem for BootstrapFs {
    fn info(&self) -> FsInfo {
        FsInfo {
            name: "namespace",
            magic: 0x6e73_6673,
            name_max: self
                .root
                .visible
                .as_ref()
                .unwrap()
                .keys()
                .map(Vec::len)
                .max()
                .unwrap_or(crate::NAME_MAX)
                .max(crate::NAME_MAX),
            read_only: false,
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
            block_size: 4096,
            name_max: self.info().name_max as u32,
            fragment_size: 4096,
            ..StatFs::default()
        })
    }
}

struct Directory {
    ino: u64,
    visible: Option<BTreeMap<Vec<u8>, Arc<Directory>>>,
    fallback: OnceLock<Weak<Dentry>>,
}

impl Directory {
    fn new(ino: u64, visible: Option<BTreeMap<Vec<u8>, Arc<Directory>>>) -> Self {
        Self {
            ino,
            visible,
            fallback: OnceLock::new(),
        }
    }
}

#[async_trait(?Send)]
impl Node for Directory {
    fn ino(&self) -> u64 {
        self.ino
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn namespace_component(&self, name: &[u8]) -> NamespaceComponent {
        match &self.visible {
            None => NamespaceComponent::Ordinary,
            Some(visible) if visible.contains_key(name) => NamespaceComponent::Ordinary,
            Some(_) => match self.namespace_root_fallback() {
                Some(path) => NamespaceComponent::Fallback(path),
                None => NamespaceComponent::Boundary,
            },
        }
    }

    fn namespace_root_fallback(&self) -> Option<Arc<Dentry>> {
        self.fallback.get()?.upgrade()
    }

    fn namespace_mutation(&self) -> PathResult<()> {
        if self.visible.is_some() {
            Err(PathError::NamespaceMutation)
        } else {
            Ok(())
        }
    }

    async fn getattr(&self) -> FsResult<Attr> {
        Ok(Attr {
            ino: self.ino,
            file_type: FileType::Directory,
            mode: 0o777,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: Default::default(),
            size: 0,
            blocks: 0,
            blksize: 4096,
            atime: Timestamp::new(0, 0),
            mtime: Timestamp::new(0, 0),
            ctime: Timestamp::new(0, 0),
            btime: None,
            dev: None,
        })
    }

    async fn setattr(&self, _: &SetAttr) -> FsResult<Attr> {
        Err(Errno::EPERM)
    }

    async fn lookup(&self, name: &[u8]) -> FsResult<Arc<dyn Node>> {
        self.visible
            .as_ref()
            .and_then(|visible| visible.get(name))
            .map(|node| node.clone() as Arc<dyn Node>)
            .ok_or(Errno::ENOENT)
    }

    async fn open(&self, _: OpenOptions) -> FsResult<Box<dyn Handle>> {
        Ok(Box::new(DirectoryHandle(
            self.visible
                .as_ref()
                .map(|visible| {
                    visible
                        .iter()
                        .map(|(name, node)| (name.clone(), node.ino))
                        .collect()
                })
                .unwrap_or_default(),
        )))
    }
}

struct DirectoryHandle(Vec<(Vec<u8>, u64)>);

#[async_trait(?Send)]
impl Handle for DirectoryHandle {
    async fn readdir(&self, cookie: u64, sink: &mut dyn DirSink) -> FsResult<()> {
        for (index, (name, ino)) in self
            .0
            .iter()
            .enumerate()
            .skip(cookie.min(usize::MAX as u64) as usize)
        {
            if !sink.push(DirEntry {
                name,
                ino: *ino,
                file_type: FileType::Directory,
                next: index as u64 + 1,
            }) {
                break;
            }
        }
        Ok(())
    }
}
