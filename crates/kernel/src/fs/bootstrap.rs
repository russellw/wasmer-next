//! Trusted process creation with a private filesystem namespace and preinstalled files.

use std::sync::Arc;

use wasixv2_abi::OpenFlags;
use wasixv2_syscalls::{DescriptorAttachment, DescriptorSet, Errno, Fd, TaskId};
use wasixv2_vfs::{Ctx, File, LookupFlags, NamespaceDirectory, OpenHow};

use crate::{
    Kernel, ProcessConfig,
    file::{Backing, OpenFile},
    fs::FsContext,
    ns::NsProxy,
};

pub struct DirectoryBootstrap {
    pub source: File,
    pub lookup_name: Option<Vec<u8>>,
    pub attachment: Option<DescriptorAttachment>,
}

pub struct NamespaceBootstrap {
    pub directories: Vec<DirectoryBootstrap>,
    pub root_attachment: Option<DescriptorAttachment>,
    pub root_fallback: Option<usize>,
}

pub struct BootstrappedProcess {
    pub task: TaskId,
    /// The virtual root, then the directory grants in input order.
    pub descriptors: Vec<Fd>,
    /// Exact slot/file/attachment identity captured before task publication.
    pub binding: DescriptorSet,
}

pub(crate) struct PreparedNamespace {
    pub(crate) fs: FsContext,
    pub(crate) ns: Arc<NsProxy>,
    pub(crate) descriptors: Vec<Fd>,
}

impl Kernel {
    pub async fn spawn_with_namespace(
        &self,
        config: ProcessConfig,
        namespace: NamespaceBootstrap,
    ) -> Result<BootstrappedProcess, Errno> {
        let NamespaceBootstrap {
            directories,
            root_attachment,
            root_fallback,
        } = namespace;
        let (sources, attachments): (Vec<_>, Vec<_>) = directories
            .into_iter()
            .map(|directory| {
                (
                    NamespaceDirectory {
                        source: directory.source,
                        lookup_name: directory.lookup_name,
                    },
                    directory.attachment,
                )
            })
            .unzip();
        let namespace = self.vfs.bootstrap_namespace(
            &self.init_ns.mnt.tree,
            self.init_user_ns.clone(),
            &sources,
            root_fallback,
        )?;
        let ns = NsProxy::bootstrap_mount(self, namespace.namespace)?;
        let cred = crate::cred::Cred::new(&self.credentials, self.init_user_ns.clone());
        let fs_cred = cred.fs();
        let cx = Ctx {
            cred: &fs_cred,
            root: &namespace.root,
            umask: 0o022,
            task: 0,
            leases: None,
        };
        let mut files = self.fd_table();
        for file in crate::stdio::open_files(config.stdio, &self.pseudo, cred.fs_owner()) {
            files.install(Arc::new(file), false).ok_or(Errno::EMFILE)?;
        }
        let flags = OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY;
        let how = OpenHow {
            flags,
            mode: 0,
            lookup: LookupFlags {
                empty: true,
                directory: true,
                ..LookupFlags::default()
            },
        };
        let mut descriptors = Vec::with_capacity(sources.len() + 1);
        let paths = std::iter::once(namespace.root.clone()).chain(namespace.directories);
        let attachments = std::iter::once(root_attachment).chain(attachments);
        for (path, attachment) in paths.zip(attachments) {
            let file = self
                .vfs
                .open(&cx, &path, b"", &how)
                .await
                .map_err(|error| error.errno())?;
            let file = Arc::new(OpenFile::new(Backing::Inode(file), flags));
            descriptors.push(
                files
                    .install_from_attached(3, file, false, attachment)
                    .ok_or(Errno::EMFILE)?,
            );
        }
        let prepared = PreparedNamespace {
            fs: FsContext::new(namespace.root),
            ns,
            descriptors: descriptors.clone(),
        };
        let parent = self.init.map_or(0, |init| init.0);
        let (task, binding) = self.new_process_as_prepared(
            &self.credentials,
            config.args,
            config.env,
            files,
            parent,
            false,
            Some(prepared),
        )?;
        Ok(BootstrappedProcess {
            task,
            descriptors,
            binding: binding.expect("bootstrap binding"),
        })
    }
}
