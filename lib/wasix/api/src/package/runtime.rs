//! Opt-in package acquisition from the guest's `wasmer run` command.

use std::{collections::HashSet, fmt::Write, io, sync::Arc};

use futures_util::lock::Mutex;
use wasixv2_vfs::{Cred, Ctx, LookupFlags, MountFlags, Path, PathError, RenameMode, Vfs};

use super::{VolumeView, resolved::VolumeLayers, wasmer_command::RuntimePackage};
use crate::{
    COMMAND_DIRS, Errno, Filesystem, Host, HostClock, MAX_LOWERS, Machine, MemFs, MemoryConfig,
    OverlayFs, ResolvedLayout, commands_layer, errno_to_io,
};

const PREFIX: &str = "/run/wasmer/packages";

/// Locations in the Machine's initial mount namespace.
#[derive(Debug, Clone)]
pub struct InstalledRuntimePackage {
    pub root: String,
    pub executable: String,
}

impl Machine {
    /// Publishes a resolved package into a running machine. Requires an opt-in resolver.
    /// Repeated installs of the same identity reuse the existing subtree and its changes.
    pub async fn install_runtime_package(
        &self,
        package: &RuntimePackage,
    ) -> io::Result<InstalledRuntimePackage> {
        let packages = self
            .runtime_packages
            .as_ref()
            .ok_or_else(|| errno_to_io(Errno::EOPNOTSUPP))?;
        self.in_use
            .store(true, std::sync::atomic::Ordering::Relaxed);
        packages.install(self.vfs(), package, true).await
    }
}

pub(crate) struct RuntimePackages {
    limit: usize,
    owner: (u32, u32),
    memory: MemoryConfig,
    host: Arc<dyn Host>,
    state: Mutex<InstallState>,
    #[cfg(feature = "wasix1")]
    defaults: Arc<std::sync::RwLock<wasixv2_wasix1::Commands>>,
}

#[derive(Default)]
struct InstallState {
    prefix: Option<Path>,
    alias_dirs: [Option<Path>; COMMAND_DIRS.len()],
    installed: HashSet<[u8; 32]>,
}

impl RuntimePackages {
    pub(crate) fn new(
        limit: usize,
        memory: &MemoryConfig,
        host: &Arc<dyn Host>,
        owner: (u32, u32),
        #[cfg(feature = "wasix1")] defaults: Arc<std::sync::RwLock<wasixv2_wasix1::Commands>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            limit,
            owner,
            memory: memory.clone(),
            host: host.clone(),
            state: Mutex::default(),
            #[cfg(feature = "wasix1")]
            defaults,
        })
    }

    async fn prepare_locked(&self, vfs: &Arc<Vfs>, state: &mut InstallState) -> io::Result<()> {
        if state.prefix.is_some() {
            return Ok(());
        }

        let root = vfs.root();
        let cred = Cred::root();
        let cx = context(&cred, &root);
        let mut parent = root.clone();
        for component in [b"run".as_slice(), b"wasmer", b"packages"] {
            mkdir(vfs, &cx, &parent, component).await?;
            parent = vfs
                .lookup(&cx, &parent, component, confined(true))
                .await
                .map_err(path_io)?;
            if !Arc::ptr_eq(&parent.mnt, &root.mnt) {
                return Err(errno_to_io(Errno::EBUSY));
            }
        }
        let fs = self.upper((0, 0))?;
        let prefix = vfs.create_mount(
            fs,
            PREFIX.as_bytes().to_vec(),
            package_flags(),
            false,
            vfs.namespace().owner().clone(),
        );
        vfs.move_mount(vfs.namespace(), &prefix.path, &parent, false)
            .map_err(errno_to_io)?;
        state.prefix = Some(prefix.path.clone());
        Ok(())
    }

    fn upper(&self, (uid, gid): (u32, u32)) -> io::Result<Arc<dyn Filesystem>> {
        let clock = Arc::new(HostClock(self.host.clone()));
        let upper = self
            .memory
            .apply(MemFs::new(clock, 0o755, uid, gid))
            .map_err(errno_to_io)?;
        Ok(Arc::new(upper))
    }

    pub(super) async fn install(
        &self,
        vfs: &Arc<Vfs>,
        package: &RuntimePackage,
        aliases: bool,
    ) -> io::Result<InstalledRuntimePackage> {
        if !package
            .layout
            .commands
            .iter()
            .any(|(name, _)| *name == package.entrypoint)
        {
            return Err(errno_to_io(Errno::ENOEXEC));
        }
        let key = layout_key(&package.identity);
        let installed = installed_paths(&key, &package.entrypoint);
        let mut state = self.state.lock().await;
        if state.installed.contains(&package.identity) {
            if aliases {
                let cred = Cred::root();
                let top = vfs.root();
                self.publish_aliases(
                    vfs,
                    &context(&cred, &top),
                    &mut state,
                    &installed.root,
                    &package.layout,
                )
                .await;
            }
            return Ok(installed);
        }
        if state.installed.len() >= self.limit {
            return Err(errno_to_io(Errno::ENOSPC));
        }
        self.prepare_locked(vfs, &mut state).await?;

        let mut layers = VolumeLayers::default();
        let mut lowers = Vec::new();
        let mut mounts = Vec::new();
        for volume in &package.layout.volumes {
            let layer = layers
                .get_inner(self.owner, volume)
                .await
                .map_err(|err| volume.context(err))?;
            let path = relative_mapping(&volume.mount_path)?;
            if path.is_empty() {
                lowers.push(layer.0);
            } else {
                mounts.push((path, layer.0));
            }
        }
        if let Some(commands) = commands_layer(self.owner, package.layout.commands.clone())? {
            lowers.push(commands.0);
        }
        if lowers.len() > MAX_LOWERS {
            return Err(errno_to_io(Errno::E2BIG));
        }
        lowers.reverse();
        let fs = OverlayFs::new(Some(self.upper(self.owner)?), lowers);
        let tree = vfs.create_mount(
            fs,
            installed.root.as_bytes().to_vec(),
            package_flags(),
            false,
            vfs.namespace().owner().clone(),
        );
        for (relative, lower) in mounts {
            let fs = OverlayFs::new(Some(self.upper(self.owner)?), vec![lower]);
            vfs.mount_detached(&tree, relative.as_bytes(), fs, package_flags())
                .await
                .map_err(errno_to_io)?;
        }
        let cred = Cred::root();
        let staged_root = &tree.path;
        let staged = context(&cred, staged_root);
        // A volume at bin can hide the command layer. Reject a hidden or substituted entrypoint.
        let path = format!("bin/{}", package.entrypoint);
        let target = vfs
            .lookup(&staged, staged_root, path.as_bytes(), confined(false))
            .await
            .map_err(path_io)?;
        if !Arc::ptr_eq(&target.mnt, &staged_root.mnt)
            || target.dentry.file_type() != wasixv2_vfs::FileType::Regular
        {
            return Err(errno_to_io(Errno::ENOEXEC));
        }

        let prefix = state.prefix.as_ref().unwrap();
        let top = vfs.root();
        let cx = context(&cred, &top);
        mkdir(vfs, &cx, prefix, key.as_bytes()).await?;
        let target = vfs
            .lookup(&cx, prefix, key.as_bytes(), confined(true))
            .await
            .map_err(path_io)?;
        if !Arc::ptr_eq(&target.mnt, &prefix.mnt) {
            return Err(errno_to_io(Errno::EBUSY));
        }
        if let Err(error) = vfs.move_mount(vfs.namespace(), staged_root, &target, false) {
            let _ = vfs.rmdir(&cx, prefix, key.as_bytes()).await;
            return Err(errno_to_io(error));
        }

        state.installed.insert(package.identity);
        if aliases {
            self.publish_aliases(vfs, &cx, &mut state, &installed.root, &package.layout)
                .await;
        }
        Ok(installed)
    }

    async fn alias_directory(
        &self,
        vfs: &Arc<Vfs>,
        cx: &Ctx<'_>,
        dir: &str,
        cached: &mut Option<Path>,
    ) -> io::Result<Path> {
        let absolute = format!("/{dir}");
        if let Some(expected) = cached {
            let visible = vfs
                .lookup(cx, cx.root, absolute.as_bytes(), confined(true))
                .await
                .map_err(path_io)?;
            return if visible == *expected {
                Ok(visible)
            } else {
                Err(errno_to_io(Errno::EBUSY))
            };
        }

        let flags = LookupFlags {
            no_xdev: true,
            ..confined(true)
        };
        let mut target = cx.root.clone();
        for part in dir.split('/') {
            mkdir(vfs, cx, &target, part.as_bytes()).await?;
            target = vfs
                .lookup(cx, &target, part.as_bytes(), flags)
                .await
                .map_err(path_io)?;
        }
        let attr = vfs.stat(&target).await.map_err(errno_to_io)?;
        let flags = target.mnt.flags();
        // Keep existing directory permissions and contents. Every alias and its rename
        // live in the private upper, even when the root's writable layer is persistent.
        let upper = self
            .memory
            .apply(MemFs::new(
                Arc::new(HostClock(self.host.clone())),
                attr.mode & 0o7777,
                attr.uid,
                attr.gid,
            ))
            .map_err(errno_to_io)?;
        let lower = Arc::new(VolumeView {
            fs: target.dentry.sb().fs.clone(),
            root: target.dentry.node().clone(),
        });
        let overlay = OverlayFs::new(Some(Arc::new(upper)), vec![lower]);
        let tree = vfs.create_mount(
            overlay,
            absolute.into_bytes(),
            flags,
            false,
            vfs.namespace().owner().clone(),
        );

        // A mount beneath this directory already has an explicit place in the namespace.
        if vfs
            .mount_info(vfs.namespace(), cx.root)
            .iter()
            .any(|entry| {
                let path = entry.mount.root_path();
                vfs.is_path_reachable(&path.mnt, &path.dentry, &target)
            })
        {
            return Err(errno_to_io(Errno::EBUSY));
        }

        vfs.move_mount(vfs.namespace(), &tree.path, &target, false)
            .map_err(errno_to_io)?;
        *cached = Some(tree.path.clone());
        Ok(tree.path.clone())
    }

    async fn publish_aliases(
        &self,
        vfs: &Arc<Vfs>,
        cx: &Ctx<'_>,
        state: &mut InstallState,
        root: &str,
        layout: &ResolvedLayout,
    ) {
        for (index, dir) in COMMAND_DIRS.into_iter().enumerate() {
            let parent = match self
                .alias_directory(vfs, cx, dir, &mut state.alias_dirs[index])
                .await
            {
                Ok(parent) => parent,
                Err(error) => {
                    tracing::debug!(%dir, %error, "could not prepare a private runtime command directory");
                    continue;
                }
            };
            let mut seen = HashSet::new();
            for (name, _) in &layout.commands {
                if !seen.insert(name) || (dir == "bin" && name == "wasmer") {
                    continue;
                }
                let target = format!("{root}/bin/{name}");
                let Ok(file) = vfs
                    .lookup(cx, cx.root, target.as_bytes(), confined(false))
                    .await
                else {
                    continue;
                };
                if file.dentry.file_type() != wasixv2_vfs::FileType::Regular {
                    continue;
                }
                #[cfg(feature = "wasix1")]
                if let Some((_, defaults)) =
                    layout.defaults.iter().find(|(command, _)| command == name)
                    && let Ok(attr) = vfs.stat(&file).await
                {
                    let dev = attr.dev.unwrap_or_default();
                    self.defaults.write().unwrap().insert(
                        wasixv2_wasix1::FileId {
                            dev: (dev.major, dev.minor),
                            ino: attr.ino,
                        },
                        defaults.clone(),
                    );
                }
                if let Err(error) = publish_alias(vfs, cx, &parent, name, target.as_bytes()).await {
                    tracing::debug!(%dir, %name, ?error, "could not publish a runtime package command");
                }
            }
        }
    }
}

fn layout_key(identity: &[u8; 32]) -> String {
    let mut key = String::with_capacity(64);
    for byte in identity {
        write!(&mut key, "{byte:02x}").expect("writing to a string");
    }
    key
}

fn installed_paths(key: &str, entrypoint: &str) -> InstalledRuntimePackage {
    let root = format!("{PREFIX}/{key}");
    let executable = format!("{root}/bin/{entrypoint}");
    InstalledRuntimePackage { root, executable }
}

fn package_flags() -> MountFlags {
    MountFlags {
        nodev: true,
        nosuid: true,
        ..MountFlags::default()
    }
}

fn context<'a>(cred: &'a Cred, root: &'a Path) -> Ctx<'a> {
    Ctx {
        cred,
        root,
        umask: 0o022,
        task: 0,
        leases: None,
    }
}

fn confined(directory: bool) -> LookupFlags {
    LookupFlags {
        no_symlinks: true,
        follow: true,
        directory,
        ..LookupFlags::default()
    }
}

fn path_io(error: PathError) -> io::Error {
    errno_to_io(error.errno())
}

async fn mkdir(vfs: &Vfs, cx: &Ctx<'_>, start: &Path, name: &[u8]) -> io::Result<()> {
    match vfs.mkdir(cx, start, name, 0o755).await {
        Ok(()) | Err(PathError::Errno(Errno::EEXIST)) => Ok(()),
        Err(error) => Err(path_io(error)),
    }
}

fn relative_mapping(path: &str) -> io::Result<String> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(errno_to_io(Errno::EINVAL));
    }
    let mut parts = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(errno_to_io(Errno::EINVAL)),
            part => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

async fn publish_alias(
    vfs: &Vfs,
    cx: &Ctx<'_>,
    dir: &Path,
    name: &str,
    target: &[u8],
) -> io::Result<()> {
    // Rename replaces an existing writable alias without following the destination.
    let temporary = format!(".wasmer-link-{}", vfs.next_id());
    let temp = temporary.as_bytes();
    vfs.symlink(cx, target, dir, temp).await.map_err(path_io)?;
    let result = vfs
        .rename(cx, dir, temp, dir, name.as_bytes(), RenameMode::Replace)
        .await;
    if result.is_err() {
        let _ = vfs.unlink(cx, dir, temp).await;
    }
    result.map_err(path_io)
}
