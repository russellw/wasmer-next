//! Machine-lifetime imports into existing package overlays.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, Weak},
};

use futures_util::lock::Mutex as AsyncMutex;
use wasixv2_abi::OpenFlags;
use wasixv2_vfs::{Cred, Ctx, File, LookupFlags, Mount, OpenHow, Path, Superblock, Vfs};
use wasixv2_vfs_overlay::{OverlayAppender, PrefixFs};

use super::{resolved::VolumeLayers, wasmer_command::RuntimePackage};
use crate::{
    Errno, Filesystem, MAX_LOWERS, Machine, OverlayFs, OwnedBuffer, commands_layer, errno_to_io,
};

/// The initial namespace's view at the time a runtime package was imported.
#[derive(Clone, Debug)]
pub struct ImportedRuntimePackage {
    pub identity: [u8; 32],
    pub entrypoint: String,
    pub entrypoint_visible: bool,
    /// Mapping paths covered by mounts that do not accept new package layers.
    pub hidden: Vec<String>,
}

impl Machine {
    /// Imports the package at its original paths, below existing content. Repeated identities
    /// reuse the earlier import. Requires runtime packages to be enabled on this machine.
    pub async fn import_runtime_package(
        &self,
        package: &RuntimePackage,
    ) -> io::Result<ImportedRuntimePackage> {
        let packages = self
            .runtime_packages
            .as_ref()
            .ok_or_else(|| errno_to_io(Errno::EOPNOTSUPP))?;
        self.in_use
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(packages.import(self.vfs(), package).await?.public)
    }
}

pub(crate) struct RuntimePackages {
    limit: usize,
    owner: (u32, u32),
    targets: Mutex<Vec<Target>>,
    slots: Mutex<HashMap<[u8; 32], Slot>>,
    #[cfg(feature = "wasix1")]
    defaults: Arc<std::sync::RwLock<wasixv2_wasix1::Commands>>,
}

struct Target {
    fs: Weak<dyn Filesystem>,
    append: OverlayAppender,
}

type ImportState = AsyncMutex<Progress>;

/// The first append makes the slot machine-lifetime. Before the first append a
/// failed or cancelled import releases its capacity when the last waiter leaves.
struct Slot {
    weak: Weak<ImportState>,
    committed: Option<Arc<ImportState>>,
}

#[derive(Default)]
struct Progress {
    plan: Option<Plan>,
    imported: Option<Imported>,
}

struct Plan {
    tails: Vec<Append>,
    next: usize,
    import: Imported,
    #[cfg(feature = "wasix1")]
    defaults: Vec<(String, Arc<OwnedBuffer>, crate::CommandDefaults)>,
}

struct Append {
    sb: Weak<Superblock>,
    appender: OverlayAppender,
    fs: Arc<dyn Filesystem>,
}

#[derive(Clone)]
pub(super) struct Imported {
    pub(super) public: ImportedRuntimePackage,
    pub(super) atom: Arc<OwnedBuffer>,
    commands: Arc<dyn Filesystem>,
}

impl Imported {
    /// A detached executable used when the package's real entrypoint is shadowed.
    /// Do not retain the open file in the ledger: it owns a reference to the VFS.
    pub(super) async fn open_entrypoint(&self, vfs: &Arc<Vfs>) -> io::Result<File> {
        let root = vfs.kern_mount(self.commands.clone()).root_path();
        open(vfs, &root, self.public.entrypoint.as_bytes()).await
    }
}

impl RuntimePackages {
    pub(crate) fn new(
        limit: usize,
        owner: (u32, u32),
        #[cfg(feature = "wasix1")] defaults: Arc<std::sync::RwLock<wasixv2_wasix1::Commands>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            limit,
            owner,
            targets: Mutex::default(),
            slots: Mutex::default(),
            #[cfg(feature = "wasix1")]
            defaults,
        })
    }

    pub(crate) fn overlay(
        &self,
        upper: Option<Arc<dyn Filesystem>>,
        lowers: Vec<Arc<dyn Filesystem>>,
    ) -> Arc<dyn Filesystem> {
        let (fs, append) = OverlayFs::new_appendable(upper, lowers);
        let mut targets = self.targets.lock().unwrap();
        targets.retain(|target| target.fs.strong_count() != 0);
        targets.push(Target {
            fs: Arc::downgrade(&fs),
            append,
        });
        fs
    }

    fn target(&self, sb: &Arc<Superblock>) -> Option<OverlayAppender> {
        self.targets.lock().unwrap().iter().find_map(|target| {
            Weak::ptr_eq(&target.fs, &Arc::downgrade(&sb.fs)).then(|| target.append.clone())
        })
    }

    fn reserve(&self, id: [u8; 32]) -> io::Result<Arc<ImportState>> {
        let mut slots = self.slots.lock().unwrap();
        slots.retain(|_, slot| slot.weak.strong_count() != 0);
        if let Some(slot) = slots.get(&id).and_then(|slot| slot.weak.upgrade()) {
            return Ok(slot);
        }
        if slots.len() >= self.limit {
            return Err(errno_to_io(Errno::ENOSPC));
        }
        let slot = Arc::new(ImportState::default());
        slots.insert(
            id,
            Slot {
                weak: Arc::downgrade(&slot),
                committed: None,
            },
        );
        Ok(slot)
    }

    pub(super) async fn import(
        &self,
        vfs: &Arc<Vfs>,
        package: &RuntimePackage,
    ) -> io::Result<Imported> {
        let slot = self.reserve(package.identity)?;
        let mut progress = slot.lock().await;
        if let Some(imported) = &progress.imported {
            return Ok(imported.clone());
        }
        if progress.plan.is_none() {
            progress.plan = Some(self.plan(vfs, package).await?);
        }
        let plan = progress.plan.as_mut().expect("planned import");
        while let Some(tail) = plan.tails.get(plan.next) {
            let sb = tail
                .sb
                .upgrade()
                .ok_or_else(|| errno_to_io(Errno::ESTALE))?;
            tail.appender
                .append_lower(tail.fs.clone())
                .await
                .map_err(errno_to_io)?;
            vfs.invalidate_negative(&sb);
            if plan.next == 0 {
                self.slots
                    .lock()
                    .unwrap()
                    .get_mut(&package.identity)
                    .expect("reserved import")
                    .committed = Some(slot.clone());
            }
            // There is no await between an append and recording its commit.
            plan.next += 1;
        }

        let root = vfs.namespace().entry_root();
        let entrypoint = &plan.import.public.entrypoint;
        plan.import.public.entrypoint_visible = match open(vfs, &root, entrypoint.as_bytes()).await
        {
            Ok(file) => matches_atom(file.shared_contents().await, &plan.import.atom),
            Err(_) => false,
        };
        #[cfg(feature = "wasix1")]
        self.install_defaults(vfs, &root, &plan.defaults).await;
        let imported = progress.plan.take().expect("completed import plan").import;
        progress.imported = Some(imported.clone());
        Ok(imported)
    }

    async fn plan(&self, vfs: &Arc<Vfs>, package: &RuntimePackage) -> io::Result<Plan> {
        let atom = package
            .layout
            .shared_command_atom(&package.entrypoint)
            .ok_or_else(|| errno_to_io(Errno::ENOEXEC))?;
        let commands = commands_layer(self.owner, package.layout.commands.clone())?
            .ok_or_else(|| errno_to_io(Errno::ENOEXEC))?
            .0;
        let root_mount = vfs.root().mnt;
        let root_appender = self
            .target(root_mount.sb())
            .ok_or_else(|| errno_to_io(Errno::ESTALE))?;
        let root_sb = root_mount.sb().clone();
        let mut grouped = vec![(root_sb, root_appender, vec![commands.clone()])];
        let mut hidden = Vec::new();
        let root = vfs.namespace().entry_root();
        let mut layers = VolumeLayers::default();
        // ResolvedLayout installs layers from low to high priority. An overlay takes
        // its lowers from top to bottom.
        for volume in package.layout.volumes.iter().rev() {
            let parts = mapping_components(&volume.mount_path)?;
            let (mount, rest) = covering_mount(vfs, &root, &parts).await?;
            let Some(appender) = self.target(mount.sb()) else {
                tracing::warn!(path = %volume.mount_path, "runtime package mapping is hidden by an existing mount");
                hidden.push(volume.mount_path.clone());
                continue;
            };
            let relative = relative_path(&mount, rest);
            let layer = layers
                .get_inner(self.owner, volume)
                .await
                .map_err(|err| volume.context(err))?;
            let prefixed = PrefixFs::new(&relative, layer.0).map_err(errno_to_io)?;
            if let Some((_, _, lowers)) = grouped
                .iter_mut()
                .find(|(sb, _, _)| Arc::ptr_eq(sb, mount.sb()))
            {
                lowers.push(prefixed);
            } else {
                grouped.push((mount.sb().clone(), appender, vec![prefixed]));
            }
        }
        let tails = grouped
            .into_iter()
            .map(|(sb, appender, lowers)| {
                if lowers.len() > MAX_LOWERS || appender.lower_count() >= MAX_LOWERS {
                    return Err(errno_to_io(Errno::ENOSPC));
                }
                Ok(Append {
                    sb: Arc::downgrade(&sb),
                    appender,
                    fs: OverlayFs::new(None, lowers),
                })
            })
            .collect::<io::Result<_>>()?;

        Ok(Plan {
            tails,
            next: 0,
            import: Imported {
                public: ImportedRuntimePackage {
                    identity: package.identity,
                    entrypoint: format!("/bin/{}", package.entrypoint),
                    entrypoint_visible: false,
                    hidden,
                },
                atom,
                commands,
            },
            #[cfg(feature = "wasix1")]
            defaults: package
                .layout
                .defaults
                .iter()
                .filter_map(|(name, defaults)| {
                    let atom = package.layout.shared_command_atom(name)?;
                    Some((name.clone(), atom, defaults.clone()))
                })
                .collect(),
        })
    }

    #[cfg(feature = "wasix1")]
    async fn install_defaults(
        &self,
        vfs: &Arc<Vfs>,
        root: &Path,
        commands: &[(String, Arc<OwnedBuffer>, crate::CommandDefaults)],
    ) {
        let mut resolved = Vec::new();
        for (name, atom, defaults) in commands {
            for dir in crate::COMMAND_DIRS {
                let path = format!("/{dir}/{name}");
                let Ok(file) = open(vfs, root, path.as_bytes()).await else {
                    continue;
                };
                if !matches_atom(file.shared_contents().await, atom) {
                    continue;
                }
                let Ok(attr) = vfs.stat(&file.path).await else {
                    continue;
                };
                let dev = attr.dev.unwrap_or_default();
                resolved.push((
                    wasixv2_wasix1::FileId {
                        dev: (dev.major, dev.minor),
                        ino: attr.ino,
                    },
                    defaults.clone(),
                ));
            }
        }
        let mut files = self.defaults.write().unwrap();
        for (id, defaults) in resolved {
            files.insert(id, defaults);
        }
    }
}

fn mapping_components(path: &str) -> io::Result<Vec<&[u8]>> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(errno_to_io(Errno::EINVAL));
    }
    if path.len() >= wasixv2_vfs::PATH_MAX {
        return Err(errno_to_io(Errno::ENAMETOOLONG));
    }
    let mut parts = Vec::new();
    for component in path.as_bytes().split(|&b| b == b'/') {
        match component {
            b"" | b"." => {}
            b".." => return Err(errno_to_io(Errno::EINVAL)),
            part if part.len() > wasixv2_vfs::NAME_MAX => {
                return Err(errno_to_io(Errno::ENAMETOOLONG));
            }
            part => parts.push(part),
        }
    }
    Ok(parts)
}

/// Select the mount of the deepest existing ancestor, without redirecting an original
/// package path through a guest symlink. Keep the suffix from the original mapping.
async fn covering_mount<'a>(
    vfs: &Arc<Vfs>,
    root: &Path,
    parts: &'a [&'a [u8]],
) -> io::Result<(Arc<Mount>, &'a [&'a [u8]])> {
    let cred = Cred::root();
    let cx = context(&cred, root);
    let mut cursor = root.clone();
    let mut suffix = parts;
    for (i, part) in parts.iter().enumerate() {
        let next = vfs
            .lookup(
                &cx,
                &cursor,
                part,
                LookupFlags {
                    no_symlinks: true,
                    ..LookupFlags::follow()
                },
            )
            .await;
        let next = match next {
            Ok(next) => next,
            Err(err) if matches!(err.errno(), Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => {
                break;
            }
            Err(err) => return Err(errno_to_io(err.errno())),
        };
        if !Arc::ptr_eq(&cursor.mnt, &next.mnt) {
            suffix = &parts[i + 1..];
        }
        cursor = next;
    }
    Ok((cursor.mnt, suffix))
}

fn relative_path(mount: &Mount, suffix: &[&[u8]]) -> Vec<u8> {
    // A bind mount begins partway down the superblock. Keep that directory prefix.
    let mut names = Vec::new();
    let mut dentry = mount.root.clone();
    while let Some(parent) = dentry.parent() {
        names.push(dentry.name());
        dentry = parent;
    }
    names
        .iter()
        .rev()
        .map(Vec::as_slice)
        .chain(suffix.iter().copied())
        .collect::<Vec<_>>()
        .join(&b'/')
}

fn context<'a>(cred: &'a Cred, root: &'a Path) -> Ctx<'a> {
    Ctx {
        cred,
        root,
        umask: 0,
        task: 0,
        leases: None,
    }
}

async fn open(vfs: &Arc<Vfs>, root: &Path, path: &[u8]) -> io::Result<File> {
    let cred = Cred::root();
    vfs.open(
        &context(&cred, root),
        root,
        path,
        &OpenHow {
            flags: OpenFlags::O_RDONLY,
            mode: 0,
            lookup: LookupFlags::follow(),
        },
    )
    .await
    .map_err(|err| errno_to_io(err.errno()))
}

pub(super) fn matches_atom(
    contents: Option<wasixv2_vfs::SharedContents>,
    atom: &OwnedBuffer,
) -> bool {
    contents.is_some_and(|bytes| std::ptr::eq((*bytes).as_ref(), atom.as_ref()))
}
