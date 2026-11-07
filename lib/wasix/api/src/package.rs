//! Byte-backed package assembly. Acquisition, credentials and persistent caches belong
//! to the embedder; execution remains ordinary VFS exec (`fs/exec.c:kernel_execve`).
use crate::{Filesystem, Layer, Machine, OwnedBuffer};
#[cfg(feature = "resolved-packages")]
mod resolved;
#[cfg(feature = "resolved-packages")]
pub use resolved::{
    ResolvedCommand, ResolvedLayout, ResolvedReaderProvider, ResolvedReaderVolume,
    ResolvedVolumeRequest, preflight_resolved_filesystem,
};
use std::{
    collections::{BTreeMap, HashSet},
    io,
    sync::Arc,
};
use webc::{Version, metadata::annotations::Wasi, v3::read::OwnedReader};

/// Apply command annotations to initial launch arguments and environment.
/// Explicit caller environment values retain precedence and position. Returns
/// the annotation cwd for the consumer to apply with its own cwd policy.
pub fn command_config(
    name: &str,
    annotation: Option<&Wasi>,
    config: &mut crate::ProcessConfig,
) -> io::Result<Option<String>> {
    let mut args = vec![
        annotation
            .and_then(|annotation| annotation.exec_name.clone())
            .unwrap_or_else(|| name.to_owned()),
    ];
    let mut environment: Vec<(String, String)> = Vec::new();
    if let Some(annotation) = annotation {
        args.extend(annotation.main_args.clone().unwrap_or_default());
        for entry in annotation.env.as_deref().unwrap_or_default() {
            let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
            match environment.iter_mut().find(|(existing, _)| existing == key) {
                Some((_, old)) => *old = value.to_owned(),
                None => environment.push((key.to_owned(), value.to_owned())),
            }
        }
    }
    for (key, value) in environment {
        if !config
            .env
            .iter()
            .any(|entry| entry.split_once('=').map_or(entry.as_str(), |(key, _)| key) == key)
        {
            config.env.push(format!("{key}={value}"));
        }
    }
    let cwd = annotation
        .and_then(|annotation| annotation.cwd.as_ref())
        .map(|cwd| {
            cwd.to_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("package cwd is not UTF-8"))
        })
        .transpose()?;
    args.append(&mut config.args);
    config.args = args;
    Ok(cwd)
}

/// A WEBC with dependencies supplied as bytes rather than fetched by the runtime.
/// Dependency aliases are those in the WEBC manifest's `use` map.
pub struct Package {
    reader: OwnedReader,
    dependencies: BTreeMap<String, Arc<Package>>,
}

impl Package {
    pub fn from_bytes(bytes: OwnedBuffer) -> io::Result<Self> {
        let bytes = match webc::detect(bytes.as_ref()).map_err(io::Error::other)? {
            Version::V3 => bytes,
            Version::V2 => webc::migration::v2_to_v3(bytes).map_err(io::Error::other)?,
            version => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported WEBC {version}"),
                ));
            }
        };
        Ok(Self {
            reader: OwnedReader::parse(bytes).map_err(io::Error::other)?,
            dependencies: BTreeMap::new(),
        })
    }

    pub fn with_dependency(mut self, alias: impl Into<String>, package: Arc<Package>) -> Self {
        self.dependencies.insert(alias.into(), package);
        self
    }

    pub fn entrypoint(&self) -> Option<&str> {
        self.reader.manifest().entrypoint.as_deref()
    }
    pub fn commands(&self) -> impl Iterator<Item = &str> {
        self.reader.manifest().commands.keys().map(String::as_str)
    }

    /// The command's module bytes, retaining the package buffer for a registry/cache
    /// consumer. No native filesystem or engine-specific serialization is needed.
    pub fn binary(&self, command: &str) -> io::Result<OwnedBuffer> {
        let command = self
            .reader
            .manifest()
            .commands
            .get(command)
            .ok_or_else(|| invalid("unknown package command"))?;
        let atom = command
            .atom()
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("command has no atom"))?;
        let source = self.dependency(atom.dependency.as_deref())?;
        source
            .reader
            .get_atom(&atom.name)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| invalid("command atom is missing"))
    }

    pub fn annotation(&self, command: &str) -> io::Result<Option<Wasi>> {
        self.reader
            .manifest()
            .commands
            .get(command)
            .ok_or_else(|| invalid("unknown package command"))?
            .wasi()
            .map_err(io::Error::other)
    }

    /// Prepare a named/default command after installing this package tree.
    /// `config.args` contains caller arguments without argv[0]; command defaults
    /// precede them, explicit environment values and an explicit cwd win. This is
    /// container launch configuration; guest execve keeps its existing ABI policy.
    pub fn prepare_command(
        &self,
        machine: &mut Machine,
        command: Option<&str>,
        config: &mut crate::ProcessConfig,
    ) -> io::Result<String> {
        let name = command
            .or_else(|| self.entrypoint())
            .ok_or_else(|| invalid("package has no entrypoint"))?;
        self.binary(name)?;
        let annotation = self.annotation(name)?;
        let cwd = command_config(name, annotation.as_ref(), config)?;
        if machine.working_dir.is_none()
            && let Some(cwd) = cwd
        {
            machine.set_working_dir(cwd);
        }
        Ok(format!("/bin/{name}"))
    }

    fn dependency(&self, alias: Option<&str>) -> io::Result<&Package> {
        match alias {
            None => Ok(self),
            Some(alias) => self
                .dependencies
                .get(alias)
                .map(Arc::as_ref)
                .ok_or_else(|| invalid(&format!("missing supplied dependency {alias}"))),
        }
    }

    /// Installs the package and its supplied dependencies before mounts/processes.
    /// Root commands win, then dependencies in alias order. Dependencies' volumes
    /// are mounted first; the root package overlays them. Additional `uses` packages
    /// can be installed together by `install_packages`.
    pub async fn install(&self, machine: &mut Machine) -> io::Result<()> {
        install_packages(machine, &[self]).await
    }
}

/// Install a root package followed by additional injected packages. The first
/// command of a name wins; all file access remains under the Machine's VFS root.
pub async fn install_packages(machine: &mut Machine, packages: &[&Package]) -> io::Result<()> {
    let sources = packages
        .iter()
        .map(|package| PackageInstallSource::Webc(package))
        .collect::<Vec<_>>();
    install_package_sources(machine, &sources).await
}

/// Sources in package precedence order. In-memory content has no WEBC archive;
/// its existing filesystem remains shared as a lower layer, with private writes
/// in each Machine's upper layer. The embedder owns package identity/validation.
#[derive(Clone)]
pub enum PackageInstallSource<'a> {
    Webc(&'a Package),
    #[cfg(feature = "resolved-packages")]
    Resolved(&'a ResolvedLayout),
    Memory {
        commands: &'a [(String, OwnedBuffer)],
        root: Option<Arc<dyn Filesystem>>,
    },
}

/// The same installer as [`install_packages`], with ordered in-memory command
/// and file contents. Every root/command layer is prepared before any nonroot
/// mount. As with `install_packages`, a failure can leave partial installation.
pub async fn install_package_sources(
    machine: &mut Machine,
    sources: &[PackageInstallSource<'_>],
) -> io::Result<()> {
    install_package_sources_with_root_overlays(machine, sources, &[]).await
}

/// Install sources with caller-selected root layers above the command layer.
pub async fn install_package_sources_with_root_overlays(
    machine: &mut Machine,
    sources: &[PackageInstallSource<'_>],
    root_overlays: &[Layer],
) -> io::Result<()> {
    let mut prepared = prepare_package_sources(machine, sources).await?;
    prepared.mount_roots(machine, root_overlays).await?;
    prepared.mount_volumes(machine).await
}

#[derive(Clone)]
enum PreparedVolume {
    Layer(Layer),
    #[cfg(feature = "resolved-packages")]
    Resolved(resolved::ResolvedVolume),
}

#[derive(Debug, thiserror::Error)]
#[error("cannot install the package's commands in /bin and /usr/bin")]
struct CommandLayerError(#[source] io::Error);

#[derive(Debug, thiserror::Error)]
#[error("cannot stack the root filesystem's layers")]
struct RootLayersError(#[source] io::Error);

#[cfg(feature = "wasix1")]
#[derive(Debug, thiserror::Error)]
#[error("cannot configure the package's commands")]
struct CommandDefaultsError(#[source] io::Error);

/// Sources prepared for a Machine, with separate root and nonroot mount phases.
/// This lets a consumer apply its cwd policy between those existing phases.
pub struct PreparedPackageSources {
    root_layers: Vec<PreparedVolume>,
    prepared_roots: Option<Vec<Layer>>,
    resolved: bool,
    commands: Vec<(String, OwnedBuffer)>,
    #[cfg(feature = "wasix1")]
    defaults: Vec<(String, crate::CommandDefaults)>,
    mounts: Vec<(String, PreparedVolume, usize)>,
    #[cfg(feature = "resolved-packages")]
    volume_layers: resolved::VolumeLayers,
}

impl PreparedPackageSources {
    pub fn mount_paths(&self) -> impl Iterator<Item = &str> {
        self.mounts.iter().map(|(path, _, _)| path.as_str())
    }

    async fn layer(&mut self, machine: &Machine, backing: &PreparedVolume) -> io::Result<Layer> {
        match backing {
            PreparedVolume::Layer(layer) => Ok(layer.clone()),
            #[cfg(feature = "resolved-packages")]
            PreparedVolume::Resolved(volume) => self.volume_layers.get(machine, volume).await,
        }
    }

    pub async fn prepare_roots(&mut self, machine: &Machine) -> io::Result<()> {
        if self.prepared_roots.is_some() {
            return Ok(());
        }
        let mut roots = Vec::new();
        for backing in self.root_layers.clone() {
            roots.push(self.layer(machine, &backing).await?);
        }
        let commands = machine
            .commands_layer(self.commands.clone())
            .map_err(|source| {
                if self.resolved {
                    io::Error::new(source.kind(), CommandLayerError(source))
                } else {
                    source
                }
            })?;
        roots.extend(commands);
        self.prepared_roots = Some(roots);
        Ok(())
    }

    pub async fn mount_roots(
        &mut self,
        machine: &mut Machine,
        root_overlays: &[Layer],
    ) -> io::Result<()> {
        self.prepare_roots(machine).await?;
        let mut roots = self.prepared_roots.as_ref().unwrap().clone();
        roots.extend(root_overlays.iter().cloned());
        machine.mount_root_layers(roots).await.map_err(|source| {
            if self.resolved {
                io::Error::new(source.kind(), RootLayersError(source))
            } else {
                source
            }
        })?;
        #[cfg(feature = "wasix1")]
        machine
            .set_wasix1_command_defaults(self.defaults.clone())
            .map_err(|source| {
                if self.resolved {
                    io::Error::new(source.kind(), CommandDefaultsError(source))
                } else {
                    source
                }
            })?;
        Ok(())
    }

    pub async fn mount_volumes(&mut self, machine: &Machine) -> io::Result<()> {
        for (path, backing, _) in self.mounts.clone() {
            let layer = self.layer(machine, &backing).await?;
            machine
                .mount_layer(&path, &layer, true)
                .await
                .map_err(|error| match &backing {
                    #[cfg(feature = "resolved-packages")]
                    PreparedVolume::Resolved(volume) => volume.context(error),
                    PreparedVolume::Layer(_) => error,
                })?;
        }
        Ok(())
    }
}

/// Prepare sources in their existing precedence order, without mounting roots.
pub async fn prepare_package_sources(
    machine: &Machine,
    sources: &[PackageInstallSource<'_>],
) -> io::Result<PreparedPackageSources> {
    let mut ordered = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = sources.iter().rev().cloned().collect::<Vec<_>>();
    while let Some(source) = pending.pop() {
        if let PackageInstallSource::Webc(package) = &source {
            let package = *package;
            if !seen.insert(package as *const Package) {
                continue;
            }
            for (alias, _) in &package.reader.manifest().use_map {
                package.dependency(Some(alias))?;
            }
            pending.extend(
                package
                    .dependencies
                    .values()
                    .rev()
                    .map(|package| PackageInstallSource::Webc(package.as_ref())),
            );
        } else if let PackageInstallSource::Memory {
            root: Some(root), ..
        } = &source
            && root.root().file_type() != wasixv2_vfs::FileType::Directory
        {
            return Err(invalid("in-memory package root is not a directory"));
        }
        ordered.push(source);
    }
    let mut commands = Vec::new();
    #[cfg(feature = "wasix1")]
    let mut defaults = Vec::new();
    let mut names = HashSet::new();
    for source in &ordered {
        #[cfg(feature = "resolved-packages")]
        if let PackageInstallSource::Resolved(layout) = source {
            let mut selected = HashSet::new();
            for (name, bytes) in &layout.commands {
                if names.insert(name.clone()) {
                    selected.insert(name.clone());
                    commands.push((name.clone(), bytes.clone()));
                }
            }
            #[cfg(feature = "wasix1")]
            defaults.extend(
                layout
                    .defaults
                    .iter()
                    .filter(|(name, _)| selected.contains(name))
                    .cloned(),
            );
            continue;
        }
        let PackageInstallSource::Webc(package) = source else {
            if let PackageInstallSource::Memory {
                commands: memory, ..
            } = source
            {
                for (name, bytes) in *memory {
                    if names.insert(name.clone()) {
                        commands.push((name.clone(), bytes.clone()));
                    }
                }
            }
            continue;
        };
        for name in package.commands() {
            if names.insert(name.to_owned()) {
                commands.push((name.to_owned(), package.binary(name)?));
                #[cfg(feature = "wasix1")]
                if let Some(wasi) = package.annotation(name)? {
                    defaults.push((
                        name.to_owned(),
                        crate::CommandDefaults {
                            argv0: wasi.exec_name,
                            args: wasi.main_args.unwrap_or_default(),
                            env: wasi.env.unwrap_or_default(),
                        },
                    ));
                }
            }
        }
    }
    let mut root_layers: Vec<PreparedVolume> = Vec::new();
    let mut mounts = Vec::new();
    for source in ordered.iter().rev() {
        #[cfg(feature = "resolved-packages")]
        if let PackageInstallSource::Resolved(layout) = source {
            for volume in &layout.volumes {
                let backing = PreparedVolume::Resolved(volume.clone());
                if std::path::Path::new(&volume.mount_path) == std::path::Path::new("/") {
                    root_layers.push(backing);
                } else {
                    let depth = std::path::Path::new(&volume.mount_path)
                        .components()
                        .count()
                        .saturating_sub(1);
                    mounts.push((volume.mount_path.clone(), backing, depth));
                }
            }
            continue;
        }
        let PackageInstallSource::Webc(package) = source else {
            if let PackageInstallSource::Memory {
                root: Some(root), ..
            } = source
            {
                root_layers.push(PreparedVolume::Layer(Layer(root.clone())));
            }
            continue;
        };
        if let Some(mappings) = package
            .reader
            .manifest()
            .filesystem()
            .map_err(io::Error::other)?
        {
            for mapping in mappings {
                let source = package.dependency(mapping.from.as_deref())?;
                if !mapping.mount_path.starts_with('/') {
                    return Err(invalid("package mount must be absolute"));
                }
                let mut layer = machine.package_layer(&source.reader, &mapping.volume_name)?;
                if let Some(path) = mapping
                    .host_path
                    .as_deref()
                    .filter(|p| !matches!(*p, "" | "/"))
                {
                    layer = volume_subtree(layer, Some(path)).await?;
                }
                if mapping.mount_path == "/" {
                    root_layers.push(PreparedVolume::Layer(layer));
                } else {
                    let depth = mapping
                        .mount_path
                        .split('/')
                        .filter(|part| !part.is_empty())
                        .count();
                    mounts.push((mapping.mount_path, PreparedVolume::Layer(layer), depth));
                }
            }
        }
    }

    mounts.sort_by_key(|(_, _, depth)| *depth);
    let resolved = {
        #[cfg(feature = "resolved-packages")]
        {
            ordered
                .iter()
                .any(|source| matches!(source, PackageInstallSource::Resolved(_)))
        }
        #[cfg(not(feature = "resolved-packages"))]
        {
            false
        }
    };
    Ok(PreparedPackageSources {
        root_layers,
        resolved,
        prepared_roots: None,
        commands,
        #[cfg(feature = "wasix1")]
        defaults,
        mounts,
        #[cfg(feature = "resolved-packages")]
        volume_layers: resolved::VolumeLayers::default(),
    })
}

async fn volume_subtree(layer: Layer, path: Option<&str>) -> io::Result<Layer> {
    if let Some(path) = path.filter(|path| !matches!(*path, "" | "/")) {
        let vfs = wasixv2_vfs::Vfs::new(layer.0.clone());
        let root = vfs.root();
        let cred = wasixv2_vfs::Cred::root();
        let cx = wasixv2_vfs::Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let node = vfs
            .lookup(
                &cx,
                &root,
                path.as_bytes(),
                wasixv2_vfs::LookupFlags {
                    in_root: true,
                    directory: true,
                    ..wasixv2_vfs::LookupFlags::follow()
                },
            )
            .await
            .map_err(|error| crate::errno_to_io(error.errno()))?;
        let layer = Layer(Arc::new(VolumeView {
            fs: layer.0,
            root: node.dentry.node().clone(),
        }));
        return Ok(layer);
    }
    Ok(layer)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(all(test, feature = "tokio", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use webc::v3::{
        ChecksumAlgorithm, SignatureAlgorithm, Timestamps,
        write::{FileEntry, Writer},
    };
    #[test]
    fn annotation_environment_keeps_first_position_with_last_value_and_caller_precedence() {
        let mut annotation = Wasi::new("main");
        annotation.exec_name = Some("program".to_owned());
        annotation.main_args = Some(vec!["default".to_owned()]);
        annotation.env = Some(vec![
            "A=old".to_owned(),
            "B=second".to_owned(),
            "A=new".to_owned(),
            "BARE".to_owned(),
            "CALLER=ignored".to_owned(),
        ]);
        let mut config = crate::ProcessConfig {
            args: vec!["argument".to_owned()],
            env: vec!["CALLER=explicit".to_owned()],
            stdio: crate::Stdio::from_fns(|_| {}, |_| {}),
        };
        assert_eq!(
            command_config("main", Some(&annotation), &mut config).unwrap(),
            None
        );
        assert_eq!(config.args, ["program", "default", "argument"]);
        assert_eq!(
            config.env,
            ["CALLER=explicit", "A=new", "B=second", "BARE="]
        );
    }

    fn bytes(code: i32) -> OwnedBuffer {
        let module = wat::parse_str(format!(r#"(module (import "wasixv2" "exit_group" (func $exit (param i32))) (memory (export "memory") 1) (func (export "_start") (call $exit (i32.const {code})) unreachable))"#)).unwrap();
        let manifest = serde_json::from_value(serde_json::json!({"entrypoint":"hello","commands":{"hello":{"runner":"https://webc.org/runner/wasi","annotations":{"atom":{"name":"main"}}}}})).unwrap();
        let writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(BTreeMap::from([(
                "main".parse().unwrap(),
                FileEntry::borrowed(&module, Timestamps::default()),
            )]))
            .unwrap();
        OwnedBuffer::from_bytes(writer.finish(SignatureAlgorithm::None).unwrap())
    }
    #[tokio::test]
    async fn byte_backed_packages_install_commands_without_native_sources() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = Package::from_bytes(bytes(23)).unwrap();
                let injected = Package::from_bytes(bytes(99)).unwrap();
                assert_eq!(root.entrypoint(), Some("hello"));
                assert!(root.binary("absent").is_err());
                let mut machine = Machine::new();
                install_packages(&mut machine, &[&root, &injected])
                    .await
                    .unwrap();
                let config = crate::ProcessConfig {
                    args: vec!["hello".into()],
                    env: vec![],
                    stdio: crate::Stdio::from_fns(|_| {}, |_| {}),
                };
                assert_eq!(
                    machine
                        .run_file(&crate::Engine::default(), "/bin/hello", config)
                        .await
                        .unwrap(),
                    23
                );
                machine.shutdown().await;
            })
            .await;
    }
    #[tokio::test]
    async fn mixed_sources_keep_first_command_and_live_memory_root() {
        use wasixv2_vfs::{Cred, Ctx, LookupFlags, OpenHow, Vfs};
        tokio::task::LocalSet::new()
            .run_until(async {
                let archive = Package::from_bytes(bytes(23)).unwrap();
                let memory_binary = Package::from_bytes(bytes(99))
                    .unwrap()
                    .binary("hello")
                    .unwrap();
                let commands = vec![
                    ("hello".to_owned(), memory_binary.clone()),
                    ("memory-only".to_owned(), memory_binary),
                ];
                let fs: Arc<dyn Filesystem> = Arc::new(wasixv2_vfs_mem::MemFs::new(
                    Arc::new(wasixv2_kernel::HostClock(Arc::new(
                        crate::TokioHost::default(),
                    ))),
                    0o755,
                    0,
                    0,
                ));
                crate::populate_directory(
                    fs.clone(),
                    &[
                        crate::DirectoryEntry::Directory {
                            path: String::new(),
                            mode: 0o755,
                        },
                        crate::DirectoryEntry::File {
                            path: "value".into(),
                            mode: 0o644,
                            data: b"before".to_vec(),
                        },
                    ],
                    0,
                    0,
                )
                .await
                .unwrap();
                for memory_first in [true, false] {
                    let memory = PackageInstallSource::Memory {
                        commands: &commands,
                        root: Some(fs.clone()),
                    };
                    let webc = PackageInstallSource::Webc(&archive);
                    let sources = if memory_first {
                        [memory, webc]
                    } else {
                        [webc, memory]
                    };
                    let mut machine = Machine::new();
                    install_package_sources(&mut machine, &sources)
                        .await
                        .unwrap();
                    for (name, expected) in [
                        ("hello", if memory_first { 99 } else { 23 }),
                        ("memory-only", 99),
                    ] {
                        let config = crate::ProcessConfig {
                            args: vec![name.into()],
                            env: vec![],
                            stdio: crate::Stdio::from_fns(|_| {}, |_| {}),
                        };
                        assert_eq!(
                            machine
                                .run_file(
                                    &crate::Engine::default(),
                                    &format!("/bin/{name}"),
                                    config
                                )
                                .await
                                .unwrap(),
                            expected
                        );
                    }
                    // The memory source remains the same live filesystem below the
                    // Machine's writable overlay; it is not copied during install.
                    let vfs = Vfs::new(fs.clone());
                    let root = vfs.root();
                    let cred = Cred::root();
                    let cx = Ctx {
                        cred: &cred,
                        root: &root,
                        umask: 0,
                        task: 0,
                        leases: None,
                    };
                    let file = vfs
                        .open(
                            &cx,
                            &root,
                            b"value",
                            &OpenHow {
                                flags: wasixv2_abi::OpenFlags::O_WRONLY,
                                mode: 0,
                                lookup: LookupFlags::follow(),
                            },
                        )
                        .await
                        .unwrap();
                    assert_eq!(file.write_at(b"shared", 0).await.unwrap(), 6);
                    let guest = machine.vfs();
                    let root = guest.root();
                    let cx = Ctx {
                        cred: &cred,
                        root: &root,
                        umask: 0,
                        task: 0,
                        leases: None,
                    };
                    let file = guest
                        .open(
                            &cx,
                            &root,
                            b"/value",
                            &OpenHow {
                                flags: wasixv2_abi::OpenFlags::O_RDONLY,
                                mode: 0,
                                lookup: LookupFlags::follow(),
                            },
                        )
                        .await
                        .unwrap();
                    let mut value = [0; 6];
                    assert_eq!(file.read_at(&mut value, 0).await.unwrap(), 6);
                    assert_eq!(&value, b"shared");
                    machine.shutdown().await;
                }
            })
            .await;
    }

    #[tokio::test]
    async fn supplied_dependency_atoms_survive_the_package_sources() {
        tokio::task::LocalSet::new().run_until(async {
            let manifest=serde_json::from_value(serde_json::json!({"entrypoint":"alias","use":{"dep":"https://example.invalid/dep.webc"},"commands":{"alias":{"runner":"https://webc.org/runner/wasi","annotations":{"atom":{"name":"main","dependency":"dep"}}}}})).unwrap();
            let writer=Writer::new(ChecksumAlgorithm::Sha256).write_manifest(&manifest).unwrap().write_atoms(BTreeMap::new()).unwrap();
            let unresolved=Package::from_bytes(OwnedBuffer::from_bytes(writer.finish(SignatureAlgorithm::None).unwrap())).unwrap();
            assert!(unresolved.binary("alias").is_err());
            let package=unresolved.with_dependency("dep",Arc::new(Package::from_bytes(bytes(77)).unwrap()));
            let mut machine=Machine::new();package.install(&mut machine).await.unwrap();drop(package);
            let config=crate::ProcessConfig{args:vec!["alias".into()],env:vec![],stdio:crate::Stdio::from_fns(|_|{},|_|{})};
            assert_eq!(machine.run_file(&crate::Engine::default(),"/bin/alias",config).await.unwrap(),77);
        }).await;
    }
    #[test]
    fn initial_command_configuration_preserves_explicit_values() {
        let mut package = Package::from_bytes(bytes(0)).unwrap();
        // Rebuild the manifest with the same source atom and launch annotations.
        let manifest=serde_json::from_value(serde_json::json!({"entrypoint":"hello","commands":{"hello":{"runner":"https://webc.org/runner/wasi","annotations":{"atom":{"name":"main"},"wasi":{"atom":"main","exec-name":"package-name","main-args":["default"],"env":["FOO=package","BAR=package"],"cwd":"/tmp"}}}}})).unwrap();
        let atom = package.binary("hello").unwrap();
        let writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(BTreeMap::from([(
                "main".parse().unwrap(),
                FileEntry::borrowed(&atom, Timestamps::default()),
            )]))
            .unwrap();
        package = Package::from_bytes(OwnedBuffer::from_bytes(
            writer.finish(SignatureAlgorithm::None).unwrap(),
        ))
        .unwrap();
        let mut machine = Machine::new();
        let mut config = crate::ProcessConfig {
            args: vec!["caller".into()],
            env: vec!["FOO=caller".into()],
            stdio: crate::Stdio::from_fns(|_| {}, |_| {}),
        };
        assert_eq!(
            package
                .prepare_command(&mut machine, None, &mut config)
                .unwrap(),
            "/bin/hello"
        );
        assert_eq!(config.args, ["package-name", "default", "caller"]);
        assert_eq!(config.env, ["FOO=caller", "BAR=package"]);
        assert_eq!(machine.working_dir.as_deref(), Some("/tmp"));
        machine.set_working_dir("/home/user");
        assert!(
            package
                .prepare_command(&mut machine, Some("hello"), &mut config)
                .is_ok()
        );
        assert_eq!(machine.working_dir.as_deref(), Some("/home/user"));
    }
    #[tokio::test]
    async fn package_subdirectory_is_a_vfs_mount_root() {
        use wasixv2_vfs::{Cred, Ctx, LookupFlags, OpenHow};
        use webc::v3::write::{DirEntry, Directory};
        let manifest = serde_json::from_value(serde_json::json!({"package":{"fs":[{"volume_name":"files","host_path":"sub","mount_path":"/data"}]}})).unwrap();
        let sub = Directory::new(
            BTreeMap::from([(
                "file".parse().unwrap(),
                DirEntry::File(FileEntry::borrowed(b"inside", Timestamps::default())),
            )]),
            Timestamps::default(),
        );
        let volume = Directory::new(
            BTreeMap::from([
                ("sub".parse().unwrap(), DirEntry::Dir(sub)),
                (
                    "outside".parse().unwrap(),
                    DirEntry::File(FileEntry::borrowed(b"hidden", Timestamps::default())),
                ),
            ]),
            Timestamps::default(),
        );
        let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(BTreeMap::new())
            .unwrap();
        writer.write_volume("files", volume).unwrap();
        let package = Package::from_bytes(OwnedBuffer::from_bytes(
            writer.finish(SignatureAlgorithm::None).unwrap(),
        ))
        .unwrap();
        let mut machine = Machine::new();
        package.install(&mut machine).await.unwrap();
        let vfs = machine.vfs();
        let root = vfs.root();
        let cred = Cred::root();
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        let file = vfs
            .open(
                &cx,
                &root,
                b"/data/file",
                &OpenHow {
                    flags: wasixv2_abi::OpenFlags::O_RDONLY,
                    mode: 0,
                    lookup: LookupFlags::follow(),
                },
            )
            .await
            .unwrap();
        let mut bytes = [0; 6];
        assert_eq!(file.read_at(&mut bytes, 0).await.unwrap(), 6);
        assert_eq!(&bytes, b"inside");
        for path in [b"/data/outside".as_slice(), b"/data/../outside"] {
            assert_eq!(
                vfs.lookup(&cx, &root, path, LookupFlags::follow())
                    .await
                    .err(),
                Some(wasixv2_vfs::PathError::Errno(wasixv2_abi::Errno::ENOENT))
            );
        }
    }
    #[tokio::test]
    async fn version_two_sources_migrate_from_bytes() {
        let original = bytes(4);
        let v2 = webc::migration::v3_to_v2(original.clone()).unwrap();
        let package = Package::from_bytes(v2).unwrap();
        assert_eq!(package.entrypoint(), Some("hello"));
        assert_eq!(
            package.binary("hello").unwrap(),
            Package::from_bytes(original)
                .unwrap()
                .binary("hello")
                .unwrap()
        );
        assert!(Package::from_bytes(OwnedBuffer::from_bytes(&b"bad"[..])).is_err());
    }
}

// Linux fs/namespace.c:clone_mnt retains a superblock while selecting a directory
// as a bind mount root. Package storage and readonly capabilities remain unchanged.
struct VolumeView {
    fs: Arc<dyn crate::Filesystem>,
    root: Arc<dyn wasixv2_vfs::Node>,
}
#[async_trait::async_trait(?Send)]
impl crate::Filesystem for VolumeView {
    fn limits_file_size(&self) -> bool {
        self.fs.limits_file_size()
    }
    fn info(&self) -> wasixv2_vfs::FsInfo {
        self.fs.info()
    }
    fn root(&self) -> Arc<dyn wasixv2_vfs::Node> {
        self.root.clone()
    }
    async fn statfs(&self) -> wasixv2_vfs::FsResult<wasixv2_vfs::StatFs> {
        self.fs.statfs().await
    }
    async fn sync(&self) -> wasixv2_vfs::FsResult<()> {
        self.fs.sync().await
    }
}
