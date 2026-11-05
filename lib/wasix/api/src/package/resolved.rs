//! Resolved package representation and the shared installation plan.
use std::{
    collections::{BTreeMap, HashMap},
    io,
    path::Path,
    sync::Arc,
};

use crate::{Layer, Machine, OwnedBuffer};
use wasmer_config::package::PackageId;
use wasmer_package::{
    commands::BinaryPackageCommand,
    loader::LoadedPackage,
    resolver::{ResolvedFileSystemMapping, ResolvedPackage},
};
use webc::{Container, Volume, metadata::annotations::Wasi, v3::read::OwnedReader};

/// A selected source volume after the common resolved-volume policy is applied.
pub struct ResolvedVolumeRequest<'a> {
    pub package: &'a PackageId,
    pub container: &'a Container,
    pub volume_name: &'a str,
    pub source_path: Option<&'a str>,
}

/// A reader representation, including any volume/subpath translation during migration.
pub struct ResolvedReaderVolume {
    pub reader: Arc<OwnedReader>,
    pub volume_name: String,
    pub source_path: Option<String>,
    pub migrated_from_v2: bool,
}

/// A provider is called only for selected mappings. Errors are final. Explicit `None`
/// selects the original opaque volume; no error falls back to another representation.
pub type ResolvedReaderProvider<'a> =
    dyn for<'r> Fn(ResolvedVolumeRequest<'r>) -> io::Result<Option<ResolvedReaderVolume>> + 'a;

#[derive(Clone)]
enum Backing {
    Reader {
        reader: Arc<OwnedReader>,
        name: String,
    },
    Opaque {
        identity: Arc<()>,
        volume: Volume,
        name: String,
    },
}

#[derive(Clone)]
pub(super) struct ResolvedVolume {
    pub(super) mount_path: String,
    source_path: Option<String>,
    backing: Backing,
}

/// One host command override or resolver-selected command.
#[derive(Clone)]
pub struct ResolvedCommand {
    pub name: String,
    pub atom: OwnedBuffer,
    #[cfg(feature = "wasix1")]
    pub defaults: crate::CommandDefaults,
}

/// A reusable, engine-independent description of resolved sources for one installation.
/// No raw `use` map is traversed: resolution already chose aliases and the required closure.
#[derive(Clone, Default)]
pub struct ResolvedLayout {
    pub(super) volumes: Vec<ResolvedVolume>,
    pub(super) commands: Vec<(String, OwnedBuffer)>,
    #[cfg(feature = "wasix1")]
    pub(super) defaults: Vec<(String, crate::CommandDefaults)>,
}

impl ResolvedLayout {
    /// Prepare selected volume representations, then tolerant exec defaults. Callers
    /// needing strict annotation validation retain that separate consumer phase.
    pub fn new(
        package: &LoadedPackage,
        root_is_local_dir: bool,
        provider: Option<&ResolvedReaderProvider<'_>>,
    ) -> io::Result<Self> {
        Self::from_parts(
            &package.resolution.package,
            &package.containers,
            &package.commands,
            root_is_local_dir,
            provider,
        )
    }

    /// Prepare already-resolved container and command data without requiring the
    /// dependency graph used during acquisition. Uses the same installation policy
    /// as [`Self::new`].
    pub fn from_parts(
        package: &ResolvedPackage,
        containers: &HashMap<PackageId, Container>,
        commands: &[BinaryPackageCommand],
        root_is_local_dir: bool,
        provider: Option<&ResolvedReaderProvider<'_>>,
    ) -> io::Result<Self> {
        let mut layout = Self::default();
        let mut identities: HashMap<&PackageId, Arc<()>> = HashMap::new();
        let mut volumes: HashMap<&PackageId, BTreeMap<String, Volume>> = HashMap::new();
        for mapping in package.filesystem.iter().rev() {
            if root_is_local_dir && mapping.package == package.root_package {
                continue;
            }
            let mount_path = mapping.mount_path.to_str().ok_or_else(|| {
                super::invalid(&format!(
                    "the mount path {} is not UTF-8",
                    mapping.mount_path.display()
                ))
            })?;
            if !mount_path.starts_with('/') {
                return Err(super::invalid(&format!(
                    "the package \"{}\" mounts a volume at a relative path, {mount_path}",
                    mapping.package
                )));
            }
            let container = containers.get(&mapping.package).ok_or_else(|| {
                super::invalid(&format!(
                    "the package \"{}\" is not in the dependency tree",
                    mapping.package
                ))
            })?;
            // V1/V2 mappings select a subtree of the named volume. The legacy
            // V3 mapping selects the whole volume; raw Package keeps its own policy.
            let source_path =
                if matches!(container.version(), webc::Version::V1 | webc::Version::V2) {
                    mapping.original_path.as_deref()
                } else {
                    None
                };
            let supplied = match provider {
                Some(provider) => provider(ResolvedVolumeRequest {
                    package: &mapping.package,
                    container,
                    volume_name: &mapping.volume_name,
                    source_path,
                })?,
                None => None,
            };
            let (backing, source_path) = match supplied {
                Some(supplied) => {
                    // Migration can omit the old full-atom fallback when no fs table
                    // named it. Preserve that strict reader representation's behavior.
                    if supplied.migrated_from_v2
                        && supplied.reader.get_volume(&supplied.volume_name).is_err()
                    {
                        tracing::event!(target: "wasmer_cli::commands::run::machine", tracing::Level::WARN, package = %mapping.package, volume = %supplied.volume_name, "the webc v2 package has no `fs` table; its \"atom\" volume is not mounted");
                        continue;
                    }
                    (
                        Backing::Reader {
                            reader: supplied.reader,
                            name: supplied.volume_name,
                        },
                        supplied.source_path,
                    )
                }
                None => {
                    let volume = volumes
                        .entry(&mapping.package)
                        .or_insert_with(|| container.volumes())
                        .get(&mapping.volume_name)
                        .cloned()
                        .ok_or_else(|| {
                            super::invalid(&format!(
                                "The \"{}\" package doesn't have a \"{}\" volume",
                                mapping.package, mapping.volume_name
                            ))
                        })?;
                    let identity = identities
                        .entry(&mapping.package)
                        .or_insert_with(|| Arc::new(()))
                        .clone();
                    (
                        Backing::Opaque {
                            identity,
                            volume,
                            name: mapping.volume_name.clone(),
                        },
                        source_path.map(str::to_owned),
                    )
                }
            };
            layout.volumes.push(ResolvedVolume {
                mount_path: mount_path.to_owned(),
                source_path,
                backing,
            });
        }
        layout
            .volumes
            .sort_by_key(|volume| Path::new(&volume.mount_path).components().count());
        for command in commands {
            layout
                .commands
                .push((command.name().to_owned(), command.atom()));
            #[cfg(feature = "wasix1")]
            {
                let annotation = command
                    .metadata()
                    .annotation::<Wasi>(Wasi::KEY)
                    .ok()
                    .flatten();
                layout.defaults.push((
                    command.name().to_owned(),
                    crate::CommandDefaults {
                        argv0: annotation
                            .as_ref()
                            .and_then(|annotation| annotation.exec_name.clone()),
                        args: annotation
                            .as_ref()
                            .and_then(|annotation| annotation.main_args.clone())
                            .unwrap_or_default(),
                        env: annotation
                            .and_then(|annotation| annotation.env)
                            .unwrap_or_default(),
                    },
                ));
            }
        }
        Ok(layout)
    }

    /// Add injected packages in CLI order: their volumes under the program's,
    /// their commands after its names. Preserve the supplied exec-default sequence.
    pub fn using(mut self, used: impl IntoIterator<Item = Self>) -> Self {
        let mut volumes = Vec::new();
        for package in used {
            volumes.extend(package.volumes);
            self.commands.extend(package.commands);
            #[cfg(feature = "wasix1")]
            self.defaults.extend(package.defaults);
        }
        volumes.append(&mut self.volumes);
        volumes.sort_by_key(|volume| Path::new(&volume.mount_path).components().count());
        self.volumes = volumes;
        self
    }

    /// Host command atoms override package atoms; their empty/explicit exec defaults
    /// follow the package table, matching the original command-map configuration.
    pub fn override_commands(&mut self, commands: Vec<ResolvedCommand>) {
        let mut atoms = Vec::with_capacity(commands.len() + self.commands.len());
        for command in commands {
            atoms.push((command.name.clone(), command.atom));
            #[cfg(feature = "wasix1")]
            self.defaults.push((command.name, command.defaults));
        }
        atoms.append(&mut self.commands);
        self.commands = atoms;
    }

    pub fn mount_paths(&self) -> impl Iterator<Item = &str> {
        self.volumes.iter().map(|volume| volume.mount_path.as_str())
    }

    /// The CLI validates every command's annotation at its historical strict phase.
    /// Other embedders may validate only the selected command.
    pub fn validate_command_annotations(package: &LoadedPackage) -> io::Result<()> {
        for command in &package.commands {
            command
                .metadata()
                .annotation::<Wasi>(Wasi::KEY)
                .map_err(|error| {
                    io::Error::other(AnnotationError {
                        command: command.name().to_owned(),
                        source: io::Error::other(error),
                    })
                })?;
        }
        Ok(())
    }
}

/// Legacy acquisition preflight, before command selection. This policy is explicit;
/// a universal LoadedPackage or an opaque-volume installation does not impose it.
pub fn preflight_resolved_filesystem(
    packages: &HashMap<PackageId, Container>,
    package: &ResolvedPackage,
    root_is_local_dir: bool,
) -> io::Result<()> {
    if package.filesystem.is_empty() {
        return Ok(());
    }
    let mut v1 = false;
    let mut v2 = None;
    let mut v3 = None;
    for ResolvedFileSystemMapping { package: id, .. } in &package.filesystem {
        let container = packages.get(id).ok_or_else(|| {
            super::invalid(&format!(
                "\"{}\" wants to use the \"{id}\" package, but it isn't in the dependency tree",
                package.root_package
            ))
        })?;
        match container.version() {
            webc::Version::V1 => v1 = true,
            webc::Version::V2 => {
                if v2.is_none() {
                    v2 = Some(id);
                }
            }
            webc::Version::V3 => {
                if v3.is_none() {
                    v3 = Some(id);
                }
            }
            other => {
                return Err(super::invalid(&format!(
                    "the package '{id}' has an unknown webc version: {other}"
                )));
            }
        }
    }
    match (v2, v3) {
        (Some(v2), Some(v3)) => {
            return Err(super::invalid(&format!(
                "Mix of webc v2 and v3 in the same dependency tree is not supported; v2: {v2}, v3: {v3}"
            )));
        }
        (None, None) if !v1 => {
            return Err(super::invalid("Internal error: no packages found in tree"));
        }
        _ => {}
    }
    let mut volumes: HashMap<&PackageId, BTreeMap<String, Volume>> = HashMap::new();
    for mapping in &package.filesystem {
        if root_is_local_dir && mapping.package == package.root_package {
            continue;
        }
        if mapping.mount_path.as_path() == Path::new("/") {
            tracing::warn!(target: "wasmer_wasix::runtime::package_loader::load_package_tree",
                "The \"{}\" package wants to mount a volume at \"/\", which breaks WASIX modules' filesystems",
                mapping.package
            );
        }
        let container = packages.get(&mapping.package).ok_or_else(|| {
            super::invalid(&format!(
                "\"{}\" wants to use the \"{}\" package, but it isn't in the dependency tree",
                package.root_package, mapping.package
            ))
        })?;
        if !volumes
            .entry(&mapping.package)
            .or_insert_with(|| container.volumes())
            .contains_key(&mapping.volume_name)
        {
            return Err(super::invalid(&format!(
                "The \"{}\" package doesn't have a \"{}\" volume",
                mapping.package, mapping.volume_name
            )));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("invalid annotations on the \"{command}\" command")]
struct AnnotationError {
    command: String,
    #[source]
    source: io::Error,
}

#[derive(Debug, thiserror::Error)]
#[error("cannot mount the package volume \"{name}\" at {path}")]
struct VolumeError {
    name: String,
    path: String,
    #[source]
    source: io::Error,
}

impl ResolvedVolume {
    pub(super) fn context(&self, source: io::Error) -> io::Error {
        let name = match &self.backing {
            Backing::Reader { name, .. } | Backing::Opaque { name, .. } => name.clone(),
        };
        io::Error::new(
            source.kind(),
            VolumeError {
                name,
                path: self.mount_path.clone(),
                source,
            },
        )
    }
}

#[derive(PartialEq, Eq, Hash)]
enum VolumeKey {
    Reader(usize, String),
    Opaque(usize, String),
}

#[derive(Default)]
pub(super) struct VolumeLayers(HashMap<VolumeKey, Layer>);
impl VolumeLayers {
    pub(super) async fn get(
        &mut self,
        machine: &Machine,
        volume: &ResolvedVolume,
    ) -> io::Result<Layer> {
        self.get_inner(machine, volume)
            .await
            .map_err(|error| volume.context(error))
    }

    async fn get_inner(&mut self, machine: &Machine, volume: &ResolvedVolume) -> io::Result<Layer> {
        let key = match &volume.backing {
            Backing::Reader { reader, name } => {
                VolumeKey::Reader(Arc::as_ptr(reader) as usize, name.clone())
            }
            Backing::Opaque { identity, name, .. } => {
                VolumeKey::Opaque(Arc::as_ptr(identity) as usize, name.clone())
            }
        };
        let layer = match self.0.get(&key) {
            Some(layer) => layer.clone(),
            None => {
                let layer = match &volume.backing {
                    Backing::Reader { reader, name } => machine.package_layer(reader, name)?,
                    Backing::Opaque { volume, .. } => {
                        let (uid, gid) = machine.owner;
                        Layer(Arc::new(
                            crate::PackageFs::from_volume(volume, uid, gid)
                                .map_err(io::Error::other)?,
                        ))
                    }
                };
                self.0.insert(key, layer.clone());
                layer
            }
        };
        super::volume_subtree(layer, volume.source_path.as_deref()).await
    }
}

#[cfg(all(test, feature = "tokio", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::BTreeMap};
    use wasixv2_vfs::{Cred, Ctx, LookupFlags, OpenHow};
    use wasmer_config::package::PackageHash;
    use wasmer_package::resolver::{InMemorySource, PackageInfo, resolve};
    use webc::v3::{
        ChecksumAlgorithm, SignatureAlgorithm, Timestamps,
        write::{DirEntry, Directory, FileEntry, SymlinkEntry, Writer},
    };

    fn volume() -> Directory<'static> {
        Directory::new(
            BTreeMap::from([
                (
                    "msg".parse().unwrap(),
                    DirEntry::File(FileEntry::borrowed(b"contents", Timestamps::default())),
                ),
                (
                    "empty".parse().unwrap(),
                    DirEntry::Dir(Directory::new(BTreeMap::new(), Timestamps::default())),
                ),
                (
                    "link".parse().unwrap(),
                    DirEntry::Symlink(SymlinkEntry::borrowed("msg", Timestamps::default())),
                ),
            ]),
            Timestamps::default(),
        )
    }

    fn archive(fs: bool) -> OwnedBuffer {
        let manifest = if fs {
            serde_json::from_value(
                serde_json::json!({"package":{"fs":[{"volume_name":"atom","mount_path":"/data"}]}}),
            )
            .unwrap()
        } else {
            webc::metadata::Manifest::default()
        };
        let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(BTreeMap::new())
            .unwrap();
        writer.write_volume("atom", volume()).unwrap();
        OwnedBuffer::from_bytes(writer.finish(SignatureAlgorithm::None).unwrap())
    }

    async fn loaded(bytes: OwnedBuffer) -> LoadedPackage {
        let container = wasmer_package::utils::from_bytes(bytes.as_ref().to_vec()).unwrap();
        let id = PackageId::Hash(PackageHash::from_sha256_bytes([0; 32]));
        let info =
            PackageInfo::from_manifest(id.clone(), container.manifest(), container.version())
                .unwrap();
        let resolution = resolve(&id, &info, &InMemorySource::new()).await.unwrap();
        LoadedPackage::from_containers(resolution, HashMap::from([(id, container)])).unwrap()
    }

    async fn read(machine: &Machine, path: &[u8]) -> Vec<u8> {
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
                path,
                &OpenHow {
                    flags: wasixv2_abi::OpenFlags::O_RDONLY,
                    mode: 0,
                    lookup: LookupFlags::follow(),
                },
            )
            .await
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let count = file.read_at(&mut chunk, bytes.len() as u64).await.unwrap();
            if count == 0 {
                return bytes;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
    }

    #[tokio::test]
    async fn opaque_memory_v3_volume_survives_source_drop_with_symlinks_and_empty_directories() {
        let package = loaded(archive(true)).await;
        let layout = ResolvedLayout::new(&package, false, None).unwrap();
        let mut machine = Machine::new();
        crate::install_package_sources(
            &mut machine,
            &[super::super::PackageInstallSource::Resolved(&layout)],
        )
        .await
        .unwrap();
        drop(layout);
        drop(package);
        assert_eq!(read(&machine, b"/data/link").await, b"contents");
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
        assert_eq!(
            vfs.lookup(&cx, &root, b"/data/empty", LookupFlags::follow())
                .await
                .unwrap()
                .dentry
                .node()
                .file_type(),
            wasixv2_vfs::FileType::Directory
        );
    }

    #[tokio::test]
    async fn noncanonical_resolved_root_mounts_remain_root_layers() {
        for spelling in ["//", "/./"] {
            let mut package = loaded(archive(true)).await;
            for mapping in &mut package.resolution.package.filesystem {
                mapping.mount_path = spelling.into();
            }
            let layout = ResolvedLayout::new(&package, false, None).unwrap();
            let mut machine = Machine::new();
            crate::install_package_sources(
                &mut machine,
                &[super::super::PackageInstallSource::Resolved(&layout)],
            )
            .await
            .unwrap();
            assert_eq!(read(&machine, b"/msg").await, b"contents", "{spelling}");
        }
    }

    #[tokio::test]
    async fn opaque_v2_without_fs_keeps_the_original_atom_fallback() {
        use webc::v2::write::{
            DirEntry as V2Entry, Directory as V2Directory, FileEntry as V2File, Writer as V2Writer,
        };
        let writer = V2Writer::default()
            .write_manifest(&webc::metadata::Manifest::default())
            .unwrap()
            .write_atoms(BTreeMap::new())
            .unwrap();
        let writer = writer
            .with_volume(
                "atom",
                V2Directory {
                    children: BTreeMap::from([(
                        "msg".parse().unwrap(),
                        V2Entry::File(V2File::from(b"contents".as_slice())),
                    )]),
                },
            )
            .unwrap();
        let bytes = writer.finish(webc::v2::SignatureAlgorithm::None).unwrap();
        let package = loaded(OwnedBuffer::from_bytes(bytes)).await;
        let layout = ResolvedLayout::new(&package, false, None).unwrap();
        let mut machine = Machine::new();
        crate::install_package_sources(
            &mut machine,
            &[super::super::PackageInstallSource::Resolved(&layout)],
        )
        .await
        .unwrap();
        assert_eq!(read(&machine, b"/msg").await, b"contents");
    }

    // Match webc's tests/v1.rs serializer: these are original V1 bytes, with a
    // filesystem volume named "atom" separate from the executable atom table.
    fn v1_archive(fs: Option<serde_json::Value>) -> OwnedBuffer {
        use webc::v1::{DirOrFile, GenerateChecksum, Volume as V1Volume, WebC};
        let command = wat::parse_str(
            r#"(module
            (import "wasixv2" "exit_group" (func $exit (param i32)))
            (memory (export "memory") 1)
            (func (export "_start") (call $exit (i32.const 37)) unreachable))"#,
        )
        .unwrap();
        let signature = webc::metadata::AtomSignature::Sha256(
            wasmer_package::resolver::WebcHash::sha256(&command).as_bytes(),
        )
        .to_string();
        let mut manifest = serde_json::json!({
            "atoms": {"main": {"kind": "https://webc.org/kind/wasm", "signature": signature}},
            "commands": {"hello": {"runner": "https://webc.org/runner/wasi", "annotations": {"wasi": {"atom": "main"}}}},
            "entrypoint": "hello"
        });
        if let Some(fs) = fs {
            manifest["package"] = serde_json::json!({"fs": fs});
        }
        let atoms =
            V1Volume::serialize_atoms(BTreeMap::from([(DirOrFile::File("main".into()), command)]));
        let files = V1Volume::serialize_files(BTreeMap::from([
            (DirOrFile::Dir("nested/".into()), Vec::new()),
            (DirOrFile::File("nested/msg".into()), b"selected".to_vec()),
            (DirOrFile::File("msg".into()), b"filesystem atom".to_vec()),
            (DirOrFile::File("decoy".into()), b"outside subtree".to_vec()),
        ]));
        let webc = WebC {
            version: 1,
            checksum: None,
            signature: None,
            manifest: serde_json::from_value(manifest).unwrap(),
            atoms: V1Volume::parse(&atoms).unwrap(),
            volumes: [("atom".to_owned(), V1Volume::parse(&files).unwrap())]
                .into_iter()
                .collect(),
        };
        OwnedBuffer::from_bytes(webc.into_bytes(GenerateChecksum::Sha256).unwrap())
    }

    async fn assert_missing(machine: &Machine, path: &[u8]) {
        let root = machine.vfs().root();
        let cred = Cred::root();
        let cx = Ctx {
            cred: &cred,
            root: &root,
            umask: 0,
            task: 0,
            leases: None,
        };
        assert!(
            machine
                .vfs()
                .lookup(&cx, &root, path, LookupFlags::follow())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn v1_original_path_selects_subtrees_at_nested_and_root_mounts() {
        for mount in ["/data", "/"] {
            let bytes = v1_archive(Some(serde_json::json!([
                {"volume_name": "atom", "original_path": "/nested", "mount_path": mount}
            ])));
            // The classic SDK passes incoming bytes directly to this constructor.
            let original = webc::Container::from_bytes_and_version(
                bytes.as_ref().to_vec().into(),
                webc::Version::V1,
            )
            .unwrap();
            assert_eq!(original.version(), webc::Version::V1);
            drop(original);
            let package = loaded(bytes.clone()).await;
            assert_eq!(package.webc_version, webc::Version::V1);
            let container = &package.containers[&package.resolution.package.root_package];
            assert_eq!(container.version(), webc::Version::V1);
            preflight_resolved_filesystem(&package.containers, &package.resolution.package, false)
                .unwrap();
            let layout = ResolvedLayout::new(&package, false, None).unwrap();
            let mut machine = Machine::new();
            crate::install_package_sources(
                &mut machine,
                &[super::super::PackageInstallSource::Resolved(&layout)],
            )
            .await
            .unwrap();
            let command = package.get_command("hello").unwrap().atom();
            assert_eq!(read(&machine, b"/bin/hello").await, command.as_ref());
            drop(command);
            drop(layout);
            drop(package);
            drop(bytes);
            let prefix = if mount == "/" { "" } else { mount };
            assert_eq!(
                read(&machine, format!("{prefix}/msg").as_bytes()).await,
                b"selected"
            );
            assert_missing(&machine, format!("{prefix}/decoy").as_bytes()).await;
            assert_missing(&machine, format!("{prefix}/nested").as_bytes()).await;
        }
    }

    #[tokio::test]
    async fn v1_without_fs_mounts_filesystem_atom_and_executes_the_separate_command_atom() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let package = loaded(v1_archive(None)).await;
                preflight_resolved_filesystem(
                    &package.containers,
                    &package.resolution.package,
                    false,
                )
                .unwrap();
                let layout = ResolvedLayout::new(&package, false, None).unwrap();
                let mut machine = Machine::new();
                crate::install_package_sources(
                    &mut machine,
                    &[super::super::PackageInstallSource::Resolved(&layout)],
                )
                .await
                .unwrap();
                drop(layout);
                drop(package);
                assert_eq!(read(&machine, b"/msg").await, b"filesystem atom");
                assert_eq!(
                    machine
                        .run_file(
                            &crate::Engine::default(),
                            "/bin/hello",
                            crate::ProcessConfig {
                                args: vec!["hello".into()],
                                env: vec![],
                                stdio: crate::Stdio::from_fns(|_| {}, |_| {}),
                            }
                        )
                        .await
                        .unwrap(),
                    37
                );
                machine.shutdown().await;
            })
            .await;
    }

    #[tokio::test]
    async fn v1_missing_volume_is_rejected_before_invalid_command_selection() {
        let bytes = v1_archive(Some(serde_json::json!([
            {"volume_name": "missing", "mount_path": "/data"}
        ])));
        let container = wasmer_package::utils::from_bytes(bytes.as_ref().to_vec()).unwrap();
        let id = PackageId::Hash(PackageHash::from_sha256_bytes([0; 32]));
        let info =
            PackageInfo::from_manifest(id.clone(), container.manifest(), container.version())
                .unwrap();
        let mut resolution = resolve(&id, &info, &InMemorySource::new()).await.unwrap();
        // Deliberately invalid command lookup must remain later than filesystem validation.
        resolution.package.commands.get_mut("hello").unwrap().name = "absent".into();
        let containers = HashMap::from([(id, container)]);
        let error =
            preflight_resolved_filesystem(&containers, &resolution.package, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("doesn't have a \"missing\" volume")
        );
        assert!(
            LoadedPackage::from_containers(resolution, containers)
                .unwrap_err()
                .to_string()
                .contains("command metadata")
        );
    }

    #[tokio::test]
    async fn v1_dependency_mapping_keeps_alias_subtree_and_local_root_skip() {
        use wasmer_package::resolver::{Dependency, DistributionInfo, PackageSummary};
        let dep = wasmer_package::utils::from_bytes(
            v1_archive(Some(serde_json::json!([]))).as_ref().to_vec(),
        )
        .unwrap();
        let dep_id = PackageId::new_named("demo/assets", "1.0.0".parse().unwrap());
        let dep_info =
            PackageInfo::from_manifest(dep_id.clone(), dep.manifest(), dep.version()).unwrap();
        let mut source = InMemorySource::new();
        source.add(PackageSummary {
            pkg: dep_info,
            dist: DistributionInfo {
                webc: "https://example.invalid/assets.webc".parse().unwrap(),
                webc_sha256: [1; 32].into(),
            },
        });
        let root = wasmer_package::utils::from_bytes(v1_archive(Some(serde_json::json!([
            {"from": "assets", "volume_name": "atom", "original_path": "/nested", "mount_path": "/data"},
            {"volume_name": "atom", "mount_path": "/local"}
        ]))).as_ref().to_vec()).unwrap();
        let root_id = PackageId::Hash(PackageHash::from_sha256_bytes([0; 32]));
        let mut info =
            PackageInfo::from_manifest(root_id.clone(), root.manifest(), root.version()).unwrap();
        info.dependencies.push(Dependency {
            alias: "assets".into(),
            pkg: "demo/assets@1.0.0".parse().unwrap(),
        });
        let resolution = resolve(&root_id, &info, &source).await.unwrap();
        let package = LoadedPackage::from_containers(
            resolution,
            HashMap::from([(root_id, root), (dep_id.clone(), dep)]),
        )
        .unwrap();
        preflight_resolved_filesystem(&package.containers, &package.resolution.package, true)
            .unwrap();
        let calls = Cell::new(0);
        let provider =
            |request: ResolvedVolumeRequest<'_>| -> io::Result<Option<ResolvedReaderVolume>> {
                assert_eq!(request.package, &dep_id);
                assert_eq!(request.source_path, Some("/nested"));
                calls.set(calls.get() + 1);
                Ok(None)
            };
        let layout = ResolvedLayout::new(&package, true, Some(&provider)).unwrap();
        assert_eq!(calls.get(), 1);
        let mut machine = Machine::new();
        crate::install_package_sources(
            &mut machine,
            &[super::super::PackageInstallSource::Resolved(&layout)],
        )
        .await
        .unwrap();
        assert_eq!(read(&machine, b"/data/msg").await, b"selected");
        assert_missing(&machine, b"/data/decoy").await;
        assert_missing(&machine, b"/local").await;
    }

    #[tokio::test]
    async fn v1_preflight_does_not_change_the_v2_v3_mixing_policy() {
        use webc::v2::write::{Directory as V2Directory, Writer as V2Writer};
        let v2_bytes = V2Writer::default()
            .write_manifest(&webc::metadata::Manifest::default())
            .unwrap()
            .write_atoms(BTreeMap::new())
            .unwrap()
            .with_volume(
                "atom",
                V2Directory {
                    children: BTreeMap::new(),
                },
            )
            .unwrap()
            .finish(webc::v2::SignatureAlgorithm::None)
            .unwrap();
        let v2 = wasmer_package::utils::from_bytes(v2_bytes.to_vec()).unwrap();
        let v3 = wasmer_package::utils::from_bytes(archive(true).as_ref().to_vec()).unwrap();
        let mut package = loaded(v1_archive(None)).await;
        let v1_mapping = package.resolution.package.filesystem[0].clone();
        for (index, container) in [v2, v3].into_iter().enumerate() {
            let id = PackageId::Hash(PackageHash::from_sha256_bytes([index as u8 + 1; 32]));
            let mut mapping = v1_mapping.clone();
            mapping.package = id.clone();
            package.containers.insert(id, container);
            package.resolution.package.filesystem.push(mapping);
            // A V1/V2 or V1/V3 tree is not an actual V2/V3 mixture.
            if index == 0 {
                preflight_resolved_filesystem(
                    &package.containers,
                    &package.resolution.package,
                    false,
                )
                .unwrap();
            } else {
                let error = preflight_resolved_filesystem(
                    &package.containers,
                    &package.resolution.package,
                    false,
                )
                .unwrap_err();
                assert!(error.to_string().starts_with("Mix of webc v2 and v3"));
                package.resolution.package.filesystem.remove(1);
                preflight_resolved_filesystem(
                    &package.containers,
                    &package.resolution.package,
                    false,
                )
                .unwrap();
            }
        }
    }

    #[derive(Debug)]
    struct ProviderFailure(Arc<()>);
    impl std::fmt::Display for ProviderFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("selected reader failed")
        }
    }
    impl std::error::Error for ProviderFailure {}

    #[tokio::test]
    async fn selected_provider_failure_is_final_and_keeps_the_original_error() {
        let package = loaded(archive(true)).await;
        let identity = Arc::new(());
        let calls = Cell::new(0);
        let provider = |_: ResolvedVolumeRequest<'_>| -> io::Result<Option<ResolvedReaderVolume>> {
            calls.set(calls.get() + 1);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ProviderFailure(identity.clone()),
            ))
        };
        let error = ResolvedLayout::new(&package, false, Some(&provider))
            .err()
            .expect("selected reader must fail even though the opaque volume is valid");
        assert_eq!(calls.get(), 1);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(Arc::ptr_eq(
            &error
                .get_ref()
                .unwrap()
                .downcast_ref::<ProviderFailure>()
                .unwrap()
                .0,
            &identity
        ));
    }

    #[tokio::test]
    async fn selected_v3_reader_corruption_never_uses_the_valid_opaque_backing() {
        let manifest = serde_json::from_value(
            serde_json::json!({"package":{"fs":[{"volume_name":"atom","mount_path":"/data"}]}}),
        )
        .unwrap();
        let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
            .write_manifest(&manifest)
            .unwrap()
            .write_atoms(BTreeMap::new())
            .unwrap();
        writer
            .write_volume(
                "atom",
                Directory::new(
                    BTreeMap::from([(
                        "ab".parse().unwrap(),
                        DirEntry::File(FileEntry::borrowed(b"valid", Timestamps::default())),
                    )]),
                    Timestamps::default(),
                ),
            )
            .unwrap();
        let bytes = writer.finish(SignatureAlgorithm::None).unwrap();
        let package = loaded(OwnedBuffer::from_bytes(bytes.clone())).await;
        let mut corrupt = bytes.to_vec();
        // The same malformed-name fixture as the package driver's validation tests.
        let pattern = b"\x02\0\0\0\0\0\0\0ab";
        let name = corrupt
            .windows(pattern.len())
            .position(|window| window == pattern)
            .expect("volume entry")
            + 8;
        corrupt[name..name + 2].copy_from_slice(b"a/");
        let reader = Arc::new(OwnedReader::parse(corrupt).unwrap());
        let provider =
            |request: ResolvedVolumeRequest<'_>| -> io::Result<Option<ResolvedReaderVolume>> {
                Ok(Some(ResolvedReaderVolume {
                    reader: reader.clone(),
                    volume_name: request.volume_name.to_owned(),
                    source_path: None,
                    migrated_from_v2: false,
                }))
            };
        let layout = ResolvedLayout::new(&package, false, Some(&provider)).unwrap();
        let mut machine = Machine::new();
        let error = crate::install_package_sources(
            &mut machine,
            &[super::super::PackageInstallSource::Resolved(&layout)],
        )
        .await
        .expect_err("malformed selected v3 reader must not fall back to valid opaque contents");
        // io::Error::source delegates to the payload's source, skipping the
        // payload itself. Inspect both owned payloads to check typed custody.
        let context = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<VolumeError>())
            .expect("selected reader failure retains its volume context");
        assert_eq!(context.name, "atom");
        assert_eq!(context.path, "/data");
        let original = context
            .source
            .get_ref()
            .and_then(|error| error.downcast_ref::<wasixv2_vfs_package::PackageFsError>())
            .expect("volume context retains the original typed package error");
        assert!(
            matches!(original, wasixv2_vfs_package::PackageFsError::Malformed(_)),
            "original malformed-volume error is preserved"
        );
    }

    #[tokio::test]
    async fn providers_are_called_only_for_selected_mappings() {
        let mut package = loaded(archive(true)).await;
        let root = package.resolution.package.root_package.clone();
        let unused = PackageId::Hash(PackageHash::from_sha256_bytes([1; 32]));
        package
            .containers
            .insert(unused.clone(), package.containers[&root].clone());
        let calls = Cell::new(0);
        let provider =
            |request: ResolvedVolumeRequest<'_>| -> io::Result<Option<ResolvedReaderVolume>> {
                assert_ne!(request.package, &unused);
                calls.set(calls.get() + 1);
                Ok(None)
            };
        ResolvedLayout::new(&package, false, Some(&provider)).unwrap();
        assert_eq!(calls.get(), package.resolution.package.filesystem.len());
    }

    #[cfg(feature = "wasix1")]
    #[tokio::test]
    async fn command_overrides_keep_atom_precedence_and_the_original_default_sequence() {
        fn command(value: &'static [u8]) -> ResolvedCommand {
            ResolvedCommand {
                name: "same".to_owned(),
                atom: OwnedBuffer::from_bytes(value),
                defaults: crate::CommandDefaults {
                    argv0: Some(String::from_utf8(value.to_vec()).unwrap()),
                    args: Vec::new(),
                    env: Vec::new(),
                },
            }
        }
        let mut root = ResolvedLayout::default();
        root.override_commands(vec![command(b"root")]);
        let mut used = ResolvedLayout::default();
        used.override_commands(vec![command(b"used")]);
        let mut layout = root.using([used]);
        layout.override_commands(vec![command(b"mapped")]);
        let mut machine = Machine::new();
        crate::install_package_sources(
            &mut machine,
            &[super::super::PackageInstallSource::Resolved(&layout)],
        )
        .await
        .unwrap();
        assert_eq!(read(&machine, b"/bin/same").await, b"mapped");
        let defaults = machine.wasix1.names.lock().unwrap();
        assert_eq!(
            defaults
                .iter()
                .map(|(_, defaults)| defaults.argv0.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["root", "used", "mapped"]
        );
    }

    #[cfg(feature = "wasix1")]
    #[tokio::test]
    async fn unselected_malformed_defaults_are_tolerated_but_cli_can_validate_eagerly() {
        let mut package = loaded(archive(true)).await;
        let id = package.resolution.package.root_package.clone();
        let atom = OwnedBuffer::from_bytes(wat::parse_str("(module)").unwrap());
        let hash = wasmer_package::resolver::WebcHash::sha256(&atom).as_bytes();
        let metadata = serde_json::from_value(serde_json::json!({"runner":"https://webc.org/runner/wasi", "annotations":{"wasi":{"atom":"main","env":42}}})).unwrap();
        package
            .commands
            .push(wasmer_package::commands::BinaryPackageCommand::new(
                "ignored".to_owned(),
                metadata,
                atom,
                wasmer_package::commands::to_module_hash(webc::metadata::AtomSignature::Sha256(
                    hash,
                )),
                None,
                id.clone(),
                id,
            ));
        ResolvedLayout::new(&package, false, None).unwrap();
        assert!(ResolvedLayout::validate_command_annotations(&package).is_err());
    }
}
