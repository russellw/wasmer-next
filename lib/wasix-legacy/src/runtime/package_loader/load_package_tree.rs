use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Error};
use futures::{StreamExt, TryStreamExt};
use once_cell::sync::OnceCell;
use virtual_fs::{FileSystem, WebcVolumeFileSystem};
use wasmer_config::package::PackageId;
use webc::{Container, Volume};

use crate::{
    bin_factory::{BinaryPackage, BinaryPackageMount, BinaryPackageMounts},
    runtime::{
        package_loader::PackageLoader,
        resolver::{
            DependencyGraph, PackageSummary, Resolution, ResolvedFileSystemMapping, ResolvedPackage,
        },
    },
};

/// The maximum number of packages that will be loaded in parallel.
const MAX_PARALLEL_DOWNLOADS: usize = 32;

/// Given a fully resolved package, load it into memory for execution.
#[tracing::instrument(level = "debug", skip_all)]
pub async fn load_package_tree(
    root: &Container,
    loader: &dyn PackageLoader,
    resolution: &Resolution,
    root_is_local_dir: bool,
) -> Result<BinaryPackage, Error> {
    let webc_version = root.version();
    let mut containers = fetch_dependencies(loader, &resolution.package, &resolution.graph).await?;
    containers.insert(resolution.package.root_package.clone(), root.clone());
    let package_ids = containers.keys().cloned().collect();
    let fs_opt = filesystem(&containers, &resolution.package, root_is_local_dir)?;

    let root = &resolution.package.root_package;
    let commands = wasmer_package::commands::load_commands(&containers, resolution)?;

    let file_system_memory_footprint = if let Some(fs) = &fs_opt {
        count_package_mounts(fs)
    } else {
        0
    };

    let loaded = BinaryPackage {
        id: root.clone(),
        package_ids,
        webc_version,
        when_cached: crate::syscalls::platform_clock_time_get(
            wasmer_wasix_types::wasi::Snapshot0Clockid::Monotonic,
            1_000_000,
        )
        .ok()
        .map(|ts| ts as u128),
        hash: OnceCell::new(),
        entrypoint_cmd: resolution.package.entrypoint.clone(),
        package_mounts: fs_opt.map(Arc::new),
        commands,
        uses: Vec::new(),
        file_system_memory_footprint,

        additional_host_mapped_directories: vec![],
    };

    Ok(loaded)
}

async fn fetch_dependencies(
    loader: &dyn PackageLoader,
    pkg: &ResolvedPackage,
    graph: &DependencyGraph,
) -> Result<HashMap<PackageId, Container>, Error> {
    let packages = packages_needed_for_load(pkg);

    let packages = packages.into_iter().filter_map(|id| {
        let crate::runtime::resolver::Node { pkg, dist, .. } = &graph[&id];
        let summary = PackageSummary {
            pkg: pkg.clone(),
            dist: dist.clone()?,
        };
        Some((id, summary))
    });
    let packages: HashMap<PackageId, Container> = futures::stream::iter(packages)
        .map(|(id, s)| async move {
            match loader.load(&s).await {
                Ok(webc) => Ok((id, webc)),
                Err(e) => Err(e),
            }
        })
        .buffer_unordered(MAX_PARALLEL_DOWNLOADS)
        .try_collect()
        .await?;

    Ok(packages)
}

fn packages_needed_for_load(pkg: &ResolvedPackage) -> HashSet<PackageId> {
    let mut packages = HashSet::new();

    for loc in pkg.commands.values() {
        packages.insert(loc.package.clone());
    }

    for mapping in &pkg.filesystem {
        packages.insert(mapping.package.clone());
    }

    // We don't need to download the root package
    packages.remove(&pkg.root_package);

    packages
}

/// How many bytes worth of files does a directory contain?
fn count_file_system(fs: &dyn FileSystem, path: &Path) -> u64 {
    let mut total = 0;

    let dir = match fs.read_dir(path) {
        Ok(d) => d,
        Err(_err) => {
            return 0;
        }
    };

    for entry in dir.flatten() {
        if let Ok(meta) = entry.metadata() {
            total += meta.len();
            if meta.is_dir() {
                total += count_file_system(fs, entry.path.as_path());
            }
        }
    }

    total
}

fn count_package_mounts(mounts: &BinaryPackageMounts) -> u64 {
    let mut total = 0;

    if let Some(root_layer) = &mounts.root_layer {
        total += count_file_system(root_layer.as_ref(), Path::new("/"));
    }

    for mount in &mounts.mounts {
        total += count_file_system(mount.fs.as_ref(), Path::new("/"));
    }

    total
}

/// Given a set of [`ResolvedFileSystemMapping`]s and the [`Container`] for each
/// package in a dependency tree, construct the resulting filesystem.
///
/// Returns `Ok(None)` if no filesystem mappings were specified.
fn filesystem(
    packages: &HashMap<PackageId, Container>,
    pkg: &ResolvedPackage,
    root_is_local_dir: bool,
) -> Result<Option<BinaryPackageMounts>, Error> {
    if pkg.filesystem.is_empty() {
        return Ok(None);
    }

    let mut found_v2 = None;
    let mut found_v3 = None;

    for ResolvedFileSystemMapping { package, .. } in &pkg.filesystem {
        let container = packages.get(package).with_context(|| {
            format!(
                "\"{}\" wants to use the \"{}\" package, but it isn't in the dependency tree",
                pkg.root_package, package,
            )
        })?;

        match container.version() {
            webc::Version::V2 => {
                if found_v2.is_none() {
                    found_v2 = Some(package.clone());
                }
            }
            webc::Version::V3 => {
                if found_v3.is_none() {
                    found_v3 = Some(package.clone());
                }
            }
            other => {
                anyhow::bail!("the package '{package}' has an unknown webc version: {other}");
            }
        }
    }

    match (found_v2, found_v3) {
        (None, Some(_)) => filesystem_v3(packages, pkg, root_is_local_dir).map(Some),
        (Some(_), None) => filesystem_v2(packages, pkg, root_is_local_dir).map(Some),
        (Some(v2), Some(v3)) => {
            anyhow::bail!(
                "Mix of webc v2 and v3 in the same dependency tree is not supported; v2: {v2}, v3: {v3}"
            )
        }
        (None, None) => anyhow::bail!("Internal error: no packages found in tree"),
    }
}

/// Build the filesystem for webc v3 packages.
fn filesystem_v3(
    packages: &HashMap<PackageId, Container>,
    pkg: &ResolvedPackage,
    root_is_local_dir: bool,
) -> Result<BinaryPackageMounts, Error> {
    let mut volumes: HashMap<&PackageId, BTreeMap<String, Volume>> = HashMap::new();
    let mut root_layer = None;
    let mut mounts = Vec::new();

    for ResolvedFileSystemMapping {
        mount_path,
        volume_name,
        package,
        ..
    } in &pkg.filesystem
    {
        if *package == pkg.root_package && root_is_local_dir {
            continue;
        }

        if mount_path.as_path() == Path::new("/") {
            tracing::warn!(
                "The \"{package}\" package wants to mount a volume at \"/\", which breaks WASIX modules' filesystems",
            );
        }

        // Note: We want to reuse existing Volume instances if we can. That way
        // we can keep the memory usage down. A webc::compat::Volume is
        // reference-counted, anyway.
        // looks like we need to insert it
        let container = packages.get(package).with_context(|| {
            format!(
                "\"{}\" wants to use the \"{}\" package, but it isn't in the dependency tree",
                pkg.root_package, package,
            )
        })?;
        let container_volumes = match volumes.entry(package) {
            std::collections::hash_map::Entry::Occupied(entry) => &*entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => &*entry.insert(container.volumes()),
        };

        let volume = container_volumes.get(volume_name).with_context(|| {
            format!("The \"{package}\" package doesn't have a \"{volume_name}\" volume")
        })?;

        let webc_vol = WebcVolumeFileSystem::new(volume.clone());
        if mount_path.as_path() == Path::new("/") {
            root_layer = Some(Arc::new(webc_vol) as Arc<dyn FileSystem + Send + Sync>);
        } else {
            mounts.push(BinaryPackageMount {
                guest_path: mount_path.clone(),
                fs: Arc::new(webc_vol),
                source_path: PathBuf::from("/"),
            });
        }
    }

    Ok(BinaryPackageMounts { root_layer, mounts })
}

/// Build the filesystem for webc v2 packages.
///
// # Note to future readers
//
// Sooo... this code is a bit convoluted because we're constrained by the
// filesystem implementations we've got available.
//
// Ideally, we would create a WebcVolumeFileSystem for each volume we're
// using, then we'd have a single mount filesystem which lets you mount
// filesystem objects under various paths.
//
// The OverlayFileSystem lets us make files from multiple filesystem
// implementations available at the same time, however all of the
// filesystems will be mounted at "/", when the user wants to mount volumes
// at arbitrary locations.
//
// The TmpFileSystem *does* allow mounting at non-root paths, however it can't
// handle nested paths (e.g. mounting to "/lib" and "/lib/python3.10" - see
// <https://github.com/wasmerio/wasmer/issues/3678> for more) and you aren't
// allowed to mount to "/" because it's a special directory that already
// exists.
//
// As a result, we'll duct-tape things together and hope for the best 🤞
fn filesystem_v2(
    packages: &HashMap<PackageId, Container>,
    pkg: &ResolvedPackage,
    root_is_local_dir: bool,
) -> Result<BinaryPackageMounts, Error> {
    let mut volumes: HashMap<&PackageId, BTreeMap<String, Volume>> = HashMap::new();
    let mut root_layer = None;
    let mut mounts = Vec::new();

    for ResolvedFileSystemMapping {
        mount_path,
        volume_name,
        package,
        original_path,
    } in &pkg.filesystem
    {
        if *package == pkg.root_package && root_is_local_dir {
            continue;
        }

        if mount_path.as_path() == Path::new("/") {
            tracing::warn!(
                "The \"{package}\" package wants to mount a volume at \"/\", which breaks WASIX modules' filesystems",
            );
        }

        // Note: We want to reuse existing Volume instances if we can. That way
        // we can keep the memory usage down. A webc::compat::Volume is
        // reference-counted, anyway.
        let container_volumes = match volumes.entry(package) {
            std::collections::hash_map::Entry::Occupied(entry) => &*entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                // looks like we need to insert it
                let container = packages.get(package)
                    .with_context(|| format!(
                        "\"{}\" wants to use the \"{}\" package, but it isn't in the dependency tree",
                        pkg.root_package,
                        package,
                    ))?;
                &*entry.insert(container.volumes())
            }
        };

        let volume = container_volumes.get(volume_name).with_context(|| {
            format!("The \"{package}\" package doesn't have a \"{volume_name}\" volume")
        })?;

        let mounted_fs = Arc::new(WebcVolumeFileSystem::new(volume.clone()))
            as Arc<dyn FileSystem + Send + Sync>;
        let source_path = original_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));

        if mount_path.as_path() == Path::new("/") {
            root_layer = Some(mounted_fs);
        } else {
            mounts.push(BinaryPackageMount {
                guest_path: mount_path.clone(),
                fs: mounted_fs,
                source_path,
            });
        }
    }

    Ok(BinaryPackageMounts { root_layer, mounts })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        path::{Path, PathBuf},
    };

    use anyhow::Error;
    use ciborium::value::Value;
    use petgraph::graph::DiGraph;
    use virtual_fs::FileSystem;
    use wasmer_config::package::PackageId;
    use webc::{
        Container,
        indexmap::IndexMap,
        metadata::{
            Command as WebcCommand, Manifest,
            annotations::{
                Atom as AtomAnnotation, FileSystemMapping, FileSystemMappings, WASI_RUNNER_URI,
            },
        },
        v2::{
            SignatureAlgorithm,
            read::OwnedReader,
            write::{DirEntry, Directory, FileEntry, Writer},
        },
    };

    use super::{ResolvedFileSystemMapping, ResolvedPackage, filesystem_v2};
    use crate::runtime::{
        package_loader::PackageLoader,
        resolver::{
            Command, DependencyGraph, DistributionInfo, Edge, ItemLocation, Node, PackageInfo,
            PackageSummary, Resolution, WebcHash,
        },
    };

    #[derive(Debug, Default)]
    struct TestLoader;

    #[async_trait::async_trait]
    impl PackageLoader for TestLoader {
        async fn load(&self, summary: &PackageSummary) -> Result<Container, Error> {
            anyhow::bail!("unexpected dependency fetch: {}", summary.package_id())
        }

        async fn load_package_tree(
            &self,
            root: &Container,
            resolution: &Resolution,
            root_is_local_dir: bool,
        ) -> Result<crate::bin_factory::BinaryPackage, Error> {
            super::load_package_tree(root, self, resolution, root_is_local_dir).await
        }
    }

    #[test]
    fn v2_filesystem_mapping_resolves_mount_paths() {
        // Regression test: v2 fs mounts are already relative to the mount root,
        // so stripping the mount path again breaks lookups like /public.
        let mut manifest = Manifest::default();
        let fs = FileSystemMappings(vec![FileSystemMapping {
            from: None,
            volume_name: "atom".to_string(),
            host_path: Some("/public".to_string()),
            mount_path: "/public".to_string(),
        }]);
        let mut package = IndexMap::new();
        package.insert(
            FileSystemMappings::KEY.to_string(),
            Value::serialized(&fs).unwrap(),
        );
        manifest.package = package;

        let mut public_children = BTreeMap::new();
        public_children.insert(
            "index.html".parse().unwrap(),
            DirEntry::File(FileEntry::from(b"ok".as_slice())),
        );
        let public_mount_dir = Directory {
            children: public_children,
        };
        let mut root_children = BTreeMap::new();
        root_children.insert("public".parse().unwrap(), DirEntry::Dir(public_mount_dir));
        let atom_dir = Directory {
            children: root_children,
        };

        let writer = Writer::default().write_manifest(&manifest).unwrap();
        let writer = writer.write_atoms(BTreeMap::new()).unwrap();
        let writer = writer.with_volume("atom", atom_dir).unwrap();
        let bytes = writer.finish(SignatureAlgorithm::None).unwrap();

        let reader = OwnedReader::parse(bytes).unwrap();
        let container = Container::from(reader);

        let pkg_id = PackageId::new_named("ns/pkg", "0.1.0".parse().unwrap());
        let mut packages = HashMap::new();
        packages.insert(pkg_id.clone(), container);

        let pkg = ResolvedPackage {
            root_package: pkg_id.clone(),
            commands: BTreeMap::new(),
            entrypoint: None,
            filesystem: vec![ResolvedFileSystemMapping {
                mount_path: PathBuf::from("/public"),
                volume_name: "atom".to_string(),
                original_path: Some("/public".to_string()),
                package: pkg_id,
            }],
        };

        let mounts = filesystem_v2(&packages, &pkg, false).unwrap();
        let mount_fs = mounts.to_mount_fs().unwrap();
        assert!(mount_fs.metadata(Path::new("/public")).unwrap().is_dir());
        assert!(
            mount_fs
                .metadata(Path::new("/public/index.html"))
                .unwrap()
                .is_file()
        );
    }

    #[tokio::test]
    async fn load_package_tree_reports_shadowed_dependency_command_without_panic() {
        let root_id = PackageId::new_named("root", "0.1.0".parse().unwrap());
        let dep_id = PackageId::new_named("wasmer/static-web-server", "1.0.0".parse().unwrap());
        let dep_alias = "wasmer/static-web-server";

        let root_info = PackageInfo {
            id: root_id.clone(),
            commands: vec![Command {
                name: "webserver".to_string(),
            }],
            entrypoint: Some("webserver".to_string()),
            dependencies: Vec::new(),
            filesystem: Vec::new(),
        };
        let dep_info = PackageInfo {
            id: dep_id.clone(),
            commands: vec![Command {
                name: "webserver".to_string(),
            }],
            entrypoint: Some("webserver".to_string()),
            dependencies: Vec::new(),
            filesystem: Vec::new(),
        };
        let root_container = test_container([(
            "webserver",
            command_for_atom("webserver", Some(dep_alias.to_string())),
        )]);

        let mut graph = DiGraph::new();
        let root = graph.add_node(Node {
            id: root_id.clone(),
            pkg: root_info,
            dist: None,
        });
        let dep = graph.add_node(Node {
            id: dep_id.clone(),
            pkg: dep_info,
            dist: Some(DistributionInfo {
                webc: "http://localhost/wasmer-static-web-server.webc"
                    .parse()
                    .unwrap(),
                webc_sha256: WebcHash::from([0; 32]),
            }),
        });
        graph.add_edge(
            root,
            dep,
            Edge {
                alias: dep_alias.to_string(),
            },
        );

        let dependency_graph = DependencyGraph::new(
            root,
            graph,
            BTreeMap::from([(root_id.clone(), root), (dep_id.clone(), dep)]),
        );
        let pkg = ResolvedPackage {
            root_package: root_id.clone(),
            commands: BTreeMap::from([(
                "webserver".to_string(),
                ItemLocation {
                    name: "webserver".to_string(),
                    package: root_id.clone(),
                },
            )]),
            entrypoint: Some("webserver".to_string()),
            filesystem: Vec::new(),
        };

        let err = super::load_package_tree(
            &root_container,
            &TestLoader,
            &Resolution {
                package: pkg,
                graph: dependency_graph,
            },
            false,
        )
        .await
        .unwrap_err();
        let message = format!("{err:#}");

        assert!(message.contains("shadows an entry/command"));
        assert!(message.contains("Rename the local command"));
    }

    fn command_for_atom(atom: &str, dependency: Option<String>) -> WebcCommand {
        let mut annotations = IndexMap::new();
        annotations.insert(
            AtomAnnotation::KEY.to_string(),
            Value::serialized(&AtomAnnotation::new(atom, dependency)).unwrap(),
        );

        WebcCommand {
            runner: WASI_RUNNER_URI.to_string(),
            annotations,
        }
    }

    fn test_container<'a>(commands: impl IntoIterator<Item = (&'a str, WebcCommand)>) -> Container {
        let mut manifest = Manifest::default();

        for (name, command) in commands {
            manifest.commands.insert(name.to_string(), command);
        }

        let writer = Writer::default().write_manifest(&manifest).unwrap();
        let writer = writer.write_atoms(BTreeMap::new()).unwrap();
        let bytes = writer.finish(SignatureAlgorithm::None).unwrap();
        let reader = OwnedReader::parse(bytes).unwrap();
        Container::from(reader)
    }

    #[test]
    fn v2_filesystem_mapping_preserves_root_and_nested_mounts() {
        let mut manifest = Manifest::default();
        let fs = FileSystemMappings(vec![
            FileSystemMapping {
                from: None,
                volume_name: "root".to_string(),
                host_path: Some("/".to_string()),
                mount_path: "/".to_string(),
            },
            FileSystemMapping {
                from: None,
                volume_name: "public".to_string(),
                host_path: Some("/public".to_string()),
                mount_path: "/public".to_string(),
            },
        ]);
        let mut package = IndexMap::new();
        package.insert(
            FileSystemMappings::KEY.to_string(),
            Value::serialized(&fs).unwrap(),
        );
        manifest.package = package;

        let mut root_children = BTreeMap::new();
        root_children.insert(
            "root.txt".parse().unwrap(),
            DirEntry::File(FileEntry::from(b"root".as_slice())),
        );
        let root_dir = Directory {
            children: root_children,
        };

        let mut public_children = BTreeMap::new();
        public_children.insert(
            "index.html".parse().unwrap(),
            DirEntry::File(FileEntry::from(b"ok".as_slice())),
        );
        let public_dir = Directory {
            children: public_children,
        };

        let writer = Writer::default().write_manifest(&manifest).unwrap();
        let writer = writer.write_atoms(BTreeMap::new()).unwrap();
        let writer = writer.with_volume("root", root_dir).unwrap();
        let writer = writer.with_volume("public", public_dir).unwrap();
        let bytes = writer.finish(SignatureAlgorithm::None).unwrap();

        let reader = OwnedReader::parse(bytes).unwrap();
        let container = Container::from(reader);

        let pkg_id = PackageId::new_named("ns/pkg", "0.1.0".parse().unwrap());
        let mut packages = HashMap::new();
        packages.insert(pkg_id.clone(), container);

        let pkg = ResolvedPackage {
            root_package: pkg_id.clone(),
            commands: BTreeMap::new(),
            entrypoint: None,
            filesystem: vec![
                ResolvedFileSystemMapping {
                    mount_path: PathBuf::from("/"),
                    volume_name: "root".to_string(),
                    original_path: Some("/".to_string()),
                    package: pkg_id.clone(),
                },
                ResolvedFileSystemMapping {
                    mount_path: PathBuf::from("/public"),
                    volume_name: "public".to_string(),
                    original_path: Some("/public".to_string()),
                    package: pkg_id,
                },
            ],
        };

        let mounts = filesystem_v2(&packages, &pkg, false).unwrap();
        let root_layer = mounts
            .root_layer
            .as_ref()
            .expect("expected root layer mount");
        assert!(
            root_layer
                .metadata(Path::new("/root.txt"))
                .unwrap()
                .is_file()
        );
        assert_eq!(mounts.mounts.len(), 1);
        assert_eq!(mounts.mounts[0].guest_path, Path::new("/public"));
    }
}
