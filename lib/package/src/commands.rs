//! Resolved package-command bytes and their manifest metadata.
use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Error};
use petgraph::visit::EdgeRef;
use wasmer_config::package::PackageId;
use wasmer_types::ModuleHash;
use webc::{Container, compat::SharedBytes, metadata::annotations::Atom as AtomAnnotation};

use crate::{
    resolver::{ItemLocation, Resolution},
    utils::wasm_annotations_to_features,
};

#[derive(derive_more::Debug, Clone)]
pub struct BinaryPackageCommand {
    name: String,
    metadata: webc::metadata::Command,
    #[debug(ignore)]
    pub(crate) atom: SharedBytes,
    hash: ModuleHash,
    features: Option<wasmer_types::Features>,
    /// Package that declares this command in the resolved manifest graph.
    ///
    /// This identifies "who owns the command name" (the package that exposes
    /// the command entry), even if execution uses an atom from another package.
    package: PackageId,
    /// Package that provides the module this command actually executes.
    ///
    /// Usually this matches `package`. It differs when the command's atom
    /// annotation points at a dependency, so the command is declared by one
    /// package but runs code from another package.
    origin_package: PackageId,
}

impl BinaryPackageCommand {
    pub fn new(
        name: String,
        metadata: webc::metadata::Command,
        atom: SharedBytes,
        hash: ModuleHash,
        features: Option<wasmer_types::Features>,
        package: PackageId,
        origin_package: PackageId,
    ) -> Self {
        Self {
            name,
            metadata,
            atom,
            hash,
            features,
            package,
            origin_package,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn metadata(&self) -> &webc::metadata::Command {
        &self.metadata
    }

    /// Get a reference to this [`BinaryPackageCommand`]'s atom as a cheap
    /// clone of the internal OwnedBuffer.
    pub fn atom(&self) -> SharedBytes {
        self.atom.clone()
    }

    /// Get a reference to this [`BinaryPackageCommand`]'s atom as a cheap
    /// clone of the internal OwnedBuffer.
    pub fn atom_ref(&self) -> &SharedBytes {
        &self.atom
    }

    pub fn hash(&self) -> &ModuleHash {
        &self.hash
    }

    pub fn package(&self) -> &PackageId {
        &self.package
    }

    pub fn origin_package(&self) -> &PackageId {
        &self.origin_package
    }

    /// Get the WebAssembly features required by this command's module
    pub fn wasm_features(&self) -> Option<wasmer_types::Features> {
        // Return only the pre-computed features from the container manifest
        if let Some(features) = &self.features {
            return Some(features.clone());
        }

        // If no annotations were found, return None
        None
    }
}

/// Convert WebAssembly feature annotations to a Features object
fn wasm_annotation_to_features(
    wasm_annotation: &webc::metadata::annotations::Wasm,
) -> Option<wasmer_types::Features> {
    Some(wasm_annotations_to_features(&wasm_annotation.features))
}

/// Extract WebAssembly features from atom metadata if available
fn extract_features_from_atom_metadata(
    atom_metadata: &webc::metadata::Atom,
) -> Option<wasmer_types::Features> {
    if let Ok(Some(wasm_annotation)) = atom_metadata
        .annotation::<webc::metadata::annotations::Wasm>(webc::metadata::annotations::Wasm::KEY)
    {
        wasm_annotation_to_features(&wasm_annotation)
    } else {
        None
    }
}

/// Load the commands selected by a resolved dependency graph, preserving resolver order.
pub fn load_commands(
    containers: &HashMap<PackageId, Container>,
    resolution: &Resolution,
) -> Result<Vec<BinaryPackageCommand>, Error> {
    commands(&resolution.package.commands, containers, resolution)
}

/// Convert the package's signed atom digest to the module-cache hash.
pub fn to_module_hash(value: webc::metadata::AtomSignature) -> ModuleHash {
    match value {
        webc::metadata::AtomSignature::Sha256(bytes) => ModuleHash::from_bytes(bytes),
    }
}

fn commands(
    commands: &BTreeMap<String, ItemLocation>,
    containers: &HashMap<PackageId, Container>,
    resolution: &Resolution,
) -> Result<Vec<BinaryPackageCommand>, Error> {
    let mut pkg_commands = Vec::new();

    for (
        name,
        ItemLocation {
            name: original_name,
            package,
        },
    ) in commands
    {
        let webc = containers.get(package).with_context(|| {
            format!("Unable to find the \"{package}\" package for the \"{name}\" command")
        })?;
        let manifest = webc.manifest();
        let command_metadata = manifest.commands.get(original_name).with_context(|| {
            format!(
                "Unable to find the \"{original_name}\" command metadata in the \"{package}\" package"
            )
        })?;

        if let Some(cmd) =
            load_binary_command(package, name, command_metadata, containers, resolution)?
        {
            pkg_commands.push(cmd);
        }
    }

    Ok(pkg_commands)
}

/// Given a [`webc::metadata::Command`], figure out which atom it uses and load
/// that atom into a [`BinaryPackageCommand`].
#[tracing::instrument(target = "wasmer_wasix::runtime::package_loader::load_package_tree", skip_all, fields(%package_id, %command_name))]
fn load_binary_command(
    package_id: &PackageId,
    command_name: &str,
    cmd: &webc::metadata::Command,
    containers: &HashMap<PackageId, Container>,
    resolution: &Resolution,
) -> Result<Option<BinaryPackageCommand>, anyhow::Error> {
    let AtomAnnotation {
        name: atom_name,
        dependency,
        ..
    } = match atom_name_for_command(command_name, cmd)? {
        Some(name) => name,
        None => {
            tracing::event!(target: "wasmer_wasix::runtime::package_loader::load_package_tree", tracing::Level::WARN,
                cmd.name=command_name,
                cmd.runner=%cmd.runner,
                "Skipping unsupported command",
            );
            return Ok(None);
        }
    };

    let package = containers
        .get(package_id)
        .with_context(|| format!("Unable to find the \"{package_id}\" package"))?;

    let (webc, resolved_package_id) = match dependency {
        Some(dep) => {
            let ix = resolution
                .graph
                .packages()
                .get(package_id)
                .copied()
                .unwrap();
            let graph = resolution.graph.graph();
            let edge_reference = graph
                .edges_directed(ix, petgraph::Direction::Outgoing)
                .find(|edge| edge.weight().alias == dep)
                .with_context(|| format!("Unable to find the \"{dep}\" dependency for the \"{command_name}\" command in \"{package_id}\""))?;

            let other_package = graph.node_weight(edge_reference.target()).unwrap();
            let id = &other_package.id;

            tracing::event!(target: "wasmer_wasix::runtime::package_loader::load_package_tree", tracing::Level::DEBUG,
                dependency=%dep,
                resolved_package_id=%id,
                "command atom resolution: resolved dependency",
            );
            let container = containers.get(id).ok_or_else(|| {
                anyhow::anyhow!(
                    "The \"{command_name}\" command in \"{package_id}\" shadows an entry/command of the \"{dep}\" dependency. Rename the local command."
                )
            })?;

            (container, id)
        }
        None => (package, package_id),
    };

    let atom = webc.get_atom(&atom_name);

    if atom.is_none() && cmd.annotations.is_empty() {
        tracing::event!(target: "wasmer_wasix::runtime::package_loader::load_package_tree", tracing::Level::INFO, "applying legacy atom hack");
        return legacy_atom_hack(webc, package_id, command_name, cmd);
    }

    let hash = to_module_hash(webc.manifest().atom_signature(&atom_name)?);

    let atom = atom.with_context(|| {

        let available_atoms = webc.atoms().keys().map(|x| x.as_str()).collect::<Vec<_>>().join(",");

        tracing::event!(target: "wasmer_wasix::runtime::package_loader::load_package_tree", tracing::Level::WARN,
            %atom_name,
            %resolved_package_id,
            %available_atoms,
            "invalid command: could not find atom in package",
        );

        format!(
            "The '{command_name}' command uses the '{atom_name}' atom, but it isn't present in the package: {resolved_package_id})"
        )
    })?;

    // Get WebAssembly features from manifest atom annotations
    let features = if let Some(atom_metadata) = webc.manifest().atoms.get(&atom_name) {
        extract_features_from_atom_metadata(atom_metadata)
    } else {
        None
    };

    let cmd = BinaryPackageCommand::new(
        command_name.to_string(),
        cmd.clone(),
        atom,
        hash,
        features,
        package_id.clone(),
        resolved_package_id.clone(),
    );

    Ok(Some(cmd))
}

fn atom_name_for_command(
    command_name: &str,
    cmd: &webc::metadata::Command,
) -> Result<Option<AtomAnnotation>, anyhow::Error> {
    use webc::metadata::annotations::{WASI_RUNNER_URI, WCGI_RUNNER_URI};

    if let Some(atom) = cmd
        .atom()
        .context("Unable to deserialize atom annotations")?
    {
        return Ok(Some(atom));
    }

    if [WASI_RUNNER_URI, WCGI_RUNNER_URI]
        .iter()
        .any(|uri| cmd.runner.starts_with(uri))
    {
        // Note: We use the command name as the atom name as a special case
        // for known runner types because sometimes people will construct
        // a manifest by hand instead of using wapm2pirita.
        tracing::event!(target: "wasmer_wasix::runtime::package_loader::load_package_tree", tracing::Level::DEBUG,
            command = command_name,
            "No annotations specifying the atom name found. Falling back to the command name"
        );
        return Ok(Some(AtomAnnotation::new(command_name, None)));
    }

    Ok(None)
}

/// HACK: Some older packages like `sharrattj/bash` and `sharrattj/coreutils`
/// contain commands with no annotations. When this happens, you can just assume
/// it wants to use the first atom in the WEBC file.
///
/// That works because most of these packages only have a single atom (e.g. in
/// `sharrattj/coreutils` there are commands for `ls`, `pwd`, and so on, but
/// under the hood they all use the `coreutils` atom).
///
/// See <https://github.com/wasmerio/wasmer/commit/258903140680716da1431d92bced67d486865aeb>
/// for more.
fn legacy_atom_hack(
    webc: &Container,
    package_id: &PackageId,
    command_name: &str,
    metadata: &webc::metadata::Command,
) -> Result<Option<BinaryPackageCommand>, anyhow::Error> {
    let (name, atom) = webc
        .atoms()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::Error::msg("container does not have any atom"))?;

    tracing::event!(target: "wasmer_wasix::runtime::package_loader::load_package_tree", tracing::Level::DEBUG,
        command_name,
        atom.name = name.as_str(),
        atom.len = atom.len(),
        "(hack) The command metadata is malformed. Falling back to the first atom in the WEBC file",
    );

    let hash = to_module_hash(webc.manifest().atom_signature(&name)?);

    // Get WebAssembly features from manifest atom annotations
    let features = if let Some(atom_metadata) = webc.manifest().atoms.get(&name) {
        extract_features_from_atom_metadata(atom_metadata)
    } else {
        None
    };

    Ok(Some(BinaryPackageCommand::new(
        command_name.to_string(),
        metadata.clone(),
        atom,
        hash,
        features,
        package_id.clone(),
        package_id.clone(),
    )))
}
