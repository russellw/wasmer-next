//! Serializable host-directory mount configuration.

/// The historical guest path used when mapping the host's current directory.
pub const MAPPED_CURRENT_DIR_DEFAULT_PATH: &str = "/home";

/// A host directory and the guest path at which it is mounted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MappedDirectory {
    /// The absolute path for a directory on the host filesystem.
    pub host: std::path::PathBuf,
    /// The absolute path specifying where the host directory should be mounted
    /// inside the guest.
    pub guest: String,
}
