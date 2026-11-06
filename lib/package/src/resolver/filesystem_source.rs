use crate::utils::from_disk;
use anyhow::Context;
use wasmer_config::package::{PackageHash, PackageId, PackageSource};

use crate::resolver::{
    DistributionInfo, PackageInfo, PackageSummary, QueryError, Source, WebcHash,
};

/// A [`Source`] that knows how to query files on the filesystem.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileSystemSource {}

impl FileSystemSource {
    async fn load_path(path: &std::path::Path) -> Result<Vec<PackageSummary>, anyhow::Error> {
        let webc_sha256 = crate::resolver::block_in_place(|| WebcHash::for_file(path))
            .with_context(|| format!("Unable to hash \"{}\"", path.display()))?;
        let container = crate::resolver::block_in_place(|| from_disk(path))
            .with_context(|| format!("Unable to parse \"{}\"", path.display()))?;

        let url = crate::resolver::utils::url_from_file_path(path)
            .ok_or_else(|| anyhow::anyhow!("Unable to turn \"{}\" into a URL", path.display()))?;

        let id = PackageInfo::package_id_from_manifest(container.manifest())
            .context("Unable to determine the package's ID")?
            .unwrap_or_else(|| PackageId::from(PackageHash::from_sha256_bytes(webc_sha256.0)));

        let pkg = PackageInfo::from_manifest(id, container.manifest(), container.version())
            .context("Unable to determine the package's metadata")?;
        let summary = PackageSummary {
            pkg,
            dist: DistributionInfo {
                webc_size: None,
                webc: url,
                webc_sha256,
            },
        };

        Ok(vec![summary])
    }
}

#[async_trait::async_trait]
impl Source for FileSystemSource {
    #[tracing::instrument(target = "wasmer_wasix::runtime::resolver::filesystem_source", level = "debug", skip_all, fields(%package))]
    async fn query(&self, package: &PackageSource) -> Result<Vec<PackageSummary>, QueryError> {
        let path = match package {
            PackageSource::Path(path) => {
                let path = std::path::PathBuf::from(path);
                path.canonicalize()
                    .with_context(|| {
                        format!(
                            "Unable to get the canonical form for \"{}\"",
                            path.display()
                        )
                    })
                    .map_err(|error| QueryError::new_other(error, package))?
            }
            _ => {
                return Err(QueryError::Unsupported {
                    query: package.clone(),
                });
            }
        };

        Self::load_path(&path)
            .await
            .map_err(|error| QueryError::new_other(error, package))
    }
}
