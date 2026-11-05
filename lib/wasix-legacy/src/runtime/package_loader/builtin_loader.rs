//! Legacy execution adapter for the shared package-container downloader.
use std::sync::Arc;

use anyhow::Error;
use webc::Container;

use crate::{
    bin_factory::BinaryPackage,
    http::HttpClient,
    runtime::{
        package_loader::PackageLoader,
        resolver::{PackageSummary, Resolution, WebcHash},
    },
};
use wasmer_package::loader::PackageDownloader;

pub use wasmer_package::loader::{
    CacheValidationMode, FileSystemCache, HashIntegrityValidationMode, ImageHashMismatchError,
    PackageCache,
};

/// Downloads containers and assembles them with the legacy execution adapter.
#[derive(Debug)]
pub struct BuiltinPackageLoader {
    downloader: PackageDownloader,
}

impl BuiltinPackageLoader {
    pub fn new() -> Self {
        Self {
            downloader: PackageDownloader::new(Arc::new(
                crate::http::default_http_client().unwrap(),
            )),
        }
    }

    pub fn with_hash_validation_mode(mut self, mode: HashIntegrityValidationMode) -> Self {
        self.downloader = self.downloader.with_hash_validation_mode(mode);
        self
    }

    pub fn with_cache_dir(mut self, cache_dir: impl Into<std::path::PathBuf>) -> Self {
        self.downloader = self.downloader.with_cache_dir(cache_dir);
        self
    }

    pub fn with_cache(mut self, cache: Arc<dyn PackageCache>) -> Self {
        self.downloader = self.downloader.with_cache(cache);
        self
    }

    pub fn without_in_memory_cache(mut self) -> Self {
        self.downloader = self.downloader.without_in_memory_cache();
        self
    }

    pub fn cache(&self) -> Option<&FileSystemCache> {
        self.downloader.cache()
    }

    pub fn validate_cache(
        &self,
        mode: CacheValidationMode,
    ) -> Result<Vec<ImageHashMismatchError>, Error> {
        self.downloader.validate_cache(mode)
    }

    pub fn with_http_client(self, client: impl HttpClient + Send + Sync + 'static) -> Self {
        self.with_shared_http_client(Arc::new(client))
    }

    pub fn with_shared_http_client(mut self, client: Arc<dyn HttpClient + Send + Sync>) -> Self {
        self.downloader = self.downloader.with_shared_http_client(client);
        self
    }

    pub fn with_tokens<I, K, V>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.downloader = self.downloader.with_tokens(tokens);
        self
    }

    pub fn with_token(mut self, hostname: impl Into<String>, token: impl Into<String>) -> Self {
        self.downloader = self.downloader.with_token(hostname, token);
        self
    }

    pub fn insert_cached(&self, hash: WebcHash, container: &Container) {
        self.downloader.insert_cached(hash, container);
    }

    pub fn evict_cached(&self, hash: &WebcHash) -> Option<Container> {
        self.downloader.evict_cached(hash)
    }
}

impl Default for BuiltinPackageLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PackageLoader for BuiltinPackageLoader {
    async fn load(&self, summary: &PackageSummary) -> Result<Container, Error> {
        self.downloader.load(summary).await
    }

    async fn load_package_tree(
        &self,
        root: &Container,
        resolution: &Resolution,
        root_is_local_dir: bool,
    ) -> Result<BinaryPackage, Error> {
        super::load_package_tree(root, self, resolution, root_is_local_dir).await
    }
}
