#[cfg(not(feature = "napi-v8"))]
use crate::compiler::CompilationOwner;
use crate::package_progress::{Progress, SharedPackageLoader, observe};
use crate::{
    Error, Package, PackageDefinition, PackageLoadOptions, PackageSource, Result, SandboxBuilder,
    sandbox::SandboxInner, service::Services,
};
use sha2::Digest;
use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use wasmer::Engine;
use wasmer_config::package::{PackageHash, PackageId, PackageSource as WasmerPackageSource};
use wasmer_package::{
    http::{HttpClient, reqwest::ReqwestHttpClient},
    loader::{LoadedPackage, PackageDownloader, fetch_dependencies},
    resolver::{BackendSource, MultiSource, PackageInfo, Resolution, Source, resolve},
};
use webc::Container;

const REGISTRY_QUERY_CACHE_TTL: Duration = Duration::from_mins(10);

/// Persistent cache configuration.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub root: PathBuf,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from(".wasmer"),
        }
    }
}
/// Client-wide SDK configuration.
#[derive(Clone, Debug)]
pub struct WasmerConfig {
    pub cache: CacheConfig,
    /// Maximum bytes retained from each captured output stream.
    pub output_bytes: usize,
}
impl Default for WasmerConfig {
    fn default() -> Self {
        Self {
            cache: CacheConfig::default(),
            output_bytes: 16 * 1024 * 1024,
        }
    }
}
/// Shared entry point for package and sandbox services.
#[derive(Clone)]
pub struct Wasmer {
    pub(crate) inner: Arc<ClientInner>,
}
/// Package acquisition operations for one [`Wasmer`] client.
#[derive(Clone, Debug)]
pub struct Packages {
    client: Wasmer,
}
/// Sandbox creation operations for one [`Wasmer`] client.
#[derive(Clone, Debug)]
pub struct Sandboxes {
    client: Wasmer,
}
pub(crate) struct ClientInner {
    pub(crate) services: Services,
    pub(crate) engine: Engine,
    #[cfg(not(feature = "napi-v8"))]
    pub(crate) compilation: Arc<CompilationOwner>,
    #[cfg(feature = "napi-v8")]
    pub(crate) compiled_cache: PathBuf,
    pub(crate) output_bytes: usize,
    pub(crate) sandboxes: Mutex<Vec<Weak<SandboxInner>>>,
    source: Arc<dyn Source + Send + Sync>,
    registry_packages: RwLock<HashMap<String, Package>>,
    loader: Arc<SharedPackageLoader>,
    closed: AtomicBool,
    close_started: AtomicBool,
    close_result: tokio::sync::watch::Sender<Option<std::result::Result<(), String>>>,
}
impl std::fmt::Debug for Wasmer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wasmer")
            .field("closed", &self.inner.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}
impl Wasmer {
    pub fn new() -> Result<Self> {
        Self::with_config(WasmerConfig::default())
    }
    pub fn with_config(config: WasmerConfig) -> Result<Self> {
        let services = Services::new()?;
        let handle = services.handle();
        let http_client = {
            let _entered = handle.enter();
            Arc::new(ReqwestHttpClient::default())
        };
        Self::assemble(config, http_client, services)
    }
    #[cfg(test)]
    fn new_with_http_client(
        config: WasmerConfig,
        http_client: Arc<dyn HttpClient + Send + Sync>,
    ) -> Result<Self> {
        Self::assemble(config, http_client, Services::new()?)
    }
    fn assemble(
        config: WasmerConfig,
        http_client: Arc<dyn HttpClient + Send + Sync>,
        services: Services,
    ) -> Result<Self> {
        let root = absolutize(config.cache.root)?;
        let package_cache = root.join("cache-v1/packages");
        let registry_cache = root.join("cache-v1/registry");
        let compiled_cache = root
            .join("cache-v1/compiled")
            .join(target_identity())
            .join(engine_identity());
        for directory in [&package_cache, &registry_cache, &compiled_cache] {
            std::fs::create_dir_all(directory).map_err(|error| Error::Initialization {
                message: format!(
                    "unable to create cache directory `{}`: {error}",
                    directory.display()
                ),
            })?;
        }
        #[cfg(not(feature = "napi-v8"))]
        let compilation = CompilationOwner::new(&compiled_cache, services.handle());
        let mut source = MultiSource::new();
        source.add_source(
            BackendSource::new(
                BackendSource::WASMER_PROD_ENDPOINT.parse().unwrap(),
                http_client.clone(),
            )
            .with_local_cache(registry_cache, REGISTRY_QUERY_CACHE_TTL),
        );
        let downloader = PackageDownloader::new(http_client).with_cache_dir(package_cache);
        Ok(Self {
            inner: Arc::new(ClientInner {
                services,
                engine: Engine::default(),
                #[cfg(not(feature = "napi-v8"))]
                compilation,
                #[cfg(feature = "napi-v8")]
                compiled_cache,
                output_bytes: config.output_bytes,
                sandboxes: Mutex::default(),
                source: Arc::new(source),
                loader: Arc::new(SharedPackageLoader::new(Arc::new(downloader))),
                registry_packages: RwLock::default(),
                closed: AtomicBool::new(false),
                close_started: AtomicBool::new(false),
                close_result: tokio::sync::watch::channel(None).0,
            }),
        })
    }
    #[must_use]
    pub fn packages(&self) -> Packages {
        Packages {
            client: self.clone(),
        }
    }
    #[must_use]
    pub fn sandboxes(&self) -> Sandboxes {
        Sandboxes {
            client: self.clone(),
        }
    }
    #[deprecated(note = "use `wasmer.packages().load(source)`")]
    pub async fn load_package(&self, source: impl Into<PackageSource>) -> Result<Package> {
        self.packages().load(source).await
    }
    #[must_use]
    #[deprecated(note = "use `wasmer.sandboxes().create()`")]
    pub fn sandbox(&self) -> SandboxBuilder {
        self.sandboxes().create()
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        if !self.inner.close_started.swap(true, Ordering::AcqRel) {
            let client = self.clone();
            let completed = self.inner.close_result.clone();
            let sandboxes: Vec<_> = self
                .inner
                .sandboxes
                .lock()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .map(|inner| crate::Sandbox { inner })
                .collect();
            // Revoke every sandbox before joining any one provider. A slow
            // callback in one sandbox must not leave a sibling guest running.
            for sandbox in &sandboxes {
                sandbox.begin_close();
            }
            if let Err(error) = self.inner.services.cleanup(async move {
                let mut failure = None;
                for sandbox in sandboxes {
                    if let Err(error) = sandbox.close().await {
                        failure.get_or_insert_with(|| error.to_string());
                    }
                }
                completed.send_replace(Some(failure.map_or(Ok(()), Err)));
                // The retained cleanup task releases its service lease after this
                // cutoff. Subscribers independently await the actual service exit.
                client.inner.services.request_close();
                Ok(())
            }) {
                self.inner
                    .close_result
                    .send_replace(Some(Err(error.to_string())));
            }
        }
        let mut completed = self.inner.close_result.subscribe();
        let result = loop {
            {
                let value = completed.borrow_and_update().clone();
                if let Some(result) = value {
                    break result;
                }
            }
            completed.changed().await.map_err(|_| Error::Task {
                message: "client close owner stopped".into(),
            })?;
        };
        let services = self.inner.services.close().await;
        result.map_err(|message| Error::Execution { message })?;
        services
    }
    pub(crate) fn ensure_open(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            Err(Error::ClientClosed)
        } else {
            Ok(())
        }
    }
    async fn load_package_observed(
        &self,
        source: PackageSource,
        progress: Option<Progress>,
    ) -> Result<Package> {
        self.ensure_open()?;
        let _admission = self.inner.services.admit()?;
        if let PackageSource::Package(package) = source {
            if let Some(progress) = &progress {
                progress.local(&package, true);
            }
            return Ok(package);
        }
        let label = source.label();
        let loader = progress.map_or_else(
            || self.inner.loader.clone(),
            |p| Arc::new(self.inner.loader.observing(p)),
        );
        let result: anyhow::Result<Package> = async {
            match source {
                PackageSource::Registry(specifier) => {
                    let parsed = WasmerPackageSource::from_str(&specifier).map_err(|error| {
                        Error::InvalidPackageSource {
                            package_source: specifier.clone(),
                            message: error.to_string(),
                        }
                    })?;
                    let key = parsed.to_string();
                    if let Some(package) = self
                        .inner
                        .registry_packages
                        .read()
                        .unwrap()
                        .get(&key)
                        .cloned()
                    {
                        if let Some(progress) = loader.progress() {
                            progress.local(&package, true);
                        }
                        return Ok(package);
                    }
                    let summary = self.inner.source.latest(&parsed).await?;
                    let resolution =
                        resolve(&summary.pkg.id, &summary.pkg, self.inner.source.as_ref()).await?;
                    // Register this root's selected closure before any artifact
                    // download; aliases retire their own resolution before sharing it.
                    loader.resolved(Some(&summary), &resolution);
                    let root = loader.load(&summary).await?;
                    let package = self
                        .finish_package(root, resolution, false, vec![], &loader)
                        .await?;
                    self.ensure_open()?;
                    let mut cache = self.inner.registry_packages.write().unwrap();
                    Ok(cache.entry(key).or_insert(package).clone())
                }
                PackageSource::Path(path) if path.is_dir() => {
                    let manifest = path.join("wasmer.toml");
                    let root: Container =
                        wasmer_package::package::Package::from_manifest(&manifest)?.into();
                    let id = PackageId::Hash(PackageHash::from_sha256_bytes(
                        sha2::Sha256::digest(path.display().to_string().as_bytes()).into(),
                    ));
                    let info =
                        PackageInfo::from_manifest(id.clone(), root.manifest(), root.version())?;
                    let resolution = resolve(&id, &info, self.inner.source.as_ref()).await?;
                    loader.resolved(None, &resolution);
                    let text = std::fs::read_to_string(&manifest)?;
                    let manifest: wasmer_config::package::Manifest = toml::from_str(&text)?;
                    let mounts = manifest
                        .fs
                        .into_iter()
                        .map(|(guest, host)| Ok((guest, path.join(host).canonicalize()?)))
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    self.finish_package(root, resolution, true, mounts, &loader)
                        .await
                }
                PackageSource::Path(path) => {
                    self.load_container(wasmer_package::utils::from_disk(path)?, &loader)
                        .await
                }
                PackageSource::Bytes(bytes) if bytes.starts_with(b"\0asm") => {
                    let package = PackageDefinition::from_wasm(bytes).into_package().await?;
                    if let Some(progress) = loader.progress() {
                        progress.local(&package, false);
                    }
                    Ok(package)
                }
                PackageSource::Bytes(bytes) | PackageSource::Webc(bytes) => {
                    self.load_container(wasmer_package::utils::from_bytes(bytes)?, &loader)
                        .await
                }
                PackageSource::Package(_) => unreachable!(),
            }
        }
        .await;
        if result.is_ok() {
            self.ensure_open()?;
        }
        result.map_err(|error| match error.downcast::<Error>() {
            Ok(error) => error,
            Err(error) => Error::PackageLoad {
                package_source: label,
                message: format!("{error:#}"),
            },
        })
    }
    async fn load_container(
        &self,
        root: Container,
        loader: &SharedPackageLoader,
    ) -> anyhow::Result<Package> {
        only_v3(&root)?;
        let id = PackageInfo::package_id_from_manifest(root.manifest())?
            .or_else(|| {
                root.webc_hash()
                    .map(|hash| PackageId::Hash(PackageHash::from_sha256_bytes(hash)))
            })
            .ok_or_else(|| anyhow::anyhow!("webc file did not provide its hash"))?;
        let info = PackageInfo::from_manifest(id.clone(), root.manifest(), root.version())?;
        let resolution = resolve(&id, &info, self.inner.source.as_ref()).await?;
        loader.resolved(None, &resolution);
        self.finish_package(root, resolution, false, vec![], loader)
            .await
    }
    async fn finish_package(
        &self,
        root: Container,
        resolution: Resolution,
        local: bool,
        host_mounts: Vec<(String, PathBuf)>,
        loader: &SharedPackageLoader,
    ) -> anyhow::Result<Package> {
        only_v3(&root)?;
        let mut containers = fetch_dependencies(
            &resolution.package,
            &resolution.graph,
            |summary| async move {
                let container = loader.load(&summary).await?;
                only_v3(&container)?;
                Ok(container)
            },
        )
        .await?;
        containers.insert(resolution.package.root_package.clone(), root);
        wasixv2::preflight_resolved_filesystem(&containers, &resolution.package, local)?;
        let loaded = LoadedPackage::from_containers(resolution, containers)?;
        Ok(Package::from_loaded(loaded, local, host_mounts)?)
    }
}
fn only_v3(container: &Container) -> anyhow::Result<()> {
    if container.version() != webc::Version::V3 {
        anyhow::bail!(
            "unsupported WEBC version {}; only WebC v3 is supported",
            container.version()
        );
    }
    Ok(())
}

impl Packages {
    /// Create a reusable executable package from module bytes and bundled files.
    ///
    /// Does not serialize a WEBC archive, compile modules, or access the registry.
    /// Modules are compiled when a command is executed.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is closed, the definition is invalid,
    /// a module cannot be decoded, or the bundled filesystem cannot be created.
    pub async fn create(&self, definition: PackageDefinition) -> Result<Package> {
        self.client.ensure_open()?;
        definition.into_package().await
    }

    /// Resolve a registry, local, or in-memory package.
    ///
    /// In-memory bytes can contain WEBC or a raw WASI/WASIX module. Raw modules
    /// must export `_start` and get a single command and entrypoint named `main`.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is closed, the source is invalid, package
    /// acquisition fails, or the package cannot be decoded and resolved.
    pub async fn load(&self, source: impl Into<PackageSource>) -> Result<Package> {
        self.load_with_options(source, PackageLoadOptions::default())
            .await
    }

    /// Load one package with operation-scoped progress and cancellation.
    pub async fn load_with_options(
        &self,
        source: impl Into<PackageSource>,
        options: PackageLoadOptions,
    ) -> Result<Package> {
        Ok(self
            .load_many_with_options([source.into()], options)
            .await?
            .remove(0))
    }

    /// Load packages concurrently, preserving input order and sharing downloads.
    pub async fn load_many(
        &self,
        sources: impl IntoIterator<Item = impl Into<PackageSource>>,
    ) -> Result<Vec<Package>> {
        self.load_many_with_options(sources, PackageLoadOptions::default())
            .await
    }

    pub async fn load_many_with_options(
        &self,
        sources: impl IntoIterator<Item = impl Into<PackageSource>>,
        options: PackageLoadOptions,
    ) -> Result<Vec<Package>> {
        use futures::{StreamExt, TryStreamExt};
        self.client.ensure_open()?;
        let sources: Vec<PackageSource> = sources.into_iter().map(Into::into).collect();
        let progress = options
            .observer
            .as_ref()
            .map(|_| Progress::new(sources.len()));
        let work = futures::stream::iter(sources)
            .map(|source| self.client.load_package_observed(source, progress.clone()))
            .buffered(32)
            .try_collect();
        observe(options, progress.clone(), work).await
    }
}

impl Sandboxes {
    /// Begin creating a sandbox.
    ///
    /// Configure the returned builder and await it to finish creation.
    #[must_use]
    pub fn create(&self) -> SandboxBuilder {
        SandboxBuilder::new(self.client.clone())
    }
}

#[cfg(feature = "sys")]
fn absolutize(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(|error| Error::Initialization {
            message: format!("unable to determine the current directory: {error}"),
        })
}

#[cfg(feature = "sys")]
fn target_identity() -> String {
    format!(
        "{}-{}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::env::consts::FAMILY
    )
}

fn engine_identity() -> &'static str {
    "cranelift"
}

#[cfg(all(test, feature = "sys"))]
mod tests {
    use std::{
        collections::VecDeque,
        path::Path,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use futures::future::BoxFuture;
    use http::{HeaderMap, StatusCode};
    use tempfile::TempDir;
    use wasmer_package::{
        http::{HttpClient, HttpRequest, HttpResponse},
        resolver::WebcHash,
    };

    use super::{CacheConfig, Wasmer, WasmerConfig};

    #[derive(Debug, Default)]
    struct MockHttpClient {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: AtomicUsize,
    }

    impl MockHttpClient {
        fn new(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: AtomicUsize::new(0),
            }
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::Acquire)
        }
    }

    impl HttpClient for MockHttpClient {
        fn request(&self, _request: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            self.requests.fetch_add(1, Ordering::AcqRel);
            let response = self
                .responses
                .lock()
                .expect("mock response lock poisoned")
                .pop_front();
            Box::pin(
                async move { response.ok_or_else(|| anyhow::anyhow!("unexpected HTTP request")) },
            )
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn registry_metadata_and_packages_survive_a_fresh_client() {
        let fixture = TempDir::new().expect("create package fixture");
        let webc = registry_fixture(fixture.path());
        let hash = WebcHash::sha256(&webc);
        let container =
            wasmer_package::utils::from_bytes(webc.clone()).expect("decode package fixture");
        let manifest = serde_json::to_string(container.manifest()).expect("serialize manifest");
        let release = serde_json::json!({
            "version": "1.0.0",
            "isArchived": false,
            "v2": {
                "webcManifest": manifest,
                "piritaDownloadUrl": "https://packages.test/cache.webc",
                "piritaSha256Hash": hash.as_hex(),
            },
            "v3": {
                "webcManifest": manifest,
                "piritaDownloadUrl": "https://packages.test/cache.webc",
                "piritaSha256Hash": hash.as_hex(),
            },
        });
        let registry_response = HttpResponse {
            body: Some(
                serde_json::to_vec(&serde_json::json!({
                    "data": {
                        "getPackage": {
                            "packageName": "cache",
                            "namespace": "sdk-test",
                            "versions": [release],
                        },
                        "info": {
                            "defaultFrontend": "https://wasmer.io/",
                        },
                    },
                }))
                .expect("serialize registry response"),
            ),
            redirected: false,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        let package_response = HttpResponse {
            body: Some(webc.to_vec()),
            redirected: false,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };

        let state = TempDir::new().expect("create cache fixture");
        let config = WasmerConfig {
            cache: CacheConfig {
                root: state.path().join(".wasmer"),
            },
            ..WasmerConfig::default()
        };
        let online = Arc::new(MockHttpClient::new([registry_response, package_response]));
        let client = Wasmer::new_with_http_client(config.clone(), online.clone());
        let client = client.expect("create online client");
        let first = client
            .packages()
            .load("sdk-test/cache@1.0.0")
            .await
            .expect("load registry package");
        let in_memory = client
            .packages()
            .load("sdk-test/cache@1.0.0")
            .await
            .expect("reuse loaded registry package");

        assert!(Arc::ptr_eq(&first.inner, &in_memory.inner));
        assert_eq!(online.requests(), 2);
        drop(first);
        drop(in_memory);
        drop(client);

        let offline = Arc::new(MockHttpClient::default());
        let client = Wasmer::new_with_http_client(config, offline.clone())
            .expect("create cache-only client");
        let cached = client
            .packages()
            .load("sdk-test/cache@1.0.0")
            .await
            .expect("load registry package entirely from disk");

        assert_eq!(cached.id(), "sdk-test/cache@1.0.0");
        assert_eq!(offline.requests(), 0);
        assert!(state.path().join(".wasmer/cache-v1/registry").is_dir());
        assert!(
            state
                .path()
                .join(".wasmer/cache-v1/packages")
                .join(format!("{}.bin", hash.as_hex()))
                .is_file()
        );
    }

    #[derive(Debug)]
    struct StreamingHttp {
        metadata: Vec<u8>,
        bytes: Vec<u8>,
        downloads: AtomicUsize,
        cancelled: Arc<AtomicUsize>,
    }
    impl HttpClient for StreamingHttp {
        fn request(&self, _request: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            Box::pin(async {
                Ok(HttpResponse {
                    body: Some(self.metadata.clone()),
                    redirected: false,
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                })
            })
        }
        fn request_with_body_progress(
            &self,
            _request: HttpRequest,
            progress: wasmer_package::http::HttpBodyObserver,
        ) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            Box::pin(async move {
                self.downloads.fetch_add(1, Ordering::SeqCst);
                struct DropCount(Arc<AtomicUsize>, bool);
                impl Drop for DropCount {
                    fn drop(&mut self) {
                        if !self.1 {
                            self.0.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                let mut guard = DropCount(self.cancelled.clone(), false);
                let headers = HeaderMap::new();
                progress(wasmer_package::http::HttpBodyEvent::Head {
                    status: StatusCode::OK,
                    headers: &headers,
                    cached: false,
                });
                let mut body = Vec::with_capacity(self.bytes.len());
                let chunk = self.bytes.len().div_ceil(4);
                for end in (chunk..self.bytes.len())
                    .step_by(chunk)
                    .chain([self.bytes.len()])
                {
                    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                    let chunk = &self.bytes[body.len()..end];
                    body.extend_from_slice(chunk);
                    progress(wasmer_package::http::HttpBodyEvent::Chunk(chunk));
                }
                guard.1 = true;
                Ok(HttpResponse {
                    body: Some(body),
                    redirected: false,
                    status: StatusCode::OK,
                    headers,
                })
            })
        }
    }

    fn streaming_fixture(known_size: bool) -> (TempDir, Arc<StreamingHttp>) {
        let dir = TempDir::new().unwrap();
        let bytes = registry_fixture(dir.path());
        let container = wasmer_package::utils::from_bytes(bytes.clone()).unwrap();
        let distribution = serde_json::json!({
            "webcManifest": serde_json::to_string(container.manifest()).unwrap(),
            "piritaDownloadUrl": "https://packages.test/cache.webc",
            "piritaSha256Hash": WebcHash::sha256(&bytes).as_hex(),
            "webcSize": if known_size { Some(bytes.len()) } else { None },
        });
        let metadata = serde_json::to_vec(&serde_json::json!({ "data": {
            "getPackage": { "packageName":"cache", "namespace":"sdk-test", "versions":[{
                "version":"1.0.0", "isArchived":false, "v2":distribution, "v3":distribution }] },
            "info":{"defaultFrontend":"https://wasmer.io/"}
        }}))
        .unwrap();
        (
            dir,
            Arc::new(StreamingHttp {
                metadata,
                bytes: bytes.to_vec(),
                downloads: AtomicUsize::new(0),
                cancelled: Arc::default(),
            }),
        )
    }

    #[tokio::test]
    async fn package_progress_streams_deduplicates_and_reports_cache_hits() {
        use crate::{PackageLoadOptions, PackageLoadPhase};
        for known in [true, false] {
            let (_fixture, http) = streaming_fixture(known);
            let cache = TempDir::new().unwrap();
            let config = WasmerConfig {
                cache: CacheConfig {
                    root: cache.path().into(),
                },
                ..Default::default()
            };
            let client = Wasmer::new_with_http_client(config.clone(), http.clone()).unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let captured = events.clone();
            let packages = client
                .packages()
                .load_many_with_options(
                    ["sdk-test/cache", "sdk-test/cache@1.0.0"],
                    PackageLoadOptions::default()
                        .on_progress(move |p| captured.lock().unwrap().push(p)),
                )
                .await
                .unwrap();
            assert_eq!(packages.len(), 2);
            assert_eq!(http.downloads.load(Ordering::SeqCst), 1);
            let events = events.lock().unwrap();
            assert!(events.iter().any(|p| p.download.downloaded_bytes > 0
                && p.download.downloaded_bytes < http.bytes.len() as u64));
            let partial = events
                .iter()
                .find(|p| {
                    p.download.downloaded_bytes > 0
                        && p.download.downloaded_bytes < http.bytes.len() as u64
                })
                .unwrap();
            assert_eq!(partial.download.percent.is_some(), known);
            let ready = events.last().unwrap();
            assert_eq!(ready.phase, PackageLoadPhase::Ready);
            assert_eq!(ready.packages.len(), 1);
            assert_eq!(ready.download.downloaded_bytes, http.bytes.len() as u64);
            assert_eq!(ready.download.percent, Some(100.0));
            drop(events);
            // A fresh client exercises the persistent cache, not just loaded handles.
            let fresh = Wasmer::new_with_http_client(config, http.clone()).unwrap();
            let cached = Arc::new(Mutex::new(Vec::new()));
            let captured = cached.clone();
            fresh
                .packages()
                .load_with_options(
                    "sdk-test/cache",
                    PackageLoadOptions::default()
                        .on_progress(move |p| captured.lock().unwrap().push(p)),
                )
                .await
                .unwrap();
            assert_eq!(http.downloads.load(Ordering::SeqCst), 1);
            let cached = cached.lock().unwrap();
            let ready = cached.last().unwrap();
            assert!(ready.packages.iter().all(|p| p.cached));
            assert_eq!(ready.download.downloaded_bytes, 0);
            assert_eq!(ready.download.total_bytes, Some(0));
        }
    }

    /// Hold one real resolver query while the other alias downloads, without
    /// changing the backend's metadata parsing or selected dependency graph.
    #[derive(Debug)]
    struct GatedSource {
        inner: Arc<dyn wasmer_package::resolver::Source + Send + Sync>,
        blocked: String,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    #[async_trait::async_trait]
    impl wasmer_package::resolver::Source for GatedSource {
        async fn query(
            &self,
            package: &wasmer_config::package::PackageSource,
        ) -> std::result::Result<
            Vec<wasmer_package::resolver::PackageSummary>,
            wasmer_package::resolver::QueryError,
        > {
            if package.to_string() == self.blocked {
                self.started.notify_one();
                self.release.notified().await;
            }
            self.inner.query(package).await
        }
    }

    #[tokio::test]
    async fn aggregate_waits_for_each_aliased_root_to_resolve_before_using_known_totals() {
        use crate::{PackageLoadOptions, PackageLoadPhase};
        use std::str::FromStr;

        let (_fixture, http) = streaming_fixture(true);
        let cache = TempDir::new().unwrap();
        let mut client = Wasmer::new_with_http_client(
            WasmerConfig {
                cache: CacheConfig {
                    root: cache.path().into(),
                },
                ..Default::default()
            },
            http.clone(),
        )
        .unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let inner = Arc::get_mut(&mut client.inner).unwrap();
        inner.source = Arc::new(GatedSource {
            inner: inner.source.clone(),
            blocked: wasmer_config::package::PackageSource::from_str("sdk-test/cache@1.0.0")
                .unwrap()
                .to_string(),
            started: started.clone(),
            release: release.clone(),
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let partial = Arc::new(tokio::sync::Notify::new());
        let seen_partial = partial.clone();
        let size = http.bytes.len() as u64;
        let options = PackageLoadOptions::default().on_progress(move |progress| {
            let unresolved_partial = progress.phase == PackageLoadPhase::Resolving
                && progress.download.downloaded_bytes > 0
                && progress.download.downloaded_bytes < size;
            captured.lock().unwrap().push(progress);
            if unresolved_partial {
                seen_partial.notify_one();
            }
        });
        let api = client.packages();
        let mut load = Box::pin(
            api.load_many_with_options(["sdk-test/cache", "sdk-test/cache@1.0.0"], options),
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::select! {
                result = &mut load => panic!("load finished before gated resolution: {result:?}"),
                () = started.notified() => {}
            }
            tokio::select! {
                result = &mut load => panic!("load finished before unresolved partial progress: {result:?}"),
                () = partial.notified() => {}
            }
        }).await.expect("other alias must download while one root remains unresolved");
        {
            let events = events.lock().unwrap();
            let unresolved = events
                .iter()
                .find(|p| p.download.downloaded_bytes > 0)
                .unwrap();
            assert_eq!(unresolved.phase, PackageLoadPhase::Resolving);
            assert_eq!(unresolved.download.total_bytes, None);
            assert_eq!(unresolved.download.percent, None);
            assert_eq!(unresolved.packages.len(), 1);
            assert_eq!(unresolved.packages[0].download.total_bytes, Some(size));
        }
        release.notify_one();
        let packages = tokio::time::timeout(std::time::Duration::from_secs(5), load)
            .await
            .expect("released alias must join the shared download")
            .unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(http.downloads.load(Ordering::SeqCst), 1);
        {
            let events = events.lock().unwrap();
            assert!(
                events
                    .iter()
                    .any(|p| p.phase == PackageLoadPhase::Downloading
                        && p.download.downloaded_bytes > 0
                        && p.download.downloaded_bytes < size
                        && p.download.total_bytes == Some(size)
                        && p.download.percent.is_some())
            );
            let ready = events.last().unwrap();
            assert_eq!(ready.phase, PackageLoadPhase::Ready);
            assert_eq!(ready.packages.len(), 1);
            assert_eq!(ready.download.downloaded_bytes, size);
            assert_eq!(ready.download.total_bytes, Some(size));
        }
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_alias_does_not_leave_the_observed_survivor_resolving() {
        use crate::{PackageLoadCancellation, PackageLoadOptions, PackageLoadPhase};

        let (_fixture, http) = streaming_fixture(true);
        let cache = TempDir::new().unwrap();
        let client = Wasmer::new_with_http_client(
            WasmerConfig {
                cache: CacheConfig {
                    root: cache.path().into(),
                },
                ..Default::default()
            },
            http.clone(),
        )
        .unwrap();
        let token = PackageLoadCancellation::default();
        let cancel = token.clone();
        let canceled_events = Arc::new(Mutex::new(Vec::new()));
        let captured = canceled_events.clone();
        let canceled_options = PackageLoadOptions::default()
            .cancellation(token)
            .on_progress(move |p| {
                if p.download.downloaded_bytes > 0 {
                    cancel.cancel();
                }
                captured.lock().unwrap().push(p);
            });
        let kept_events = Arc::new(Mutex::new(Vec::new()));
        let captured = kept_events.clone();
        let kept_options =
            PackageLoadOptions::default().on_progress(move |p| captured.lock().unwrap().push(p));
        let api = client.packages();
        let (canceled, kept) = tokio::join!(
            api.load_with_options("sdk-test/cache", canceled_options),
            api.load_with_options("sdk-test/cache@1.0.0", kept_options),
        );
        assert!(matches!(canceled, Err(crate::Error::Cancelled)));
        assert!(kept.is_ok());
        assert_eq!(http.downloads.load(Ordering::SeqCst), 1);
        assert_eq!(http.cancelled.load(Ordering::SeqCst), 0);
        assert!(
            canceled_events
                .lock()
                .unwrap()
                .iter()
                .all(|p| p.phase != PackageLoadPhase::Ready)
        );
        {
            let events = kept_events.lock().unwrap();
            let size = http.bytes.len() as u64;
            assert!(events.iter().any(|p| p.download.downloaded_bytes > 0
                && p.download.downloaded_bytes < size
                && p.download.total_bytes == Some(size)
                && p.phase == PackageLoadPhase::Downloading));
            for p in events.iter().filter(|p| p.download.downloaded_bytes > 0) {
                assert_ne!(p.phase, PackageLoadPhase::Resolving);
                assert_eq!(p.download.total_bytes, Some(size));
            }
            let ready = events.last().unwrap();
            assert_eq!(ready.phase, PackageLoadPhase::Ready);
            assert_eq!(ready.packages.len(), 1);
            assert_eq!(ready.download.downloaded_bytes, size);
            assert_eq!(ready.download.percent, Some(100.0));
        }
        let cached_events = Arc::new(Mutex::new(Vec::new()));
        let captured = cached_events.clone();
        api.load_with_options(
            "sdk-test/cache@1.0.0",
            PackageLoadOptions::default().on_progress(move |p| captured.lock().unwrap().push(p)),
        )
        .await
        .unwrap();
        {
            let events = cached_events.lock().unwrap();
            let ready = events.last().unwrap();
            assert_eq!(ready.phase, PackageLoadPhase::Ready);
            assert_eq!(ready.download.downloaded_bytes, 0);
            assert_eq!(ready.download.total_bytes, Some(0));
            assert!(ready.packages.iter().all(|p| p.cached));
        }
        assert_eq!(http.downloads.load(Ordering::SeqCst), 1);
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_one_subscriber_preserves_other_downloads_and_last_cancel_aborts() {
        use crate::{PackageLoadCancellation, PackageLoadOptions, PackageLoadPhase};
        let (_fixture, http) = streaming_fixture(true);
        let cache = TempDir::new().unwrap();
        let client = Wasmer::new_with_http_client(
            WasmerConfig {
                cache: CacheConfig {
                    root: cache.path().into(),
                },
                ..Default::default()
            },
            http.clone(),
        )
        .unwrap();
        let token = PackageLoadCancellation::default();
        let cancel = token.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let options = PackageLoadOptions::default()
            .cancellation(token)
            .on_progress(move |p| {
                if p.download.downloaded_bytes > 0 {
                    cancel.cancel();
                }
                captured.lock().unwrap().push(p);
            });
        let api = client.packages();
        let (cancelled, kept) = tokio::join!(
            api.load_with_options("sdk-test/cache", options),
            api.load("sdk-test/cache@1.0.0")
        );
        assert!(matches!(cancelled, Err(crate::Error::Cancelled)));
        assert!(kept.is_ok());
        assert_eq!(http.downloads.load(Ordering::SeqCst), 1);
        assert_eq!(http.cancelled.load(Ordering::SeqCst), 0);
        assert!(
            !events
                .lock()
                .unwrap()
                .iter()
                .any(|p| p.phase == PackageLoadPhase::Ready)
        );

        let cache = TempDir::new().unwrap();
        let client = Wasmer::new_with_http_client(
            WasmerConfig {
                cache: CacheConfig {
                    root: cache.path().into(),
                },
                ..Default::default()
            },
            http.clone(),
        )
        .unwrap();
        let token = PackageLoadCancellation::default();
        let cancel = token.clone();
        let result = client
            .packages()
            .load_with_options(
                "sdk-test/cache",
                PackageLoadOptions::default()
                    .cancellation(token)
                    .on_progress(move |p| {
                        if p.download.downloaded_bytes > 0 {
                            cancel.cancel();
                        }
                    }),
            )
            .await;
        assert!(matches!(result, Err(crate::Error::Cancelled)));
        assert_eq!(http.cancelled.load(Ordering::SeqCst), 1);
    }

    fn registry_fixture(directory: &Path) -> bytes::Bytes {
        let manifest = r#"
[package]
name = "sdk-test/cache"
version = "1.0.0"
description = "SDK cache fixture"
entrypoint = "echo"

[[module]]
name = "echo"
source = "echo.wasm"
abi = "wasi"

[[command]]
name = "echo"
module = "echo"
"#;
        std::fs::write(directory.join("wasmer.toml"), manifest).expect("write manifest");
        std::fs::write(
            directory.join("echo.wasm"),
            wat::parse_str("(module (func (export \"_start\")))").expect("compile fixture"),
        )
        .expect("write module");
        wasmer_package::package::Package::from_manifest(directory.join("wasmer.toml"))
            .expect("build package")
            .serialize()
            .expect("serialize package")
    }
}
