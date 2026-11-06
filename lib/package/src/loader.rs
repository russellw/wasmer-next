//! Package-container acquisition and persistent checkout caches.
use std::{
    collections::{HashMap, HashSet},
    io::{ErrorKind, Read, Write as _},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use crate::{
    WasmerPackageError,
    utils::{from_bytes, from_disk},
};
use anyhow::{Context, Error, bail};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use http::{HeaderMap, Method};
use tempfile::NamedTempFile;
use url::Url;
use wasmer_config::package::PackageId;
use webc::DetectError;
use webc::{Container, ContainerError};

use crate::{
    http::{HttpBodyEvent, HttpClient, HttpRequest, USER_AGENT},
    resolver::{
        DependencyGraph, DistributionInfo, PackageSummary, Resolution, ResolvedPackage, WebcHash,
    },
};

/// Acquisition phases. `Ready` is emitted only after a container loads successfully.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageDownloadPhase {
    Downloading,
    Loading,
    Ready,
}

/// A snapshot of decoded package-body bytes, not encoded HTTP transfer bytes.
/// Cache hits and local files contribute zero. An opaque/archive body whose decoded
/// size is unavailable retains `0`/`None`, including after a successful load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageDownloadProgress {
    pub phase: PackageDownloadPhase,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub cached: bool,
}

pub type PackageDownloadObserver = Arc<dyn Fn(PackageDownloadProgress) + Send + Sync>;

struct BodyProgress {
    snapshot: PackageDownloadProgress,
    identity: bool,
    total: Option<u64>,
    received: u64,
    prefix: [u8; 8],
    prefix_len: usize,
    raw_webc: bool,
}

struct DownloadProgress {
    observer: PackageDownloadObserver,
    state: Mutex<BodyProgress>,
}

fn raw_webc(prefix: &[u8]) -> bool {
    matches!(
        webc::detect(prefix),
        Ok(webc::Version::V1 | webc::Version::V2 | webc::Version::V3)
    )
}

impl DownloadProgress {
    fn new(observer: PackageDownloadObserver) -> Self {
        Self {
            observer,
            state: Mutex::new(BodyProgress {
                snapshot: PackageDownloadProgress {
                    phase: PackageDownloadPhase::Downloading,
                    downloaded_bytes: 0,
                    total_bytes: None,
                    cached: false,
                },
                identity: false,
                total: None,
                received: 0,
                prefix: [0; 8],
                prefix_len: 0,
                raw_webc: false,
            }),
        }
    }

    fn update(&self, update: impl FnOnce(&mut BodyProgress) -> bool) {
        let snapshot = {
            let mut state = self.state.lock().unwrap();
            update(&mut state).then(|| state.snapshot.clone())
        };
        // Embedders may reenter acquisition/cache APIs from the callback.
        if let Some(snapshot) = snapshot {
            (self.observer)(snapshot);
        }
    }

    fn body(&self, event: HttpBodyEvent<'_>) {
        self.update(|state| match event {
            HttpBodyEvent::Head {
                status,
                headers,
                cached,
            } => {
                state.identity = !status.is_client_error()
                    && !status.is_server_error()
                    && headers
                        .get(http::header::CONTENT_ENCODING)
                        .is_none_or(|encoding| {
                            encoding.to_str().ok().is_some_and(|encoding| {
                                encoding.split(',').all(|part| {
                                    matches!(
                                        part.trim().to_ascii_lowercase().as_str(),
                                        "" | "identity"
                                    )
                                })
                            })
                        });
                state.total = crate::http::content_length(headers);
                state.received = 0;
                state.prefix_len = 0;
                state.raw_webc = false;
                state.snapshot.cached = cached;
                state.snapshot.downloaded_bytes = 0;
                state.snapshot.total_bytes = if cached { Some(0) } else { None };
                true
            }
            HttpBodyEvent::Chunk(chunk) => {
                if !state.identity || state.snapshot.cached {
                    return false;
                }
                state.received = state.received.saturating_add(chunk.len() as u64);
                let take = (state.prefix.len() - state.prefix_len).min(chunk.len());
                state.prefix[state.prefix_len..state.prefix_len + take]
                    .copy_from_slice(&chunk[..take]);
                state.prefix_len += take;
                if state.prefix_len == state.prefix.len() {
                    state.raw_webc = raw_webc(&state.prefix);
                }
                if !state.raw_webc {
                    return false;
                }
                state.snapshot.downloaded_bytes = state.received;
                state.snapshot.total_bytes = state.total.filter(|total| *total >= state.received);
                true
            }
        });
    }

    fn decoded(&self, body: &[u8]) {
        self.update(|state| {
            if state.snapshot.cached {
                state.snapshot.downloaded_bytes = 0;
                state.snapshot.total_bytes = Some(0);
            } else if raw_webc(body) {
                state.snapshot.downloaded_bytes = body.len() as u64;
                state.snapshot.total_bytes = Some(body.len() as u64);
            } else {
                // Container-wrapper decoding belongs to from_bytes; it exposes no
                // decoded length. Never report the encoded wrapper length as progress.
                state.snapshot.downloaded_bytes = 0;
                state.snapshot.total_bytes = None;
            }
            true
        });
    }

    fn local(&self) {
        self.update(|state| {
            state.snapshot.downloaded_bytes = 0;
            state.snapshot.total_bytes = Some(0);
            true
        });
    }

    fn phase(&self, phase: PackageDownloadPhase) {
        self.update(|state| {
            state.snapshot.phase = phase;
            true
        });
    }

    fn cached(&self) {
        self.update(|state| {
            state.snapshot = PackageDownloadProgress {
                phase: PackageDownloadPhase::Ready,
                downloaded_bytes: 0,
                total_bytes: Some(0),
                cached: true,
            };
            true
        });
    }
}

/// Downloads package containers through an embedder's HTTP client and caches.
/// Dependency resolution and guest execution are separate concerns.
#[derive(Debug)]
pub struct PackageDownloader {
    client: Arc<dyn HttpClient + Send + Sync>,
    in_memory: Option<InMemoryCache>,
    cache: Option<Arc<dyn PackageCache>>,
    filesystem_cache: Option<Arc<FileSystemCache>>,
    /// A mapping from hostnames to tokens
    tokens: HashMap<String, String>,

    hash_validation: HashIntegrityValidationMode,
}

/// Defines how to validate package hash integrity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashIntegrityValidationMode {
    /// Do not validate anything.
    /// Best for performance.
    NoValidate,
    /// Compute the image hash and produce a trace warning on hash mismatches.
    WarnOnHashMismatch,
    /// Compute the image hash and fail on a mismatch.
    FailOnHashMismatch,
}

impl PackageDownloader {
    pub fn new(client: Arc<dyn HttpClient + Send + Sync>) -> Self {
        PackageDownloader {
            in_memory: Some(InMemoryCache::default()),
            client,
            cache: None,
            filesystem_cache: None,
            hash_validation: HashIntegrityValidationMode::NoValidate,
            tokens: HashMap::new(),
        }
    }

    /// Set the validation mode to apply after downloading an image.
    ///
    /// See [`HashIntegrityValidationMode`] for details.
    pub fn with_hash_validation_mode(mut self, mode: HashIntegrityValidationMode) -> Self {
        self.hash_validation = mode;
        self
    }

    pub fn with_cache_dir(self, cache_dir: impl Into<PathBuf>) -> Self {
        let cache = Arc::new(FileSystemCache {
            cache_dir: cache_dir.into(),
        });
        PackageDownloader {
            cache: Some(cache.clone()),
            filesystem_cache: Some(cache),
            ..self
        }
    }

    /// Use a target-provided persistent package cache.
    pub fn with_cache(self, cache: Arc<dyn PackageCache>) -> Self {
        PackageDownloader {
            cache: Some(cache),
            filesystem_cache: None,
            ..self
        }
    }

    /// Disable promotion of loaded containers into the in-memory cache.
    pub fn without_in_memory_cache(self) -> Self {
        PackageDownloader {
            in_memory: None,
            ..self
        }
    }

    pub fn cache(&self) -> Option<&FileSystemCache> {
        self.filesystem_cache.as_deref()
    }

    pub fn validate_cache(
        &self,
        mode: CacheValidationMode,
    ) -> Result<Vec<ImageHashMismatchError>, anyhow::Error> {
        let cache = self
            .filesystem_cache
            .as_deref()
            .context("can not validate cache - no filesystem cache configured")?;

        let items = cache.validate_hashes()?;
        let mut errors = Vec::new();
        for (path, error) in items {
            match mode {
                CacheValidationMode::WarnOnMismatch => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN, ?error, "hash mismatch in cached image file");
                }
                CacheValidationMode::PruneOnMismatch => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN, ?error, "deleting cached image file due to hash mismatch");
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(fs_err) => {
                            tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::ERROR,
                                path=%error.source,
                                ?fs_err,
                                "could not delete cached image file with hash mismatch"
                            );
                        }
                    }
                }
            }

            errors.push(error);
        }

        Ok(errors)
    }

    pub fn with_http_client(self, client: impl HttpClient + Send + Sync + 'static) -> Self {
        self.with_shared_http_client(Arc::new(client))
    }

    pub fn with_shared_http_client(self, client: Arc<dyn HttpClient + Send + Sync>) -> Self {
        PackageDownloader { client, ..self }
    }

    pub fn with_tokens<I, K, V>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (hostname, token) in tokens {
            self = self.with_token(hostname, token);
        }

        self
    }

    /// Add an API token that will be used whenever sending requests to a
    /// particular hostname.
    ///
    /// Note that this uses [`Url::authority()`] when looking up tokens, so it
    /// will match both plain hostnames (e.g. `registry.wasmer.io`) and hosts
    /// with a port number (e.g. `localhost:8000`).
    pub fn with_token(mut self, hostname: impl Into<String>, token: impl Into<String>) -> Self {
        self.tokens.insert(hostname.into(), token.into());
        self
    }

    /// Insert a container into the in-memory hash.
    pub fn insert_cached(&self, hash: WebcHash, container: &Container) {
        if let Some(in_memory) = &self.in_memory {
            in_memory.save(container, hash);
        }
    }

    /// Remove a container from the in-memory cache.
    pub fn evict_cached(&self, hash: &WebcHash) -> Option<Container> {
        self.in_memory
            .as_ref()
            .and_then(|in_memory| in_memory.remove(hash))
    }

    #[tracing::instrument(target = "wasmer_wasix::runtime::package_loader::builtin_loader", level = "debug", skip_all, fields(pkg.hash=%hash))]
    async fn get_cached(&self, hash: &WebcHash) -> Result<Option<Container>, Error> {
        if let Some(cached) = self
            .in_memory
            .as_ref()
            .and_then(|in_memory| in_memory.lookup(hash))
        {
            return Ok(Some(cached));
        }

        if let Some(cache) = self.cache.as_ref() {
            match cache.lookup(hash).await {
                Ok(Some(cached)) => {
                    if let Some(in_memory) = &self.in_memory {
                        tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG, "Copying from the persistent cache to the in-memory cache");
                        in_memory.save(&cached, *hash);
                    }
                    return Ok(Some(cached));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN,
                        error = &*error,
                        pkg.hash = %hash,
                        "Unable to read a cached package; treating it as a cache miss",
                    );
                }
            }
        }

        Ok(None)
    }

    /// Validate image contents with the specified validation mode.
    async fn validate_hash(
        image: &bytes::Bytes,
        mode: HashIntegrityValidationMode,
        info: &DistributionInfo,
    ) -> Result<(), anyhow::Error> {
        let info = info.clone();
        let image = image.clone();
        crate::resolver::spawn_blocking(move || Self::validate_hash_sync(&image, mode, &info))
            .await
            .context("tokio runtime failed")?
    }

    /// Validate image contents with the specified validation mode.
    fn validate_hash_sync(
        image: &[u8],
        mode: HashIntegrityValidationMode,
        info: &DistributionInfo,
    ) -> Result<(), anyhow::Error> {
        match mode {
            HashIntegrityValidationMode::NoValidate => {
                // Nothing to do.
                Ok(())
            }
            HashIntegrityValidationMode::WarnOnHashMismatch => {
                let actual_hash = WebcHash::sha256(image);
                if actual_hash != info.webc_sha256 {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN, %info.webc_sha256, %actual_hash, "image hash mismatch - actual image hash does not match the expected hash!");
                }
                Ok(())
            }
            HashIntegrityValidationMode::FailOnHashMismatch => {
                let actual_hash = WebcHash::sha256(image);
                if actual_hash != info.webc_sha256 {
                    Err(ImageHashMismatchError {
                        source: info.webc.to_string(),
                        actual_hash,
                        expected_hash: info.webc_sha256,
                    }
                    .into())
                } else {
                    Ok(())
                }
            }
        }
    }

    #[tracing::instrument(target = "wasmer_wasix::runtime::package_loader::builtin_loader", level = "debug", skip_all, fields(%dist.webc, %dist.webc_sha256))]
    async fn download(
        &self,
        dist: &DistributionInfo,
        progress: Option<&Arc<DownloadProgress>>,
    ) -> Result<Bytes, Error> {
        if dist.webc.scheme() == "file" {
            match crate::resolver::utils::file_path_from_url(&dist.webc) {
                Ok(path) => {
                    let bytes = crate::resolver::spawn_blocking({
                        let path = path.clone();
                        move || std::fs::read(path)
                    })
                    .await?
                    .with_context(|| format!("Unable to read \"{}\"", path.display()))?;

                    let bytes = bytes::Bytes::from(bytes);

                    Self::validate_hash(&bytes, self.hash_validation, dist).await?;
                    if let Some(progress) = progress {
                        progress.local();
                    }

                    return Ok(bytes);
                }
                Err(e) => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG,
                        url=%dist.webc,
                        error=&*e,
                        "Unable to convert the file:// URL to a path",
                    );
                }
            }
        }

        let request = HttpRequest {
            headers: self.headers(&dist.webc),
            url: dist.webc.clone(),
            method: Method::GET,
            body: None,
            options: Default::default(),
        };

        tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG, %request.url, %request.method, "webc_package_download_start");
        tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::TRACE, ?request.headers);

        let response = if let Some(progress) = progress {
            progress.phase(PackageDownloadPhase::Downloading);
            let progress = progress.clone();
            self.client
                .request_with_body_progress(request, Arc::new(move |event| progress.body(event)))
                .await?
        } else {
            self.client.request(request).await?
        };

        tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::TRACE,
            %response.status,
            %response.redirected,
            ?response.headers,
            response.len=response.body.as_ref().map(|body| body.len()),
            "Received a response",
        );

        let url = &dist.webc;
        if !response.is_ok() {
            return Err(
                crate::resolver::utils::http_error(&response).context(format!(
                    "package download failed: GET request to \"{}\" failed with status {}",
                    url, response.status
                )),
            );
        }

        let body = response.body.context("package download failed")?;
        let body = Self::decode_response_body(&response.headers, body)
            .context("package download failed: could not decode response body")?;
        tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG, %url, "package_download_succeeded");

        let body = bytes::Bytes::from(body);
        if let Some(progress) = progress {
            progress.decoded(&body);
        }

        Self::validate_hash(&body, self.hash_validation, dist).await?;

        Ok(body)
    }

    fn headers(&self, url: &Url) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/webc".parse().unwrap());
        headers.insert("User-Agent", USER_AGENT.parse().unwrap());

        // Accept compressed responses.
        // NOTE: gzip and zstd decoding is available on native platforms.
        // In browser platforms, the fetch implementation should automatically
        // handle decoding of gzip/zstd responses transparently.
        headers.insert(
            http::header::ACCEPT_ENCODING,
            "zstd;q=1.0, gzip;q=0.8".parse().unwrap(),
        );

        if url.has_authority()
            && let Some(token) = self.tokens.get(url.authority())
        {
            let header = format!("Bearer {token}");
            match header.parse() {
                Ok(header) => {
                    headers.insert(http::header::AUTHORIZATION, header);
                }
                Err(e) => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN,
                        error = &e as &dyn std::error::Error,
                        "An error occurred while parsing the authorization header",
                    );
                }
            }
        }

        headers
    }

    /// Decode the response body according to the `Content-Encoding` header.
    ///
    /// * Supports `gzip` and `zstd` encodings
    /// * Supports nested encodings (e.g. `gzip, zstd`)
    /// * Passes through unencoded bodies or "identity" encoding unchanged
    fn decode_response_body(headers: &HeaderMap, body: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        let encodings = match headers.get(http::header::CONTENT_ENCODING) {
            Some(header) => header
                .to_str()
                .context("non-utf8 content-encoding header")?
                .split(',')
                .map(|encoding| encoding.trim().to_ascii_lowercase())
                .filter(|encoding| !encoding.is_empty())
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };

        // Check if there is nothing to decode, return early.
        // "identity" is the default encoding meaning "no encoding" (See RFC 2616 / RFC 7231)
        if encodings.is_empty() || (encodings.len() == 1 && encodings[0] == "identity") {
            return Ok(body);
        }

        let mut reader: Box<dyn Read> = Box::new(std::io::Cursor::new(body));
        for encoding in encodings.iter().rev() {
            match encoding.as_str() {
                "gzip" => {
                    reader = Box::new(flate2::read::GzDecoder::new(reader));
                }
                "zstd" => {
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        reader = Box::new(
                            zstd::stream::read::Decoder::new(reader)
                                .context("failed to initialize zstd decoder")?,
                        );
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        // NOTE: in browsers this code will not be hit because
                        // the fetch API automatically handles content decoding.
                        bail!("zstd content-encoding is not supported on wasm32");
                    }
                }
                "identity" => {}
                other => bail!("unsupported content-encoding: {other}"),
            }
        }

        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .context("failed to decode response body")?;
        Ok(decoded)
    }
}

impl PackageDownloader {
    #[tracing::instrument(target = "wasmer_wasix::runtime::package_loader::builtin_loader",
        level="debug",
        skip_all,
        fields(
            pkg=%summary.pkg.id,
        ),
    )]
    pub async fn load(&self, summary: &PackageSummary) -> Result<Container, Error> {
        self.load_with_progress(summary, None).await
    }

    /// Observe acquisition without changing cache, validation, or parsing policy.
    /// Dropping the future during HTTP stops this load from advancing to Loading/Ready.
    /// Already-started blocking cache work and custom cache/provider effects retain their
    /// existing lifetime; this API does not promise cancellation of their publication.
    pub async fn load_with_progress(
        &self,
        summary: &PackageSummary,
        progress: Option<PackageDownloadObserver>,
    ) -> Result<Container, Error> {
        let progress = progress.map(|observer| Arc::new(DownloadProgress::new(observer)));
        if let Some(container) = self.get_cached(&summary.dist.webc_sha256).await? {
            tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG, "Cache hit!");
            if let Some(progress) = &progress {
                progress.cached();
            }
            return Ok(container);
        }

        // looks like we had a cache miss and need to download it manually
        let bytes = self
            .download(&summary.dist, progress.as_ref())
            .await
            .with_context(|| format!("Unable to download \"{}\"", summary.dist.webc))?;

        if let Some(progress) = &progress {
            progress.phase(PackageDownloadPhase::Loading);
        }

        // We want to cache the container we downloaded, but we want to do it
        // in a smart way to keep memory usage down.

        if let Some(cache) = &self.cache {
            match cache.save(bytes.clone(), &summary.dist).await {
                Ok(container) => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG, "Cached to disk");
                    if let Some(in_memory) = &self.in_memory {
                        in_memory.save(&container, summary.dist.webc_sha256);
                    }
                    // The happy path - we've saved to both caches and loaded the
                    // container from disk (hopefully using mmap) so we're done.
                    if let Some(progress) = &progress {
                        progress.phase(PackageDownloadPhase::Ready);
                    }
                    return Ok(container);
                }
                Err(e) => {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN,
                        error=&*e,
                        pkg=%summary.pkg.id,
                        pkg.hash=%summary.dist.webc_sha256,
                        pkg.url=%summary.dist.webc,
                        "Unable to save the downloaded package to disk",
                    );
                }
            }
        }

        // The sad path - looks like we don't have a filesystem cache so we'll
        // need to keep the whole thing in memory.
        let container = crate::resolver::spawn_blocking(move || from_bytes(bytes)).await??;
        if let Some(in_memory) = &self.in_memory {
            // We still want to cache it in memory, of course
            in_memory.save(&container, summary.dist.webc_sha256);
        }
        if let Some(progress) = &progress {
            progress.phase(PackageDownloadPhase::Ready);
        }
        Ok(container)
    }
}

#[derive(Clone, Debug)]
pub struct ImageHashMismatchError {
    source: String,
    expected_hash: WebcHash,
    actual_hash: WebcHash,
}

impl std::fmt::Display for ImageHashMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "image hash mismatch! expected hash '{}', but the computed hash is '{}' (source '{}')",
            self.expected_hash, self.actual_hash, self.source,
        )
    }
}

impl std::error::Error for ImageHashMismatchError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheValidationMode {
    /// Just emit a warning for all images where the filename doesn't match
    /// the expected hash.
    WarnOnMismatch,
    /// Remove images from the cache if the filename doesn't match the actual
    /// hash.
    PruneOnMismatch,
}

// FIXME: This implementation will block the async runtime and should use
// some sort of spawn_blocking() call to run it in the background.
#[derive(Debug)]
pub struct FileSystemCache {
    cache_dir: PathBuf,
}

/// Persistent storage for immutable WEBC package contents.
#[async_trait::async_trait]
pub trait PackageCache: Send + Sync + std::fmt::Debug {
    /// Load and decode a package by its expected content hash.
    async fn lookup(&self, hash: &WebcHash) -> Result<Option<Container>, Error>;

    /// Persist downloaded bytes and return a decoded container.
    async fn save(&self, webc: Bytes, dist: &DistributionInfo) -> Result<Container, Error>;
}

impl FileSystemCache {
    const FILE_SUFFIX: &'static str = ".bin";

    /// The cache in `cache_dir`, as [`PackageDownloader::with_cache_dir`] uses it.
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    fn temp_dir(&self) -> PathBuf {
        self.cache_dir.join("__temp__")
    }

    /// Validate that the cached image file names correspond to their actual
    /// file content hashes.
    fn validate_hashes(&self) -> Result<Vec<(PathBuf, ImageHashMismatchError)>, anyhow::Error> {
        let mut items = Vec::<(PathBuf, ImageHashMismatchError)>::new();

        let iter = match std::fs::read_dir(&self.cache_dir) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Cache dir does not exist, so nothing to validate.
                return Ok(Vec::new());
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "Could not read image cache dir: '{}'",
                        self.cache_dir.display()
                    )
                });
            }
        };

        for res in iter {
            let entry = res?;
            if !entry.file_type()?.is_file() {
                continue;
            }

            // Extract the hash from the filename.

            let hash_opt = entry
                .file_name()
                .to_str()
                .and_then(|x| {
                    let (raw_hash, _) = x.split_once(Self::FILE_SUFFIX)?;
                    Some(raw_hash)
                })
                .and_then(|x| WebcHash::parse_hex(x).ok());
            let Some(expected_hash) = hash_opt else {
                continue;
            };

            // Compute the actual hash.
            let path = entry.path();
            let actual_hash = WebcHash::for_file(&path)?;

            if actual_hash != expected_hash {
                let err = ImageHashMismatchError {
                    source: path.to_string_lossy().to_string(),
                    actual_hash,
                    expected_hash,
                };
                items.push((path, err));
            }
        }

        Ok(items)
    }

    async fn lookup_impl(&self, hash: &WebcHash) -> Result<Option<Container>, Error> {
        let path = self.path(hash);

        let container = crate::resolver::spawn_blocking({
            let path = path.clone();
            move || from_disk(path)
        })
        .await?;
        match container {
            Ok(c) => Ok(Some(c)),
            Err(WasmerPackageError::ContainerError(ContainerError::Open { error, .. }))
            | Err(WasmerPackageError::ContainerError(ContainerError::Read { error, .. }))
            | Err(WasmerPackageError::ContainerError(ContainerError::Detect(DetectError::Io(
                error,
            )))) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => {
                let msg = format!("Unable to read \"{}\"", path.display());
                Err(Error::new(e).context(msg))
            }
        }
    }

    async fn save_impl(&self, webc: Bytes, dist: &DistributionInfo) -> Result<PathBuf, Error> {
        let path = self.path(&dist.webc_sha256);
        let dist = dist.clone();
        let temp_dir = self.temp_dir();

        let path2 = path.clone();
        crate::resolver::spawn_blocking(move || {
            // Keep files in a temporary directory until they are fully written
            // to prevent temp files being included in [`Self::scan`] or `[Self::retain]`.

            std::fs::create_dir_all(&temp_dir)
                .with_context(|| format!("Unable to create directory '{}'", temp_dir.display()))?;

            let mut temp = NamedTempFile::new_in(&temp_dir)?;
            temp.write_all(&webc)?;
            temp.flush()?;
            temp.as_file_mut().sync_all()?;

            // Move the temporary file to the final location.
            temp.persist(&path)?;

            tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG,
                pkg.hash=%dist.webc_sha256,
                pkg.url=%dist.webc,
                path=%path.display(),
                num_bytes=webc.len(),
                "Saved to disk",
            );
            Result::<_, Error>::Ok(())
        })
        .await??;

        Ok(path2)
    }

    #[tracing::instrument(
        target = "wasmer_wasix::runtime::package_loader::builtin_loader",
        level = "debug",
        skip_all
    )]
    async fn save_and_load_as_mmapped(
        &self,
        webc: Bytes,
        dist: &DistributionInfo,
    ) -> Result<Container, Error> {
        // First, save it to disk
        self.save_impl(webc, dist).await?;

        // Now try to load it again. The resulting container should use
        // a memory-mapped file rather than an in-memory buffer.
        match self.lookup_impl(&dist.webc_sha256).await? {
            Some(container) => Ok(container),
            None => {
                // Something really weird has occurred and we can't see the
                // saved file. Just error out and let the fallback code do its
                // thing.
                Err(Error::msg("Unable to load the downloaded memory from disk"))
            }
        }
    }

    /// Where the package whose webc has the hash `hash` is cached, for a reader of its own
    /// (e.g. a zero-copy webc v3 reader; [`Container`] does not give one back).
    pub fn path(&self, hash: &WebcHash) -> PathBuf {
        self.cache_dir.join(format!(
            "{}{}",
            hex::encode(hash.as_bytes()),
            Self::FILE_SUFFIX
        ))
    }

    /// Scan all the cached webc files and invoke the callback for each.
    pub async fn scan<S, F>(&self, state: S, callback: F) -> Result<S, Error>
    where
        S: Send + 'static,
        F: Fn(&mut S, &std::fs::DirEntry) -> Result<(), Error> + Send + 'static,
    {
        let cache_dir = self.cache_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<S, anyhow::Error> {
            let mut state = state;

            let iter = match std::fs::read_dir(&cache_dir) {
                Ok(v) => v,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // path does not exist, so nothing to scan.
                    return Ok(state);
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("Could not read image cache dir: '{}'", cache_dir.display())
                    });
                }
            };

            for res in iter {
                let entry = res?;
                if !entry.file_type()?.is_file() {
                    continue;
                }

                callback(&mut state, &entry)?;
            }

            Ok(state)
        })
        .await?
        .context("tokio runtime failed")
    }

    /// Remove entries from the cache that do not pass the callback.
    pub async fn retain<S, F>(&self, state: S, filter: F) -> Result<S, Error>
    where
        S: Send + 'static,
        F: Fn(&mut S, &std::fs::DirEntry) -> Result<bool, anyhow::Error> + Send + 'static,
    {
        let cache_dir = self.cache_dir.clone();
        tokio::task::spawn_blocking(move || {
            let iter = match std::fs::read_dir(&cache_dir) {
                Ok(v) => v,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // path does not exist, so nothing to scan.
                    return Ok(state);
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("Could not read image cache dir: '{}'", cache_dir.display())
                    });
                }
            };

            let mut state = state;
            for res in iter {
                let entry = res?;
                if !entry.file_type()?.is_file() {
                    continue;
                }

                if !filter(&mut state, &entry)? {
                    tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::DEBUG,
                        path=%entry.path().display(),
                        "Removing cached image file - does not pass the filter",
                    );
                    match std::fs::remove_file(entry.path()) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(fs_err) => {
                            tracing::event!(target: "wasmer_wasix::runtime::package_loader::builtin_loader", tracing::Level::WARN,
                                path=%entry.path().display(),
                                ?fs_err,
                                "Could not delete cached image file",
                            );
                        }
                    }
                }
            }

            Ok(state)
        })
        .await?
        .context("tokio runtime failed")
    }
}

#[async_trait::async_trait]
impl PackageCache for FileSystemCache {
    async fn lookup(&self, hash: &WebcHash) -> Result<Option<Container>, Error> {
        self.lookup_impl(hash).await
    }

    async fn save(&self, webc: Bytes, dist: &DistributionInfo) -> Result<Container, Error> {
        self.save_and_load_as_mmapped(webc, dist).await
    }
}

#[derive(Debug, Default)]
struct InMemoryCache(RwLock<HashMap<WebcHash, Container>>);

impl InMemoryCache {
    fn lookup(&self, hash: &WebcHash) -> Option<Container> {
        self.0.read().unwrap().get(hash).cloned()
    }

    fn save(&self, container: &Container, hash: WebcHash) {
        let mut cache = self.0.write().unwrap();
        cache.entry(hash).or_insert_with(|| container.clone());
    }

    fn remove(&self, hash: &WebcHash) -> Option<Container> {
        self.0.write().unwrap().remove(hash)
    }
}

/// Resolved containers and command bytes, independent of filesystem or guest execution.
#[derive(Debug, Clone)]
pub struct LoadedPackage {
    pub resolution: Resolution,
    pub containers: HashMap<PackageId, Container>,
    pub commands: Vec<crate::commands::BinaryPackageCommand>,
    pub webc_version: webc::Version,
}

impl LoadedPackage {
    /// Select commands from supplied containers after the embedder's filesystem preflight.
    pub fn from_containers(
        resolution: Resolution,
        containers: HashMap<PackageId, Container>,
    ) -> Result<Self, Error> {
        let webc_version = containers
            .get(&resolution.package.root_package)
            .with_context(|| {
                format!(
                    "Unable to find the \"{}\" root package",
                    resolution.package.root_package
                )
            })?
            .version();
        let commands = crate::commands::load_commands(&containers, &resolution)?;
        Ok(Self {
            resolution,
            containers,
            commands,
            webc_version,
        })
    }

    pub fn get_command(&self, name: &str) -> Option<&crate::commands::BinaryPackageCommand> {
        self.commands.iter().find(|cmd| cmd.name() == name)
    }

    pub fn infer_entrypoint(&self) -> Result<&str, Error> {
        infer_entrypoint(
            self.resolution.package.entrypoint.as_deref(),
            &self.commands,
        )
    }
}

/// Apply the package entrypoint and the historical single-command inference.
pub fn infer_entrypoint<'a>(
    entrypoint: Option<&'a str>,
    commands: &'a [crate::commands::BinaryPackageCommand],
) -> Result<&'a str, Error> {
    if let Some(entrypoint) = entrypoint {
        return Ok(entrypoint);
    }
    match commands {
        [] => anyhow::bail!("The package doesn't contain any executable commands"),
        [one] => Ok(one.name()),
        [..] => {
            let mut commands: Vec<_> = commands.iter().map(|cmd| cmd.name()).collect();
            commands.sort();
            anyhow::bail!(
                "Unable to determine the package's entrypoint. Please choose one of {commands:?}"
            );
        }
    }
}

const MAX_PARALLEL_DOWNLOADS: usize = 32;

/// Fetch the command/filesystem dependency closure using the embedder's loader future.
/// Callbacks retain control of scheduling; their futures need not be Send.
pub async fn fetch_dependencies<F, Fut>(
    pkg: &ResolvedPackage,
    graph: &DependencyGraph,
    load: F,
) -> Result<HashMap<PackageId, Container>, Error>
where
    F: Fn(PackageSummary) -> Fut,
    Fut: std::future::Future<Output = Result<Container, Error>>,
{
    let packages = packages_needed_for_load(pkg);

    let packages = packages.into_iter().filter_map(|id| {
        let crate::resolver::Node { pkg, dist, .. } = &graph[&id];
        let summary = PackageSummary {
            pkg: pkg.clone(),
            dist: dist.clone()?,
        };
        Some((id, summary))
    });
    let packages: HashMap<PackageId, Container> = futures::stream::iter(packages)
        .map(|(id, s)| {
            let load = &load;
            async move {
                match load(s).await {
                    Ok(webc) => Ok((id, webc)),
                    Err(e) => Err(e),
                }
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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io::Write, sync::Mutex};

    use futures::future::BoxFuture;
    use http::{HeaderMap, HeaderValue, StatusCode};
    use tempfile::TempDir;
    use wasmer_config::package::PackageId;

    use crate::{
        http::{HttpRequest, HttpResponse},
        resolver::PackageInfo,
    };

    use super::*;

    const PYTHON: &[u8] =
        include_bytes!("../../../wasmer-test-files/examples/python--python@3.13.5.webc");

    #[derive(Debug)]
    pub(crate) struct DummyClient {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    impl DummyClient {
        pub fn with_responses(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
            DummyClient {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into_iter().collect()),
            }
        }
    }

    impl HttpClient for DummyClient {
        fn request(
            &self,
            request: HttpRequest,
        ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
            let response = self.responses.lock().unwrap().pop_front().unwrap();
            self.requests.lock().unwrap().push(request);
            Box::pin(async { Ok(response) })
        }
    }

    async fn cache_misses_will_trigger_a_download_internal() {
        let temp = TempDir::new().unwrap();
        let client = Arc::new(DummyClient::with_responses([HttpResponse {
            body: Some(PYTHON.to_vec()),
            redirected: false,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }]));
        let loader = PackageDownloader::new(Arc::new(DummyClient::with_responses([])))
            .with_cache_dir(temp.path())
            .with_shared_http_client(client.clone());
        let summary = PackageSummary {
            pkg: PackageInfo {
                id: PackageId::new_named("python/python", "0.1.0".parse().unwrap()),
                dependencies: Vec::new(),
                commands: Vec::new(),
                entrypoint: Some("asdf".to_string()),
                filesystem: Vec::new(),
            },
            dist: DistributionInfo {
                webc: "https://wasmer.io/python/python".parse().unwrap(),
                webc_sha256: [0xaa; 32].into(),
            },
        };

        let container = loader.load(&summary).await.unwrap();

        // A HTTP request was sent
        let requests = client.requests.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.url, summary.dist.webc);
        assert_eq!(request.method, "GET");
        #[cfg(not(target_arch = "wasm32"))]
        {
            assert_eq!(request.headers.len(), 3);
            assert_eq!(request.headers["Accept-Encoding"], "zstd;q=1.0, gzip;q=0.8");
        }
        #[cfg(target_arch = "wasm32")]
        {
            assert_eq!(request.headers.len(), 2);
            assert!(!request.headers.contains_key(http::header::ACCEPT_ENCODING));
        }
        assert_eq!(request.headers["Accept"], "application/webc");
        assert_eq!(request.headers["User-Agent"], USER_AGENT);
        // Make sure we got the right package
        let manifest = container.manifest();
        assert_eq!(manifest.entrypoint.as_deref(), Some("python"));
        // it should have been automatically saved to disk
        let path = loader
            .filesystem_cache
            .as_ref()
            .unwrap()
            .path(&summary.dist.webc_sha256);
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), PYTHON);
        // and cached in memory for next time
        let in_memory = loader.in_memory.as_ref().unwrap().0.read().unwrap();
        assert!(in_memory.contains_key(&summary.dist.webc_sha256));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn cache_misses_will_trigger_a_download() {
        cache_misses_will_trigger_a_download_internal().await
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn can_disable_in_memory_cache() {
        let temp = TempDir::new().unwrap();
        let client = Arc::new(DummyClient::with_responses([HttpResponse {
            body: Some(PYTHON.to_vec()),
            redirected: false,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }]));
        let loader = PackageDownloader::new(Arc::new(DummyClient::with_responses([])))
            .with_cache_dir(temp.path())
            .without_in_memory_cache()
            .with_shared_http_client(client);
        let summary = PackageSummary {
            pkg: PackageInfo {
                id: PackageId::new_named("python/python", "0.1.0".parse().unwrap()),
                dependencies: Vec::new(),
                commands: Vec::new(),
                entrypoint: Some("asdf".to_string()),
                filesystem: Vec::new(),
            },
            dist: DistributionInfo {
                webc: "https://wasmer.io/python/python".parse().unwrap(),
                webc_sha256: [0xbb; 32].into(),
            },
        };

        loader.load(&summary).await.unwrap();

        assert!(loader.in_memory.is_none());
    }

    #[cfg(target_arch = "wasm32")]
    #[tokio::test()]
    async fn cache_misses_will_trigger_a_download() {
        cache_misses_will_trigger_a_download_internal().await
    }

    #[tokio::test]
    async fn evict_cached_removes_in_memory_container() {
        let loader = PackageDownloader::new(Arc::new(DummyClient::with_responses([])));
        let container = from_bytes(PYTHON).unwrap();
        let hash: WebcHash = [0xaa; 32].into();
        loader.insert_cached(hash, &container);
        let evicted = loader.evict_cached(&hash);
        assert!(evicted.is_some());
        {
            let in_memory = loader.in_memory.as_ref().unwrap().0.read().unwrap();
            assert!(!in_memory.contains_key(&hash));
        }
        assert!(loader.evict_cached(&hash).is_none());
    }

    /// Small helper to construct headers with a given content-encoding.
    fn headers_with_encoding(content_encoding: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = content_encoding {
            headers.insert(http::header::CONTENT_ENCODING, value.parse().unwrap());
        }
        headers
    }

    /// Small helper to construct headers with a raw content-encoding value.
    fn headers_with_raw_encoding(value: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_bytes(value).unwrap(),
        );
        headers
    }

    /// Confirm decode_response_body passes through unencoded bodies unchanged.
    #[test]
    fn decode_response_body_passthrough() {
        let body = b"plain-bytes".to_vec();

        let decoded =
            PackageDownloader::decode_response_body(&headers_with_encoding(None), body.clone())
                .unwrap();
        assert_eq!(decoded, body);

        let decoded = PackageDownloader::decode_response_body(
            &headers_with_encoding(Some("identity")),
            body.clone(),
        )
        .unwrap();
        assert_eq!(decoded, body);
    }

    /// Confirm decode_response_body treats empty/whitespace encoding lists as no encoding.
    #[test]
    fn decode_response_body_empty_encoding_list() {
        let body = b"plain-bytes".to_vec();
        let decoded = PackageDownloader::decode_response_body(
            &headers_with_encoding(Some(" , , ")),
            body.clone(),
        )
        .unwrap();
        assert_eq!(decoded, body);
    }

    /// Confirm decode_response_body errors on non-utf8 content-encoding headers.
    #[test]
    fn decode_response_body_non_utf8_encoding_header() {
        let body = b"bytes".to_vec();
        let err =
            PackageDownloader::decode_response_body(&headers_with_raw_encoding(&[0xff]), body)
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("non-utf8 content-encoding"));
    }

    /// Confirm decode_response_body decodes gzip-encoded bodies.
    #[test]
    fn decode_response_body_gzip() {
        let body = b"gzip-bytes".to_vec();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&body).unwrap();
        let encoded = encoder.finish().unwrap();

        let decoded =
            PackageDownloader::decode_response_body(&headers_with_encoding(Some("gzip")), encoded)
                .unwrap();
        assert_eq!(decoded, body);
    }

    /// Confirm decode_response_body ignores identity when combined with other encodings.
    #[test]
    fn decode_response_body_identity_and_gzip() {
        let body = b"gzip-bytes".to_vec();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&body).unwrap();
        let encoded = encoder.finish().unwrap();

        let decoded = PackageDownloader::decode_response_body(
            &headers_with_encoding(Some("identity, gzip")),
            encoded,
        )
        .unwrap();
        assert_eq!(decoded, body);
    }

    /// Confirm decode_response_body errors on invalid gzip payloads.
    #[test]
    fn decode_response_body_gzip_invalid_payload() {
        let body = b"not-gzip".to_vec();
        let err =
            PackageDownloader::decode_response_body(&headers_with_encoding(Some("gzip")), body)
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to decode response body"));
    }

    /// Confirm decode_response_body decodes zstd-encoded bodies.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_response_body_zstd() {
        let body = b"zstd-bytes".to_vec();
        let encoded = zstd::stream::encode_all(std::io::Cursor::new(&body), 0).unwrap();

        let decoded =
            PackageDownloader::decode_response_body(&headers_with_encoding(Some("zstd")), encoded)
                .unwrap();
        assert_eq!(decoded, body);
    }

    /// Confirm decode_response_body errors on invalid zstd payloads.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_response_body_zstd_invalid_payload() {
        let body = b"not-zstd".to_vec();
        let err =
            PackageDownloader::decode_response_body(&headers_with_encoding(Some("zstd")), body)
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to decode response body"));
    }

    /// Confirm decode_response_body decodes layered gzip+zstd-encoded bodies.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn decode_response_body_zstd_and_gzip() {
        let body = b"layered-bytes".to_vec();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&body).unwrap();
        let gzipped = encoder.finish().unwrap();
        let encoded = zstd::stream::encode_all(std::io::Cursor::new(gzipped), 0).unwrap();

        let decoded = PackageDownloader::decode_response_body(
            &headers_with_encoding(Some("gzip, zstd")),
            encoded,
        )
        .unwrap();
        assert_eq!(decoded, body);
    }

    /// Confirm decode_response_body errors on unknown encodings.
    #[test]
    fn decode_response_body_unknown_encoding() {
        let body = b"weird".to_vec();
        let err = PackageDownloader::decode_response_body(&headers_with_encoding(Some("br")), body)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported content-encoding"));
    }

    #[tokio::test]
    async fn test_builtin_package_downloader_cache_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        let contents = "fail";
        let correct_hash = WebcHash::sha256(contents);
        let used_hash =
            WebcHash::parse_hex("0000a28ea38a000f3a3328cb7fabe330638d3258affe1a869e3f92986222d997")
                .unwrap();
        let filename = format!("{}{}", used_hash, FileSystemCache::FILE_SUFFIX);
        let file_path = path.join(filename);
        std::fs::write(&file_path, contents).unwrap();

        let dl =
            PackageDownloader::new(Arc::new(DummyClient::with_responses([]))).with_cache_dir(path);

        let errors = dl
            .validate_cache(CacheValidationMode::PruneOnMismatch)
            .unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].actual_hash, correct_hash);
        assert_eq!(errors[0].expected_hash, used_hash);

        assert_eq!(file_path.exists(), false);
    }

    #[tokio::test]
    async fn test_file_cache_scan_retain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        let cache = FileSystemCache {
            cache_dir: path.to_path_buf(),
        };

        {
            let state = cache
                .scan(0u64, |state: &mut u64, _entry| {
                    *state += 1;
                    Ok(())
                })
                .await
                .unwrap();

            assert_eq!(state, 0);
        }

        let path1 = cache
            .save_impl(
                Bytes::from_static(b"test1"),
                &DistributionInfo {
                    webc: Url::parse("file:///test1.webc").unwrap(),
                    webc_sha256: WebcHash::sha256(b"test1"),
                },
            )
            .await
            .unwrap();
        let path2 = cache
            .save_impl(
                Bytes::from_static(b"test2"),
                &DistributionInfo {
                    webc: Url::parse("file:///test2.webc").unwrap(),
                    webc_sha256: WebcHash::sha256(b"test2"),
                },
            )
            .await
            .unwrap();

        {
            let path1 = path1.clone();
            let path2 = path2.clone();
            let state = cache
                .scan(0u64, move |state: &mut u64, entry| {
                    *state += 1;
                    assert!(entry.path() == path1 || entry.path() == path2);
                    Ok(())
                })
                .await
                .unwrap();

            assert_eq!(state, 2);
        }

        {
            let path1 = path1.clone();
            let state = cache
                .retain(0u64, move |state: &mut u64, entry| {
                    *state += 1;
                    Ok(entry.path() == path1)
                })
                .await
                .unwrap();
            assert_eq!(state, 2);
        }

        assert!(path1.exists());
        assert!(!path2.exists(), "Path 2 should have been deleted");

        {
            let path1 = path1.clone();
            let state = cache
                .scan(0u64, move |state: &mut u64, entry| {
                    *state += 1;
                    assert!(entry.path() == path1);
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(state, 1);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod progress {
        use super::*;
        use crate::http::{HttpBodyObserver, HttpResponse};
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Debug)]
        struct BodyClient {
            body: Vec<u8>,
            headers: HeaderMap,
            status: StatusCode,
            cached: bool,
            stall: bool,
            fail: bool,
            returned: AtomicBool,
            dropped: Arc<AtomicBool>,
            http_started: Mutex<Option<futures::channel::oneshot::Sender<()>>>,
        }

        impl BodyClient {
            fn new(body: Vec<u8>, headers: HeaderMap) -> Arc<Self> {
                Arc::new(Self {
                    body,
                    headers,
                    status: StatusCode::OK,
                    cached: false,
                    stall: false,
                    fail: false,
                    returned: AtomicBool::new(false),
                    dropped: Arc::default(),
                    http_started: Mutex::new(None),
                })
            }
            fn response(&self) -> HttpResponse {
                HttpResponse {
                    body: Some(self.body.clone()),
                    headers: self.headers.clone(),
                    status: self.status,
                    redirected: false,
                }
            }
        }

        impl HttpClient for BodyClient {
            fn request(&self, _: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>> {
                Box::pin(async move {
                    if self.fail {
                        bail!("body stream failed");
                    }
                    Ok(self.response())
                })
            }
            fn request_with_body_progress(
                &self,
                _: HttpRequest,
                progress: HttpBodyObserver,
            ) -> BoxFuture<'_, Result<HttpResponse, Error>> {
                Box::pin(async move {
                    struct Dropped(Arc<AtomicBool>);
                    impl Drop for Dropped {
                        fn drop(&mut self) {
                            self.0.store(true, Ordering::SeqCst);
                        }
                    }
                    let _guard = Dropped(self.dropped.clone());
                    if let Some(started) = self.http_started.lock().unwrap().take() {
                        let _ = started.send(());
                    }
                    progress(HttpBodyEvent::Head {
                        status: self.status,
                        headers: &self.headers,
                        cached: self.cached,
                    });
                    // Split the WEBC format prefix across chunks, not just the payload.
                    for chunk in self.body.chunks(5) {
                        progress(HttpBodyEvent::Chunk(chunk));
                    }
                    if self.stall {
                        futures::future::pending::<()>().await;
                    }
                    if self.fail {
                        bail!("body stream failed");
                    }
                    self.returned.store(true, Ordering::SeqCst);
                    Ok(self.response())
                })
            }
        }

        fn webc() -> Vec<u8> {
            use webc::v3::{ChecksumAlgorithm, SignatureAlgorithm, write::Writer};
            Writer::new(ChecksumAlgorithm::Sha256)
                .write_manifest(&webc::metadata::Manifest::default())
                .unwrap()
                .write_atoms(Default::default())
                .unwrap()
                .finish(SignatureAlgorithm::None)
                .unwrap()
                .to_vec()
        }

        fn summary(body: &[u8]) -> PackageSummary {
            PackageSummary {
                pkg: PackageInfo {
                    id: PackageId::new_named("test/progress", "1.0.0".parse().unwrap()),
                    dependencies: Vec::new(),
                    commands: Vec::new(),
                    entrypoint: None,
                    filesystem: Vec::new(),
                },
                dist: DistributionInfo {
                    webc: "https://example.test/package.webc".parse().unwrap(),
                    webc_sha256: WebcHash::sha256(body),
                },
            }
        }

        type Events = Arc<Mutex<Vec<(bool, PackageDownloadProgress)>>>;
        fn observe(client: &Arc<BodyClient>) -> (Events, PackageDownloadObserver) {
            let events: Events = Arc::default();
            let captured = events.clone();
            let client = client.clone();
            let observer = Arc::new(move |event| {
                captured
                    .lock()
                    .unwrap()
                    .push((client.returned.load(Ordering::SeqCst), event));
            });
            (events, observer)
        }

        fn gzip(body: &[u8]) -> Vec<u8> {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(body).unwrap();
            encoder.finish().unwrap()
        }

        #[tokio::test]
        async fn raw_webc_progress_uses_actual_chunks_and_known_or_unknown_totals() {
            let body = webc();
            for known in [false, true] {
                let mut headers = HeaderMap::new();
                if known {
                    headers.insert(http::header::CONTENT_LENGTH, body.len().into());
                }
                let client = BodyClient::new(body.clone(), headers);
                let (events, observer) = observe(&client);
                PackageDownloader::new(client)
                    .load_with_progress(&summary(&body), Some(observer))
                    .await
                    .unwrap();
                let events = events.lock().unwrap();
                let during: Vec<_> = events
                    .iter()
                    .filter(|(returned, p)| !returned && p.downloaded_bytes > 0)
                    .map(|(_, p)| p)
                    .collect();
                assert!(during.len() > 1);
                assert_eq!(
                    during[0].downloaded_bytes, 10,
                    "first five bytes cannot identify a raw WEBC"
                );
                for progress in &during {
                    assert_eq!(progress.phase, PackageDownloadPhase::Downloading);
                    assert_eq!(progress.total_bytes, known.then_some(body.len() as u64));
                }
                assert_eq!(during.last().unwrap().downloaded_bytes, body.len() as u64);
                assert_eq!(
                    events.last().unwrap().1,
                    PackageDownloadProgress {
                        phase: PackageDownloadPhase::Ready,
                        downloaded_bytes: body.len() as u64,
                        total_bytes: Some(body.len() as u64),
                        cached: false,
                    }
                );
            }
        }

        #[tokio::test]
        async fn declared_compression_counts_only_the_existing_decoders_output() {
            let body = webc();
            for (encoding, encoded) in [
                ("gzip", gzip(&body)),
                (
                    "zstd",
                    zstd::stream::encode_all(body.as_slice(), 0).unwrap(),
                ),
                (
                    "gzip, zstd",
                    zstd::stream::encode_all(gzip(&body).as_slice(), 0).unwrap(),
                ),
            ] {
                let mut headers = headers_with_encoding(Some(encoding));
                headers.insert(http::header::CONTENT_LENGTH, encoded.len().into());
                let client = BodyClient::new(encoded.clone(), headers);
                let (events, observer) = observe(&client);
                PackageDownloader::new(client)
                    .load_with_progress(&summary(&body), Some(observer))
                    .await
                    .unwrap();
                let events = events.lock().unwrap();
                assert!(
                    events
                        .iter()
                        .filter(|(returned, _)| !returned)
                        .all(|(_, p)| p.downloaded_bytes == 0 && p.total_bytes.is_none())
                );
                let ready = &events.last().unwrap().1;
                assert_eq!(ready.phase, PackageDownloadPhase::Ready);
                assert_eq!(ready.downloaded_bytes, body.len() as u64);
                assert_eq!(ready.total_bytes, Some(body.len() as u64));
            }
        }

        #[tokio::test]
        async fn unknown_wrappers_bad_headers_and_failures_never_invent_decoded_bytes_or_ready() {
            let raw = webc();
            let mut bad_status = BodyClient::new(raw.clone(), headers_with_encoding(Some("gzip")));
            Arc::get_mut(&mut bad_status).unwrap().status = StatusCode::BAD_GATEWAY;
            let mut stream_failure = BodyClient::new(raw.clone(), HeaderMap::new());
            Arc::get_mut(&mut stream_failure).unwrap().fail = true;
            let clients = [
                BodyClient::new(gzip(&raw), HeaderMap::new()),
                BodyClient::new(
                    zstd::stream::encode_all(raw.as_slice(), 0).unwrap(),
                    HeaderMap::new(),
                ),
                BodyClient::new(gzip(&gzip(&raw)), headers_with_encoding(Some("gzip"))),
                BodyClient::new(raw.clone(), headers_with_encoding(Some("unknown"))),
                BodyClient::new(raw.clone(), headers_with_raw_encoding(&[0xff])),
                BodyClient::new(b"opaque unknown container".to_vec(), HeaderMap::new()),
                bad_status,
            ];
            for client in clients {
                let (events, observer) = observe(&client);
                let downloader = PackageDownloader::new(client);
                let summary = summary(&raw);
                let observed = downloader
                    .load_with_progress(&summary, Some(observer))
                    .await
                    .unwrap_err();
                let unobserved = downloader.load(&summary).await.unwrap_err();
                assert_eq!(format!("{observed:#}"), format!("{unobserved:#}"));
                assert!(
                    events
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|(_, p)| p.downloaded_bytes == 0
                            && p.total_bytes.is_none()
                            && p.phase != PackageDownloadPhase::Ready)
                );
            }
            // Failures after a recognizable raw prefix can report genuine bytes,
            // but only a successfully parsed container may become Ready.
            for (client, hash_failure) in [
                (stream_failure, false),
                (
                    BodyClient::new(b"\0webc003bad container".to_vec(), HeaderMap::new()),
                    false,
                ),
                (BodyClient::new(raw.clone(), HeaderMap::new()), true),
            ] {
                let (events, observer) = observe(&client);
                let mut summary = summary(&client.body);
                let downloader = PackageDownloader::new(client)
                    .with_hash_validation_mode(HashIntegrityValidationMode::FailOnHashMismatch);
                if hash_failure {
                    summary.dist.webc_sha256 = [0xaa; 32].into();
                }
                assert!(
                    downloader
                        .load_with_progress(&summary, Some(observer))
                        .await
                        .is_err()
                );
                assert!(
                    events
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|(_, p)| p.phase != PackageDownloadPhase::Ready)
                );
            }
        }

        #[tokio::test]
        async fn local_and_memory_or_persistent_cache_hits_contribute_zero_download_bytes() {
            let body = webc();
            let summary = summary(&body);
            let cache = TempDir::new().unwrap();
            let client = BodyClient::new(body.clone(), HeaderMap::new());
            let downloader =
                Arc::new(PackageDownloader::new(client.clone()).with_cache_dir(cache.path()));
            downloader.load(&summary).await.unwrap();
            for loader in [
                downloader.clone(),
                Arc::new(PackageDownloader::new(client.clone()).with_cache_dir(cache.path())),
            ] {
                let events: Arc<Mutex<Vec<_>>> = Arc::default();
                let captured = events.clone();
                let reentrant = loader.clone();
                let summary = summary.clone();
                let hash = summary.dist.webc_sha256;
                loader
                    .load_with_progress(
                        &summary,
                        Some(Arc::new(move |progress| {
                            // This takes the cache write lock: observer calls are outside it.
                            reentrant.evict_cached(&hash);
                            captured.lock().unwrap().push(progress);
                        })),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    *events.lock().unwrap(),
                    [PackageDownloadProgress {
                        phase: PackageDownloadPhase::Ready,
                        downloaded_bytes: 0,
                        total_bytes: Some(0),
                        cached: true,
                    }]
                );
            }
            let file = cache.path().join("local.webc");
            std::fs::write(&file, &body).unwrap();
            let mut local = summary.clone();
            local.dist.webc = Url::from_file_path(&file).unwrap();
            let (events, observer) = observe(&client);
            PackageDownloader::new(client)
                .load_with_progress(&local, Some(observer))
                .await
                .unwrap();
            assert!(
                events
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(_, p)| p.downloaded_bytes == 0 && p.total_bytes == Some(0))
            );
        }

        #[tokio::test]
        async fn provider_cache_hits_preserve_cached_identity_without_transfer_bytes() {
            let body = webc();
            let mut client = BodyClient::new(body.clone(), HeaderMap::new());
            Arc::get_mut(&mut client).unwrap().cached = true;
            let (events, observer) = observe(&client);
            PackageDownloader::new(client)
                .load_with_progress(&summary(&body), Some(observer))
                .await
                .unwrap();
            let events = events.lock().unwrap();
            assert!(
                events
                    .iter()
                    .skip(1)
                    .all(|(_, p)| p.cached && p.downloaded_bytes == 0 && p.total_bytes == Some(0))
            );
            assert_eq!(events.last().unwrap().1.phase, PackageDownloadPhase::Ready);
        }

        #[tokio::test]
        async fn tuple_only_provider_cache_hits_do_not_count_buffered_package_bytes() {
            #[derive(Debug)]
            struct TupleCacheClient(Arc<BodyClient>);
            impl HttpClient for TupleCacheClient {
                fn request(
                    &self,
                    request: HttpRequest,
                ) -> BoxFuture<'_, Result<HttpResponse, Error>> {
                    self.0.request(request)
                }
                fn request_with_progress(
                    &self,
                    request: HttpRequest,
                    progress: crate::http::HttpDownloadObserver,
                ) -> BoxFuture<'_, Result<HttpResponse, Error>> {
                    let response = self.request(request);
                    Box::pin(async move {
                        progress(1000, None, false);
                        progress(1, None, true);
                        response.await
                    })
                }
            }
            let body = webc();
            let events: Arc<Mutex<Vec<PackageDownloadProgress>>> = Arc::default();
            let captured = events.clone();
            let client = Arc::new(TupleCacheClient(BodyClient::new(
                body.clone(),
                HeaderMap::new(),
            )));
            PackageDownloader::new(client)
                .load_with_progress(
                    &summary(&body),
                    Some(Arc::new(move |progress| {
                        captured.lock().unwrap().push(progress)
                    })),
                )
                .await
                .unwrap();
            let events = events.lock().unwrap();
            assert!(
                events
                    .iter()
                    .skip(1)
                    .all(|p| p.cached && p.downloaded_bytes == 0 && p.total_bytes == Some(0))
            );
            assert_eq!(events.last().unwrap().phase, PackageDownloadPhase::Ready);
        }

        #[tokio::test]
        async fn dropping_an_http_load_stops_before_cache_and_ready() {
            let body = webc();
            let mut client = BodyClient::new(body.clone(), HeaderMap::new());
            let (started, in_http) = futures::channel::oneshot::channel();
            let configuration = Arc::get_mut(&mut client).unwrap();
            configuration.stall = true;
            *configuration.http_started.get_mut().unwrap() = Some(started);
            let (events, observer) = observe(&client);
            let cache = TempDir::new().unwrap();
            let downloader = PackageDownloader::new(client.clone()).with_cache_dir(cache.path());
            let summary = summary(&body);
            let mut load = Box::pin(downloader.load_with_progress(&summary, Some(observer)));
            // Disk-cache lookup may be the first Pending. Drive it until the
            // actual HTTP future has been polled and owns its live drop guard.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::select! {
                    result = &mut load => panic!("load completed before HTTP cancellation: {result:?}"),
                    started = in_http => started.expect("HTTP future started"),
                }
            })
            .await
            .expect("HTTP future must start within the test deadline");
            assert!(!client.dropped.load(Ordering::SeqCst));
            drop(load);
            assert!(
                client.dropped.load(Ordering::SeqCst),
                "the actual HTTP future was dropped"
            );
            assert!(
                downloader
                    .in_memory
                    .as_ref()
                    .unwrap()
                    .0
                    .read()
                    .unwrap()
                    .is_empty()
            );
            assert!(std::fs::read_dir(cache.path()).unwrap().next().is_none());
            assert!(
                events
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(_, p)| p.phase == PackageDownloadPhase::Downloading)
            );
        }

        #[cfg(feature = "authoring")]
        #[tokio::test]
        async fn an_opaque_archive_can_be_ready_with_unknown_decoded_size() {
            let manifest =
                b"[package]\nname = 'test'\nversion = '0.0.0'\ndescription = 'opaque archive'\n";
            let mut archive = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "wasmer.toml", manifest.as_slice())
                .unwrap();
            let body = gzip(&archive.into_inner().unwrap());
            let client = BodyClient::new(body.clone(), HeaderMap::new());
            let (events, observer) = observe(&client);
            PackageDownloader::new(client)
                .load_with_progress(&summary(&body), Some(observer))
                .await
                .unwrap();
            let events = events.lock().unwrap();
            assert!(
                events
                    .iter()
                    .all(|(_, p)| p.downloaded_bytes == 0 && p.total_bytes.is_none())
            );
            assert_eq!(events.last().unwrap().1.phase, PackageDownloadPhase::Ready);
        }
    }
}
