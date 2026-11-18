//! Host-owned preparation, shared by opt-in native loader roots.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};

use async_lock::OnceCell;
use wasixv2_syscalls::{Image, ImageId};
use wasmer::{Engine, EngineId, MemoryStyle, Module};
use wasmer_cache::module_cache::{ModuleCache, load_module};
use wasmer_compiler::ArtifactCreate;
use wasmer_types::ModuleHash;

use super::{LoadPolicy, Result, graph::Library, lock, verify_compiled_source};
use crate::artifact::PreparedArtifact;

/// In-memory retention limits for one shared dylink cache.
#[derive(Clone, Copy, Debug, Default)]
pub struct DylinkCacheConfig {
    /// Maximum bytes charged to resident entries. Zero disables in-memory retention.
    pub max_bytes: usize,
    /// Optional additional entry limit. Zero disables the cache.
    pub max_entries: Option<usize>,
    /// Time since the last lookup before eviction. Zero retains no completed entries.
    pub time_to_idle: Option<Duration>,
}

/// Cumulative preparation events and current resident payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DylinkCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub bytes: usize,
    pub entries: usize,
}

type SourceOwner = Weak<dyn AsRef<[u8]> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum SourceKey {
    Shared(ImageId),
    Copied(ModuleHash),
}

impl SourceKey {
    pub(super) fn of(image: &Image) -> (Self, Option<SourceOwner>) {
        match image.identity() {
            Some(id) => (Self::Shared(id), Some(Arc::downgrade(&image.keep_alive()))),
            None => (Self::Copied(ModuleHash::new(image.bytes())), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum Key {
    Main(String, bool),
    Side(SourceKey, EngineId, bool),
    Code {
        source: SourceKey,
        engine: EngineId,
        memories: Vec<MemoryStyle>,
        main_tls: Vec<(u32, u32)>,
    },
}

impl Key {
    fn heap_bytes(&self) -> usize {
        match self {
            Self::Main(id, _) => id.capacity(),
            Self::Side(..) => 0,
            Self::Code {
                memories, main_tls, ..
            } => {
                memories.capacity() * size_of::<MemoryStyle>()
                    + main_tls.capacity() * size_of::<(u32, u32)>()
            }
        }
    }
}

pub(super) enum Payload {
    Library(Box<Library>),
    Code(Arc<PreparedArtifact>),
}

struct Resident {
    source: Option<SourceOwner>,
    value: Arc<Payload>,
    bytes: usize,
    last_use: Instant,
    order: u64,
}

type Flight = OnceCell<Result<Arc<Payload>>>;

#[derive(Default)]
struct State {
    entries: HashMap<Key, Resident>,
    flights: HashMap<Key, Weak<Flight>>,
    stats: DylinkCacheStats,
    order: u64,
    stopping: bool,
}

impl State {
    fn remove(&mut self, key: &Key) {
        if let Some(entry) = self.entries.remove(key) {
            self.stats.bytes -= entry.bytes;
            self.stats.entries -= 1;
            self.stats.evictions += 1;
        }
    }
}

struct Shared {
    config: DylinkCacheConfig,
    state: Mutex<State>,
    changed: Condvar,
}

struct Persistent {
    cache: Arc<dyn ModuleCache + Send + Sync>,
    namespace: String,
}

impl Persistent {
    fn prepare(
        &self,
        engine: &Engine,
        library: &Library,
        memories: &[MemoryStyle],
        main_tls: &BTreeMap<u32, u32>,
    ) -> Result<(ModuleHash, Vec<u8>)> {
        let bytes = PreparedArtifact::compiler_input(&library.initialization, main_tls)?;
        let input = ModuleHash::new(&bytes);
        let sys = engine.as_sys();
        let target = sys.target();
        let features = sys.inner().features().clone();
        // Use the actual instrumented input, plus compile settings not captured by
        // the cache's engine/format partition. The namespace covers custom middleware.
        let configuration = (
            &self.namespace,
            engine.deterministic_id(),
            engine.artifact_format(),
            wasmer_types::MetadataHeader::CURRENT_VERSION,
            target.triple(),
            target.cpu_features(),
            features,
            memories,
            main_tls,
        );
        let key = ModuleHash::new(format!("wasixv2-side-v1 {input} {configuration:?}").as_bytes());
        Ok((key, bytes))
    }
}

fn memory_styles(engine: &Engine, library: &Library) -> Option<Vec<MemoryStyle>> {
    let tunables = engine.as_sys().tunables();
    library
        .metadata
        .memory_types
        .iter()
        .map(|ty| {
            let min = u32::try_from(ty.initial).ok()?;
            let max = match ty.maximum {
                Some(max) => Some(u32::try_from(max).ok()?),
                None => None,
            };
            Some(tunables.memory_style(&wasmer::MemoryType::new(min, max, ty.shared)))
        })
        .collect()
}

/// Bounded, in-memory dylink preparation for machines that share this object.
///
/// Cached state owns its parsed and compiled outputs. Its image identity keys
/// hold weak owners, so the cache does not extend the lifetime of package files
/// or their backing WEBC. Once an entry is evicted, already running images may
/// still use their own references to the parsed state.
pub struct DylinkCache {
    shared: Arc<Shared>,
    persistent: Option<Persistent>,
}

impl std::fmt::Debug for DylinkCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DylinkCache")
            .field("config", &self.shared.config)
            .field("stats", &self.stats())
            .finish()
    }
}

impl DylinkCache {
    /// Creates an empty cache. A positive idle timeout starts its expiry worker.
    pub fn new(config: DylinkCacheConfig) -> Self {
        let cache = Self {
            shared: Arc::new(Shared {
                config,
                state: Mutex::default(),
                changed: Condvar::new(),
            }),
            persistent: None,
        };
        if cache.enabled()
            && let Some(idle) = config.time_to_idle.filter(|idle| !idle.is_zero())
        {
            let shared = cache.shared.clone();
            std::thread::spawn(move || expire_idle(&shared, idle));
        }
        cache
    }

    /// Use an embedder's trusted compiled-module cache for native side modules.
    ///
    /// The namespace must distinguish compiler and middleware settings that affect
    /// artifacts but are not reflected in the engine's deterministic ID. Use the
    /// same namespace on every node sharing compatible artifacts. Cache failures
    /// fall back to local compilation. This works with a zero in-memory budget.
    pub fn with_module_cache(
        mut self,
        cache: Arc<dyn ModuleCache + Send + Sync>,
        namespace: impl Into<String>,
    ) -> Self {
        self.persistent = Some(Persistent {
            cache,
            namespace: namespace.into(),
        });
        self
    }

    /// Return the persistent key and compiler input for a side-only image whose
    /// main TLS bindings are independent of the loaded graph. Call only for
    /// images classified by [`crate::is_side_only`]. Returns `None` if the engine
    /// has no cache configured or an import could require main TLS relocation.
    pub fn prepare_side_for_prewarm(
        &self,
        engine: &Engine,
        source: &[u8],
    ) -> Result<Option<(ModuleHash, Vec<u8>)>> {
        let Some(persistent) = self.persistent.as_ref().filter(|_| engine.is_sys()) else {
            return Ok(None);
        };
        let library = Library::new(source.to_vec(), None)?;
        if library.metadata.imports().iter().any(|import| {
            import.module == "GOT.mem" && matches!(import.ty, crate::ExternType::Global(_))
        }) {
            return Ok(None);
        }
        let Some(memories) = memory_styles(engine, &library) else {
            return Ok(None);
        };
        persistent
            .prepare(engine, &library, &memories, &BTreeMap::new())
            .map(Some)
    }

    /// Takes a snapshot of preparation counters and current resident entries.
    pub fn stats(&self) -> DylinkCacheStats {
        lock(&self.shared.state).stats
    }

    pub(super) fn active(&self) -> bool {
        self.enabled() || self.persistent.is_some()
    }

    fn enabled(&self) -> bool {
        self.shared.config.max_bytes != 0 && self.shared.config.max_entries != Some(0)
    }

    pub(super) fn verified_main(
        &self,
        artifact: &wasmer::sys::Artifact,
        module: &Module,
        policy: &dyn LoadPolicy,
    ) -> Option<Result<Library>> {
        module.info().custom_sections.get(crate::SOURCE_SECTION)?;
        let honor_visibility = policy.honor_export_visibility();
        let key = Key::Main(artifact.id().id(), honor_visibility);
        Some(self.library(key, None, || {
            let source = verify_compiled_source(module)?;
            Library::with_visibility(source, None, honor_visibility)
        }))
    }

    pub(super) fn prepare_library(
        &self,
        image: &Image,
        engine: EngineId,
        policy: &dyn LoadPolicy,
    ) -> Result<Library> {
        let (source, owner) = SourceKey::of(image);
        let honor_visibility = policy.honor_export_visibility();
        let key = Key::Side(source, engine, honor_visibility);
        self.library(key, owner, || {
            Library::with_visibility(image.bytes().to_vec(), None, honor_visibility)
        })
    }

    fn library(
        &self,
        key: Key,
        owner: Option<SourceOwner>,
        prepare: impl FnOnce() -> Result<Library> + Unpin,
    ) -> Result<Library> {
        if !self.enabled() {
            return prepare();
        }
        let value = self.get_or_prepare(key, owner, || {
            let library = prepare()?;
            let bytes = library.retained_bytes();
            Ok((Payload::Library(Box::new(library)), Some(bytes)))
        })?;
        let Payload::Library(library) = value.as_ref() else {
            unreachable!("only libraries use this cache key");
        };
        Ok((**library).clone())
    }

    pub(super) async fn prepare_code(
        &self,
        engine: &Engine,
        library: &Library,
        main_tls: &BTreeMap<u32, u32>,
    ) -> Result<Arc<PreparedArtifact>> {
        let Some(memories) = memory_styles(engine, library) else {
            return PreparedArtifact::compile_main_tls(
                engine,
                library.initialization.clone(),
                main_tls,
            )
            .map(Arc::new);
        };
        let compile = || self.compile(engine, library, main_tls, &memories);
        if !self.enabled() {
            return compile().await;
        }
        let (source, owner) = match library.backing.as_ref() {
            Some(image) if image.identity().is_some() => SourceKey::of(image),
            _ => (SourceKey::Copied(library.code_hash), None),
        };
        let key = Key::Code {
            source,
            engine: engine.id(),
            memories: memories.clone(),
            main_tls: main_tls
                .iter()
                .map(|(&index, &offset)| (index, offset))
                .collect(),
        };
        let prepare = || async {
            let artifact = compile().await?;
            let compiled = artifact
                .module()
                .sys_artifact()
                .expect("sys compiler returned sys code");
            if !compiled.memory_styles().values().eq(&memories) {
                return Ok((Payload::Code(artifact), None));
            }
            let heap = loupe::size_of_val(compiled)
                .saturating_add(library.initialization.retained_bytes());
            // The runtime heap metric omits the backing of native archives.
            let bytes = if engine.artifact_format() == "native" {
                artifact
                    .module()
                    .serialize()
                    .ok()
                    .map(|bytes| heap.saturating_add(bytes.len()))
            } else {
                Some(heap)
            };
            Ok((Payload::Code(artifact), bytes))
        };
        let value = match self.begin(&key) {
            Ok(value) => value,
            Err(flight) => flight
                .get_or_init(|| async {
                    let output = prepare().await;
                    self.finish(key, owner, output)
                })
                .await
                .clone()?,
        };
        let Payload::Code(artifact) = value.as_ref() else {
            unreachable!("only compiled modules use this cache key");
        };
        Ok(artifact.clone())
    }

    async fn compile(
        &self,
        engine: &Engine,
        library: &Library,
        main_tls: &BTreeMap<u32, u32>,
        memories: &[MemoryStyle],
    ) -> Result<Arc<PreparedArtifact>> {
        let initialization = library.initialization.clone();
        let Some(persistent) = &self.persistent else {
            return PreparedArtifact::compile_main_tls(engine, initialization, main_tls)
                .map(Arc::new);
        };
        let (key, bytes) = persistent.prepare(engine, library, memories, main_tls)?;
        let module = load_module(engine, persistent.cache.as_ref(), key, &bytes, None)
            .await
            .map_err(super::failure)?;
        Ok(Arc::new(PreparedArtifact::new(initialization, module)))
    }

    fn get_or_prepare(
        &self,
        key: Key,
        source: Option<SourceOwner>,
        prepare: impl FnOnce() -> Result<(Payload, Option<usize>)> + Unpin,
    ) -> Result<Arc<Payload>> {
        match self.begin(&key) {
            Ok(value) => Ok(value),
            Err(flight) => flight
                .get_or_init_blocking(|| self.finish(key, source, prepare()))
                .clone(),
        }
    }

    fn begin(&self, key: &Key) -> std::result::Result<Arc<Payload>, Arc<Flight>> {
        debug_assert!(self.enabled());
        let config = self.shared.config;
        let mut state = lock(&self.shared.state);
        let order = state.order;
        state.order += 1;
        let now = Instant::now();
        if let Some(entry) = state.entries.get_mut(key) {
            if entry
                .source
                .as_ref()
                .is_none_or(|owner| owner.upgrade().is_some())
                && config
                    .time_to_idle
                    .is_none_or(|idle| now.duration_since(entry.last_use) < idle)
            {
                entry.last_use = now;
                entry.order = order;
                let value = entry.value.clone();
                state.stats.hits += 1;
                return Ok(value);
            }
            state.remove(key);
        }
        if let Some(flight) = state.flights.get(key).and_then(Weak::upgrade) {
            state.stats.hits += 1;
            Err(flight)
        } else {
            state.stats.misses += 1;
            state.flights.retain(|_, flight| flight.strong_count() != 0);
            let flight = Arc::new(OnceCell::new());
            state.flights.insert(key.clone(), Arc::downgrade(&flight));
            Err(flight)
        }
    }

    fn finish(
        &self,
        key: Key,
        source: Option<SourceOwner>,
        output: Result<(Payload, Option<usize>)>,
    ) -> Result<Arc<Payload>> {
        let config = self.shared.config;
        let mut state = lock(&self.shared.state);
        state.flights.remove(&key);
        let (value, bytes) = output?;
        let value = Arc::new(value);
        if let Some(bytes) = bytes.map(|bytes| {
            bytes.saturating_add(size_of::<(Key, Resident, Payload)>() + key.heap_bytes())
        }) && bytes <= config.max_bytes
            && config.time_to_idle != Some(Duration::ZERO)
        {
            while state.stats.bytes > config.max_bytes - bytes
                || config
                    .max_entries
                    .is_some_and(|max| state.entries.len() >= max)
            {
                let oldest = state
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.order)
                    .map(|(key, _)| key.clone())
                    .expect("a resident entry exceeds the cache budget");
                state.remove(&oldest);
            }
            let order = state.order;
            state.order += 1;
            state.entries.insert(
                key,
                Resident {
                    source,
                    value: value.clone(),
                    bytes,
                    last_use: Instant::now(),
                    order,
                },
            );
            state.stats.bytes += bytes;
            state.stats.entries += 1;
            self.shared.changed.notify_one();
        }
        Ok(value)
    }
}

impl Drop for DylinkCache {
    fn drop(&mut self) {
        let mut state = lock(&self.shared.state);
        state.stopping = true;
        state.entries.clear();
        self.shared.changed.notify_one();
    }
}

fn expire_idle(shared: &Shared, idle: Duration) {
    let mut state = lock(&shared.state);
    while !state.stopping {
        let now = Instant::now();
        let mut next = None;
        state.entries.retain(|_, entry| {
            if let Some(remaining) = idle
                .checked_sub(now.duration_since(entry.last_use))
                .filter(|remaining| !remaining.is_zero())
            {
                next = Some(next.map_or(remaining, |next: Duration| next.min(remaining)));
                true
            } else {
                false
            }
        });
        let removed = state.stats.entries - state.entries.len();
        if removed != 0 {
            state.stats.bytes = state.entries.values().map(|entry| entry.bytes).sum();
            state.stats.entries -= removed;
            state.stats.evictions += removed as u64;
        }
        state = match next {
            Some(timeout) => {
                shared
                    .changed
                    .wait_timeout(state, timeout)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0
            }
            None => shared
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    fn code() -> Result<(Payload, Option<usize>)> {
        let library = Library::new(crate::tests::bytes("(module)", [0; 4], &[], &[], &[]), None)?;
        Ok((Payload::Library(Box::new(library)), Some(1024)))
    }

    #[test]
    fn byte_limit_evicts_the_least_recently_used_entry_and_does_not_pin_source() {
        let cache = DylinkCache::new(DylinkCacheConfig {
            max_bytes: 3000,
            ..DylinkCacheConfig::default()
        });
        let data = Arc::new(vec![0_u8; 64]);
        let source = Arc::downgrade(&data);
        let image = Image::shared(data);
        let (source_key, owner) = SourceKey::of(&image);
        let first = Key::Side(source_key, Engine::default().id(), true);
        let value = cache.get_or_prepare(first.clone(), owner, code).unwrap();
        let old_value = Arc::downgrade(&value);
        drop(value);
        let second = Key::Main("second".to_owned(), true);
        let recent = cache.get_or_prepare(second.clone(), None, code).unwrap();
        assert!(Arc::ptr_eq(
            &recent,
            &cache.get_or_prepare(second, None, code).unwrap()
        ));
        drop(image);
        assert!(
            source.upgrade().is_none(),
            "even a resident entry must not pin package bytes"
        );
        assert!(old_value.upgrade().is_some());
        cache
            .get_or_prepare(Key::Main("third".to_owned(), true), None, code)
            .unwrap();
        assert!(old_value.upgrade().is_none());
        let stats = cache.stats();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.evictions, 1);
        assert!(stats.bytes <= 3000);
    }

    #[test]
    fn shared_identity_requires_a_live_owner() {
        let cache = DylinkCache::new(DylinkCacheConfig {
            max_bytes: 4096,
            ..DylinkCacheConfig::default()
        });
        static DATA: &[u8] = b"same address, separate byte owners";
        let engine = Engine::default().id();
        let image = Image::shared(Arc::new(DATA));
        let (source_key, owner) = SourceKey::of(&image);
        let first = cache
            .get_or_prepare(Key::Side(source_key, engine, true), owner, code)
            .unwrap();
        drop(image);
        let replacement = Image::shared(Arc::new(DATA));
        let (new_key, owner) = SourceKey::of(&replacement);
        assert_eq!(source_key, new_key);
        let second = cache
            .get_or_prepare(Key::Side(new_key, engine, true), owner, code)
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(cache.stats().hits, 0);
        assert_eq!(cache.stats().misses, 2);
    }

    #[test]
    fn idle_expiry_releases_payload_without_another_lookup() {
        let cache = DylinkCache::new(DylinkCacheConfig {
            max_bytes: 4096,
            time_to_idle: Some(Duration::from_millis(30)),
            ..DylinkCacheConfig::default()
        });
        let value = cache
            .get_or_prepare(Key::Main("idle".to_owned(), true), None, code)
            .unwrap();
        let observer = Arc::downgrade(&value);
        drop(value);
        let start = Instant::now();
        while observer.strong_count() != 0 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(observer.upgrade().is_none());
        assert_eq!(cache.stats().bytes, 0);
        assert_eq!(cache.stats().evictions, 1);
    }

    #[cfg(feature = "engine-tests")]
    #[tokio::test]
    async fn persistent_side_module_survives_fresh_caches_and_engines() {
        use crate::artifact::tests::counting_engine;
        use wasmer_cache::module_cache::FileSystemCache;

        let dir = tempfile::tempdir().unwrap();
        let cache = |namespace| {
            DylinkCache::new(DylinkCacheConfig {
                max_bytes: 1024 * 1024,
                ..Default::default()
            })
            .with_module_cache(
                Arc::new(FileSystemCache::new(
                    dir.path(),
                    tokio::runtime::Handle::current(),
                )),
                namespace,
            )
        };
        let wasm = crate::tests::bytes(
            r#"(module
                (import "env" "memory" (memory 1 4 shared))
                (func (export "run") (result i32) i32.const 42))"#,
            [0; 4],
            &[],
            &[],
            &[],
        );
        assert!(crate::is_side_only(&wasm).unwrap());
        let library = Library::new(wasm.clone(), None).unwrap();
        let (engine, count) = counting_engine(None);
        let tls = BTreeMap::new();

        let first = cache("compiler-v1");
        let (key, bytes) = first
            .prepare_side_for_prewarm(&engine, &wasm)
            .unwrap()
            .unwrap();
        first.prepare_code(&engine, &library, &tls).await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
        let stored = first
            .persistent
            .as_ref()
            .unwrap()
            .cache
            .load(key, &engine)
            .await
            .unwrap();
        assert_eq!(stored.info().hash, Some(ModuleHash::new(&bytes)));
        drop((stored, first, engine));

        let (engine, count) = counting_engine(None);
        cache("compiler-v1")
            .prepare_code(&engine, &library, &tls)
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 0);

        let features = engine.as_sys().inner().features().clone();
        let mut other_features = features;
        other_features.multi_value = !other_features.multi_value;
        let (other_engine, other_count) = counting_engine(Some(other_features));
        assert_eq!(engine.deterministic_id(), other_engine.deterministic_id());
        cache("compiler-v1")
            .prepare_code(&other_engine, &library, &tls)
            .await
            .unwrap();
        assert_eq!(other_count.load(Ordering::Relaxed), 1);

        let changed = cache("compiler-v2");
        changed.prepare_code(&engine, &library, &tls).await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "engine-tests")]
    #[tokio::test]
    async fn graph_dependent_tls_variants_cache_separately_and_skip_prewarm() {
        use crate::artifact::tests::counting_engine;

        let dir = tempfile::tempdir().unwrap();
        let cache = DylinkCache::new(Default::default()).with_module_cache(
            Arc::new(wasmer_cache::module_cache::FileSystemCache::new(
                dir.path(),
                tokio::runtime::Handle::current(),
            )),
            "test",
        );
        let wasm = crate::tests::bytes(
            r#"(module
                (import "env" "memory" (memory 1 4 shared))
                (import "GOT.mem" "tls_value" (global (mut i32)))
                (func (export "get") (result i32) global.get 0))"#,
            [0; 4],
            &[],
            &[],
            &[],
        );
        assert!(crate::is_side_only(&wasm).unwrap());
        let (engine, count) = counting_engine(None);
        assert!(
            cache
                .prepare_side_for_prewarm(&engine, &wasm)
                .unwrap()
                .is_none()
        );
        let library = Library::new(wasm, None).unwrap();
        for offset in [4, 8, 4] {
            cache
                .prepare_code(&engine, &library, &[(0, offset)].into())
                .await
                .unwrap();
        }
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn concurrent_preparation_is_single_flight() {
        let cache = DylinkCache::new(DylinkCacheConfig {
            max_bytes: 4096,
            ..DylinkCacheConfig::default()
        });
        let threads = 8;
        let begin = Barrier::new(threads);
        let preparations = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    begin.wait();
                    cache
                        .get_or_prepare(Key::Main("one".to_owned(), true), None, || {
                            preparations.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(Duration::from_millis(10));
                            code()
                        })
                        .unwrap();
                });
            }
        });
        assert_eq!(preparations.load(Ordering::Relaxed), 1);
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, threads as u64 - 1);
    }
}
