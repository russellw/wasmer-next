use std::{fmt::Debug, ops::Deref, path::PathBuf};

use wasmer::{Engine, Module};
use wasmer_types::ModuleHash;

use crate::module_cache::{FallbackCache, progress::ModuleLoadProgressReporter};

/// A cache for compiled WebAssembly modules.
///
/// ## Deterministic ID
///
/// Implementations are encouraged to take the [`Engine::deterministic_id()`]
/// into account when saving and loading cached a [`Module`].
///
/// ## Assumptions
///
/// Implementations can assume that cache keys are unique and that using the
/// same key to load or save will always result in the "same" module.
///
/// Implementations can also assume that [`ModuleCache::load()`] will
/// be called more often than [`ModuleCache::save()`] and optimise
/// their caching strategy accordingly.
///
#[async_trait::async_trait]
pub trait ModuleCache: Debug {
    /// Load a module based on its hash.
    async fn load(&self, key: ModuleHash, engine: &Engine) -> Result<Module, CacheError>;

    /// Load a module based on its hash, with progress reporting.
    ///
    /// The provided progress reporter will receive updates about the loading process, if supported.
    async fn load_with_progress(
        &self,
        key: ModuleHash,
        engine: &Engine,
        on_progress: ModuleLoadProgressReporter,
    ) -> Result<Module, CacheError> {
        // Default implementation just ignores progress reporting.
        let _ = on_progress;
        self.load(key, engine).await
    }

    /// Check if a module is present in the cache.
    async fn contains(&self, key: ModuleHash, engine: &Engine) -> Result<bool, CacheError>;

    /// Save a module so it can be retrieved with [`ModuleCache::load()`] at a
    /// later time.
    ///
    /// # Panics
    ///
    /// Implementations are free to assume the [`Module`] being passed in was
    /// compiled using the provided [`Engine`], and may panic if this isn't the
    /// case.
    async fn save(
        &self,
        key: ModuleHash,
        engine: &Engine,
        module: &Module,
    ) -> Result<(), CacheError>;

    /// Chain a second [`ModuleCache`] that will be used as a fallback if
    /// lookups on the primary cache fail.
    ///
    /// The general assumption is that each subsequent cache in the chain will
    /// be significantly slower than the previous one.
    ///
    /// ```rust
    /// # #[cfg(feature = "module-cache-filesystem")]
    /// # {
    /// use wasmer_cache::module_cache::{
    ///     ModuleCache, ThreadLocalCache, FileSystemCache, SharedCache,
    /// };
    ///
    /// let runtime = tokio::runtime::Runtime::new().unwrap();
    /// let handle = runtime.handle().clone();
    ///
    /// let cache = SharedCache::default()
    ///     .with_fallback(FileSystemCache::new("~/.local/cache", handle));
    /// # }
    /// ```
    fn with_fallback<C>(self, other: C) -> FallbackCache<Self, C>
    where
        Self: Sized,
        C: ModuleCache,
    {
        FallbackCache::new(self, other)
    }
}

#[async_trait::async_trait]
impl<D, C> ModuleCache for D
where
    D: Deref<Target = C> + Debug + Send + Sync,
    C: ModuleCache + Send + Sync + ?Sized,
{
    async fn load(&self, key: ModuleHash, engine: &Engine) -> Result<Module, CacheError> {
        (**self).load(key, engine).await
    }

    async fn contains(&self, key: ModuleHash, engine: &Engine) -> Result<bool, CacheError> {
        (**self).contains(key, engine).await
    }

    async fn save(
        &self,
        key: ModuleHash,
        engine: &Engine,
        module: &Module,
    ) -> Result<(), CacheError> {
        (**self).save(key, engine, module).await
    }
}

/// Possible errors that may occur during [`ModuleCache`] operations.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// The module could not be serialized.
    #[error("Unable to serialize the module")]
    Serialize(#[from] wasmer::SerializeError),
    /// The module artifact could not be deserialized.
    #[error("Unable to deserialize the module")]
    Deserialize(#[from] wasmer::DeserializeError),
    /// The cache file could not be read.
    #[error("Unable to read from \"{}\"", path.display())]
    FileRead {
        /// Cache artifact path.
        path: PathBuf,
        /// Original filesystem failure.
        #[source]
        error: std::io::Error,
    },
    /// The cache file could not be written.
    #[error("Unable to write to \"{}\"", path.display())]
    FileWrite {
        /// Cache artifact path.
        path: PathBuf,
        /// Original filesystem failure.
        #[source]
        error: std::io::Error,
    },
    /// The item was not found.
    #[error("Not found")]
    NotFound,
    /// A catch-all variant for any other errors that may occur.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl CacheError {
    /// Preserve a custom cache failure.
    pub fn other(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        CacheError::Other(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_object_safe() {
        let _: Option<Box<dyn ModuleCache>> = None;
    }

    #[test]
    fn key_is_displayed_as_hex() {
        let key = ModuleHash::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ]);

        let repr = key.to_string();

        assert_eq!(
            repr,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        );
    }

    #[test]
    fn module_hash_is_just_sha_256() {
        let wasm = b"\0asm...";
        let raw = [
            90, 57, 254, 239, 82, 229, 59, 143, 254, 223, 215, 5, 21, 86, 236, 16, 94, 216, 105,
            130, 241, 34, 160, 93, 39, 40, 217, 103, 120, 228, 235, 150,
        ];

        let hash = ModuleHash::new(wasm);

        assert_eq!(hash.as_bytes(), raw);
    }
}
