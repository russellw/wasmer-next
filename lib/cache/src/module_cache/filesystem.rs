use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use wasmer::{Engine, Module};

use crate::module_cache::{CacheError, ModuleCache, ModuleHash};
use tokio::runtime::Handle;

/// A cache that saves modules to a folder on the host filesystem using
/// [`Module::serialize()`].
#[derive(Debug, Clone)]
pub struct FileSystemCache {
    cache_dir: PathBuf,
    handle: Handle,
}

impl FileSystemCache {
    /// Use the supplied Tokio runtime for filesystem and serialization work.
    /// The caller must keep that runtime alive while using this cache.
    pub fn new(cache_dir: impl Into<PathBuf>, handle: Handle) -> Self {
        FileSystemCache {
            cache_dir: cache_dir.into(),
            handle,
        }
    }

    /// Directory containing the versioned compiled-artifact caches.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    fn path(&self, key: ModuleHash, deterministic_id: &str, artifact_format: &str) -> PathBuf {
        let artifact_version = wasmer_types::MetadataHeader::CURRENT_VERSION;
        self.cache_dir
            .join(format!(
                "{deterministic_id}-{artifact_format}-v{artifact_version}"
            ))
            .join(key.to_string())
            .with_extension("bin")
    }
}

/// Loads a module from the filesystem cache.
///
/// A tokio reactor must be available
#[tracing::instrument(target = "wasmer_wasix::runtime::module_cache::filesystem", level = "debug", skip_all, fields(? path))]
async fn tokio_load(path: PathBuf, engine: Engine) -> Result<Module, CacheError> {
    let artifact_path = path.clone();
    let deserialized =
        tokio::task::spawn_blocking(move || deserialize_file(&artifact_path, &engine))
            .await
            .unwrap();
    match deserialized {
        Ok(m) => {
            tracing::event!(target: "wasmer_wasix::runtime::module_cache::filesystem", tracing::Level::DEBUG, "Cache hit!");
            Ok(m)
        }
        Err(e) => {
            tracing::event!(target: "wasmer_wasix::runtime::module_cache::filesystem", tracing::Level::DEBUG,
                path=%path.display(),
                error=&e as &dyn std::error::Error,
                "Deleting the cache file because the artifact couldn't be deserialized",
            );

            if let Err(e) = std::fs::remove_file(&path) {
                tracing::event!(target: "wasmer_wasix::runtime::module_cache::filesystem", tracing::Level::WARN,
                    path=%path.display(),
                    error=&e as &dyn std::error::Error,
                    "Unable to remove the corrupted cache file",
                );
            }
            Err(e)
        }
    }
}

/// Checks if the path exists in the filesystem cache.
///
/// A tokio reactor must be available
async fn tokio_contains(path: PathBuf) -> Result<bool, CacheError> {
    tokio::fs::try_exists(&path)
        .await
        .map_err(|e| CacheError::FileRead {
            path: path.clone(),
            error: e,
        })
}

/// Saves the module to the filesystem cache.
///
/// A tokio reactor must be available
#[tracing::instrument(target = "wasmer_wasix::runtime::module_cache::filesystem", level = "debug", skip_all, fields(? path))]
async fn tokio_save(path: PathBuf, module: Module) -> Result<(), CacheError> {
    let parent = path
        .parent()
        .expect("Unreachable - always created by joining onto cache_dir");

    if let Err(e) = tokio::fs::create_dir_all(parent).await {
        tracing::event!(target: "wasmer_wasix::runtime::module_cache::filesystem", tracing::Level::WARN,
            dir=%parent.display(),
            error=&e as &dyn std::error::Error,
            "Unable to create the cache directory",
        );
    }

    // TODO: NamedTempFile is blocking and we should use the appropriate tokio function instead.
    // Note: We save to a temporary file and persist() it at the end so
    // concurrent readers won't see a partially written module.
    let (file, temp) = NamedTempFile::new_in(parent)
        .map_err(CacheError::other)?
        .into_parts();

    let mut file = tokio::fs::File::from_std(file);

    let serialized = tokio::task::spawn_blocking(move || module.serialize())
        .await
        .unwrap()?;

    let mut writer = tokio::io::BufWriter::new(&mut file);
    if let Err(error) = writer.write_all(&serialized).await {
        return Err(CacheError::FileWrite { path, error });
    }
    if let Err(error) = writer.flush().await {
        return Err(CacheError::FileWrite { path, error });
    }

    temp.persist(&path).map_err(CacheError::other)?;
    tracing::event!(target: "wasmer_wasix::runtime::module_cache::filesystem", tracing::Level::DEBUG, path=%path.display(), "Saved to disk");

    Ok(())
}

#[async_trait::async_trait]
impl ModuleCache for FileSystemCache {
    #[tracing::instrument(target = "wasmer_wasix::runtime::module_cache::filesystem", level = "debug", skip_all, fields(% key))]
    async fn load(&self, key: ModuleHash, engine: &Engine) -> Result<Module, CacheError> {
        let path = self.path(key, &engine.deterministic_id(), &engine.artifact_format());
        let engine = engine.clone();

        // Use the bundled tokio runtime instead of the given async runtime
        // This is necessary because this function can also be called with a futures_executor
        self.handle.spawn(tokio_load(path, engine)).await.unwrap()
    }

    async fn contains(&self, key: ModuleHash, engine: &Engine) -> Result<bool, CacheError> {
        let path = self.path(key, &engine.deterministic_id(), &engine.artifact_format());

        // Use the bundled tokio runtime instead of the given async runtime
        // This is necessary because this function can also be called with a futures_executor
        self.handle.spawn(tokio_contains(path)).await.unwrap()
    }

    #[tracing::instrument(target = "wasmer_wasix::runtime::module_cache::filesystem", level = "debug", skip_all, fields(% key))]
    async fn save(
        &self,
        key: ModuleHash,
        engine: &Engine,
        module: &Module,
    ) -> Result<(), CacheError> {
        let path = self.path(key, &engine.deterministic_id(), &engine.artifact_format());
        let module = module.clone();

        // Use the bundled tokio runtime instead of the given async runtime
        // This is necessary because this function can also be called with a futures_executor
        self.handle.spawn(tokio_save(path, module)).await.unwrap()
    }
}

fn deserialize_file(path: &Path, engine: &Engine) -> Result<Module, CacheError> {
    // We used to compress our compiled modules using LZW encoding in the past.
    // This was removed because it has a negative impact on startup times for
    // "wasmer run", so all new compiled modules should be saved directly to
    // disk.
    //
    // For perspective, compiling php.wasm with cranelift took about 4.75
    // seconds on a M1 Mac.
    //
    // Without LZW compression:
    // - ModuleCache::save(): 408ms, 142MB binary
    // - ModuleCache::load(): 155ms
    // With LZW compression:
    // - ModuleCache::save(): 2.4s, 72MB binary
    // - ModuleCache::load(): 822ms

    match unsafe { Module::deserialize_from_file(engine, path) } {
        // The happy case. ELF artifacts are memory mapped directly from the cache file.
        Ok(m) => Ok(m),
        Err(wasmer::DeserializeError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Err(CacheError::NotFound)
        }
        Err(wasmer::DeserializeError::Io(error)) => Err(CacheError::FileRead {
            path: path.to_path_buf(),
            error,
        }),
        Err(e) => Err(CacheError::Deserialize(e)),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use tokio::runtime::Handle;

    use super::*;

    const ADD_WAT: &[u8] = br#"(
        module
            (func
                (export "add")
                (param $x i64)
                (param $y i64)
                (result i64)
                (i64.add (local.get $x) (local.get $y)))
        )"#;

    fn current_handle() -> Handle {
        Handle::current()
    }

    #[tokio::test]
    async fn save_to_disk() {
        let temp = TempDir::new().unwrap();
        let engine = Engine::default();
        let module = Module::new(&engine, ADD_WAT).unwrap();
        let cache = FileSystemCache::new(temp.path(), current_handle());
        let key = ModuleHash::from_bytes([0; _]);
        let expected_path = cache.path(key, &engine.deterministic_id(), &engine.artifact_format());

        cache.save(key, &engine, &module).await.unwrap();

        assert!(expected_path.exists());
    }

    #[tokio::test]
    async fn create_cache_dir_automatically() {
        let temp = TempDir::new().unwrap();
        let engine = Engine::default();
        let module = Module::new(&engine, ADD_WAT).unwrap();
        let cache_dir = temp.path().join("this").join("doesn't").join("exist");
        assert!(!cache_dir.exists());
        let cache = FileSystemCache::new(&cache_dir, current_handle());
        let key = ModuleHash::from_bytes([0; _]);

        cache.save(key, &engine, &module).await.unwrap();

        assert!(cache_dir.is_dir());
    }

    #[tokio::test]
    async fn missing_file() {
        let temp = TempDir::new().unwrap();
        let engine = Engine::default();
        let key = ModuleHash::from_bytes([0; _]);
        let cache = FileSystemCache::new(temp.path(), current_handle());

        let err = cache.load(key, &engine).await.unwrap_err();

        assert!(matches!(err, CacheError::NotFound));
    }

    #[tokio::test]
    async fn load_from_disk() {
        let temp = TempDir::new().unwrap();
        let engine = Engine::default();
        let module = Module::new(&engine, ADD_WAT).unwrap();
        let key = ModuleHash::from_bytes([0; _]);
        let cache = FileSystemCache::new(temp.path(), current_handle());
        let expected_path = cache.path(key, &engine.deterministic_id(), &engine.artifact_format());
        std::fs::create_dir_all(expected_path.parent().unwrap()).unwrap();
        let serialized = module.serialize().unwrap();
        std::fs::write(&expected_path, &serialized).unwrap();

        let module = cache.load(key, &engine).await.unwrap();

        let exports: Vec<_> = module
            .exports()
            .map(|export| export.name().to_string())
            .collect();
        assert_eq!(exports, ["add"]);
    }
}
