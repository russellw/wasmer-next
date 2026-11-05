use crate::runtime::{
    module_cache::{CacheError, ModuleCache, ModuleHash},
    task_manager::tokio::TokioTaskManager,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use wasmer::{Engine, Module};

/// The legacy constructor for the shared compiled-module filesystem cache.
#[derive(Debug, Clone)]
pub struct FileSystemCache {
    inner: wasmer_cache::module_cache::FileSystemCache,
    // A Handle alone does not keep a Runtime owned by the task manager alive.
    _task_manager: Arc<TokioTaskManager>,
}

impl FileSystemCache {
    pub fn new(cache_dir: impl Into<PathBuf>, task_manager: Arc<TokioTaskManager>) -> Self {
        Self {
            inner: wasmer_cache::module_cache::FileSystemCache::new(
                cache_dir,
                task_manager.runtime_handle(),
            ),
            _task_manager: task_manager,
        }
    }
    pub fn cache_dir(&self) -> &Path {
        self.inner.cache_dir()
    }
}

#[async_trait::async_trait]
impl ModuleCache for FileSystemCache {
    async fn load(&self, key: ModuleHash, engine: &Engine) -> Result<Module, CacheError> {
        self.inner.load(key, engine).await
    }
    async fn contains(&self, key: ModuleHash, engine: &Engine) -> Result<bool, CacheError> {
        self.inner.contains(key, engine).await
    }
    async fn save(
        &self,
        key: ModuleHash,
        engine: &Engine,
        module: &Module,
    ) -> Result<(), CacheError> {
        self.inner.save(key, engine, module).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_clone_keeps_owned_runtime_alive_until_final_drop() {
        let temp = tempfile::TempDir::new().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let task_manager = Arc::new(TokioTaskManager::new(runtime));
        let manager_lifetime = Arc::downgrade(&task_manager);
        let cache = FileSystemCache::new(temp.path(), task_manager.clone());
        let cache_clone = cache.clone();
        drop(task_manager);
        drop(cache);

        // Poll outside Tokio after dropping every original owner. A bare Handle
        // would leave the filesystem task canceled when its Runtime was dropped.
        let present = futures::executor::block_on(
            cache_clone.contains(ModuleHash::from_bytes([0; 32]), &Engine::default()),
        )
        .unwrap();
        assert!(!present);
        assert!(manager_lifetime.upgrade().is_some());

        drop(cache_clone);
        assert!(manager_lifetime.upgrade().is_none());
    }
}
