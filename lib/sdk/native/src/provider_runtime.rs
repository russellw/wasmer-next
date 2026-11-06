//! Callback custody shared by native SDK provider adapters.
use crate::{
    Error, File, FileOpenOptions, FileSystem, FsError, FsResult, RelativePath, service::Services,
};
use bytes::Bytes;
use std::{
    future::Future,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    active: usize,
    operations: usize,
    closed: bool,
    close_started: bool,
    failure: Option<FsError>,
    files: Vec<Weak<OpenFile>>,
}
struct Scope {
    state: Mutex<State>,
    changed: Notify,
    completed: tokio::sync::watch::Sender<Option<FsResult<()>>>,
}
impl Default for Scope {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            changed: Notify::new(),
            completed: tokio::sync::watch::channel(None).0,
        }
    }
}
pub(crate) struct CallbackLease {
    scope: Arc<Scope>,
    operation: bool,
}
impl Drop for CallbackLease {
    fn drop(&mut self) {
        {
            let mut state = self.scope.state.lock().unwrap();
            state.active -= 1;
            if self.operation {
                state.operations -= 1;
            }
        }
        self.scope.changed.notify_waiters();
    }
}
#[derive(Clone)]
pub(crate) struct ProviderRuntime {
    services: Services,
    scope: Arc<Scope>,
}
impl std::fmt::Debug for ProviderRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRuntime").finish_non_exhaustive()
    }
}
impl ProviderRuntime {
    pub(crate) fn new(services: Services) -> Self {
        Self {
            services,
            scope: Arc::default(),
        }
    }
    pub(crate) fn fork(&self) -> Self {
        Self::new(self.services.clone())
    }
    #[cfg(test)]
    pub(crate) fn current() -> Self {
        Self::new(Services::new().unwrap())
    }
    fn lease(&self) -> FsResult<CallbackLease> {
        let mut state = self.scope.state.lock().unwrap();
        if state.closed {
            return Err(FsError::Io("filesystem provider is closed".into()));
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| FsError::Io("provider operation count exhausted".into()))?;
        state.operations += 1;
        Ok(CallbackLease {
            scope: self.scope.clone(),
            operation: true,
        })
    }
    fn failure(&self, error: FsError) {
        self.scope
            .state
            .lock()
            .unwrap()
            .failure
            .get_or_insert(error);
    }
    fn call_work<T: Send + 'static>(
        &self,
        future: impl Future<Output = FsResult<T>> + Send + 'static,
    ) -> FsResult<impl Future<Output = FsResult<T>> + Send + 'static> {
        let lease = self.lease()?;
        Ok(async move {
            let result = future.await;
            drop(lease);
            result
        })
    }
    pub(crate) async fn call<T: Send + 'static>(
        &self,
        future: impl Future<Output = FsResult<T>> + Send + 'static,
    ) -> FsResult<T> {
        self.services
            .callback(self.call_work(future)?, |output| async move {
                drop(output);
            })
            .await
            .map_err(|error| FsError::Io(error.to_string()))?
    }
    fn open_work(
        &self,
        provider: Arc<dyn FileSystem>,
        path: RelativePath,
        options: FileOpenOptions,
    ) -> FsResult<impl Future<Output = FsResult<Arc<OpenFile>>> + Send + 'static> {
        let lease = self.lease()?;
        let runtime = self.clone();
        Ok(async move {
            let result = match provider.open(&path, options).await {
                Ok(file) => {
                    let opened = (|| {
                        let mut state = runtime.scope.state.lock().unwrap();
                        if state.closed {
                            return Ok(None);
                        }
                        let active = state.active.checked_add(1).ok_or_else(|| {
                            FsError::Io("provider operation count exhausted".into())
                        })?;
                        let service_lease = runtime
                            .services
                            .retain_cleanup()
                            .map_err(|error| FsError::Io(error.to_string()))?;
                        let opened = Arc::new(OpenFile {
                            file: file.clone(),
                            service_lease: Mutex::new(Some(service_lease)),
                            runtime: runtime.clone(),
                            lease: Mutex::new(Some(CallbackLease {
                                scope: runtime.scope.clone(),
                                operation: false,
                            })),
                            closed: AtomicBool::new(false),
                            completed: tokio::sync::watch::channel(None).0,
                        });
                        state.active = active;
                        state.files.retain(|file| file.strong_count() != 0);
                        state.files.push(Arc::downgrade(&opened));
                        Ok(Some(opened))
                    })();
                    match opened {
                        Ok(Some(opened)) => Ok(opened),
                        failed => {
                            if let Err(error) = file.close().await {
                                runtime.failure(error);
                            }
                            match failed {
                                Err(error) => Err(error),
                                _ => Err(FsError::Io("filesystem provider is closed".into())),
                            }
                        }
                    }
                }
                Err(error) => Err(error),
            };
            drop(lease);
            result
        })
    }
    pub(crate) async fn open(
        &self,
        provider: Arc<dyn FileSystem>,
        path: RelativePath,
        options: FileOpenOptions,
    ) -> FsResult<Arc<OpenFile>> {
        self.services
            .callback(
                self.open_work(provider, path, options)?,
                |output| async move {
                    drop(output);
                },
            )
            .await
            .map_err(|error| FsError::Io(error.to_string()))?
    }
    pub(crate) fn blocking<T: Send + 'static>(
        &self,
        future: impl Future<Output = FsResult<T>> + Send + 'static,
    ) -> FsResult<T> {
        if self.services.on_service_thread() {
            return Err(FsError::Io(
                "synchronous filesystem access cannot block SDK services".into(),
            ));
        }
        self.services
            .callback_blocking(self.call_work(future)?, |output| async move {
                drop(output);
            })
            .map_err(|error| FsError::Io(error.to_string()))?
    }
    pub(crate) async fn close(&self) -> FsResult<()> {
        let start = {
            let mut state = self.scope.state.lock().unwrap();
            state.closed = true;
            if state.close_started {
                false
            } else {
                state.close_started = true;
                true
            }
        };
        if start {
            let runtime = self.clone();
            let completed = self.scope.completed.clone();
            if let Err(error) = self.services.cleanup(async move {
                let result = runtime.close_owned().await;
                completed.send_replace(Some(result));
                Ok(())
            }) {
                self.scope
                    .completed
                    .send_replace(Some(Err(FsError::Io(error.to_string()))));
            }
        }
        wait_close(&self.scope.completed).await
    }
    async fn close_owned(&self) -> FsResult<()> {
        // Already admitted mutations finish before their opened files close.
        loop {
            let changed = self.scope.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.scope.state.lock().unwrap().operations == 0 {
                break;
            }
            changed.await;
        }
        let files: Vec<_> = {
            let state = self.scope.state.lock().unwrap();
            state.files.iter().filter_map(Weak::upgrade).collect()
        };
        for file in files {
            if let Err(error) = self
                .services
                .callback(async move { file.close().await }, |_| async {})
                .await
            {
                self.failure(FsError::Io(error.to_string()));
            }
        }
        loop {
            let changed = self.scope.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.scope.state.lock().unwrap();
                if state.active == 0 {
                    return state.failure.clone().map_or(Ok(()), Err);
                }
            }
            changed.await;
        }
    }
}

/// A successful open owns its close even before a caller receives the result.
pub(crate) struct OpenFile {
    pub(crate) file: Arc<dyn File>,
    runtime: ProviderRuntime,
    lease: Mutex<Option<CallbackLease>>,
    service_lease: Mutex<Option<crate::service::Lease>>,
    closed: AtomicBool,
    completed: tokio::sync::watch::Sender<Option<FsResult<()>>>,
}
impl std::fmt::Debug for OpenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFile")
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}
#[async_trait::async_trait]
impl File for OpenFile {
    async fn read_at(&self, offset: u64, length: usize) -> FsResult<Bytes> {
        self.file.read_at(offset, length).await
    }
    async fn write_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
        self.file.write_at(offset, data).await
    }
    async fn write_positioned_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
        self.file.write_positioned_at(offset, data).await
    }
    async fn try_atomic_append(&self, data: Bytes) -> FsResult<Option<(u64, usize)>> {
        self.file.try_atomic_append(data).await
    }
    async fn set_len(&self, length: u64) -> FsResult<()> {
        self.file.set_len(length).await
    }
    async fn flush(&self) -> FsResult<()> {
        self.file.flush().await
    }
    async fn close(&self) -> FsResult<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let lease = self.lease.lock().unwrap().take();
            let service_lease = self.service_lease.lock().unwrap().take();
            let file = self.file.clone();
            let runtime = self.runtime.clone();
            let completed = self.completed.clone();
            if let Err(error) = self.runtime.services.cleanup(async move {
                let result = file.close().await;
                if let Err(error) = &result {
                    runtime.failure(error.clone());
                }
                drop(lease);
                drop(service_lease);
                completed.send_replace(Some(result));
                Ok(())
            }) {
                let error = FsError::Io(error.to_string());
                self.runtime.failure(error.clone());
                self.completed.send_replace(Some(Err(error)));
            }
        }
        wait_close(&self.completed).await
    }
    async fn metadata(&self) -> FsResult<crate::FileMetadata> {
        self.file.metadata().await
    }
    async fn set_times(&self, atime: Option<u64>, mtime: Option<u64>) -> FsResult<()> {
        self.file.set_times(atime, mtime).await
    }
}
impl Drop for OpenFile {
    fn drop(&mut self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let file = self.file.clone();
        let runtime = self.runtime.clone();
        let lease = self.lease.get_mut().unwrap().take();
        let service_lease = self.service_lease.get_mut().unwrap().take();
        let _ = self.runtime.services.cleanup(async move {
            let result = file.close().await;
            if let Err(error) = &result {
                runtime.failure(error.clone());
            }
            drop(lease);
            drop(service_lease);
            result.map_err(Error::from)
        });
    }
}

async fn wait_close(completed: &tokio::sync::watch::Sender<Option<FsResult<()>>>) -> FsResult<()> {
    let mut receiver = completed.subscribe();
    loop {
        {
            let value = receiver.borrow_and_update().clone();
            if let Some(result) = value {
                return result;
            }
        }
        receiver
            .changed()
            .await
            .map_err(|_| FsError::Io("provider close owner stopped".into()))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Directory, DirectoryEntry, FileMetadata, FileSystemCapabilities, SandboxFileSystem,
    };
    use std::{sync::atomic::AtomicUsize, time::Duration};
    use tokio::sync::Semaphore;

    #[derive(Debug)]
    struct GatedProvider {
        directory: Directory,
        entered: Semaphore,
        release: Semaphore,
        closed: Arc<AtomicUsize>,
        readonly: bool,
        close_failure: bool,
    }
    #[derive(Debug)]
    struct GatedFile {
        file: Arc<dyn File>,
        closed: Arc<AtomicUsize>,
        close_failure: bool,
    }
    #[async_trait::async_trait]
    impl File for GatedFile {
        async fn read_at(&self, offset: u64, length: usize) -> FsResult<Bytes> {
            self.file.read_at(offset, length).await
        }
        async fn write_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
            self.file.write_at(offset, data).await
        }
        async fn write_positioned_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
            self.file.write_positioned_at(offset, data).await
        }
        async fn set_len(&self, length: u64) -> FsResult<()> {
            self.file.set_len(length).await
        }
        async fn flush(&self) -> FsResult<()> {
            self.file.flush().await
        }
        async fn close(&self) -> FsResult<()> {
            self.closed.fetch_add(1, Ordering::SeqCst);
            self.file.close().await?;
            if self.close_failure {
                Err(FsError::Io("late open close failure".into()))
            } else {
                Ok(())
            }
        }
        async fn metadata(&self) -> FsResult<FileMetadata> {
            self.file.metadata().await
        }
    }
    #[async_trait::async_trait]
    impl FileSystem for GatedProvider {
        fn capabilities(&self) -> FileSystemCapabilities {
            if self.readonly {
                FileSystemCapabilities::READ_ONLY
            } else {
                FileSystemCapabilities::READ_WRITE
            }
        }
        async fn stat(&self, path: &RelativePath) -> FsResult<FileMetadata> {
            self.directory.stat(path).await
        }
        async fn read_dir(&self, path: &RelativePath) -> FsResult<Vec<DirectoryEntry>> {
            self.directory.read_dir(path).await
        }
        async fn open(
            &self,
            path: &RelativePath,
            options: FileOpenOptions,
        ) -> FsResult<Arc<dyn File>> {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            Ok(Arc::new(GatedFile {
                file: self.directory.open(path, options).await?,
                closed: self.closed.clone(),
                close_failure: self.close_failure,
            }))
        }
        async fn create_dir(&self, path: &RelativePath) -> FsResult<()> {
            self.directory.create_dir(path).await
        }
        async fn remove(&self, path: &RelativePath, recursive: bool) -> FsResult<()> {
            self.directory.remove(path, recursive).await
        }
        async fn rename(&self, from: &RelativePath, to: &RelativePath) -> FsResult<()> {
            self.directory.rename(from, to).await
        }
        async fn flush(&self) -> FsResult<()> {
            self.directory.flush().await
        }
    }
    async fn provider(readonly: bool, close_failure: bool) -> Arc<GatedProvider> {
        let directory = Directory::new();
        directory.write_text("file", "original").await.unwrap();
        Arc::new(GatedProvider {
            directory,
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            closed: Arc::new(AtomicUsize::new(0)),
            readonly,
            close_failure,
        })
    }
    #[tokio::test]
    async fn late_open_and_close_failure_remain_owned_after_both_waiters_cancel() {
        let services = Services::new().unwrap();
        let runtime = ProviderRuntime::new(services.clone());
        let provider = provider(false, true).await;
        let opening = runtime.clone();
        let source = provider.clone();
        let waiter = tokio::spawn(async move {
            opening
                .open(
                    source,
                    RelativePath::new("file").unwrap(),
                    FileOpenOptions {
                        read: true,
                        ..Default::default()
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), provider.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        waiter.abort();
        let _ = waiter.await;
        let mut closing = Box::pin(runtime.close());
        assert!(futures::poll!(&mut closing).is_pending());
        drop(closing);
        provider.release.add_permits(1);
        let result = tokio::time::timeout(Duration::from_secs(2), runtime.close())
            .await
            .unwrap();
        assert_eq!(result, Err(FsError::Io("late open close failure".into())));
        assert_eq!(provider.closed.load(Ordering::SeqCst), 1);
        services.close().await.unwrap();
    }
    #[tokio::test]
    async fn workspace_sync_subscriber_preserves_readonly_metadata_and_open_close_custody() {
        let services = Services::new().unwrap();
        let runtime = ProviderRuntime::new(services.clone());
        let provider = provider(true, false).await;
        provider.release.add_permits(1);
        let filesystem = SandboxFileSystem::new(provider.clone(), runtime.clone());
        assert!(filesystem.stat("file").unwrap().readonly);
        assert!(filesystem.read_dir(".").unwrap()[0].metadata.readonly);
        assert!(filesystem.create_dir("denied").is_err());
        assert!(filesystem.write_text("file", "wrong").await.is_err());
        assert_eq!(filesystem.read_text("file").await.unwrap(), "original");
        assert_eq!(provider.closed.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider.directory.read_text("file").await.unwrap(),
            "original"
        );
        runtime.close().await.unwrap();
        assert!(filesystem.stat("file").is_err());
        services.close().await.unwrap();
    }
}
