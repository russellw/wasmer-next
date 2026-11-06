//! Mounted user callbacks stay off the SDK LocalSet and retain cleanup custody.
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use wasmer_sdk::{
    CacheConfig, Directory, DirectoryEntry, File, FileMetadata, FileOpenOptions, FileSystem,
    FileSystemCapabilities, FsError, FsResult, MountMode, PackageSource, RelativePath, Result,
    SandboxFileSystem, Wasmer, WasmerConfig,
};

const MOUNT_COPY_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_prestat_get"
    (func $fd_prestat_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_dir_name"
    (func $fd_prestat_dir_name (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 200) "external/input.txt")
  (data (i32.const 240) "external/output.txt")
  (func (export "_start")
    (local $fd i32)
    (local $dirfd i32)
    (local $input i32)
    (local $output i32)
    (local $count i32)
    (local.set $fd (i32.const 3))
    (local.set $dirfd (i32.const -1))
    (block $found
      (loop $search
        (if
          (i32.eqz
            (call $fd_prestat_get (local.get $fd) (i32.const 0)))
          (then
            (drop
              (call $fd_prestat_dir_name
                (local.get $fd)
                (i32.const 100)
                (i32.load (i32.const 4))))
            (if
              (i32.and
                (i32.eq (i32.load (i32.const 4)) (i32.const 1))
                (i32.eq
                  (i32.load8_u (i32.const 100))
                  (i32.const 47)))
              (then
                (local.set $dirfd (local.get $fd))
                (br $found)))))
        (local.set $fd (i32.add (local.get $fd) (i32.const 1)))
        (br_if $search (i32.lt_u (local.get $fd) (i32.const 32)))))
    (if (i32.eq (local.get $dirfd) (i32.const -1))
      (then (call $proc_exit (i32.const 91))))
    (if
      (call $path_open
        (local.get $dirfd)
        (i32.const 0)
        (i32.const 200)
        (i32.const 18)
        (i32.const 0)
        (i64.const 2)
        (i64.const 0)
        (i32.const 0)
        (i32.const 16))
      (then (call $proc_exit (i32.const 92))))
    (local.set $input (i32.load (i32.const 16)))
    (i32.store (i32.const 20) (i32.const 400))
    (i32.store (i32.const 24) (i32.const 4096))
    (if
      (call $fd_read
        (local.get $input)
        (i32.const 20)
        (i32.const 1)
        (i32.const 8))
      (then (call $proc_exit (i32.const 93))))
    (local.set $count (i32.load (i32.const 8)))
    (drop (call $fd_close (local.get $input)))
    (if
      (call $path_open
        (local.get $dirfd)
        (i32.const 0)
        (i32.const 240)
        (i32.const 19)
        (i32.const 9)
        (i64.const 64)
        (i64.const 0)
        (i32.const 0)
        (i32.const 16))
      (then (call $proc_exit (i32.const 94))))
    (local.set $output (i32.load (i32.const 16)))
    (i32.store (i32.const 24) (local.get $count))
    (if
      (call $fd_write
        (local.get $output)
        (i32.const 20)
        (i32.const 1)
        (i32.const 12))
      (then (call $proc_exit (i32.const 95))))
    (drop (call $fd_close (local.get $output)))))
"#;

#[derive(Debug)]
struct Provider {
    directory: Directory,
    peer: SandboxFileSystem,
    _peer_owner: wasmer_sdk::Sandbox,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
    closed: Arc<AtomicUsize>,
}
#[derive(Debug)]
struct ProviderFile {
    file: Arc<dyn File>,
    peer: SandboxFileSystem,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
    closed: Arc<AtomicUsize>,
}
#[async_trait]
impl FileSystem for Provider {
    fn capabilities(&self) -> FileSystemCapabilities {
        self.directory.capabilities()
    }
    async fn stat(&self, path: &RelativePath) -> FsResult<FileMetadata> {
        self.directory.stat(path).await
    }
    async fn read_dir(&self, path: &RelativePath) -> FsResult<Vec<DirectoryEntry>> {
        self.directory.read_dir(path).await
    }
    async fn open(&self, path: &RelativePath, options: FileOpenOptions) -> FsResult<Arc<dyn File>> {
        Ok(Arc::new(ProviderFile {
            file: self.directory.open(path, options).await?,
            peer: self.peer.clone(),
            entered: self.entered.clone(),
            release: self.release.clone(),
            closed: self.closed.clone(),
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
#[async_trait]
impl File for ProviderFile {
    async fn read_at(&self, offset: u64, length: usize) -> FsResult<Bytes> {
        // This workspace is itself backed by the public async provider bridge.
        // Polling this user callback on the LocalSet would reject or deadlock.
        self.peer
            .stat("peer.txt")
            .map_err(|error| FsError::Io(error.to_string()))?;
        let entries = self
            .peer
            .read_dir("/")
            .map_err(|error| FsError::Io(error.to_string()))?;
        assert!(entries.iter().any(|entry| entry.name == "peer.txt"));
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(|error| FsError::Io(error.to_string()))?
            .forget();
        self.file.read_at(offset, length).await
    }
    async fn write_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
        self.file.write_at(offset, data).await
    }
    async fn set_len(&self, length: u64) -> FsResult<()> {
        self.file.set_len(length).await
    }
    async fn flush(&self) -> FsResult<()> {
        self.file.flush().await
    }
    async fn metadata(&self) -> FsResult<FileMetadata> {
        self.file.metadata().await
    }
    async fn close(&self) -> FsResult<()> {
        let result = self.file.close().await;
        self.closed.fetch_add(1, Ordering::SeqCst);
        result
    }
}
async fn setup(
    permits: usize,
) -> Result<(
    tempfile::TempDir,
    Wasmer,
    wasmer_sdk::Sandbox,
    Arc<Provider>,
)> {
    let state = tempfile::TempDir::new()?;
    let client = Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().join("cache"),
        },
        output_bytes: 1024,
    })?;
    let peer = client
        .sandboxes()
        .create()
        .storage(Directory::new())
        .await?;
    peer.fs().write_text("peer.txt", "peer").await?;
    let directory = Directory::new();
    directory.write_text("input.txt", "callback bytes").await?;
    let provider = Arc::new(Provider {
        directory,
        peer: peer.fs().clone(),
        _peer_owner: peer,
        entered: Arc::new(Semaphore::new(0)),
        release: Arc::new(Semaphore::new(permits)),
        closed: Arc::new(AtomicUsize::new(0)),
    });
    let external: Arc<dyn FileSystem> = provider.clone();
    let sandbox = client
        .sandboxes()
        .create()
        .package(PackageSource::bytes(
            wat::parse_str(MOUNT_COPY_WAT).unwrap(),
        ))
        .mount("/external", external, MountMode::ReadWrite)
        .await?;
    Ok((state, client, sandbox, provider))
}
#[tokio::test(flavor = "multi_thread")]
async fn mounted_callback_can_sync_stat_and_list_an_independent_provider_workspace() -> Result<()> {
    let (_state, client, sandbox, provider) = setup(1).await?;
    tokio::time::timeout(Duration::from_secs(20), sandbox.command("main").run())
        .await
        .unwrap()?;
    assert_eq!(
        provider.directory.read_text("output.txt").await?,
        "callback bytes"
    );
    client.shutdown().await?;
    assert!(provider.closed.load(Ordering::SeqCst) > 0);
    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn canceled_close_keeps_pending_callback_and_file_cleanup_owned() -> Result<()> {
    let (_state, client, sandbox, provider) = setup(0).await?;
    let mut process = sandbox.command("main").spawn().await?;
    tokio::time::timeout(Duration::from_secs(20), provider.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    process.kill()?;
    let closer = sandbox.clone();
    let closing = tokio::spawn(async move { closer.close().await });
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if matches!(
                sandbox
                    .install_package(PackageSource::bytes(Bytes::new()))
                    .await,
                Err(wasmer_sdk::Error::SandboxClosed)
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    closing.abort();
    let _ = closing.await;
    assert_eq!(provider.closed.load(Ordering::SeqCst), 0);
    provider.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(20), async {
        while provider.closed.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("close cleanup must finish without another close subscriber");
    client.shutdown().await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn client_shutdown_waits_for_the_actual_mounted_callback() -> Result<()> {
    let (_state, client, sandbox, provider) = setup(0).await?;
    let mut process = sandbox.command("main").spawn().await?;
    tokio::time::timeout(Duration::from_secs(20), provider.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    process.kill()?;
    let shutdown_client = client.clone();
    let mut shutdown = tokio::spawn(async move { shutdown_client.shutdown().await });
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if matches!(
                client
                    .packages()
                    .create(wasmer_sdk::PackageDefinition::default())
                    .await,
                Err(wasmer_sdk::Error::ClientClosed)
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut shutdown)
            .await
            .is_err()
    );
    assert_eq!(provider.closed.load(Ordering::SeqCst), 0);
    provider.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(20), shutdown)
        .await
        .unwrap()
        .unwrap()?;
    assert!(provider.closed.load(Ordering::SeqCst) > 0);
    Ok(())
}
