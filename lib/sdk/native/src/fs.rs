use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;

use crate::{
    DirectoryEntry, Error, File, FileMetadata, FileOpenOptions, FileSystem, FsError, FsResult,
    RelativePath, Result, provider_runtime::ProviderRuntime,
};

/// Filesystem access to a sandbox's persistent `/workspace`.
#[derive(Clone, Debug)]
pub struct SandboxFileSystem {
    provider: Arc<dyn FileSystem>,
    runtime: ProviderRuntime,
}
impl SandboxFileSystem {
    pub(crate) fn new(provider: Arc<dyn FileSystem>, runtime: ProviderRuntime) -> Self {
        Self { provider, runtime }
    }
    /// Write bytes, creating parent directories as needed.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub async fn write(&self, path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Result<()> {
        let (guest, path) = workspace_path(path.as_ref())?;
        let provider = self.provider.clone();
        let parent = path
            .as_path()
            .parent()
            .map(RelativePath::new)
            .transpose()
            .map_err(|error| filesystem_error("create_dir_all", &guest, error))?;
        self.runtime
            .call(async move {
                writable(provider.as_ref())?;
                if let Some(parent) = parent {
                    create_parents(provider.as_ref(), &parent).await?;
                }
                Ok(())
            })
            .await
            .map_err(|error| filesystem_error("create_dir_all", &guest, error))?;
        let file = self
            .runtime
            .open(
                self.provider.clone(),
                path,
                FileOpenOptions {
                    write: true,
                    create: true,
                    truncate: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| filesystem_error("open", &guest, error))?;
        let target = file.clone();
        let data = Bytes::copy_from_slice(bytes.as_ref());
        let result = self
            .runtime
            .call(async move {
                let mut written = 0usize;
                while written < data.len() {
                    let count = target
                        .write_positioned_at(written as u64, data.slice(written..))
                        .await?;
                    if count == 0 || count > data.len() - written {
                        return Err(FsError::Io(
                            "provider returned an invalid write count".into(),
                        ));
                    }
                    written += count;
                }
                target.flush().await
            })
            .await;
        let closed = file.close().await;
        result
            .and(closed)
            .map_err(|error| filesystem_error("write", &guest, error))
    }
    /// Write UTF-8 text.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub async fn write_text(&self, path: impl AsRef<Path>, text: impl AsRef<str>) -> Result<()> {
        self.write(path, text.as_ref().as_bytes()).await
    }
    /// Read a file in full.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub async fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let (guest, path) = workspace_path(path.as_ref())?;
        readable(self.provider.as_ref())
            .map_err(|error| filesystem_error("open", &guest, error))?;
        let file = self
            .runtime
            .open(
                self.provider.clone(),
                path,
                FileOpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| filesystem_error("open", &guest, error))?;
        let source = file.clone();
        let result = self
            .runtime
            .call(async move {
                let mut bytes = Vec::new();
                loop {
                    let chunk = source.read_at(bytes.len() as u64, 64 * 1024).await?;
                    if chunk.len() > 64 * 1024 {
                        return Err(FsError::Io(
                            "provider returned an invalid read count".into(),
                        ));
                    }
                    if chunk.is_empty() {
                        return Ok(bytes);
                    }
                    bytes.extend_from_slice(&chunk);
                }
            })
            .await;
        let closed = file.close().await;
        match result {
            Ok(bytes) => closed.map(|()| bytes),
            Err(error) => Err(error),
        }
        .map_err(|error| filesystem_error("read", &guest, error))
    }
    /// Read and decode a UTF-8 text file.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub async fn read_text(&self, path: impl AsRef<Path>) -> Result<String> {
        Ok(String::from_utf8(self.read(path).await?)?)
    }
    /// Create a directory and any missing parents.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> Result<()> {
        let (guest, path) = workspace_path(path.as_ref())?;
        let provider = self.provider.clone();
        self.runtime
            .blocking(async move {
                writable(provider.as_ref())?;
                create_parents(provider.as_ref(), &path).await
            })
            .map_err(|error| filesystem_error("create_dir_all", &guest, error))
    }
    /// Create one directory. The parent must already exist.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        let (guest, path) = workspace_path(path.as_ref())?;
        let provider = self.provider.clone();
        self.runtime
            .blocking(async move {
                writable(provider.as_ref())?;
                provider.create_dir(&path).await
            })
            .map_err(|error| filesystem_error("create_dir", &guest, error))
    }
    /// List the immediate children of a directory.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<Vec<DirectoryEntry>> {
        let (guest, path) = workspace_path(path.as_ref())?;
        let provider = self.provider.clone();
        self.runtime
            .blocking(async move {
                readable(provider.as_ref())?;
                let mut entries = provider.read_dir(&path).await?;
                for entry in &mut entries {
                    entry.metadata.readonly |= !provider.capabilities().write;
                }
                Ok(entries)
            })
            .map_err(|error| filesystem_error("read_dir", &guest, error))
    }
    /// Return metadata for one path.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub fn stat(&self, path: impl AsRef<Path>) -> Result<FileMetadata> {
        let (guest, path) = workspace_path(path.as_ref())?;
        let provider = self.provider.clone();
        self.runtime
            .blocking(async move {
                readable(provider.as_ref())?;
                let mut metadata = provider.stat(&path).await?;
                metadata.readonly |= !provider.capabilities().write;
                Ok(metadata)
            })
            .map_err(|error| filesystem_error("stat", &guest, error))
    }
    /// Remove a file, or a directory when empty or `recursive` is requested.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub fn remove(&self, path: impl AsRef<Path>, recursive: bool) -> Result<()> {
        let (guest, path) = workspace_path(path.as_ref())?;
        let provider = self.provider.clone();
        self.runtime
            .blocking(async move {
                writable(provider.as_ref())?;
                provider.remove(&path, recursive).await
            })
            .map_err(|error| filesystem_error("remove", &guest, error))
    }
    /// Rename a file or directory within the workspace.
    ///
    /// # Errors
    /// Returns an error for invalid guest paths, denied rights or failed provider operations.
    pub async fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
        let (guest, from) = workspace_path(from.as_ref())?;
        let (_, to) = workspace_path(to.as_ref())?;
        let provider = self.provider.clone();
        self.runtime
            .call(async move {
                writable(provider.as_ref())?;
                provider.rename(&from, &to).await
            })
            .await
            .map_err(|error| filesystem_error("rename", &guest, error))
    }
}
fn readable(provider: &dyn FileSystem) -> FsResult<()> {
    if provider.capabilities().read {
        Ok(())
    } else {
        Err(FsError::PermissionDenied)
    }
}
fn writable(provider: &dyn FileSystem) -> FsResult<()> {
    if provider.capabilities().write {
        Ok(())
    } else {
        Err(FsError::PermissionDenied)
    }
}
async fn create_parents(provider: &dyn FileSystem, path: &RelativePath) -> FsResult<()> {
    let mut prefix = PathBuf::new();
    for component in path.as_path().components() {
        prefix.push(component);
        let path = RelativePath::new(&prefix)?;
        match provider.create_dir(&path).await {
            Ok(()) => {}
            Err(FsError::AlreadyExists) => {
                if provider.stat(&path).await?.file_type != crate::FileType::Directory {
                    return Err(FsError::NotDirectory);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn filesystem_error(operation: &'static str, path: &Path, error: FsError) -> Error {
    Error::FileSystem {
        operation,
        path: path.to_owned(),
        message: error.to_string(),
    }
}

pub(crate) fn validate_guest_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidGuestPath {
            path: path.to_owned(),
            message: "path must not be empty".into(),
        });
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::Prefix(_)) {
            return Err(Error::InvalidGuestPath {
                path: path.to_owned(),
                message: "path traversal and host prefixes are not allowed".into(),
            });
        }
    }
    Ok(path.to_owned())
}
fn workspace_path(path: &Path) -> Result<(PathBuf, RelativePath)> {
    let path = validate_guest_path(path)?;
    let relative = if path.has_root() {
        path.strip_prefix("/workspace")
            .map_err(|_| Error::InvalidGuestPath {
                path: path.clone(),
                message: "sandbox filesystem paths must be inside `/workspace`".into(),
            })?
    } else {
        path.as_path()
    };
    let internal = RelativePath::new(relative).map_err(|error| Error::InvalidGuestPath {
        path: path.clone(),
        message: error.to_string(),
    })?;
    Ok((Path::new("/workspace").join(relative), internal))
}
