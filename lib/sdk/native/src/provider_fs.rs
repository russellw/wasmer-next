use std::{
    fmt::Debug,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

/// Result type for external filesystem providers.
pub type FsResult<T> = std::result::Result<T, FsError>;

/// Stable errors returned by an SDK filesystem provider.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum FsError {
    #[error("entry not found")]
    NotFound,
    #[error("entry already exists")]
    AlreadyExists,
    #[error("permission denied")]
    PermissionDenied,
    #[error("invalid path or option: {0}")]
    InvalidInput(String),
    #[error("expected a directory")]
    NotDirectory,
    #[error("expected a file")]
    NotFile,
    #[error("directory is not empty")]
    DirectoryNotEmpty,
    #[error("operation is unsupported")]
    Unsupported,
    #[error("filesystem I/O failed: {0}")]
    Io(String),
}

/// A normalized path relative to a provider's mounted root.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RelativePath(PathBuf);

impl RelativePath {
    /// Parse and validate a provider-relative path.
    ///
    /// # Errors
    ///
    /// Returns an error for absolute paths, host prefixes, or `..`.
    pub fn new(path: impl AsRef<Path>) -> FsResult<Self> {
        let path = path.as_ref();
        if path.is_absolute() {
            return Err(FsError::InvalidInput(
                "provider paths must be relative".to_owned(),
            ));
        }
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => normalized.push(value),
                Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                    return Err(FsError::InvalidInput(
                        "provider paths cannot escape their root".to_owned(),
                    ));
                }
            }
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.as_os_str().is_empty()
    }
}

/// The kind of an external filesystem entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    File,
    Directory,
}

/// Metadata returned by an external filesystem provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub file_type: FileType,
    pub len: u64,
    pub readonly: bool,
    /// Nanoseconds since the Unix epoch; zero when unavailable.
    pub accessed: u64,
    pub modified: u64,
    pub created: u64,
}

/// One immediate child returned by [`FileSystem::read_dir`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    pub metadata: FileMetadata,
}

/// Provider-declared capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSystemCapabilities {
    pub read: bool,
    pub write: bool,
}

impl FileSystemCapabilities {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
    };
}

/// Options used when opening a provider file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct FileOpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
    pub append: bool,
}

/// An asynchronously accessed file supplied by an external provider.
#[async_trait]
pub trait File: Debug + Send + Sync + 'static {
    async fn read_at(&self, offset: u64, length: usize) -> FsResult<Bytes>;
    async fn write_at(&self, offset: u64, data: Bytes) -> FsResult<usize>;
    /// A positioned write even when the file was opened for append. The default
    /// preserves existing providers; canonical storage overrides it for append
    /// flag changes and RWF_NOAPPEND without a second cursor.
    async fn write_positioned_at(&self, offset: u64, data: Bytes) -> FsResult<usize> {
        self.write_at(offset, data).await
    }
    /// Attempt an atomic append and report the actual start and accepted count.
    /// `None` keeps the existing provider's positioned-write append contract;
    /// callers must not infer an atomic offset by reading metadata afterward.
    async fn try_atomic_append(&self, _data: Bytes) -> FsResult<Option<(u64, usize)>> {
        Ok(None)
    }
    async fn set_len(&self, length: u64) -> FsResult<()>;
    async fn flush(&self) -> FsResult<()>;
    async fn close(&self) -> FsResult<()>;
    async fn metadata(&self) -> FsResult<FileMetadata> {
        Err(FsError::Unsupported)
    }
    /// Update timestamps in nanoseconds since the Unix epoch; `None` preserves a value.
    async fn set_times(&self, _atime: Option<u64>, _mtime: Option<u64>) -> FsResult<()> {
        Err(FsError::Unsupported)
    }
}

/// Object-safe asynchronous filesystem provider mounted beneath a guest path.
#[async_trait]
pub trait FileSystem: Debug + Send + Sync + 'static {
    fn capabilities(&self) -> FileSystemCapabilities;
    async fn stat(&self, path: &RelativePath) -> FsResult<FileMetadata>;
    async fn read_dir(&self, path: &RelativePath) -> FsResult<Vec<DirectoryEntry>>;
    async fn open(&self, path: &RelativePath, options: FileOpenOptions) -> FsResult<Arc<dyn File>>;
    async fn create_dir(&self, path: &RelativePath) -> FsResult<()>;
    async fn remove(&self, path: &RelativePath, recursive: bool) -> FsResult<()>;
    async fn rename(&self, from: &RelativePath, to: &RelativePath) -> FsResult<()>;
    async fn flush(&self) -> FsResult<()>;
    /// Update timestamps in nanoseconds since the Unix epoch; `None` preserves a value.
    async fn set_times(
        &self,
        _path: &RelativePath,
        _atime: Option<u64>,
        _mtime: Option<u64>,
        _follow_symlinks: bool,
    ) -> FsResult<()> {
        Err(FsError::Unsupported)
    }
}

/// Guest rights applied on top of provider capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

pub use crate::memory::Directory;
