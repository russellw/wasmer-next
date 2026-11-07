//! Filesystem driver that passes through to a host directory.
//!
//! # Containment
//!
//! The guest must never reach anything outside the mapped directory. The VFS resolves every
//! path itself, symlinks and `..` included, and asks this driver only for single names inside a
//! directory it already holds. On Linux every object is held as a host `O_PATH` descriptor, and every
//! name is resolved with `openat(dir, name, O_PATH | O_NOFOLLOW)`: one component, never `..`, never
//! following a symlink. A symlink is opened as itself and its target is handed to the VFS as
//! data. No host path string exists that a rename on the host could redirect; this is the scheme
//! of libfuse's `passthrough_ll`.
//!
//! Operations the kernel does not offer on an `O_PATH` descriptor (reopening for I/O, `chmod`,
//! `truncate`, `utimensat`, xattrs, `link`) go through `/proc/self/fd/N`, which names exactly the
//! held inode. The Linux driver therefore requires `/proc`.
//!
//! On macOS 13 and later, vnode descriptors (`O_EVTONLY` and `O_SYMLINK`) retain object identity.
//! Searchable directories can instead retain `O_SEARCH` grants without directory-read access.
//! A terminal name whose metadata is readable but which cannot be pinned returns an
//! operation-scoped observation from `lookup_entry`, never an inode capability. Existing-file
//! acquisition selects the current name and supplies actual fd attributes for VFS approval
//! before I/O or truncation. Already-pinned metadata and symlink reads use descriptor operations.
//! Symlink reads keep the host's
//! current authorization and errors: APFS can discard an unlinked symlink's body even
//! while its descriptor remains open. No removed-link body recovery is promised.
//! Data opens walk a candidate
//! beneath the pinned root without following symlinks, then verify device/inode identity
//! before any I/O. Already-open handles survive rename, unlink and permission changes;
//! reopening an unlinked or no-longer-contained node can fail with `ESTALE`.
//! `freadlink` is resolved at runtime, so hosts without it (before macOS 13) return
//! `Unsupported` from [`open`] without preventing the embedding binary from loading.
//! Native Linux export handles, unnamed files and hard links are not available on macOS.
//! Other hosts return `Unsupported`.
//!
//! # Ownership
//!
//! Objects owned by the host user running the machine appear as owned by the configured guest
//! user (uid and gid 1 by default), and the reverse when the guest changes ownership;
//! other ids pass through.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::{io, path::Path, sync::Arc};

use wasixv2_host::Host;
use wasixv2_vfs::Filesystem;

/// How a host directory is mapped.
#[derive(Clone, Debug)]
pub struct Options {
    /// Refuse every change, whatever the host would allow.
    pub read_only: bool,
    /// The guest uid and gid that the host user running the machine appears as.
    pub owner: (u32, u32),
}

impl Default for Options {
    fn default() -> Self {
        Self {
            read_only: false,
            owner: (1, 1),
        }
    }
}

/// Opens the host directory `root` as a filesystem. Blocking host calls run on `host`'s
/// executor.
pub fn open(root: &Path, host: Arc<dyn Host>, options: Options) -> io::Result<Arc<dyn Filesystem>> {
    #[cfg(target_os = "linux")]
    return Ok(Arc::new(linux::HostFs::new(root, host, options)?));
    #[cfg(target_os = "macos")]
    return Ok(Arc::new(macos::HostFs::new(root, host, options)?));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (root, host, options);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host directories are only supported on Linux and macOS hosts",
        ))
    }
}
