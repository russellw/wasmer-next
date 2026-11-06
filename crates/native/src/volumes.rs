//! Host directory mounts exposed inside a native WLK process.

use std::{ffi::OsStr, io, os::unix::ffi::OsStrExt, path::PathBuf, sync::Arc};

use wasixv2_host::Host;
use wasixv2_kernel::Kernel;
use wasixv2_vfs::MountFlags;
use wasixv2_vfs_host::Options;

/// A host directory mapped at an absolute guest path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Volume {
    pub host: PathBuf,
    pub guest: Vec<u8>,
    pub read_only: bool,
}

/// Parse `HOST:GUEST[:ro]`, preserving non-UTF-8 host and guest path bytes.
pub fn parse(value: &OsStr) -> io::Result<Volume> {
    let bytes = value.as_bytes();
    let separator = bytes
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| invalid("volume must be HOST:GUEST[:ro]"))?;
    let host = &bytes[..separator];
    let guest_and_mode = &bytes[separator + 1..];
    if host.is_empty() || guest_and_mode.is_empty() {
        return Err(invalid("volume host and guest paths must be non-empty"));
    }

    let (guest, read_only) = match guest_and_mode.iter().rposition(|byte| *byte == b':') {
        Some(index) if &guest_and_mode[index + 1..] == b"ro" => (&guest_and_mode[..index], true),
        Some(_) => return Err(invalid("volume mode must be `ro` when specified")),
        None => (guest_and_mode, false),
    };
    if guest.is_empty() || guest[0] != b'/' {
        return Err(invalid("volume guest path must be absolute"));
    }
    if guest.contains(&0) || host.contains(&0) {
        return Err(invalid("volume paths cannot contain NUL bytes"));
    }

    Ok(Volume {
        host: PathBuf::from(OsStr::from_bytes(host)),
        guest: guest.to_vec(),
        read_only,
    })
}

/// Open and mount each host directory at its guest target, creating target directories as needed.
pub async fn mount(kernel: &Kernel, host: Arc<dyn Host>, volumes: &[Volume]) -> io::Result<()> {
    for volume in volumes {
        let filesystem = wasixv2_vfs_host::open(
            &volume.host,
            host.clone(),
            Options {
                read_only: volume.read_only,
                ..Options::default()
            },
        )?;
        kernel
            .vfs()
            .mount(
                &volume.guest,
                filesystem,
                MountFlags {
                    read_only: volume.read_only,
                    ..MountFlags::default()
                },
                true,
            )
            .await
            .map_err(|error| {
                io::Error::other(format!(
                    "could not mount volume at {}: {error:?}",
                    String::from_utf8_lossy(&volume.guest)
                ))
            })?;
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
