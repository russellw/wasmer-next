//! `fd_readdir`: v1 directory cookies over Linux directory offsets.
//!
//! A v1 cookie names where to start, and every `dirent.d_next` is the cookie of the entry after
//! it; `getdents64`'s `d_off` is exactly that for the open file's position (`.` and `..`
//! included). So each call seeks the descriptor to the cookie and repacks `linux_dirent64`
//! records as v1 `dirent` + name, filling the guest's buffer up to its last byte. A record that
//! does not fit is cut off, and `bufused == buf_len` tells wasix-libc to grow its buffer and
//! ask again from the cookie before it.

use crate::abi::fs::Rights;

use wasixv2_abi::{Fd, GuestLayout, GuestPtrMut, LinuxDirent64, SeekWhence};
use wasixv2_syscalls::{Control, Syscalls};
use wasmer::RuntimeError;

use crate::{
    abi::fs::{Dirent, Filetype},
    shim::{self, Env},
};

/// How much `getdents64` reads per round: room for many entries, and always for one.
const CHUNK: u32 = 16 * 1024;

/// The v1 type for a Linux `d_type` (`DT_*`). FIFOs have no v1 type.
fn dirent_type(d_type: u8) -> Filetype {
    match d_type {
        2 => Filetype::CHARACTER_DEVICE,
        4 => Filetype::DIRECTORY,
        6 => Filetype::BLOCK_DEVICE,
        8 => Filetype::REGULAR_FILE,
        10 => Filetype::SYMBOLIC_LINK,
        12 => Filetype::SOCKET_STREAM,
        _ => Filetype::UNKNOWN,
    }
}

/// Offset of `d_name` in `linux_dirent64`.
const NAME_OFFSET: usize = 19;

/// Appends the v1 form of each `linux_dirent64` record in `records` to `out`, until `out`
/// holds `limit` bytes; the record that crosses `limit` is cut there. Returns whether `out`
/// is full.
fn repack(records: &[u8], out: &mut Vec<u8>, limit: usize) -> bool {
    let mut rest = records;
    while let Some(record) = LinuxDirent64::read_from(rest) {
        let reclen = usize::from(record.d_reclen);
        let Some(raw) = rest.get(..reclen).filter(|_| reclen > NAME_OFFSET) else {
            break;
        };
        let name = &raw[NAME_OFFSET..];
        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
        let dirent = Dirent {
            d_next: record.d_off as u64,
            d_ino: record.d_ino,
            d_namlen: name.len() as u32,
            d_type: dirent_type(record.d_type),
        };
        if append(dirent, name, out, limit) {
            return true;
        }
        rest = &rest[reclen..];
    }
    out.len() >= limit
}

fn append(dirent: Dirent, name: &[u8], out: &mut Vec<u8>, limit: usize) -> bool {
    let mut bytes = vec![0; Dirent::SIZE];
    dirent.write_to(&mut bytes);
    bytes.extend_from_slice(name);
    let room = limit - out.len();
    out.extend_from_slice(&bytes[..bytes.len().min(room)]);
    out.len() == limit
}

fn root_entries(entries: &[(Vec<u8>, u64)], cookie: u64, out: &mut Vec<u8>, limit: usize) {
    let start = usize::try_from(cookie).unwrap_or(usize::MAX);
    for (index, (name, ino)) in entries.iter().enumerate().skip(start) {
        let name = [b"/".as_slice(), name].concat();
        if append(
            Dirent {
                d_next: index as u64 + 1,
                d_ino: *ino,
                d_namlen: name.len() as u32,
                d_type: Filetype::DIRECTORY,
            },
            &name,
            out,
            limit,
        ) {
            break;
        }
    }
}

pub(crate) async fn fd_readdir<S: Syscalls + Control + 'static>(
    env: Env<S>,
    fd: i32,
    buf: i32,
    buf_len: i32,
    cookie: i64,
    used: i32,
) -> Result<i32, RuntimeError> {
    shim::errno(&env, async |frame| {
        crate::rights::require(frame, &[(wasixv2_abi::Fd(fd), Rights::FD_READDIR)]).await?;
        let limit = buf_len as u32 as usize;
        let startup = frame.startup().await?;
        if let Some(root) = &startup.root {
            let stat =
                crate::calls::fs::fstat(frame, Fd(fd), wasixv2_abi::StatxMask::STATX_BASIC_STATS)
                    .await?;
            if root.root
                == (crate::process::FileId {
                    dev: (stat.stx_dev_major, stat.stx_dev_minor),
                    ino: stat.stx_ino,
                })
            {
                let mut out = Vec::with_capacity(limit.min(CHUNK as usize));
                root_entries(&root.entries, cookie as u64, &mut out, limit);
                frame.write_bytes(buf as u32, &out).await?;
                return frame.write(used as u32, &(out.len() as u32)).await;
            }
        }
        let caller = frame.caller();
        frame
            .syscalls
            .lseek(&caller, Fd(fd), cookie, SeekWhence::SEEK_SET)
            .await?;
        let chunk = frame.mem.alloc_zeroed(CHUNK)?;
        let mut out = Vec::with_capacity(limit.min(CHUNK as usize));
        while out.len() < limit {
            let n = frame
                .syscalls
                .getdents64(&caller, Fd(fd), GuestPtrMut::new(chunk.addr), CHUNK)
                .await?;
            if n <= 0 {
                break;
            }
            let records = frame.mem.take_bytes(chunk, n as usize);
            if repack(&records, &mut out, limit) {
                break;
            }
        }
        frame.write_bytes(buf as u32, &out).await?;
        frame.write(used as u32, &(out.len() as u32)).await
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_presentation_keeps_opaque_names_cookies_and_truncated_prefixes() {
        let entries = vec![(b"same//path".to_vec(), 7), (b"same/path".to_vec(), 8)];
        let mut full = Vec::new();
        root_entries(&entries, 0, &mut full, 4096);
        let first = Dirent::read_from(&full).unwrap();
        assert_eq!(first.d_next, 1);
        assert_eq!(first.d_ino, 7);
        assert_eq!(first.d_type, Filetype::DIRECTORY);
        assert_eq!(
            &full[Dirent::SIZE..Dirent::SIZE + first.d_namlen as usize],
            b"/same//path"
        );
        let next = Dirent::SIZE + first.d_namlen as usize;
        let second = Dirent::read_from(&full[next..]).unwrap();
        assert_eq!(second.d_next, 2);
        assert_eq!(&full[next + Dirent::SIZE..], b"/same/path");
        let mut resumed = Vec::new();
        root_entries(&entries, 1, &mut resumed, 4096);
        assert_eq!(resumed, full[next..]);
        for limit in [0, 1, Dirent::SIZE - 1, next, next + 3] {
            let mut prefix = Vec::new();
            root_entries(&entries, 0, &mut prefix, limit);
            assert_eq!(prefix, full[..limit]);
        }
        let mut empty = Vec::new();
        root_entries(&[], 0, &mut empty, 4096);
        root_entries(&entries, u64::MAX, &mut empty, 4096);
        assert!(
            empty.is_empty(),
            "no implicit dot entries or cookie wraparound"
        );
    }

    /// One `linux_dirent64` record, padded to 8 bytes as the kernel does.
    fn record(ino: u64, off: i64, d_type: u8, name: &[u8]) -> Vec<u8> {
        let reclen = (NAME_OFFSET + name.len() + 1).next_multiple_of(8);
        let mut bytes = vec![0; reclen];
        LinuxDirent64 {
            d_ino: ino,
            d_off: off,
            d_reclen: reclen as u16,
            d_type,
        }
        .write_to(&mut bytes);
        bytes[NAME_OFFSET..NAME_OFFSET + name.len()].copy_from_slice(name);
        bytes
    }

    fn records() -> Vec<u8> {
        [
            record(1, 1, 4, b"."),
            record(2, 2, 4, b".."),
            record(7, 3, 8, b"file.txt"),
        ]
        .concat()
    }

    #[test]
    fn repacks_as_v1_dirents() {
        let mut out = Vec::new();
        assert!(!repack(&records(), &mut out, 4096));
        assert_eq!(out.len(), 3 * Dirent::SIZE + 1 + 2 + 8);
        let first = Dirent::read_from(&out).unwrap();
        assert_eq!(
            first,
            Dirent {
                d_next: 1,
                d_ino: 1,
                d_namlen: 1,
                d_type: Filetype::DIRECTORY
            }
        );
        assert_eq!(out[Dirent::SIZE], b'.');
        let third_at = 2 * Dirent::SIZE + 3;
        let third = Dirent::read_from(&out[third_at..]).unwrap();
        assert_eq!(third.d_next, 3);
        assert_eq!(third.d_type, Filetype::REGULAR_FILE);
        assert_eq!(&out[third_at + Dirent::SIZE..], b"file.txt");
    }

    #[test]
    fn truncates_the_last_entry() {
        // Room for the first entry and half of the second's header.
        let limit = Dirent::SIZE + 1 + 12;
        let mut out = Vec::new();
        assert!(repack(&records(), &mut out, limit));
        assert_eq!(out.len(), limit);
        // An entry that ends exactly at the limit also reports a full buffer.
        let mut out = Vec::new();
        assert!(repack(&records(), &mut out, Dirent::SIZE + 1));
    }

    #[test]
    fn types() {
        assert_eq!(dirent_type(10), Filetype::SYMBOLIC_LINK);
        assert_eq!(dirent_type(1), Filetype::UNKNOWN);
        assert_eq!(dirent_type(0), Filetype::UNKNOWN);
    }
}
