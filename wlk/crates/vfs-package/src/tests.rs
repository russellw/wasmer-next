use std::collections::BTreeMap;

use futures::executor::block_on;
use webc::v3::{
    ChecksumAlgorithm, SignatureAlgorithm, Timestamps,
    write::{DirEntry as WEntry, Directory as WDir, FileEntry, SymlinkEntry, Writer},
};

use super::*;

fn dir(children: Vec<(&str, WEntry<'static>)>) -> WDir<'static> {
    dir_with_timestamps(children, Timestamps::default())
}

fn dir_with_timestamps(
    children: Vec<(&str, WEntry<'static>)>,
    timestamps: Timestamps,
) -> WDir<'static> {
    let children: BTreeMap<_, _> = children
        .into_iter()
        .map(|(name, entry)| (name.parse().unwrap(), entry))
        .collect();
    WDir::new(children, timestamps)
}

fn file(data: &'static [u8]) -> WEntry<'static> {
    WEntry::File(FileEntry::borrowed(data, Timestamps::default()))
}

/// `/a.txt`, `/bin/{tool,sh -> tool}`, `/empty/`, `/z/`.
fn fs() -> PackageFs {
    PackageFs::new(&reader(), "atom").unwrap()
}

fn reader() -> OwnedReader {
    let volume = dir(vec![
        ("z", WEntry::Dir(dir(vec![]))),
        ("a.txt", file(b"hello world")),
        (
            "bin",
            WEntry::Dir(dir(vec![
                ("tool", file(b"\0asm")),
                (
                    "sh",
                    WEntry::Symlink(SymlinkEntry::borrowed("tool", Timestamps::default())),
                ),
            ])),
        ),
        ("empty", WEntry::Dir(dir(vec![]))),
    ]);
    let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
        .write_manifest(&Default::default())
        .unwrap()
        .write_atoms(BTreeMap::new())
        .unwrap();
    writer.write_volume("atom", volume).unwrap();
    let webc = writer.finish(SignatureAlgorithm::None).unwrap();
    OwnedReader::parse(webc).unwrap()
}

fn lookup(fs: &PackageFs, path: &str) -> Arc<dyn Node> {
    let mut node = fs.root();
    for name in path.split('/').filter(|n| !n.is_empty()) {
        node = block_on(node.lookup(name.as_bytes())).unwrap();
    }
    node
}

struct Names(Vec<(Vec<u8>, u64, FileType, u64)>, usize);

impl DirSink for Names {
    fn push(&mut self, entry: DirEntry<'_>) -> bool {
        if self.0.len() == self.1 {
            return false;
        }
        self.0
            .push((entry.name.to_vec(), entry.ino, entry.file_type, entry.next));
        true
    }
}

fn read_dir(node: &dyn Node, cookie: u64, max: usize) -> Vec<(Vec<u8>, u64, FileType, u64)> {
    let handle = block_on(node.open(OpenOptions::default())).unwrap();
    let mut names = Names(Vec::new(), max);
    block_on(handle.readdir(cookie, &mut names)).unwrap();
    names.0
}

#[test]
fn lookup_finds_entries_and_misses_with_enoent() {
    let fs = fs();
    assert_eq!(lookup(&fs, "bin/tool").file_type(), FileType::Regular);
    assert_eq!(lookup(&fs, "bin/sh").file_type(), FileType::Symlink);
    assert_eq!(lookup(&fs, "empty").file_type(), FileType::Directory);
    assert_eq!(
        block_on(fs.root().lookup(b"missing")).err(),
        Some(Errno::ENOENT)
    );
    assert_eq!(
        block_on(lookup(&fs, "a.txt").lookup(b"x")).err(),
        Some(Errno::ENOTDIR)
    );
}

#[test]
fn inode_numbers_are_unique_stable_and_match_readdir() {
    let fs = fs();
    let ino = lookup(&fs, "bin/tool").ino();
    assert_eq!(ino, lookup(&fs, "bin/tool").ino());
    assert_eq!(fs.root().ino(), ROOT_INO);

    let mut all = vec![ROOT_INO];
    for path in ["a.txt", "bin", "bin/tool", "bin/sh", "empty", "z"] {
        all.push(lookup(&fs, path).ino());
    }
    let count = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), count);

    let entries = read_dir(&*lookup(&fs, "bin"), 0, usize::MAX);
    assert!(entries.iter().any(|e| e.0 == b"tool" && e.1 == ino));
}

#[test]
fn readdir_is_sorted_and_resumes_at_cookies() {
    let fs = fs();
    let root = fs.root();
    let all = read_dir(&*root, 0, usize::MAX);
    let names: Vec<_> = all.iter().map(|e| e.0.as_slice()).collect();
    assert_eq!(names, [&b"a.txt"[..], b"bin", b"empty", b"z"]);
    assert_eq!(all[1].2, FileType::Directory);

    let first = read_dir(&*root, 0, 2);
    let rest = read_dir(&*root, first[1].3, usize::MAX);
    assert_eq!(rest, all[2..]);
    assert!(read_dir(&*root, all[3].3, usize::MAX).is_empty());
}

#[test]
fn read_at_serves_data_and_eof() {
    let fs = fs();
    let handle = block_on(lookup(&fs, "a.txt").open(OpenOptions {
        read: true,
        ..Default::default()
    }))
    .unwrap();
    let mut buf = [0; 8];
    assert_eq!(block_on(handle.read_at(&mut buf, 6)), Ok(5));
    assert_eq!(&buf[..5], b"world");
    assert_eq!(block_on(handle.read_at(&mut buf, 11)), Ok(0));
    assert_eq!(block_on(handle.read_at(&mut buf, u64::MAX)), Ok(0));
}

#[test]
fn getattr_reports_a_root_owned_read_only_image() {
    let fs = fs();
    let file = block_on(lookup(&fs, "a.txt").getattr()).unwrap();
    assert_eq!(
        (file.mode, file.uid, file.gid, file.nlink, file.size),
        (0o755, 0, 0, 1, 11)
    );
    let root = block_on(fs.root().getattr()).unwrap();
    // `.`, the parent's entry, and one `..` each from bin, empty and z.
    assert_eq!((root.mode, root.nlink), (0o755, 5));
    let link = lookup(&fs, "bin/sh");
    assert_eq!(block_on(link.readlink()), Ok(b"tool".to_vec()));
    assert_eq!(block_on(link.getattr()).unwrap().size, 4);
    assert!(fs.info().read_only);
}

#[test]
fn with_owner_sets_every_objects_owner() {
    let fs = PackageFs::with_owner(&reader(), "atom", 1, 2).unwrap();
    for path in ["", "a.txt", "bin", "bin/sh"] {
        let attr = block_on(lookup(&fs, path).getattr()).unwrap();
        assert_eq!((attr.uid, attr.gid), (1, 2), "{path}");
    }
}

#[test]
fn mutations_fail_with_erofs() {
    let fs = fs();
    let root = fs.root();
    let file = lookup(&fs, "a.txt");
    let new = NewNode {
        umask: 0,
        kind: wasixv2_vfs::NewKind::Regular,
        mode: 0o644,
        uid: 0,
        gid: 0,
        task: 0,
        quota_exempt: false,
    };
    assert_eq!(block_on(root.create(b"n", &new)).err(), Some(Errno::EROFS));
    assert_eq!(block_on(root.unlink(b"a.txt")), Err(Errno::EROFS));
    assert_eq!(block_on(root.rmdir(b"empty")), Err(Errno::EROFS));
    assert_eq!(
        block_on(file.setattr(&SetAttr::default())).err(),
        Some(Errno::EROFS)
    );
    let write = OpenOptions {
        write: true,
        ..Default::default()
    };
    assert_eq!(block_on(file.open(write)).err(), Some(Errno::EROFS));
    assert_eq!(block_on(file.getxattr(b"user.x")), Err(Errno::ENODATA));
    assert_eq!(block_on(file.listxattr()), Ok(vec![]));
}

/// The bytes of a package whose volume `atom` holds `children`.
fn webc_bytes(children: Vec<(&str, WEntry<'static>)>) -> Vec<u8> {
    volume_bytes(dir(children))
}

fn volume_bytes(volume: WDir<'static>) -> Vec<u8> {
    let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
        .write_manifest(&Default::default())
        .unwrap()
        .write_atoms(BTreeMap::new())
        .unwrap();
    writer.write_volume("atom", volume).unwrap();
    writer.finish(SignatureAlgorithm::None).unwrap().to_vec()
}

fn mount(bytes: Vec<u8>) -> Result<PackageFs, PackageFsError> {
    PackageFs::new(&OwnedReader::parse(bytes).unwrap(), "atom")
}

fn find(bytes: &[u8], what: &[u8]) -> usize {
    let at = bytes.windows(what.len()).position(|w| w == what);
    let at = at.expect("pattern in the image");
    assert_eq!(
        bytes[at + 1..].windows(what.len()).position(|w| w == what),
        None
    );
    at
}

#[test]
fn a_file_whose_data_ends_before_it_starts_is_rejected_at_mount() {
    let mut bytes = webc_bytes(vec![("f", file(&[0xab; 1000]))]);
    // The file's header entry: its tag, then its data's start and end offsets.
    let at = (0..bytes.len() - 17)
        .find(|&i| {
            let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            bytes[i] == 31 && word(i + 9).checked_sub(word(i + 1)) == Some(1000)
        })
        .expect("the file's entry");
    let (start, end) = (at + 1, at + 9);
    let (a, b) = (bytes[start..end].to_vec(), bytes[end..end + 8].to_vec());
    bytes[start..end].copy_from_slice(&b);
    bytes[end..end + 8].copy_from_slice(&a);

    assert!(matches!(mount(bytes), Err(PackageFsError::Malformed(_))));
}

#[test]
fn names_that_are_not_file_names_are_rejected_at_mount() {
    for bad in [&b".."[..], b"a/", b"a\0"] {
        let mut bytes = webc_bytes(vec![("ab", file(b"x"))]);
        // A directory entry: the name's length, then the name.
        let at = find(&bytes, b"\x02\0\0\0\0\0\0\0ab") + 8;
        bytes[at..at + 2].copy_from_slice(bad);
        assert!(
            matches!(mount(bytes), Err(PackageFsError::Malformed(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn a_directory_that_contains_itself_is_rejected_at_mount() {
    let mut bytes = webc_bytes(vec![("d", WEntry::Dir(dir(vec![])))]);
    // The root's entry for `d`: its header offset, hash, name length and name. Offset 0 is the
    // root itself.
    let at = find(&bytes, b"\x01\0\0\0\0\0\0\0d") - 40;
    bytes[at..at + 8].copy_from_slice(&0u64.to_le_bytes());

    assert!(matches!(mount(bytes), Err(PackageFsError::Malformed(_))));
}

fn files(paths: &[(&str, &'static [u8])]) -> Result<PackageFs, PackageFsError> {
    let files = paths
        .iter()
        .map(|(path, data)| (path.to_string(), OwnedBuffer::from_static(data)));
    PackageFs::from_files(files, 1, 2)
}

#[test]
fn from_files_builds_the_directories_the_paths_imply() {
    let fs = files(&[
        ("bin/ls", b"\0asm ls"),
        ("usr/bin/ls", b"\0asm ls"),
        ("x", b""),
    ])
    .unwrap();
    assert_eq!(
        block_on(fs.root().getattr()).unwrap().mtime,
        Timestamp::default()
    );
    let names: Vec<_> = read_dir(&*fs.root(), 0, usize::MAX)
        .into_iter()
        .map(|e| (e.0, e.2))
        .collect();
    assert_eq!(
        names,
        [
            (b"bin".to_vec(), FileType::Directory),
            (b"usr".to_vec(), FileType::Directory),
            (b"x".to_vec(), FileType::Regular),
        ]
    );
    let ls = lookup(&fs, "usr/bin/ls");
    let attr = block_on(ls.getattr()).unwrap();
    assert_eq!(
        (attr.file_type, attr.mode, attr.uid, attr.gid, attr.size),
        (FileType::Regular, 0o755, 1, 2, 7)
    );
    let handle = block_on(ls.open(OpenOptions {
        read: true,
        ..Default::default()
    }))
    .unwrap();
    let mut buf = [0; 16];
    assert_eq!(block_on(handle.read_at(&mut buf, 0)), Ok(7));
    assert_eq!(&buf[..7], b"\0asm ls");
    // `.`, the parent's entry and `..` of `bin`.
    assert_eq!(block_on(lookup(&fs, "usr").getattr()).unwrap().nlink, 3);
    assert!(fs.info().read_only);
    assert_eq!(block_on(fs.root().unlink(b"x")), Err(Errno::EROFS));
}

#[test]
fn from_files_numbers_every_object_once() {
    let fs = files(&[("bin/a", b"a"), ("bin/b", b"b"), ("usr/bin/a", b"a")]).unwrap();
    let mut all = vec![fs.root().ino()];
    for path in ["bin", "bin/a", "bin/b", "usr", "usr/bin", "usr/bin/a"] {
        let ino = lookup(&fs, path).ino();
        assert_eq!(ino, lookup(&fs, path).ino(), "{path}");
        all.push(ino);
    }
    let count = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), count);
    let entries = read_dir(&*lookup(&fs, "bin"), 0, usize::MAX);
    assert_eq!(entries[1].1, lookup(&fs, "bin/b").ino());
}

#[test]
fn from_files_rejects_bad_and_clashing_paths() {
    for path in [
        "", "/bin/a", "bin/", "bin//a", "bin/./a", "bin/../a", "a\0b",
    ] {
        assert!(
            matches!(files(&[(path, b"")]), Err(PackageFsError::InvalidPath(_))),
            "{path:?}"
        );
    }
    let long = "n".repeat(NAME_MAX + 1);
    assert!(matches!(
        files(&[(long.as_str(), b"")]).err(),
        Some(PackageFsError::InvalidPath(_))
    ));
    for clash in [
        &[("bin/a", &b""[..]), ("bin/a", b"")][..],
        &[("bin", b""), ("bin/a", b"")],
        &[("bin/a", b""), ("bin", b"")],
    ] {
        assert!(
            matches!(files(clash), Err(PackageFsError::Conflict(_))),
            "{clash:?}"
        );
    }
}

/// A path's length bounds the tree's depth: the deepest path that fits `PATH_MAX` builds,
/// works and drops on a test thread's stack, and a deeper one is refused before anything
/// recurses through it.
#[test]
fn from_files_bounds_the_depth() {
    let deepest = format!("{}x", "d/".repeat((PATH_MAX - 2) / 2));
    assert_eq!(deepest.len(), PATH_MAX - 1);
    let fs = files(&[(deepest.as_str(), b"deep")]).unwrap();
    let attr = block_on(lookup(&fs, &deepest).getattr()).unwrap();
    assert_eq!(attr.size, 4);
    drop(fs);

    let hostile = format!("{}x", "d/".repeat(1 << 20));
    assert!(matches!(
        files(&[(hostile.as_str(), b"")]),
        Err(PackageFsError::PathTooLong(len)) if len == hostile.len()
    ));
}

#[test]
fn mounted_v3_retains_mtime_across_reader_paths() {
    use std::time::{Duration, SystemTime};

    let modified = Timestamps {
        modified: SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800),
    };
    let bytes = volume_bytes(dir_with_timestamps(
        vec![
            ("plain", file(b"")),
            ("stamped", WEntry::File(FileEntry::borrowed(b"", modified))),
            (
                "link",
                WEntry::Symlink(SymlinkEntry::borrowed("stamped", modified)),
            ),
            ("sub", WEntry::Dir(WDir::new(BTreeMap::new(), modified))),
        ],
        modified,
    ));
    let reader = OwnedReader::parse(bytes).unwrap();
    let fast = PackageFs::new(&reader, "atom").unwrap();
    let abstract_volume = webc::Container::from(reader).get_volume("atom").unwrap();
    let collected = PackageFs::from_volume(&abstract_volume, 0, 0).unwrap();
    for fs in [fast, collected] {
        for (path, seconds) in [
            ("", 946_684_800),
            ("plain", 1),
            ("link", 946_684_800),
            ("stamped", 946_684_800),
            ("sub", 946_684_800),
        ] {
            let attr = block_on(lookup(&fs, path).getattr()).unwrap();
            assert_eq!(attr.mtime, Timestamp::new(seconds, 0), "{path}");
            assert_eq!(attr.atime, Timestamp::default());
            assert_eq!(attr.ctime, Timestamp::default());
            assert_eq!(attr.btime, None);
        }
    }
}

#[test]
fn v3_mtime_preserves_seconds_beyond_u64_nanosecond_range() {
    use std::time::{Duration, SystemTime};

    let seconds = 22_000_000_000;
    let modified = Timestamps {
        modified: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
    };
    let reader = OwnedReader::parse(volume_bytes(dir_with_timestamps(vec![], modified))).unwrap();
    let fs = PackageFs::new(&reader, "atom").unwrap();
    let attr = block_on(fs.root().getattr()).unwrap();
    assert_eq!(attr.mtime, Timestamp::new(seconds as i64, 0));
}

#[test]
fn abstract_webc_mtime_keeps_fractional_values() {
    let metadata = Metadata::Dir {
        timestamps: Some(webc::Timestamps::from_modified(500_000_123)),
    };
    assert_eq!(webc_mtime(metadata), Timestamp::new(0, 500_000_123));
}

#[test]
fn from_volume_preserves_v3_directories_symlinks_and_buffers_after_source_drop() {
    let container = webc::Container::from(reader());
    let volume = container.get_volume("atom").unwrap();
    let (bytes, _) = volume.read_file("/bin/tool").unwrap();
    let fs = PackageFs::from_volume(&volume, 41, 42).unwrap();
    drop(volume);
    drop(container);

    for path in ["empty", "z"] {
        let node = lookup(&fs, path);
        assert_eq!(node.file_type(), FileType::Directory);
        assert!(read_dir(&*node, 0, usize::MAX).is_empty());
    }
    let link = lookup(&fs, "bin/sh");
    assert_eq!(link.file_type(), FileType::Symlink);
    assert_eq!(block_on(link.readlink()), Ok(b"tool".to_vec()));
    assert_eq!(
        block_on(link.open(OpenOptions::default())).err(),
        Some(Errno::ELOOP)
    );
    for path in ["", "bin", "bin/tool", "bin/sh", "empty"] {
        let attr = block_on(lookup(&fs, path).getattr()).unwrap();
        assert_eq!((attr.uid, attr.gid), (41, 42));
    }
    let handle = block_on(lookup(&fs, "bin/tool").open(OpenOptions::default())).unwrap();
    let shared = block_on(handle.shared_contents()).unwrap();
    assert_eq!(shared.as_ref().as_ref().as_ptr(), bytes.as_slice().as_ptr());
    drop(bytes);
    drop(fs);
    let mut buf = [0; 4];
    assert_eq!(block_on(handle.read_at(&mut buf, 0)), Ok(4));
    assert_eq!(&buf, b"\0asm");
    assert_eq!(shared.as_ref().as_ref(), b"\0asm");
}

#[test]
fn from_volume_preserves_v2_nested_and_empty_directories() {
    use webc::v2::{
        ChecksumAlgorithm, SignatureAlgorithm,
        write::{DirEntry, Directory, FileEntry, Writer},
    };
    let directory = |entries: Vec<(&str, DirEntry<'static>)>| Directory {
        children: entries
            .into_iter()
            .map(|(n, e)| (n.parse().unwrap(), e))
            .collect(),
    };
    let nested = directory(vec![
        ("data", DirEntry::File(FileEntry::Borrowed(b"v2"))),
        ("empty", DirEntry::Dir(directory(vec![]))),
    ]);
    let root = directory(vec![("nested", DirEntry::Dir(nested))]);
    let mut writer = Writer::new(ChecksumAlgorithm::Sha256)
        .write_manifest(&Default::default())
        .unwrap()
        .write_atoms(BTreeMap::new())
        .unwrap();
    writer.write_volume("atom", root).unwrap();
    let bytes = writer.finish(SignatureAlgorithm::None).unwrap();
    let container = webc::Container::from(webc::v2::read::OwnedReader::parse(bytes).unwrap());
    let volume = container.get_volume("atom").unwrap();
    let fs = PackageFs::from_volume(&volume, 1, 2).unwrap();
    drop(volume);
    drop(container);
    let nested = lookup(&fs, "nested");
    let entries = read_dir(&*nested, 0, usize::MAX);
    assert_eq!(
        entries.iter().map(|e| e.0.as_slice()).collect::<Vec<_>>(),
        [b"data".as_slice(), b"empty"]
    );
    assert_eq!(read_dir(&*nested, entries[0].3, usize::MAX), entries[1..]);
    assert!(read_dir(&*lookup(&fs, "nested/empty"), 0, usize::MAX).is_empty());
    let data = lookup(&fs, "nested/data");
    assert_eq!(
        block_on(data.getattr()).unwrap().mtime,
        Timestamp::new(1, 0)
    );
    let handle = block_on(data.open(OpenOptions::default())).unwrap();
    let mut buf = [0; 2];
    assert_eq!(block_on(handle.read_at(&mut buf, 0)), Ok(2));
    assert_eq!(&buf, b"v2");
}

#[test]
fn from_volume_keeps_directory_and_cyclic_symlinks_as_links() {
    let bytes = webc_bytes(vec![
        ("directory", WEntry::Dir(dir(vec![]))),
        (
            "nested",
            WEntry::Dir(dir(vec![("empty", WEntry::Dir(dir(vec![])))])),
        ),
        (
            "directory-link",
            WEntry::Symlink(SymlinkEntry::borrowed("directory", Timestamps::default())),
        ),
        (
            "nested-link",
            WEntry::Symlink(SymlinkEntry::borrowed(
                "nested/empty",
                Timestamps::default(),
            )),
        ),
        (
            "cycle",
            WEntry::Symlink(SymlinkEntry::borrowed("cycle", Timestamps::default())),
        ),
    ]);
    let container = webc::Container::from(OwnedReader::parse(bytes).unwrap());
    let fs = PackageFs::from_volume(&container.get_volume("atom").unwrap(), 0, 0).unwrap();
    for (name, target) in [
        ("directory-link", "directory"),
        ("nested-link", "nested/empty"),
        ("cycle", "cycle"),
    ] {
        let link = lookup(&fs, name);
        assert_eq!(link.file_type(), FileType::Symlink);
        assert_eq!(block_on(link.readlink()), Ok(target.as_bytes().to_vec()));
    }
    assert!(read_dir(&*lookup(&fs, "nested/empty"), 0, usize::MAX).is_empty());
}

#[derive(Debug)]
enum BadVolume {
    MissingRoot,
    RootFile,
    MissingRootDir,
    MissingDir,
    MissingFile,
    MissingLink,
    MissingMetadata,
    FileLength,
    LinkLength,
    InvalidName(String),
    Duplicate,
    RepeatedDir,
    Panic,
}

impl BadVolume {
    fn entry(&self) -> webc::Metadata {
        use webc::Metadata;
        match self {
            Self::MissingDir | Self::RepeatedDir => Metadata::Dir { timestamps: None },
            Self::MissingLink | Self::LinkLength => Metadata::Symlink {
                target_length: usize::MAX,
                timestamps: None,
            },
            Self::Duplicate => Metadata::File {
                length: 4,
                timestamps: None,
            },
            _ => Metadata::File {
                length: usize::MAX,
                timestamps: None,
            },
        }
    }

    fn volume(self) -> webc::Volume {
        let provider: Arc<dyn webc::AbstractVolume + Send + Sync> = Arc::new(self);
        provider.into()
    }
}

impl webc::AbstractVolume for BadVolume {
    fn metadata(&self, path: &webc::PathSegments) -> Option<webc::Metadata> {
        if *path == webc::PathSegments::ROOT {
            match self {
                Self::MissingRoot => None,
                Self::RootFile => Some(self.entry()),
                _ => Some(webc::Metadata::Dir { timestamps: None }),
            }
        } else if matches!(self, Self::MissingMetadata) {
            None
        } else {
            Some(self.entry())
        }
    }

    fn read_dir(
        &self,
        path: &webc::PathSegments,
    ) -> Option<Vec<(webc::PathSegment, Option<[u8; 32]>, webc::Metadata)>> {
        assert!(!matches!(self, Self::Panic), "broken volume provider");
        if matches!(self, Self::MissingRootDir) {
            return None;
        }
        if matches!(self, Self::MissingDir) && *path != webc::PathSegments::ROOT {
            return None;
        }
        let name = match self {
            Self::InvalidName(name) => name.as_str(),
            _ => "entry",
        };
        let entry = (name.parse().unwrap(), None, self.entry());
        Some(if matches!(self, Self::Duplicate) {
            vec![entry.clone(), entry]
        } else {
            vec![entry]
        })
    }

    fn read_file(&self, _path: &webc::PathSegments) -> Option<(OwnedBuffer, Option<[u8; 32]>)> {
        if matches!(self, Self::MissingFile) {
            None
        } else {
            Some((OwnedBuffer::from_static(b"data"), None))
        }
    }

    fn read_link(&self, _path: &webc::PathSegments) -> Option<(String, Option<[u8; 32]>)> {
        if matches!(self, Self::MissingLink) {
            None
        } else {
            Some(("target".to_string(), None))
        }
    }
}

#[test]
fn from_volume_fails_closed_on_unreadable_or_inconsistent_entries() {
    for provider in [
        BadVolume::MissingRoot,
        BadVolume::RootFile,
        BadVolume::MissingRootDir,
        BadVolume::MissingDir,
        BadVolume::MissingFile,
        BadVolume::MissingLink,
        BadVolume::MissingMetadata,
        BadVolume::FileLength,
        BadVolume::LinkLength,
        BadVolume::Panic,
    ] {
        assert!(matches!(
            PackageFs::from_volume(&provider.volume(), 0, 0),
            Err(PackageFsError::Malformed(_))
        ));
    }
}

#[test]
fn from_volume_rejects_invalid_and_duplicate_names() {
    for name in [
        "a/b".to_string(),
        "a\0b".to_string(),
        "n".repeat(NAME_MAX + 1),
    ] {
        assert!(matches!(
            PackageFs::from_volume(&BadVolume::InvalidName(name).volume(), 0, 0),
            Err(PackageFsError::Malformed(_))
        ));
    }
    assert!(matches!(
        PackageFs::from_volume(&BadVolume::Duplicate.volume(), 0, 0),
        Err(PackageFsError::Conflict(_))
    ));
}

#[test]
fn from_volume_bounds_repeated_directory_traversal() {
    assert!(matches!(
        PackageFs::from_volume(&BadVolume::RepeatedDir.volume(), 0, 0),
        Err(PackageFsError::PathTooLong(_))
    ));
}
