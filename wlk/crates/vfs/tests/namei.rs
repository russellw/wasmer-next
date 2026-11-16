//! Path-walk and namespace rules, checked against Linux's behaviour on a memory filesystem.

use std::sync::Arc;

use futures::executor::block_on;
use wasixv2_abi::OpenFlags;
use wasixv2_vfs::{
    Clock, Cred, Ctx, Errno, File, LookupFlags, MountFlags, OpenHow, Path, RenameMode, Timestamp,
    Vfs,
};
use wasixv2_vfs_mem::MemFs;

struct Epoch;

impl Clock for Epoch {
    fn now(&self) -> Timestamp {
        Timestamp::default()
    }
}

struct World {
    vfs: Arc<Vfs>,
    root: Path,
    cred: Cred,
}

impl World {
    /// A root owned by uid 1, which the caller runs as.
    fn new() -> Self {
        let vfs = Vfs::new(Arc::new(MemFs::new(Arc::new(Epoch), 0o755, 1, 1)));
        let root = vfs.root();
        Self {
            vfs,
            root,
            cred: Cred::user(1, 1),
        }
    }

    fn cx(&self) -> Ctx<'_> {
        Ctx {
            cred: &self.cred,
            root: &self.root,
            umask: 0o022,
            task: 0,
            leases: None,
        }
    }

    fn open(&self, path: &[u8], flags: OpenFlags, follow: bool) -> Result<File, Errno> {
        let how = OpenHow {
            flags,
            mode: 0o644,
            lookup: LookupFlags {
                follow,
                directory: flags.contains(OpenFlags::O_DIRECTORY),
                ..LookupFlags::default()
            },
        };
        block_on(self.vfs.open(&self.cx(), &self.root, path, &how))
            .map_err(wasixv2_vfs::PathError::errno)
    }

    fn create(&self, path: &[u8]) -> File {
        self.open(path, OpenFlags::O_CREAT | OpenFlags::O_RDWR, true)
            .unwrap()
    }

    fn mkdir(&self, path: &[u8]) -> Result<(), Errno> {
        block_on(self.vfs.mkdir(&self.cx(), &self.root, path, 0o755))
            .map_err(wasixv2_vfs::PathError::errno)
    }

    fn symlink(&self, target: &[u8], path: &[u8]) {
        block_on(self.vfs.symlink(&self.cx(), target, &self.root, path))
            .map_err(wasixv2_vfs::PathError::errno)
            .unwrap();
    }

    fn lookup(&self, path: &[u8], flags: LookupFlags) -> Result<Path, Errno> {
        block_on(self.vfs.lookup(&self.cx(), &self.root, path, flags))
            .map_err(wasixv2_vfs::PathError::errno)
    }
}

fn namespace(
    world: &World,
    grants: &[(&[u8], Option<&[u8]>)],
    fallback: Option<usize>,
) -> Result<wasixv2_vfs::BootstrapNamespace, Errno> {
    let directories = grants
        .iter()
        .map(|(path, name)| {
            let path = world.lookup(path, LookupFlags::follow()).unwrap();
            wasixv2_vfs::NamespaceDirectory {
                source: world
                    .vfs
                    .open_tree(world.vfs.namespace(), &path, true)
                    .unwrap(),
                lookup_name: name.map(<[u8]>::to_vec),
            }
        })
        .collect::<Vec<_>>();
    world.vfs.bootstrap_namespace(
        world.vfs.namespace(),
        world.vfs.namespace().owner().clone(),
        &directories,
        fallback,
    )
}

#[test]
fn bootstrap_namespace_empty_root_lists_only_dots_and_rejects_invalid_capabilities() {
    struct Names(Vec<Vec<u8>>);
    impl wasixv2_vfs::DirSink for Names {
        fn push(&mut self, entry: wasixv2_vfs::DirEntry<'_>) -> bool {
            self.0.push(entry.name.to_vec());
            true
        }
    }
    let world = World::new();
    world.create(b"/outside");
    let boot = namespace(&world, &[], None).unwrap();
    let cx = Ctx {
        root: &boot.root,
        ..world.cx()
    };
    let how = OpenHow {
        flags: OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY,
        lookup: LookupFlags {
            empty: true,
            directory: true,
            ..LookupFlags::default()
        },
        mode: 0,
    };
    let root = block_on(world.vfs.open(&cx, &boot.root, b"", &how)).unwrap();
    let mut names = Names(Vec::new());
    block_on(root.readdir(0, &mut names)).unwrap();
    assert_eq!(names.0, [b".".to_vec(), b"..".to_vec()]);
    assert!(boot.directories.is_empty());
    assert_eq!(
        block_on(
            world
                .vfs
                .lookup(&cx, &boot.root, b"outside", LookupFlags::follow())
        )
        .err(),
        Some(wasixv2_vfs::PathError::NamespaceBoundary)
    );
    let foreign = World::new();
    let sources = vec![wasixv2_vfs::NamespaceDirectory {
        source: foreign
            .vfs
            .open_tree(foreign.vfs.namespace(), &foreign.root, true)
            .unwrap(),
        lookup_name: None,
    }];
    assert_eq!(
        world
            .vfs
            .bootstrap_namespace(
                world.vfs.namespace(),
                world.vfs.namespace().owner().clone(),
                &sources,
                None
            )
            .err(),
        Some(Errno::EINVAL)
    );
    let sources = vec![wasixv2_vfs::NamespaceDirectory {
        source: world.open(b"/outside", OpenFlags::O_RDONLY, true).unwrap(),
        lookup_name: None,
    }];
    assert_eq!(
        world
            .vfs
            .bootstrap_namespace(
                world.vfs.namespace(),
                world.vfs.namespace().owner().clone(),
                &sources,
                None
            )
            .err(),
        Some(Errno::EINVAL)
    );
    assert!(world.lookup(b"/outside", LookupFlags::follow()).is_ok());
}

#[test]
fn bootstrap_namespace_fallback_mutations_use_exact_relative_or_absolute_parents() {
    use wasixv2_vfs::PathError;
    let world = World::new();
    world.mkdir(b"/left").unwrap();
    world.mkdir(b"/left/named").unwrap();
    world.mkdir(b"/left/directory").unwrap();
    world.mkdir(b"/right").unwrap();
    let source = world.create(b"/left/file");
    assert_eq!(block_on(source.write_at(b"retained", 0)), Ok(8));
    let before = block_on(world.vfs.stat(&source.path)).unwrap();
    world.create(b"/right/marker");
    let boot = namespace(
        &world,
        &[(b"/left", None), (b"/right", Some(b"named"))],
        Some(0),
    )
    .unwrap();
    let cx = Ctx {
        root: &boot.root,
        ..world.cx()
    };
    let mutation = Err(PathError::NamespaceMutation);
    let how = OpenHow {
        flags: OpenFlags::O_CREAT | OpenFlags::O_RDWR,
        mode: 0o600,
        lookup: LookupFlags::follow(),
    };
    let existing = block_on(world.vfs.open(&cx, &boot.root, b"file", &how)).unwrap();
    assert_eq!(
        (existing.path.dentry.sb().id, existing.node().ino()),
        (source.path.dentry.sb().id, source.node().ino())
    );
    let mut bytes = [0; 8];
    assert_eq!(block_on(existing.read_at(&mut bytes, 0)), Ok(8));
    assert_eq!(&bytes, b"retained");
    let after = block_on(world.vfs.stat(&source.path)).unwrap();
    assert_eq!(
        (after.mode, after.size, after.nlink),
        (before.mode, before.size, before.nlink)
    );
    assert_eq!(
        block_on(world.vfs.open(&cx, &boot.root, b"not-created", &how)).err(),
        Some(PathError::NamespaceMutation)
    );
    assert_eq!(
        block_on(world.vfs.link(
            &cx,
            &boot.root,
            b"/file",
            LookupFlags::follow(),
            &boot.root,
            b"linked"
        )),
        mutation
    );
    block_on(world.vfs.link(
        &cx,
        &boot.root,
        b"/file",
        LookupFlags::follow(),
        &boot.root,
        b"/linked",
    ))
    .unwrap();
    assert_eq!(
        world
            .lookup(b"/left/file", LookupFlags::follow())
            .unwrap()
            .dentry
            .node()
            .ino(),
        world
            .lookup(b"/left/linked", LookupFlags::follow())
            .unwrap()
            .dentry
            .node()
            .ino()
    );
    assert_eq!(
        block_on(world.vfs.symlink(&cx, b"file", &boot.root, b"symbol")),
        mutation
    );
    block_on(world.vfs.symlink(&cx, b"file", &boot.root, b"/symbol")).unwrap();
    let original = block_on(
        world
            .vfs
            .lookup(&cx, &boot.root, b"/file", LookupFlags::follow()),
    )
    .unwrap();
    assert_eq!(
        block_on(
            world
                .vfs
                .lookup(&cx, &boot.root, b"/symbol", LookupFlags::follow())
        )
        .unwrap(),
        original
    );
    assert_eq!(
        block_on(world.vfs.rename(
            &cx,
            &boot.root,
            b"file",
            &boot.root,
            b"/moved",
            RenameMode::Replace
        )),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.rename(
            &cx,
            &boot.root,
            b"/file",
            &boot.root,
            b"moved",
            RenameMode::Replace
        )),
        mutation
    );
    block_on(world.vfs.rename(
        &cx,
        &boot.root,
        b"/file",
        &boot.root,
        b"/moved",
        RenameMode::Replace,
    ))
    .unwrap();
    assert!(world.lookup(b"/left/moved", LookupFlags::follow()).is_ok());
    assert_eq!(
        block_on(world.vfs.unlink(&cx, &boot.root, b"linked")),
        mutation
    );
    block_on(world.vfs.unlink(&cx, &boot.root, b"/linked")).unwrap();
    assert_eq!(
        block_on(world.vfs.rmdir(&cx, &boot.root, b"directory")),
        mutation
    );
    block_on(world.vfs.rmdir(&cx, &boot.root, b"/directory")).unwrap();
    assert_eq!(
        block_on(world.vfs.rmdir(&cx, &boot.root, b"named")),
        mutation
    );
    block_on(world.vfs.rmdir(&cx, &boot.root, b"/named")).unwrap();
    assert_eq!(
        block_on(
            world
                .vfs
                .lookup(&cx, &boot.root, b"/named", LookupFlags::follow())
        )
        .unwrap(),
        boot.directories[1]
    );
    block_on(world.vfs.mkdir(&cx, &boot.root, b"/named", 0o755)).unwrap();
    assert!(world.lookup(b"/left/named", LookupFlags::follow()).is_ok());
    assert!(
        block_on(
            world
                .vfs
                .lookup(&cx, &boot.root, b"/named/marker", LookupFlags::follow())
        )
        .is_ok()
    );
}

#[test]
fn bootstrap_namespace_preserves_intermediate_lookup_provenance_for_every_mutation_family() {
    use wasixv2_vfs::PathError;
    for fallback in [None, Some(0)] {
        let world = World::new();
        world.mkdir(b"/left").unwrap();
        world.mkdir(b"/right").unwrap();
        world.create(b"/right/file");
        let boot = namespace(
            &world,
            &[(b"/left", None), (b"/right", Some(b"named"))],
            fallback,
        )
        .unwrap();
        let cx = Ctx {
            root: &boot.root,
            ..world.cx()
        };
        for (path, expected) in [
            (
                b"outside/new".as_slice(),
                if fallback.is_some() {
                    PathError::Errno(Errno::ENOENT)
                } else {
                    PathError::NamespaceBoundary
                },
            ),
            (
                b"named/missing/new".as_slice(),
                PathError::Errno(Errno::ENOENT),
            ),
        ] {
            let how = OpenHow {
                flags: OpenFlags::O_CREAT | OpenFlags::O_RDWR,
                mode: 0o644,
                lookup: LookupFlags::follow(),
            };
            let results = [
                block_on(world.vfs.mkdir(&cx, &boot.root, path, 0o755)),
                block_on(world.vfs.mknod(
                    &cx,
                    &boot.root,
                    path,
                    wasixv2_vfs::FileType::Regular.mode_bits() | 0o644,
                    Default::default(),
                )),
                block_on(world.vfs.open(&cx, &boot.root, path, &how)).map(drop),
                block_on(world.vfs.rmdir(&cx, &boot.root, path)),
                block_on(world.vfs.unlink(&cx, &boot.root, path)),
                block_on(world.vfs.symlink(&cx, b"target", &boot.root, path)),
                block_on(world.vfs.link(
                    &cx,
                    &boot.root,
                    b"named/file",
                    LookupFlags::follow(),
                    &boot.root,
                    path,
                )),
                block_on(world.vfs.link(
                    &cx,
                    &boot.root,
                    path,
                    LookupFlags::follow(),
                    &boot.root,
                    b"named/new",
                )),
                block_on(world.vfs.rename(
                    &cx,
                    &boot.root,
                    b"named/file",
                    &boot.root,
                    path,
                    RenameMode::Replace,
                )),
                block_on(world.vfs.rename(
                    &cx,
                    &boot.root,
                    path,
                    &boot.root,
                    b"named/new",
                    RenameMode::Replace,
                )),
            ];
            for result in results {
                assert_eq!(result, Err(expected));
            }
        }
    }
}

#[test]
fn bootstrap_namespace_uses_real_mount_ancestry_and_unreachable_private_anchors() {
    use wasixv2_vfs::PathError;
    let world = World::new();
    world.mkdir(b"/left").unwrap();
    world.mkdir(b"/right").unwrap();
    world.mkdir(b"/left/nested").unwrap();
    world.create(b"/outside");
    world.create(b"/left/a");
    world.create(b"/right/b");
    world.symlink(b"../../outside", b"/left/escape");
    world.symlink(b"/outside", b"/left/absolute");
    let flags = MountFlags {
        read_only: true,
        noexec: true,
        ..MountFlags::default()
    };
    block_on(world.vfs.mount(
        b"/left/nested",
        Arc::new(MemFs::new(Arc::new(Epoch), 0o755, 1, 1)),
        flags,
        false,
    ))
    .unwrap();
    let boot = namespace(
        &world,
        &[(b"/left", None), (b"/right", Some(b"named"))],
        None,
    )
    .unwrap();
    let cx = Ctx {
        root: &boot.root,
        ..world.cx()
    };
    let lookup = |start: &Path, path: &[u8]| {
        block_on(world.vfs.lookup(&cx, start, path, LookupFlags::follow()))
    };
    assert_eq!(lookup(&boot.directories[0], b"..").unwrap(), boot.root);
    assert_eq!(lookup(&boot.directories[1], b"..").unwrap(), boot.root);
    assert_eq!(
        lookup(&boot.directories[0], b"../named").unwrap(),
        boot.directories[1]
    );
    for path in [
        b"outside".as_slice(),
        b"proc",
        b"dev",
        b"tmp",
        b"0",
        b"#0",
        b"left",
    ] {
        assert_eq!(
            lookup(&boot.root, path).err(),
            Some(PathError::NamespaceBoundary)
        );
    }
    for path in [b"../outside".as_slice(), b"escape", b"absolute"] {
        assert_eq!(
            lookup(&boot.directories[0], path).err(),
            Some(PathError::NamespaceBoundary)
        );
    }
    assert_eq!(
        lookup(&boot.directories[0], b"missing").err(),
        Some(PathError::Errno(Errno::ENOENT))
    );
    let nested = lookup(&boot.directories[0], b"nested").unwrap();
    assert!(nested.mnt.flags().read_only && nested.mnt.is_noexec());
    assert_eq!(lookup(&nested, b"../..").unwrap(), boot.root);
    let initial = world.lookup(b"/left", LookupFlags::follow()).unwrap();
    assert!(!Arc::ptr_eq(&initial.mnt, &boot.directories[0].mnt));
    let second = namespace(&world, &[(b"/right", Some(b"other"))], None).unwrap();
    let second_cx = Ctx {
        root: &second.root,
        ..world.cx()
    };
    assert_eq!(
        block_on(
            world
                .vfs
                .lookup(&second_cx, &second.root, b"named", LookupFlags::follow())
        )
        .err(),
        Some(PathError::NamespaceBoundary)
    );
    assert!(lookup(&boot.root, b"named/b").is_ok());
    assert!(world.lookup(b"/outside", LookupFlags::follow()).is_ok());
}

#[test]
fn bootstrap_namespace_fallback_keeps_full_and_parent_goals_distinct() {
    use wasixv2_vfs::PathError;
    let world = World::new();
    world.mkdir(b"/left").unwrap();
    world.mkdir(b"/right").unwrap();
    world.mkdir(b"/left/named").unwrap();
    world.create(b"/left/file");
    world.create(b"/right/right");
    world.symlink(b"/", b"/left/slash");
    world.symlink(b"/.", b"/left/dot");
    world.symlink(b"/..", b"/left/parent");
    world.symlink(b"..", b"/left/relative");
    let boot = namespace(
        &world,
        &[(b"/left", None), (b"/right", Some(b"named"))],
        Some(0),
    )
    .unwrap();
    let cx = Ctx {
        root: &boot.root,
        ..world.cx()
    };
    let lookup = |path: &[u8]| {
        block_on(
            world
                .vfs
                .lookup(&cx, &boot.root, path, LookupFlags::follow()),
        )
    };
    for path in [b"/".as_slice(), b"//", b"/slash", b"/dot"] {
        assert_eq!(lookup(path).unwrap(), boot.directories[0]);
    }
    for path in [b".".as_slice(), b"/.", b"/..", b"/parent", b"/relative"] {
        assert_eq!(lookup(path).unwrap(), boot.root);
    }
    assert_eq!(lookup(b"/named").unwrap(), boot.directories[1]);
    assert_eq!(
        lookup(b"missing").err(),
        Some(PathError::Errno(Errno::ENOENT))
    );
    assert_eq!(
        block_on(world.vfs.mkdir(&cx, &boot.root, b"new", 0o755)),
        Err(PathError::NamespaceMutation)
    );
    assert_eq!(
        block_on(world.vfs.mkdir(&cx, &boot.root, b"/./new", 0o755)),
        Err(PathError::NamespaceMutation)
    );
    block_on(world.vfs.mkdir(&cx, &boot.root, b"/new", 0o755)).unwrap();
    assert!(world.lookup(b"/left/new", LookupFlags::follow()).is_ok());
    assert_eq!(
        block_on(world.vfs.unlink(&cx, &boot.root, b"file")),
        Err(PathError::NamespaceMutation)
    );
    block_on(world.vfs.rename(
        &cx,
        &boot.root,
        b"/file",
        &boot.root,
        b"/moved",
        RenameMode::Replace,
    ))
    .unwrap();
    block_on(world.vfs.unlink(&cx, &boot.root, b"/moved")).unwrap();
    block_on(world.vfs.rmdir(&cx, &boot.root, b"/new")).unwrap();
    let how = OpenHow {
        flags: OpenFlags::O_CREAT | OpenFlags::O_RDWR,
        mode: 0o644,
        lookup: LookupFlags::follow(),
    };
    assert_eq!(
        block_on(world.vfs.open(&cx, &boot.root, b"relative-new", &how)).err(),
        Some(PathError::NamespaceMutation)
    );
    block_on(world.vfs.open(&cx, &boot.root, b"/absolute-new", &how)).unwrap();
    let mut copied_root = boot.root.clone();
    let copied = world.vfs.copy_mnt_ns(
        &boot.namespace,
        boot.namespace.owner().clone(),
        &mut [&mut copied_root],
    );
    let copied_cx = Ctx {
        root: &copied_root,
        ..world.cx()
    };
    let fallback = block_on(world.vfs.lookup(
        &copied_cx,
        &copied_root,
        b"/",
        LookupFlags::follow(),
    ))
    .unwrap();
    assert!(copied.contains(&fallback.mnt));
    assert!(!Arc::ptr_eq(&fallback.mnt, &boot.directories[0].mnt));
    assert!(Arc::ptr_eq(
        &fallback.mnt.parent().unwrap().mnt,
        &copied_root.mnt
    ));
    assert!(
        world
            .lookup(b"/left/absolute-new", LookupFlags::follow())
            .is_ok()
    );
}

#[test]
fn bootstrap_namespace_classifies_lookup_and_every_structural_mutation_separately() {
    use wasixv2_vfs::PathError;
    let world = World::new();
    world.mkdir(b"/grant").unwrap();
    world.create(b"/grant/file");
    let boot = namespace(&world, &[(b"/grant", Some(b"grant"))], None).unwrap();
    let cx = Ctx {
        root: &boot.root,
        ..world.cx()
    };
    let mutation = Err(PathError::NamespaceMutation);
    assert_eq!(
        block_on(world.vfs.mkdir(&cx, &boot.root, b"new", 0o755)),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.rmdir(&cx, &boot.root, b"grant")),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.unlink(&cx, &boot.root, b"grant")),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.symlink(&cx, b"grant/file", &boot.root, b"new")),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.link(
            &cx,
            &boot.root,
            b"grant/file",
            LookupFlags::follow(),
            &boot.root,
            b"new"
        )),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.rename(
            &cx,
            &boot.root,
            b"grant",
            &boot.root,
            b"new",
            RenameMode::Replace
        )),
        mutation
    );
    assert_eq!(
        block_on(world.vfs.mkdir(&cx, &boot.root, b"outside/new", 0o755)),
        Err(PathError::NamespaceBoundary)
    );
    assert_eq!(
        block_on(
            world
                .vfs
                .mkdir(&cx, &boot.root, b"grant/missing/new", 0o755)
        ),
        Err(PathError::Errno(Errno::ENOENT))
    );
    assert_eq!(
        namespace(
            &world,
            &[(b"/grant", Some(b"same")), (b"/grant", Some(b"same"))],
            None
        )
        .err(),
        Some(Errno::EEXIST)
    );
    assert_eq!(
        namespace(&world, &[(b"/grant", Some(b"slash/name"))], None).err(),
        Some(Errno::EINVAL)
    );
    assert_eq!(
        namespace(&world, &[(b"/grant", None)], Some(1)).err(),
        Some(Errno::EINVAL)
    );
}

#[test]
fn trailing_slashes_demand_directories() {
    let w = World::new();
    w.create(b"/f");
    w.mkdir(b"/d").unwrap();

    assert_eq!(
        w.lookup(b"/f/", LookupFlags::follow()).err(),
        Some(Errno::ENOTDIR)
    );
    assert!(w.lookup(b"/d//", LookupFlags::follow()).is_ok());
    assert_eq!(w.mkdir(b"/d/"), Err(Errno::EEXIST));
    assert_eq!(w.mkdir(b"/new/"), Ok(()));
    assert_eq!(
        w.open(b"/g/", OpenFlags::O_CREAT | OpenFlags::O_RDWR, true)
            .err(),
        Some(Errno::EISDIR)
    );
    assert_eq!(
        block_on(w.vfs.unlink(&w.cx(), &w.root, b"/f/")).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(
        block_on(w.vfs.rmdir(&w.cx(), &w.root, b"/d/.")).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EINVAL)
    );
}

#[test]
fn symlinks_resolve_in_the_middle_and_loop_out_at_forty() {
    let w = World::new();
    w.mkdir(b"/d").unwrap();
    w.create(b"/d/f");
    w.symlink(b"d", b"/l");
    w.symlink(b"/l/f", b"/abs");
    w.symlink(b"loop", b"/loop");
    w.symlink(b"missing", b"/dangling");

    assert!(w.lookup(b"/l/f", LookupFlags::nofollow()).is_ok());
    assert!(w.lookup(b"/abs", LookupFlags::follow()).is_ok());
    assert_eq!(
        w.lookup(b"/loop", LookupFlags::follow()).err(),
        Some(Errno::ELOOP)
    );
    // Not following the last component finds the link itself.
    assert!(w.lookup(b"/loop", LookupFlags::nofollow()).is_ok());
    // A trailing slash follows even without LOOKUP_FOLLOW.
    assert!(w.lookup(b"/l/", LookupFlags::nofollow()).is_ok());
    // O_CREAT through a dangling symlink creates its target; O_EXCL refuses.
    assert_eq!(
        w.open(
            b"/dangling",
            OpenFlags::O_CREAT | OpenFlags::O_EXCL | OpenFlags::O_RDWR,
            false
        )
        .err(),
        Some(Errno::EEXIST)
    );
    w.open(b"/dangling", OpenFlags::O_CREAT | OpenFlags::O_RDWR, true)
        .unwrap();
    assert!(w.lookup(b"/missing", LookupFlags::nofollow()).is_ok());
    assert_eq!(
        w.open(b"/l", OpenFlags::O_RDONLY, false).err(),
        Some(Errno::ELOOP)
    );
}

#[test]
fn resolve_beneath_and_in_root_scope_the_walk() {
    let w = World::new();
    w.mkdir(b"/jail").unwrap();
    w.mkdir(b"/jail/sub").unwrap();
    w.create(b"/secret");
    w.symlink(b"/secret", b"/jail/abs");
    let jail = w.lookup(b"/jail", LookupFlags::follow()).unwrap();
    let scoped = |path: &[u8], beneath: bool| {
        let flags = LookupFlags {
            follow: true,
            beneath,
            in_root: !beneath,
            ..LookupFlags::default()
        };
        block_on(w.vfs.lookup(&w.cx(), &jail, path, flags)).map_err(wasixv2_vfs::PathError::errno)
    };

    assert!(scoped(b"sub/..", true).is_ok());
    assert_eq!(scoped(b"..", true).err(), Some(Errno::EXDEV));
    assert_eq!(scoped(b"abs", true).err(), Some(Errno::EXDEV));
    // In-root: `..` and absolute targets stop at the jail.
    assert_eq!(scoped(b"../../secret", false).err(), Some(Errno::ENOENT));
    assert_eq!(scoped(b"abs", false).err(), Some(Errno::ENOENT));
    // An absolute path starts at the jail, which must be a directory (`path_init`).
    assert_eq!(scoped(b"/sub", false), scoped(b"sub", false));
    let file = w.lookup(b"/secret", LookupFlags::follow()).unwrap();
    let in_root = LookupFlags {
        in_root: true,
        ..LookupFlags::default()
    };
    let from_file = block_on(w.vfs.lookup(&w.cx(), &file, b"/", in_root))
        .map_err(wasixv2_vfs::PathError::errno);
    assert_eq!(from_file.err(), Some(Errno::ENOTDIR));
}

#[test]
fn permissions_apply_to_an_unprivileged_user() {
    let w = World::new();
    w.mkdir(b"/locked").unwrap();
    w.create(b"/locked/f");
    let locked = w.lookup(b"/locked", LookupFlags::follow()).unwrap();
    block_on(w.vfs.chmod(&w.cx(), &locked, 0o600)).unwrap();

    assert_eq!(
        w.lookup(b"/locked/f", LookupFlags::follow()).err(),
        Some(Errno::EACCES)
    );
    let other = Cred::user(2, 2);
    let cx = Ctx {
        cred: &other,
        root: &w.root,
        umask: 0,
        task: 0,
        leases: None,
    };
    assert_eq!(
        block_on(w.vfs.chmod(&cx, &locked, 0o777)),
        Err(Errno::EPERM)
    );
    assert_eq!(
        block_on(w.vfs.mkdir(&cx, &w.root, b"/x", 0o777)).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EACCES)
    );
}

#[test]
fn rename_rules_follow_linux() {
    let w = World::new();
    w.mkdir(b"/a").unwrap();
    w.mkdir(b"/a/b").unwrap();
    w.mkdir(b"/full").unwrap();
    w.create(b"/full/x");
    w.create(b"/f");
    let rename = |from: &[u8], to: &[u8], mode| {
        block_on(w.vfs.rename(&w.cx(), &w.root, from, &w.root, to, mode))
            .map_err(wasixv2_vfs::PathError::errno)
    };

    assert_eq!(
        rename(b"/a", b"/a/b/c", RenameMode::Replace),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        rename(b"/a/b", b"/a", RenameMode::Replace),
        Err(Errno::ENOTEMPTY)
    );
    assert_eq!(
        rename(b"/a", b"/full", RenameMode::Replace),
        Err(Errno::ENOTEMPTY)
    );
    assert_eq!(
        rename(b"/f", b"/a", RenameMode::Replace),
        Err(Errno::EISDIR)
    );
    assert_eq!(
        rename(b"/a", b"/f", RenameMode::Replace),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(
        rename(b"/f", b"/full/x", RenameMode::NoReplace),
        Err(Errno::EEXIST)
    );
    assert_eq!(rename(b"/f", b"/a", RenameMode::Exchange), Ok(()));
    assert!(w.lookup(b"/f/b", LookupFlags::follow()).is_ok());
    assert_eq!(
        rename(b"/nope", b"/x", RenameMode::Replace),
        Err(Errno::ENOENT)
    );
}

#[test]
fn unlinked_files_stay_readable_through_open_descriptors() {
    let w = World::new();
    let file = w.create(b"/f");
    block_on(file.write_at(b"still here", 0)).unwrap();

    block_on(w.vfs.unlink(&w.cx(), &w.root, b"/f"))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    let mut buf = [0; 10];
    let n = block_on(file.read_at(&mut buf, 0)).unwrap();

    assert_eq!(&buf[..n], b"still here");
    assert_eq!(block_on(w.vfs.stat(&file.path)).unwrap().nlink, 0);
    assert!(w.vfs.d_path(&file.path, &w.root).ends_with(b" (deleted)"));
}

#[test]
fn mounts_cover_their_mountpoint_and_dotdot_climbs_out() {
    let w = World::new();
    w.mkdir(b"/m").unwrap();
    w.create(b"/m/hidden");
    let fs = Arc::new(MemFs::new(Arc::new(Epoch), 0o755, 1, 1));
    block_on(w.vfs.mount(b"/m", fs, MountFlags::default(), false)).unwrap();
    w.create(b"/m/visible");

    assert_eq!(
        w.lookup(b"/m/hidden", LookupFlags::follow()).err(),
        Some(Errno::ENOENT)
    );
    let up = w.lookup(b"/m/..", LookupFlags::follow()).unwrap();
    assert!(up == w.root);
    let m = w.lookup(b"/m", LookupFlags::follow()).unwrap();
    assert_eq!(w.vfs.d_path(&m, &w.root), b"/m");
    assert_eq!(
        block_on(w.vfs.rmdir(&w.cx(), &w.root, b"/m")).map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EBUSY)
    );
    // Hard links cannot cross mounts.
    assert_eq!(
        block_on(w.vfs.link(
            &w.cx(),
            &w.root,
            b"/m/visible",
            LookupFlags::default(),
            &w.root,
            b"/v"
        ))
        .map_err(wasixv2_vfs::PathError::errno),
        Err(Errno::EXDEV)
    );
}

#[test]
fn hard_links_share_one_inode() {
    let w = World::new();
    w.create(b"/a");
    block_on(w.vfs.link(
        &w.cx(),
        &w.root,
        b"/a",
        LookupFlags::default(),
        &w.root,
        b"/b",
    ))
    .map_err(wasixv2_vfs::PathError::errno)
    .unwrap();

    let a = w.lookup(b"/a", LookupFlags::default()).unwrap();
    let b = w.lookup(b"/b", LookupFlags::default()).unwrap();
    assert!(!Arc::ptr_eq(&a.dentry, &b.dentry));
    assert!(Arc::ptr_eq(a.dentry.inode(), b.dentry.inode()));
}

#[test]
fn only_tmpfiles_can_be_linked_back_from_nothing() {
    let w = World::new();
    let link_fd = |file: &File, to: &[u8]| {
        let flags = LookupFlags {
            empty: true,
            ..LookupFlags::default()
        };
        block_on(w.vfs.link(&w.cx(), &file.path, b"", flags, &w.root, to))
            .map_err(wasixv2_vfs::PathError::errno)
    };

    // A deleted file stays deleted (`I_LINKABLE` is not set).
    let deleted = w.create(b"/f");
    block_on(w.vfs.unlink(&w.cx(), &w.root, b"/f"))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(link_fd(&deleted, b"/back"), Err(Errno::ENOENT));

    // An O_TMPFILE file gets a name once; O_EXCL makes it unlinkable.
    let tmp = OpenFlags::__O_TMPFILE | OpenFlags::O_DIRECTORY | OpenFlags::O_RDWR;
    let file = w.open(b"/", tmp, true).unwrap();
    assert_eq!(link_fd(&file, b"/named"), Ok(()));
    block_on(w.vfs.unlink(&w.cx(), &w.root, b"/named"))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    assert_eq!(link_fd(&file, b"/again"), Err(Errno::ENOENT));
    let excl = w.open(b"/", tmp | OpenFlags::O_EXCL, true).unwrap();
    assert_eq!(link_fd(&excl, b"/excl"), Err(Errno::ENOENT));
}

#[test]
fn nothing_is_created_in_a_removed_or_replaced_directory() {
    let w = World::new();
    w.mkdir(b"/gone").unwrap();
    w.mkdir(b"/src").unwrap();
    w.mkdir(b"/dst").unwrap();
    let gone = w.lookup(b"/gone", LookupFlags::default()).unwrap();
    let replaced = w.lookup(b"/dst", LookupFlags::default()).unwrap();

    block_on(w.vfs.rmdir(&w.cx(), &w.root, b"/gone"))
        .map_err(wasixv2_vfs::PathError::errno)
        .unwrap();
    block_on(w.vfs.rename(
        &w.cx(),
        &w.root,
        b"/src",
        &w.root,
        b"/dst",
        RenameMode::Replace,
    ))
    .map_err(wasixv2_vfs::PathError::errno)
    .unwrap();

    for dir in [&gone, &replaced] {
        assert_eq!(
            block_on(w.vfs.mkdir(&w.cx(), dir, b"x", 0o755)).map_err(wasixv2_vfs::PathError::errno),
            Err(Errno::ENOENT)
        );
        assert!(w.vfs.d_path(dir, &w.root).ends_with(b" (deleted)"));
    }
    // The new /dst is the old /src and is usable.
    assert_eq!(w.mkdir(b"/dst/x"), Ok(()));
}

#[test]
fn every_filesystem_has_its_own_device() {
    let w = World::new();
    w.mkdir(b"/m").unwrap();
    let fs = Arc::new(MemFs::new(Arc::new(Epoch), 0o755, 1, 1));
    block_on(w.vfs.mount(b"/m", fs, MountFlags::default(), false)).unwrap();

    let stat = |path: &[u8]| {
        let path = w.lookup(path, LookupFlags::default()).unwrap();
        block_on(w.vfs.stat(&path)).unwrap()
    };
    let (root, m) = (stat(b"/"), stat(b"/m"));
    assert_eq!(root.dev.unwrap().major, 0);
    assert_ne!(root.dev, m.dev);
    // Both roots have the same inode number; the device tells them apart.
    assert_eq!(root.ino, m.ino);
}

#[test]
fn exchanged_directories_both_stay_live() {
    let w = World::new();
    w.mkdir(b"/a").unwrap();
    w.mkdir(b"/b").unwrap();
    let cwd = w.lookup(b"/a", LookupFlags::default()).unwrap();

    block_on(w.vfs.rename(
        &w.cx(),
        &w.root,
        b"/a",
        &w.root,
        b"/b",
        RenameMode::Exchange,
    ))
    .map_err(wasixv2_vfs::PathError::errno)
    .unwrap();

    // `getcwd` in the moved directory, and creating in it, work as on Linux.
    assert_eq!(w.vfs.d_path(&cwd, &w.root), b"/b");
    assert_eq!(
        block_on(w.vfs.mkdir(&w.cx(), &cwd, b"x", 0o755)).map_err(wasixv2_vfs::PathError::errno),
        Ok(())
    );
    let other = w.lookup(b"/a", LookupFlags::default()).unwrap();
    assert_eq!(w.vfs.d_path(&other, &w.root), b"/a");
    assert!(w.lookup(b"/b/x", LookupFlags::default()).is_ok());
}

#[test]
fn chown_to_the_current_ids_needs_ownership() {
    let w = World::new();
    w.create(b"/f");
    let f = w.lookup(b"/f", LookupFlags::default()).unwrap();
    let other = Cred::user(2, 2);
    let cx = Ctx {
        cred: &other,
        root: &w.root,
        umask: 0o022,
        task: 0,
        leases: None,
    };

    assert_eq!(
        block_on(w.vfs.chown(&cx, &f, Some(1), None)),
        Err(Errno::EPERM)
    );
    assert_eq!(
        block_on(w.vfs.chown(&cx, &f, None, Some(1))),
        Err(Errno::EPERM)
    );
    assert_eq!(block_on(w.vfs.chown(&w.cx(), &f, Some(1), Some(1))), Ok(()));
}

#[test]
fn fifos_open_for_writing_on_read_only_mounts() {
    let w = World::new();
    w.mkdir(b"/d").unwrap();
    block_on(w.vfs.mknod(
        &w.cx(),
        &w.root,
        b"/d/fifo",
        0o010_644,
        wasixv2_vfs::Device::default(),
    ))
    .map_err(wasixv2_vfs::PathError::errno)
    .unwrap();
    w.mkdir(b"/ro").unwrap();
    let read_only = MountFlags {
        read_only: true,
        ..MountFlags::default()
    };
    block_on(w.vfs.bind_mount(b"/d", b"/ro", read_only, false)).unwrap();

    assert!(w.open(b"/ro/fifo", OpenFlags::O_WRONLY, true).is_ok());
    w.create(b"/d/file");
    assert_eq!(
        w.open(b"/ro/file", OpenFlags::O_WRONLY, true).err(),
        Some(Errno::EROFS)
    );
}

/// A filesystem whose root holds one empty directory, `p`, whose lookup waits until `open` is
/// set: a walk can be stopped inside it.
struct GateFs {
    root: Arc<GateNode>,
}

struct GateNode {
    ino: u64,
    open: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait(?Send)]
impl wasixv2_vfs::Filesystem for GateFs {
    fn info(&self) -> wasixv2_vfs::FsInfo {
        wasixv2_vfs::FsInfo {
            name: "gate",
            magic: 0,
            name_max: 255,
            read_only: false,
            dev: None,
            has_btime: false,
            stable: false,
        }
    }

    fn root(&self) -> Arc<dyn wasixv2_vfs::Node> {
        self.root.clone()
    }

    async fn statfs(&self) -> Result<wasixv2_vfs::StatFs, Errno> {
        Ok(Default::default())
    }
}

#[async_trait::async_trait(?Send)]
impl wasixv2_vfs::Node for GateNode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn file_type(&self) -> wasixv2_vfs::FileType {
        wasixv2_vfs::FileType::Directory
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn getattr(&self) -> Result<wasixv2_vfs::Attr, Errno> {
        Ok(wasixv2_vfs::Attr {
            ino: self.ino,
            file_type: wasixv2_vfs::FileType::Directory,
            mode: 0o755,
            nlink: 2,
            uid: 1,
            gid: 1,
            rdev: Default::default(),
            size: 0,
            blocks: 0,
            blksize: 4096,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
            btime: None,
            dev: None,
        })
    }

    async fn setattr(&self, _: &wasixv2_vfs::SetAttr) -> Result<wasixv2_vfs::Attr, Errno> {
        Err(Errno::EPERM)
    }

    async fn lookup(&self, name: &[u8]) -> Result<Arc<dyn wasixv2_vfs::Node>, Errno> {
        if self.ino != 1 || name != b"p" {
            return Err(Errno::ENOENT);
        }
        futures::future::poll_fn(
            |_| match self.open.load(std::sync::atomic::Ordering::SeqCst) {
                true => std::task::Poll::Ready(()),
                false => std::task::Poll::Pending,
            },
        )
        .await;
        Ok(Arc::new(GateNode {
            ino: 2,
            open: self.open.clone(),
        }))
    }

    async fn open(
        &self,
        _: wasixv2_vfs::OpenOptions,
    ) -> Result<Box<dyn wasixv2_vfs::Handle>, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
}

/// `openat2(jail, "a/m/p/../../../../x", RESOLVE_IN_ROOT)` while `a` is renamed out of the
/// jail after the walk entered it: `..` would climb to the real `/x`, so the walk fails with
/// `EAGAIN`, as Linux's does when `rename_lock` changed.
#[test]
fn a_rename_during_a_scoped_walk_makes_dotdot_fail_with_eagain() {
    use std::{
        future::Future,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };

    let w = World::new();
    for dir in [&b"/jail"[..], b"/jail/a", b"/jail/a/m", b"/elsewhere"] {
        w.mkdir(dir).unwrap();
    }
    w.create(b"/x");
    let open = Arc::new(AtomicBool::new(false));
    let gate = GateFs {
        root: Arc::new(GateNode {
            ino: 1,
            open: open.clone(),
        }),
    };
    block_on(
        w.vfs
            .mount(b"/jail/a/m", Arc::new(gate), MountFlags::default(), false),
    )
    .unwrap();
    let jail = w.lookup(b"/jail", LookupFlags::default()).unwrap();
    let flags = LookupFlags {
        follow: true,
        in_root: true,
        ..LookupFlags::default()
    };

    let cx = w.cx();
    let mut walk = std::pin::pin!(w.vfs.lookup(&cx, &jail, b"a/m/p/../../../../x", flags));
    let mut poll = || {
        let waker = futures::task::noop_waker();
        walk.as_mut().poll(&mut Context::from_waker(&waker))
    };
    assert!(poll().is_pending());
    block_on(w.vfs.rename(
        &w.cx(),
        &w.root,
        b"/jail/a",
        &w.root,
        b"/elsewhere/a",
        RenameMode::Replace,
    ))
    .map_err(wasixv2_vfs::PathError::errno)
    .unwrap();
    open.store(true, Ordering::SeqCst);

    assert!(matches!(
        poll(),
        Poll::Ready(Err(wasixv2_vfs::PathError::Errno(Errno::EAGAIN)))
    ));
}

/// include/linux/fs.h get_write_access/deny_write_access: positive writers and negative
/// executable users exclude each other across opens and path truncation.
#[test]
fn executable_write_denials_exclude_writers_and_truncation() {
    let w = World::new();
    let writer = w.create(b"/prog");
    let inode = writer.path.dentry.inode().clone();
    assert!(matches!(inode.deny_write_access(), Err(Errno::ETXTBSY)));
    drop(writer);
    let exec = inode.deny_write_access().unwrap();
    let other = inode.deny_write_access().unwrap();
    for flags in [
        OpenFlags::O_WRONLY,
        OpenFlags::O_RDWR,
        OpenFlags::O_RDONLY | OpenFlags::O_TRUNC,
    ] {
        assert_eq!(w.open(b"/prog", flags, true).err(), Some(Errno::ETXTBSY));
    }
    let path = w.lookup(b"/prog", LookupFlags::follow()).unwrap();
    assert_eq!(
        block_on(w.vfs.truncate(&w.cx(), &path, 0)),
        Err(Errno::ETXTBSY)
    );
    assert!(w.open(b"/prog", OpenFlags::O_RDONLY, true).is_ok());
    drop(exec);
    assert_eq!(
        w.open(b"/prog", OpenFlags::O_WRONLY, true).err(),
        Some(Errno::ETXTBSY)
    );
    drop(other);
    assert!(w.open(b"/prog", OpenFlags::O_WRONLY, true).is_ok());
    assert_eq!(block_on(w.vfs.truncate(&w.cx(), &path, 0)), Ok(()));
}
