# Native runner fixtures

The freestanding C sources are x86_64 Linux programs with a tiny `_start` and raw syscalls. They build without a C library. The Rust integration suite rebuilds these ignored ELF artifacts with `CC` (default `gcc`) and runs each guest under a timeout that also kills its process group if a ptrace tracee hangs.

All generated binaries, Nix links, dynamic fixture trees, and temporary download files are ignored by this directory's `.gitignore`; only source, scripts, and documentation are tracked. To download the optional static Bash and BusyBox binaries into this directory (or another output directory), run:

```sh
crates/native/tests/fixtures/download-fixtures.sh
# Or: crates/native/tests/fixtures/download-fixtures.sh /tmp/wlk-native-fixtures
```

The downloader requires Nix and `sha256sum`. It fetches the pinned x86_64 musl outputs directly from the signed `cache.nixos.org` binary cache with `nix copy`; it does not evaluate or build packages. The store paths, NAR hashes, and executable SHA256 checksums are pinned in the script. If the cache does not have those paths, the script fails without changing installed fixture binaries. The `build-bash.sh` and `build-busybox.sh` scripts remain available for local Nix builds.

`process_groups.c` checks virtual process-group and session IDs and verifies Linux's `EPERM` result for `setpgid` on the session-leader root process. `tty_ioctl.c` checks `ENOTTY` for a terminal-group ioctl on stream stdin, `EBADF` after closing stdin, and `EBADF` for an unknown ioctl request on an invalid descriptor.

`fd_ops.c` checks `fcntl` descriptor flags, shared offsets across `dup`/`dup2`/`dup3`, same-descriptor `dup2`, and Linux's `EINVAL`/`EBADF` cases. The optional static Bash fixture exercises shell redirections (`>`, `>>`, `<`, `2>&1`), descriptor restoration, shared open-file-description offsets, pipelines, and command substitution using the static BusyBox fixture rather than a host command lookup.

`file_mmap.c` checks that a one-byte private mapping exposes file bytes beyond the requested length within its rounded page, survives descriptor close, and allows private writes without changing the backing file. It also checks zero-length `mmap` (`EINVAL`) and anonymous mmap with the zero-extended Linux `fd=-1` value. `file_mmap_shared.c` keeps the separate `MAP_SHARED`-unsupported regression.

`libc_smoke.c` is a normal `main`-based program using musl's C library for argv, `printf`, `getpid`, and file I/O. Set `MUSL_CC` to an x86_64 musl compiler to build and run it; it is automatically tested when one is available. The same build adds static musl probes for pthread create/join, fork/wait with virtual child IDs and inherited file offsets, fork/exec of BusyBox, TCP and UDP echo to a host-loopback server through the guest gateway (`10.0.2.2`), and writable/read-only host volume mappings.

For broader local acceptance coverage, the static x86_64 musl BusyBox binary is optional and is neither downloaded nor built by CI. Run:

```sh
crates/native/tests/fixtures/download-fixtures.sh
cargo test -p wlk-native --test smoke --locked static_busybox_echo_and_cat_run_when_the_fixture_is_built
```

The BusyBox tests exercise `echo`, `cat`, `ls`, `mkdir`, `touch`, `rm`, and `rmdir` through WLK. The raw `dynamic` fixture has a `PT_INTERP` but no usable interpreter in an isolated guest root; it checks the missing-interpreter error path.

`build-dynamic.sh` builds normal dynamically linked glibc fixtures with `gcc` (or `DYNAMIC_CC`) and musl fixtures with `DYNAMIC_CC` set to the musl cross-compiler. Its output goes under ignored `dynamic-libs/` so it does not conflict with the raw `dynamic` fixture above. The smoke executable depends on `libdynamic_middle.so`, which depends on `libdynamic_leaf.so` through `$ORIGIN` runpaths. It checks constructor order, `dlopen`/`dlsym`/`dlclose`, pthread TLS isolation, and a plugin destructor. The integration suite stages interpreter/runtime libraries into an isolated `--root`, then checks application DSOs loaded from both the root and a read-only `--volume`. Set `MUSL_CC` to build the musl dynamic variant and static exec/fork parents during `cargo test`.
