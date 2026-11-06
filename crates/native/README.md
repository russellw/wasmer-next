# WLK Native Runner

`wlk-native` is a Linux x86_64 proof of concept that runs static and dynamically linked Linux ELF programs with WLK handling selected syscalls. It needs no root privileges, cgroups, or namespaces. It uses a seccomp filter with ptrace mediation for guest tasks.

See [TODO.md](TODO.md) for known implementation limitations and follow-up work.

```sh
cargo run -p wlk-native -- [--trace] [--root DIR] [--volume HOST:GUEST[:ro]]... PROGRAM [ARGS...]
```

For example:

```sh
cargo run -p wlk-native -- --trace /path/to/busybox echo hello
```

Download the optional static x86_64 musl Bash and BusyBox fixtures:

```sh
crates/native/tests/fixtures/download-fixtures.sh
```

The script requires Nix and `sha256sum`. It copies pinned, signed static binaries from `cache.nixos.org` with `nix copy` (download only; no local package build), verifies the pinned NAR and executable SHA256 hashes, and atomically installs them under `crates/native/tests/fixtures/`. Pass a directory argument to install them elsewhere. The per-fixture README documents the pins; local Nix build scripts are also provided.

Map a host directory into the guest with repeatable `--volume` options:

```sh
mkdir -p /tmp/wlk-native-root /tmp/wlk-native-data
cargo run -p wlk-native -- \
  --root /tmp/wlk-native-root \
  --volume /tmp/wlk-native-data:/data:ro \
  "$PWD/crates/native/tests/fixtures/busybox" ls -l /data
```

`--trace` prints the syscalls routed through WLK. By default, `/` is the guest filesystem root; `--root DIR` maps another host directory as that root. `--volume HOST:GUEST` adds a writable host directory; append `:ro` for a read-only mount. The current working directory is inherited within the selected root when possible, otherwise the guest starts at `/`. Standard input, output, and error are inherited. For a dynamically linked program, place the host `PROGRAM` path under the selected root or a volume so it maps to a guest path; its interpreter and shared libraries are then resolved through WLK in that filesystem view. Static initial programs may be supplied by an absolute host path.

This is a narrow proof of concept, not a general Linux compatibility layer. It accepts 64-bit little-endian x86_64 ELF images with or without `PT_INTERP` and shared-library dependencies. The system's musl or glibc loader handles relocations; WLK resolves the executable, interpreter, and tested shared libraries from the guest root or a volume. The tested dynamic subset covers transitive `$ORIGIN` dependencies, constructors, `dlopen`/`dlsym`/`dlclose`, pthread TLS, and exec/fork into a dynamic image.

WLK handles the tested filesystem operations: create/open, read/write, vectored I/O, seek, stat, directory listing, mkdir/rmdir, rename, unlink, symlink/readlink, access, timestamps, and permissions. It also handles process identity, pthread create/join, ordinary fork/wait, exec, and TCP/UDP socket calls. Anonymous memory setup, protection changes, signal setup, and TLS operations needed during native startup pass through to Linux. File-backed `MAP_PRIVATE` mappings are copied from WLK-owned descriptors into private native pages; changes to the backing file after mapping are not reflected, and truncation/SIGBUS behavior is not reproduced. File-backed `MAP_SHARED` mappings return `ENOSYS`. Unsupported syscalls return `ENOSYS`; vfork and unusual clone variants are unavailable, and exec is limited to single-threaded guests.

Guest TCP/UDP clients reach host-loopback services through `10.0.2.2`. Guest listeners bound to wildcard or non-loopback addresses are published on host `127.0.0.1` at the same port; listeners bound only to guest `127.0.0.1` remain private.

## Smoke tests

The integration tests compile ELF fixtures and run each program with a timeout. Raw syscall fixtures cover anonymous mappings, private file mappings after descriptor close, zero-length `mmap` errors, and rejection of shared file mappings. They also cover virtual process-group calls, `ioctl` errors, and `dup`/`dup2`/`dup3`/`fcntl` behavior including shared file offsets. With a static musl compiler, they test pthread create/join, fork/wait and inherited file offsets, static and dynamic exec, filesystem lifecycle and directory listing, read-only host volumes, and host-loopback TCP/UDP echo. Dynamic glibc and musl fixtures cover shared-library loading, constructors, `$ORIGIN`, `dlopen`/`dlsym`/`dlclose`, pthread TLS, isolated roots and volumes, fork/exec, missing dependencies, and a guest root with a missing interpreter. Other cases cover argv and exit status, virtual `getpid`, invalid pointers, and unsupported calls.

To run the libc-backed case using nixpkgs' x86_64 musl compiler:

```sh
nix --extra-experimental-features 'nix-command flakes' shell \
  'nixpkgs#pkgsCross.musl64.stdenv.cc' -c env \
  CC=x86_64-unknown-linux-musl-gcc \
  MUSL_CC=x86_64-unknown-linux-musl-gcc \
  cargo test -p wlk-native --test smoke --locked
```

To run the dynamic loader matrix, the same command builds both dynamic fixture variants, runs glibc tests with the host `gcc`, and enables musl tests with nixpkgs' musl compiler:

```sh
nix --extra-experimental-features 'nix-command flakes' shell \
  'nixpkgs#pkgsCross.musl64.stdenv.cc' -c env \
  CC=x86_64-unknown-linux-musl-gcc \
  MUSL_CC=x86_64-unknown-linux-musl-gcc \
  cargo test -p wlk-native --test smoke --locked dynamic_ -- --nocapture
```

Build and run the glibc fixture directly using the default guest root:

```sh
crates/native/tests/fixtures/build-dynamic.sh
cargo run -p wlk-native -- --trace \
  "$PWD/crates/native/tests/fixtures/dynamic-libs/glibc/bin/dynamic_smoke"
```

The root/volume integration case builds a temporary guest root containing the fixture interpreter and libc runtime files at their guest absolute paths, then mounts the application and custom DSOs at `/opt/wlk`. Run it with:

```sh
cargo test -p wlk-native --test smoke --locked \
  dynamic_glibc_loader_and_libraries_resolve_from_guest_root_and_volume -- --nocapture
```

For optional local BusyBox and Bash acceptance tests, download both static musl fixtures and rerun the smoke suite. This step is not part of CI:

```sh
crates/native/tests/fixtures/download-fixtures.sh
cargo test -p wlk-native --test smoke --locked
```

These tests run BusyBox `echo`, `cat`, `ls`, `mkdir`, `touch`, `rm`, and `rmdir` through WLK and the mapped host volume. When Bash and BusyBox fixtures are present, they also test `>`, `>>`, `<`, `2>&1`, restoring stdout after a builtin, shared offsets across duplicated file descriptors, pipelines, and command substitution.

To run BusyBox directly after building it, prepare a writable host directory and invoke its absolute fixture path:

```sh
mkdir -p /tmp/wlk-native-root /tmp/wlk-native-data
printf 'hello from the host volume\n' > /tmp/wlk-native-data/example.txt
cargo run -p wlk-native -- \
  --root /tmp/wlk-native-root \
  --volume /tmp/wlk-native-data:/data:ro \
  "$PWD/crates/native/tests/fixtures/busybox" ls -l /data
cargo run -p wlk-native -- \
  --root /tmp/wlk-native-root \
  --volume /tmp/wlk-native-data:/data:ro \
  "$PWD/crates/native/tests/fixtures/busybox" cat /data/example.txt
```

## Manual Bash process probe

Download a static x86_64 musl Bash binary. The fixture is installed at `crates/native/tests/fixtures/bash`:

```sh
crates/native/tests/fixtures/download-fixtures.sh
```

This command checks a builtin, a subshell, a background child with `wait`, and an external static BusyBox command under the native runner:

```sh
bash_bin="$PWD/crates/native/tests/fixtures/bash"
busybox_bin="$PWD/crates/native/tests/fixtures/busybox"
cargo run -p wlk-native -- --trace "$bash_bin" --noprofile --norc -c '
printf "bash builtin\\n"
(printf "subshell pid=%s\\n" "$BASHPID")
(printf "child pid=%s\\n" "$BASHPID") & child=$!
wait "$child"
printf "before external command\\n"
"$1" echo "external BusyBox"
printf "after external command\\n"
' bash "$busybox_bin"
```

For an interactive prompt on a PTY, force interactive mode:

```sh
cargo run -p wlk-native -- "$PWD/crates/native/tests/fixtures/bash" --noprofile --norc -i
```

WLK Native does not provide full controlling-terminal or job-control semantics. Bash can print `no job control in this shell` while still showing a prompt and accepting commands. Adding `+m` before or after `-i` does not skip Bash's startup job-control initialization. `fg`/`bg`, Ctrl-Z job control, and Readline terminal editing are unavailable or unverified. Automatic interactive detection without `-i` is not guaranteed.
