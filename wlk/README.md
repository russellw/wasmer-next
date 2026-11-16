# Wasmer Lightweight Kernel (WLK)

This private repository contains the engine-independent WASIX kernel, syscall interfaces, host services, and filesystem/network drivers used by Wasmer. The Rust package names and public APIs are kept stable across the repository extraction. Wasmer runtime integration remains in the main Wasmer repository.

## Workspace

The workspace contains 22 crates under `crates/`:

| Crate | Description |
| --- | --- |
| [wasixv2-abi](crates/abi) | Guest-visible WASIX constants, errno values, flags, and struct layouts. |
| [wasixv2-syscalls](crates/syscalls) | Syscall traits, typed calls, layering, and guest-memory interfaces. |
| [wasixv2-wait](crates/wait) | Poll masks, wait queues, and blocking readiness waits. |
| [wasixv2-pages](crates/pages) | Shared host-memory objects mapped into multiple processes. |
| [wasixv2-host](crates/host) | Host traits and native/browser services for execution, clocks, timers, entropy, and shared memory. |
| [wasixv2-kernel](crates/kernel) | WASIX syscall implementation for processes, memory, files, signals, and sockets. |
| [wasixv2-vfs](crates/vfs) | VFS path, mount, permission, and file semantics with filesystem driver interfaces. |
| [wasixv2-vfs-mem](crates/vfs-mem) | Writable in-memory filesystem driver with sparse files and quotas. |
| [wasixv2-vfs-host](crates/vfs-host) | Host-directory passthrough filesystem driver with mapped-directory containment. |
| [wasixv2-vfs-overlay](crates/vfs-overlay) | Overlay filesystem driver combining writable and lower filesystem trees. |
| [wasixv2-vfs-package](crates/vfs-package) | Read-only WebC package filesystem driver. |
| [wasixv2-vfs-web](crates/vfs-web) | Browser directory providers implementing the VFS driver interfaces. |
| [wasixv2-vnet](crates/vnet) | Socket-level networking, namespace ports and routes, in-memory sockets, and backend interfaces. |
| [wasixv2-vnet-host](crates/vnet-host) | Unix host-socket backend for outbound connections and published guest listeners. |
| [wasixv2-vnet-switch](crates/vnet-switch) | In-runtime socket switch for machine-to-machine traffic and socket publication. |
| [wasixv2-vnet-web](crates/vnet-web) | Browser socket backend with bounded queues and frame transports. |
| [wasixv2-stdio-web](crates/stdio-web) | Bounded browser stdin, stdout, and stderr transports with session lifecycle. |
| [wasixv2-trace](crates/trace) | Syscall tracing layer that emits each call and its result. |
| [wasixv2-record](crates/record) | Placeholder for syscall recording, guest-memory write capture, and replay. |
| [wasixv2-policy](crates/policy) | Placeholder for syscall filtering and embedder policy enforcement. |
| [wasixv2-checkpoint](crates/checkpoint) | Placeholder for serializing kernel state and guest memory for checkpoint/restore. |
| [wlk-native](crates/native) | Linux x86_64 ELF runner with seccomp/ptrace, WLK filesystem, process, volume, and socket bridges. |

The kernel uses engine-free capability traits. Host implementations provide clocks, timers, randomness, standard I/O, task execution, and platform-specific drivers. Engine-specific imports, Store and Instance ownership, guest memory access, and runtime control stay in Wasmer.

The Linux-only `wlk-native` binary runs selected static and dynamically linked x86_64 Linux programs through WLK. It uses unprivileged seccomp and ptrace, creates no namespaces or cgroups, supports repeatable host volume mappings, and resolves dynamic interpreters and libraries through WLK. See [crates/native/README.md](crates/native/README.md) for tested behavior and syscall limits, and [crates/native/TODO.md](crates/native/TODO.md) for follow-up work.

The host crate's optional `terminal` feature provides owned native-terminal handles and
shared raw-mode leases without an engine or async runtime. The Wasmer facade owns the
process-stdio and Console routing policy. Native terminal support targets Linux and
macOS 13 or later. The inherited-terminal profile uses Linux `TIOCGDEV` to unify direct
and `/dev/tty` descriptors; independently mounted devpts instances that reuse device
numbers are outside its process-wide identity domain. macOS `/dev/tty` handles are
reopened as verified canonical endpoints, with the original access mode, because XNU
resolves that alias against the calling process on each operation. See the source
contracts in [Linux tty_io.c](https://github.com/torvalds/linux/blob/master/drivers/tty/tty_io.c),
[XNU tty_tty.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/tty_tty.c),
and [XNU proc_info.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c).
CI runs the terminal regressions and strict Clippy with default features disabled on
Linux and macOS, using a macOS deployment target of 13.0. A newer macOS CI runner
does not by itself establish execution coverage on macOS 13.

See [PROVENANCE.md](PROVENANCE.md) for the source revision and extraction boundary.

## Build

Install Rust 1.96 through rustup. Common checks are:

```sh
cargo check --workspace --locked
cargo test -p wlk-native --test smoke --locked
cargo run -p wlk-native -- --help
cargo clippy --workspace --all-targets --locked -- -D clippy::all
cargo nextest run --workspace --locked
cargo check -p wasixv2-host --features tokio --locked
rustup target add wasm32-unknown-unknown
cargo check -p wasixv2-host --features browser --target wasm32-unknown-unknown --locked
```

The repository CI runs formatting, native check and lint, Rust and browser protocol tests, a dependency-boundary check, security audit, and supported wasm32 checks. The browser worker/TLS integration recipe requires its pinned nightly, Rust source, Node, Chromium, and a matching `wasm-bindgen` CLI; see [the host browser test guide](crates/host/tests/browser/README.md).

This repository is private and is consumed from Wasmer at a pinned Git revision. The crates are currently workspace packages and are not independently published.
