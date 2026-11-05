# Wasmer Lightweight Kernel (WLK)

This private repository contains the engine-independent WASIX kernel, syscall interfaces, host services, and filesystem/network drivers used by Wasmer. The Rust package names and public APIs are kept stable across the repository extraction. Wasmer runtime integration remains in the main Wasmer repository.

## Workspace

The workspace contains 21 crates under `crates/`:

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

The kernel uses engine-free capability traits. Host implementations provide clocks, timers, randomness, standard I/O, task execution, and platform-specific drivers. Engine-specific imports, Store and Instance ownership, guest memory access, and runtime control stay in Wasmer.

See [PROVENANCE.md](PROVENANCE.md) for the source revision and extraction boundary.

## Build

Install Rust 1.96 through rustup. Common checks are:

```sh
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D clippy::all
cargo nextest run --workspace --locked
cargo check -p wasixv2-host --features tokio --locked
rustup target add wasm32-unknown-unknown
cargo check -p wasixv2-host --features browser --target wasm32-unknown-unknown --locked
```

The repository CI runs formatting, native check and lint, Rust and browser protocol tests, a dependency-boundary check, security audit, and supported wasm32 checks. The browser worker/TLS integration recipe requires its pinned nightly, Rust source, Node, Chromium, and a matching `wasm-bindgen` CLI; see [the host browser test guide](crates/host/tests/browser/README.md).

This repository is private and is consumed from Wasmer at a pinned Git revision. The crates are currently workspace packages and are not independently published.
