# Wasmer Kernel Library

This private repository contains the engine-independent WASIX kernel, syscall interfaces, host services, and filesystem/network drivers used by Wasmer. The Rust package names and public APIs are kept stable across the repository extraction. Wasmer runtime integration remains in the main Wasmer repository.

## Workspace

The workspace contains 21 crates under `crates/`: `wasixv2-abi`, `wasixv2-syscalls`, `wasixv2-wait`, `wasixv2-pages`, `wasixv2-host`, `wasixv2-kernel`, the `wasixv2-vfs*` and `wasixv2-vnet*` drivers, `wasixv2-stdio-web`, `wasixv2-trace`, `wasixv2-record`, `wasixv2-policy`, and `wasixv2-checkpoint`.

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
