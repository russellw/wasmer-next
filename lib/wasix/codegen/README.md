# wasixv2-abi

The wasixv2 guest ABI, the Linux syscall ABI for wasm32 guests, and the generator for its
bindings.

- `wit/`: the ABI, written as annotated WIT. [`wit/README.md`](wit/README.md) describes the
  conventions and every annotation.
- `src/`: `wasixv2-codegen`, which reads the WIT and generates the host-side Rust (the ABI types,
  the `Syscalls` trait and the wasm import shims) and the musl C glue.
- `tests/`: golden tests for the generator, including a snapshot of the C glue for the real ABI,
  so that an ABI change shows up in review as a C diff.
- [`compat-libc/`](compat-libc/README.md): owned public context/function headers
  and standalone wasm32-wasixv2 wrappers for separately labelled rebuilt consumers.

This canonical source is owned in public `wasmerio/wasmer-next` at
`lib/wasix/codegen`. See [PROVENANCE.md](PROVENANCE.md) for the upstream
source revisions and ownership boundary. Generated Rust is committed in Wasmer
(exec) and `wlk/crates/{abi,syscalls}`.

## Changing the ABI

Review WIT and generator changes with all affected generated outputs and producer
profiles. ABI changes land in this repository with matching kernel, import-shim
and `guest/libc` outputs. Downstream libc2 consumers need the same matching ABI
revision; toolchain releases remain separately coordinated.

From the Wasmer workspace, check output equality:

```sh
cargo test -p wasixv2-exec --test generated
```

Regenerate directly into the local kernel and exec source:

```sh
WASIXV2_CODEGEN_BLESS=1 cargo test -p wasixv2-exec --test generated
```

`cargo test -p wasixv2-codegen` runs the generator's own tests.
`WASIXV2_CODEGEN_BLESS=1 cargo test -p wasixv2-codegen` rewrites its golden
files. The C emitter can write to the owned guest libc source tree:

```sh
cargo run -p wasixv2-codegen -- c --wit lib/wasix/codegen/wit --libc guest/libc
```
