# Testing

Product checks and tests are defined by the root Makefile. `make check` checks
the CLI and C API; `make test` runs retained workspace tests and WASI examples.
Build the CLI with an explicit backend or Makefile detection:

```sh
cargo build --locked -p wasmer-cli --features cranelift
cargo test --locked -p wasixv2 -p wasixv2-exec -p wasixv2-wasix1
cargo test --locked -p wasixv2-exec --test generated
make test-capi
make test-integration-cli-ci
make check-wasixv2-wasm
```

Engine unit, WAST, backend, Miri, benchmark and fuzz tests now belong in
wasmerio/wasmer-runtime. Its tests/ignores.txt belongs to that engine suite;
do not add engine ignores to this product repository. Private dependency setup
is documented in [RUNTIME-EXTRACTION.md](RUNTIME-EXTRACTION.md).

## Kernel and guest tests

WLK tests run from wlk/ with its own lockfile, including sealed checks, Clippy,
nextest, audit and wasm profiles. Root fmt/lint does not cover that workspace.
The product additionally checks generated files and the v1 network protocol
reference tests in lib/wasix/api/tests/vnet_reference_{codec,relay}.rs.
The independent classic-reference fixtures remain conformance oracles.

The source-built guest suite is tests/wasixv2; upstream suites remain submodules.
`make test-wasixv2` builds the CLI and invokes its runner. It needs wasixcc with
wasm32-wasixv2 support, WASIXCC_LLVM_LOCATION and WASIXCC_SYSROOT_PREFIX selecting
libc2's EH and asyncify sysroots. The guest LLVM fork is separate from the
engine's LLVM 23. Expected failures live in expected-failures/<suite>.txt.
See the suite README for setup. Full guest coverage is still a CI setup item.

Legacy implementation fixtures were deleted with that runtime. Retained CLI,
C API and adapter tests exercise v1 guests on v2. Do not copy old guest tests or
prebuilt wasm into the v2 suite. macOS/musl label gating still applies; consult
CONTRIBUTING.md. CI has integration/product areas and one ci_success aggregate;
engine implementation jobs are owned by runtime.
