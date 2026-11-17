# Testing

Product checks and tests are defined by the root Makefile. `make check` checks
the CLI and C API. `make test` runs retained workspace tests and WASI examples.
To run CLI, package, cache, or C API tests and examples that use
`wasmer-test-files` directly, initialize the fixtures from the repository root:

```sh
git submodule update --init --recursive --checkout -- wasmer-test-files
```

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
do not add engine ignores to this product repository. Runtime fetch setup
is documented in [RUNTIME-EXTRACTION.md](RUNTIME-EXTRACTION.md).

## Kernel and guest tests

WLK tests run from wlk/ with its own lockfile, including sealed checks, Clippy,
nextest, audit and wasm profiles. Root fmt/lint does not cover that workspace.
The product additionally checks generated files and the v1 network protocol
reference tests in lib/wasix/api/tests/vnet_reference_{codec,relay}.rs.
The independent classic-reference fixtures remain conformance oracles.

The source-built guest suite is tests/wasixv2; upstream suites remain submodules.
`make test-wasixv2` builds the CLI, checks out the upstream suites, and invokes
the runner. To run it directly, initialize the suites from the repository root
with `git submodule update --init --recursive --checkout -- tests/wasixv2/upstream`.
It needs wasixcc with wasm32-wasixv2 support, WASIXCC_LLVM_LOCATION and
WASIXCC_SYSROOT_PREFIX selecting `$PWD/guest/libc/build-wasixv2` for the EH and
asyncify sysroots. The guest LLVM fork is separate from the engine's LLVM 23.
Expected failures live in expected-failures/<suite>.txt.
See the suite README for setup. Full guest coverage is still a CI setup item.

Legacy implementation fixtures were deleted with that runtime. Retained CLI,
C API and adapter tests exercise v1 guests on v2. Do not copy old guest tests or
prebuilt wasm into the v2 suite. macOS/musl label gating still applies; consult
CONTRIBUTING.md. CI has integration/product areas and one ci_success aggregate;
engine implementation jobs are owned by runtime.

Check guest C glue with
`cargo test -p wasixv2-codegen --test guest_libc --locked`. Regenerate with
`WASIXV2_LIBC_BLESS=1` on that command after ABI/generator changes; commit libc
and kernel updates together. This checks all C emitter outputs, including the
syscall number header. Guest CI runs this check and sysroot smoke tests on
GitHub-hosted runners; full guest-suite execution still needs the toolchain
setup above, wasixcc v2 and `WASIXCC_BINARYEN_LOCATION` for asyncify.
