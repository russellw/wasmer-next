# Working in this repo as an agent

Before your first edit, read `docs/CONTRIBUTING.md` and `docs/BUILD.md` in
full, plus the row below covering whatever you are about to touch. Skipping one
of those docs does not exempt you from what it says.

Always read:

| Read                   | For                                                    |
| ---------------------- | ------------------------------------------------------ |
| `docs/CONTRIBUTING.md` | PR expectations, commit format, lint gates, code style |
| `docs/ARCHITECTURE.md` | the crate map, one place per concern, submodules       |
| `docs/BUILD.md`        | toolchain setup, compiler backends, fast iteration     |
| `docs/TEST.md`         | test suites, WAST spec tests, `tests/ignores.txt`      |
| `docs/SECURITY.md`     | supported versions, how to report vulnerabilities      |

Read if necessary:

| If necessary        | For                            |
| ------------------- | ------------------------------ |
| `docs/journal.md`   | snapshot and restore internals |
| `docs/PACKAGING.md` | distro packaging constraints   |
| `docs/RISCV.md`     | state of RISC-V support        |

Trust the repository more than any doc. `Makefile` targets and `--help`
output beat external docs, and docs.wasmer.io lags this repository.

## Before you write code

Every new test, fixture, syscall implementation, or backend arm has a
sibling in this repo that already does the same kind of thing. Find it and
match its location, naming, and structure. If you cannot find one, say so
before inventing a layout.

Before implementing a new mechanism, state the design in one or two
sentences and get agreement. Prioritise the smallest diff that slots into
existing machinery. Work already done is not an argument for keeping a
shape: if the design is wrong, say so rather than defending it.

## Attribution

An agent MUST disclose that it is the one that committed its changes, and
MUST NOT feign being a user. The human user is fully responsible for all
contributions.

## Debugging the Runtime

### Logging

Set `RUST_LOG` with standard EnvFilter syntax, for example:

```bash
RUST_LOG="warn,wasmer_wasix=trace" wasmer run file.wasm
```

The `-v` to `-vvvv` flags map to warn/info/debug/trace for the targets
`wasmer`, `wasmer_wasix`, and `virtual_fs`.

`make build-wasmer-debug` builds a debug binary with tokio-console support.

### Run the Workspace CLI Directly

```bash
cargo run -p wasmer-cli --features cranelift -- run file.wasm
```

### Inspect and Author Wasm

- Inspect a module with `wasm-tools print file.wasm`. Pipe through `head`
  or `grep` — the output is large.
- Author test cases with `wasm-tools parse file.wat -o file.wasm`.
- Reduce hard cases with `wasm-opt` and `creduce`.

### Compile a C Repro to WASIX

```bash
WASIXCC_WASM_EXCEPTIONS=1 WASIXCC_PIC=1 wasixcc -g -O0 file.c -o file.wasm
```

### Debug a Failing WAST Test

Engine WAST tests and tests/ignores.txt live in wasmerio/wasmer-runtime.
Use that repository's TEST.md and backend-filtered runner. Product checks here
use the Git engine pinned by Cargo.lock; see docs/RUNTIME-EXTRACTION.md.

## Testing WASIX v2

The WASIX v2 test suite and runner live in `tests/wasixv2/`. The
`make test-wasixv2` target checks out the upstream suites. To run the runner
directly, first run
`git submodule update --init --recursive --checkout -- tests/wasixv2/upstream`
from the repository root.

| Repository | Here | Holds |
| ---------- | ---- | ----- |
| This repository | `lib/wasix/codegen` (tracked source) | The canonical ABI (annotated WIT) and `wasixv2-codegen` |
| [libc2](https://github.com/wasix-org/libc2) | `guest/libc` (tracked source) | The musl-based libc and sysroots |

### Crate tests

```bash
cargo test -p wasixv2 -p wasixv2-abi -p wasixv2-kernel -p wasixv2-codegen  # and the other lib/wasix crates
```

These are plain Rust: the kernel's unit tests, the facade's WAT tests, and
`lib/wasix/exec/tests/generated.rs`, which checks that the generated
kernel and exec crates match the owned canonical WIT. After an ABI or
generator change, regenerate with
`WASIXV2_CODEGEN_BLESS=1 cargo test -p wasixv2-exec --test generated`.

### The test suite

```bash
make test-wasixv2   # builds the wasmer CLI, then runs tests/wasixv2
```

The suite builds every program under `tests/wasixv2/suite/`, and three
upstream suites (musl's libc-test, the Open POSIX Test Suite and LTP, from
wasix-org's LTP fork), with `wasixcc` for `wasm32-wasixv2` and runs them
with that `wasmer`. It needs, from the environment:

- `wasixcc` with wasixv2 support on `PATH` (unreleased:
  wasix-org/wasixcc#87).
- The wasix-org LLVM fork (`wasix-22.1.8` branch), via
  `WASIXCC_LLVM_LOCATION`.
- The libc2 sysroots, via `WASIXCC_SYSROOT_PREFIX=$PWD/guest/libc/build-wasixv2` after
  `make -C guest/libc wasixv2-sysroot wasixv2-sysroot-asyncify` from the repo root. Tests that fork build
  for the asyncify configuration (`WASIXCC_WASM_EXCEPTIONS=no`), whose sysroot is
  `sysroot-wasixv2-asyncify`; `WASIXCC_SYSROOT` names one sysroot for every test,
  so those tests fail with it.
- binaryen's `wasm-opt`, via `WASIXCC_BINARYEN_LOCATION` (its install
  directory), for the asyncify configuration's `wasm-opt --asyncify`.

Filter tests with `WASIXV2_TESTS_ARGS=<filter>`, for example `ltp/` or
`posix/`. Many tests are expected to fail until wasixv2 is complete:
`tests/wasixv2/expected-failures/<suite>.txt` lists them, and a listed test
that starts passing fails the run. Regenerate the lists with
`WASIXV2_TESTS_BLESS=1`, then commit them here. Upstream tests
that cannot make sense on wasixv2 (root, block devices, kernel modules, ...)
are excluded rather than listed; see `tests/wasixv2/excluded.txt`. CI does
not run the suite yet.

### Rules

- New wasixv2 program tests go in `tests/wasixv2/suite/`, built from source
  with `wasixcc`. Never check in prebuilt wasm for them.
- The legacy implementation and its fixtures are removed. Keep v1 adapter/product
  compatibility tests here; never copy legacy fixtures into `tests/wasixv2/`.
- ABI changes land here in one commit: canonical WIT/generator, kernel, import
  shim, libc C glue and wrappers, and tests. Downstream libc2 consumers need
  the matching ABI revision. Regenerate libc with
  `WASIXV2_LIBC_BLESS=1 cargo test -p wasixv2-codegen --test guest_libc --locked`.

## Personal execution preferences

The gitignored `AGENTS.override.md` is the user's personal addendum. When
it exists, it overrides this file's defaults.
