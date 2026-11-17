# Repository architecture

This workspace owns the product: CLI, C API, NAPI, native SDK, Swift and WASIX v2
engine integration. The root Cargo.toml lists its members.

| Path | Responsibility |
| --- | --- |
| lib/cli | wasmer and wasmer-headless binaries |
| lib/c-api, lib/c-api-imports | Native C API and guest wasm_c_api_v0 imports |
| lib/napi, lib/sdk/native, lib/swift | Product bindings and embedding APIs |
| wlk/crates/* | WASIX v2 kernel (WLK): abi, syscalls, kernel, host, native, vfs*, vnet*, ... (sealed workspace, see below) |
| lib/wasix/{api,exec,dylink,wasix1,codegen} | V2 facade, engine glue, v1 guest adapter and canonical generator |
| lib/package, lib/package-sdk, lib/config, lib/backend-api, lib/cache | Packaging, registry/configuration and module caching |
| lib/wasi-types | Native dev-only ABI oracle for v2 adapter layout tests |
| guest/libc | Musl-based WASIX v2 libc and sysroot builder (plain source import) |
| tests/integration, tests/wasixv2 | Product and guest integration suites |

The engine (API, VM, compilers, types, derive, middlewares, WAST/compiler tests
and fuzzing) lives in public wasmerio/wasmer-runtime, branch next. All engine
packages use one Git source; Cargo.lock pins its revision. See
[RUNTIME-EXTRACTION.md](RUNTIME-EXTRACTION.md) for development against it.

The obsolete wasmer-wasix runtime, journal, virtual-fs/net/mio, sys-utils and
wai-bindgen-wasmer crates are removed. Supported WASI preview1 and WASIX32 guests
run through the v2 kernel's wasix1 adapter, including in the CLI and C API.
There is no legacy fallback. Limits are listed in lib/wasix/TODO.md.

## Sealed kernel workspace

WLK is tracked at wlk/ and excluded from the root workspace. Its crates and lock
remain independent; root integration consumes them by path. No WLK crate may
depend on an engine crate. Its sparse-checkout CI enforces the boundary.

## ABI and code generation

lib/wasix/codegen owns the canonical ABI (annotated WIT) and `wasixv2-codegen`.
It generates the kernel side (wlk/crates/{abi,syscalls}), the engine glue in
lib/wasix/exec, and the guest C glue in guest/libc (wasixv2_syscalls.h,
wasixv2_dyn.c, wasixv2_asserts.c). Drift checks keep all of them in sync:
lib/wasix/exec/tests/generated.rs for Rust and the codegen `guest_libc` test
for C. An ABI change is therefore one commit here: WIT, kernel, import shim,
libc glue and wrappers, and tests (see AGENTS.md for the bless commands).

Submodules are wasmer-test-files, lib/napi (wasmerio/napi, branch next), and the
upstream suites at tests/wasixv2/upstream/{ltp,libc-test,libcap,libaio}. NAPI owns
its nested QuickJS submodule. The v2 suite itself is tracked source. Initialize
with `git submodule update --init --recursive` before builds. NAPI retains its
WASIX v2 adaptations and path dependencies on this workspace; see
[NAPI-UPSTREAM-DIFF.md](NAPI-UPSTREAM-DIFF.md).
