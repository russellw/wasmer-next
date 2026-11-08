# WASIX directory migration and legacy removal gates

The machine implementation now lives under `lib/wasix/`, retaining its
nested crates and existing `wasixv2*` package names. The old `wasmer-wasix`
crate moves intact to `lib/wasix-legacy/`. This is a directory migration,
not evidence of functional parity or completed legacy removal.

Legacy crates remain while their active consumer migrations still compile.
Journaling, snapshot/restore, and compatibility with old journal formats are
explicitly excluded at the user's request. The CLI journal commands, run options,
Cargo feature, and provider dependency are intentionally removed; they are not
parity blockers. The old journal crate remains only as a temporary dependency of
the legacy runtime and will be deleted with it. No format replacement is planned.

The remaining non-journal consumers must preserve their required behavior before
retirement. A successful Cargo check alone does not establish that behavior.

Intel macOS support is excluded at the user's request. Its private V8 package
producer is removed; no Intel package or runtime acceptance gate remains.
Linux and macOS ARM64 support remain required.

## Crate map

| Retained legacy crate | Existing responsibility and consumers | V2 implementation and current evidence | Removal gate |
| --- | --- | --- | --- |
| `wasmer-wasix` (`lib/wasix-legacy`) | Guest imports, `WasiEnv`/`WasiEnvBuilder`/`WasiFunctionEnv`, pluggable runtime, package acquisition/resolution/caches, HTTP, runners, hooks, journal integration. Public exports are in [`src/lib.rs`](../lib/wasix-legacy/src/lib.rs); consumer details follow below. | [`Machine`](../lib/wasix/api/src/lib.rs), [`Package`](../lib/wasix/api/src/package.rs), [`exec`](../lib/wasix/exec/src/lib.rs), [`kernel`](https://github.com/wasmerio/wlk/blob/main/crates/kernel/src/lib.rs), and [`wasix1`](../lib/wasix/wasix1/src/lib.rs) provide new execution machinery. Existing tests cover [machine execution](../lib/wasix/api/tests/machine.rs), [packages](../lib/wasix/api/tests/package.rs), [commands](../lib/wasix/api/tests/commands.rs), [custom bindings](../lib/wasix/api/tests/custom_bindings.rs), and [v1 guests](../lib/wasix/wasix1/tests/guest.rs). These are coverage locations, not a claim of full old API or behavior parity. | Port every consumer listed below; preserve source compatibility or obtain explicit approval for each removed public API. Registry acquisition, credentials, persistent caches and the old embedding facade are still used. |
| `wasmer-wasix-types` (`lib/wasi-types`) | Published v1 ABI types, asyncify layouts, serde/rkyv support; used by the legacy runtime and `wasmer-journal`, and re-exported by the legacy public facade. See [`src/lib.rs`](../lib/wasi-types/src/lib.rs) and [`Cargo.toml`](../lib/wasi-types/Cargo.toml). | The [v1 adapter ABI](../lib/wasix/wasix1/src/abi/mod.rs) decodes old guest layouts; [`wasixv2-abi`](https://github.com/wasmerio/wlk/blob/main/crates/abi/src/lib.rs) defines the new ABI. Adapter [layout tests](../lib/wasix/wasix1/tests/layout.rs) cover its layouts. | Internal guest-layout decoding does not replace the published Rust types or serialized journal representations. Retain until the remaining runtime consumers are migrated and public compatibility is settled. Old journal-format compatibility is intentionally excluded. |
| `virtual-fs` (`lib/virtual-fs`) | Public `FileSystem`/`VirtualFile` traits, buffers/pipes, host/memory/overlay/mount/WEBC filesystems and adapters. Retained for the legacy runtime, journal and remaining embedding consumers. The CLI default normal dependency closure no longer includes it. See [`src/lib.rs`](../lib/virtual-fs/src/lib.rs). | [`wasixv2-vfs`](https://github.com/wasmerio/wlk/blob/main/crates/vfs/src/lib.rs), `vfs-mem`, `vfs-host`, `vfs-overlay`, `vfs-package`, `vfs-web`, and host byte streams cover corresponding new machinery; [v1 filesystem tests](../lib/wasix/wasix1/tests/fs.rs) exercise guest translation. | Port custom Rust filesystem/file implementors and all stream/capture APIs, then demonstrate equivalent consumer behavior. The new filesystem interfaces are different types. |
| `virtual-net` (`lib/virtual-net`) | Public virtual socket/network traits; host, loopback, composite and remote client/server networking; ruleset parser. The legacy runtime and journal use its types. CLI network rules are owned by `wasmer-config`; its default normal dependency closure no longer includes `virtual-net`. Retained TUN source is unchanged. | `vnet`, `vnet-host`, `vnet-switch`, `vnet-web` implement new transport paths. See [machine networking tests](../lib/wasix/api/tests/net.rs) and [v1 socket tests](../lib/wasix/wasix1/tests/net.rs). | Preserve retained TUN behavior; map custom networking implementors, remote protocol and serialization for the remaining non-journal consumers. A browser relay does not establish old remote-protocol compatibility. |
| `virtual-mio` (`lib/virtual-io`) | Interest handlers, wakers, selector and registration guards; used by virtual-fs, virtual-net and the legacy runtime. Retained CLI TUN source is unchanged; the CLI default normal dependency closure excludes `virtual-mio`. See [`src/lib.rs`](../lib/virtual-io/src/lib.rs). | [`Host`/`Executor`](https://github.com/wasmerio/wlk/blob/main/crates/host/src/lib.rs), [`TokioHost`](https://github.com/wasmerio/wlk/blob/main/crates/host/src/tokio_host.rs), and [browser drivers](https://github.com/wasmerio/wlk/blob/main/crates/host/src/browser/mod.rs) provide the new scheduling/reactor boundaries. | Port every old `InterestHandler`/`Selector` consumer and its wakeup/cancellation behavior. Existing host abstractions are not source-compatible substitutes. |
| `wasmer-journal` (`lib/journal`) | Temporary dependency of [`wasmer-wasix`](../lib/wasix-legacy/Cargo.toml); the CLI no longer depends on or exposes it. | Journaling, snapshot/restore and old-format compatibility are intentionally excluded. | Delete with the legacy runtime after its remaining consumers migrate. No replacement provider, adapter or format-compatibility gate. |

The new runtime crates retained under `lib/wasix/` are exactly:

```text
wasixv2                 (api)
wasixv2-abi             wasixv2-checkpoint      wasixv2-dylink
wasixv2-exec            wasixv2-host            wasixv2-kernel
wasixv2-pages           wasixv2-policy          wasixv2-record
wasixv2-stdio-web       wasixv2-syscalls        wasixv2-trace
wasixv2-vfs             wasixv2-vfs-host        wasixv2-vfs-mem
wasixv2-vfs-overlay     wasixv2-vfs-package     wasixv2-vfs-web
wasixv2-vnet            wasixv2-vnet-host       wasixv2-vnet-switch
wasixv2-vnet-web        wasixv2-wait            wasixv2-wasix1
```

`lib/wasix/codegen` now owns the canonical annotated WIT and generator as tracked
source, preserving the original MIT license and upstream provenance. The
`wasixv2-codegen` package is retained. See its `PROVENANCE.md` for the source
revisions and the engine-context emitter delta. `wasixv2-wasix1` is the active
WASIX v1/WASI guest adapter on the new kernel; it is not the old runtime
and must not be removed as part of legacy retirement.

## Consumer gates

| Consumer | Source-backed remaining use | Required behavior before removal |
| --- | --- | --- |
| CLI execution and packages | [`run/machine.rs`](../lib/cli/src/commands/run/machine.rs) uses `Machine`; [`run/runtime.rs`](../lib/cli/src/commands/run/runtime.rs) uses shared `wasmer-package` acquisition and `wasmer-cache::module_cache`, with network rules in `wasmer-config`. The journal dependency and run options are removed. | Preserve the remaining registry/file/URL resolution, credentials, caches, logging, compiler selection, HTTP, network rules and command annotations. Journaling is intentionally excluded. |
| CLI journal | Journal inspect/export/import/compact/filter/extract commands, run/snapshot options and the Cargo feature are removed from [`wasmer-cli`](../lib/cli/Cargo.toml) at the user's request. | Intentional removal; old journal data and command compatibility are not required. |
| C API | [`wasm_c_api/wasi/mod.rs`](../lib/c-api/src/wasm_c_api/wasi/mod.rs) owns configuration and version detection. Its native `sys` backend uses [`NativeWasi`](../lib/c-api/src/wasm_c_api/wasi/native.rs), `Machine` and `HostEnvironment`; the V8 backend temporarily retains `WasiFunctionEnv`. Default native and bare `wasi` normal dependency closures exclude the legacy runtime and virtual filesystem/network crates. | Native Linux public tests cover configuration, independent environments, A/B/A routing, shared/private memory reselection, threads, exec/handoff and cancellation, driven final-Store cleanup, and borrowed synchronous calls from a foreign Tokio runtime. The unchanged shutdown regressions complete both LocalSet and VM cleanup. Initialized `_start` copying fork passes the same imported-shared-memory fixture on the old and current runtimes, including child rewind, exact exit/reap and private-memory separation. Escaped helper/cancellation tests and composed CLI/SDK/NAPI compilation pass at `cd52d14`. Old arbitrary export/table calls instead start the child at `_start` with no arguments; this legacy wrong-target fallback is intentionally not reproduced, and general child-target replay is not advertised. ARM64 Mac acceptance also passes all 14 exact public C API gates, including six compiled-C executable/dylib load checks, on macOS 15 with deployment target 13; this is not actual macOS 13 execution. The V8 backend migration remains open. Original owner-thread usage is the contract; no foreign-thread finalizer or progress after every owner job/driver is discarded is inferred. Borrowed synchronous calls retain the engine's existing ready/Pending behavior, not a new asynchronous executor guarantee. Preserve symbols, exact routing, streams and the WASI SNAPSHOT namespace names. Journaling is excluded. |
| `wasmer-c-api-imports` | [`src/wasixv2.rs`](../lib/c-api-imports/src/wasixv2.rs) implements the v2 execution hook; published `wasix` and `wasi` feature names select it. Its original guest fixture is retained and its normal/development closure excludes the old runtime. | Original guest and imported-memory hook component tests pass. Preserve real bindings through early start, instance attachment, fork/exec and cleanup; these component results do not close the C API facade gates. |
| NAPI | The in-repository [`lib/napi/Cargo.toml`](../lib/napi/Cargo.toml) and `src/wasix.rs` provide a generic v2 `NapiHook` over executor/syscall traits. The standalone CLI consumer is being migrated from the old runner. | Integrate the separately developed NAPI facade without overwriting its source; preserve guest import behavior, memory, per-instance state, threads, fork/exec and cleanup. The native binding owns its v2 hook; the machine facade has no NAPI dependency. Optional runner dependencies target `../wasix/api`, so runner migration does not create a package cycle. The imported `bdc2474` baseline already includes the earlier `afe139d` path correction. |
| Swift | [`lib/swift/src/lib.rs`](../lib/swift/src/lib.rs) builds old `WasiEnv`, uses `ArcFile`/`BufferFile` capture and old run/error APIs. | Preserve Swift-facing execution, errors and stdout capture with the new machine, then remove old dependencies. |
| Root meta-crate/examples | Root [`Cargo.toml`](../Cargo.toml)'s `wasi` feature selects `wasmer-wasix`; [`wasi.rs`](../examples/wasi.rs), [`wasi_manual_setup.rs`](../examples/wasi_manual_setup.rs), and [`wasi_pipes.rs`](../examples/wasi_pipes.rs) compile against its embedding APIs. | Preserve the feature and examples until an explicit source-compatible facade or approved consumer migration exists. |
| `wasmer-sys-utils` | [`Cargo.toml`](../lib/sys-utils/Cargo.toml) declares `wasmer-wasix.workspace`; the only source mention is commented code in [`tests/fd_mmap_memory.rs`](../lib/sys-utils/tests/fd_mmap_memory.rs). | This dependency can be audited for separate removal; removing an unused declaration does not establish parity of the legacy runtime. |
| Browser SDK | Browser machine/transport primitives live in [`api/src/browser.rs`](../lib/wasix/api/src/browser.rs), [`host/src/browser`](https://github.com/wasmerio/wlk/blob/main/crates/host/src/browser), and web drivers. The SDK consumer is maintained outside this checkout. | Update SDK path dependencies from `lib/wasixv2/<crate>` to `lib/wasix/<crate>` when integrating its ongoing transport work; preserve registry/cache/streams and real browser/worker behavior. No SDK source is overwritten here. |

## Evidence preservation and validation boundaries

All 744 tracked files under the old `lib/wasix/tests/` are retained at
`lib/wasix-legacy/tests/`, including old fixtures, expectations, harnesses
and runner code. The harness still resolves its fixtures from
`CARGO_MANIFEST_DIR/tests/wasm_tests`; its directory depth is unchanged.
Only the test README's direct file paths change. Future old/new comparisons
must reuse these fixtures and record each result before deleting anything.
The existing new-kernel v1 tests remain under `lib/wasix/wasix1/tests/`.

The directory migration does not complete the deferred WASIX64 or Windows
work. Their non-journal source and fixtures remain subject to their existing
retirement gates. Journaling and snapshot/restore are an explicit user-authorized
removal, including their CLI commands, options, feature and old-format support;
this exception does not authorize unrelated removals.

The Cargo workspace still names the old runtime explicitly and includes
the new crates with `lib/wasix/*`. The generator is tracked source rather than an external gitlink so required
engine changes are obtainable from the same private repository. Generated source
headers now name the new WIT location. A WIT-derived comment in the generated
syscall file still names the historical `lib/wasixv2/DESIGN.md` path because
the upstream ABI source and pinned revision were not changed.

In an existing checkout, synchronize and update submodules after changing
branches:

```sh
git submodule sync --recursive
git submodule update --init --recursive
```

Use the same named-package build/test commands as before; public package
identities did not change. Run legacy guest tests with `cargo test -p
wasmer-wasix --features sys`, new adapter tests with `cargo test -p
wasixv2-wasix1`, the generated-source checks with `cargo test -p wasixv2-abi
--test generated`, and the CLI/C API/NAPI/Swift consumer checks after their
respective ports. These commands are requirements for the relevant change,
not a record of tests already run by this migration.

## Directory migration checks

The migration passed locked workspace metadata (64 members, including the
25 nested runtime crates, unchanged code-generator package and six legacy
crates), locked CLI dependency resolution, browser dependency isolation,
`cargo fmt --all -- --check`, shell syntax checks for the relocated browser
scripts, and 117 existing Node tests across the facade, host, execution
memory and stream drivers. A git-blob comparison verified that all legacy
test fixtures and harnesses are unchanged apart from the README paths.

Compiler builds, Rust execution tests and the full `make lint` gate have
not been run for this path-only change while compilation slots are reserved
for runtime work. These checks do not establish legacy removal parity.

## NAPI source ownership

`lib/napi` is maintained as in-repository source, imported from the integrated
`bdc2474` baseline with its GC/frame repairs preserved. Its former gitlink is
removed; the unchanged nested QuickJS gitlink is registered at the repository
root. See [NAPI provenance](../lib/napi/SOURCE.md). This source ownership change
does not waive the NAPI lifecycle and consumer execution gates above.


### V8 VM export provenance

V8 VM export payloads now use an opaque handle carrying owner-thread and weak
Store identity metadata. The C ABI and generated headers are unchanged. Rust
code constructing `VMExtern::V8(raw_pointer)` must instead use the explicitly
unsafe `VMExtern::from_raw_v8_unchecked` constructor with a live raw extern from
that exact Store. It does not infer ownership from the raw address or StoreId.

`Extern::from_vm_extern` and `VMExternToExtern::to_extern` retain their infallible
signatures and panic on invalid V8 provenance before querying the raw handle.
Use `Extern::try_from_vm_extern` for checked conversion returning `RuntimeError`.
Normal typed export/copy conversions preserve existing provenance. Metadata
clone and Drop remain inert after expiration and on another thread; invocation
still requires the original Store thread. This source change does not claim
completion of the V8 CAPI WASI migration or its runtime acceptance gates.

### V8 raw trap custody

V8 Rust traps now own their message or typed error after a call; displaying or
moving an escaped trap does not query a destroyed Store. Canonical synchronous,
typed, instance-start and asynchronous calls preserve typed host errors through
their exact finite call scope, using owned exception identity rather than
message text. A forged address-like message has no typed-error authority.

The low-level Rust `From<*mut wasm_trap_t>` conversion consumes a trusted OWN
raw trap as a **message-only** snapshot. It cannot recover a typed error without
the canonical explicit owning scope. The existing unsafe
`Trap::into_wasm_trap(User)` additionally requires a matching live actual-call
scope; failure rejects before C++ publication. Checked internal C callbacks
use their publisher captured before user work. These are narrow raw-Rust source
contract changes, not C ABI changes or an extra executor/borrow grant. Default
native and JS trap behavior is unchanged. V8 WASI migration and actual runtime
acceptance remain separate gates.
