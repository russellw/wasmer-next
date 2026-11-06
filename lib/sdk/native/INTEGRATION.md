# Native SDK recovery

This tree recovers only the Rust SDK source, license and original tests from the
revision and paths in SOURCE.json. The six original integration sources and two
fixture files remain byte-identical. Additional network adapters use the SDK-owned
provider signatures. Browser and Node source/builds are not imported by this
native workstream. The README describes the public consumer contracts and workspace path.

The Linux native port is a workspace member using local facade, acquisition,
resolved installer, C API and optional N-API crates. One client-owned LocalSet
services private per-run Machines and network namespaces; the common facade
owns guest threads. Runs share the original public network provider/configuration,
while each run and the independent Ports probe group retain their own I/O jobs. User
filesystem callbacks run on the existing Tokio runtime and retain their actual
completion and close custody independently of public wait subscriptions.

The filesystem/stdio retirement replaces Directory's private virtual-fs
storage with closed canonical MemFs/Vfs and uses SDK providers directly for the
workspace and package root. Stdio uses ByteSink, the retained PipeWriter and
capture storage directly. See MEMORY-STORAGE.md for the closed progress proof and
positioned/append seam. Independent source review and actual
retirement validation pass: 41 library tests, 40 integration tests and the N-API
V8 test's eight original guest executions. That slice removed virtual-fs from the normal SDK closure and changed only
the SDK dependency lock record.
The native network retirement source replaces the nominal `virtual-net` provider
with SDK-owned `network_api::NetworkProvider`, canonical WLK transports/readiness,
and the same per-run Services/Group cleanup owners. Host factories use the shared
WLK reactor and resolver. Explicit TCP binds retain their actual bound token;
unbound connect/listen remain separate factories. UDP receives initialized bytes
with actual destination/interface metadata through canonical namespace ingress.
The SDK manifest removes its `virtual-net` dependency. Both default and `napi-v8`
normal dependency trees exclude virtual-net, virtual-fs, virtual-mio, virtual-io,
wasmer-wasix, wasmer-wasix-types and journal. No old WASIX Runtime/runner or copied
socket backend is reintroduced. The intentional provider API migration and
pending-resource/close contracts are documented in README.md and network_api.rs.
Configured SDK providers receive the original lookup name and optional service
port through the canonical namespace's opt-in host lookup. Each syscall layer must
admit this path; unknown layers, tracing restrictions and seccomp retain ordinary
wire DNS. Pending selected operations keep their initiating namespace and cannot
be replayed through wire DNS after interruption or a policy/provider change.
Exact selected-provider errors remain authoritative. Host and custom networking
use optional selected endpoints on the same admitted resource. Ordinary namespace
networking retains its existing defaults.

Compiled modules and their allocating feature engines share one cache owner.
Plain runs reuse the client owner; N-API creates a separate owner and budget per
run. Persistent artifact bytes use the existing versioned cache directories.

Only WEBC v3 is supported. Journaling is excluded and configured guest CPU
parallelism is deferred. Browser/Node/macOS are held. Canonical opt-in legacy
append offsets and native endpoint policy use the reviewed WLK main API. All 21
WLK packages have one Git-main identity at
`8ec0fc67017353513321617103f85739b07556b9`; no development path overrides remain.
Import-free raw `_start` modules with exported memory remain a parity gap: the old native runner could execute them,
while the facade reports NoAbi. A narrow initial-entry profile fix is pending;
no direct-instance fallback is provided.
The accepted pre-retirement base is d0b6c749f373 on WLK
049156e0b7a92588f4827c1915d722b182f97a75. Its default native suite passed
62 tests, and the optional N-API success gate passed all eight original fixture
executions. This includes the original 23 integration contracts, package/cache
and provider ownership, separate terminal stdout/stderr and finite terminal EOF.
The earlier retirement validation covers storage and stdio. Focused native network
validation passes 7 provider units, the observed-exit cleanup unit, 11 public Host
contracts, 4 network contracts, 2 Ports contracts and 6 process contracts. The
original N-API success test passes all eight guest executions. These gates include
actual IPv4/IPv6 and non-loopback TCP/UDP, literal source/port-zero ownership,
multicast metadata, publication, sibling isolation and physical close acknowledgement.
The WLK component passes 218 vnet tests and 42 Host tests, with 63 endpoint tests
and the final bind-authority control checked after scoped source normalization.
These are focused changed-path gates; the earlier complete suites were not rerun.
Default and N-API all-target SDK Clippy pass with `clippy::all` denied.
Locked/offline metadata and the zero-legacy normal-tree audit pass.

The integration preserves the Python compatibility fixes, root C API imports
changes and WLK console/append policies already on main. Legacy
support crates may remain for other consumers; root integration owns their final
workspace removal. This slice removes their native SDK dependency edges.
