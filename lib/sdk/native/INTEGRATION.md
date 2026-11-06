# Native SDK recovery

This tree recovers only the Rust SDK source, license and original tests from the
revision and paths in SOURCE.json. Original integration tests and fixture bytes
are unchanged. Browser and Node source/builds are not imported by this native
workstream. The README describes the public consumer contracts and workspace path.

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
V8 test's eight original guest executions. The normal SDK closure excludes
virtual-fs; the SDK dependency record is the only changed lock record.
The public network_provider type still uses virtual-net and a live canonical
network adapter, retaining virtual-io transitively. Their separate retirement is
not implemented in this slice. No old WASIX Runtime/runner is reintroduced.
Configured SDK providers receive the original lookup name and optional service
port through the canonical namespace's opt-in host lookup. Each syscall layer must
admit this path; unknown layers, tracing restrictions and seccomp retain ordinary
wire DNS. Pending selected operations keep their initiating namespace and cannot
be replayed through wire DNS after interruption or a policy/provider change.
Exact selected-provider errors remain authoritative. This does not complete the
physical endpoint or legacy network-crate retirement work described below.

Compiled modules and their allocating feature engines share one cache owner.
Plain runs reuse the client owner; N-API creates a separate owner and budget per
run. Persistent artifact bytes use the existing versioned cache directories.

Only WEBC v3 is supported. Journaling is excluded and configured guest CPU
parallelism is deferred. Browser/Node/macOS are held. Canonical opt-in legacy
append offsets use the reviewed WLK main API. Host network endpoint policy is
pending its reviewed WLK main integration. Import-free raw `_start` modules with
exported memory remain a parity gap: the old native runner could execute them,
while the facade reports NoAbi. A narrow initial-entry profile fix is pending;
no direct-instance fallback is provided.
The accepted pre-retirement base is d0b6c749f373 on WLK
049156e0b7a92588f4827c1915d722b182f97a75. Its default native suite passed
62 tests, and the optional N-API success gate passed all eight original fixture
executions. This includes the original 23 integration contracts, package/cache
and provider ownership, separate terminal stdout/stderr and finite terminal EOF.
The retirement validation above covers the changed storage and stdio paths on
the same coherent WLK revision. Configured-provider guest pre-bind/endpoint policy and the remaining
network/support-crate retirement are still separate unfinished work.

The integration preserves the Python compatibility fixes, root C API imports
changes and WLK console/append policies already on main. The legacy filesystem
crate still exists for other consumers; this slice removes it from the native SDK
dependency closure.
