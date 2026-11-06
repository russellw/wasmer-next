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

The portable Directory and SandboxFileSystem storage still use virtual-fs, and
the public network_provider type still uses virtual-net with a live canonical
network adapter. This support-crate retention is INTERMEDIATE for the first
runnable port. Retirement of virtual-fs, virtual-net and virtual-io is required
in the following minimal native SDK/WLK slice; this port is not that retirement.
These dependencies do not restore the old WASIX Runtime/runner.
Compiled modules and their allocating feature engines share one cache owner.
Plain runs reuse the client owner; N-API creates a separate owner and budget per
run. Persistent artifact bytes use the existing versioned cache directories.

Only WEBC v3 is supported. Journaling is excluded and configured guest CPU
parallelism is deferred. Browser/Node/macOS are held. Canonical opt-in legacy
append offsets use the reviewed WLK main API. Host network endpoint policy is
pending its reviewed WLK main integration. Import-free raw `_start` modules may
hit the current facade's NoAbi policy; no direct-instance fallback is provided.
The native compiler check and all 23 original integration contracts pass on the
recorded WLK 7cb98a1 graph. This includes actual repeated and persisted-cache
execution, writable package overlays, readonly provider mounts, process control
and direct Ports. All 29 SDK library regressions also pass, including streamed
registry progress, alias resolution and cancellation. Four targeted shared
resolver/loader boundary checks and the temporary timestamp helper test pass
using the original pinned fixtures. These results do
not establish N-API execution, configured-provider guest loopback/pre-bind,
separate terminal output routing, finite terminal EOF, or legacy-provider retirement.
