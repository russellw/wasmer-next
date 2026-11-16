# WASIX legacy retirement

The legacy implementation is removed. CLI, C API (native and V8), NAPI, SDK and
Swift consume WASIX v2; supported v1/preview1 guests run through wasixv2-wasix1.
No retained consumer reaches the old runtime or has a legacy fallback.

Removed crates: wasmer-wasix, wasmer-journal, virtual-fs, virtual-net, virtual-mio,
wasmer-sys-utils and wai-bindgen-wasmer. Old Rust embedding APIs disappear with
those crates; use the v2 Machine, embedding-process, host/VFS/network interfaces.
Old journal formats/snapshot compatibility remain outside delivery.

wasmer-wasix-types remains only as an adapter layout-test oracle. Shared package,
registry, config, cache and wasm_c_api_v0 imports are product functionality and
stay. Independent classic-reference/IO fixtures remain for v2 protocol checks.

C API wasi_* declarations, feature flags, generated headers, examples and test
runners stay: they already bootstrap a v2 Machine and adapter HostEnvironment.
This removal does not require another C API migration. CLI likewise already
selects Machine for supported v1 and preview1 imports.

WASIX64, proc_snapshot and existing CLI/C API limitations are recorded in
lib/wasix/TODO.md. Removal does not claim new compatibility or a passing suite.
Engine ownership and private fetch setup are in RUNTIME-EXTRACTION.md.
