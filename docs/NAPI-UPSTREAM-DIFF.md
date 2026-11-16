# Local NAPI versus runtime upstream

Comparison against wasmer-runtime `next` 843f911162ad72ed061bcfad5027505c3bd5101f,
whose unchanged upstream NAPI submodule is `82b328f50ddaac78de388b67b4707f21864b9245`.
Tracked regular files only; nested submodule contents are excluded.
The working product manifests include the engine git-source switch.

**45 files changed, 21699 insertions, 5236 deletions** (line diff).

The local implementation carries WASIX v2 execution/instantiation hooks and
protected memory leases, v2 pending-call/refill/cancellation tests, native frame
and GC repairs, native/JSPI continuation and retirement ownership, CLI package
and mount integration, memory budgeting and charged growth/reset/refill paths,
and browser profile adaptations. See SOURCE.md and the integration tests.
Upstream still uses its legacy WASIX integration. Replacing this source with
upstream is a separate port requiring these contracts and tests to be preserved.

Runtime's extraction report identifies upstream budget.rs using obsolete
NonNull arguments for Tunables::create_vm_memory/table. This local budget.rs
already accepts VMDefinitionLocation for both production and test adapters.
That specific upstream blocker therefore does not require a local adapter edit.
No local builds/tests were run for this extraction, by owner instruction.

| File | Added lines | Removed lines |
| --- | ---: | ---: |
| `Cargo.lock` | 1 | 0 |
| `Cargo.standalone.lock` | 618 | 2214 |
| `Cargo.standalone.toml` | 42 | 27 |
| `Cargo.toml` | 34 | 21 |
| `SOURCE.md` | 19 | 0 |
| `build.rs` | 690 | 1 |
| `cargo-standalone.sh` | 4 | 1 |
| `include/unofficial_napi.h` | 3 | 0 |
| `lib/src/napi_buffer_lease.cc` | 11 | 0 |
| `quickjs/src/unofficial_napi.cc` | 8 | 0 |
| `src/budget.rs` | 1123 | 41 |
| `src/cli.rs` | 613 | 196 |
| `src/ctx.rs` | 680 | 47 |
| `src/env.rs` | 873 | 197 |
| `src/guest/callback.rs` | 399 | 274 |
| `src/guest/callback_js.rs` | 65 | 43 |
| `src/guest/mod.rs` | 89 | 0 |
| `src/guest/napi.rs` | 1271 | 703 |
| `src/guest/napi_js.rs` | 64 | 66 |
| `src/guest/util.rs` | 12 | 28 |
| `src/guest/util_js.rs` | 3 | 6 |
| `src/guest_heap.rs` | 1467 | 156 |
| `src/lib.rs` | 8 | 2 |
| `src/napi_bridge_init.cc` | 1712 | 154 |
| `src/native_frame.rs` | 685 | 0 |
| `src/snapi.rs` | 54 | 17 |
| `src/snapi_js.rs` | 1744 | 990 |
| `src/wasix.rs` | 801 | 47 |
| `tests/browser/README.md` | 43 | 0 |
| `tests/browser/napi-browser.html` | 40 | 0 |
| `tests/browser/run.mjs` | 463 | 0 |
| `tests/callback_control.rs` | 3500 | 0 |
| `tests/callback_control_js.rs` | 1433 | 0 |
| `tests/cli_facade_mounts.rs` | 348 | 0 |
| `tests/native_jspi.rs` | 475 | 0 |
| `tests/programs/run_script_test.c` | 58 | 0 |
| `tests/programs/test_sdk_js_active_loop.c` | 40 | 0 |
| `tests/wasix_facade.rs` | 1289 | 0 |
| `tests/wasix_facade_js.rs` | 61 | 0 |
| `tests/wasix_leases.rs` | 230 | 0 |
| `tests/wasix_pending.rs` | 494 | 0 |
| `v8/src/internal/napi_v8_env.h` | 4 | 0 |
| `v8/src/internal/unofficial_napi_bridge.h` | 20 | 0 |
| `v8/src/js_native_api_v8.cc` | 1 | 0 |
| `v8/src/unofficial_napi.cc` | 107 | 5 |
