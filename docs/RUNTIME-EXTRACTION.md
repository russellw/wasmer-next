# Product runtime dependency

The engine is maintained in private `wasmerio/wasmer-runtime`, branch `next`.
The root Cargo.lock pins the reviewed revision; all engine packages must use the
same Git source identity. Rust 1.99 and LLVM 23 are required by that engine.

For HTTPS access, configure `gh auth login` and `gh auth setup-git`. Cargo uses
Git CLI fetching through .cargo/config.toml. CI jobs resolving Cargo dependencies
need a Contents-read `RUNTIME_READ_TOKEN` for wasmer-runtime. WLK is now local under wlk/. A token scoped only to this repository cannot fetch
the private engine. Containers need the same credential setup inside them.

V8's Linux provider is a separate private wasmer-next asset (726693826). Its
automatic download needs GH_TOKEN/GITHUB_TOKEN with read access here; that is
separate from runtime Git access. Alternatively provide an absolute
WASMER_V8_ARTIFACT_DIR with lib/libv8.a (Windows: lib/v8.lib), verified against
the runtime's provider/header ABI. The override is authoritative. See the
locked runtime's docs/RUNTIME-EXTRACTION.md for archive hashes and platform
requirements. No provider archive is republished by this split.

For local engine development, use explicit temporary patches for every involved
engine package under `[patch."https://github.com/wasmerio/wasmer-runtime"]`.
Remove patches before committing and lock the pushed revision. Registry packages
that bring their own engine need corresponding `[patch.crates-io]` entries to
the same Git source. Never mix engine type identities.

Engine unit/WAST/Miri/backend tests and V8 production belong in wasmer-runtime.
This repository retains CLI/C API/NAPI/SDK/Swift and WASIX v2 integration tests.
Private-engine release and public registry distribution policy is out of scope.
