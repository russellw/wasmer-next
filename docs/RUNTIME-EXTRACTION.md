# Product runtime dependency

The engine is maintained in private `wasmerio/wasmer-runtime`, branch `next`.
The root Cargo.lock pins the reviewed revision; all engine packages must use the
same Git source identity. Rust 1.99 and LLVM 23 are required by that engine.

For HTTPS access, configure `gh auth login` and `gh auth setup-git`. Cargo uses
Git CLI fetching through .cargo/config.toml. CI jobs resolving Cargo dependencies
need a read-only deploy key `RUNTIME_CI_READ_SSH_KEY` for wasmer-runtime. WLK is now local under wlk/. A token scoped only to this repository cannot fetch
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

## CI setup and ownership

Create repository/organization secret `RUNTIME_CI_READ_SSH_KEY`, containing an
SSH private deploy key with read-only access to wasmerio/wasmer-runtime. Root
workspace jobs call .github/actions/setup-runtime, which narrowly rewrites that
HTTPS URL to SSH and enables Git CLI fetching. RISC-V Docker commands explicitly
mount its key/known-hosts and Git configuration. Fork PRs without this secret
cannot fetch the private engine and fail clearly rather than silently skipping
required product checks. `ci_success` still rejects failed/cancelled jobs and
accepts intentional skips. Sealed wlk-only jobs do not need runtime credentials.

Existing GITHUB_TOKEN/GH_TOKEN use for V8 provider assets is separate; the
provider remains in this repository. No additional V8 secret is introduced here.
The LLVM 23 custom-build release asset names were confirmed through GitHub
release metadata; CI must confirm installation and package-manager availability. Guest libc2's LLVM toolchain remains independent.

Phase C now has only integration and product areas: engine implementation changes
and compiler/WAST/API/Miri jobs belong to runtime. Product lock/manifest changes
run all retained areas. Product checks retain backend builds and C API V8 tests.
The current NAPI-specific scripts/nix/v8-prebuilt.nix helper remains because it
consumes NAPI's provider, not API's wee8 archive; its flake.nix caller was not edited.

The standalone NAPI manifest selects the git engine, but its standalone lock must
be refreshed after this product revision is reachable from its main Git source.
Root NAPI builds use the root lock and do not require that future standalone lock.

The existing modified flake.nix was explicitly excluded from this work. Its
LLVM 22/Nix toolchain selection and private dependency vendoring need a separate
coordinated update before claiming Nix builds work against the new engine.
The untracked docs/MERGE.md remains untouched; its Phase C engine-area guidance
is superseded by the integration/product selector in .github/ci-changes.py.

## Extraction evidence and CI acceptance

The selected engine revision is
843f911162ad72ed061bcfad5027505c3bd5101f. Cargo metadata resolved the product
graph after removal, with 23 root workspace packages and one Git source identity
for the engine. No registry engine patches were required by this graph.

At the owner's request, no local builds, tests, lint or CI-selector tests ran.
Only Cargo metadata/targeted updates were used to regenerate the lock. Attempts
to preserve old libc, rustls, webpki-roots, sharded-offset-map and
wasmtime-internal-core versions failed on new engine dependency constraints
(parking_lot_core, ureq, libwild and Cranelift respectively); their lock changes
are required transitive updates. WLK's standalone lock was not changed.

CI must establish cold-cache fetches, root workspace check, CLI and C API builds,
C API tests/examples, local NAPI build, focused WASIX suites and browser-profile
checks. The changed area-selector tests are retained for CI, not claimed passed.
Existing backend/platform restrictions, V8 concurrency limitations and guest-suite
setup gaps still apply. No public-registry distribution policy is established.

NAPI is mounted at lib/napi from wasmerio/napi, branch next, preserving the
product's WASIX v2 adaptations rather than reverting to runtime's upstream pin.
See [NAPI-UPSTREAM-DIFF.md](NAPI-UPSTREAM-DIFF.md).
