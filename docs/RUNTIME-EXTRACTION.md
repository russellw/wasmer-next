# Product runtime dependency

The engine is maintained in public `wasmerio/wasmer-runtime`, branch `next`.
The root Cargo.lock pins the reviewed revision; all engine packages must use the
same Git source identity. Rust 1.99 and LLVM 23 are required by that engine.

Both wasmer-next and wasmer-runtime are public as of 2026-11-17. Anonymous HTTPS
can fetch the engine. CI deliberately retains its per-job GitHub App installation
token and setup action, including container credential forwarding; current
workflows still require the configured app secrets. This also supports any
remaining restricted fetches. WLK is tracked locally at `wlk/`.

V8's Linux provider is a public wasmer-next asset (726693826). Its
current build script requires GH_TOKEN/GITHUB_TOKEN for automatic download; that is
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
Engine release and public registry distribution policy is out of scope.

## CI setup and ownership

Owner prerequisites for the retained authenticated CI configuration:

- Create or reuse the cross-dependency GitHub App and grant it repository
  **Contents: read-only** permission.
- Install the app on the **wasmerio** organization with access to the public
  **wasmer-runtime** repository; approve any pending installation/permission
  request. No access to this product repository or public wasmerio/napi is needed.
- Generate an app private key. Set Actions secrets
  `CROSS_DEPENDENCY_GITHUB_APP_CLIENT_ID` (the app's client ID) and
  `CROSS_DEPENDENCY_GITHUB_APP_PRIVATE_KEY` (the full PEM private key) on this
  product repository, or as organization secrets with this repository included
  in their access policy. Make them available to every runtime-consuming job.

Each runtime-consuming job mints its own installation token before checkout with
`actions/create-github-app-token@v3`, owner `wasmerio`, repository
`wasmer-runtime`, and `permission-contents: read`. Checkout retains its default
`GITHUB_TOKEN`, including for the public lib/napi submodule. The local
`.github/actions/setup-runtime` action takes the minted token, stores it with
mode 600 in `RUNNER_TEMP/wasmer_runtime_token`, configures path-scoped HTTPS
credential helpers for the runtime URL with and without `.git`, verifies branch
`next` using `git ls-remote --exit-code`, and enables Cargo Git CLI fetching.
The action uses bash on Linux, macOS and Windows. RISC-V Docker commands mount
the token file at the same path and mount the Git configuration read-only.
Installation tokens expire after one hour and are revoked by the mint action
when the job ends; dependency fetches must finish within that lifetime.

Fork PRs and other jobs without the app secrets fail with an explicit error
before checkout; required product checks are not silently skipped. Use a trusted
run with secrets available; do not expose secrets to untrusted fork code.
`ci_success` still rejects failed/cancelled jobs and accepts intentional skips.
Sealed wlk-only jobs do not need runtime credentials. The old runtime SSH deploy
key secret is no longer used and can be removed after migration.

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
LLVM 22/Nix toolchain selection and Git dependency vendoring need a separate
coordinated update before claiming Nix builds work against the new engine.
The untracked docs/MERGE.md remains untouched; its Phase C engine-area guidance
is superseded by the integration/product selector in .github/ci-changes.py.

## Extraction evidence and CI acceptance

The selected engine revision is
843f911162ad72ed061bcfad5027505c3bd5101f. Cargo metadata resolved the product
graph after removal, with 23 root workspace packages and one Git source identity
for the engine. No registry engine patches were required by this graph.

Cargo metadata and targeted updates regenerated the lock. Attempts
to preserve old libc, rustls, webpki-roots, sharded-offset-map and
wasmtime-internal-core versions failed on new engine dependency constraints
(parking_lot_core, ureq, libwild and Cranelift respectively); their lock changes
are required transitive updates. WLK's standalone lock was not changed.

CI must establish cold-cache fetches, root workspace check, CLI and C API builds,
C API tests/examples, local NAPI build, focused WASIX suites and browser-profile
checks. The changed area-selector tests are retained for CI, not claimed passed.
Existing backend/platform restrictions, V8 concurrency limitations and guest-suite
setup gaps still apply. No public-registry distribution policy is established.

NAPI is mounted at lib/napi from wasmerio/napi, branch `edge-wasixv2`, preserving the
product's WASIX v2 adaptations rather than reverting to runtime's upstream pin.
See [NAPI-UPSTREAM-DIFF.md](NAPI-UPSTREAM-DIFF.md).
