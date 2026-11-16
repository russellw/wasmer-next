# shared-buffer 0.1.4 security dependency patch

This directory contains the exact crates.io `shared-buffer` 0.1.4 package,
from upstream commit `65e72d29726a748b71f754846fef3dad7df64f61`.
`UPSTREAM.json` records the package archive URL, registry checksum and SHA256
of every original and imported file. Both upstream license files are retained.

The only change to an upstream file is the active `Cargo.toml` requirement
`memmap2 = "0.6.1"` to `memmap2 = "0.9.11"` (compatible `^0.9.11`). The original
manifest `Cargo.toml.orig`, every Rust source file and all other upstream files
are byte-identical. The Rust source/API, including the public `OwnedBuffer`
identity, backing `Arc<Mmap>`, clone, slice and file-lifetime behavior is unchanged.
New public-API tests in `tests/mapped_buffers.rs` follow the upstream mapping,
relative-slice and ownership tests. No mapping implementation is replaced.

[RUSTSEC-2026-0186](https://rustsec.org/advisories/RUSTSEC-2026-0186.html)
identifies unchecked pointer arithmetic in memmap2 range advice/flush methods;
0.9.11 is the first patched release. shared-buffer itself uses `Mmap::map` and
checked slice indexing, without those advice/flush methods. This patch removes
the affected dependency rather than suppressing the advisory. memmap2 0.9.11
requires Rust 1.65; WLK builds with Rust 1.96. The unchanged upstream package's
1.64 Rust declaration describes its original source, not this dependency's MSRV.

## One package identity in each build

WLK's root `[patch.crates-io]` selects this path for all direct and WebC edges.
The directory is excluded from WLK's workspace membership so the 21 core crate
members stay unchanged; it remains a patched dependency. Dependency-level patch
sections are ignored by Cargo when WLK is consumed by another workspace.

The consuming Wasmer/Next workspace must therefore add its own root override,
using the exact **same published WLK revision** as its 21 core Git dependencies:

```toml
[patch.crates-io]
shared-buffer = { git = "https://github.com/wasmerio/wlk", rev = "<PUBLISHED_WLK_REVISION>", package = "shared-buffer" }
```

Cargo locates the package by name within the Git repository; no unsupported
`subdir` key is needed. Keep all registry requirements for shared-buffer 0.1.4
(including WebC's) subject to that single root patch. Do not add another copied
package or patch only the direct workspace dependency: that would split the
`OwnedBuffer` types passed across WebC/package interfaces. For local validation,
a single consuming root path patch to this exact directory serves the same role.

After the consuming root lock is resolved, verify there is exactly one
shared-buffer 0.1.4 package, sourced from this WLK revision, and no memmap2 0.6.x.
A consumer type check must pass a `shared_buffer::OwnedBuffer` to
`webc::v3::read::OwnedReader::parse` and bind a returned atom buffer to
`&shared_buffer::OwnedBuffer`; the existing WLK package-driver interfaces also
cross these types. Runtime tests should retain the existing package/WebC fixtures.

## Standalone upstream and mapped-buffer tests

Cargo cannot run a dependency's dev tests with workspace-root `-p shared-buffer`
because this package is deliberately excluded. Its existing exclusion already
gives `--manifest-path` a standalone workspace boundary; no manifest/API change
is necessary. The accompanying standalone `Cargo.lock` pins all 16 selected
packages to the exact versions and checksums in the WLK production lock, notably
memmap2 0.9.11. Its only extra dependency edge is upstream's existing dev
`tempfile`; the unused bytes-to-serde feature edge is absent. No registry
versions were upgraded to enable the tests. The production root lock is unchanged.

Run the original upstream tests and the added mapped lifetime/offset controls:

```sh
cargo test --locked --manifest-path third-party/shared-buffer/Cargo.toml
```

The standalone lock serves only these tests. It does not replace the consuming
root patch or alter the canonical `shared-buffer` dependency identity described
above. All upstream Rust/license bytes remain exactly as recorded in UPSTREAM.json.

Changes and tests were prepared by OpenAI Codex (AI agent). Independent review
and manager-controlled validation are required before acceptance.
