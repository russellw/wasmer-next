# Extraction provenance

The initial contents of this repository were copied from `wasmerio/wasmer`, branch `feat/wasixv2`, commit `d6850e337cfa40ce19e53fc534ff2a79231826bf` (2026-11-05). The audited proposed boundary is recorded in that source revision at `lib/wasix/REPOSITORY-SPLIT.md`.

The extraction moves these 21 crates, preserving package names and source APIs: `abi`, `syscalls`, `wait`, `pages`, `host`, `kernel`, `vfs`, `vfs-mem`, `vfs-host`, `vfs-overlay`, `vfs-package`, `vfs-web`, `vnet`, `vnet-host`, `vnet-switch`, `vnet-web`, `stdio-web`, `trace`, `record`, `policy`, and `checkpoint`.

The canonical `wasixv2-codegen` submodule and its generated-output test remain in Wasmer. The `vnet-web` codec and relay reference tests remain there because they use Wasmer's `virtual-net` implementation. Wasmer-specific `api`, `exec`, `dylink`, and `wasix1` crates also remain in the main repository. This extraction does not implement snapshot/restore; `wasixv2-checkpoint` remains a documentation-only stub from the source revision.

License and copyright terms are preserved from Wasmer's MIT-licensed source. The original source repository and revision above identify the provenance of the moved files.
