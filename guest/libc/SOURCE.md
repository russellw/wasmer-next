# Source provenance

Plain import of https://github.com/wasix-org/libc2 at
`ce830d6e76e8e999e4ee0396583300c235aaecf0` (`snapshot/wasixv2-20261105`).
No upstream history, `.git`, or nested ABI/test submodule contents are imported.
At import time main (`01bff0a2610c5c13a0b6989e2f07007f2c68887c`) was an ancestor
of the snapshot, so the runtime-compatible snapshot was selected.

The canonical generator is `../../lib/wasix/codegen`, and the guest suite is
`../../tests/wasixv2`. CI lives in `.github/workflows/guest-libc.yml` at the
repository root. The old standalone release workflow is retired; guest release
publishing needs a separate policy and is not triggered by Wasmer tags.
Build-info revision fields identify the containing Wasmer checkout after import.
