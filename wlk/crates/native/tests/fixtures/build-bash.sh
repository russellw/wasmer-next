#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "$0")" && pwd)"
out_link="$here/.bash-nix"

nix --extra-experimental-features 'nix-command flakes' build \
    'nixpkgs#pkgsCross.musl64.pkgsStatic.bash' \
    --out-link "$out_link"
install -m 0755 "$out_link/bin/bash" "$here/bash"
