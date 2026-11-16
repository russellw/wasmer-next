#!/usr/bin/env bash
set -euo pipefail

# These are exact nixpkgs static-musl outputs already published by the signed
# cache.nixos.org binary cache. `nix copy` only substitutes these store paths;
# it does not evaluate a flake or build packages locally.
BASH_STORE_PATH=/nix/store/26d5h7013nhfqzsdpjnxl0ylnh1k9lhq-bash-interactive-static-x86_64-unknown-linux-musl-5.3p20
BASH_NAR_HASH=sha256-DQjDxpMQxu+HBG6XxBbLVROWJsqazCGxuThebpwbTfc=
BASH_SHA256=9adeea840fa8e4bca571157cf0210800e5a0882f6be45e75f8bf42dfd5dd75a7
BUSYBOX_STORE_PATH=/nix/store/yfcblx3wfc52q8lyrvqdpsnqkqh21wfs-busybox-static-x86_64-unknown-linux-musl-1.37.0
BUSYBOX_NAR_HASH=sha256-o0dZE2RRsqilH94QMyMn0RuVKj5LF5i7NUEuWkzHExQ=
BUSYBOX_SHA256=85c9a89cb5dd89731a0c518a5fd9491997caaf3f58742813ff03a5274ba4d915
CACHE_URL=https://cache.nixos.org

here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
out_dir="${1:-$here}"

if [[ "$(uname -m)" != x86_64 ]]; then
    echo "static fixture downloads are available for x86_64 only" >&2
    exit 1
fi
if ! command -v nix >/dev/null || ! command -v sha256sum >/dev/null; then
    echo "download-fixtures.sh requires Nix and sha256sum" >&2
    exit 1
fi

mkdir -p -- "$out_dir"
out_dir="$(cd -- "$out_dir" && pwd -P)"
tmp_dir="$(mktemp -d "$out_dir/.fixture-download.XXXXXX")"
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

nix --extra-experimental-features nix-command copy \
    --from "$CACHE_URL" \
    "$BASH_STORE_PATH" "$BUSYBOX_STORE_PATH"

verify_store_path() {
    local path="$1" expected_nar="$2"
    local actual_nar
    actual_nar="$(nix --extra-experimental-features nix-command hash path --type sha256 --sri "$path")"
    if [[ "$actual_nar" != "$expected_nar" ]]; then
        echo "NAR hash mismatch for $path: expected $expected_nar, got $actual_nar" >&2
        exit 1
    fi
}

verify_binary() {
    local path="$1" expected_sha="$2"
    local actual_sha
    actual_sha="$(sha256sum "$path")"
    actual_sha="${actual_sha%% *}"
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "SHA256 mismatch for $path: expected $expected_sha, got $actual_sha" >&2
        exit 1
    fi
}

verify_store_path "$BASH_STORE_PATH" "$BASH_NAR_HASH"
verify_store_path "$BUSYBOX_STORE_PATH" "$BUSYBOX_NAR_HASH"

install_verified() {
    local source="$1" expected_sha="$2" name="$3"
    local staged="$tmp_dir/$name"
    cp -- "$source" "$staged"
    chmod 0755 "$staged"
    verify_binary "$staged" "$expected_sha"
}

install_verified "$BASH_STORE_PATH/bin/bash" "$BASH_SHA256" bash
install_verified "$BUSYBOX_STORE_PATH/bin/busybox" "$BUSYBOX_SHA256" busybox

# Both files are checked before either existing fixture is replaced.
mv -fT -- "$tmp_dir/bash" "$out_dir/bash"
mv -fT -- "$tmp_dir/busybox" "$out_dir/busybox"

echo "Installed verified static x86_64 musl Bash and BusyBox in $out_dir"
