#!/bin/sh
# Download the pinned upstream LLVM release (wasixv2/toolchain.env) and unpack
# the parts needed to build the sysroot into DIR: clang, wasm-ld, llvm-ar,
# llvm-ranlib and clang's resource headers. Use with LLVM_BIN=DIR/bin.
# Used by CI; does nothing if DIR already holds this version.
# LLVM_TARBALL_FILE=<path> uses an already downloaded tarball.
set -eu

[ $# -eq 1 ] || { echo "usage: $0 DIR" >&2; exit 2; }
SRC=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$SRC/wasixv2/toolchain.env"
DIR=$1
STAMP=$DIR/.tarball-sha256

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$LLVM_TARBALL_SHA256" ]; then
	echo "LLVM $LLVM_VERSION already in $DIR"
	exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "${LLVM_TARBALL_FILE:-}" ]; then
	cp "$LLVM_TARBALL_FILE" "$TMP/$LLVM_TARBALL"
else
	url=https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VERSION/$LLVM_TARBALL
	echo "downloading $url"
	curl -fsSL --retry 3 -o "$TMP/$LLVM_TARBALL" "$url"
fi
echo "$LLVM_TARBALL_SHA256  $TMP/$LLVM_TARBALL" | sha256sum -c -

major=${LLVM_VERSION%%.*}
top=${LLVM_TARBALL%.tar.xz}
rm -rf "$DIR"
mkdir -p "$DIR"
tar -xJf "$TMP/$LLVM_TARBALL" -C "$DIR" --strip-components=1 \
	"$top/bin/clang" "$top/bin/clang-$major" \
	"$top/bin/lld" "$top/bin/wasm-ld" \
	"$top/bin/llvm-ar" "$top/bin/llvm-ranlib" \
	"$top/lib/clang/$major/include"
echo "$LLVM_TARBALL_SHA256" >"$STAMP"
"$DIR/bin/clang" --version | head -n1
