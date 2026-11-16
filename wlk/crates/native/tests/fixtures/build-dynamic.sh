#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "$0")" && pwd)"
src="$here/src"
variant="${DYNAMIC_VARIANT:-glibc}"
out="${DYNAMIC_OUT:-$here/dynamic-libs/$variant}"
cc="${DYNAMIC_CC:-gcc}"

mkdir -p "$out/bin" "$out/lib"

"$cc" -O2 -Wall -Wextra -fPIC -shared -Wl,--build-id=none \
    -Wl,-soname,libdynamic_leaf.so \
    "$src/dynamic_leaf.c" -o "$out/lib/libdynamic_leaf.so"

"$cc" -O2 -Wall -Wextra -fPIC -shared -Wl,--build-id=none \
    -Wl,-soname,libdynamic_middle.so \
    -Wl,-rpath,'$ORIGIN' \
    "$src/dynamic_middle.c" -L"$out/lib" -ldynamic_leaf \
    -o "$out/lib/libdynamic_middle.so"

"$cc" -O2 -Wall -Wextra -fPIC -shared -Wl,--build-id=none \
    -Wl,-soname,libdynamic_plugin.so \
    "$src/dynamic_plugin.c" -o "$out/lib/libdynamic_plugin.so"

"$cc" -O2 -Wall -Wextra -Wl,--build-id=none \
    -Wl,-rpath,'$ORIGIN/../lib' \
    "$src/dynamic_smoke.c" -pthread -ldl \
    -L"$out/lib" -ldynamic_middle -o "$out/bin/dynamic_smoke"

printf '%s\n' "$variant" > "$out/variant"
for library in ld-linux-x86-64.so.2 ld-musl-x86_64.so.1 libc.so.6 libc.so \
    libdl.so.2 libpthread.so.0 libgcc_s.so.1; do
    printf '%s=%s\n' "$library" "$($cc -print-file-name="$library")"
done > "$out/runtime-libraries"
