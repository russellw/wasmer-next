#!/bin/sh
# Smoke-test a wasixv2 sysroot of either build configuration: compile and link
# wasixv2/test/smoke.c against it, validate the module and check its imports,
# check that the Linux UAPI headers compile with libc's (wasixv2/test/uapi.c),
# and do the same for wasixv2/test/smoke.cpp with the C++ runtimes, if the
# sysroot has them.
#
#   wasixv2/test/run.sh <sysroot> [workdir]
#
# environment: LLVM_BIN or CC (clang), WASM_TOOLS (default wasm-tools)
set -eu

[ $# -ge 1 ] || { echo "usage: $0 <sysroot> [workdir]" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT=$(cd "$1" && pwd)
WORK=${2:-$(mktemp -d)}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)

CC=${CC:-${LLVM_BIN:+$LLVM_BIN/}clang}
WASM_TOOLS=${WASM_TOOLS:-wasm-tools}
LIBDIR=$SYSROOT/lib/wasm32-wasixv2
BUILTINS=$LIBDIR/libclang_rt.builtins.a
WASM=$WORK/smoke.wasm

for f in "$LIBDIR/crt1.o" "$LIBDIR/libc.a" "$BUILTINS" "$SYSROOT/include/stdio.h"; do
	[ -f "$f" ] || { echo "error: $f missing" >&2; exit 1; }
done

# Memory limit for the test; also exercises that user link flags win.
LDMEM=-Wl,--max-memory=1073741824

# The build configuration's ABI flags (see build-sysroot.sh). The wasix-org
# driver defaults to the eh configuration's; -fno-exceptions selects asyncify's.
CONFIG=$(sed -n 's/^ *"config": "\(.*\)",$/\1/p' "$SYSROOT/share/wasixv2/build-info.json" 2>/dev/null)
case ${CONFIG:-eh} in
eh)
	DRIVER_ABI=
	ABI="-pthread -ftls-model=local-exec -fwasm-exceptions -mllvm -wasm-use-legacy-eh=false -mllvm -wasm-enable-sjlj" ;;
asyncify)
	DRIVER_ABI="-fno-exceptions -mno-exception-handling"
	ABI="-pthread -ftls-model=local-exec -fno-exceptions -mno-exception-handling" ;;
*) echo "error: unknown build configuration $CONFIG" >&2; exit 1 ;;
esac
echo "==> configuration ${CONFIG:-eh}"

if "$CC" --target=wasm32-wasixv2 --no-default-config -dM -E -x c /dev/null 2>/dev/null |
	grep -q '__wasixv2__'; then
	# wasix-org/llvm-project: the driver provides the ABI flags, include
	# paths, crt1, --shared-memory and -lc. It looks for builtins only in
	# clang's resource dir, so pass the sysroot's copy explicitly.
	echo "==> linking with the wasm32-wasixv2 driver"
	HDRCHECK="--target=wasm32-wasixv2 --no-default-config --sysroot=$SYSROOT"
	link() { # <source> <output> [libraries before -lc]
		src=$1 out=$2; shift 2
		# shellcheck disable=SC2086
		set -- "$CC" --target=wasm32-wasixv2 --no-default-config --sysroot="$SYSROOT" \
			$DRIVER_ABI -O1 -nodefaultlibs "$src" "$@" -lpthread -lc "$BUILTINS" "$LDMEM" -o "$out"
		echo "$*"
		"$@"
	}
else
	# Upstream clang: everything spelled out.
	echo "==> linking with explicit flags (wasm32-unknown-unknown)"
	RES=$("$CC" -print-resource-dir)
	HDRCHECK="--target=wasm32-unknown-unknown --no-default-config -pthread -nostdinc \
		-isystem $SYSROOT/include -isystem $RES/include"
	link() { # <source> <output> [libraries before -lc]
		src=$1 out=$2; shift 2
		# shellcheck disable=SC2086
		set -- "$CC" --target=wasm32-unknown-unknown --no-default-config $ABI \
			-nostdinc -isystem "$SYSROOT/include/c++/v1" -isystem "$SYSROOT/include" \
			-isystem "$RES/include" -O1 -nostdlib "$LIBDIR/crt1.o" "$src" -L"$LIBDIR" "$@" -lc \
			"$BUILTINS" -Wl,--shared-memory -Wl,--import-memory -Wl,-z,stack-size=1048576 \
			"$LDMEM" -o "$out"
		echo "$*"
		"$@"
	}
fi

check() { # <module>
	echo "==> validating"
	"$WASM_TOOLS" validate "$1"

	echo "==> checking imports"
	"$WASM_TOOLS" print "$1" | grep -o '(import "[^"]*" "[^"]*"' |
		sed 's/(import "\([^"]*\)" "\([^"]*\)"/\1.\2/' | sort >"$WORK/imports.txt"
	tr '\n' ' ' <"$WORK/imports.txt"; echo
	bad=$(grep -v -e '^env\.memory$' -e '^wasixv2\.' "$WORK/imports.txt" || true)
	[ -z "$bad" ] || { echo "error: unexpected imports: $bad" >&2; exit 1; }
	grep -qx 'env.memory' "$WORK/imports.txt" || { echo "error: env.memory not imported" >&2; exit 1; }
}

link "$HERE/smoke.c" "$WASM"
check "$WASM"

echo "==> checking the Linux UAPI headers"
# shellcheck disable=SC2086
"$CC" $HDRCHECK -Wall -Werror -fsyntax-only "$HERE/uapi.c"

if [ -f "$LIBDIR/libc++.a" ]; then
	echo "==> linking the C++ smoke test"
	link "$HERE/smoke.cpp" "$WORK/smoke-cxx.wasm" -lc++ -lc++abi
	check "$WORK/smoke-cxx.wasm"
else
	echo "==> no C++ runtimes in the sysroot, skipping the C++ smoke test"
fi

echo "==> smoke test built and checked"
