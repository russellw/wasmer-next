#!/bin/sh
# Build the wasixv2 sysroot: libc2 (musl), compiler-rt builtins and the C++
# runtimes (libc++, libc++abi, libunwind).
#
# This is the single build entry point for local builds, CI and releases.
# See wasixv2/README.md for the layout it produces.
set -eu

usage() {
	cat <<EOF
usage: $0 [options]

Builds <out>/sysroot-wasixv2/{include,lib/wasm32-wasixv2,...}, or
<out>/sysroot-wasixv2-asyncify for the asyncify configuration.

options:
  -o, --out DIR      output directory (default: ./build-wasixv2)
  --target TRIPLE    wasm32-wasixv2, wasm32-unknown-unknown or auto (default).
                     auto picks wasm32-wasixv2 if the compiler defines
                     __wasixv2__ for it (wasix-org/llvm-project), else
                     wasm32-unknown-unknown (upstream clang).
  --config CONFIG    the build configuration: eh (default), with wasm
                     exception handling, ehpic with PIC and native EH, or asyncify without EH, for
                     programs that fork (see wasixv2/README.md)
  --no-cxx           skip the C++ runtimes (libc++, libc++abi, libunwind)
  --package          also write <out>/<sysroot>.tar.gz and
                     <out>/sha256sums.txt (sha256sums-asyncify.txt for
                     the asyncify configuration)
  -j N               parallel jobs (default: nproc)
  -h, --help         this help

environment:
  LLVM_BIN           directory with clang, llvm-ar and llvm-ranlib
                     (default: look them up in PATH)
  CC, AR, RANLIB     override the individual tools (a single path each)
  LLVM_SRC           llvm-project checkout to build compiler-rt and the C++
                     runtimes from. Default: a sparse checkout of them at
                     the llvmorg-\$LLVM_VERSION tag (wasixv2/toolchain.env),
                     cached in <out>/src.
  LINUX_SRC          Linux checkout to install the UAPI headers from (a
                     clean tree; it is built out of tree). Default: a
                     sparse checkout at the \$LINUX_UAPI_TAG tag
                     (wasixv2/toolchain.env), cached in <out>/src.
  SOURCE_DATE_EPOCH  timestamp for the tarball (default: HEAD commit time)
EOF
}

SRC=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$SRC/wasixv2/toolchain.env"

OUT=build-wasixv2
TARGET=auto
CONFIG=eh
PACKAGE=0
CXX_RUNTIMES=1
JOBS=$(nproc 2>/dev/null || echo 4)
while [ $# -gt 0 ]; do
	case $1 in
	-o|--out) OUT=$2; shift 2 ;;
	--target) TARGET=$2; shift 2 ;;
	--config) CONFIG=$2; shift 2 ;;
	--no-cxx) CXX_RUNTIMES=0; shift ;;
	--package) PACKAGE=1; shift ;;
	-j) JOBS=$2; shift 2 ;;
	-j*) JOBS=${1#-j}; shift ;;
	-h|--help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
	esac
done

case $CONFIG in
eh) SUFFIX= ;;
asyncify) SUFFIX=-asyncify ;;
ehpic) SUFFIX=-ehpic ;;
*) echo "error: unknown configuration $CONFIG" >&2; exit 2 ;;
esac

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
SYSROOT_NAME=sysroot-wasixv2$SUFFIX
SYSROOT=$OUT/$SYSROOT_NAME
BUILD=$OUT/build$SUFFIX
LIBDIR=lib/wasm32-wasixv2

tool() { if [ -n "${LLVM_BIN:-}" ]; then echo "$LLVM_BIN/$1"; else command -v "$1" || echo "$1"; fi; }
CC=${CC:-$(tool clang)}
AR=${AR:-$(tool llvm-ar)}
RANLIB=${RANLIB:-$(tool llvm-ranlib)}
for t in "$CC" "$AR" "$RANLIB"; do
	command -v "$t" >/dev/null || { echo "error: $t not found (set LLVM_BIN or CC/AR/RANLIB)" >&2; exit 1; }
done
# CMake needs full paths for its archiver, e.g. AR=wasixar.
AR=$(command -v "$AR")
RANLIB=$(command -v "$RANLIB")

log() { printf '==> %s\n' "$*" >&2; }

# --- target selection -------------------------------------------------------

if [ "$TARGET" = auto ]; then
	if "$CC" --target=wasm32-wasixv2 --no-default-config -dM -E -x c /dev/null 2>/dev/null |
		grep -q '__wasixv2__'; then
		TARGET=wasm32-wasixv2
	else
		TARGET=wasm32-unknown-unknown
	fi
fi
case $TARGET in
wasm32-wasixv2|wasm32-unknown-wasixv2|wasm32-unknown-unknown) ;;
*) echo "error: unsupported target $TARGET" >&2; exit 2 ;;
esac

# --no-default-config keeps a fork release's .cfg (which sets --sysroot) out
# of the build.
TFLAGS="--target=$TARGET --no-default-config"
# The code generation flags that are part of the wasixv2 ABI, per build
# configuration. Keep in sync with arch/wasm32/arch.mak, which applies them to
# libc itself.
case $CONFIG in
eh|ehpic) ABI_CFLAGS="-pthread -ftls-model=local-exec -fwasm-exceptions -mllvm -wasm-use-legacy-eh=false -mllvm -wasm-enable-sjlj" ;;
asyncify) ABI_CFLAGS="-pthread -ftls-model=local-exec -fno-exceptions -mno-exception-handling" ;;
esac
if [ "$CONFIG" = ehpic ]; then ABI_CFLAGS="$ABI_CFLAGS -fPIC"; fi

# libc++ takes its platform code paths (the futex for atomic waits, the random
# device, the time zone database) from the target, which must be Linux, as
# wasm32-wasixv2 is. For wasm32-unknown-unknown it builds generic fallbacks or
# not at all, so the C++ runtimes need the wasix-org clang.
if [ "$CXX_RUNTIMES" = 1 ] && [ "$TARGET" != wasm32-wasixv2 ]; then
	echo "error: the C++ runtimes need the wasm32-wasixv2 target (wasix-org/llvm-project);" \
		"pass --no-cxx to build $TARGET without them" >&2
	exit 2
fi

CC_VERSION=$("$CC" --version | head -n1)
log "compiler: $CC_VERSION"
log "target:   $TARGET"
log "config:   $CONFIG"
log "output:   $SYSROOT"

rm -rf "$SYSROOT" "$BUILD/libc" "$BUILD/builtins" "$BUILD/runtimes"
mkdir -p "$SYSROOT" "$BUILD/libc" "$BUILD/builtins"

# --- libc -------------------------------------------------------------------

log "configuring libc"
(
	cd "$BUILD/libc"
	"$SRC/configure" --target="$TARGET" --prefix= --includedir=/include \
		--libdir="/$LIBDIR" --disable-shared --disable-wrapper \
		CC="$CC $TFLAGS" AR="$AR" RANLIB="$RANLIB" \
		CFLAGS="-ffile-prefix-map=$SRC=/libc2" >configure.log 2>&1 ||
		{ cat configure.log >&2; exit 1; }
)
log "building libc"
make -C "$BUILD/libc" -j"$JOBS" WASIXV2_CONFIG="$CONFIG" >"$BUILD/libc/make.log" 2>&1 ||
	{ tail -n 50 "$BUILD/libc/make.log" >&2; exit 1; }
make -C "$BUILD/libc" install-headers install-libs WASIXV2_CONFIG="$CONFIG" DESTDIR="$SYSROOT" >/dev/null

# --- Linux UAPI headers -----------------------------------------------------

# The target is Linux (clang defines __linux__), so the sysroot ships the
# kernel's UAPI headers next to libc's, as a distribution's linux-headers
# package does. riscv's: wasixv2's struct layouts and constants follow riscv32.
if [ -z "${LINUX_SRC:-}" ]; then
	LINUX_SRC=$OUT/src/linux-$LINUX_UAPI_TAG
	if [ ! -f "$LINUX_SRC/Makefile" ]; then
		log "fetching Linux $LINUX_UAPI_TAG"
		rm -rf "$LINUX_SRC"
		mkdir -p "$LINUX_SRC"
		git -C "$LINUX_SRC" init -q
		git -C "$LINUX_SRC" remote add origin "$LINUX_REPO"
		git -C "$LINUX_SRC" sparse-checkout set include arch/riscv scripts usr tools/include
		git -C "$LINUX_SRC" fetch -q --depth 1 --filter=blob:none origin "$LINUX_UAPI_COMMIT"
		git -C "$LINUX_SRC" -c advice.detachedHead=false checkout -q FETCH_HEAD
	fi
	got=$(git -C "$LINUX_SRC" rev-parse HEAD)
	[ "$got" = "$LINUX_UAPI_COMMIT" ] || { echo "error: $LINUX_SRC is at $got, expected $LINUX_UAPI_COMMIT" >&2; exit 1; }
fi
LINUX_SRC=$(cd "$LINUX_SRC" && pwd)
LINUX_SRC_REV=$(git -C "$LINUX_SRC" rev-parse HEAD 2>/dev/null || echo unknown)

log "installing Linux UAPI headers ($LINUX_SRC)"
rm -rf "$BUILD/linux"
mkdir -p "$BUILD/linux"
make -s -C "$LINUX_SRC" O="$BUILD/linux/obj" ARCH=riscv headers_install \
	INSTALL_HDR_PATH="$BUILD/linux/install" >"$BUILD/linux/build.log" 2>&1 ||
	{ cat "$BUILD/linux/build.log" >&2; exit 1; }
UAPI=$BUILD/linux/install/include
# The syscall numbers are the wasixv2 ABI's, which libc's <sys/syscall.h>
# carries; riscv32's differ for lseek and mmap. riscv's generated number lists,
# which only its asm/unistd.h includes, go.
rm -f "$UAPI/asm/unistd_32.h" "$UAPI/asm/unistd_64.h"
cat >"$UAPI/asm/unistd.h" <<'UNISTD'
/* wasixv2: the syscall numbers are libc2's, which are the wasixv2 ABI's. */
#include <sys/syscall.h>
UNISTD
# Backport the supported Landlock flag from Linux include/uapi/linux/landlock.h;
# the pinned 7.2 headers predate security/landlock/syscalls.c's NNP convenience flag.
cat >>"$UAPI/linux/landlock.h" <<'LANDLOCK'
#ifndef LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS
#define LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS (1U << 4)
#endif
LANDLOCK
# Kernel and libc headers share directories (scsi/), never files.
clash=$(cd "$UAPI" && find . -type f | while read -r f; do
	if [ -e "$SYSROOT/include/$f" ]; then echo "$f"; fi
done)
[ -z "$clash" ] || { echo "error: Linux UAPI headers clash with libc's:" $clash >&2; exit 1; }
cp -R "$UAPI/." "$SYSROOT/include/"

# --- compiler-rt builtins ---------------------------------------------------

if [ -z "${LLVM_SRC:-}" ]; then
	LLVM_SRC=$OUT/src/llvm-project-$LLVM_VERSION
	if [ ! -d "$LLVM_SRC/compiler-rt/lib/builtins" ] || [ ! -d "$LLVM_SRC/llvm/cmake/modules" ] ||
		[ ! -d "$LLVM_SRC/runtimes" ] || [ ! -d "$LLVM_SRC/libc/shared" ]; then
		log "fetching compiler-rt and the C++ runtimes $LLVM_VERSION"
		rm -rf "$LLVM_SRC"
		mkdir -p "$LLVM_SRC"
		git -C "$LLVM_SRC" init -q
		git -C "$LLVM_SRC" remote add origin "$LLVM_REPO"
		# libc++ uses LLVM libc's header-only shared utilities (libc/shared).
		git -C "$LLVM_SRC" sparse-checkout set compiler-rt cmake llvm/cmake \
			runtimes libcxx libcxxabi libunwind \
			libc/shared libc/src/__support libc/hdr libc/include
		git -C "$LLVM_SRC" fetch -q --depth 1 --filter=blob:none origin "$LLVM_COMMIT"
		git -C "$LLVM_SRC" -c advice.detachedHead=false checkout -q FETCH_HEAD
	fi
	got=$(git -C "$LLVM_SRC" rev-parse HEAD)
	[ "$got" = "$LLVM_COMMIT" ] || { echo "error: $LLVM_SRC is at $got, expected $LLVM_COMMIT" >&2; exit 1; }
fi
LLVM_SRC=$(cd "$LLVM_SRC" && pwd)
LLVM_SRC_REV=$(git -C "$LLVM_SRC" rev-parse HEAD 2>/dev/null || echo unknown)

if command -v ninja >/dev/null; then GEN=Ninja; else GEN="Unix Makefiles"; fi
log "configuring compiler-rt builtins ($LLVM_SRC)"
BFLAGS="--no-default-config $ABI_CFLAGS -ffile-prefix-map=$LLVM_SRC=/llvm-project"
cmake -G "$GEN" -S "$LLVM_SRC/compiler-rt/lib/builtins" -B "$BUILD/builtins" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_SYSTEM_NAME=Generic \
	-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CC" -DCMAKE_ASM_COMPILER="$CC" \
	-DCMAKE_AR="$AR" -DCMAKE_RANLIB="$RANLIB" \
	-DCMAKE_C_COMPILER_TARGET="$TARGET" -DCMAKE_CXX_COMPILER_TARGET="$TARGET" \
	-DCMAKE_ASM_COMPILER_TARGET="$TARGET" \
	-DCMAKE_C_COMPILER_WORKS=ON -DCMAKE_CXX_COMPILER_WORKS=ON -DCMAKE_ASM_COMPILER_WORKS=ON \
	-DCMAKE_C_FLAGS="$BFLAGS" -DCMAKE_CXX_FLAGS="$BFLAGS" -DCMAKE_ASM_FLAGS="$BFLAGS" \
	-DCMAKE_SYSROOT="$SYSROOT" \
	-DCOMPILER_RT_BAREMETAL_BUILD=ON \
	-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
	-DCOMPILER_RT_BUILTINS_ENABLE_PIC=OFF \
	-DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=ON \
	-DCMAKE_INSTALL_PREFIX="$BUILD/builtins/install" \
	>"$BUILD/builtins/cmake.log" 2>&1 || { cat "$BUILD/builtins/cmake.log" >&2; exit 1; }
log "building compiler-rt builtins"
cmake --build "$BUILD/builtins" -j"$JOBS" >"$BUILD/builtins/build.log" 2>&1 ||
	{ tail -n 50 "$BUILD/builtins/build.log" >&2; exit 1; }
cmake --install "$BUILD/builtins" >/dev/null
BUILTINS=$(find "$BUILD/builtins/install" -name 'libclang_rt.builtins*.a' | head -n1)
[ -n "$BUILTINS" ] || { echo "error: no builtins library was built" >&2; exit 1; }
cp "$BUILTINS" "$SYSROOT/$LIBDIR/libclang_rt.builtins.a"

# --- C++ runtimes -----------------------------------------------------------

# libc++, libc++abi and, with wasm exception handling, libunwind, built from
# the same llvm-project source as the builtins, against the libc and builtins
# above. The asyncify configuration has no C++ exceptions: binaryen's asyncify
# cannot instrument wasm exception handling, and there is no other lowering of
# them for wasm outside Emscripten's JavaScript runtime. There libc++ is built
# with -fno-exceptions, as programs are, and needs no unwinder.
#
# libunwind's wasm unwinder (Unwind-wasm.c, the personality glue for wasm EH)
# is merged into libc++abi.a, so the -lc++ -lc++abi the clang driver passes
# for C++ links is all a program needs; libunwind.a is installed as well, for
# build systems that ask for -lunwind.
#
# libunwind's symbols are hidden: they are for libc++abi in the same static
# link, and libunwind 22 spells exports on wasm, which is not ELF, as
# __declspec(dllexport) otherwise.
#
# ABI version 2, as wasi-sdk and Emscripten use for wasm: wasixv2 has no
# existing C++ binaries to stay compatible with.
LIBCXX_ABI_VERSION=2
case $CONFIG in
eh) CXX_EXCEPTIONS=ON; CXX_RUNTIME_LIST="libcxx;libcxxabi;libunwind" ;;
asyncify) CXX_EXCEPTIONS=OFF; CXX_RUNTIME_LIST="libcxx;libcxxabi" ;;
esac

if [ "$CXX_RUNTIMES" = 1 ]; then
	mkdir -p "$BUILD/runtimes"
	log "configuring the C++ runtimes ($CXX_RUNTIME_LIST)"
	RFLAGS="--no-default-config $ABI_CFLAGS -ffile-prefix-map=$LLVM_SRC=/llvm-project"
	# CMake's checks link test programs; give them what the driver would
	# (libc and the sysroot's builtins, see wasixv2/README.md).
	RLIBS="-lc $SYSROOT/$LIBDIR/libclang_rt.builtins.a"
	cmake -G "$GEN" -S "$LLVM_SRC/runtimes" -B "$BUILD/runtimes" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=wasm32 \
		-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CC" -DCMAKE_ASM_COMPILER="$CC" \
		-DCMAKE_AR="$AR" -DCMAKE_RANLIB="$RANLIB" \
		-DCMAKE_C_COMPILER_TARGET="$TARGET" -DCMAKE_CXX_COMPILER_TARGET="$TARGET" \
		-DCMAKE_ASM_COMPILER_TARGET="$TARGET" \
		-DCMAKE_C_COMPILER_WORKS=ON -DCMAKE_CXX_COMPILER_WORKS=ON -DCMAKE_ASM_COMPILER_WORKS=ON \
		-DCMAKE_C_FLAGS="$RFLAGS" -DCMAKE_CXX_FLAGS="$RFLAGS" -DCMAKE_ASM_FLAGS="$RFLAGS" \
		-DCMAKE_EXE_LINKER_FLAGS=-nodefaultlibs \
		-DCMAKE_C_STANDARD_LIBRARIES="$RLIBS" -DCMAKE_CXX_STANDARD_LIBRARIES="$RLIBS" \
		-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES="CMAKE_C_STANDARD_LIBRARIES;CMAKE_CXX_STANDARD_LIBRARIES" \
		-DCMAKE_SYSROOT="$SYSROOT" \
		-DCMAKE_INSTALL_PREFIX="$SYSROOT" \
		-DLLVM_ENABLE_RUNTIMES="$CXX_RUNTIME_LIST" \
		-DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF \
		-DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_DOCS=OFF \
		-DLIBCXX_INSTALL_LIBRARY_DIR="$LIBDIR" \
		-DLIBCXXABI_INSTALL_LIBRARY_DIR="$LIBDIR" \
		-DLIBUNWIND_INSTALL_LIBRARY_DIR="$LIBDIR" \
		-DLIBCXX_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBUNWIND_ENABLE_SHARED=OFF \
		-DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
		-DLIBCXXABI_INCLUDE_TESTS=OFF -DLIBUNWIND_INCLUDE_TESTS=OFF \
		-DLIBCXX_ABI_VERSION="$LIBCXX_ABI_VERSION" \
		-DLIBCXX_CXX_ABI=libcxxabi \
		-DLIBCXX_HAS_MUSL_LIBC=ON \
		-DLIBCXX_ENABLE_THREADS=ON -DLIBCXX_HAS_PTHREAD_API=ON \
		-DLIBCXXABI_ENABLE_THREADS=ON -DLIBCXXABI_HAS_PTHREAD_API=ON \
		-DLIBCXX_ENABLE_EXCEPTIONS="$CXX_EXCEPTIONS" \
		-DLIBCXXABI_ENABLE_EXCEPTIONS="$CXX_EXCEPTIONS" \
		-DLIBCXXABI_USE_LLVM_UNWINDER="$CXX_EXCEPTIONS" \
		-DLIBCXXABI_ENABLE_STATIC_UNWINDER="$CXX_EXCEPTIONS" \
		-DLIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY="$CXX_EXCEPTIONS" \
		-DLIBUNWIND_HIDE_SYMBOLS=ON -DLIBUNWIND_INSTALL_HEADERS=OFF \
		-DLIBCXX_INSTALL_MODULES=OFF \
		>"$BUILD/runtimes/cmake.log" 2>&1 || { cat "$BUILD/runtimes/cmake.log" >&2; exit 1; }
	log "building the C++ runtimes"
	cmake --build "$BUILD/runtimes" -j"$JOBS" >"$BUILD/runtimes/build.log" 2>&1 ||
		{ tail -n 50 "$BUILD/runtimes/build.log" >&2; exit 1; }
	cmake --install "$BUILD/runtimes" >"$BUILD/runtimes/install.log"
	for f in libc++.a libc++abi.a; do
		[ -f "$SYSROOT/$LIBDIR/$f" ] || { echo "error: $LIBDIR/$f was not installed" >&2; exit 1; }
	done
	CXX_INFO="\"cxx_runtimes\": \"$CXX_RUNTIME_LIST\",
  \"cxx_exceptions\": $( [ "$CXX_EXCEPTIONS" = ON ] && echo true || echo false ),
  \"libcxx_abi_version\": $LIBCXX_ABI_VERSION,"
else
	CXX_INFO="\"cxx_runtimes\": \"\","
fi

# --- version info -----------------------------------------------------------

LIBC2_REV=$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)
LIBC2_DESC=$(git -C "$SRC" describe --tags --always --dirty 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$SRC" log -1 --format=%ct 2>/dev/null || date +%s)}
MUSL_VERSION=$(cat "$SRC/VERSION")
echo "$LIBC2_DESC" >"$SYSROOT/VERSION"
mkdir -p "$SYSROOT/share/wasixv2"
cat >"$SYSROOT/share/wasixv2/build-info.json" <<EOF
{
  "libc2_commit": "$LIBC2_REV",
  "libc2_describe": "$LIBC2_DESC",
  "musl_version": "$MUSL_VERSION",
  "target": "$TARGET",
  "config": "$CONFIG",
  "compiler": "$CC_VERSION",
  "abi_cflags": "$ABI_CFLAGS",
  "compiler_rt_version": "$LLVM_VERSION",
  "compiler_rt_commit": "$LLVM_SRC_REV",
  "linux_uapi_version": "$LINUX_UAPI_TAG",
  "linux_uapi_commit": "$LINUX_SRC_REV",
  $CXX_INFO
  "builtins": "$LIBDIR/libclang_rt.builtins.a"
}
EOF

log "sysroot ready: $SYSROOT"

# --- package ----------------------------------------------------------------

if [ "$PACKAGE" = 1 ]; then
	log "packaging"
	(
		cd "$OUT"
		tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
			--format=gnu -cf - "$SYSROOT_NAME" | gzip -9n >"$SYSROOT_NAME.tar.gz"
		sha256sum "$SYSROOT_NAME.tar.gz" >"sha256sums$SUFFIX.txt"
		cat "sha256sums$SUFFIX.txt" >&2
	)
fi
