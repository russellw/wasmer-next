# libc2: musl for WASIX (wasixv2)

libc2 is a fork of [musl](https://musl.libc.org/) v1.2.6 with a `wasm32` port that targets
**wasixv2**. wasixv2 exposes the Linux syscall ABI to WebAssembly guests:

- Syscalls are those of Linux asm-generic 32-bit (time64-only), exactly as on riscv32, the
  reference arch for the syscall set, struct layouts and constants.
- Each syscall is a typed wasm import. The module is `wasixv2` and the import name is the riscv32
  syscall table name, e.g. `wasixv2.openat` or `wasixv2.futex_time64`.
- Return values follow the raw Linux convention: the value, or `-errno`.
- Arguments that riscv32 splits into two 32-bit registers are one `i64` parameter, e.g.
  `pread64(fd, buf, count, pos: i64)`.
- Where riscv32 only has a workaround for 32-bit registers, the import uses the 64-bit form
  under riscv32's number: `lseek(fd, offset: i64, whence) -> i64` instead of `llseek`, and `mmap`
  with a byte offset (`i64`) instead of `mmap2`.
- Wasm-specific primitives (startup, and later thread spawn, fork and signal delivery) are
  extensions in the same `wasixv2` module, e.g. `wasixv2.startup_get`. Their names never collide
  with syscall names.

The canonical WIT and generator live at `../../../lib/wasix/codegen` relative to
this directory (`../../lib/wasix/codegen` from the libc root). Generated C is
checked by `cargo test -p wasixv2-codegen --test guest_libc --locked` at the
repository root. This is a plain import of libc2 without its upstream history;
see `../SOURCE.md`.

## Test suite

The wasixv2 test suite is tracked at `../../tests/wasixv2` from the libc root. Besides its own programs it runs
musl's libc-test, the Open POSIX Test Suite and LTP, which are submodules of it, so check it out
recursively. `make wasixv2-test` builds the sysroots in `build-wasixv2/` (see below) and runs the
suite against them:

```sh
git -C ../.. submodule update --init --recursive
make wasixv2-test
```

It needs, on `PATH`, `wasixcc` with `wasm32-wasixv2` and `PURE` support and a `wasmer` that runs
wasixv2 modules, which for now means one built from wasmerio/wasmer's `feat/wasixv2` branch
(`WASIXV2_TESTS_WASMER` selects another binary). The tests build against this repository's
`build-wasixv2/sysroot-wasixv2` (and `sysroot-wasixv2-asyncify` for the tests that fork); wasixcc's other settings, such as `WASIXCC_LLVM_LOCATION`, come
from the environment. `WASIXV2_TESTS_ARGS` passes test filters to the runner. Most tests are expected
to fail until wasixv2 is complete: the suite's `expected-failures.txt` lists them. CI does not run
it yet.

## Building the sysroot

`wasixv2/build-sysroot.sh` is the one build entry point, used locally, in CI and for releases. It
configures and builds musl out of tree, builds compiler-rt builtins and the C++ runtimes, and
assembles the sysroot.
`make wasixv2-sysroot` runs it with the default output directory, `build-wasixv2`, whose
`sysroot-wasixv2` is laid out the way wasixcc expects under its `SYSROOT_PREFIX`. It builds with
wasixcc in `PURE` mode (`CC=wasixcc AR=wasixar RANLIB=wasixranlib`, `WASIXCC_PURE=yes`,
`WASIXCC_TARGET=wasm32-wasixv2`), which passes every argument through to the LLVM wasixcc uses for
wasm32-wasixv2. The libc and the programs built against it then share one toolchain, found the
way wasixcc finds it: `WASIXCC_LLVM_LOCATION`, or wasixcc's download. This needs a wasixcc with
`PURE` support (wasix-org/wasixcc#87 for now).

Requirements: clang and lld ≥ 20 with the wasm32 target, `llvm-ar`/`llvm-ranlib`, cmake, git and
make (ninja is used if present). With nix:

```sh
nix shell nixpkgs#llvmPackages_latest.clang-unwrapped \
          nixpkgs#llvmPackages_latest.lld \
          nixpkgs#llvmPackages_latest.bintools-unwrapped \
          nixpkgs#cmake nixpkgs#ninja nixpkgs#python3 \
  -c wasixv2/build-sysroot.sh -o build-wasixv2
```

Tools come from `PATH`, from `LLVM_BIN=<dir>` or from `CC`/`AR`/`RANLIB`. `--package` also writes
`sysroot-wasixv2.tar.gz` and `sha256sums.txt`. `--config asyncify` builds the asyncify configuration
instead (see below). `--no-cxx` leaves out the C++ runtimes, for quicker libc iterations. `--help`
lists all options.

The script works with two kinds of clang. `--target auto` (the default) picks the first that fits:
- **wasix-org/llvm-project** (`wasm32-wasixv2` triple, detected by `__wasixv2__`): libc and builtins
  are compiled with `--target=wasm32-wasixv2 --no-default-config`. The driver's wasixv2 defaults
  also enable simd128, relaxed-simd and extended-const. For this triple clang defines
  `__wasix__`, `__wasixv2__`, `__unix__` and, from release 22.1.802 on, `__linux__` (plus `__linux`
  and, in GNU modes, `linux`), but neither `__wasi__` nor `__gnu_linux__`. Programs see a Linux
  target with a musl libc.
- **upstream clang**: `--target=wasm32-unknown-unknown`, with the generic feature set plus what the
  ABI flags turn on.

Release sysroots are built with upstream clang until a wasix-org LLVM 22 release exists, and so
without the C++ runtimes (see [C++](#c)), which need the `wasm32-wasixv2` target. They
work with the `wasm32-wasixv2` driver: objects built for `wasm32-unknown-unknown` link fine into
`wasm32-wasixv2` programs, and the smoke test passes with either compiler on either sysroot.

Either way, `arch/wasm32/arch.mak` adds the flags that are part of the ABI, and the script uses the
same flags for the builtins. For the default configuration:
- `-pthread`: atomics, bulk memory, wasm TLS
- `-ftls-model=local-exec`
- `-fwasm-exceptions -mllvm -wasm-use-legacy-eh=false`: exnref exception handling
- `-mllvm -wasm-enable-sjlj`: setjmp/longjmp built on wasm EH

### Build configurations

wasixv2 has build configurations that differ in how a wasm call stack can be left early; each has
its own sysroot, and wasixcc picks it from its `WASM_EXCEPTIONS` setting:

| Configuration | Sysroot | wasixcc | setjmp/longjmp | fork | C++ exceptions |
| --- | --- | --- | --- | --- | --- |
| `eh` (default) | `sysroot-wasixv2` | `WASM_EXCEPTIONS=yes` | wasm exceptions | `ENOSYS` | wasm exceptions |
| `asyncify` | `sysroot-wasixv2-asyncify` | `WASM_EXCEPTIONS=no` | the host's `stack_save`/`stack_restore` | yes | none (`-fno-exceptions`) |

`--config asyncify` (`make wasixv2-sysroot-asyncify`) builds without wasm exception handling
(`-fno-exceptions -mno-exception-handling`), since binaryen's asyncify cannot instrument it, and
wasixcc runs `wasm-opt --asyncify` on every program it links against that sysroot. setjmp is then a
function: the host unwinds the call stack into linear memory and keeps it, and longjmp has it
rewound (`src/setjmp/wasm32`). fork is musl's, through clone(SIGCHLD), which returns twice: the
host unwinds the stack, copies the instance for the child, and rewinds both. vfork and everything
else work as in the default configuration.

The pins live in `wasixv2/toolchain.env`. compiler-rt and the C++ runtimes are built from a sparse
checkout of `llvm/llvm-project` at `llvmorg-$LLVM_VERSION`, cached in `<out>/src`. Set `LLVM_SRC`
to use an existing llvm-project checkout instead, such as the wasix-org/llvm-project checkout
whose clang builds the sysroot.

### C++

Both sysroots ship LLVM's C++ runtimes, built from the same llvm-project source as the builtins
(`runtimes/`, with `LLVM_ENABLE_RUNTIMES`) and with the configuration's ABI flags:

- libc++ (`libc++.a`, `libc++experimental.a`, headers in `include/c++/v1`), ABI version 2, as
  wasi-sdk and Emscripten use for wasm (wasixv2 has no existing C++ binaries to stay compatible
  with), with threads (pthreads), filesystem, localization and the random device.
- libc++abi (`libc++abi.a`).
- In the `eh` configuration, C++ exceptions are wasm exceptions (exnref). libunwind's wasm
  unwinder, which is only the personality glue wasm EH needs (`Unwind-wasm.c`), is merged into
  `libc++abi.a`, so the `-lc++ -lc++abi` the clang driver adds for C++ links is enough;
  `libunwind.a` is installed too, for build systems that ask for `-lunwind`.
- In the `asyncify` configuration there are no C++ exceptions: binaryen's asyncify cannot
  instrument wasm exception handling, and the only other lowering of C++ exceptions for wasm is
  Emscripten's, which needs its JavaScript runtime. libc++ is built with `-fno-exceptions`, as
  programs are: `throw` and `try` do not compile, and where libc++ would throw
  (`std::bad_alloc`, `std::vector::at`, ...) the program aborts. libunwind is not built.

The C++ runtimes need the wasix-org clang: built for `wasm32-unknown-unknown`, libc++ would take
generic code paths (or none: the time zone database) instead of Linux's, so with upstream clang the
script stops unless `--no-cxx` is given, as CI's upstream job does.

The target is Linux (the wasix-org clang defines `__linux__`), so libc++ takes its Linux code
paths with musl: `std::atomic::wait` is a futex through `syscall()` (which imports every wasixv2
syscall, see below), the random device reads `/dev/urandom`, and `std::filesystem::copy_file` tries
`copy_file_range` and `sendfile` before falling back to a read/write loop.

### Linux UAPI headers

The sysroot ships Linux's UAPI headers (`linux/`, `asm/`, `asm-generic/`, `drm/`, `sound/`, ...),
as a Linux distribution's linux-headers package does, so code written for Linux builds unchanged.
The script installs them with `make ARCH=riscv headers_install` from a sparse checkout of
`torvalds/linux` at `$LINUX_UAPI_TAG` (`wasixv2/toolchain.env`), cached in `<out>/src`; set
`LINUX_SRC` to use an existing clean checkout instead (it is built out of tree). riscv's because
wasixv2's struct layouts and constants follow riscv32. `asm/unistd.h` is replaced by an include of
`<sys/syscall.h>`: the syscall numbers are libc2's, which are the wasixv2 ABI's (riscv32's differ for
`lseek` and `mmap`), and riscv's `asm/unistd_32.h` and `asm/unistd_64.h` are left out. The
riscv-specific `asm/` headers that describe registers and the signal context (`asm/ptrace.h`,
`asm/sigcontext.h`, `asm/ucontext.h`) do not describe wasixv2.

The installed Landlock header also backports `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS`
from newer Linux UAPI: the wasixv2 kernel supports it alongside `TSYNC`.

The tag is the newest Linux release that covers wasixv2's syscall table. Kernel and libc headers
share directories (`scsi/`) but never files; the script fails if a kernel header would replace a
libc one.

### Sysroot layout

This is the layout the `wasm32-wasixv2` clang driver expects:

```
sysroot-wasixv2/
  include/                        musl and arch/wasm32 headers (flat)
    linux/ asm/ asm-generic/ ...  Linux UAPI headers (riscv, asm/unistd.h is <sys/syscall.h>)
  lib/wasm32-wasixv2/
    crt1.o rcrt1.o Scrt1.o crti.o crtn.o
    libc.a                        all of libc
    libm.a libpthread.a librt.a libdl.a libutil.a libresolv.a libcrypt.a libxnet.a  (empty, as in musl)
    libclang_rt.builtins.a        compiler-rt builtins
    libc++.a libc++experimental.a libc++abi.a  the C++ runtimes
    libunwind.a                   eh configuration only; also merged into libc++abi.a
  include/c++/v1/                 libc++ and libc++abi headers
  share/wasixv2/build-info.json   libc2 commit, musl version, target, compiler, compiler-rt and Linux
                                  commits, the C++ runtimes and whether they have exceptions
  VERSION                         `git describe` of the libc2 commit
```

The builtins are needed for `long double` (IEEE binary128, as on riscv32) and the 128-bit integer
helpers. The driver only looks for them in clang's resource directory
(`<resource>/lib/wasm32-unknown-wasixv2/libclang_rt.builtins.a`), never in the sysroot. So pass the
sysroot's copy explicitly, either by path or with `-L<sysroot>/lib/wasm32-wasixv2
-lclang_rt.builtins`, and stop the driver from adding its own with `-nodefaultlibs` (then
`-lpthread -lc` must be given too).

### Linking a program

With the wasix-org clang:

```sh
clang --target=wasm32-wasixv2 --no-default-config --sysroot=$SYSROOT hello.c \
  -nodefaultlibs -lpthread -lc $SYSROOT/lib/wasm32-wasixv2/libclang_rt.builtins.a -o hello.wasm
```

The driver supplies the ABI flags, crt1, `--shared-memory`, `--import-memory`, the memory limits and
the stack size.

With upstream clang, everything is explicit:

```sh
ABI="--target=wasm32-unknown-unknown -pthread -ftls-model=local-exec -fwasm-exceptions \
  -mllvm -wasm-use-legacy-eh=false -mllvm -wasm-enable-sjlj"
LIB=$SYSROOT/lib/wasm32-wasixv2
clang $ABI -nostdinc -isystem $SYSROOT/include -isystem $(clang -print-resource-dir)/include \
  -nostdlib $LIB/crt1.o hello.c -L$LIB -lc $LIB/libclang_rt.builtins.a \
  -Wl,--shared-memory,--import-memory,--max-memory=67108864,-z,stack-size=1048576 -o hello.wasm
```

Notes:
- Code that calls `setjmp`/`sigsetjmp` **must** be compiled with `-mllvm -wasm-enable-sjlj` and
  exnref EH (the wasix-org driver does this by default, unless `-fwasm-exceptions` or
  `-fno-exceptions` is given). On wasm, `setjmp` is lowered by the compiler and is not a callable
  function. `sigsetjmp` is a macro in `<setjmp.h>` for the same reason.
- `--shared-memory` is required. libc uses wasm TLS (`__tls_base`), and the main thread's TLS block
  is initialized by wasm-ld's `__wasm_init_memory` start function.
- A linked program imports `env.memory` plus only the `wasixv2.*` functions it actually uses.
  Every syscall site is a direct call to its import. The exception is anything that uses
  `syscall()` or `setuid`-family functions, which go through `__syscall_dyn` and so import every
  wasixv2 syscall.
- configure finds no compiler runtime (`LIBCC` stays empty), which is expected.

## Smoke test

```sh
wasixv2/test/run.sh build-wasixv2/sysroot-wasixv2
wasixv2/test/run.sh build-wasixv2/sysroot-wasixv2-asyncify
```

It compiles and links `wasixv2/test/smoke.c` against the sysroot with the same clang the build would
pick (wasix-org driver or upstream flags, as above) and the ABI flags of the sysroot's build
configuration (from `build-info.json`), validates the module with `wasm-tools`, checks
that it imports only `env.memory` and `wasixv2.*`, and compiles `wasixv2/test/uapi.c`, which
includes the Linux UAPI headers together with libc's. If the sysroot has the C++ runtimes, it links
and checks `wasixv2/test/smoke.cpp` the same way (iostream, threads and, in the `eh`
configuration, an exception). It does not run the modules; running v2
programs is tested in the wasmer repo (`lib/wasix`, `tests/wasixv2`). Needs wasm-tools.

## CI and releases

- the repository-root `.github/workflows/guest-libc.yml` runs on pull requests and pushes to `main`. It downloads the pinned
  upstream LLVM release (`wasixv2/fetch-llvm.sh`, checksum in `wasixv2/toolchain.env`), runs
  `build-sysroot.sh --package` and the smoke test, and uploads the tarball as an artifact (best
  effort).
  A second job builds with a wasix-org/llvm-project release. It is skipped until the repository
  variable `WASIXV2_LLVM_TAG` is set to a fork release tag (e.g. `22.1.801`, asset
  `LLVM-Linux-x86_64.tar.gz`).
- The standalone libc2 release workflow is retired. Wasmer tags do not publish
  libc sysroots; a guest-specific release policy remains to be defined.

The tarball is reproducible for a given commit and toolchain: archive members are
sorted, owned by 0:0 and dated to the commit time, and gzip omits the timestamp.
Build-info revision fields now identify the containing Wasmer checkout.

## How the syscall layer works

musl calls syscalls via macros such as `__syscall3(SYS_openat, a, b, c)`. By the time the arch
macro sees the call, `SYS_openat` has already been expanded to `56`. `arch/wasm32/syscall_arch.h`
token-pastes that number:

```
__syscall3(56, a, b, c)  ->  __wxv2_nr_56(a, b, c)  ->  __wasixv2_openat((int)(a), (const void *)..., ...)
```

The arm `__wxv2_nr_56` casts musl's `long` argument slots to the import's parameter types, pads
missing slots with 0, and ignores extra ones. It also reassembles split 64-bit arguments into one
i64. Because of this:
- `SYS_*` stay plain integer macros, so musl's `#ifdef SYS_x` path selection, the time64 fallbacks
  and comparisons such as `nr == SYS_close` all work unchanged.
- An unknown or non-constant syscall number is a compile error.
- The few sites with a run-time number call `__syscall_dyn(n, ...)`, a generated `switch`. These
  are `syscall()` (src/misc/wasm32/syscall.c) and `__setxid` (src/unistd/wasm32/setxid.c).

The only generic (non-arch) changes:
- `src/internal/syscall.h`: `#ifndef __SYSCALL_ARCH_DISPATCH` guards around the generic
  `__syscallN`/`__syscall_cpN` wrappers and `__alt_socketcall`.
- `include/setjmp.h`: the `sigsetjmp` macro under `__wasm__`.
- `src/env/__libc_start_main.c`: calls `__wasm_call_ctors()` under `__wasm__`.
- `configure`: the `wasm32*` target.

## Generated files

The [wasixv2-codegen](https://github.com/wasmerio/wasmer/tree/main/lib/wasix/codegen) C
backend owns these files. Do not edit them by hand:

| File | Content |
|---|---|
| `arch/wasm32/bits/syscall.h.in` | `__NR_*` numbers (riscv32 set) |
| `arch/wasm32/wasixv2_syscalls.h` | `wasixv2` syscall import declarations and the per-number `__wxv2_nr_<N>` arms |
| `src/internal/wasm32/wasixv2_dyn.c` | `__syscall_dyn` switch |
| `src/internal/wasm32/wasixv2_asserts.c` | `_Static_assert`s of musl types and constants against the WIT definitions |

ABI, kernel and libc changes now land together in this repository. Regenerate
from the libc root with `make wasixv2-codegen`, or from the repository root:

```sh
WASIXV2_LIBC_BLESS=1 cargo test -p wasixv2-codegen --test guest_libc --locked
```

A drift between the WIT definitions and musl shows up as a compile error, either in an arm or in
`wasixv2_asserts.c`.

`arch/wasm32/wasixv2_ext.h` (the extension imports) is hand-written for now.

## Startup ABI

`_start` (crt/wasm32/crt1.c) calls `wasixv2.startup_size()` and then
`wasixv2.startup_get(buf, len)`.
The host writes the Linux initial-stack block into `buf`: argc, argv, envp, auxv and the string
data, with pointers being guest addresses inside the buffer. `_start` then calls
`__libc_start_main` as on Linux. See `arch/wasm32/wasixv2_ext.h` for the exact layout and the
required auxv entries.

clang renames `main` on wasm (`__main_argc_argv`, `__main_void`). crt1 and
`src/env/wasm32/__main_*.c` handle all three forms of `main`.

## Status / not yet implemented

| Area | State |
|---|---|
| Threads (`__clone`) | `__clone` (src/thread/wasm32/clone.c) goes through the `thread_spawn` extension; the host starts a new instance at the exported `wasixv2_thread_start` |
| `fork`, `_Fork` | clone(SIGCHLD) (src/process/wasm32/_Fork.c): returns twice in the `asyncify` configuration; fails with `ENOSYS` in the default (`eh`) one |
| `clone()` | musl's wrapper (src/linux/clone.c), which refuses `CLONE_THREAD`, `CLONE_SETTLS` and `CLONE_CHILD_CLEARTID` and a null `stack` with `EINVAL`, over `__clone` (src/thread/wasm32/clone.c). Without `CLONE_VM` it forks with the given flags, as `_Fork` does, and the child calls `fn(arg)` and exits with its result: the asyncify configuration only (`ENOSYS` in the default one), and the child runs on its copy of the caller's stack, not on `stack`. With `CLONE_VFORK` the parent's call returns once the child exited or execed. `CLONE_VM \| CLONE_VFORK` runs `fn` as a vfork child. Other `CLONE_VM` clones, a process sharing the caller's memory, start through `thread_spawn` like a thread, at `wasixv2_thread_start` on `stack`, and the kernel makes them a process of their own; without `CLONE_SETTLS` the child runs on the caller's TLS block and thread pointer, as a Linux child keeps the caller's, in both configurations |
| `vfork` | a macro in both configurations: setjmp in the caller's frame, the child runs in the parent's instance until it calls `_exit` or `execve` (src/process/wasm32/vfork.c). Calls that bypass the macro reach the vfork function, which is `_Fork` and so fails with `ENOSYS` in the default configuration; its declaration is deprecated to say so |
| `__unmapself` | munmap, then exit without touching the stack |
| Cancellation | pre/post check around each cancellation point instead of PC rewriting. There is a race between the check and the host blocking (see `src/thread/wasm32/pthread_cancel.c`); the host will close it later |
| Signal delivery | needs a host design. `SA_RESTORER` is intentionally not defined, so `k_sigaction` matches the kernel layout |
| Dynamic linking, `dlopen` | native EH/PIC NOW/bounded LAZY wrappers; requires matching host loader, see below |
| vDSO | none: `clock_gettime` is a syscall |
| fenv | generic: round-to-nearest only, no exceptions |
| `sched_{get,set}param`, `sched_{get,set}scheduler` | the Linux syscalls, as glibc calls them (src/sched): a deviation from musl, whose wrappers fail with `ENOSYS` because POSIX names a process where Linux acts on one thread. The kernel takes `pid` as a thread id (0: the calling thread), so for a process it is its main thread, and `sched_setscheduler` returns 0 rather than the previous policy, as with glibc |

## Native EH/PIC dynamic loading (source profile)

`--config ehpic` produces an isolated `sysroot-wasixv2-ehpic` sibling using
native exnref EH and PIC libc objects; the default EH and asyncify sysroots stay
unchanged. This source configuration does not install or replace a sysroot.
wasixcc's native PIC profile selects it for dynamic main/side modules. It is not
present in existing downloaded release sysroots. Main owns libc and its existing
pthread TLS; the host installs separate side-module TLS in each store without a
new guest DTV protocol.

The wasm32 dlfcn wrappers use the existing four host imports. `dlopen` accepts
RTLD_NOW or RTLD_LAZY, holds a recursive libc lock until constructors finish, and permits nested
constructor loads after the host's transaction gate has released. Cancellation is
disabled while owning that lock. `dlerror` retains musl's per-thread storage.
LD_LIBRARY_PATH is copied before user constructors and ignored for secure startup;
default directories are `/lib:/usr/local/lib:/usr/lib`. RTLD_NEXT remains
explicitly rejected. The current wrapper passes main caller identity zero; DSO
caller-sensitive runtime paths and NEXT remain later work. `dlclose` drops the host
reference without unloading code. Normal exit retains existing atexit handling;
side destructor registration requires the matching lld constructor/atexit contract.

These wrappers are a source component, not proof of a complete live loader. The
matching host must implement validated initialization, per-store TLS/table state,
all-peer publication and rollback before plugins work; no installed toolchain or
full browser/asyncify acceptance is claimed by this source profile.

### Startup constructor queue

With a matching host that prepares native DT_NEEDED/preload graphs before entry,
`__wasixv2_dl_startup` drains the existing constructor queue after main TLS/SSP
and secure startup initialization and before main `_init`/constructors. It uses
the same recursive loader lock, cancellation protection and post-publication
queue-error policy as `dlopen`, including nested constructor loads. Queue draining
also occurs when LD_LIBRARY_PATH is absent or ignored for secure startup. Host
startup policy owns dependency/preload collection; libc adds no new import or
LD_PRELOAD interpretation. This source hook alone is not runtime startup acceptance.

### Bounded native LAZY direct functions

The wrapper forwards binding flags unchanged to the matching host; at least one
of RTLD_NOW/RTLD_LAZY is required, and the host gives NOW precedence when both
are set. Native LAZY currently permits only missing strong direct-function
imports that are not called yet. Missing data/TLS/GOT.func/GOT.mem references and
type mismatches still fail loading. A later GLOBAL load or NOLOAD GLOBAL
promotion can resolve registered deferred functions; an unrelated LOCAL load
cannot, and old NOW bindings remain fixed. Calling an unresolved function follows
the existing process SIGILL path, rather than an mm-wide internal-loader failure.
Startup loading remains NOW. This bounded scope requires the matching runtime;
accepting a flag in libc alone is not proof of complete LAZY support.
