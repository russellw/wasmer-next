/* wasm32 has no syscall instruction. Every Linux syscall is a typed wasm
 * import in the "wasixv2" module (declared in wasixv2_syscalls.h, which is
 * generated). Calls are routed by token-pasting the syscall NUMBER:
 *
 *   __syscall3(SYS_openat, a, b, c)  ->  __syscall3(56, a, b, c)
 *                                    ->  __wxv2_nr_56(a, b, c)
 *                                    ->  __wasixv2_openat((int)(a), ...)
 *
 * __SYSCALL_DISP has already expanded SYS_openat to its number by the time
 * __syscallN sees it, so SYS_* stay plain integer macros usable in #ifdef
 * and comparisons. A syscall number that is not a literal (a variable) is a
 * compile error; such sites call __syscall_dyn() instead. */

#define __SYSCALL_ARCH_DISPATCH 1

/* 64-bit arguments occupy two long slots, low word first (the riscv32 slot
 * layout). The generated arms reassemble them into one i64 import param. */
#define __SYSCALL_LL_E(x) \
	(long)(unsigned long long)(x), (long)((unsigned long long)(x) >> 32)
#define __SYSCALL_LL_O(x) __SYSCALL_LL_E((x))

#define __wxv2_cat_(a,b) a##b
#define __wxv2_cat(a,b) __wxv2_cat_(a,b)
#define __wxv2_nr(n) __wxv2_cat(__wxv2_nr_, n)

#define __syscall0(n) __wxv2_nr(n)(0)
#define __syscall1(n,...) __wxv2_nr(n)(__VA_ARGS__)
#define __syscall2(n,...) __wxv2_nr(n)(__VA_ARGS__)
#define __syscall3(n,...) __wxv2_nr(n)(__VA_ARGS__)
#define __syscall4(n,...) __wxv2_nr(n)(__VA_ARGS__)
#define __syscall5(n,...) __wxv2_nr(n)(__VA_ARGS__)
#define __syscall6(n,...) __wxv2_nr(n)(__VA_ARGS__)
#define __syscall7(n,...) __wxv2_nr(n)(__VA_ARGS__)

/* Cancellation points. Instead of musl's asm __syscall_cp_asm (which relies
 * on rewriting the PC from the SIGCANCEL handler, impossible on wasm),
 * __wasm_cp_begin marks the thread as inside a cancellation point and checks
 * for a pending cancel, and __wasm_cp_end clears the mark and acts on an
 * -EINTR that a cancel caused (src/thread/wasm32/pthread_cancel.c). */
hidden long __wasm_cp_begin(long);
hidden long __wasm_cp_end(long, long);
#define __wxv2_cp(n, call) ({ \
	long __wxv2_r = __wasm_cp_begin(n); \
	if (!__wxv2_r) __wxv2_r = __wasm_cp_end(n, call); \
	__wxv2_r; })

#define __syscall_cp0(n) __wxv2_cp(n, __wxv2_nr(n)(0))
#define __syscall_cp1(n,...) __wxv2_cp(n, __wxv2_nr(n)(__VA_ARGS__))
#define __syscall_cp2(n,...) __wxv2_cp(n, __wxv2_nr(n)(__VA_ARGS__))
#define __syscall_cp3(n,...) __wxv2_cp(n, __wxv2_nr(n)(__VA_ARGS__))
#define __syscall_cp4(n,...) __wxv2_cp(n, __wxv2_nr(n)(__VA_ARGS__))
#define __syscall_cp5(n,...) __wxv2_cp(n, __wxv2_nr(n)(__VA_ARGS__))
#define __syscall_cp6(n,...) __wxv2_cp(n, __wxv2_nr(n)(__VA_ARGS__))

/* Run-time syscall number (syscall(), setxid). Generated switch in
 * src/internal/wasm32/wasixv2_dyn.c; references every import. */
hidden long __syscall_dyn(long, long, long, long, long, long, long);

#include "wasixv2_syscalls.h"

#define IPC_64 0

/* No vDSO: VDSO_* deliberately left undefined. */
