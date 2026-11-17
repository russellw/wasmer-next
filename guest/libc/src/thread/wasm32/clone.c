#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <sched.h>
#include "pthread_impl.h"
#include "syscall.h"
#include "wasixv2_ext.h"
#include "wasixv2_vfork.h"

/* Linux clone() returns twice with the child running on a new stack, which
 * a wasm import cannot do. Threads go through the wasixv2 thread_spawn
 * extension instead: the kernel creates the task with the usual clone flag
 * semantics (CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, ...), and the host
 * starts a new instance of the module on the same shared memory at the
 * exported wasixv2_thread_start(tid, start_arg). That entry has no stack or
 * TLS yet: it points __stack_pointer at the stack recorded in the start
 * block below, then the C part sets up TLS and calls func(arg).
 *
 * vfork-style clones (CLONE_VM | CLONE_VFORK, as posix_spawn makes) run
 * func in this instance as the child, on the caller's stack: the parent is
 * suspended until the child exits or execs (src/process/wasm32/vfork.c).
 *
 * Clones without CLONE_VM fork as _Fork does: clone returns twice in the
 * asyncify configuration, and the child calls func(arg) and exits with its
 * result, as a native clone's child does. The child runs on its copy of the
 * caller's stack, not on stack, since the kernel cannot start a forked child
 * on another stack (newsp). Either stack is in the child's own memory, so
 * only the addresses of the child's locals tell the difference. Elsewhere
 * the kernel fails the call with ENOSYS, as it does fork.
 *
 * Other clones with CLONE_VM, a process sharing the caller's memory without
 * being its thread or its vfork child, start through thread_spawn as threads
 * do: the kernel makes them a process of their own (CLONE_THREAD absent), and
 * the host starts them at wasixv2_thread_start on the same memory. Without
 * CLONE_SETTLS such a child keeps the caller's thread pointer, as on Linux:
 * it runs on the caller's TLS block (__tls_base), with the caller's struct
 * pthread, the restrictive context musl's clone() documents for CLONE_VM. */

struct start_block {
	void *stack;		/* offset 0: read by wasixv2_thread_start */
	int (*func)(void *);
	void *arg;
	void *tls;
	int flags;
	void *tls_base;		/* the caller's, for a child without CLONE_SETTLS */
};

hidden void __wasm_thread_init_tp(void *);
hidden void __wasixv2_set_tls_base(void *);

hidden _Noreturn void __wasixv2_thread_start_C(int tid, struct start_block *b)
{
	int (*func)(void *) = b->func;
	void *arg = b->arg;
	if (b->flags & CLONE_SETTLS) __wasm_thread_init_tp(b->tls);
	else __wasixv2_set_tls_base(b->tls_base);
	for (;;) __syscall(SYS_exit, func(arg));
}

__asm__(
	".text\n"
	".globaltype __stack_pointer, i32\n"
	".functype __wasixv2_thread_start_C (i32, i32) -> ()\n"
	".globl wasixv2_thread_start\n"
	".hidden wasixv2_thread_start\n"
	".export_name wasixv2_thread_start, wasixv2_thread_start\n"
	".type wasixv2_thread_start,@function\n"
	"wasixv2_thread_start:\n"
	".functype wasixv2_thread_start (i32, i32) -> ()\n"
	"	local.get 1\n"
	"	i32.load 0\n"
	"	global.set __stack_pointer\n"
	"	local.get 0\n"
	"	local.get 1\n"
	"	call __wasixv2_thread_start_C\n"
	"	end_function\n"
	".globaltype __tls_base, i32\n"
	".globl __wasixv2_set_tls_base\n"
	".hidden __wasixv2_set_tls_base\n"
	".type __wasixv2_set_tls_base,@function\n"
	"__wasixv2_set_tls_base:\n"
	".functype __wasixv2_set_tls_base (i32) -> ()\n"
	"	local.get 0\n"
	"	global.set __tls_base\n"
	"	end_function\n"
);

int __clone(int (*func)(void *), void *stack, int flags, void *arg, ...)
{
	va_list ap;
	va_start(ap, arg);
	pid_t *ptid = va_arg(ap, pid_t *);
	void *tls = va_arg(ap, void *);
	pid_t *ctid = va_arg(ap, pid_t *);
	va_end(ap);

	if ((flags & (CLONE_VM|CLONE_VFORK|CLONE_THREAD)) == (CLONE_VM|CLONE_VFORK))
		return __wasixv2_vfork_call(func, arg, (unsigned)flags
			& ~(CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID));
	if (!(flags & CLONE_VM)) {
		long r = __syscall(SYS_clone, flags, 0, ptid, tls, ctid);
		if (r) return r;
		for (;;) __syscall(SYS_exit, func(arg));
	}
	/* The start block sits at the top of the new stack; the thread's
	 * stack begins below it, 16-byte aligned. */
	uintptr_t sp = (uintptr_t)stack - sizeof(struct start_block);
	sp &= -(uintptr_t)16;
	struct start_block *b = (void *)sp;
	b->stack = (void *)sp;
	b->func = func;
	b->arg = arg;
	b->tls = tls;
	b->flags = flags;
	b->tls_base = __builtin_wasm_tls_base();

	return __wasixv2_ext_thread_spawn((unsigned long)flags, b, ptid, tls, ctid);
}
