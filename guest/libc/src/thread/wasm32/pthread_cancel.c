#define _GNU_SOURCE
#include <string.h>
#include "pthread_impl.h"
#include "syscall.h"
#include "wasixv2_ext.h"

/* wasm32 version of pthread_cancel.c, with musl's semantics: SIGCANCEL is
 * installed with SA_RESTART, and its handler acts only when the thread was
 * interrupted inside a cancellation point before the syscall took effect.
 * Everything else, including every syscall outside a cancellation point,
 * restarts.
 *
 * Upstream decides that from the interrupted PC: in [__cp_begin, __cp_end)
 * of __syscall_cp_asm, the handler rewrites it to __cp_cancel. wasm code
 * cannot inspect or rewrite its own PC, so every cancellation point (the
 * __syscall_cpN macros in arch/wasm32/syscall_arch.h) does
 *
 *   r = __wasm_cp_begin(nr);         sets self->incp, then checks cancel
 *   if (!r) r = __wasm_cp_end(nr, <the wasixv2 import call>);
 *
 * and the two halves of the PC test come from elsewhere:
 *   - self->incp says the thread is in a cancellation point. It is set
 *     before the check for a pending cancel, as __cp_begin's load is inside
 *     the range, so a cancel that arrives after the check finds it set.
 *     The signal trampoline records it per frame (WASM_MC_INCP).
 *   - The frame's restart slot says the syscall was interrupted and would
 *     run again, so it has not taken effect: Linux rewinds the PC into the
 *     range for exactly that case.
 * The handler then clears the restart slot, which makes the syscall fail
 * with EINTR, and __wasm_cp_end turns that into the cancellation, as
 * __cp_cancel would. A syscall that completed keeps its result, and the
 * re-raised SIGCANCEL is acted on at the next cancellation point.
 *
 * A cancel that arrives between the check and the syscall is pending when
 * the host starts to wait, so the wait returns at once, interrupted. */

hidden long __cancel();

long __cancel()
{
	pthread_t self = __pthread_self();
	if (self->canceldisable == PTHREAD_CANCEL_ENABLE || self->cancelasync)
		pthread_exit(PTHREAD_CANCELED);
	self->canceldisable = PTHREAD_CANCEL_DISABLE;
	return -ECANCELED;
}

/* __syscall_cp_c, split around the import call. A cancellation point whose
 * cancellation is disabled, and close in PTHREAD_CANCEL_MASKED mode, are
 * plain syscalls. */
hidden long __wasm_cp_begin(long nr)
{
	pthread_t self = __pthread_self();
	int st = self->canceldisable;
	if (st && (st==PTHREAD_CANCEL_DISABLE || nr==SYS_close)) return 0;
	self->incp = 1;
	a_barrier();
	if (self->cancel) {
		self->incp = 0;
		return __cancel();
	}
	return 0;
}

hidden long __wasm_cp_end(long nr, long r)
{
	pthread_t self = __pthread_self();
	self->incp = 0;
	if (r==-EINTR && nr!=SYS_close && self->cancel &&
	    self->canceldisable != PTHREAD_CANCEL_DISABLE)
		r = __cancel();
	return r;
}

static void _sigaddset(sigset_t *set, int sig)
{
	unsigned s = sig-1;
	set->__bits[s/8/sizeof *set->__bits] |= 1UL<<(s&8*sizeof *set->__bits-1);
}

static void cancel_handler(int sig, siginfo_t *si, void *ctx)
{
	pthread_t self = __pthread_self();
	ucontext_t *uc = ctx;
	unsigned long *mc = uc->uc_mcontext.__gregs;

	a_barrier();
	if (!self->cancel || self->canceldisable == PTHREAD_CANCEL_DISABLE) return;

	_sigaddset(&uc->uc_sigmask, SIGCANCEL);

	if (self->cancelasync) {
		pthread_sigmask(SIG_SETMASK, &uc->uc_sigmask, 0);
		__cancel();
	}

	if (mc[WASM_MC_INCP] && mc[WASM_MC_RESTART]) {
		mc[WASM_MC_RESTART] = 0;
		return;
	}

	__syscall(SYS_tkill, self->tid, SIGCANCEL);
}

void __testcancel()
{
	pthread_t self = __pthread_self();
	if (self->cancel && !self->canceldisable)
		__cancel();
}

static void init_cancellation()
{
	struct sigaction sa = {
		.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK,
		.sa_sigaction = cancel_handler
	};
	memset(&sa.sa_mask, -1, _NSIG/8);
	__libc_sigaction(SIGCANCEL, &sa, 0);
}

int pthread_cancel(pthread_t t)
{
	static int init;
	if (!init) {
		init_cancellation();
		init = 1;
	}
	a_store(&t->cancel, 1);
	if (t == pthread_self()) {
		if (t->canceldisable == PTHREAD_CANCEL_ENABLE && t->cancelasync)
			pthread_exit(PTHREAD_CANCELED);
		return 0;
	}
	return pthread_kill(t, SIGCANCEL);
}
