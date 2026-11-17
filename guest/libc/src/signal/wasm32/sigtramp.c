#include <signal.h>
#include "pthread_impl.h"
#include "wasixv2_ext.h"

/* The host delivers a signal by calling this trampoline on top of the
 * interrupted wasm call stack, with the frame below the shadow stack pointer
 * (see signal-callback-register in the wasixv2 ABI). The first uc_mcontext
 * slots hold the handler, its sa_flags and how many parameters it takes; the
 * host restores the mask from uc_sigmask and the shadow stack pointer and TLS
 * base from the next slots once this returns, which is the sigreturn. A
 * siglongjmp out of the handler unwinds through the host as a wasm exception
 * instead.
 *
 * The handler is called through its actual type, so one that declares fewer
 * parameters than SA_SIGINFO implies, or more, works as it does natively.
 *
 * Whether the interrupted code was inside a cancellation point is per frame
 * state, as the interrupted PC is on Linux: it is recorded in the frame for
 * the SIGCANCEL handler, and cleared while the handler runs, since a
 * handler's own syscalls are not that cancellation point. A siglongjmp out of
 * the handler abandons the cancellation point, so leaving it cleared is
 * right. */

void __wasm_signal_trampoline(int sig, siginfo_t *si, void *ctx)
{
	ucontext_t *uc = ctx;
	unsigned long *mc = uc->uc_mcontext.__gregs;
	unsigned long handler = mc[WASM_MC_HANDLER];
	pthread_t self = __pthread_self();
	int incp = self->incp;

	mc[WASM_MC_INCP] = incp;
	self->incp = 0;
	switch (mc[WASM_MC_NPARAMS]) {
	case 0:
		((void (*)(void))handler)();
		break;
	case 1:
		((void (*)(int))handler)(sig);
		break;
	case 2:
		((void (*)(int, siginfo_t *))handler)(sig, si);
		break;
	default:
		((void (*)(int, siginfo_t *, void *))handler)(sig, si, ctx);
		break;
	}
	self->incp = incp;
}

hidden void __wasm_signal_init(void)
{
	__wasixv2_ext_signal_callback_register(
		(unsigned)(unsigned long)__wasm_signal_trampoline);
}
