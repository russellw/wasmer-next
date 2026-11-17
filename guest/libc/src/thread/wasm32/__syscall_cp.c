#include "pthread_impl.h"
#include "syscall.h"

/* Cancellation-point hooks used by the __syscall_cpN macros in
 * arch/wasm32/syscall_arch.h. These no-op versions are used unless
 * pthread_cancel is linked, whose src/thread/wasm32/pthread_cancel.c
 * provides the real ones (same scheme as musl's sccp/__syscall_cp_c). */

static long cp_begin(long nr)
{
	return 0;
}

static long cp_end(long nr, long r)
{
	return r;
}

weak_alias(cp_begin, __wasm_cp_begin);
weak_alias(cp_end, __wasm_cp_end);
