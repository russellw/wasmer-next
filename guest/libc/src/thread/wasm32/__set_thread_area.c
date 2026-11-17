#include "pthread_impl.h"

/* The thread pointer is a wasm TLS variable (see arch/wasm32/pthread_arch.h);
 * the calling thread's TLS block must already be set up. */
hidden _Thread_local uintptr_t __wasm_tp;

int __set_thread_area(void *p)
{
	__wasm_tp = (uintptr_t)p;
	return 0;
}
