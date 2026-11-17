#include "pthread_impl.h"

extern void __wasm_init_tls(void *);

/* Reset the calling thread's TLS to the initial image (used by the
 * timer_create notification thread between callbacks). The thread
 * pointer is itself a TLS variable and must survive. */
void __reset_tls()
{
	uintptr_t tp = __get_tp();
	__wasm_init_tls(__builtin_wasm_tls_base());
	__set_thread_area((void *)tp);
}
