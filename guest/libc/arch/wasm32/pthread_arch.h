/* wasm has no thread pointer register. The thread pointer (the address of
 * the thread's struct pthread, since TLS_ABOVE_TP is not defined) lives in
 * a wasm TLS variable, i.e. at a fixed offset from the per-thread
 * __tls_base global. A thread's TLS block must therefore be initialized
 * (__wasm_init_tls) before __set_thread_area is called; see
 * src/env/wasm32/__init_tls.c. */
extern hidden _Thread_local uintptr_t __wasm_tp;

static inline uintptr_t __get_tp()
{
	return __wasm_tp;
}

/* Only consulted by signal-context code; wasm32 mcontext_t is a stub. */
#define MC_PC __gregs[0]
