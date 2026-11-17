#define SYSCALL_NO_TLS 1
#include <string.h>
#include <stddef.h>
#include "pthread_impl.h"
#include "libc.h"
#include "atomic.h"
#include "syscall.h"

/* wasm32 TLS. There are no program headers; the linker (wasm-ld) owns the
 * TLS image and exposes it through:
 *
 *   __tls_base   mutable per-thread (per-instance) global, base of the
 *                calling thread's TLS block
 *   __tls_size, __tls_align (__builtin_wasm_tls_size/_align)
 *   __wasm_init_tls(mem)  copies the TLS image to mem and points
 *                __tls_base at it
 *
 * The main thread's block is the static .tdata area, initialized by
 * wasm-ld's start function (__wasm_init_memory), so it is usable before
 * any libc code runs. Each other thread gets its block in the area
 * pthread_create reserves (libc.tls_size bytes), laid out as
 *
 *   [struct pthread][pad to tls_align][TLS block: __tls_size bytes]
 *
 * and must call __wasm_thread_init_tp(tp) as the first thing it does, before
 * touching any TLS variable (including errno and the thread pointer). */

volatile int __thread_list_lock;

int __init_tp(void *p)
{
	pthread_t td = p;
	td->self = td;
	int r = __set_thread_area(TP_ADJ(p));
	if (r < 0) return -1;
	if (!r) libc.can_do_threads = 1;
	td->detach_state = DT_JOINABLE;
	td->tid = __syscall(SYS_set_tid_address, &__thread_list_lock);
	td->locale = &libc.global_locale;
	td->robust_list.head = &td->robust_list.head;
	td->sysinfo = __sysinfo;
	td->next = td->prev = td;
	return 0;
}

/* No dynamic TLS modules: every dtv is the empty one. */
static uintptr_t empty_dtv[1];

static struct pthread main_pthread;

extern void __wasm_init_tls(void *);

static size_t tls_block_offset(void)
{
	return sizeof(struct pthread) + libc.tls_align - 1 & -libc.tls_align;
}

void *__copy_tls(unsigned char *mem)
{
	pthread_t td;

	mem += -(uintptr_t)mem & (libc.tls_align-1);
	td = (pthread_t)mem;
	td->dtv = empty_dtv;
	/* The TLS image itself is copied by the new thread, see
	 * __wasm_thread_init_tp: __wasm_init_tls always targets the
	 * calling thread's __tls_base. */
	return td;
}

/* First call in a new thread; tp is what __copy_tls returned (passed as the
 * clone "tls" argument). */
hidden void __wasm_thread_init_tp(void *tp)
{
	__wasm_init_tls((unsigned char *)tp + tls_block_offset());
	__set_thread_area(TP_ADJ(tp));
}

static void static_init_tls(size_t *aux)
{
	size_t align = __builtin_wasm_tls_align();

	if (align < _Alignof(struct pthread)) align = _Alignof(struct pthread);
	libc.tls_align = align;
	libc.tls_cnt = 0;
	libc.tls_head = 0;
	/* struct pthread, TLS block, and slack for aligning the start of the
	 * area handed to __copy_tls. */
	libc.tls_size = tls_block_offset() + __builtin_wasm_tls_size()
		+ align - 1 + sizeof(void *) - 1 & -sizeof(void *);

	main_pthread.dtv = empty_dtv;
	/* Failure to initialize thread pointer is always fatal. */
	if (__init_tp(&main_pthread) < 0)
		a_crash();
}

weak_alias(static_init_tls, __init_tls);
