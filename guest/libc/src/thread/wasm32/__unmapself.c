#include "pthread_impl.h"
#include "syscall.h"

/* Upstream switches to a shared stack (CRTJMP) before unmapping the exiting
 * thread's stack, which wasm code cannot do. It does not need to: a wasm
 * call to an import keeps its operands and locals off linear memory, and
 * nothing below touches the shadow stack, the TLS block or anything else in
 * the mapping once munmap returned. musl has already unregistered the robust
 * list, and the clear_child_tid word (__thread_list_lock) lives outside the
 * mapping. */
void __unmapself(void *base, size_t size)
{
	__syscall(SYS_munmap, base, size);
	for (;;) __syscall(SYS_exit, 0);
}
