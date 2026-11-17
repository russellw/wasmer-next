#include <features.h>
#include <sys/mman.h>
#include "libc.h"
#include "syscall.h"
#include "wasixv2_ext.h"

/* wasm32 process entry. There is no initial stack prepared by the kernel,
 * so ask the host for the same block (argc, argv, envp, auxv and their
 * strings; see arch/wasm32/wasixv2_ext.h) and hand it to the generic startup
 * code as if it had been found at the initial stack pointer. The block
 * must outlive main (environ, argv), which holds both for the _start
 * frame (it never returns) and for the mmap fallback. */

/* Larger blocks are not put on the (small, fixed-size) wasm C stack. */
#define STARTUP_STACK_MAX 4096

/* clang on wasm renames main: main(int, char **) is emitted as
 * __main_argc_argv, main(void) as __main_void. Fallbacks in libc
 * (src/env/wasm32/__main_*.c) chain the other forms to __main_argc_argv. */
int __main_argc_argv(int, char **);

static int call_main(int argc, char **argv, char **envp)
{
	return __main_argc_argv(argc, argv);
}

hidden void __wasm_signal_init(void);

weak void _init();
weak void _fini();
int __libc_start_main(int (*)(), int, char **,
	void (*)(), void(*)(), void(*)());

static _Noreturn void start_with(long *p, size_t n)
{
	if (__wasixv2_ext_startup_get(p, n) < 0) __builtin_trap();
	int argc = p[0];
	char **argv = (void *)(p+1);
	__wasm_signal_init();
	__libc_start_main(call_main, argc, argv, _init, _fini, 0);
	__builtin_trap();
}

void _start(void)
{
	size_t n = __wasixv2_ext_startup_size();
	if (n <= STARTUP_STACK_MAX) {
		long buf[STARTUP_STACK_MAX/sizeof(long)] __attribute__((__aligned__(16)));
		start_with(buf, sizeof buf);
	}
	long *p = (void *)__syscall(SYS_mmap, 0, n, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ((unsigned long)p > -4096UL) __builtin_trap();
	start_with(p, n);
}
