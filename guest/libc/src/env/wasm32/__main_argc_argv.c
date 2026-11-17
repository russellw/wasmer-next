#include <features.h>

/* Linked only if the program does not define main(int, char **) (which
 * clang emits as __main_argc_argv on wasm). Forward to main(void), emitted
 * as __main_void; see crt/wasm32/crt1.c. */

hidden int __wasm_main_argc;
hidden char **__wasm_main_argv;

int __main_void(void);

int __main_argc_argv(int argc, char **argv)
{
	__wasm_main_argc = argc;
	__wasm_main_argv = argv;
	return __main_void();
}
