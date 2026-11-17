#include <features.h>

/* Linked only if the program defines neither main(int, char **) nor
 * main(void): fall back to main(int, char **, char **), which clang emits
 * unrenamed. */

extern hidden int __wasm_main_argc;
extern hidden char **__wasm_main_argv;
extern char **__environ;

int main(int, char **, char **);

int __main_void(void)
{
	return main(__wasm_main_argc, __wasm_main_argv, __environ);
}
