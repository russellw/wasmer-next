#include <setjmp.h>

#ifdef __wasm_exception_handling__

/* Runtime half of LLVM's wasm exception-handling based setjmp/longjmp
 * (-mllvm -wasm-enable-sjlj with -fwasm-exceptions). The compiler rewrites
 * calls to setjmp/_setjmp into __wasm_setjmp plus a try/catch on the
 * __c_longjmp tag around the function body, and calls to longjmp into
 * __wasm_longjmp, so there is no setjmp function to call at run time.
 * Code calling setjmp must be compiled with those flags. */

struct __wasm_jmp_buf {
	void *func_invocation_id;
	unsigned label;
	struct {
		void *env;
		int val;
	} arg;
};

_Static_assert(sizeof(struct __wasm_jmp_buf) <= sizeof(((jmp_buf){0})->__jb),
               "jmp_buf too small for the wasm sjlj state");

void __wasm_setjmp(void *env, unsigned label, void *func_invocation_id)
{
	struct __wasm_jmp_buf *jb = env;
	if (!label || !func_invocation_id) __builtin_trap();
	jb->func_invocation_id = func_invocation_id;
	jb->label = label;
}

unsigned __wasm_setjmp_test(void *env, void *func_invocation_id)
{
	struct __wasm_jmp_buf *jb = env;
	if (!jb->label || !func_invocation_id) __builtin_trap();
	if (jb->func_invocation_id == func_invocation_id)
		return jb->label;
	return 0;
}

#else

/* The asyncify build configuration has no wasm exceptions, so setjmp is a
 * function: the host records the call stack up to here, and longjmp has it
 * unwind the current one and rewind this one, which returns again. Locals in
 * linear memory keep their current values, as longjmp requires; wasm locals
 * come back as they were here, which is what C allows for automatic
 * variables that are not volatile. */

#include "wasixv2_ext.h"

int setjmp(jmp_buf env)
{
	int val;
	return __wasixv2_ext_stack_save(env->__jb, &val) == 1 ? val : 0;
}

weak_alias(setjmp, _setjmp);

#endif
