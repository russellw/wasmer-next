#include <setjmp.h>

#ifdef __wasm_exception_handling__

/* See setjmp.c in this directory. The thrown payload must stay valid while
 * the exception propagates, so it lives in the jmp_buf itself. */

struct __wasm_jmp_buf {
	void *func_invocation_id;
	unsigned label;
	struct {
		void *env;
		int val;
	} arg;
};

_Noreturn void __wasm_longjmp(void *env, int val)
{
	struct __wasm_jmp_buf *jb = env;
	jb->arg.env = env;
	jb->arg.val = val ? val : 1;
	__builtin_wasm_throw(1, &jb->arg); /* 1 = __c_longjmp tag */
}

_Noreturn void longjmp(jmp_buf env, int val)
{
	__wasm_longjmp(env, val);
}

#else

#include "wasixv2_ext.h"

_Noreturn void longjmp(jmp_buf env, int val)
{
	__wasixv2_ext_stack_restore(env->__jb, val ? val : 1);
}

#endif

weak_alias(longjmp, _longjmp);
