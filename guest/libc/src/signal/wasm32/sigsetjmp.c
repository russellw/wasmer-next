#include <setjmp.h>

hidden int __sigsetjmp_tail(sigjmp_buf, int);

/* sigsetjmp cannot be a function on wasm: only the compiler can implement
 * "return twice" (by lowering setjmp calls in the caller), so <setjmp.h>
 * defines sigsetjmp(b, s) as __wasm_sigsetjmp_tail(b, s, setjmp(b)).
 * Like musl's asm sigsetjmp, this saves the signal mask on the direct
 * return (ret == 0) and restores it on the return from siglongjmp. */
int __wasm_sigsetjmp_tail(sigjmp_buf buf, int savemask, int ret)
{
	return savemask ? __sigsetjmp_tail(buf, ret) : ret;
}
