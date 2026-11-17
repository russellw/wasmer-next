/* Exception tag thrown by __wasm_longjmp and caught by code compiled with
 * -mllvm -wasm-enable-sjlj. Its payload is a pointer to {env, val}. The
 * asyncify build configuration has no wasm exceptions, and no tag. */
#ifdef __wasm_exception_handling__
.tagtype __c_longjmp i32
.globl __c_longjmp
__c_longjmp:
#endif
