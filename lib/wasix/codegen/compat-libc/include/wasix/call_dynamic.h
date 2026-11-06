#ifndef _WASIX_CALL_DYNAMIC_H
#define _WASIX_CALL_DYNAMIC_H

#include <stdbool.h>
#include <stddef.h>
#include <wasix/function_pointer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Values are packed without padding: i32/f32 use 4 bytes, i64/f64 use 8,
 * v128 uses 16. Strict calls require exact buffer lengths. Returns 0 or -1
 * with errno set; callee traps, exceptions and longjmps pass through. */
int wasix_call_dynamic(wasix_function_pointer_t, void*, size_t, void*, size_t,
                       bool);

#ifdef __cplusplus
}
#endif
#endif
