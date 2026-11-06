#ifndef _WASIX_CLOSURE_H
#define _WASIX_CLOSURE_H

#include <stddef.h>
#include <wasix/function_pointer.h>
#include <wasix/value_type.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The backing function takes (values, results, user_data), three pointers.
 * Type arrays contain one WASIX_VALUE_TYPE_* byte per argument or result.
 * These functions return 0 or -1 with errno set. */
int wasix_closure_prepare(wasix_function_pointer_t, wasix_function_pointer_t,
                          const wasix_value_type_t*, size_t,
                          const wasix_value_type_t*, size_t, void*);
int wasix_closure_allocate(wasix_function_pointer_t*);
/* Calling an unprepared or freed closure traps. Freeing an unallocated slot
 * fails with EINVAL. */
int wasix_closure_free(wasix_function_pointer_t);

#ifdef __cplusplus
}
#endif
#endif
