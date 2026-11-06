#ifndef _WASIX_REFLECTION_H
#define _WASIX_REFLECTION_H

#include <wasix/function_pointer.h>
#include <wasix/value_type.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t cacheable;
  uint16_t arguments;
  uint16_t results;
} wasix_reflection_result_t;

/* Returns 0 or -1 with errno set. On EOVERFLOW only the result record is
 * written; both type arrays remain untouched. */
int wasix_reflect_signature(wasix_function_pointer_t, wasix_value_type_t*,
                            uint16_t, wasix_value_type_t*, uint16_t,
                            wasix_reflection_result_t*);

#ifdef __cplusplus
}
#endif
#endif
