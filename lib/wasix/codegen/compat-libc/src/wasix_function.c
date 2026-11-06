#include <wasix/call_dynamic.h>
#include <wasix/closure.h>
#include <wasix/reflection.h>

#include "errno_result.h"
#include "wasixv2_ext.h"

_Static_assert(sizeof(wasix_reflection_result_t) == 6,
               "reflection result size");
_Static_assert(_Alignof(wasix_reflection_result_t) == 2,
               "reflection result alignment");
_Static_assert(offsetof(wasix_reflection_result_t, cacheable) == 0,
               "cacheable offset");
_Static_assert(offsetof(wasix_reflection_result_t, arguments) == 2,
               "arguments offset");
_Static_assert(offsetof(wasix_reflection_result_t, results) == 4,
               "results offset");

int wasix_call_dynamic(wasix_function_pointer_t function, void* values,
                       size_t values_len, void* results, size_t results_len,
                       bool strict) {
  return wasix_compat_result(__wasixv2_ext_call_dynamic(
      function, values, values_len, results, results_len, strict ? 1 : 0));
}

int wasix_reflect_signature(wasix_function_pointer_t function,
                            wasix_value_type_t* arguments,
                            uint16_t arguments_len, wasix_value_type_t* results,
                            uint16_t results_len,
                            wasix_reflection_result_t* result) {
  return wasix_compat_result(__wasixv2_ext_reflect_signature(
      function, arguments, arguments_len, results, results_len, result));
}

int wasix_closure_allocate(wasix_function_pointer_t* closure) {
  return wasix_compat_result(__wasixv2_ext_closure_allocate(closure));
}

int wasix_closure_prepare(wasix_function_pointer_t backing,
                          wasix_function_pointer_t closure,
                          const wasix_value_type_t* arguments,
                          size_t arguments_len,
                          const wasix_value_type_t* results, size_t results_len,
                          void* env) {
  return wasix_compat_result(__wasixv2_ext_closure_prepare(
      backing, closure, arguments, arguments_len, results, results_len, env));
}

int wasix_closure_free(wasix_function_pointer_t closure) {
  return wasix_compat_result(__wasixv2_ext_closure_free(closure));
}
