#ifndef WASIX_COMPAT_LIBC_IMPORTS_H
#define WASIX_COMPAT_LIBC_IMPORTS_H

/* Owned declarations, checked against canonical wit/ext.wit by generator tests.
 * These C types are the wasm32 data model used by libc2. */
_Static_assert(sizeof(unsigned) == 4, "wasixv2 function index width");
_Static_assert(sizeof(long) == 4, "wasixv2 syscall result width");
_Static_assert(sizeof(void*) == 4, "wasixv2 pointer width");
_Static_assert(sizeof(unsigned long long) == 8, "wasixv2 context id width");

#define __WASIXV2_EXT_IMPORT(name) \
  __attribute__((__import_module__("wasixv2"), __import_name__(#name)))

__WASIXV2_EXT_IMPORT(call_dynamic)
long __wasixv2_ext_call_dynamic(unsigned, const void*, unsigned long, void*,
                                unsigned long, unsigned);
__WASIXV2_EXT_IMPORT(reflect_signature)
long __wasixv2_ext_reflect_signature(unsigned, void*, unsigned long, void*,
                                     unsigned long, void*);
__WASIXV2_EXT_IMPORT(closure_allocate)
long __wasixv2_ext_closure_allocate(unsigned*);
__WASIXV2_EXT_IMPORT(closure_prepare)
long __wasixv2_ext_closure_prepare(unsigned, unsigned, const void*,
                                   unsigned long, const void*, unsigned long,
                                   void*);
__WASIXV2_EXT_IMPORT(closure_free)
long __wasixv2_ext_closure_free(unsigned);
__WASIXV2_EXT_IMPORT(context_create)
long __wasixv2_ext_context_create(unsigned, unsigned long long*);
__WASIXV2_EXT_IMPORT(context_switch)
long __wasixv2_ext_context_switch(unsigned long long);
__WASIXV2_EXT_IMPORT(context_destroy)
long __wasixv2_ext_context_destroy(unsigned long long);

#endif
