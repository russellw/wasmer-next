#ifndef _WASIX_CONTEXT_H
#define _WASIX_CONTEXT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t wasix_context_id_t;

#define wasix_context_main (__wasix_context_main())
wasix_context_id_t __wasix_context_main(void);

/* Contexts share the current thread, TLS and memory. The guest provides any
 * separate shadow stacks. Only suspended contexts can be switched to or
 * destroyed; the main context cannot be destroyed. Entry must not return.
 * Returns 0 or -1 with errno set, including ENOTSUP on unsupported engines. */
int wasix_context_create(wasix_context_id_t*, void (*)(void));
int wasix_context_switch(wasix_context_id_t);
int wasix_context_destroy(wasix_context_id_t);

#ifdef __cplusplus
}
#endif
#endif
