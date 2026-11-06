#include <wasix/context.h>

#include "errno_result.h"
#include "wasixv2_ext.h"

wasix_context_id_t __wasix_context_main(void) { return 0; }

int wasix_context_create(wasix_context_id_t* id, void (*entry)(void)) {
  return wasix_compat_result(__wasixv2_ext_context_create((unsigned)entry, id));
}

int wasix_context_switch(wasix_context_id_t id) {
  return wasix_compat_result(__wasixv2_ext_context_switch(id));
}

int wasix_context_destroy(wasix_context_id_t id) {
  return wasix_compat_result(__wasixv2_ext_context_destroy(id));
}
