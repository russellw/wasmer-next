#ifndef _WASIXV2_VFORK_H
#define _WASIXV2_VFORK_H

/* clone(CLONE_VM | CLONE_VFORK) running func(arg) as the child in this
 * instance; returns the child's pid once it exited or exec'd, or -errno
 * (src/process/wasm32/vfork.c). */
hidden long __wasixv2_vfork_call(int (*)(void *), void *, unsigned long);

#endif
