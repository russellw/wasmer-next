#include <features.h>

/* Exactly the kernel's asm-generic struct sigaction (16 bytes, mask at
 * offset 8). wasm32 has no SA_RESTORER, and unlike the generic header there
 * is no trailing padding member: the layout is asserted against the wasixv2
 * definitions in src/internal/wasm32/wasixv2_asserts.c. */
struct k_sigaction {
	void (*handler)(int);
	unsigned long flags;
	unsigned mask[2];
};

hidden void __restore(), __restore_rt();
