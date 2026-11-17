/* wasm32 is static-only for now; the dynamic linker is not supported. */
#define LDSO_ARCH "wasm32"

#define CRTJMP(pc,sp) __builtin_trap()
