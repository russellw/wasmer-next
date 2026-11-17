#ifndef _WASIXV2_EXT_H
#define _WASIXV2_EXT_H

/* wasm-specific host primitives (the extensions in import module "wasixv2",
 * next to the syscalls).
 *
 * Hand-written for now; lib/wasixv2/codegen/wit/ext.wit in the wasmer repo
 * mirrors these and the wasixv2-codegen C backend will take this file over. */

#define __WASIXV2_EXT_IMPORT(name) \
	__attribute__((__import_module__("wasixv2"), __import_name__(#name)))

/* Size in bytes of the initial process block written by startup_get. */
__WASIXV2_EXT_IMPORT(startup_size)
unsigned __wasixv2_ext_startup_size(void);

/* Write the initial process block into buf, which holds len bytes (at least
 * startup_size()) and is aligned to 16. The layout is what Linux puts on the
 * initial stack:
 *
 *   long argc
 *   char *argv[argc], NULL
 *   char *envp[], NULL
 *   size_t auxv[][2] (key, value pairs), AT_NULL pair
 *   string data (argv/env strings, AT_RANDOM bytes, ...)
 *
 * All pointers are guest addresses inside buf. auxv should carry at least
 * AT_PAGESZ, AT_RANDOM (16 bytes), AT_UID/AT_EUID/AT_GID/AT_EGID, AT_SECURE,
 * AT_HWCAP (0) and optionally AT_EXECFN; never AT_PHDR or AT_SYSINFO_EHDR.
 * Returns 0, or -EINVAL if len is less than startup_size(). */
__WASIXV2_EXT_IMPORT(startup_get)
int __wasixv2_ext_startup_get(void *buf, unsigned long len);

/* clone() for the thread case. The kernel validates flags and creates the
 * task as clone(flags, newsp, ptid, tls, ctid) would; flags must contain
 * CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND and CLONE_THREAD. The host
 * then calls the module's exported wasixv2_thread_start(tid, start_arg) in
 * a new instance on the same shared memory; that entry sets up the stack and
 * TLS from start_arg itself (see src/thread/wasm32/clone.c). Returns the new
 * thread id or -errno. */
__WASIXV2_EXT_IMPORT(thread_spawn)
long __wasixv2_ext_thread_spawn(unsigned long flags, void *start_arg,
	int *ptid, void *tls, int *ctid);

/* Register the signal trampoline (a function table index) for the thread
 * group. The host calls it as fn(signo, siginfo_t *, ucontext_t *) on top of
 * the interrupted stack, with the frame below __stack_pointer minus the
 * 128-byte red zone; see src/signal/wasm32/sigtramp.c. */
__WASIXV2_EXT_IMPORT(signal_callback_register)
long __wasixv2_ext_signal_callback_register(unsigned callback);

/* The uc_mcontext.__gregs slots of a signal frame. The host writes slots 0
 * to 5 and reads back 2 to 4 at sigreturn; 16 to 31 belong to libc. */
#define WASM_MC_HANDLER 0	/* sa_handler, a table index */
#define WASM_MC_FLAGS 1		/* sa_flags */
#define WASM_MC_SP 2		/* the interrupted __stack_pointer */
#define WASM_MC_TLS 3		/* the interrupted __tls_base */
#define WASM_MC_RESTART 4	/* 1: the interrupted syscall reruns after the
				 * handler; clearing it makes it fail with EINTR */
#define WASM_MC_NPARAMS 5	/* the handler's parameter count, 0 to 3 */
#define WASM_MC_INCP 16		/* libc: the interrupted context was in a
				 * cancellation point */

/* setjmp and longjmp of the asyncify build configuration, which has no wasm
 * exceptions (src/setjmp/wasm32). stack_save records the call stack in
 * snapshot, 24 bytes aligned to 8 that only the host reads, and returns 0;
 * once stack_restore resumes it, it returns 1 with the value stack_restore
 * was given written to val. Modules not instrumented with asyncify get
 * -ENOSYS. */
__WASIXV2_EXT_IMPORT(stack_save)
long __wasixv2_ext_stack_save(void *snapshot, int *val);

__WASIXV2_EXT_IMPORT(stack_restore)
_Noreturn void __wasixv2_ext_stack_restore(const void *snapshot, int val);

/* Host-owned loading and symbol relocation; libc runs queued constructors only
 * after successful publication. Handles are guest pointers by the existing WIT. */
__WASIXV2_EXT_IMPORT(dl_open)
long __wasixv2_ext_dl_open(const char *, int, const char *, unsigned long,
	void **, char *, unsigned long);
__WASIXV2_EXT_IMPORT(dl_sym)
long __wasixv2_ext_dl_sym(void *, const char *, unsigned long, void **,
	char *, unsigned long);
__WASIXV2_EXT_IMPORT(dl_close)
long __wasixv2_ext_dl_close(void *);
__WASIXV2_EXT_IMPORT(dl_next_init)
long __wasixv2_ext_dl_next_init(void **);

#endif
