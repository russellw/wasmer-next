#include <signal.h>
#include <stddef.h>
#include <time.h>
#include "syscall.h"

_Static_assert(sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8,
	"wasm32 timespec must have the kernel time64 layout");

int sigtimedwait(const sigset_t *restrict mask, siginfo_t *restrict si, const struct timespec *restrict timeout)
{
	/* Linux kernel/time/time.c get_timespec64 copies from the user's pointer
	 * and drops the 32-bit ABI's tv_nsec padding. Pass the native layout so
	 * an invalid timeout faults in the kernel rather than being read here. */
	int ret = __syscall_ret(__syscall_cp(SYS_rt_sigtimedwait_time64,
		mask, si, timeout, _NSIG/8));
#ifdef __wasixv2__
	/* glibc sysdeps/unix/sysv/linux/sigtimedwait.c __sigtimedwait64 folds
	 * Linux SI_TKILL from raise() into the POSIX SI_USER result here. */
	if (ret >= 0 && si && si->si_code == SI_TKILL) si->si_code = SI_USER;
#endif
	return ret;
}
