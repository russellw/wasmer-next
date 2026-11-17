#include <signal.h>
#include <errno.h>

int sigwait(const sigset_t *restrict mask, int *restrict sig)
{
	siginfo_t si;
	int ret;
	/* Unlike Linux's do_sigtimedwait, POSIX sigwait does not return EINTR. */
	do ret = sigtimedwait(mask, &si, 0);
	while (ret < 0 && errno == EINTR);
	if (ret < 0)
		return errno;
	*sig = si.si_signo;
	return 0;
}
