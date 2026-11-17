#include <sched.h>
#include "syscall.h"

/* wasixv2: the Linux syscall, as glibc calls it, where musl refuses with ENOSYS. It acts on
 * the thread pid names (0: the calling thread), which for a process is its main thread. */
int sched_getscheduler(pid_t pid)
{
	return syscall(SYS_sched_getscheduler, pid);
}
