#include <sched.h>
#include "syscall.h"

/* wasixv2: the Linux syscall, as glibc calls it, where musl refuses with ENOSYS. It acts on
 * the thread pid names (0: the calling thread), which for a process is its main thread. */
int sched_setscheduler(pid_t pid, int sched, const struct sched_param *param)
{
	return syscall(SYS_sched_setscheduler, pid, sched, param);
}
