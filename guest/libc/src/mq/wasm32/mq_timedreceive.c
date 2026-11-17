#include <mqueue.h>
#include <stddef.h>
#include "syscall.h"

_Static_assert(sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8,
	"wasm32 timespec must have the kernel time64 layout");

ssize_t mq_timedreceive(mqd_t mqd, char *restrict msg, size_t len, unsigned *restrict prio, const struct timespec *restrict at)
{
	/* Linux ipc/mqueue.c uses get_timespec64 on the original deadline pointer;
	 * kernel/time/time.c drops the 32-bit ABI's tv_nsec padding. */
	return syscall_cp(SYS_mq_timedreceive_time64, mqd, msg, len, prio, at);
}
