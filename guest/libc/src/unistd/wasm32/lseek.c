#include <unistd.h>
#include <errno.h>
#include "syscall.h"

/* wasm32 has no SYS__llseek: the lseek import takes and returns a 64-bit
 * offset. Call it directly, since the __syscallN path passes the offset in
 * one long slot and returns a long, truncating offsets beyond 2 GiB. */
off_t __lseek(int fd, off_t offset, int whence)
{
	long long r = __wasixv2_lseek(fd, offset, whence);
	if (r < 0 && r > -4096) {
		errno = -r;
		return -1;
	}
	return r;
}

weak_alias(__lseek, lseek);
