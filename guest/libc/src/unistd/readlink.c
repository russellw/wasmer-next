#include <unistd.h>
#include <fcntl.h>
#include "syscall.h"

ssize_t readlink(const char *restrict path, char *restrict buf, size_t bufsize)
{
	/* Linux fs/stat.c do_readlinkat rejects a zero buffer size before lookup. */
#ifdef SYS_readlink
	int r = __syscall(SYS_readlink, path, buf, bufsize);
#else
	int r = __syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsize);
#endif
	return __syscall_ret(r);
}
