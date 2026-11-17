#include <unistd.h>
#include "syscall.h"

ssize_t readlinkat(int fd, const char *restrict path, char *restrict buf, size_t bufsize)
{
	/* Keep Linux do_readlinkat's EINVAL and error precedence for an empty buffer. */
	int r = __syscall(SYS_readlinkat, fd, path, buf, bufsize);
	return __syscall_ret(r);
}
