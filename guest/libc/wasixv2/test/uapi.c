/* Compile-only check, done by wasixv2/test/run.sh: the sysroot's Linux UAPI
 * headers work together with libc's, and <asm/unistd.h> carries libc's
 * syscall numbers. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/landlock.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <linux/version.h>

#ifndef LINUX_VERSION_CODE
#error "<linux/version.h> does not define LINUX_VERSION_CODE"
#endif

_Static_assert(__NR_openat == SYS_openat, "asm/unistd.h is not libc's");
_Static_assert(__NR_lseek == SYS_lseek, "asm/unistd.h is not libc's");
_Static_assert(__BITS_PER_LONG == 8 * sizeof(long), "wrong __BITS_PER_LONG");
_Static_assert(sizeof(__kernel_long_t) == sizeof(long), "wrong __kernel_long_t");
_Static_assert(sizeof(__kernel_off_t) == sizeof(long), "wrong __kernel_off_t");
_Static_assert(sizeof(__u64) == 8, "wrong __u64");
_Static_assert(FICLONE == _IOW(0x94, 9, int), "FICLONE differs from <sys/ioctl.h>'s _IOW");
_Static_assert(FUTEX_WAIT == 0, "wrong FUTEX_WAIT");
_Static_assert(sizeof(struct sockaddr_nl) == 12, "wrong struct sockaddr_nl");

_Static_assert(LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS == (1U << 4), "wrong Landlock NNP flag");
