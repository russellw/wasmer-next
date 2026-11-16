#include "syscalls.h"

#define SYS_dup 32
#define SYS_dup2 33
#define SYS_fcntl 72
#define SYS_dup3 292
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define FD_CLOEXEC 1
#define ERRNO_EBADF 9
#define ERRNO_EINVAL 22

int wlk_main(long *stack) {
    long argc = stack[0];
    char **argv = (char **)&stack[1];
    if (argc != 2) return 64;

    long fd = syscall4(SYS_openat, -100, (long)argv[1], 0x242, 0600);
    if (fd < 0) return 70;
    if (syscall3(SYS_fcntl, fd, F_GETFD, 0) != 0) return 71;
    if (syscall3(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC) != 0) return 72;
    if (syscall3(SYS_fcntl, fd, F_GETFD, 0) != FD_CLOEXEC) return 73;
    if ((syscall3(SYS_fcntl, fd, F_GETFL, 0) & 3) != 2) return 74;

    long copy = syscall1(SYS_dup, fd);
    if (copy < 0) return 75;
    if (syscall3(SYS_write, fd, (long)"A", 1) != 1) return 76;
    if (syscall3(SYS_write, copy, (long)"B", 1) != 1) return 77;
    if (syscall2(SYS_dup2, fd, fd) != fd) return 78;
    if (syscall3(SYS_write, copy, (long)"C", 1) != 1) return 79;

    if (syscall3(SYS_dup3, fd, copy, 0) != copy) return 80;
    if (syscall3(SYS_write, copy, (long)"D", 1) != 1) return 81;
    if (syscall3(SYS_dup3, fd, fd, 0) != -ERRNO_EINVAL) return 82;
    if (syscall2(SYS_dup2, -1, -1) != -ERRNO_EBADF) return 83;

    if (syscall1(SYS_close, copy) != 0) return 84;
    if (syscall1(SYS_close, fd) != 0) return 85;
    put_str("fd-ops=ok\n");
    return 0;
}
