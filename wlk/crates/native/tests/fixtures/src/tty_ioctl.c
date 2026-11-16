#include "syscalls.h"

#define SYS_ioctl 16
#define SYS_close 3
#define TIOCGPGRP 0x540f
#define UNKNOWN_IOCTL 0xdeadbeef
#define ERRNO_EBADF 9
#define ERRNO_ENOTTY 25

int wlk_main(long *stack) {
    (void)stack;
    int foreground_group = -1;
    long stream_result = syscall3(SYS_ioctl, 0, TIOCGPGRP, (long)&foreground_group);
    long stream_errno = stream_result < 0 ? -stream_result : 0;
    long close_result = syscall1(SYS_close, 0);
    long invalid_result = syscall3(SYS_ioctl, 0, TIOCGPGRP, (long)&foreground_group);
    long invalid_errno = invalid_result < 0 ? -invalid_result : 0;
    long unknown_result = syscall3(SYS_ioctl, -1, UNKNOWN_IOCTL, 0);
    long unknown_errno = unknown_result < 0 ? -unknown_result : 0;

    if (stream_result != -ERRNO_ENOTTY || close_result != 0 || invalid_result != -ERRNO_EBADF ||
        unknown_result != -ERRNO_EBADF) {
        put_str("ioctl-errors=failed stream=");
        put_num(stream_result);
        put_str(" stream-errno=");
        put_num(stream_errno);
        put_str(" close=");
        put_num(close_result);
        put_str(" invalid=");
        put_num(invalid_result);
        put_str(" invalid-errno=");
        put_num(invalid_errno);
        put_str(" unknown=");
        put_num(unknown_result);
        put_str(" unknown-errno=");
        put_num(unknown_errno);
        put_str("\n");
        return 41;
    }

    put_str("ioctl-errors=ENOTTY,EBADF,EBADF\n");
    return 0;
}
