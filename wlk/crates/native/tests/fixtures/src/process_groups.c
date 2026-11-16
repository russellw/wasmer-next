#include "syscalls.h"

#define SYS_setpgid 109
#define SYS_getpgrp 111
#define SYS_getpgid 121
#define SYS_getsid 124
#define ERRNO_EPERM 1

int wlk_main(long *stack) {
    (void)stack;
    long pid = syscall0(SYS_getpid);
    long before = syscall0(SYS_getpgrp);
    long before_pgid = syscall1(SYS_getpgid, 0);
    long sid = syscall1(SYS_getsid, 0);
    long changed = syscall2(SYS_setpgid, 0, 0);
    long after = syscall0(SYS_getpgrp);
    long after_pgid = syscall1(SYS_getpgid, 0);

    if (pid != 2 || before != pid || before != before_pgid || sid != pid ||
        changed != -ERRNO_EPERM || after != before || after_pgid != before_pgid) {
        put_str("process-groups=failed pid=");
        put_num(pid);
        put_str(" before=");
        put_num(before);
        put_str(" pgid=");
        put_num(before_pgid);
        put_str(" sid=");
        put_num(sid);
        put_str(" setpgid=");
        put_num(changed);
        put_str(" after=");
        put_num(after);
        put_str(" after-pgid=");
        put_num(after_pgid);
        put_str("\n");
        return 40;
    }

    put_str("process-groups=ok\n");
    return 0;
}
