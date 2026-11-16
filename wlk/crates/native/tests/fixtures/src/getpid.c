#include "syscalls.h"

int wlk_main(long *stack) {
    (void)stack;
    isize pid = syscall0(SYS_getpid);
    put_str("pid=");
    put_num(pid);
    put_str("\n");
    return pid > 0 ? 0 : 1;
}
