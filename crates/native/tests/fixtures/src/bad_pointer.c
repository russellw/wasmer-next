#include "syscalls.h"

int wlk_main(long *stack) {
    (void)stack;
    isize result = syscall3(SYS_write, 1, 1, 1);
    if (result == -14) {
        put_str("bad-pointer=EFAULT\n");
        return 0;
    }
    put_str("bad-pointer=unexpected\n");
    return 80;
}
