#include "syscalls.h"

int wlk_main(long *stack) {
    (void)stack;
    isize result = syscall0(0x7fffffff);
    if (result == -38) {
        put_str("unsupported=ENOSYS\n");
        return 0;
    }
    put_str("unsupported=unexpected\n");
    return 79;
}
