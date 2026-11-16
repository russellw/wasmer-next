#include "syscalls.h"

int wlk_main(long *stack) {
    (void)stack;
    put_str("dynamic-program-started\n");
    return 0;
}
