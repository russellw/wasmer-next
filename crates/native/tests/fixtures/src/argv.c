#include "syscalls.h"

int wlk_main(long *stack) {
    long argc = stack[0];
    char **argv = (char **)&stack[1];
    put_str("argc=");
    put_num(argc);
    put_str("\n");
    for (long i = 1; i < argc; ++i) {
        put_str("arg=");
        put_str(argv[i]);
        put_str("\n");
    }
    return 0;
}
