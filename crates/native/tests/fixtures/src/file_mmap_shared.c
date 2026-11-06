#include "syscalls.h"

int wlk_main(long *stack) {
    long argc = stack[0];
    char **argv = (char **)&stack[1];
    if (argc != 2) return 64;
    long fd = syscall4(SYS_openat, -100, (long)argv[1], 0, 0);
    if (fd < 0) return 70;
    isize result = syscall6(9, 0, 4096, 1, 1, fd, 0); /* PROT_READ, MAP_SHARED */
    syscall1(SYS_close, fd);
    if (result == -38) {
        put_str("file-mmap-shared=ENOSYS\n");
        return 0;
    }
    if (result >= 0) syscall2(11, result, 4096); /* munmap */
    put_str("file-mmap-shared=unexpected\n");
    return 82;
}
