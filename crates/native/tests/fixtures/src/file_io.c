#include "syscalls.h"

int wlk_main(long *stack) {
    long argc = stack[0];
    char **argv = (char **)&stack[1];
    if (argc != 2) return 64;

    const char *path = argv[1];
    const char message[] = "wlk-native-file-fixture\n";
    long fd = syscall4(SYS_openat, -100, (long)path, 0x242, 0600); /* O_RDWR|O_CREAT|O_TRUNC */
    if (fd < 0) return 70;
    if (syscall3(SYS_write, fd, (long)message, sizeof(message) - 1) != (long)(sizeof(message) - 1)) return 71;
    if (syscall1(SYS_close, fd) < 0) return 72;

    fd = syscall4(SYS_openat, -100, (long)path, 0, 0);
    if (fd < 0) return 73;
    char buffer[64];
    long count = syscall3(SYS_read, fd, (long)buffer, sizeof(buffer));
    if (count < 0) return 74;
    write_all(1, buffer, (usize)count);
    if (syscall1(SYS_close, fd) < 0) return 75;
    return 0;
}
