#include "syscalls.h"

int wlk_main(long *stack) {
    long argc = stack[0];
    char **argv = (char **)&stack[1];
    if (argc != 2) return 64;
    long fd = syscall4(SYS_openat, -100, (long)argv[1], 0, 0);
    if (fd < 0) return 70;
    if (syscall6(9, 0, 0, 1, 2, fd, 0) != -22) return 71; /* zero-length mmap is EINVAL */
    char *anonymous = (char *)syscall6(9, 0, 4096, 3, 0x22, 0xffffffff, 0);
    if ((isize)anonymous < 0) return 72; /* fd is a zero-extended Linux int -1 */
    anonymous[0] = 'A';
    if (anonymous[0] != 'A' || syscall2(11, (isize)anonymous, 4096) < 0) return 73;
    char *mapping = (char *)syscall6(9, 0, 1, 3, 2, fd, 0); /* rounded one-byte MAP_PRIVATE */
    if ((isize)mapping < 0) return 74;
    if (syscall1(SYS_close, fd) < 0) return 75;

    static const char original[] = "mmap fixture\n";
    for (usize i = 0; i < sizeof(original) - 1; ++i) {
        if (mapping[i] != original[i]) return 76;
    }
    mapping[0] = 'X';
    if (mapping[0] != 'X' || mapping[1] != 'm') return 77;
    if (syscall2(11, (isize)mapping, 4096) < 0) return 78; /* munmap */

    put_str("file-mmap=private-ok anon=ok zero=EINVAL\n");
    return 0;
}
