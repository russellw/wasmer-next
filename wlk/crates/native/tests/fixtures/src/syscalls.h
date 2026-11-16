#ifndef WLK_NATIVE_TEST_SYSCALLS_H
#define WLK_NATIVE_TEST_SYSCALLS_H

typedef unsigned long usize;
typedef long isize;

#define SYS_read 0
#define SYS_write 1
#define SYS_openat 257
#define SYS_close 3
#define SYS_getpid 39

static inline isize syscall0(isize nr) {
    isize result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr) : "rcx", "r11", "memory");
    return result;
}

static inline isize syscall1(isize nr, isize a1) {
    isize result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a1) : "rcx", "r11", "memory");
    return result;
}

static inline isize syscall2(isize nr, isize a1, isize a2) {
    isize result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return result;
}

static inline isize syscall3(isize nr, isize a1, isize a2, isize a3) {
    isize result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return result;
}

static inline isize syscall4(isize nr, isize a1, isize a2, isize a3, isize a4) {
    isize result;
    register isize r10 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return result;
}

static inline isize syscall6(isize nr, isize a1, isize a2, isize a3, isize a4, isize a5, isize a6) {
    isize result;
    register isize r10 __asm__("r10") = a4;
    register isize r8 __asm__("r8") = a5;
    register isize r9 __asm__("r9") = a6;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}

static inline usize str_len(const char *text) {
    usize len = 0;
    while (text[len]) ++len;
    return len;
}

static inline void write_all(int fd, const char *text, usize len) {
    while (len) {
        isize count = syscall3(SYS_write, fd, (isize)text, (isize)len);
        if (count <= 0) return;
        text += count;
        len -= (usize)count;
    }
}

static inline void put_str(const char *text) {
    write_all(1, text, str_len(text));
}

static inline void put_num(isize value) {
    char buffer[32];
    usize len = 0;
    if (value < 0) {
        put_str("-");
        value = -value;
    }
    do {
        buffer[len++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (len) write_all(1, &buffer[--len], 1);
}

#endif
