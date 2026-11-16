#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    printf("libc-argv=%s\n", argv[1]);
    printf("libc-pid=%ld\n", (long)getpid());

    const char message[] = "wlk-native-libc-file\n";
    int fd = open(argv[2], O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 70;
    if (write(fd, message, sizeof(message) - 1) != (ssize_t)(sizeof(message) - 1)) return 71;
    if (close(fd) < 0) return 72;

    fd = open(argv[2], O_RDONLY);
    if (fd < 0) return 73;
    char buffer[64] = {0};
    ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    if (count < 0) return 74;
    if (close(fd) < 0) return 75;
    printf("libc-file=%s", buffer);
    return strcmp(buffer, message) == 0 ? 0 : 76;
}
