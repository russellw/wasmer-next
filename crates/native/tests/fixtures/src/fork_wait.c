#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int fd = open(argv[1], O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 69;
    if (write(fd, "A", 1) != 1) return 68;

    pid_t child = fork();
    if (child < 0) return 70;
    if (child == 0) {
        printf("child-pid=%ld\n", (long)getpid());
        fflush(stdout);
        if (write(fd, "B", 1) != 1) _exit(37);
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) return 71;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 72;
    if (write(fd, "C", 1) != 1) return 73;
    if (close(fd) != 0) return 74;

    fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 75;
    char buffer[4] = {0};
    ssize_t count = read(fd, buffer, sizeof(buffer));
    close(fd);
    if (count != 3 || strcmp(buffer, "ABC") != 0) return 76;

    printf("fork-wait=%d file=%s\n", WEXITSTATUS(status), buffer);
    return 0;
}
