#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;

    pid_t child = fork();
    if (child < 0) return 70;
    if (child == 0) {
        execl(argv[1], argv[1], "started", (char *)0);
        _exit(127);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) return 71;
    if (!WIFEXITED(status)) return 72;
    printf("dynamic-fork-exec=%d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status);
}
