#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *child_argv[] = {argv[1], "started", 0};
    execv(argv[1], child_argv);
    perror("execv");
    return 88;
}
