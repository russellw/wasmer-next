#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    printf("exec-child=%s\n", argv[1]);
    return 29;
}
