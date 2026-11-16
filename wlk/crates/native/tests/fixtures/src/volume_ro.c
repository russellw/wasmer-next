#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    FILE *file = fopen(argv[1], "w");
    if (file) {
        fclose(file);
        puts("readonly=unexpected-write");
        return 80;
    }
    if (errno != EROFS && errno != EACCES && errno != EPERM) return 81;
    puts("readonly=denied");
    return 0;
}
