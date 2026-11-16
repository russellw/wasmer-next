#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    FILE *file = fopen(argv[1], "w");
    if (!file) return 70;
    const char message[] = "mapped-volume-data\n";
    if (fwrite(message, 1, sizeof(message) - 1, file) != sizeof(message) - 1) return 71;
    if (fclose(file) != 0) return 72;
    file = fopen(argv[1], "r");
    if (!file) return 73;
    char buffer[64] = {0};
    if (!fgets(buffer, sizeof(buffer), file)) return 74;
    if (fclose(file) != 0) return 75;
    if (strcmp(buffer, message) != 0) return 76;
    printf("volume=%s", buffer);
    return 0;
}
