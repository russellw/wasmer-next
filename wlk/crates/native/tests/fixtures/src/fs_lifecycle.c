#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char dir[512], file[512], renamed[512];
    if (snprintf(dir, sizeof(dir), "%s/dir", argv[1]) >= (int)sizeof(dir)) return 65;
    if (snprintf(file, sizeof(file), "%s/item.txt", dir) >= (int)sizeof(file)) return 65;
    if (snprintf(renamed, sizeof(renamed), "%s/renamed.txt", dir) >= (int)sizeof(renamed)) return 65;

    if (mkdir(dir, 0700) != 0) return 70;
    int fd = open(file, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return 71;
    const char content[] = "filesystem-lifecycle\n";
    if (write(fd, content, sizeof(content) - 1) != (ssize_t)(sizeof(content) - 1)) return 72;

    struct stat descriptor_stat = {0};
    if (fstat(fd, &descriptor_stat) != 0 || descriptor_stat.st_size != sizeof(content) - 1) return 73;
    if (close(fd) != 0) return 74;

    struct stat path_stat = {0};
    if (stat(file, &path_stat) != 0 || path_stat.st_size != sizeof(content) - 1) return 75;

    DIR *directory = opendir(dir);
    if (!directory) return 76;
    int saw_item = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != 0) {
        if (strcmp(entry->d_name, "item.txt") == 0) saw_item = 1;
    }
    if (closedir(directory) != 0 || !saw_item) return 77;

    FILE *input = fopen(file, "r");
    if (!input) return 78;
    char buffer[64] = {0};
    if (!fgets(buffer, sizeof(buffer), input) || strcmp(buffer, content) != 0) return 79;
    if (fclose(input) != 0) return 80;

    if (rename(file, renamed) != 0) return 81;
    if (unlink(renamed) != 0) return 82;
    if (rmdir(dir) != 0) return 83;
    puts("filesystem-lifecycle=ok");
    return 0;
}
