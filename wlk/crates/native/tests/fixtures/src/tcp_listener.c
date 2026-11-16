#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int read_exact(int fd, char *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, buffer + offset, length - offset);
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int write_exact(int fd, const char *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, buffer + offset, length - offset);
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *end = 0;
    unsigned long port = strtoul(argv[1], &end, 10);
    if (!end || *end != '\0' || port == 0 || port > 65535) return 65;

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 70;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0) return 71;
    if (listen(listener, 1) < 0) return 72;

    int client = accept(listener, 0, 0);
    if (client < 0) return 73;
    const char request[] = "host-request";
    char received[sizeof(request) - 1];
    if (read_exact(client, received, sizeof(received)) < 0) return 74;
    if (memcmp(received, request, sizeof(received)) != 0) return 75;

    const char response[] = "guest-reply";
    if (write_exact(client, response, sizeof(response) - 1) < 0) return 76;
    printf("listener=%s\n", response);
    close(client);
    close(listener);
    return 0;
}
