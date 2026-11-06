#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    unsigned long port = strtoul(argv[1], 0, 10);
    if (port == 0 || port > 65535) return 65;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 70;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, "10.0.2.2", &address.sin_addr) != 1) return 71;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) return 72;

    const char request[] = "tcp-request";
    if (send(fd, request, sizeof(request) - 1, 0) != sizeof(request) - 1) return 73;
    char response[32] = {0};
    ssize_t count = recv(fd, response, sizeof(response) - 1, 0);
    if (count < 0) return 74;
    response[count] = 0;
    if (strcmp(response, "tcp-reply") != 0) return 75;
    printf("tcp=%s\n", response);
    close(fd);
    return 0;
}
