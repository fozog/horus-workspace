/* SPDX-License-Identifier: BSD-3-Clause */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "stun.h"

/* HORUS_DELEGATE_SOCKET_DEFAULT must match delegate/client.h in the horus
 * project; it is duplicated here rather than shared because this executable
 * has no dependency on the horus source tree. */
#define HORUS_DELEGATE_SOCKET_DEFAULT "/var/run/horus/delegate.sock"

static void run(int fd)
{
    const char *host = getenv("HORUS_STUN_HOST");
    const char *service = getenv("HORUS_STUN_PORT");
    if (host == NULL) host = "ovh1.p2pd.net";
    if (service == NULL) service = "3478";
    for (;;) {
        uint8_t request[HD_MAX_MESSAGE], response[HD_MAX_MESSAGE];
        ssize_t n = recv(fd, request, sizeof(request), MSG_TRUNC);
        printf("delegate: received request of size %zd\n", n);
        fflush(stdout);
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            break;
        if (n < 0) {
            perror("delegate: receive");
            close(fd);
            exit(EXIT_FAILURE);
        }
        if (n < HD_HEADER_SIZE) {
            fprintf(stderr, "delegate: request too short for correlation ID\n");
            close(fd);
            exit(EXIT_FAILURE);
        }
        uint8_t status = HD_BAD_REQUEST, count = 0;
        hd_address_t addresses[HD_MAX_ADDRESSES];
        if (n == HD_HEADER_SIZE && request[0] == HD_VERSION &&
            request[1] == HD_GET_PUBLIC_ADDRESSES && request[2] == 0 && request[3] == 0)
            {
                status = stun_public_addresses(host, service, addresses, &count);
                printf("delegate: received public addresses from STUN: %u\n", count);
                fflush(stdout);
            }
        else
            fprintf(stderr, "delegate: invalid protocol request\n");
        hd_header(response, request[1], status, count, hd_request_id(request));
        size_t size = HD_HEADER_SIZE;
        for (unsigned i = 0; i < count; i++) {
            response[size++] = addresses[i].family;
            size_t bytes = addresses[i].family == 4 ? 4 : 16;
            memcpy(response + size, addresses[i].bytes, bytes);
            size += bytes;
        }
        ssize_t sent;
        do { sent = send(fd, response, size, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
        if (sent != (ssize_t)size) {
            perror("delegate: send");
            close(fd);
            exit(EXIT_FAILURE);
        }
    }
    close(fd);
}

static void usage(void)
{
    fprintf(stderr,
            "Usage: horus-delegate --fd <inherited SOCK_SEQPACKET descriptor>\n"
            "       horus-delegate --connect [<path>]\n"
            "\n"
            "--fd is used when horus spawns this program itself.\n"
            "--connect is for manual/debug use: it connects to the AF_UNIX\n"
            "socket horus falls back to listening on when it could not spawn\n"
            "a companion itself (default path: %s, or $HORUS_DELEGATE_SOCKET).\n",
            HORUS_DELEGATE_SOCKET_DEFAULT);
}

int main(int argc, char **argv)
{
    printf("Starting delegate\n");
    fflush(stdout);

    if (argc == 3 && strcmp(argv[1], "--fd") == 0) {
        char *end;
        errno = 0;
        long value = strtol(argv[2], &end, 10);
        if (errno || *end || value < 0 || value > 1024) {
            fprintf(stderr, "delegate: invalid socket descriptor\n");
            return EXIT_FAILURE;
        }
        int fd = (int)value, type;
        socklen_t type_size = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) != 0 || type != SOCK_SEQPACKET) {
            fprintf(stderr, "delegate: expected a connected SOCK_SEQPACKET socket\n");
            return EXIT_FAILURE;
        }
        run(fd);
        return EXIT_SUCCESS;
    }

    if ((argc == 2 || argc == 3) && strcmp(argv[1], "--connect") == 0) {
        const char *path = argc == 3 ? argv[2] : getenv("HORUS_DELEGATE_SOCKET");
        if (path == NULL || path[0] == '\0') path = HORUS_DELEGATE_SOCKET_DEFAULT;
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        if (strlen(path) >= sizeof(address.sun_path)) {
            fprintf(stderr, "delegate: socket path too long: %s\n", path);
            return EXIT_FAILURE;
        }
        memcpy(address.sun_path, path, strlen(path) + 1);
        int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (fd < 0) {
            perror("delegate: socket");
            return EXIT_FAILURE;
        }
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            fprintf(stderr, "delegate: cannot connect to %s: %s\n", path, strerror(errno));
            close(fd);
            return EXIT_FAILURE;
        }
        fprintf(stderr, "delegate: connected to %s\n", path);
        run(fd);
        return EXIT_SUCCESS;
    }

    usage();
    return EXIT_FAILURE;
}
