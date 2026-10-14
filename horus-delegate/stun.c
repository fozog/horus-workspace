/* SPDX-License-Identifier: BSD-3-Clause */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "stun.h"

#define STUN_COOKIE 0x2112a442u
#define STUN_TIMEOUT_MS 1000
#define STUN_TOTAL_MS 8000

static uint16_t read16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int parse_response(const uint8_t *buf, size_t len, const uint8_t *id,
                          uint8_t family, hd_address_t *out)
{
    if (len < 20 || read16(buf) != 0x0101 || read32(buf + 4) != STUN_COOKIE ||
        memcmp(buf + 8, id, 12) || read16(buf + 2) != len - 20 || (read16(buf + 2) & 3))
        return -1;
    size_t pos = 20;
    bool found = false, found_xor = false;
    while (pos < len) {
        if (len - pos < 4)
            return -1;
        uint16_t type = read16(buf + pos), size = read16(buf + pos + 2);
        pos += 4;
        size_t padded = ((size_t)size + 3) & ~(size_t)3;
        if (padded > len - pos)
            return -1;
        if (type == 1 || type == 0x20) {
            if (size < 4 || buf[pos] != 0 || (buf[pos + 1] != 1 && buf[pos + 1] != 2))
                return -1;
            uint8_t mapped_family = buf[pos + 1] == 1 ? 4 : 6;
            size_t address_size = mapped_family == 4 ? 4 : 16;
            if (size != 4 + address_size)
                return -1;
            if (mapped_family == family && (!found_xor || type == 0x20)) {
                memset(out, 0, sizeof(*out));
                out->family = family;
                memcpy(out->bytes, buf + pos + 4, address_size);
                if (type == 0x20) {
                    uint8_t mask[16] = {0x21, 0x12, 0xa4, 0x42};
                    memcpy(mask + 4, id, 12);
                    for (size_t i = 0; i < address_size; i++)
                        out->bytes[i] ^= mask[i];
                    found_xor = true;
                }
                found = true;
            }
        }
        pos += padded;
    }
    return found ? 0 : -1;
}

static int query(const struct addrinfo *ai, int64_t total_deadline, hd_address_t *out)
{
    int fd = socket(ai->ai_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    int result = -1;
    uint8_t request[20] = {0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42};
    size_t random_size = 0;
    while (random_size < 12) {
        ssize_t n = getrandom(request + 8 + random_size, 12 - random_size, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto done;
        random_size += n;
    }
    /* Connected UDP accepts datagrams only from this server address and port. */
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0 ||
        send(fd, request, sizeof(request), 0) != sizeof(request))
        goto done;
    int64_t now = milliseconds();
    if (now < 0)
        goto done;
    int64_t deadline = now + STUN_TIMEOUT_MS;
    if (deadline > total_deadline)
        deadline = total_deadline;
    for (;;) {
        now = milliseconds();
        if (now < 0 || now >= deadline) {
            errno = ETIMEDOUT;
            break;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0) {
            if (ready == 0)
                errno = ETIMEDOUT;
            break;
        }
        uint8_t response[2048];
        ssize_t n = recv(fd, response, sizeof(response), MSG_TRUNC);
        if (n < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (n < 0)
            break;
        if ((size_t)n <= sizeof(response) &&
            parse_response(response, n, request + 8, ai->ai_family == AF_INET ? 4 : 6, out) == 0) {
            result = 0;
            break;
        }
        fprintf(stderr, "delegate: rejected malformed or unrelated STUN response\n");
    }
done:
    if (result != 0)
        fprintf(stderr, "delegate: STUN IPv%d query failed: %s\n",
                ai->ai_family == AF_INET ? 4 : 6, strerror(errno));
    close(fd);
    return result;
}

uint8_t stun_public_addresses(const char *host, const char *service,
                              hd_address_t addresses[HD_MAX_ADDRESSES], uint8_t *count)
{
    *count = 0;
    bool have4 = false, have6 = false, failed = false;
    int64_t now = milliseconds();
    if (now < 0) {
        perror("delegate: monotonic clock");
        return HD_FAILED;
    }
    int64_t deadline = now + STUN_TOTAL_MS;
    for (unsigned f = 0; f < 2; f++) {
        struct addrinfo hints = {.ai_family = f == 0 ? AF_INET : AF_INET6, .ai_socktype = SOCK_DGRAM};
        struct addrinfo *results = NULL;
        int error = getaddrinfo(host, service, &hints, &results);
        if (error != 0) {
            fprintf(stderr, "delegate: STUN IPv%d DNS: %s\n", f == 0 ? 4 : 6, gai_strerror(error));
            failed = true;
            continue;
        }
        for (struct addrinfo *ai = results; ai != NULL; ai = ai->ai_next) {
            now = milliseconds();
            if (now < 0 || now >= deadline) {
                fprintf(stderr, "delegate: STUN discovery deadline exceeded\n");
                failed = true;
                break;
            }
            hd_address_t address;
            if (query(ai, deadline, &address) != 0) {
                failed = true;
                continue;
            }
            if (address.family == 4) have4 = true;
            else have6 = true;
            bool duplicate = false;
            for (unsigned i = 0; i < *count; i++)
                if (addresses[i].family == address.family && memcmp(addresses[i].bytes, address.bytes, 16) == 0)
                    duplicate = true;
            if (!duplicate) {
                if (*count == HD_MAX_ADDRESSES) {
                    fprintf(stderr, "delegate: public address set exceeds protocol capacity\n");
                    failed = true;
                    break;
                }
                addresses[(*count)++] = address;
            }
        }
        freeaddrinfo(results);
    }
    return *count == 0 ? HD_FAILED : have4 && have6 && !failed ? HD_OK : HD_PARTIAL;
}
