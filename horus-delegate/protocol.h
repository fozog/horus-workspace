/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HORUS_DELEGATE_PROTOCOL_H
#define HORUS_DELEGATE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define HD_VERSION 1
#define HD_GET_PUBLIC_ADDRESSES 1
#define HD_OK 0
#define HD_PARTIAL 1
#define HD_FAILED 2
#define HD_BAD_REQUEST 3
#define HD_MAX_ADDRESSES 32
#define HD_HEADER_SIZE 8
#define HD_MAX_MESSAGE (HD_HEADER_SIZE + HD_MAX_ADDRESSES * 17)

/* Header bytes: version, opcode, status, address count, big-endian request ID.
 * Request status/count are zero. Response entries: family (4 or 6), followed
 * by 4 or 16 network-order bytes. SOCK_SEQPACKET supplies message boundaries. */
static inline uint32_t hd_request_id(const uint8_t *bytes)
{
    return ((uint32_t)bytes[4] << 24) | ((uint32_t)bytes[5] << 16) |
           ((uint32_t)bytes[6] << 8) | bytes[7];
}

static inline void hd_header(uint8_t *bytes, uint8_t opcode, uint8_t status,
                             uint8_t count, uint32_t id)
{
    bytes[0] = HD_VERSION; bytes[1] = opcode; bytes[2] = status; bytes[3] = count;
    bytes[4] = id >> 24; bytes[5] = id >> 16; bytes[6] = id >> 8; bytes[7] = id;
}

typedef struct hd_address {
    uint8_t family;
    uint8_t bytes[16];
} hd_address_t;

#endif
