/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef HORUS_DELEGATE_STUN_H
#define HORUS_DELEGATE_STUN_H
#include "protocol.h"

/* Queries all resolved server addresses for both families, deduplicates results.
 * Logs network/protocol errors; returns HD_OK, HD_PARTIAL or HD_FAILED.
 * No DPDK dependency and no network operations in the probe. */
uint8_t stun_public_addresses(const char *host, const char *service,
                              hd_address_t addresses[HD_MAX_ADDRESSES], uint8_t *count);
#endif
