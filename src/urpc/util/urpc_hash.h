/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc hash
 */

#ifndef URPC_HASH_H
#define URPC_HASH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BITS_PER_UINT32 32

static inline uint32_t urpc_mhash_finish(uint32_t hash_value)
{
    hash_value ^= hash_value >> 16;
    hash_value *= 0x85ebca6b;
    hash_value ^= hash_value >> 13;
    hash_value *= 0xc2b2ae35;
    hash_value ^= hash_value >> 16;
    return hash_value;
}

static inline uint32_t urpc_hash_finish(uint32_t hash_value, uint32_t final)
{
    return urpc_mhash_finish(hash_value ^ final);
}

static inline uint32_t get_unaligned_u32(const uint32_t *ptr)
{
    const uint8_t *_ptr = (const uint8_t *)ptr;
    return ntohl((_ptr[0] << 24) | (_ptr[1] << 16) | (_ptr[2] << 8) | _ptr[3]);
}

static inline uint32_t urpc_hash_rot(uint32_t a, uint32_t b)
{
    return (a << b) | (a >> (32 - b));
}

static inline uint32_t urpc_mhash_add__(uint32_t hash_value, uint32_t data)
{
    /* zero-valued 'data' will not change the 'hash' value */
    if (data == 0) {
        return hash_value;
    }

    data *= 0xcc9e2d51;
    data = urpc_hash_rot(data, 15);
    data *= 0x1b873593;
    return hash_value ^ data;
}

static inline uint32_t urpc_mhash_add(uint32_t hash_value, uint32_t data)
{
    hash_value = urpc_mhash_add__(hash_value, data);
    hash_value = urpc_hash_rot(hash_value, 13);
    return hash_value * 5 + 0xe6546b64;
}

static inline uint32_t urpc_hash_add(uint32_t hash_value, uint32_t data)
{
    return urpc_mhash_add(hash_value, data);
}

static inline uint32_t urpc_hash_add64(uint32_t hash_value, uint64_t data)
{
    return urpc_hash_add(urpc_hash_add(hash_value, (uint32_t)data), data >> BITS_PER_UINT32);
}

/* Returns the hash of memory bytes'. */
static inline uint32_t urpc_hash_bytes(const void *ptr, uint32_t n_bytes, uint32_t basis)
{
    const uint32_t *hash_ptr = ptr;
    uint32_t tmp_bytes = n_bytes;
    uint32_t hash_value;

    hash_value = basis;
    while (tmp_bytes >= sizeof(uint32_t)) {
        hash_value = urpc_hash_add(hash_value, get_unaligned_u32(hash_ptr));
        tmp_bytes -= (uint32_t)sizeof(uint32_t);
        hash_ptr += 1;
    }

    if (tmp_bytes != 0) {
        uint32_t left = 0;
        memcpy(&left, hash_ptr, tmp_bytes);
        hash_value = urpc_hash_add(hash_value, left);
    }

    return urpc_hash_finish(hash_value, n_bytes);
}

static inline uint32_t urpc_hash_string(const char *str, uint32_t basis)
{
    return urpc_hash_bytes(str, (uint32_t)strlen(str), basis);
}

static inline uint32_t urpc_hash_uint64_base(const uint64_t key, const uint32_t base)
{
    return urpc_hash_finish(urpc_hash_add64(base, key), 8);
}

static inline uint32_t urpc_hash_uint64(const uint64_t key)
{
    return urpc_hash_uint64_base(key, 0);
}

#ifdef __cplusplus
}
#endif

#endif // URPC_HASH_H
