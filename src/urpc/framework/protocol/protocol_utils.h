/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uRPC 2.0 protocol utils
 * Create: 2024-07-26
 */

#ifndef PROTOCOL_UTILS_H
#define PROTOCOL_UTILS_H

#include <stdint.h>
#include <arpa/inet.h>
#include <endian.h>
#include <asm/byteorder.h>

#ifdef __BYTE_ORDER
#if ((__BYTE_ORDER != __BIG_ENDIAN) && (__BYTE_ORDER != __LITTLE_ENDIAN))
#error "__BYTE_ORDER must be defined as either __BIG_ENDIAN or __LITTLE_ENDIAN"
#endif
#else
#error "__BYTE_ORDER must be defined"
#endif

#if !defined(__BIG_ENDIAN_BITFIELD) && !defined(__LITTLE_ENDIAN_BITFIELD)
#error "__BIG_ENDIAN_BITFIELD or __LITTLE_ENDIAN_BITFIELD must be defined"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ONE_BYTE_LEN                8
#define TWO_BYTES_LEN               16
#define ONE_BYTE_MASK               0xff
#define THREE_BYTES_MASK            0xffffff
#define SIX_BYTES_MASK              0xffffffffffff

#define URPC_AES_IV_LEN             (12)
#define URPC_AES_TAG_LEN            (16)

/* These interfaces are used for protocol processing endian conversion */
static inline uint64_t proto_filed64_put(uint64_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return __builtin_bswap64(x);
#endif
}

static inline uint64_t proto_filed64_get(uint64_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return __builtin_bswap64(x);
#endif
}

static inline uint64_t proto_filed48_put(uint64_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x & SIX_BYTES_MASK;
#else
    return proto_filed64_put(x) >> TWO_BYTES_LEN;
#endif
}

static inline uint64_t proto_filed48_get(uint64_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x & SIX_BYTES_MASK;
#else
    return proto_filed64_get(x) >> TWO_BYTES_LEN;
#endif
}

static inline uint32_t proto_filed32_put(uint32_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return htonl(x);
#endif
}

static inline uint32_t proto_filed32_get(uint32_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return ntohl(x);
#endif
}

static inline uint32_t proto_filed24_put(uint32_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x & THREE_BYTES_MASK;
#else
    return htonl(x) >> ONE_BYTE_LEN;
#endif
}

static inline uint32_t proto_filed24_get(uint32_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x & THREE_BYTES_MASK;
#else
    return ntohl(x) >> ONE_BYTE_LEN;
#endif
}

static inline uint16_t proto_filed16_put(uint16_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return htons(x);
#endif
}

static inline uint16_t proto_filed16_get(uint16_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return x;
#else
    return ntohs(x);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_UTILS_H */