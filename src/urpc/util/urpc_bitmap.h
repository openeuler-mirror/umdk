/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc bitmap
 */
#ifndef URPC_BITMAP_H
#define URPC_BITMAP_H

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "urpc_util.h"
#include "urpc_dbuf_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long* urpc_bitmap_t;

#define URPC_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)

static inline size_t urpc_bitmap_n_ulongs(size_t n_bits)
{
    return DIV_ROUND_UP(n_bits, URPC_ULONG_BITS);
}

static inline size_t urpc_bitmap_nbytes(size_t n_bits)
{
    return DIV_ROUND_UP(n_bits, URPC_ULONG_BITS) * sizeof(unsigned long);
}

static inline urpc_bitmap_t urpc_bitmap_offset(const urpc_bitmap_t bitmap, size_t offset)
{
    return (urpc_bitmap_t)(&bitmap[offset / URPC_ULONG_BITS]);
}

static inline unsigned long urpc_bitmap_offset_bit(size_t offset)
{
    return 1ULL << (offset % URPC_ULONG_BITS);
}

static inline urpc_bitmap_t urpc_bitmap_alloc(size_t n_bits)
{
    return (urpc_bitmap_t)urpc_dbuf_calloc(URPC_DBUF_TYPE_UTIL, 1, urpc_bitmap_nbytes(n_bits));
}

static inline urpc_bitmap_t urpc_bitmap_alloc_1(size_t n_bits)
{
    size_t n_bytes = urpc_bitmap_nbytes(n_bits);
    urpc_bitmap_t bitmap = urpc_bitmap_alloc(n_bits);
    if (bitmap == NULL) {
        return bitmap;
    }
    memset(bitmap, 0xff, n_bytes);
    if ((n_bits % URPC_ULONG_BITS) != 0) {
        bitmap[urpc_bitmap_n_ulongs(n_bits) - 1] >>= (unsigned long)(URPC_ULONG_BITS - n_bits % URPC_ULONG_BITS);
    }
    return bitmap;
}

static inline urpc_bitmap_t urpc_bitmap_clone(const urpc_bitmap_t bitmap, size_t n_bits)
{
    size_t n_bytes = urpc_bitmap_nbytes(n_bits);
    urpc_bitmap_t clone = (urpc_bitmap_t)urpc_dbuf_calloc(URPC_DBUF_TYPE_UTIL, 1, n_bytes);
    if (clone == NULL) {
        return clone;
    }
    memcpy(clone, bitmap, n_bytes);

    return clone;
}

static inline void urpc_bitmap_free(urpc_bitmap_t bitmap)
{
    urpc_dbuf_free((void *)bitmap);
}

static inline bool urpc_bitmap_is_set(const urpc_bitmap_t bitmap, size_t offset)
{
    return (*urpc_bitmap_offset(bitmap, offset) & urpc_bitmap_offset_bit(offset)) != 0;
}

static inline void urpc_bitmap_set1(urpc_bitmap_t bitmap, size_t offset)
{
    *urpc_bitmap_offset(bitmap, offset) |= urpc_bitmap_offset_bit(offset);
}

static inline void urpc_bitmap_set0(urpc_bitmap_t bitmap, size_t offset)
{
    *urpc_bitmap_offset(bitmap, offset) &= ~urpc_bitmap_offset_bit(offset);
}

static inline void urpc_bitmap_set(urpc_bitmap_t bitmap, size_t offset, bool value)
{
    (value) ? urpc_bitmap_set1(bitmap, offset) : urpc_bitmap_set0(bitmap, offset);
}

static inline urpc_bitmap_t urpc_bitmap_and(urpc_bitmap_t dst, const urpc_bitmap_t src, size_t n)
{
    size_t i = 0;
    while (i < urpc_bitmap_n_ulongs(n)) {
        dst[i] &= src[i];
        i++;
    }
    return dst;
}

static inline urpc_bitmap_t urpc_bitmap_or(urpc_bitmap_t dst, const urpc_bitmap_t src, size_t n)
{
    size_t i = 0;
    while (i < urpc_bitmap_n_ulongs(n)) {
        dst[i] |= src[i];
        i++;
    }
    return dst;
}

bool urpc_bitmap_equal(const urpc_bitmap_t a, const urpc_bitmap_t b, size_t n);

unsigned long urpc_bitmap_find_next_bit(const urpc_bitmap_t b, unsigned long size, unsigned long offset);
unsigned long urpc_bitmap_find_next_zero_bit(const urpc_bitmap_t b, unsigned long size, unsigned long offset);

size_t urpc_bitmap_scan(const urpc_bitmap_t bitmap, bool target, size_t begin, size_t end);

#define URPC_BITMAP_FOR_EACH_1(IDX, SIZE, BITMAP) \
    for ((IDX) = urpc_bitmap_scan(BITMAP, true, 0, SIZE); (IDX) < (SIZE); \
         (IDX) = urpc_bitmap_scan(BITMAP, true, (IDX) + 1, SIZE))

#ifdef __cplusplus
}
#endif

#endif