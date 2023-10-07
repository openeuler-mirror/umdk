/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: bitmap head file
 * Author: lichunhe
 * Create: 2021-8-27
 * Note:
 * History: 2021-8-27 Yan Fangfang import bitmap.
 */

#ifndef UB_BITMAP_H
#define UB_BITMAP_H 1

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "ub_util.h"
#ifdef __cplusplus
extern "C"
{
#endif

#define UB_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)

static inline size_t ub_bitmap_n_ulongs(size_t n_bits)
{
    return DIV_ROUND_UP(n_bits, UB_ULONG_BITS);
}

static inline size_t ub_bitmap_nbytes(size_t n_bits)
{
    return DIV_ROUND_UP(n_bits, UB_ULONG_BITS) * sizeof(unsigned long);
}

static inline unsigned long *ub_bitmap_offset(const unsigned long *bitmap, size_t offset)
{
    return (unsigned long *)(&bitmap[offset / UB_ULONG_BITS]);
}

static inline unsigned long ub_bitmap_offset_bit(size_t offset)
{
    return 1ULL << (offset % UB_ULONG_BITS);
}

static inline unsigned long *ub_bitmap_alloc(size_t n_bits)
{
    return (unsigned long *)calloc(1, ub_bitmap_nbytes(n_bits));
}

static inline unsigned long *ub_bitmap_alloc_1(size_t n_bits)
{
    size_t n_bytes = ub_bitmap_nbytes(n_bits);
    unsigned long *bitmap = ub_bitmap_alloc(n_bits);

    if (bitmap == NULL) {
        return NULL;
    }
    memset(bitmap, 0xff, n_bytes);
    if ((n_bits % UB_ULONG_BITS) != 0) {
        bitmap[ub_bitmap_n_ulongs(n_bits) - 1] >>= (UB_ULONG_BITS - n_bits % UB_ULONG_BITS);
    }
    return bitmap;
}

static inline unsigned long *ub_bitmap_clone(const unsigned long *bitmap, size_t n_bits)
{
    size_t n_bytes = ub_bitmap_nbytes(n_bits);
    unsigned long *clone = (unsigned long *)calloc(1, n_bytes);
    if (clone == NULL) {
        return NULL;
    }
    (void)memcpy(clone, bitmap, n_bytes);
    return clone;
}

static inline void ub_bitmap_free(unsigned long *bitmap)
{
    free(bitmap);
}

static inline bool ub_bitmap_is_set(const unsigned long *bitmap, size_t offset)
{
    return (*ub_bitmap_offset(bitmap, offset) & ub_bitmap_offset_bit(offset)) != 0;
}

static inline void ub_bitmap_set1(unsigned long *bitmap, size_t offset)
{
    *ub_bitmap_offset(bitmap, offset) |= ub_bitmap_offset_bit(offset);
}

static inline void ub_bitmap_set0(unsigned long *bitmap, size_t offset)
{
    *ub_bitmap_offset(bitmap, offset) &= ~ub_bitmap_offset_bit(offset);
}

static inline void ub_bitmap_set(unsigned long *bitmap, size_t offset, bool value)
{
    (value) ? ub_bitmap_set1(bitmap, offset) : ub_bitmap_set0(bitmap, offset);
}

static inline unsigned long *ub_bitmap_and(unsigned long *dst, const unsigned long *src, size_t n)
{
    size_t i = 0;
    while (i < ub_bitmap_n_ulongs(n)) {
        dst[i] &= src[i];
        i++;
    }
    return dst;
}

static inline unsigned long *ub_bitmap_or(unsigned long *dst, const unsigned long *src, size_t n)
{
    size_t i = 0;
    while (i < ub_bitmap_n_ulongs(n)) {
        dst[i] |= src[i];
        i++;
    }
    return dst;
}

bool ub_bitmap_equal(const unsigned long *a, const unsigned long *b, size_t n);

size_t ub_bitmap_scan(const unsigned long *bitmap, bool target, size_t begin, size_t end);

#define UB_BITMAP_FOR_EACH_1(IDX, SIZE, BITMAP) \
    for ((IDX) = ub_bitmap_scan(BITMAP, true, 0, SIZE); (IDX) < (SIZE); \
         (IDX) = ub_bitmap_scan(BITMAP, true, (IDX) + 1, SIZE))

#ifdef __cplusplus
}
#endif

#endif /* ub_bitmap.h */
