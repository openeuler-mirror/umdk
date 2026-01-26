/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc bitmap
 */
#include "urpc_bitmap.h"

bool urpc_bitmap_equal(const urpc_bitmap_t a, const urpc_bitmap_t b, size_t n)
{
    size_t offset_bytes = n / CHAR_BIT;
    unsigned char last_bits = (unsigned char)(n % CHAR_BIT);

    if (memcmp(a, b, offset_bytes) != 0) {
        return false;
    }

    if (last_bits != 0) {
        unsigned char _xor = (unsigned char)(((unsigned char *)a)[offset_bytes] ^ ((unsigned char *)b)[offset_bytes]);
        unsigned char mask = (unsigned char)(((unsigned char)1 << last_bits) - (unsigned char)1);
        return ((_xor & mask) == 0);
    }

    return true;
}

size_t urpc_bitmap_scan(const urpc_bitmap_t bitmap, bool target, size_t begin, size_t end)
{
    if (begin >= end) {
        return end;
    }

    urpc_bitmap_t offset = urpc_bitmap_offset(bitmap, begin);
    unsigned long bits = (target ? *offset : ~*offset) >> (begin % URPC_ULONG_BITS);
    size_t i = begin;
    if (bits == 0) {
        i -= i % URPC_ULONG_BITS;
        i += URPC_ULONG_BITS;

        for (; i < end; i += URPC_ULONG_BITS) {
            bits = target ? *++offset : ~*++offset;
            if (bits != 0) {
                break;
            }
        }
        if (bits == 0) {
            return end;
        }
    }

    i += (size_t)urpc_count_trail_zero(bits); /* bit != 0 */
    if (i < end) {
        return i;
    }
    return end;
}

static unsigned long find_next_bit(const urpc_bitmap_t array, unsigned long size, unsigned long offset,
    unsigned long invert)
{
    unsigned long i;
    unsigned long ret;
    unsigned long long_offset;
    unsigned long tmp;
    unsigned long array_size;

    if (URPC_UNLIKELY(offset >= size || size == 0)) {
        return size;
    }

    /* Calc the array index for offset. For example: offset=65, index=1. */
    i = offset >> BITS_PER_LONG_SHIFT;
    ret = i * BITS_PER_LONG;

    /* Calc the offset in unsigned long for "offset" bit. */
    long_offset = offset % BITS_PER_LONG;
    /* Set bits before "offset" to "0". */
    tmp = (array[i] ^ invert) & (~0UL << long_offset) ;
    if (tmp != 0) {
        return (ret + urpc_ffs(tmp));
    }
    /* Next unsigned long. */
    ret += BITS_PER_LONG;
    i++;

    array_size = BITS_TO_LONGS(size);
    for (; i < array_size; i++) {
        tmp = array[i] ^ invert;
        if (tmp != 0) {
            return (ret + urpc_ffs(tmp));
        }
        ret += BITS_PER_LONG;
    }

    return size;
}

unsigned long urpc_bitmap_find_next_bit(const urpc_bitmap_t b, unsigned long size, unsigned long offset)
{
    return find_next_bit(b, size, offset, 0UL);
}

unsigned long urpc_bitmap_find_next_zero_bit(const urpc_bitmap_t b, unsigned long size, unsigned long offset)
{
    return find_next_bit(b, size, offset, ~0UL);
}