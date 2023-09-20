/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: ub bitmap source file
 * Author: lichunhe
 * Create: 2021-08-27
 * Note:
 * History: 2021-8-27 Yan Fangfang import bitmap.
 */

#include "ub_bitmap.h"

bool ub_bitmap_equal(const unsigned long *a, const unsigned long *b, size_t n)
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

size_t ub_bitmap_scan(const unsigned long *bitmap, bool target, size_t begin, size_t end)
{
    if (begin >= end) {
        return end;
    }

    unsigned long *offset = ub_bitmap_offset(bitmap, begin);
    unsigned long bits = (target ? *offset : ~*offset) >> (begin % UB_ULONG_BITS);
    size_t i = begin;
    if (bits == 0) {
        i -= i % UB_ULONG_BITS;
        i += UB_ULONG_BITS;

        for (; i < end; i += UB_ULONG_BITS) {
            bits = target ? *++offset : ~*++offset;
            if (bits != 0) {
                break;
            }
        }
        if (bits == 0) {
            return end;
        }
    }

    i += (size_t)ub_count_trail_zero(bits); /* bit != 0 */
    if (i < end) {
        return i;
    }
    return end;
}