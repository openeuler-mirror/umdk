/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond Bitmap implementation
 * Author: Ma Chuan
 * Create: 2025-02-18
 * Note:
 * History: 2025-02-18   Create File
 */
#include <stdlib.h>
#include <limits.h>
#include "ub_bitmap.h"
#include "ub_util.h"
#include "urma_log.h"
#include "bondp_bitmap.h"

bondp_bitmap_t *bondp_bitmap_alloc(uint32_t bitmap_size)
{
    bondp_bitmap_t *bitmap = calloc(1, sizeof(bondp_bitmap_t));
    if (bitmap == NULL) {
        return NULL;
    }
    bitmap->size = bitmap_size;
    bitmap->bits = ub_bitmap_alloc(bitmap_size);
    if (bitmap->bits == NULL) {
        free(bitmap);
        return NULL;
    }
    return bitmap;
}

void bondp_bitmap_free(bondp_bitmap_t *bitmap)
{
    if (bitmap->bits != NULL) {
        ub_bitmap_free(bitmap->bits);
    }
    free(bitmap);
}

int bondp_bitmap_init(bondp_bitmap_t *bitmap, uint32_t size)
{
    bitmap->size = size;
    bitmap->bits = ub_bitmap_alloc(size);
    if (bitmap->bits == NULL) {
        return -1;
    }
    return 0;
}

void bondp_bitmap_uninit(bondp_bitmap_t *bitmap)
{
    if (bitmap->bits != NULL) {
        ub_bitmap_free(bitmap->bits);
    }
}

static unsigned long bondp_find_first_zero_bit(const unsigned long *array, unsigned long size)
{
    unsigned long i;
    unsigned long ret = 0;
    unsigned long array_size;

    if (UB_UNLIKELY(size == 0)) {
        return size;
    }

    array_size = ub_bitmap_n_ulongs(size);
    for (i = 0; i < array_size; i++) {
        if (array[i] == ULONG_MAX) {
            ret += UB_ULONG_BITS;
        } else {
            return (ret + ffz(array[i]));
        }
    }

    return size;
}

int bondp_bitmap_alloc_idx(bondp_bitmap_t *bitmap, uint32_t *idx_out)
{
    uint32_t idx;
    idx = (uint32_t)bondp_find_first_zero_bit(bitmap->bits, bitmap->size);
    if (idx >= bitmap->size) {
        return -1;
    }
    ub_bitmap_set1(bitmap->bits, idx);
    *idx_out = idx;
    return 0;
}

int bondp_bitmap_alloc_idx_from_offset(bondp_bitmap_t *bitmap, uint32_t offset, uint32_t *idx_out)
{
    uint32_t idx = 0;
    uint32_t offset_n_ulongs = 0;

    if (offset >= bitmap->size) {
        URMA_LOG_ERR("offset(%u) exceeds the bitmap size(%u).\n", offset, bitmap->size);
        return -1;
    }

    offset_n_ulongs = ub_bitmap_n_ulongs(offset);
    idx = (uint32_t)bondp_find_first_zero_bit(bitmap->bits + offset_n_ulongs, bitmap->size - offset);
    if (idx >= bitmap->size - offset_n_ulongs) {
        URMA_LOG_ERR("bitmap allocation failed.\n");
        return -1;
    }
    ub_bitmap_set1(bitmap->bits + offset_n_ulongs, idx);
    *idx_out = idx + offset_n_ulongs * sizeof(unsigned long) * CHAR_BIT;
    return 0;
}

int bondp_bitmap_use_id(bondp_bitmap_t *bitmap, uint32_t id)
{
    if (ub_bitmap_is_set(bitmap->bits, id)) {
        URMA_LOG_ERR("Bit %u is already taken.\n", id);
        return -1;
    }
    ub_bitmap_set1(bitmap->bits, id);
    return 0;
}

int bondp_bitmap_free_idx(bondp_bitmap_t *bitmap, uint32_t idx)
{
    if (!ub_bitmap_is_set(bitmap->bits, idx)) {
        return -EINVAL;
    }
    ub_bitmap_set0(bitmap->bits, idx);
    return 0;
}

bool bondp_bitmap_is_set(bondp_bitmap_t *bitmap, uint32_t id)
{
    return ub_bitmap_is_set(bitmap->bits, id);
}