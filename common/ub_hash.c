/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: UB hash implementation file
 * Author: Lilijun
 * Create: 2020-10-14
 * Note:
 */

#include "ub_hash.h"

/* Returns the hash of memory bytes'. */
uint32_t ub_hash_bytes(const void *ptr, uint32_t n_bytes, uint32_t basis)
{
    const uint32_t *hash_ptr = ptr;
    uint32_t tmp_bytes = n_bytes;
    uint32_t hash_value;

    hash_value = basis;
    while (tmp_bytes >= sizeof(uint32_t)) {
        hash_value = ub_hash_add(hash_value, get_unaligned_u32(hash_ptr));
        tmp_bytes -= sizeof(uint32_t);
        hash_ptr += 1;
    }

    if (tmp_bytes != 0) {
        uint32_t left = 0;
        (void)memcpy(&left, hash_ptr, tmp_bytes);
        hash_value = ub_hash_add(hash_value, left);
    }

    return ub_hash_finish(hash_value, n_bytes);
}
