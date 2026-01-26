/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: reference count for queue resource
 */

#include "queue_resource_ref.h"
#include "urpc_lib_log.h"

static inline bool ref_test_and_dec(atomic_uint *ref_cnt)
{
    uint32_t value = atomic_load(ref_cnt);
    do {
        if (value == 0) {
            return false;
        }
    } while (!atomic_compare_exchange_strong(ref_cnt, &value, value - 1));

    return ((value - 1) == 0);
}

void q_res_ref_init(q_res_ref_t *ref)
{
    atomic_init(&ref->ref_cnt, 1);
}

int q_res_ref_get(q_res_ref_t *ref)
{
    if (atomic_load(&ref->ref_cnt) == 0) {
        URPC_LIB_LOG_ERR("queue resource is released\n");
        return -1;
    }
    atomic_fetch_add(&ref->ref_cnt, 1);

    return 0;
}

int q_res_ref_put(q_res_ref_t *ref, void (*release)(q_res_ref_t *ref, void *args), void *args)
{
    if (ref_test_and_dec(&ref->ref_cnt)) {
        release(ref, args);
        return 1;
    }

    return 0;
}
