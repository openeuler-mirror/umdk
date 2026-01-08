/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Internal header file of UMQ function
 * Create: 2025-7-17
 * Note:
 * History: 2025-7-17
 */

#ifndef UMQ_INNER_API_H
#define UMQ_INNER_API_H

#include <time.h>
#include <stdatomic.h>

#include "urpc_util.h"
#include "umq_api.h"
#include "umq_pro_api.h"
#include "umq_tp_api.h"
#include "umq_pro_tp_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_POST_POLL_BATCH             64
#define UMQ_EID_MAP_PREFIX              (0x0000ffff)
#define UMQ_DEFAULT_BUF_SIZE            4096
#define UMQ_DEFAULT_DEPTH               1024
#define UMQ_MAX_QUEUE_NUMBER            8192
#define UMQ_SIZE_4M                     (0x400000)
#define SHM_MODE (0660)

typedef struct umq {
    umq_trans_mode_t mode;
    umq_ops_t *tp_ops;
    umq_pro_ops_t *pro_tp_ops;
    uint64_t umqh_tp;
} umq_t;

static inline uint32_t umq_get_post_rx_num(uint32_t rx_depth, atomic_uint *require_rx_count)
{
    if (rx_depth <= UMQ_POST_POLL_BATCH) {
        return atomic_exchange_explicit(require_rx_count, 0, memory_order_relaxed);
    }

    unsigned int rx_num = (uint32_t)atomic_load_explicit(require_rx_count, memory_order_relaxed);
    do {
        if (rx_num < UMQ_POST_POLL_BATCH) {
            return 0;
        }
    } while (!atomic_compare_exchange_weak_explicit(require_rx_count, &rx_num, 0,
             memory_order_relaxed, memory_order_relaxed));
    return rx_num;
}

static inline void umq_inc_ref(bool lock_free, volatile uint32_t *ref_cnt, uint32_t n)
{
    if (lock_free) {
        *ref_cnt = *ref_cnt + n;
    } else {
        (void)__sync_fetch_and_add(ref_cnt, n);
    }
}

static inline void umq_dec_ref(bool lock_free, volatile uint32_t *ref_cnt, uint32_t n)
{
    if (lock_free) {
        *ref_cnt = *ref_cnt - n;
    } else {
        (void)__sync_fetch_and_sub(ref_cnt, n);
    }
}

static inline uint32_t umq_fetch_ref(bool lock_free, volatile uint32_t *ref_cnt)
{
    if (lock_free) {
        return *ref_cnt;
    } else {
        return __sync_val_compare_and_swap(ref_cnt, 0, 0);
    }
}

static ALWAYS_INLINE bool is_timeout(const struct timespec *last, uint32_t timeout)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t t1 = (uint64_t)(last->tv_sec * NS_PER_SEC + last->tv_nsec);
    uint64_t t2 = (uint64_t)(now.tv_sec * NS_PER_SEC + now.tv_nsec);
    uint64_t t3 = (uint64_t)timeout * NS_PER_MS;

    return t2 - t1 >= t3;
}

#ifdef __cplusplus
}
#endif

#endif
