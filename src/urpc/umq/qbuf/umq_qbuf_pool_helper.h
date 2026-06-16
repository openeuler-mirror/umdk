/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: define qbuf pool helper function
 * Create: 2026-6-26
 * Note:
 * History: 2026-6-26
 */

#ifndef UMQ_QBUF_POOL_HELPER_H
#define UMQ_QBUF_POOL_HELPER_H

#include "umq_huge_qbuf_pool.h"
#include "umq_qbuf_pool.h"
#include "umq_tiny_qbuf_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_qbuf_pool_plan {
    uint32_t tiny_block_size;
    uint64_t tiny_io_buf_size;
    uint64_t normal_io_buf_size;
    uint64_t normal_pool_budget_size;
} umq_qbuf_pool_plan_t;

typedef enum umq_pool_type {
    UMQ_POOL_TYPE_NORMAL,
    UMQ_POOL_TYPE_TINY,
    UMQ_POOL_TYPE_HUGE,
    UMQ_POOL_TYPE_ESCAPE,
} umq_pool_type_t;

static inline umq_pool_type_t umq_pool_type_get(uint32_t mempool_id)
{
    if (mempool_id == UMQ_TINY_QBUF_MEMPOOL_ID) {
        return UMQ_POOL_TYPE_TINY;
    }
    if (mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
        return UMQ_POOL_TYPE_ESCAPE;
    }
    if (is_huge_mempool_pool(mempool_id)) {
        return UMQ_POOL_TYPE_HUGE;
    }
    return UMQ_POOL_TYPE_NORMAL;
}

static inline void umq_invalid_handle_buf_free(umq_buf_list_t *head, umq_pool_type_t type)
{
    if (type == UMQ_POOL_TYPE_TINY) {
        umq_tiny_qbuf_free(head);
    } else if (type == UMQ_POOL_TYPE_HUGE) {
        umq_huge_qbuf_free(head);
    } else {
        umq_qbuf_free(head);
    }
}

int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);
int umq_qbuf_pool_cfg_check(const umq_init_cfg_t *cfg, umq_qbuf_pool_plan_t *plan);

#ifdef __cplusplus
}
#endif

#endif
