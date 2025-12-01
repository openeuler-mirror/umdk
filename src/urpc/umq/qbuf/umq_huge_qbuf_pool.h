/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define qbuf pool function for huge buffer
 * Create: 2025-10-29
 * Note:
 * History: 2025-10-29
 */

#ifndef UMQ_HUGE_QBUF_POOL_H
#define UMQ_HUGE_QBUF_POOL_H

#include <pthread.h>

#include "urpc_util.h"
#include "qbuf_list.h"
#include "umq_types.h"
#include "umq_qbuf_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

enum HUGE_QBUF_POOL_SIZE_TYPE {
    HUGE_QBUF_POOL_SIZE_TYPE_MID, // Corresponding to 256KB size
    HUGE_QBUF_POOL_SIZE_TYPE_BIG, // Corresponding to 8MB size
    HUGE_QBUF_POOL_SIZE_TYPE_MAX,
};

typedef struct huge_qbuf_pool_cfg {
    uint64_t total_size;        // total buffer size
    uint32_t data_size;         // size of one data slab
    uint32_t headroom_size;     // reserve head room size
    umq_buf_mode_t mode;
    enum HUGE_QBUF_POOL_SIZE_TYPE type;
    int (*memory_init_callback)(uint8_t mempool_id, enum HUGE_QBUF_POOL_SIZE_TYPE type, void **buf_addr);
    void (*memory_uninit_callback)(uint8_t mempool_id, void *buf_addr);
} huge_qbuf_pool_cfg_t;

int umq_huge_qbuf_config_init(huge_qbuf_pool_cfg_t *cfg);

void umq_huge_qbuf_pool_uninit(void);

int umq_huge_qbuf_alloc(enum HUGE_QBUF_POOL_SIZE_TYPE type, uint32_t request_size, uint32_t num,
    umq_alloc_option_t *option, umq_buf_list_t *list);

void umq_huge_qbuf_free(umq_buf_list_t *list);

int umq_huge_qbuf_register_seg(uint8_t *ctx,
    register_seg_callback_t register_seg_func, unregister_seg_callback_t unregister_seg_func);
void umq_huge_qbuf_unregister_seg(uint8_t *ctx, unregister_seg_callback_t unregister_seg_func);

#ifdef __cplusplus
}
#endif

#endif