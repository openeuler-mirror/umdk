/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define tiny qbuf pool function
 * Create: 2026-5-28
 */

#ifndef UMQ_TINY_QBUF_POOL_H
#define UMQ_TINY_QBUF_POOL_H

#include "umq_qbuf_pool_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TINY_QBUF_POOL_DEFAULT_BLOCK_COUNT    (8192U)
#define UMQ_TINY_QBUF_POOL_MAX_SIZE           (128ULL * 1024ULL * 1024ULL)
#define UMQ_TINY_QBUF_BLOCK_SIZE              (1024U)

uint32_t umq_tiny_buf_block_size_bytes(umq_tiny_buf_block_size_t size_enum);

void *umq_tiny_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size);
void umq_tiny_io_buf_free(void);
void *umq_tiny_io_buf_addr(void);
uint64_t umq_tiny_io_buf_size(void);
bool umq_tiny_qbuf_can_alloc(uint32_t request_size, uint32_t effective_size);

int umq_tiny_qbuf_pool_init(qbuf_pool_cfg_t *cfg);
void umq_tiny_qbuf_pool_uninit(void);

int umq_tiny_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);
void umq_tiny_qbuf_free(umq_buf_list_t *list);
int umq_tiny_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size);
umq_buf_t *umq_tiny_qbuf_data_to_head(void *data);

int umq_tiny_qbuf_pool_info_get(umq_qbuf_pool_stats_t *qbuf_pool_stats);
int umq_tiny_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops);
void umq_tiny_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops);

#ifdef __cplusplus
}
#endif

#endif
