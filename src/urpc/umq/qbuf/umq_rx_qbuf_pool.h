/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef UMQ_RX_QBUF_POOL_H
#define UMQ_RX_QBUF_POOL_H

#include "umq_qbuf_pool_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_RX_QBUF_BLOCK_SIZE (4096U)
#define UMQ_RX_QBUF_POOL_MAX_SIZE (256ULL * 1024ULL * 1024ULL)

/*
 * Independent RX qbuf pool: 4KB-only, single size class.
 * Decoupled from normal 4KB pool to avoid contention with general 4KB consumers (e.g. urpc).
 * No TLS cache, no HWM cap, no expand/shrink.
 * Routing: alloc via UMQ_ALLOC_FLAG_POOL_TYPE + pool_type=UMQ_ALLOC_POOL_RX;
 *          free via qbuf->mempool_id == UMQ_RX_QBUF_MEMPOOL_ID.
 */
int umq_rx_qbuf_pool_init(qbuf_pool_cfg_t *cfg);
void umq_rx_qbuf_pool_uninit(void);

int umq_rx_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);
void umq_rx_qbuf_free(umq_buf_list_t *list);
umq_buf_t *umq_rx_qbuf_data_to_head(void *data);

void *umq_rx_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size);
void umq_rx_io_buf_free(void);
void *umq_rx_io_buf_addr(void);
uint64_t umq_rx_io_buf_size(void);

int umq_rx_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops);
void umq_rx_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops);

void umq_rx_qbuf_pool_depth_get(uint64_t *total_size, uint32_t *block_size, uint32_t *depth,
                                uint64_t *free_depth);
void umq_rx_qbuf_pool_alloc_free_count_get(uint64_t *alloc_count, uint64_t *free_count);

#ifdef __cplusplus
}
#endif

#endif
