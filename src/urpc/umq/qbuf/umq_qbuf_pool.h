/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define qbuf pool function
 * Create: 2025-7-26
 * Note:
 * History: 2025-7-26
 */

#ifndef UMQ_QBUF_POOL_H
#define UMQ_QBUF_POOL_H

#include "umq_qbuf_pool_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_BUF_DEFAULT_TOTAL_SIZE (1024L * 1024 * 1024) // 1024M size

int umq_buf_size_pow_small_set(umq_buf_block_size_t block_size);

uint8_t umq_buf_size_pow_small(void);

// small qbuf block size: 4K, 8K... 64K size
static inline uint32_t umq_buf_size_small(void)
{
    return (1 << umq_buf_size_pow_small());
}

void *umq_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size);
void umq_io_buf_free(void);
void *umq_io_buf_addr(void);
uint64_t umq_io_buf_size(void);
int umq_qbuf_pool_info_get(umq_qbuf_pool_stats_t *qbuf_pool_stats);

/*
 * init qbuf pool
 */
int umq_qbuf_pool_init(qbuf_pool_cfg_t *cfg);

/*
 * uninit qbuf pool
 */
void umq_qbuf_pool_uninit(void);

/*
 * alloc memory from qbuf pool.
 * try to alloc from thread local pool.
 * if not enough, fetch some more memory fragments from global pool to thread local pool first.
 */
int umq_normal_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);

int umq_qbuf_escape_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);

/*
 * release memory to qbuf pool.
 * if memory fragments count in thread local pool reach threshold after release,
 * return some of fragments to global pool.
 */
void umq_qbuf_free(umq_buf_list_t *list);

/*
 * reset head room size of qbuf
 * if headroom_size is not appropriate, UMQ_FAIL will be returned
 */
int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size);

/*
 * find umq_buf_t corresponding to data
 * if data is not in qbuf_pool, NULL will be returned
 */
umq_buf_t *umq_qbuf_data_to_head(void *data);

umq_buf_t *umq_qbuf_expansion_data_to_head(void *data);

void umq_qbuf_config_get(qbuf_pool_cfg_t *cfg);

uint32_t umq_qbuf_headroom_get(void);
umq_buf_mode_t umq_qbuf_mode_get(void);

int umq_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops);
void umq_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops);

#ifdef __cplusplus
}
#endif

#endif
