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

#include <malloc.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_vlog.h"
#include "umq_rx_qbuf_pool.h"

static global_block_pool_t g_rx_pool = {0};
static void *g_rx_buffer_addr = NULL;
static uint64_t g_rx_total_len = 0;
static bool g_rx_pool_inited = false;
// rx pool cumulative alloc/free counters (atomic, for DFX leak analysis)
static volatile uint64_t g_rx_alloc_count = 0;
static volatile uint64_t g_rx_free_count = 0;

void *umq_rx_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size)
{
    if (g_rx_buffer_addr != NULL) {
        return g_rx_buffer_addr;
    }

    uint64_t min_size = UMQ_RX_QBUF_BLOCK_SIZE;
    if (buf_mode == UMQ_BUF_SPLIT) {
        min_size = UMQ_RX_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t);
    }
    g_rx_total_len = (size == 0) ? UMQ_RX_QBUF_POOL_MAX_SIZE : size;
    if (g_rx_total_len > UMQ_RX_QBUF_POOL_MAX_SIZE) {
        g_rx_total_len = UMQ_RX_QBUF_POOL_MAX_SIZE;
    }

    g_rx_buffer_addr = umq_qbuf_base_io_buf_malloc(g_rx_total_len, min_size);
    if (g_rx_buffer_addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx qbuf memory alloc failed, size %lu, expect at least %lu\n", g_rx_total_len,
                     min_size);
        g_rx_total_len = 0;
        return NULL;
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "malloc rx qbuf io buf %lu bytes\n", g_rx_total_len);
    return g_rx_buffer_addr;
}

void umq_rx_io_buf_free(void)
{
    if (g_rx_buffer_addr != NULL) {
        free(g_rx_buffer_addr);
        g_rx_buffer_addr = NULL;
    }
    g_rx_total_len = 0;
}

void *umq_rx_io_buf_addr(void)
{
    return g_rx_buffer_addr;
}

uint64_t umq_rx_io_buf_size(void)
{
    return g_rx_total_len;
}

int umq_rx_qbuf_pool_init(qbuf_pool_cfg_t *cfg)
{
    if (g_rx_pool_inited) {
        UMQ_VLOG_WARN(VLOG_UMQ, "rx qbuf pool has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }
    if (cfg == NULL || cfg->buf_addr == NULL || cfg->total_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx qbuf pool cfg invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    uint32_t block_size = UMQ_RX_QBUF_BLOCK_SIZE;
    uint64_t header_per_blk = (uint64_t)sizeof(umq_buf_t);
    uint64_t blk_num = cfg->total_size / (block_size + header_per_blk);
    if (blk_num == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx qbuf pool total_size %lu too small, need at least %lu\n", cfg->total_size,
                     block_size + header_per_blk);
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq_qbuf_block_pool_init(&g_rx_pool);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx qbuf block pool init failed, status: %d\n", ret);
        return ret;
    }

    char *data_buffer = (char *)cfg->buf_addr;
    char *header_buffer = data_buffer + blk_num * block_size;
    buf_init_with_mode(data_buffer, header_buffer, blk_num, block_size, UMQ_RX_QBUF_MEMPOOL_ID, true, UMQ_BUF_SPLIT,
                       &g_rx_pool.head_with_data);
    g_rx_pool.buf_cnt_with_data = blk_num;
    g_rx_pool.buf_cnt_without_data = 0;

    g_rx_pool_inited = true;
    UMQ_VLOG_INFO(VLOG_UMQ, "rx qbuf pool inited, block_count %lu, block_size %u\n", blk_num, block_size);
    return UMQ_SUCCESS;
}

void umq_rx_qbuf_pool_uninit(void)
{
    if (!g_rx_pool_inited) {
        return;
    }
    umq_qbuf_block_pool_uninit(&g_rx_pool);
    QBUF_LIST_INIT(&g_rx_pool.head_with_data);
    QBUF_LIST_INIT(&g_rx_pool.head_without_data);
    g_rx_pool.buf_cnt_with_data = 0;
    g_rx_pool.buf_cnt_without_data = 0;
    g_rx_pool_inited = false;
}

int umq_rx_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_rx_pool_inited || num == 0) {
        return -UMQ_ERR_ENOMEM;
    }

    uint32_t headroom_size =
        (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ? option->headroom_size : 0;
    /* RX pool only has 4KB blocks. request_size must fit within one block
     * after headroom, otherwise the direct path silently returns a buf
     * smaller than requested. */
    if (request_size > UMQ_RX_QBUF_BLOCK_SIZE - headroom_size) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "rx qbuf alloc request_size %u exceeds max %u (block %u - headroom %u)\n",
                           request_size, UMQ_RX_QBUF_BLOCK_SIZE - headroom_size, UMQ_RX_QBUF_BLOCK_SIZE, headroom_size);
        return -UMQ_ERR_EINVAL;
    }

    (void)pthread_spin_lock(&g_rx_pool.global_mutex);
    if (g_rx_pool.buf_cnt_with_data < num) {
        (void)pthread_spin_unlock(&g_rx_pool.global_mutex);
        /* RX pool exhausted: fallback to normal pool SC[0] (4KB).
         * Safe because: (1) normal pool also registered as UB tseg via
         * umq_ub_register_memory_impl() (umq_ub_api.c:36); (2) mempool_id
         * on the allocated buf is UMQ_QBUF_DEFAULT_MEMPOOL_ID, so free()
         * auto-routes to umq_qbuf_free (no free path change needed).
         * pool_type=NORMAL explicit to avoid escape fallback (escape buf
         * has no tseg registration, peer cannot zero-copy access).
         * Force request_size = block_size - headroom so that normal pool
         * returns the same data_size as the direct path:
         *   need = (4096 - headroom) + headroom = 4096 → always SC[0]
         *   data_size = min(4096 - headroom, 4096 - headroom) = 4096 - headroom
         * No SC drift, no multi-block split, consistent with direct path. */
        umq_alloc_option_t fallback_opt = {0};
        fallback_opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE | UMQ_ALLOC_FLAG_POOL_TYPE;
        fallback_opt.headroom_size = headroom_size;
        fallback_opt.pool_type = UMQ_ALLOC_POOL_NORMAL;
        uint32_t forced_req = UMQ_RX_QBUF_BLOCK_SIZE - headroom_size;
        UMQ_LIMIT_VLOG_DEBUG(VLOG_UMQ, "RX pool fallback to normal: req=%u forced_req=%u num=%u avail=%lu\n",
                             request_size, forced_req, num, (unsigned long)g_rx_pool.buf_cnt_with_data);
        return umq_normal_qbuf_alloc(forced_req, num, &fallback_opt, list);
    }
    uint32_t cnt = allocate_batch(&g_rx_pool.head_with_data, num, list);
    g_rx_pool.buf_cnt_with_data -= cnt;
    (void)pthread_spin_unlock(&g_rx_pool.global_mutex);

    uint32_t max_data_capacity = UMQ_RX_QBUF_BLOCK_SIZE - headroom_size;
    umq_buf_t *cur_node;
    QBUF_LIST_FOR_EACH(cur_node, list)
    {
        cur_node->buf_data = (char *)floor_to_align(cur_node->buf_data, UMQ_RX_QBUF_BLOCK_SIZE) + headroom_size;
        cur_node->buf_size = UMQ_RX_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t);
        cur_node->headroom_size = (uint16_t)headroom_size;
        cur_node->total_data_size = max_data_capacity;
        cur_node->data_size = max_data_capacity;
        cur_node->first_fragment = 1;
        cur_node->alloc_state = QBUF_ALLOC_STATE_ALLOCATED;
    }

    __atomic_add_fetch(&g_rx_alloc_count, cnt, __ATOMIC_RELAXED);
    return UMQ_SUCCESS;
}

umq_buf_t *umq_rx_qbuf_data_to_head(void *data)
{
    if (!g_rx_pool_inited || data == NULL) {
        return NULL;
    }
    /* RX pool layout (SPLIT mode): data_buffer followed by header_buffer.
     * data_buffer holds raw 4K-aligned data blocks; header_buffer holds
     * umq_buf_t metadata. Given a data pointer, compute the block index
     * and look up the corresponding header.
     * The caller may pass either the raw block start or a pointer offset
     * by headroom_size (sizeof IOBuf::Block = 32), so we floor-align
     * to block_size to find the true block start. */
    char *data_buf_start = (char *)g_rx_buffer_addr;
    uint32_t block_size = UMQ_RX_QBUF_BLOCK_SIZE;
    uint64_t blk_num = g_rx_total_len / (block_size + sizeof(umq_buf_t));
    char *data_buf_end = data_buf_start + blk_num * block_size;
    char *hdr_buf_start = data_buf_end;

    char *blk_start = (char *)((uintptr_t)data & ~(uint64_t)(block_size - 1));
    if (blk_start < data_buf_start || blk_start >= data_buf_end) {
        return NULL;
    }
    uint64_t id = (uint64_t)(blk_start - data_buf_start) / block_size;
    umq_buf_t *qbuf = (umq_buf_t *)(hdr_buf_start + id * sizeof(umq_buf_t));
    /* Validate: qbuf->buf_data should be within [blk_start, blk_start+block_size). */
    if (qbuf->buf_data >= blk_start && qbuf->buf_data < blk_start + block_size) {
        return qbuf;
    }
    return NULL;
}

void umq_rx_qbuf_free(umq_buf_list_t *list)
{
    if (list == NULL || QBUF_LIST_FIRST(list) == NULL || !g_rx_pool_inited) {
        return;
    }

    (void)pthread_spin_lock(&g_rx_pool.global_mutex);
    uint32_t cnt = release_batch(list, &g_rx_pool.head_with_data, false);
    g_rx_pool.buf_cnt_with_data += cnt;
    __atomic_add_fetch(&g_rx_free_count, cnt, __ATOMIC_RELAXED);
    (void)pthread_spin_unlock(&g_rx_pool.global_mutex);
}

int umq_rx_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    if (!g_rx_pool_inited || ops == NULL || ops->register_seg_callback == NULL) {
        return -UMQ_ERR_EINVAL;
    }

    int ret = ops->register_seg_callback(ctx, UMQ_RX_QBUF_MEMPOOL_ID,
                                         g_rx_buffer_addr, g_rx_total_len);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx qbuf register seg failed, status: %d\n", ret);
    }
    return ret;
}

void umq_rx_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    if (!g_rx_pool_inited || ops == NULL || ops->unregister_seg_callback == NULL) {
        return;
    }
    ops->unregister_seg_callback(ctx, UMQ_RX_QBUF_MEMPOOL_ID);
}

void umq_rx_qbuf_pool_depth_get(uint64_t *total_size, uint32_t *block_size, uint32_t *depth,
                                uint64_t *free_depth)
{
    /* Read global state directly (like Normal/Tiny DFX), without checking
     * g_rx_pool_inited: after uninit, g_rx_total_len and block_size remain
     * valid (not cleared), so total_size/depth reflect the configured pool;
     * g_rx_pool.buf_cnt_with_data is cleared to 0 by uninit, so free_depth=0
     * correctly indicates no free buffers. This is consistent with Normal/Tiny
     * which also read their globals directly after uninit. */
    uint32_t blk_size = UMQ_RX_QBUF_BLOCK_SIZE;
    uint32_t header_size = (uint32_t)sizeof(umq_buf_t);
    uint32_t blk_num = (uint32_t)(g_rx_total_len / (blk_size + header_size));
    if (total_size != NULL) {
        *total_size = g_rx_total_len;
    }
    if (block_size != NULL) {
        *block_size = blk_size;
    }
    if (depth != NULL) {
        *depth = blk_num;
    }
    if (free_depth != NULL) {
        *free_depth = g_rx_pool.buf_cnt_with_data;
    }
}

void umq_rx_qbuf_pool_alloc_free_count_get(uint64_t *alloc_count, uint64_t *free_count)
{
    if (alloc_count != NULL) {
        *alloc_count = __atomic_load_n(&g_rx_alloc_count, __ATOMIC_RELAXED);
    }
    if (free_count != NULL) {
        *free_count = __atomic_load_n(&g_rx_free_count, __ATOMIC_RELAXED);
    }
}
