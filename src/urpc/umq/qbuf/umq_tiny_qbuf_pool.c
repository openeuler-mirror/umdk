/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize tiny qbuf pool function
 * Create: 2026-5-28
 */

#include <malloc.h>
#include <sys/mman.h>
#include <unistd.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "urpc_list.h"
#include "urpc_thread_closure.h"
#include "umq_tiny_qbuf_pool.h"

static qbuf_pool_base_t g_tiny_qbuf_pool = {0};
static __thread thread_local_qbuf_pool_t g_thread_tiny_cache = {0};
static void *g_tiny_buffer_addr = NULL;
static uint64_t g_tiny_total_len = 0;

uint32_t umq_tiny_buf_block_size_bytes(umq_tiny_buf_block_size_t size_enum)
{
    switch (size_enum) {
        case TINY_BLOCK_SIZE_512:
            return 512U;
        case TINY_BLOCK_SIZE_1K:
            return 1024U;
        case TINY_BLOCK_SIZE_2K:
            return 2U * 1024U;
        case TINY_BLOCK_SIZE_4K:
            return 4U * 1024U;
        case TINY_BLOCK_SIZE_8K:
            return 8U * 1024U;
        default:
            return 0;
    }
}

void *umq_tiny_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size)
{
    if (g_tiny_buffer_addr != NULL) {
        return g_tiny_buffer_addr;
    }

    uint64_t min_size = UMQ_TINY_QBUF_BLOCK_SIZE;
    if (buf_mode == UMQ_BUF_SPLIT) {
        min_size = UMQ_TINY_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t);
    }
    g_tiny_total_len = size == 0 ? UMQ_TINY_QBUF_POOL_MAX_SIZE : size;
    if (g_tiny_total_len > UMQ_TINY_QBUF_POOL_MAX_SIZE) {
        g_tiny_total_len = UMQ_TINY_QBUF_POOL_MAX_SIZE;
    }

    g_tiny_buffer_addr = umq_qbuf_base_io_buf_malloc(g_tiny_total_len, min_size);
    if (g_tiny_buffer_addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tiny qbuf memory alloc failed, size %lu, expect at least %lu\n", g_tiny_total_len,
                     min_size);
        g_tiny_total_len = 0;
        return NULL;
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "malloc tiny qbuf io buf %lu bytes\n", g_tiny_total_len);
    return g_tiny_buffer_addr;
}

void umq_tiny_io_buf_free(void)
{
    if (g_tiny_buffer_addr != NULL) {
        free(g_tiny_buffer_addr);
        g_tiny_buffer_addr = NULL;
    }
    g_tiny_total_len = 0;
}

void *umq_tiny_io_buf_addr(void)
{
    return g_tiny_buffer_addr;
}

uint64_t umq_tiny_io_buf_size(void)
{
    return g_tiny_total_len;
}

bool umq_tiny_qbuf_can_alloc(uint32_t request_size, uint32_t effective_size)
{
    return g_tiny_qbuf_pool.inited && request_size != 0 && effective_size <= g_tiny_qbuf_pool.block_size;
}

static int tiny_qbuf_base_fetch(uint32_t needed, local_block_pool_t *local_pool, bool with_data)
{
    if (!with_data) {
        return -UMQ_ERR_EINVAL;
    }

    uint32_t batch_count = qbuf_tls_round_batch(needed, QBUF_POOL_BATCH_CNT);
    global_block_pool_t *global_pool = &g_tiny_qbuf_pool.block_pool[0];

    /*
     * Tiny pool is a fixed-size pool with no expansion slots, no escape path,
     * and no async-expand. Fetch only from its own global pool.
     *
     * Do NOT call the shared fetch_from_global(): it falls through to
     * fetch_from_expansion_pools / expand_global_pool / umq_disable_scale_cap,
     * all of which hardcode access to the NORMAL pool's g_qbuf_pool state.
     * When tiny pool's global pool is exhausted, those paths would steal
     * expansion-slot buffers (mempool_id 257+) from the normal pool, causing
     * cross-pool corruption (blk_size_to_sc unmatched on free).
     *
     * Correct behavior on exhaustion: return -UMQ_ERR_ENOMEM so the C++ layer
     * (ubiobuf.cpp) falls back to the normal pool via share_tls_ub_block().
     */
    umq_buf_t *local_head_before = QBUF_LIST_FIRST(&local_pool->head_with_data[0]);
    uint64_t local_cnt_before = local_pool->buf_cnt_with_data[0];

    (void)pthread_spin_lock(&global_pool->global_mutex);
    uint32_t want = batch_count;
    if (want > global_pool->buf_cnt_with_data) {
        want = (uint32_t)global_pool->buf_cnt_with_data;
    }
    uint32_t got = 0;
    if (want > 0) {
        got = allocate_batch(&global_pool->head_with_data, want, &local_pool->head_with_data[0]);
        global_pool->buf_cnt_with_data -= got;
        local_pool->buf_cnt_with_data[0] += got;
    }
    (void)pthread_spin_unlock(&global_pool->global_mutex);

    if (got < needed) {
        UMQ_LIMIT_VLOG_DEBUG(VLOG_UMQ,
            "tiny qbuf pool not enough (got=%u, needed=%u), suggestion: increase tiny qbuf total_size\n",
            got, needed);
        thread_local_pool_rollback(local_head_before, local_cnt_before, local_pool, global_pool, true, 0);
        return -UMQ_ERR_ENOMEM;
    }

    g_thread_tiny_cache.stats.tls_fetch_buf_cnt_with_data += got;
    return UMQ_SUCCESS;
}

static void release_tiny_thread_cache(uint64_t id)
{
    (void)id;
    if (!g_tiny_qbuf_pool.inited) {
        return;
    }

    // tiny pool is single-level (size_class_count=1), so pass size_class_count=1
    release_thread_cache_impl(&g_thread_tiny_cache, &g_tiny_qbuf_pool.tls_pools, &g_tiny_qbuf_pool.block_pool[0], 1);
}

int umq_tiny_qbuf_pool_init(qbuf_pool_cfg_t *cfg)
{
    if (g_tiny_qbuf_pool.inited) {
        UMQ_VLOG_WARN(VLOG_UMQ, "tiny qbuf pool has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }
    if (cfg == NULL || cfg->buf_addr == NULL || cfg->total_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tiny qbuf pool cfg invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    uint32_t block_size = cfg->data_size == 0 ? UMQ_TINY_QBUF_BLOCK_SIZE : cfg->data_size;
    g_tiny_qbuf_pool.tls_pools.type = THREAD_CLOSURE_TINY_QBUF;
    g_tiny_qbuf_pool.tls_pools.closure = release_tiny_thread_cache;
    g_tiny_qbuf_pool.block_size = block_size;
    g_tiny_qbuf_pool.data_size = block_size;
    g_tiny_qbuf_pool.mempool_id = UMQ_TINY_QBUF_MEMPOOL_ID;
    g_tiny_qbuf_pool.tls_pools.default_tls_qbuf_pool_depth = QBUF_POOL_BATCH_CNT;
    g_tiny_qbuf_pool.tls_pools.enable_tls_expand_qbuf_pool = false;
    g_tiny_qbuf_pool.support_without_data = false;
    g_tiny_qbuf_pool.fetch_fn = tiny_qbuf_base_fetch;
    g_tiny_qbuf_pool.self_shrink_fn = NULL;
    return qbuf_pool_base_init(&g_tiny_qbuf_pool, cfg, 0);
}

void umq_tiny_qbuf_pool_uninit(void)
{
    umq_qbuf_base_uninit(&g_tiny_qbuf_pool, release_tiny_thread_cache);
}

int umq_tiny_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (request_size == 0 || num == 0) {
        return -UMQ_ERR_EINVAL;
    }

    qbuf_alloc_param_t param = {0};
    return umq_qbuf_base_alloc(&g_tiny_qbuf_pool, &g_thread_tiny_cache, request_size, num, list, option, &param);
}

void umq_tiny_qbuf_free(umq_buf_list_t *list)
{
    umq_qbuf_base_free(&g_tiny_qbuf_pool, &g_thread_tiny_cache, list, true);
}

int umq_tiny_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_tiny_qbuf_pool.inited) {
        return -UMQ_ERR_ENOMEM;
    }
    return headroom_reset(qbuf, headroom_size, g_tiny_qbuf_pool.mode, g_tiny_qbuf_pool.block_size);
}

umq_buf_t *umq_tiny_qbuf_data_to_head(void *data)
{
    return umq_qbuf_base_data_to_head(&g_tiny_qbuf_pool, data);
}

int umq_tiny_qbuf_pool_info_get(umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    if (!g_tiny_qbuf_pool.inited) {
        return UMQ_SUCCESS;
    }
    if (qbuf_pool_stats->num >= UMQ_STATS_QBUF_POOL_TYPE_MAX) {
        return -UMQ_ERR_EINVAL;
    }

    return umq_qbuf_pool_base_info_get(&g_tiny_qbuf_pool, qbuf_pool_stats, false, UMQ_QBUF_POOL_TYPE_TINY);
}

int umq_tiny_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    if (!g_tiny_qbuf_pool.inited || ops == NULL || ops->register_seg_callback == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    return ops->register_seg_callback(ctx, UMQ_TINY_QBUF_MEMPOOL_ID, g_tiny_qbuf_pool.data_buffer,
                                      g_tiny_qbuf_pool.total_size);
}

void umq_tiny_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    if (!g_tiny_qbuf_pool.inited || ops == NULL || ops->unregister_seg_callback == NULL) {
        return;
    }
    ops->unregister_seg_callback(ctx, UMQ_TINY_QBUF_MEMPOOL_ID);
}
