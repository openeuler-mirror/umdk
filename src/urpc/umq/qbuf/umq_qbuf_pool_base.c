/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize common qbuf pool function
 * Create: 2026-6-12
 */

#include <malloc.h>
#include <sys/mman.h>

#include "umq_qbuf_pool_base.h"

int qbuf_pool_base_init(qbuf_pool_base_t *base, const qbuf_pool_cfg_t *cfg, uint32_t split_extra_header_count)
{
    if (base == NULL || cfg == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    if (cfg->buf_addr == NULL || cfg->total_size == 0 || base->block_size <= sizeof(umq_buf_t)) {
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq_qbuf_block_pool_init(&base->block_pool);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq qbuf block pool init failed, status: %d\n", ret);
        return ret;
    }

    base->mode = cfg->mode;
    base->data_buffer = cfg->buf_addr;
    base->total_size = cfg->total_size;
    base->headroom_size = cfg->headroom_size;
    base->seg_ops = cfg->seg_ops;
    base->tls_pools.tls_qbuf_pool_depth =
        cfg->tls_qbuf_pool_depth == 0 ? base->tls_pools.default_tls_qbuf_pool_depth : cfg->tls_qbuf_pool_depth;
    base->tls_pools.tls_expand_qbuf_pool_depth = 0;
    if (base->tls_pools.enable_tls_expand_qbuf_pool) {
        base->tls_pools.tls_expand_qbuf_pool_depth = cfg->tls_expand_qbuf_pool_depth == 0 ?
            umq_qbuf_pool_expand_max(base->tls_pools.tls_qbuf_pool_depth) : cfg->tls_expand_qbuf_pool_depth;
    }

    uint64_t blk_num;
    if (cfg->mode == UMQ_BUF_SPLIT) {
        uint64_t header_size = ((uint64_t)split_extra_header_count + 1) * (uint32_t)sizeof(umq_buf_t);
        blk_num = cfg->total_size / (base->block_size + header_size);
        base->header_buffer = (char *)cfg->buf_addr + blk_num * base->block_size;
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        blk_num = cfg->total_size / base->block_size;
        base->header_buffer = NULL;
    } else {
        UMQ_VLOG_ERR(VLOG_UMQ, "buf mode: %d is invalid\n", cfg->mode);
        umq_qbuf_block_pool_uninit(&base->block_pool);
        return -UMQ_ERR_EINVAL;
    }

    buf_init_with_mode((char *)base->data_buffer, (char *)base->header_buffer, blk_num, base->block_size,
        base->mempool_id, true, cfg->mode, &base->block_pool.head_with_data);
    base->total_block_num = blk_num;
    base->block_pool.buf_cnt_with_data = blk_num;
    base->block_pool.buf_cnt_without_data = 0;
    (void)pthread_spin_init(&base->tls_pools.tls_stats_lock, PTHREAD_PROCESS_PRIVATE);
    urpc_list_init(&base->tls_pools.tls_register_head);
    base->inited = true;
    return UMQ_SUCCESS;
}

void *umq_qbuf_base_io_buf_malloc(uint64_t total_len, uint64_t min_size)
{
    if (total_len < min_size) {
        return NULL;
    }

    void *buffer_addr = (void *)memalign(QBUF_MEMALIGN_SIZE, total_len);
    if (buffer_addr == NULL) {
        return NULL;
    }
    madvise(buffer_addr, total_len, MADV_HUGEPAGE);
    return buffer_addr;
}

void umq_qbuf_base_uninit(qbuf_pool_base_t *base, void (*release_thread_cache)(uint64_t))
{
    if (base == NULL || !base->inited) {
        return;
    }

    if (release_thread_cache != NULL) {
        release_thread_cache(0);
    }
    (void)pthread_spin_destroy(&base->tls_pools.tls_stats_lock);
    umq_qbuf_block_pool_uninit(&base->block_pool);
    (void)memset(base, 0, sizeof(*base));
}

static int umq_qbuf_base_alloc_without_data(qbuf_pool_base_t *base, thread_local_qbuf_pool_t *thread_cache,
    local_block_pool_t *local_pool, qbuf_alloc_param_t *param)
{
    if (local_pool->buf_cnt_without_data < param->num) {
        int ret = base->fetch_fn(param->num - local_pool->buf_cnt_without_data, local_pool, false);
        if (ret != UMQ_SUCCESS) {
            return ret;
        }
        thread_cache->stats.tls_fetch_cnt_without_data++;
    }

    umq_qbuf_alloc_nodata(local_pool, param->num, param->list, param->shm);
    if (base->self_shrink_fn != NULL) {
        base->self_shrink_fn(false);
    }
    thread_cache->stats.alloc_cnt_without_data += param->num;
    return UMQ_SUCCESS;
}

static int umq_qbuf_base_alloc_with_data(qbuf_pool_base_t *base, thread_local_qbuf_pool_t *thread_cache,
    local_block_pool_t *local_pool, qbuf_alloc_param_t *param)
{
    uint32_t needed = param->actual_buf_count;
    uint32_t buf_cnt = (uint32_t)local_pool->buf_cnt_with_data;
    if (buf_cnt < needed) {
        int ret = base->fetch_fn(needed - buf_cnt, local_pool, true);
        if (ret != UMQ_SUCCESS) {
            return ret;
        }
        thread_cache->stats.tls_fetch_cnt_with_data++;
    }

    if (base->mode == UMQ_BUF_SPLIT) {
        umq_qbuf_alloc_data_with_split(local_pool, param->request_size, param, param->list, base->block_size);
    } else {
        umq_qbuf_alloc_data_with_combine(local_pool, param->request_size, param, param->list, base->block_size);
    }

    if (base->self_shrink_fn != NULL) {
        base->self_shrink_fn(true);
    }
    thread_cache->stats.alloc_cnt_with_data += param->actual_buf_count;
    return UMQ_SUCCESS;
}

int umq_qbuf_base_alloc(qbuf_pool_base_t *base, thread_local_qbuf_pool_t *thread_cache,
    umq_alloc_option_t *option, qbuf_alloc_param_t *param)
{
    if (param != NULL) {
        param->actual_buf_count = 0;
    }
    if (base == NULL || thread_cache == NULL || base->fetch_fn == NULL || param == NULL ||
        param->list == NULL || param->num == 0) {
        return -UMQ_ERR_EINVAL;
    }
    if (!base->inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    bool has_headroom = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0);
    param->headroom_size = has_headroom ? option->headroom_size : base->headroom_size;
    param->shm = false;

    if (param->request_size == 0) {
        if (!base->support_without_data) {
            return -UMQ_ERR_EINVAL;
        }
        if (has_headroom && param->headroom_size > 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "headroom_size not supported when request_size is 0\n");
            return -UMQ_ERR_EINVAL;
        }
        if (base->mode != UMQ_BUF_SPLIT) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "cannot alloc memory size 0 in combine mode\n");
            return -UMQ_ERR_ENOMEM;
        }
    } else {
        param->actual_buf_count =
            umq_qbuf_base_actual_buf_count(base, param->request_size, param->num, param->headroom_size);
    }

    local_block_pool_t *local_pool = get_thread_local_cache(thread_cache, &base->tls_pools);
    if (param->request_size == 0) {
        return umq_qbuf_base_alloc_without_data(base, thread_cache, local_pool, param);
    }

    return umq_qbuf_base_alloc_with_data(base, thread_cache, local_pool, param);
}

void umq_qbuf_base_free(qbuf_pool_base_t *base, thread_local_qbuf_pool_t *thread_cache, umq_buf_list_t *list,
    bool shm)
{
    if (base == NULL || !base->inited || list == NULL || QBUF_LIST_FIRST(list) == NULL) {
        return;
    }

    local_block_pool_t *local_pool = get_thread_local_cache(thread_cache, &base->tls_pools);
    umq_buf_list_t *local_head = NULL;
    uint64_t *local_buf_cnt = NULL;
    uint64_t *free_cnt = NULL;
    uint64_t *tls_return_cnt = NULL;
    bool without_data = base->support_without_data && base->mode == UMQ_BUF_SPLIT &&
        QBUF_LIST_FIRST(list)->mempool_without_data == 1;
    if (without_data) {
        local_head = &local_pool->head_without_data;
        local_buf_cnt = &local_pool->buf_cnt_without_data;
        free_cnt = &thread_cache->stats.free_cnt_without_data;
        tls_return_cnt = &thread_cache->stats.tls_return_cnt_without_data;
    } else {
        local_head = &local_pool->head_with_data;
        local_buf_cnt = &local_pool->buf_cnt_with_data;
        free_cnt = &thread_cache->stats.free_cnt_with_data;
        tls_return_cnt = &thread_cache->stats.tls_return_cnt_with_data;
    }

    uint32_t cnt = release_batch(list, local_head, shm);
    *local_buf_cnt += cnt;

    uint32_t cap;
    if (base->block_pool.disable_scale_cap) {
        cap = (uint32_t)base->tls_pools.tls_qbuf_pool_depth;
    } else {
        cap = without_data ? (uint32_t)local_pool->capacity_without_data : (uint32_t)local_pool->capacity_with_data;
    }

    if (*local_buf_cnt > cap) {
        uint32_t batch_count = base->tls_pools.batch_count == 0 ? QBUF_POOL_BATCH_CNT : base->tls_pools.batch_count;
        uint32_t threshold = cap > batch_count ? cap - batch_count : 0;
        return_to_global(&base->block_pool, local_pool, &thread_cache->stats, !without_data, threshold);
        (*tls_return_cnt)++;
    }
    *free_cnt += cnt;
}

umq_buf_t *umq_qbuf_base_data_to_head(qbuf_pool_base_t *base, void *data)
{
    if (base == NULL || !base->inited || data == NULL) {
        return NULL;
    }

    if (base->mode == UMQ_BUF_SPLIT) {
        if (data < base->data_buffer || data >= base->header_buffer) {
            return NULL;
        }
        uint64_t id = ((uint64_t)(uintptr_t)data - (uint64_t)(uintptr_t)base->data_buffer) / base->block_size;
        return (umq_buf_t *)((char *)base->header_buffer + id * sizeof(umq_buf_t));
    }

    if (data < base->data_buffer || data >= (void *)((char *)base->data_buffer + base->total_size)) {
        return NULL;
    }
    uint64_t id = ((uint64_t)(uintptr_t)data - (uint64_t)(uintptr_t)base->data_buffer) / base->block_size;
    return (umq_buf_t *)((char *)base->data_buffer + id * base->block_size);
}

int umq_qbuf_pool_base_info_get(qbuf_pool_base_t *base, umq_qbuf_pool_stats_t *qbuf_pool_stats,
    bool reset_local_stats)
{
    if (base == NULL || qbuf_pool_stats == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    if (qbuf_pool_stats->num >= UMQ_STATS_QBUF_POOL_TYPE_MAX) {
        return -UMQ_ERR_EINVAL;
    }

    umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[qbuf_pool_stats->num];
    uint32_t block_size = base->block_size;
    uint32_t umq_buf_t_size = (uint32_t)sizeof(umq_buf_t);
    info->mode = base->mode;
    info->total_size = base->total_size;
    info->headroom_size = base->headroom_size;
    info->block_size = block_size;
    info->total_block_num = base->total_block_num;
    info->umq_buf_t_size = umq_buf_t_size;
    if (base->mode == UMQ_BUF_SPLIT) {
        info->data_size = block_size;
        info->buf_size = block_size + umq_buf_t_size;
        info->available_mem.split.block_num_with_data = base->block_pool.buf_cnt_with_data;
        info->available_mem.split.size_with_data = base->block_pool.buf_cnt_with_data * (block_size + umq_buf_t_size);
        info->available_mem.split.block_num_without_data = base->block_pool.buf_cnt_without_data;
        info->available_mem.split.size_without_data = base->block_pool.buf_cnt_without_data * umq_buf_t_size;
    } else {
        info->data_size = block_size - umq_buf_t_size;
        info->buf_size = block_size;
        info->available_mem.combine.block_num_with_data = base->block_pool.buf_cnt_with_data;
        info->available_mem.combine.size_with_data = base->block_pool.buf_cnt_with_data * block_size;
    }
    qbuf_pool_stats->num++;

    if (reset_local_stats) {
        qbuf_pool_stats->local_qbuf_pool_num = 0;
    }

    (void)pthread_spin_lock(&base->tls_pools.tls_stats_lock);
    thread_local_qbuf_pool_t *pool_iter = NULL;
    URPC_LIST_FOR_EACH(pool_iter, tls_node, &base->tls_pools.tls_register_head) {
        if (qbuf_pool_stats->local_qbuf_pool_num >= UMQ_LOCAL_QBUF_POOL_MAX_NUM) {
            break;
        }
        umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[qbuf_pool_stats->local_qbuf_pool_num];
        (void)memset(s, 0, sizeof(*s));
        s->capacity_with_data = pool_iter->block_pool.capacity_with_data;
        s->buf_cnt_with_data = pool_iter->block_pool.buf_cnt_with_data;
        s->capacity_without_data = pool_iter->block_pool.capacity_without_data;
        s->buf_cnt_without_data = pool_iter->block_pool.buf_cnt_without_data;
        s->tid = pool_iter->stats.tid;
        s->tls_fetch_cnt_with_data = pool_iter->stats.tls_fetch_cnt_with_data;
        s->tls_fetch_buf_cnt_with_data = pool_iter->stats.tls_fetch_buf_cnt_with_data;
        s->tls_fetch_cnt_without_data = pool_iter->stats.tls_fetch_cnt_without_data;
        s->tls_fetch_buf_cnt_without_data = pool_iter->stats.tls_fetch_buf_cnt_without_data;
        s->tls_return_cnt_with_data = pool_iter->stats.tls_return_cnt_with_data;
        s->tls_return_buf_cnt_with_data = pool_iter->stats.tls_return_buf_cnt_with_data;
        s->tls_return_cnt_without_data = pool_iter->stats.tls_return_cnt_without_data;
        s->tls_return_buf_cnt_without_data = pool_iter->stats.tls_return_buf_cnt_without_data;
        s->alloc_cnt_with_data = pool_iter->stats.alloc_cnt_with_data;
        s->alloc_cnt_without_data = pool_iter->stats.alloc_cnt_without_data;
        s->free_cnt_with_data = pool_iter->stats.free_cnt_with_data;
        s->free_cnt_without_data = pool_iter->stats.free_cnt_without_data;
        qbuf_pool_stats->local_qbuf_pool_num++;
    }
    (void)pthread_spin_unlock(&base->tls_pools.tls_stats_lock);
    return UMQ_SUCCESS;
}
