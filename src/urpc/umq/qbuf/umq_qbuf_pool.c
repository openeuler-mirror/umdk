/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize qbuf pool function
 * Create: 2025-7-26
 * Note:
 * History: 2025-7-26
 */

#include <malloc.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "umq_qbuf_pool.h"

#include "urpc_thread_closure.h"

#define QBUF_POOL_TLS_MAX (2048) // max count of thread local buffer storage
#define QBUF_POOL_BATCH_CNT (512) // batch size when fetch from global or return to global

typedef struct local_qbuf_pool {
    bool inited;
    local_block_pool_t block_pool;
} local_qbuf_pool_t;

typedef struct qbuf_pool {
    bool inited;
    void *data_buffer;          // 数据区起始地址，COMBINE模式为所有的数据起始位置，SPLIT模式为所有的数据起始位置+头部区大小，需要8K对齐
    void *header_buffer;        // 头部区起始地址，COMBINE模式为NULL，SPLIT模式为所有数据的起始位置
    void *ext_header_buffer;    // ext头部区起始地址，数据区指针为空，仅有头部，数量为分片数*16。combine模式为NULL
    uint64_t total_size;        // 内存池管理的内存总大小

    uint32_t block_size;        // headroom size + data size以8K为大小向上取整，如果是combine模式还包括umq_qbuf_t结构体大小
    uint32_t headroom_size;     // 预留的头部空间大小
    uint32_t data_size;

    uint64_t total_block_num;
    umq_buf_mode_t mode;

    global_block_pool_t block_pool;
} qbuf_pool_t;

static qbuf_pool_t g_qbuf_pool = {0};
static __thread local_qbuf_pool_t g_thread_cache = {0};
static uint8_t g_umq_qbuf_size_pow_samll = UMQ_QBUF_SIZE_POW_8K;

static void *g_buffer_addr = NULL;
static uint64_t g_total_len = 0;

void *umq_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size)
{
    if (g_buffer_addr != NULL) {
        return g_buffer_addr;
    }

    uint64_t min_size = umq_buf_size_small();
    if (buf_mode == UMQ_BUF_SPLIT) {
        min_size = (UMQ_EMPTY_HEADER_COEFFICIENT + 1) * (uint32_t)sizeof(umq_buf_t) + umq_buf_size_small();
    }

    if (size > 0) {
        if (size < min_size) {
            UMQ_VLOG_ERR("memory size %lu invalid, expect at least %lu\n", size, min_size);
            return NULL;
        }

        g_total_len = size;
    } else {
        g_total_len = UMQ_BUF_DEFAULT_TOTAL_SIZE;
    }

    g_buffer_addr = (void *)memalign(umq_buf_size_small(), g_total_len);
    if (g_buffer_addr == NULL) {
        UMQ_VLOG_ERR("memory alloc failed\n");
        return NULL;
    }

    UMQ_VLOG_INFO("malloc umq io buf %lu bytes\n", g_total_len);

    return g_buffer_addr;
}

void umq_io_buf_free(void)
{
    if (g_buffer_addr != NULL) {
        free(g_buffer_addr);
        g_buffer_addr = NULL;
    }

    g_total_len = 0;
}

void *umq_io_buf_addr(void)
{
    return g_buffer_addr;
}

uint64_t umq_io_buf_size(void)
{
    return g_total_len;
}

int umq_buf_size_pow_small_set(umq_buf_block_size_t block_size)
{
    if (block_size < BLOCK_SIZE_8K || block_size >= BLOCK_SIZE_MAX) {
        UMQ_VLOG_ERR("block size %d is invalid\n", block_size);
        return -UMQ_ERR_EINVAL;
    }

    if (block_size == BLOCK_SIZE_8K) {
        g_umq_qbuf_size_pow_samll = UMQ_QBUF_SIZE_POW_8K;
    } else if (block_size == BLOCK_SIZE_16K) {
        g_umq_qbuf_size_pow_samll = UMQ_QBUF_SIZE_POW_16K;
    } else if (block_size == BLOCK_SIZE_32K) {
        g_umq_qbuf_size_pow_samll = UMQ_QBUF_SIZE_POW_32K;
    } else {
        g_umq_qbuf_size_pow_samll = UMQ_QBUF_SIZE_POW_64K;
    }

    return UMQ_SUCCESS;
}

uint8_t umq_buf_size_pow_small(void)
{
    return g_umq_qbuf_size_pow_samll;
}

void umq_qbuf_config_get(qbuf_pool_cfg_t *cfg)
{
    cfg->buf_addr = g_qbuf_pool.data_buffer;
    cfg->total_size = g_qbuf_pool.total_size;
    cfg->data_size = g_qbuf_pool.data_size;
    cfg->headroom_size = g_qbuf_pool.headroom_size;
    cfg->mode = g_qbuf_pool.mode;
}

static void release_thread_cache(uint64_t id);

static ALWAYS_INLINE local_block_pool_t *get_thread_cache(void)
{
    if (!g_thread_cache.inited) {
        QBUF_LIST_INIT(&g_thread_cache.block_pool.head_with_data);
        QBUF_LIST_INIT(&g_thread_cache.block_pool.head_without_data);
        g_thread_cache.inited = true;
        urpc_thread_closure_register(THREAD_CLOSURE_QBUF, 0, release_thread_cache);
    }

    return &g_thread_cache.block_pool;
}

// release all thread cache to global pool. should be called when thread exits
static ALWAYS_INLINE void release_thread_cache(uint64_t id)
{
    if (!g_thread_cache.inited || !g_qbuf_pool.inited) {
        return;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    (void)pthread_mutex_lock(&g_qbuf_pool.block_pool.global_mutex);
    if (local_pool->head_with_data.first != NULL) {
        uint32_t cnt = release_batch(&local_pool->head_with_data, &g_qbuf_pool.block_pool.head_with_data);
        g_qbuf_pool.block_pool.buf_cnt_with_data += cnt;
    }

    if (local_pool->head_without_data.first != NULL) {
        uint32_t cnt = release_batch(&local_pool->head_without_data, &g_qbuf_pool.block_pool.head_without_data);
        g_qbuf_pool.block_pool.buf_cnt_without_data += cnt;
    }
    (void)pthread_mutex_unlock(&g_qbuf_pool.block_pool.global_mutex);
}

int umq_qbuf_pool_init(qbuf_pool_cfg_t *cfg)
{
    if (g_qbuf_pool.inited) {
        UMQ_VLOG_INFO("qbuf pool has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    (void)pthread_mutex_init(&g_qbuf_pool.block_pool.global_mutex, NULL);
    QBUF_LIST_INIT(&g_qbuf_pool.block_pool.head_with_data);
    g_qbuf_pool.mode = cfg->mode;
    g_qbuf_pool.total_size = cfg->total_size;
    g_qbuf_pool.headroom_size = cfg->headroom_size;
    g_qbuf_pool.data_size = cfg->data_size;

    if (cfg->mode == UMQ_BUF_SPLIT) {
        QBUF_LIST_INIT(&g_qbuf_pool.block_pool.head_without_data);
        uint32_t blk_size = umq_buf_size_small();
        uint64_t blk_num = cfg->total_size /
            ((UMQ_EMPTY_HEADER_COEFFICIENT + 1) * (uint32_t)sizeof(umq_buf_t) + blk_size);

        g_qbuf_pool.block_size = blk_size;
        g_qbuf_pool.total_block_num = blk_num;

        g_qbuf_pool.data_buffer = cfg->buf_addr;
        g_qbuf_pool.header_buffer = cfg->buf_addr + blk_num * blk_size;
        g_qbuf_pool.ext_header_buffer = g_qbuf_pool.header_buffer + blk_num * sizeof(umq_buf_t);

        for (uint64_t i = 0; i < blk_num; i++) {
            umq_buf_t *buf = id_to_buf_with_data_split((char *)g_qbuf_pool.header_buffer, i);
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
            buf->data_size = blk_size;
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = g_qbuf_pool.data_buffer + i * blk_size;
            buf->mempool_id = 0;
            buf->need_import = 0;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool.head_with_data, buf);
        }

        uint64_t head_without_data_count = blk_num * UMQ_EMPTY_HEADER_COEFFICIENT;
        for (uint64_t i = 0; i < head_without_data_count; i++) {
            umq_buf_t *head_buf = id_to_buf_without_data_split((char *)g_qbuf_pool.ext_header_buffer, i);
            head_buf->umqh = UMQ_INVALID_HANDLE;
            head_buf->buf_size = (uint32_t)sizeof(umq_buf_t);
            head_buf->data_size = 0;
            head_buf->total_data_size = 0;
            head_buf->headroom_size = 0;
            head_buf->buf_data = NULL;
            head_buf->mempool_id = 0;
            head_buf->need_import = 0;
            (void)memset(head_buf->qbuf_ext, 0, sizeof(head_buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool.head_without_data, head_buf);
        }
        g_qbuf_pool.block_pool.buf_cnt_with_data = blk_num;
        g_qbuf_pool.block_pool.buf_cnt_without_data = head_without_data_count;
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        uint32_t blk_size = umq_buf_size_small();
        uint64_t blk_num = cfg->total_size / blk_size;

        g_qbuf_pool.data_buffer = cfg->buf_addr;
        g_qbuf_pool.header_buffer = NULL;
        g_qbuf_pool.ext_header_buffer = NULL;

        g_qbuf_pool.block_size = blk_size;
        g_qbuf_pool.total_block_num = blk_num;

        for (uint64_t i = 0; i < blk_num; i++) {
            umq_buf_t *buf = id_to_buf_combine((char *)g_qbuf_pool.data_buffer, i, g_qbuf_pool.block_size);
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = blk_size;
            buf->data_size = blk_size - (uint32_t)sizeof(umq_buf_t);
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = (char *)buf + sizeof(umq_buf_t);
            buf->mempool_id = 0;
            buf->need_import = 0;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool.head_with_data, buf);
        }
        g_qbuf_pool.block_pool.buf_cnt_with_data = blk_num;
        g_qbuf_pool.block_pool.buf_cnt_without_data = 0;
    } else {
        UMQ_VLOG_ERR("buf mode: %d is invalid\n", cfg->mode);
        return -UMQ_ERR_EINVAL;
    }

    g_qbuf_pool.inited = true;
    return UMQ_SUCCESS;
}

void umq_qbuf_pool_uninit(void)
{
    if (!g_qbuf_pool.inited) {
        return;
    }

    memset(&g_qbuf_pool, 0, sizeof(qbuf_pool_t));
}

int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_VLOG_ERR("qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    bool flag = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0);
    uint32_t headroom_size = flag ? option->headroom_size : g_qbuf_pool.headroom_size;
    uint32_t actual_buf_count;

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        actual_buf_count =
            num * ((request_size + headroom_size + umq_buf_size_small() - 1) >> umq_buf_size_pow_small());
    } else {
        uint32_t align_size = umq_buf_size_small() - sizeof(umq_buf_t);
        actual_buf_count = num * ((request_size + headroom_size + align_size - 1) / align_size);
    }

    if (request_size == 0) {
        if (flag && headroom_size > 0) {
            UMQ_VLOG_ERR("headroom_size not supported when request_size is 0\n");
            return -EINVAL;
        }

        if (g_qbuf_pool.mode != UMQ_BUF_SPLIT) {
            UMQ_VLOG_ERR("cannot alloc memory size 0 in combine mode\n");
            return -UMQ_ERR_ENOMEM;
        }

        while (local_pool->buf_cnt_without_data < num) {
            if (fetch_from_global(&g_qbuf_pool.block_pool, local_pool, false, QBUF_POOL_BATCH_CNT) <= 0) {
                return -UMQ_ERR_ENOMEM;
            }
        }

        umq_qbuf_alloc_nodata(local_pool, num, list);

        return 0;
    }

    while (local_pool->buf_cnt_with_data < actual_buf_count) {
        if (fetch_from_global(&g_qbuf_pool.block_pool, local_pool, true, QBUF_POOL_BATCH_CNT) <= 0) {
            UMQ_VLOG_ERR("fetch from global failed, current size: %u, alloc num: %u\n",
                local_pool->buf_cnt_with_data, actual_buf_count);
            return -UMQ_ERR_ENOMEM;
        }
    }

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        umq_qbuf_alloc_data_with_split(local_pool, request_size, actual_buf_count, list, headroom_size);
    } else {
        umq_qbuf_alloc_data_with_combine(local_pool, request_size, actual_buf_count, list, headroom_size);
    }
    return UMQ_SUCCESS;
}

void umq_qbuf_free(umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_VLOG_ERR("qbuf pool has not been inited\n");
        return;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    // split mode and buf is in head no data zone
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT && (void *)QBUF_LIST_FIRST(list) >= g_qbuf_pool.ext_header_buffer) {
        // put buf list before head of head_without_data
        uint32_t cnt = release_batch(list, &local_pool->head_without_data);
        local_pool->buf_cnt_without_data += cnt;

        // if local list node count reaches QBUF_POOL_TLS_MAX + QBUF_POOL_BATCH_CNT, return some nodes to global
        if (local_pool->buf_cnt_without_data >= QBUF_POOL_TLS_MAX + QBUF_POOL_BATCH_CNT) {
            return_to_global(&g_qbuf_pool.block_pool, local_pool, false, QBUF_POOL_TLS_MAX);
        }

        return;
    }

    uint32_t cnt = release_batch(list, &local_pool->head_with_data);
    local_pool->buf_cnt_with_data += cnt;

    // if local list node count reaches QBUF_POOL_TLS_MAX + QBUF_POOL_BATCH_CNT, return some nodes to global
    if (local_pool->buf_cnt_with_data > QBUF_POOL_TLS_MAX + QBUF_POOL_BATCH_CNT) {
        return_to_global(&g_qbuf_pool.block_pool, local_pool, true, QBUF_POOL_TLS_MAX);
    }
}

int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_qbuf_pool.inited) {
        UMQ_VLOG_ERR("qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    return headroom_reset(qbuf, headroom_size, g_qbuf_pool.mode, g_qbuf_pool.block_size);
}

umq_buf_t *umq_qbuf_data_to_head(void *data)
{
    if (!g_qbuf_pool.inited) {
        UMQ_VLOG_ERR("qbuf pool has not been inited\n");
        return NULL;
    }

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        if (data >= g_qbuf_pool.data_buffer && data < g_qbuf_pool.header_buffer) {
            uint32_t id = (uint32_t)(data - g_qbuf_pool.data_buffer) / g_qbuf_pool.block_size;
            return (umq_buf_t *)(g_qbuf_pool.header_buffer + id * sizeof(umq_buf_t));
        }
    } else {
        if (data >= g_qbuf_pool.data_buffer && data < g_qbuf_pool.data_buffer + g_qbuf_pool.total_size) {
            uint32_t id = (uint32_t)(data - g_qbuf_pool.data_buffer) / g_qbuf_pool.block_size;
            return (umq_buf_t *)(g_qbuf_pool.data_buffer + id * g_qbuf_pool.block_size);
        }
    }

    return NULL;
}

uint32_t umq_qbuf_headroom_get(void)
{
    return g_qbuf_pool.headroom_size;
}

umq_buf_mode_t umq_qbuf_mode_get(void)
{
    return g_qbuf_pool.mode;
}

int umq_qbuf_register_seg(uint8_t *ctx, register_seg_callback_t register_seg_func)
{
    return register_seg_func(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID, g_qbuf_pool.data_buffer,  g_qbuf_pool.total_size);
}

int umq_qbuf_unregister_seg(uint8_t *ctx, unregister_seg_callback_t unregister_seg_func)
{
    return unregister_seg_func(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
}