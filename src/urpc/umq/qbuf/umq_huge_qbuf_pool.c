/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realization of qbuf pool function for huge buffer
 * Create: 2025-10-29
 * Note:
 * History: 2025-10-29
 */

#include "umq_errno.h"
#include "umq_vlog.h"
#include "umq_huge_qbuf_pool.h"

#define HUGE_QBUF_POOL_NUM_MAX (64)
#define HUGE_QBUF_POOL_IDX_SHIFT (1)

typedef struct huge_pool_info {
    void *data_buffer;      // start address(this address must be 8K-aligned) of the data area.
                            // (1) in COMBINE mode, it is the starting position of all data(head + data);
                            // (2) in SPLIT mode, it is the starting position of data;
    void *header_buffer;    // head area start address.
                            // (1) in COMBINE mode, here is NULL;
                            // (2) in SPLIT mode, it is the start position of head;
    bool imported;
} huge_pool_info_t;

typedef struct huge_pool {
    bool inited;
    uint64_t total_size;    // total size of memory managed by the current 'huge memory pool'
    uint32_t block_size;    // The headroom size + data size is rounded up to the nearest multiple of 8K.
                            // In COMBINE mode, it also includes the size of the umq_qbuf_t structure.
    uint32_t data_size;
    uint64_t total_block_num;
    uint32_t pool_idx;
    uint32_t pool_idx_shift;
    int (*memory_init_callback)(uint8_t mempool_id, enum HUGE_QBUF_POOL_SIZE_TYPE type, void **buf_addr);
    void (*memory_uninit_callback)(uint8_t mempool_id, void *buf_addr);
    global_block_pool_t block_pool;
    huge_pool_info_t pool_info[HUGE_QBUF_POOL_NUM_MAX];
} huge_pool_t;

typedef struct huge_pool_ctx {
    bool inited;
    uint32_t headroom_size;     // reserve head room size
    umq_buf_mode_t mode;
    huge_pool_t pool[HUGE_QBUF_POOL_SIZE_TYPE_MAX];
} huge_pool_ctx_t;

static huge_pool_ctx_t g_huge_pool_ctx = {
    .pool = {
        [HUGE_QBUF_POOL_SIZE_TYPE_MID] = {
            .pool_idx_shift = HUGE_QBUF_POOL_IDX_SHIFT,
            .block_pool = {
                .global_mutex = PTHREAD_MUTEX_INITIALIZER,
            },
        },
        [HUGE_QBUF_POOL_SIZE_TYPE_BIG] = {
            .pool_idx_shift = HUGE_QBUF_POOL_IDX_SHIFT + HUGE_QBUF_POOL_NUM_MAX,
            .block_pool = {
                .global_mutex = PTHREAD_MUTEX_INITIALIZER,
            },
        },
        [HUGE_QBUF_POOL_SIZE_TYPE_HUGE] = {
            .pool_idx_shift = HUGE_QBUF_POOL_IDX_SHIFT +
                (HUGE_QBUF_POOL_SIZE_TYPE_HUGE * HUGE_QBUF_POOL_NUM_MAX),
            .block_pool = {
                .global_mutex = PTHREAD_MUTEX_INITIALIZER,
            },
        },
    }
};

static uint32_t (*g_huge_pool_size[HUGE_QBUF_POOL_SIZE_TYPE_MAX])(void) = {
    umq_buf_size_middle,
    umq_buf_size_big,
    umq_buf_size_huge,};

static int umq_huge_qbuf_pool_init(enum HUGE_QBUF_POOL_SIZE_TYPE type, huge_pool_t *pool)
{
    void *buf_addr = NULL;
    uint8_t mempool_id = pool->pool_idx + pool->pool_idx_shift;
    if (pool->pool_idx >= HUGE_QBUF_POOL_NUM_MAX) {
        UMQ_VLOG_ERR("huge qbuf pool has reached its maximum expansion limit(%d)\n", HUGE_QBUF_POOL_NUM_MAX);
        return -UMQ_ERR_EINVAL;
    }

    huge_pool_info_t *pool_info = &pool->pool_info[pool->pool_idx];

    if (pool->memory_init_callback(mempool_id, type, &buf_addr) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("memory generation callback executes failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    if (g_huge_pool_ctx.mode == UMQ_BUF_SPLIT) {
        pool_info->data_buffer = buf_addr;
        pool_info->header_buffer = buf_addr + pool->total_block_num * pool->block_size;

        for (uint64_t i = 0; i < pool->total_block_num; i++) {
            umq_buf_t *buf = id_to_buf_with_data_split((char *)pool_info->header_buffer, i);
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = pool->block_size + (uint32_t)sizeof(umq_buf_t);
            buf->data_size = pool->block_size;
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = pool_info->data_buffer + i * pool->block_size;
            buf->mempool_id = mempool_id;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&pool->block_pool.head_with_data, buf);
        }

        pool->block_pool.buf_cnt_with_data += pool->total_block_num;
    } else if (g_huge_pool_ctx.mode == UMQ_BUF_COMBINE) {
        pool_info->data_buffer = buf_addr;
        pool_info->header_buffer = NULL;

        for (uint64_t i = 0; i < pool->total_block_num; i++) {
            umq_buf_t *buf = id_to_buf_combine((char *)pool_info->data_buffer, i, pool->block_size);
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = pool->block_size;
            buf->data_size = pool->block_size - (uint32_t)sizeof(umq_buf_t);
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = (char *)buf + sizeof(umq_buf_t);
            buf->mempool_id = mempool_id;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&pool->block_pool.head_with_data, buf);
        }

        pool->block_pool.buf_cnt_with_data += pool->total_block_num;
    }

    pool->pool_idx++;

    return UMQ_SUCCESS;
}

enum HUGE_QBUF_POOL_SIZE_TYPE umq_huge_qbuf_get_type_for_size(uint32_t buf_size)
{
    enum HUGE_QBUF_POOL_SIZE_TYPE type;

    if (buf_size < umq_buf_size_big()) {
        type = HUGE_QBUF_POOL_SIZE_TYPE_MID;
    } else if (buf_size < umq_buf_size_huge()) {
        type = HUGE_QBUF_POOL_SIZE_TYPE_BIG;
    } else {
        type = HUGE_QBUF_POOL_SIZE_TYPE_HUGE;
    }

    return type;
}

uint32_t umq_huge_qbuf_get_size_for_type(enum HUGE_QBUF_POOL_SIZE_TYPE type)
{
    uint32_t blk_size = 0;

    switch (type) {
        case HUGE_QBUF_POOL_SIZE_TYPE_MID:
            blk_size = umq_buf_size_middle();
            break;
        case HUGE_QBUF_POOL_SIZE_TYPE_BIG:
            blk_size = umq_buf_size_big();
            break;
        case  HUGE_QBUF_POOL_SIZE_TYPE_HUGE:
            blk_size = umq_buf_size_huge();
            break;
        default:
            break;
    }

    return blk_size;
}

static int do_umq_huge_qbuf_config_init(huge_qbuf_pool_cfg_t *cfg)
{
    huge_pool_t *pool = &g_huge_pool_ctx.pool[cfg->type];
    if (pool->inited) {
        UMQ_VLOG_ERR("huge qbuf pool(type: %d) has already been inited\n", cfg->type);
        return -UMQ_ERR_EEXIST;
    }

    QBUF_LIST_INIT(&pool->block_pool.head_with_data);
    pool->total_size = cfg->total_size;
    pool->data_size = g_huge_pool_size[cfg->type]();
    pool->memory_init_callback = cfg->memory_init_callback;
    pool->memory_uninit_callback = cfg->memory_uninit_callback;
    uint32_t blk_size = umq_huge_qbuf_get_size_for_type(cfg->type);

    if (cfg->mode == UMQ_BUF_SPLIT) {
        uint64_t blk_num = cfg->total_size / ((uint32_t)sizeof(umq_buf_t) + blk_size);

        pool->block_size = blk_size;
        pool->total_block_num = blk_num;
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        uint64_t blk_num = cfg->total_size / blk_size;

        pool->block_size = blk_size;
        pool->total_block_num = blk_num;
    }

    pool->inited = true;

    return UMQ_SUCCESS;
}

void umq_huge_qbuf_pool_uninit(void)
{
    if (!g_huge_pool_ctx.inited) {
        return;
    }

    for (uint32_t i = 0; i < HUGE_QBUF_POOL_SIZE_TYPE_MAX; i++) {
        huge_pool_t *pool = &g_huge_pool_ctx.pool[i];
        for (uint32_t j = 0; j < pool->pool_idx; j++) {
            huge_pool_info_t *pool_info = &pool->pool_info[j];
            pool->memory_uninit_callback(pool->pool_idx_shift + j, pool_info->data_buffer);
        }
    }

    (void)memset(&g_huge_pool_ctx, 0, sizeof(huge_pool_ctx_t));
}

int umq_huge_qbuf_config_init(huge_qbuf_pool_cfg_t *cfg)
{
    if (cfg == NULL) {
        UMQ_VLOG_ERR("invalid input arguments\n");
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->mode != UMQ_BUF_SPLIT && cfg->mode != UMQ_BUF_COMBINE) {
        UMQ_VLOG_ERR("huge qbuf pool mode: %d is invalid\n", cfg->mode);
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->type < 0 || cfg->type >= HUGE_QBUF_POOL_SIZE_TYPE_MAX) {
        UMQ_VLOG_ERR("huge qbuf pool type: %d is invalid\n", cfg->type);
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->memory_init_callback == NULL || cfg->memory_uninit_callback == NULL) {
        UMQ_VLOG_ERR("invalid memory related callback\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret = do_umq_huge_qbuf_config_init(cfg);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    g_huge_pool_ctx.mode = cfg->mode;
    g_huge_pool_ctx.headroom_size = cfg->headroom_size;
    g_huge_pool_ctx.inited = true;

    return ret;
}

static ALWAYS_INLINE void umq_huge_qbuf_alloc_data_with_split(huge_pool_t *pool, uint32_t request_size,
    uint32_t num, umq_buf_list_t *list, int32_t headroom_size)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t blk_size = pool->block_size;
    int32_t headroom_size_temp = headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_capacity = blk_size - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &pool->block_pool.head_with_data) {
        cur_node->buf_data = floor_to_align(cur_node->buf_data, blk_size) + headroom_size_temp;
        cur_node->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
        cur_node->headroom_size = headroom_size_temp;
        cur_node->total_data_size = total_data_size;
        cur_node->first_fragment = first_fragment;
        cur_node->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        remaining_size -= cur_node->data_size;
        if (remaining_size == 0) {
            headroom_size_temp = headroom_size;
            total_data_size = request_size;
            remaining_size = request_size;
            first_fragment = true;
            max_data_capacity = blk_size - headroom_size;
        } else {
            headroom_size_temp = 0;
            total_data_size = 0;
            first_fragment = false;
            max_data_capacity = blk_size;
        }
        if (++cnt == num) {
            break;
        }
    }

    umq_buf_t *head = QBUF_LIST_FIRST(&pool->block_pool.head_with_data);
    // switch head node
    QBUF_LIST_FIRST(&pool->block_pool.head_with_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = head;
    pool->block_pool.buf_cnt_with_data -= num;
}

static ALWAYS_INLINE void umq_huge_qbuf_alloc_data_with_combine(huge_pool_t *pool, uint32_t request_size,
    uint32_t num, umq_buf_list_t *list, int32_t headroom_size)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t blk_size = pool->block_size;
    int32_t headroom_size_temp = headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_size = blk_size - sizeof(umq_buf_t);
    uint32_t max_data_capacity = max_data_size - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &pool->block_pool.head_with_data) {
        cur_node->buf_data = cur_node->data + headroom_size_temp;
        cur_node->buf_size = blk_size;
        cur_node->headroom_size = headroom_size_temp;
        cur_node->total_data_size = total_data_size;
        cur_node->first_fragment = first_fragment;
        cur_node->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        remaining_size -= cur_node->data_size;
        if (remaining_size == 0) {
            headroom_size_temp = headroom_size;
            total_data_size = request_size;
            remaining_size = request_size;
            first_fragment = true;
            max_data_capacity = max_data_size - headroom_size;
        } else {
            headroom_size_temp = 0;
            total_data_size = 0;
            first_fragment = false;
            max_data_capacity = max_data_size;
        }
        if (++cnt == num) {
            break;
        }
    }

    umq_buf_t *head = QBUF_LIST_FIRST(&pool->block_pool.head_with_data);
    // switch head node
    QBUF_LIST_FIRST(&pool->block_pool.head_with_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = head;
    pool->block_pool.buf_cnt_with_data -= num;
}

int umq_huge_qbuf_alloc(enum HUGE_QBUF_POOL_SIZE_TYPE type, uint32_t request_size, uint32_t num,
    umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_huge_pool_ctx.inited) {
        UMQ_VLOG_ERR("huge qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    huge_pool_t *pool = &g_huge_pool_ctx.pool[type];

    (void)pthread_mutex_lock(&pool->block_pool.global_mutex);

    uint32_t actual_buf_count;
    uint32_t headroom_size =
        (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ?
            option->headroom_size : g_huge_pool_ctx.headroom_size;
    uint32_t align_size = umq_huge_qbuf_get_size_for_type(type);

    if (g_huge_pool_ctx.mode == UMQ_BUF_SPLIT) {
        actual_buf_count = num * ((request_size + headroom_size + align_size - 1) / (align_size));
    } else {
        align_size -= sizeof(umq_buf_t);
        actual_buf_count = num * ((request_size + headroom_size + align_size - 1) / (align_size));
    }

    while (pool->block_pool.buf_cnt_with_data < actual_buf_count) {
        if (umq_huge_qbuf_pool_init(type, pool) != UMQ_SUCCESS) {
            (void)pthread_mutex_unlock(&pool->block_pool.global_mutex);
            UMQ_VLOG_ERR("buffer not enough, rest count: %u\n", pool->block_pool.buf_cnt_with_data);
            return -UMQ_ERR_ENOMEM;
        }
    }
    if (g_huge_pool_ctx.mode == UMQ_BUF_SPLIT) {
        umq_huge_qbuf_alloc_data_with_split(pool, request_size, actual_buf_count, list, headroom_size);
    } else {
        umq_huge_qbuf_alloc_data_with_combine(pool, request_size, actual_buf_count, list, headroom_size);
    }
    (void)pthread_mutex_unlock(&pool->block_pool.global_mutex);

    return UMQ_SUCCESS;
}

void umq_huge_qbuf_free(umq_buf_list_t *list)
{
    if (!g_huge_pool_ctx.inited) {
        UMQ_VLOG_ERR("huge qbuf pool has not been inited\n");
        return;
    }

    enum HUGE_QBUF_POOL_SIZE_TYPE type;
    uint32_t mid_big = HUGE_QBUF_POOL_IDX_SHIFT + HUGE_QBUF_POOL_NUM_MAX;
    uint32_t big_huge = HUGE_QBUF_POOL_IDX_SHIFT + (HUGE_QBUF_POOL_NUM_MAX << 1);
    uint32_t cur_mempool_id = QBUF_LIST_FIRST(list)->mempool_id;

    if (cur_mempool_id < mid_big) {
        type = HUGE_QBUF_POOL_SIZE_TYPE_MID;
    } else if (cur_mempool_id < big_huge) {
        type = HUGE_QBUF_POOL_SIZE_TYPE_BIG;
    } else {
        type = HUGE_QBUF_POOL_SIZE_TYPE_HUGE;
    }
    huge_pool_t *pool = &g_huge_pool_ctx.pool[type];
    uint32_t remove_cnt = 0;
    umq_buf_t *cur_node = NULL;
    umq_buf_t *last_node = NULL;

    (void)pthread_mutex_lock(&pool->block_pool.global_mutex);
    QBUF_LIST_FOR_EACH(cur_node, list) {
        remove_cnt++;
        last_node = cur_node;
    }

    // switch head node
    umq_buf_t *head = QBUF_LIST_FIRST(&pool->block_pool.head_with_data); // record original head node
    QBUF_LIST_FIRST(&pool->block_pool.head_with_data) = QBUF_LIST_FIRST(list); // switch head node
    QBUF_LIST_NEXT(last_node) = head; // append head node to last node
    pool->block_pool.buf_cnt_with_data += remove_cnt;
    (void)pthread_mutex_unlock(&pool->block_pool.global_mutex);
}

int umq_huge_qbuf_register_seg(
    uint8_t *ctx, register_seg_callback_t register_seg_func, unregister_seg_callback_t unregister_seg_func)
{
    int ret = 0;
    uint32_t failed_idx = 0;
    // register mid mem pool
    huge_pool_t *pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_MID];
    for (uint32_t i = 0; i < pool->pool_idx; i++) {
        ret = register_seg_func(ctx, pool->pool_idx_shift + i, pool->pool_info[i].data_buffer, pool->total_size);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR("register mid mem pool failed, ret: %d, pool idx %u\n", ret, i);
            goto UNREGISTER_MID_SEG;
        }
    }

    // register big mem pool
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_BIG];
    for (uint32_t i = 0; i < pool->pool_idx; i++) {
        ret = register_seg_func(ctx, pool->pool_idx_shift + i, pool->pool_info[i].data_buffer, pool->total_size);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR("register big mem pool failed, ret: %d, pool idx %u\n", ret, i);
            goto UNREGISTER_BIG_SEG;
        }
    }

    // register huge mem pool
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_HUGE];
    for (uint32_t i = 0; i < pool->pool_idx; i++) {
        ret = register_seg_func(ctx, pool->pool_idx_shift + i, pool->pool_info[i].data_buffer, pool->total_size);
        if (ret != UMQ_SUCCESS) {
            failed_idx = i;
            UMQ_VLOG_ERR("register huge mem pool failed, ret: %d, pool idx %u\n", ret, i);
            goto UNREGISTER_HUGE_SEG;
        }
    }
    return UMQ_SUCCESS;

UNREGISTER_HUGE_SEG:
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_HUGE];
    for (uint32_t i = 0; i < failed_idx; i++) {
        (void)unregister_seg_func(ctx, pool->pool_idx_shift + i);
    }
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_BIG];
    failed_idx =  pool->pool_idx;

UNREGISTER_BIG_SEG:
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_BIG];
    for (uint32_t i = 0; i < failed_idx; i++) {
        (void)unregister_seg_func(ctx, pool->pool_idx_shift + i);
    }
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_MID];
    failed_idx =  pool->pool_idx;

UNREGISTER_MID_SEG:
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_MID];
    for (uint32_t i = 0; i < failed_idx; i++) {
        (void)unregister_seg_func(ctx, pool->pool_idx_shift + i);
    }
    return ret;
}

void umq_huge_qbuf_unregister_seg(uint8_t *ctx, unregister_seg_callback_t unregister_seg_func)
{
    int ret = 0;
    // register mid mem pool
    huge_pool_t *pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_MID];
    for (uint32_t i = 0; i < pool->pool_idx; i++) {
        ret = unregister_seg_func(ctx, pool->pool_idx_shift + i);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("unregister mid mem pool failed, ret: %d, pool idx %u\n", ret, i);
        }
    }

    // register big mem pool
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_BIG];
    for (uint32_t i = 0; i < pool->pool_idx; i++) {
        ret = unregister_seg_func(ctx, pool->pool_idx_shift + i);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("unregister big mem pool failed, ret: %d, pool idx %u\n", ret, i);
        }
    }

    // register huge mem pool
    pool = &g_huge_pool_ctx.pool[HUGE_QBUF_POOL_SIZE_TYPE_HUGE];
    for (uint32_t i = 0; i < pool->pool_idx; i++) {
        ret = unregister_seg_func(ctx, pool->pool_idx_shift + i);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("unregister big mem pool failed, ret: %d, pool idx %u\n", ret, i);
        }
    }
}