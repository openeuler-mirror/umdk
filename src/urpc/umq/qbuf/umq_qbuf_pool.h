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

#include <pthread.h>

#include "qbuf_list.h"
#include "umq_errno.h"
#include "umq_dfx_types.h"
#include "umq_types.h"
#include "umq_vlog.h"
#include "urpc_util.h"
#include "util_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_BUF_DEFAULT_TOTAL_SIZE      (1024L * 1024 * 1024)   // 1024M size
#define UMQ_EMPTY_HEADER_COEFFICIENT    16      // if block count is n, there will be n*16 count of empty qbuf header
#define UMQ_QBUF_DEFAULT_MEMPOOL_ID     (0)
#define UMQ_HEADROOM_SIZE_LIMIT         (512)
#define UMQ_QBUF_SIZE_POW_8K            (13)
#define UMQ_QBUF_SIZE_POW_16K           (14)
#define UMQ_QBUF_SIZE_POW_32K           (15)
#define UMQ_QBUF_SIZE_POW_64K           (16)
// middle = small * UMQ_QBUF_SIZE_MULTIPLE_INTERVAL, and big = middle * UMQ_QBUF_SIZE_MULTIPLE_INTERVAL
#define UMQ_QBUF_SIZE_POW_INTERVAL      (2)
#define UMQ_QBUF_SIZE_MULTIPLE_INTERVAL (4)
#define QBUF_ALLOC_STATE_FREE      0            // define qbuf free state
#define QBUF_ALLOC_STATE_ALLOCATED 1            // define qbuf allocated state

typedef struct qbuf_pool_cfg {
    void *buf_addr;             // buffer addr
    uint64_t total_size;        // total buffer size
    uint32_t data_size;         // size of one data slab
    uint32_t headroom_size;     // reserve head room size
    umq_buf_mode_t mode;
} qbuf_pool_cfg_t;

typedef struct qbuf_alloc_param {
    uint32_t actual_buf_count;
    uint32_t headroom_size;
    bool shm;
} qbuf_alloc_param_t;

int umq_buf_size_pow_small_set(umq_buf_block_size_t block_size);

uint8_t umq_buf_size_pow_small(void);

// small qbuf block size: 8K, or 64K size
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
int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);

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

uint64_t umq_buf_to_id_with_header(umq_buf_list_t *header, char *buf, bool shm, bool *with_data);

uint64_t umq_buf_to_id(char *buf, bool shm, bool with_data);

void umq_qbuf_config_get(qbuf_pool_cfg_t *cfg);

typedef struct local_block_pool {
    umq_buf_list_t head_with_data;
    uint64_t buf_cnt_with_data;
    umq_buf_list_t head_without_data;
    uint64_t buf_cnt_without_data;
} local_block_pool_t;

typedef struct global_block_pool {
    util_external_mutex_lock *global_mutex;
    umq_buf_list_t head_with_data;
    uint64_t buf_cnt_with_data;
    umq_buf_list_t head_without_data;
    uint64_t buf_cnt_without_data;
} global_block_pool_t;

static ALWAYS_INLINE uint64_t round_up(uint64_t size, uint64_t align)
{
    return (size + align - 1) & ~(align - 1);
}

/* input align equal to 2^x */
static ALWAYS_INLINE void *floor_to_align(void *ptr, uint64_t align)
{
    return (void *)((uint64_t)(uintptr_t)ptr & ~(align - 1));
}

/* get n elements from input and insert them at the head of output
 * input list elements count must more than n
 */
static ALWAYS_INLINE uint32_t allocate_batch(umq_buf_list_t *input, uint32_t n, umq_buf_list_t *output)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    QBUF_LIST_FOR_EACH(cur_node, input) {
        if (++cnt == n) {
            break;
        }
    }

    umq_buf_t *input_head = QBUF_LIST_FIRST(input);
    umq_buf_t *output_head = QBUF_LIST_FIRST(output);
    // switch head node
    QBUF_LIST_FIRST(input) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_FIRST(output) = input_head;
    // set output
    QBUF_LIST_NEXT(cur_node) = output_head;
    return cnt;
}

// release input to output and return count of elements released
static ALWAYS_INLINE uint32_t release_to_global(umq_buf_list_t *input, umq_buf_list_t *output)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    umq_buf_t *last_node = NULL;
    QBUF_LIST_FOR_EACH(cur_node, input) {
        ++cnt;
        last_node = cur_node;
    }

    umq_buf_t *output_head = QBUF_LIST_FIRST(output);
    // switch head node
    QBUF_LIST_FIRST(output) = QBUF_LIST_FIRST(input);
    // set output
    QBUF_LIST_NEXT(last_node) = output_head;
    return cnt;
}

// release input to output and return count of elements released
static ALWAYS_INLINE uint32_t release_batch(umq_buf_list_t *input, umq_buf_list_t *output,
    bool shm)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    umq_buf_t *last_node = NULL;
    QBUF_LIST_FOR_EACH(cur_node, input) {
        ++cnt;
        last_node = cur_node;

        if (cur_node->alloc_state == QBUF_ALLOC_STATE_FREE) {
            bool with_data = true;
            uint64_t buf_id = umq_buf_to_id_with_header(input, (char *)cur_node, shm, &with_data);
            // shm id and pool name may not right
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf %lu detect in %s_data pool double free\n", buf_id,
                with_data ? "with" : "without");
        }
        cur_node->alloc_state = QBUF_ALLOC_STATE_FREE;
    }

    umq_buf_t *output_head = QBUF_LIST_FIRST(output);
    // switch head node
    QBUF_LIST_FIRST(output) = QBUF_LIST_FIRST(input);
    // set output
    QBUF_LIST_NEXT(last_node) = output_head;
    return cnt;
}

// fetch list nodes from to global to local cache
static ALWAYS_INLINE int32_t fetch_from_global(
        global_block_pool_t *global_pool, local_block_pool_t *cache_pool, bool with_data, uint32_t batch_count)
{
    uint32_t count = 0;
    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;
    uint64_t *local_buf_cnt;
    umq_buf_list_t *local_head;
    (void)util_mutex_lock(global_pool->global_mutex);
    if (with_data) {
        global_buf_cnt = &global_pool->buf_cnt_with_data;
        global_head = &global_pool->head_with_data;

        local_buf_cnt = &cache_pool->buf_cnt_with_data;
        local_head = &cache_pool->head_with_data;
    } else {
        global_buf_cnt = &global_pool->buf_cnt_without_data;
        global_head = &global_pool->head_without_data;

        local_buf_cnt = &cache_pool->buf_cnt_without_data;
        local_head = &cache_pool->head_without_data;
    }

    if (*global_buf_cnt < batch_count) {
        (void)util_mutex_unlock(global_pool->global_mutex);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "%s not enough, rest count: %u\n", with_data ? "buf with data" :
            "buf with no data", *global_buf_cnt);
        return -UMQ_ERR_ENOMEM;
    }

    count = allocate_batch(global_head, batch_count, local_head);
    *global_buf_cnt -= count;
    *local_buf_cnt += count;

    (void)util_mutex_unlock(global_pool->global_mutex);
    return count;
}

// flush list nodes from local cache to global
static ALWAYS_INLINE void return_to_global(
        global_block_pool_t *global_pool, local_block_pool_t *cache, bool with_data, uint32_t threshold)
{
    uint32_t cnt = 0;
    uint32_t remove_cnt = 0;
    umq_buf_t *cur_node = NULL;
    umq_buf_t *switch_node = NULL;
    umq_buf_t *last_node = NULL;
    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;
    uint64_t *local_buf_cnt;
    umq_buf_list_t *local_head;
    (void)util_mutex_lock(global_pool->global_mutex);
    if (with_data) {
        global_buf_cnt = &global_pool->buf_cnt_with_data;
        global_head = &global_pool->head_with_data;

        local_buf_cnt = &cache->buf_cnt_with_data;
        local_head = &cache->head_with_data;
    } else {
        global_buf_cnt = &global_pool->buf_cnt_without_data;
        global_head = &global_pool->head_without_data;

        local_buf_cnt =  &cache->buf_cnt_without_data;
        local_head = &cache->head_without_data;
    }

    QBUF_LIST_FOR_EACH(cur_node, local_head) {
        if (++cnt <= threshold) {
            switch_node = cur_node;
        } else {
            remove_cnt++;
            last_node = cur_node;
        }
    }

    // switch head node
    umq_buf_t *head = QBUF_LIST_FIRST(global_head); // record original head node
    QBUF_LIST_FIRST(global_head) = QBUF_LIST_NEXT(switch_node); // switch head node
    QBUF_LIST_NEXT(last_node) = head; // append head node to last node
    QBUF_LIST_NEXT(switch_node) = NULL; // break chain between switch_node and next of switch_node
    *global_buf_cnt += remove_cnt;
    *local_buf_cnt -= remove_cnt;

    (void)util_mutex_unlock(global_pool->global_mutex);
}

// flush polled buf to global
static ALWAYS_INLINE void return_qbuf_to_global(global_block_pool_t *global_pool, umq_buf_t *buf, bool with_data)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node = NULL;
    umq_buf_t *last_node = NULL;

    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;

    (void)util_mutex_lock(global_pool->global_mutex);
    if (with_data) {
        global_buf_cnt = &global_pool->buf_cnt_with_data;
        global_head = &global_pool->head_with_data;
    } else {
        global_buf_cnt = &global_pool->buf_cnt_without_data;
        global_head = &global_pool->head_without_data;
    }

    cur_node = buf;
    while (cur_node != NULL) {
        last_node = cur_node;
        cur_node = QBUF_LIST_NEXT(cur_node);
        cnt++;
    }
    // switch head node
    umq_buf_t *head = QBUF_LIST_FIRST(global_head); // record original head node
    QBUF_LIST_FIRST(global_head) = buf; // switch head node
    QBUF_LIST_NEXT(last_node) = head; // append head node to last node
    *global_buf_cnt += cnt;

    (void)util_mutex_unlock(global_pool->global_mutex);
}

static ALWAYS_INLINE umq_buf_t *id_to_buf_with_data_split(char *addr, uint64_t id)
{
    return (umq_buf_t *)(addr + id * sizeof(umq_buf_t));
}

static ALWAYS_INLINE uint64_t buf_to_id_with_data_split(char *addr, char *buf)
{
    return (uint64_t)((buf - addr) / sizeof(umq_buf_t));
}

static ALWAYS_INLINE umq_buf_t *id_to_buf_without_data_split(char *addr, uint64_t id)
{
    return (umq_buf_t *)(addr + id * sizeof(umq_buf_t));
}

static ALWAYS_INLINE uint64_t buf_to_id_without_data_split(char *addr, char *buf)
{
    return (uint64_t)((buf - addr) / sizeof(umq_buf_t));
}

static ALWAYS_INLINE umq_buf_t *id_to_buf_combine(char *addr, uint64_t id, uint32_t block_size)
{
    return (umq_buf_t *)(addr + id * block_size);
}

static ALWAYS_INLINE uint64_t buf_to_id_combine(char *addr, char *buf, uint32_t block_size)
{
    return (uint64_t)((buf - addr) / block_size);
}

static ALWAYS_INLINE void umq_qbuf_alloc_nodata(local_block_pool_t *local_pool, uint32_t num,
    umq_buf_list_t *list, bool shm)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_without_data) {
        if (cur_node->alloc_state == QBUF_ALLOC_STATE_ALLOCATED) {
            uint64_t buf_id = umq_buf_to_id((char *)cur_node, shm, false);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf %lu in without_data pool already allocated\n", buf_id);
        }
        cur_node->alloc_state = QBUF_ALLOC_STATE_ALLOCATED;

        if (++cnt == num) {
            break;
        }
    }

    umq_buf_t *input_head = QBUF_LIST_FIRST(&local_pool->head_without_data);
    // switch head node
    QBUF_LIST_FIRST(&local_pool->head_without_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = input_head;
    local_pool->buf_cnt_without_data -= num;
}

static ALWAYS_INLINE void umq_qbuf_alloc_data_with_split(local_block_pool_t *local_pool, uint32_t request_size,
    qbuf_alloc_param_t *param, umq_buf_list_t *list)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t headroom_size_temp = param->headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_capacity = umq_buf_size_small() - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_with_data) {
        cur_node->buf_data = (char *)floor_to_align(cur_node->buf_data, umq_buf_size_small()) + headroom_size_temp;
        cur_node->buf_size = umq_buf_size_small() + (uint32_t)sizeof(umq_buf_t);
        cur_node->headroom_size = headroom_size_temp;
        cur_node->total_data_size = total_data_size;
        cur_node->first_fragment = first_fragment;
        cur_node->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        if (cur_node->alloc_state == QBUF_ALLOC_STATE_ALLOCATED) {
            uint64_t buf_id = umq_buf_to_id((char *)cur_node, param->shm, true);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf %lu in with_data pool already allocated\n", buf_id);
        }
        cur_node->alloc_state = QBUF_ALLOC_STATE_ALLOCATED;

        remaining_size -= cur_node->data_size;
        if (remaining_size == 0) {
            headroom_size_temp = param->headroom_size;
            total_data_size = request_size;
            remaining_size = request_size;
            first_fragment = true;
            max_data_capacity = umq_buf_size_small() - param->headroom_size;
        } else {
            headroom_size_temp = 0;
            total_data_size = 0;
            first_fragment = false;
            max_data_capacity = umq_buf_size_small();
        }
        if (++cnt == param->actual_buf_count) {
            break;
        }
    }

    umq_buf_t *head = QBUF_LIST_FIRST(&local_pool->head_with_data);
    // switch head node
    QBUF_LIST_FIRST(&local_pool->head_with_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = head;
    local_pool->buf_cnt_with_data -= param->actual_buf_count;
}

static ALWAYS_INLINE void umq_qbuf_alloc_data_with_combine(local_block_pool_t *local_pool, uint32_t request_size,
    qbuf_alloc_param_t *param, umq_buf_list_t *list)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t headroom_size_temp = param->headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_size = umq_buf_size_small() - sizeof(umq_buf_t);
    uint32_t max_data_capacity = max_data_size - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_with_data) {
        cur_node->buf_data = cur_node->data + headroom_size_temp;
        cur_node->buf_size = umq_buf_size_small();
        cur_node->headroom_size = headroom_size_temp;
        cur_node->total_data_size = total_data_size;
        cur_node->first_fragment = first_fragment;
        cur_node->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        if (cur_node->alloc_state == QBUF_ALLOC_STATE_ALLOCATED) {
            uint64_t buf_id = umq_buf_to_id((char *)cur_node, param->shm, true);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf %lu in with_data pool already allocated\n", buf_id);
        }
        cur_node->alloc_state = QBUF_ALLOC_STATE_ALLOCATED;

        remaining_size -= cur_node->data_size;
        if (remaining_size == 0) {
            headroom_size_temp = param->headroom_size;
            total_data_size = request_size;
            remaining_size = request_size;
            max_data_capacity = max_data_size - param->headroom_size;
            first_fragment = true;
        } else {
            headroom_size_temp = 0;
            total_data_size = 0;
            first_fragment = false;
            max_data_capacity = max_data_size;
        }
        if (++cnt == param->actual_buf_count) {
            break;
        }
    }

    umq_buf_t *head = QBUF_LIST_FIRST(&local_pool->head_with_data);
    // switch head node
    QBUF_LIST_FIRST(&local_pool->head_with_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = head;
    local_pool->buf_cnt_with_data -= param->actual_buf_count;
}

static ALWAYS_INLINE int headroom_reset_with_split(umq_buf_t *qbuf, uint16_t headroom_size, uint32_t block_size)
{
    umq_buf_t *data = qbuf;
    uint32_t total_data_size = qbuf->total_data_size;
    uint32_t remaining_size = total_data_size;
    uint32_t max_data_capacity;
    uint32_t after_reset_buf_count = ((total_data_size + headroom_size + block_size - 1) / block_size);
    uint32_t before_reset_buf_count = ((total_data_size + data->headroom_size + block_size - 1) / block_size);

    if (after_reset_buf_count > before_reset_buf_count) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "headroom_size: %u invalid, after_reset: %u, before_reset: %u\n",
            headroom_size, after_reset_buf_count, before_reset_buf_count);
        return -UMQ_ERR_EINVAL;
    }

    int32_t diff = (int32_t)headroom_size - (int32_t)data->headroom_size;

    while (data != NULL) {
        if (data->first_fragment) {
            data->buf_data = data->buf_data + diff;
            data->headroom_size = headroom_size;
            remaining_size = data->total_data_size;
            max_data_capacity = block_size - headroom_size;
        } else {
            max_data_capacity = block_size;
        }
        data->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        remaining_size -= data->data_size;
        data = data->qbuf_next;
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE int headroom_reset_with_combine(umq_buf_t *qbuf, uint16_t headroom_size, uint32_t block_size)
{
    umq_buf_t *data = qbuf;
    uint32_t total_data_size = qbuf->total_data_size;
    uint32_t align_size = block_size - sizeof(umq_buf_t);
    uint32_t after_reset_buf_count =  ((total_data_size + headroom_size + align_size - 1) / align_size);
    uint32_t before_reset_buf_count = ((total_data_size + data->headroom_size + align_size - 1) / align_size);

    if (after_reset_buf_count > before_reset_buf_count) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "headroom_size: %u invalid, after_reset: %u, before_reset: %u\n",
            headroom_size, after_reset_buf_count, before_reset_buf_count);
        return -UMQ_ERR_EINVAL;
    }

    uint32_t remaining_size = qbuf->total_data_size;
    uint32_t max_data_capacity = align_size - headroom_size;
    int32_t diff = (int32_t)headroom_size - (int32_t)data->headroom_size;

    while (data != NULL) {
        if (data->first_fragment) {
            data->buf_data = data->buf_data + diff;
            data->headroom_size = headroom_size;
            remaining_size = data->total_data_size;
        } else {
            max_data_capacity = align_size;
        }
        data->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        remaining_size -= data->data_size;
        data = data->qbuf_next;
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE int headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size, umq_buf_mode_t mode,
        uint32_t block_size)
{
    if (mode == UMQ_BUF_SPLIT) {
        return headroom_reset_with_split(qbuf, headroom_size, block_size);
    }
    return headroom_reset_with_combine(qbuf, headroom_size, block_size);
}

static ALWAYS_INLINE int umq_qbuf_block_pool_init(global_block_pool_t *block_pool)
{
    QBUF_LIST_INIT(&block_pool->head_with_data);
    QBUF_LIST_INIT(&block_pool->head_without_data);
    block_pool->buf_cnt_with_data = 0;
    block_pool->buf_cnt_without_data = 0;
    block_pool->global_mutex = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (block_pool->global_mutex == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq qbuf block pool global mutex create failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE void umq_qbuf_block_pool_uninit(global_block_pool_t *block_pool)
{
    (void)util_mutex_lock_destroy(block_pool->global_mutex);
    block_pool->global_mutex = NULL;
}

uint32_t umq_qbuf_headroom_get(void);
umq_buf_mode_t umq_qbuf_mode_get(void);

typedef int (*register_seg_callback_t)(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size);
typedef int (*unregister_seg_callback_t)(uint8_t *ctx, uint16_t mempool_id);

int umq_qbuf_register_seg(uint8_t *ctx, register_seg_callback_t register_seg_func);
int umq_qbuf_unregister_seg(uint8_t *ctx, unregister_seg_callback_t unregister_seg_func);

#ifdef __cplusplus
}
#endif

#endif
