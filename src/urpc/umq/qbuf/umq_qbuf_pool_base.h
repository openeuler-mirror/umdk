/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: define common qbuf pool function
 * Create: 2026-6-12
 * Note:
 * History: 2026-6-12
 */

#ifndef UMQ_QBUF_POOL_BASE_H
#define UMQ_QBUF_POOL_BASE_H

#include <pthread.h>
#include <string.h>

#include "qbuf_list.h"
#include "umq_errno.h"
#include "umq_dfx_types.h"
#include "umq_types.h"
#include "umq_vlog.h"
#include "urpc_util.h"
#include "urpc_list.h"
#include "urpc_thread_closure.h"
#include "util_lock.h"
#include "urpc_id_generator.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_EMPTY_HEADER_COEFFICIENT    16      // if block count is n, there will be n*16 count of empty qbuf header
#define UMQ_QBUF_DEFAULT_MEMPOOL_ID     (0)
#define UMQ_HEADROOM_SIZE_LIMIT         (512)
#define UMQ_QBUF_SIZE_POW_4K            (12)
#define UMQ_QBUF_SIZE_POW_8K            (13)
#define UMQ_QBUF_SIZE_POW_16K           (14)
#define UMQ_QBUF_SIZE_POW_32K           (15)
#define UMQ_QBUF_SIZE_POW_64K           (16)
// middle = small * UMQ_QBUF_SIZE_MULTIPLE_INTERVAL, and big = middle * UMQ_QBUF_SIZE_MULTIPLE_INTERVAL
#define UMQ_QBUF_SIZE_MULTIPLE_INTERVAL (4)
#define QBUF_ALLOC_STATE_FREE      0            // define qbuf free state
#define QBUF_ALLOC_STATE_ALLOCATED 1            // define qbuf allocated state
#define UMQ_EXPANSION_POOL_CNT_MAX (256)        // expansion pool id 257-512
#define UMQ_TINY_QBUF_MEMPOOL_ID (1022U)
#define QBUF_POOL_MEMPOOL_ID_MAX (1023)         // escape mempool id: 1023, other memopool id must not exceed 1023

#define QBUF_POOL_TLS_MAX (2048) // max count of thread local buffer storage
#define QBUF_POOL_BATCH_CNT (64) // batch size when fetch from global or return to global
#define QBUF_POOL_SHRINK_THRESHOLD (64) // self-driven shrink threshold: N/4 >= this value (N >= 256)
#define QBUF_POOL_SELF_SHRINK_RATIO (4) // adaptive shrink ratio(1/4)
#define QBUF_POOL_EXPAND_MAX_RATIO (8)
#define QBUF_POOL_DEFAULT_EXPANSION_COUNT 8192
#define QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE (2ULL * 1024 * 1024 * 1024)
#define QBUF_POOL_MEM_SIZE_MAX (6ULL * 1024 * 1024 * 1024)
#define QBUF_MEMALIGN_SIZE (2ULL * 1024 * 1024)

typedef struct mempool_segment_ops {
    int (*register_seg_callback)(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size);
    void (*unregister_seg_callback)(uint8_t *ctx, uint16_t mempool_id);
} mempool_segment_ops_t;

typedef struct qbuf_pool_cfg {
    void *buf_addr;             // buffer addr
    uint64_t total_size;        // total buffer size
    uint32_t data_size;         // size of one data slab
    uint32_t headroom_size;     // reserve head room size
    umq_buf_mode_t mode;
    uint64_t umq_buf_pool_max_size; // default 2G

    // gloab expansion pool
    uint32_t expansion_pool_id_min;
    uint32_t expansion_pool_cnt_max;
    uint32_t expansion_block_count;  // number of blocks per expansion
    mempool_segment_ops_t seg_ops;

    // thread local qbuf pool
    uint64_t tls_qbuf_pool_depth;
    uint64_t tls_expand_qbuf_pool_depth;

    bool disable_scale_cap; // expansion and shrink switch
    // escape
    bool disable_malloc_escape;
} qbuf_pool_cfg_t;

typedef struct qbuf_alloc_param {
    uint32_t request_size;
    uint32_t num;
    umq_buf_list_t *list;
    uint32_t actual_buf_count;
    uint32_t headroom_size;
    bool shm;
} qbuf_alloc_param_t;

uint64_t umq_buf_to_id_with_header(umq_buf_list_t *header, char *buf, bool shm, bool *with_data);

uint64_t umq_buf_to_id(char *buf, bool shm, bool with_data);

typedef struct local_block_pool {
    umq_buf_list_t head_with_data;
    uint64_t buf_cnt_with_data;
    uint64_t capacity_with_data;

    umq_buf_list_t head_without_data;
    uint64_t buf_cnt_without_data;
    uint64_t capacity_without_data;
} local_block_pool_t;

typedef int (*qbuf_base_fetch_fn)(uint32_t needed, local_block_pool_t *local_pool, bool with_data);
typedef void (*qbuf_base_self_shrink_fn)(bool with_data);

typedef struct local_qbuf_pool_stats {
    uint64_t tid;
    uint64_t tls_fetch_cnt_with_data;
    uint64_t tls_fetch_buf_cnt_with_data;
    uint64_t tls_fetch_cnt_without_data;
    uint64_t tls_fetch_buf_cnt_without_data;
    uint64_t tls_return_cnt_with_data;
    uint64_t tls_return_buf_cnt_with_data;
    uint64_t tls_return_cnt_without_data;
    uint64_t tls_return_buf_cnt_without_data;
    uint64_t alloc_cnt_with_data;
    uint64_t alloc_cnt_without_data;
    uint64_t free_cnt_with_data;
    uint64_t free_cnt_without_data;
} local_qbuf_pool_stats_t;

typedef struct thread_local_qbuf_pool {
    urpc_list_t tls_node;
    bool inited;
    local_block_pool_t block_pool;
    local_qbuf_pool_stats_t stats;
} thread_local_qbuf_pool_t;

typedef struct global_block_pool {
    pthread_spinlock_t global_mutex;
    umq_buf_list_t head_with_data;
    uint64_t buf_cnt_with_data;
    umq_buf_list_t head_without_data;
    uint64_t buf_cnt_without_data;
    bool disable_scale_cap; // expansion and shrink switch
} global_block_pool_t;

typedef struct local_qbuf_pool_ctrl {
    uint64_t tls_qbuf_pool_depth;
    uint64_t tls_expand_qbuf_pool_depth;
    uint64_t default_tls_qbuf_pool_depth;
    uint32_t batch_count;
    bool enable_tls_expand_qbuf_pool;
    urpc_list_t tls_register_head;
    pthread_spinlock_t tls_stats_lock;
    urpc_thread_closure_type_t type;
    void (*closure)(uint64_t id);
} local_qbuf_pool_ctrl_t;

typedef struct qbuf_pool_base {
    bool inited;
    void *data_buffer;          // 数据区起始地址，COMBINE模式为所有的数据起始位置，SPLIT模式为所有的数据起始位置+头部区大小，需要8K对齐
    void *header_buffer;        // 头部区起始地址，COMBINE模式为NULL，SPLIT模式为所有数据的起始位置
    uint64_t total_size;        // 内存池管理的内存总大小

    uint32_t block_size;        // headroom size + data size以8K为大小向上取整，如果是combine模式还包括umq_qbuf_t结构体大小
    uint32_t headroom_size;     // 预留的头部空间大小
    uint32_t data_size;

    uint64_t total_block_num;
    umq_buf_mode_t mode;

    global_block_pool_t block_pool;
    local_qbuf_pool_ctrl_t tls_pools;
    bool support_without_data;
    qbuf_base_fetch_fn fetch_fn;
    qbuf_base_self_shrink_fn self_shrink_fn;
    mempool_segment_ops_t seg_ops;
    uint16_t mempool_id;
} qbuf_pool_base_t;

static ALWAYS_INLINE uint64_t umq_qbuf_pool_expand_max(uint64_t total_size)
{
    return ((total_size) - (total_size) / QBUF_POOL_EXPAND_MAX_RATIO);
}

static ALWAYS_INLINE local_block_pool_t *get_thread_local_cache(
    thread_local_qbuf_pool_t *thread_cache, local_qbuf_pool_ctrl_t *pools)
{
    if (!thread_cache->inited) {
        thread_cache->block_pool.capacity_with_data = 0;
        thread_cache->block_pool.capacity_without_data = 0;
        QBUF_LIST_INIT(&thread_cache->block_pool.head_with_data);
        thread_cache->block_pool.buf_cnt_with_data = 0;
        QBUF_LIST_INIT(&thread_cache->block_pool.head_without_data);
        thread_cache->block_pool.buf_cnt_without_data = 0;
        (void)memset(&thread_cache->stats, 0, sizeof(thread_cache->stats));
        thread_cache->stats.tid = (uint64_t)pthread_self();
        thread_cache->inited = true;
        urpc_thread_closure_register(pools->type, 0, pools->closure);
        // register TLS stats to global linked list
        (void)pthread_spin_lock(&pools->tls_stats_lock);
        urpc_list_push_back(&pools->tls_register_head, &thread_cache->tls_node);
        (void)pthread_spin_unlock(&pools->tls_stats_lock);
    }

    return &thread_cache->block_pool;
}

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

static ALWAYS_INLINE uint32_t qbuf_tls_round_batch(uint32_t needed, uint32_t batch_count)
{
    return (needed + batch_count - 1) / batch_count * batch_count;
}

// fetch list nodes from to global to local cache
int expand_global_pool(bool with_data);
void async_expand_global_pool(bool with_data, uint64_t g_buf_cnt, bool disable_scale_cap);
uint32_t fetch_from_expansion_pools(bool with_data, uint32_t need, umq_buf_list_t *local_head, uint64_t *local_buf_cnt);
uint64_t return_list_to_pools(umq_buf_t *local_head,
    umq_buf_list_t *global_head, uint64_t *global_buf_cnt, bool with_data);

typedef struct umq_qbuf_fetch_req_info {
    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;
    uint64_t *local_buf_cnt;
    umq_buf_list_t *local_head;
} umq_qbuf_pool_req_info_t;

static ALWAYS_INLINE void get_pool_req_info(
    local_block_pool_t *local_pool, global_block_pool_t *global_pool, umq_qbuf_pool_req_info_t *req, bool with_data)
{
    if (with_data) {
        req->global_buf_cnt = &global_pool->buf_cnt_with_data;
        req->global_head = &global_pool->head_with_data;

        req->local_buf_cnt = &local_pool->buf_cnt_with_data;
        req->local_head = &local_pool->head_with_data;
    } else {
        req->global_buf_cnt = &global_pool->buf_cnt_without_data;
        req->global_head = &global_pool->head_without_data;

        req->local_buf_cnt = &local_pool->buf_cnt_without_data;
        req->local_head = &local_pool->head_without_data;
    }
}

static ALWAYS_INLINE void local_pool_rollback(umq_buf_t *buf_head_old, uint64_t buf_cnt_old,
    local_block_pool_t *local_pool, global_block_pool_t *global_pool, bool with_data)
{
    umq_qbuf_pool_req_info_t info;
    get_pool_req_info(local_pool, global_pool, &info, with_data);

    if (*info.local_buf_cnt <= buf_cnt_old) {
        return;
    }

    umq_buf_t *head = QBUF_LIST_FIRST(info.local_head);
    QBUF_LIST_FIRST(info.local_head) = buf_head_old;
    uint64_t alloc_cnt = ((*info.local_buf_cnt) - buf_cnt_old);
    umq_buf_t *tail = head;
    for (uint64_t i = 0; i < alloc_cnt - 1; i++) {
        tail = QBUF_LIST_NEXT(tail);
    }
    tail->qbuf_next = NULL;
    (void)pthread_spin_lock(&global_pool->global_mutex);
    *info.local_buf_cnt -= return_list_to_pools(head, info.global_head, info.global_buf_cnt, with_data);
    (void)pthread_spin_unlock(&global_pool->global_mutex);
}

static ALWAYS_INLINE int32_t fetch_from_global(
        global_block_pool_t *global_pool, local_block_pool_t *cache_pool, bool with_data, uint32_t batch_count)
{
    uint32_t count = 0;
    umq_buf_t *local_head_before;
    uint64_t local_cnt_before;
    umq_qbuf_pool_req_info_t info;

    (void)pthread_spin_lock(&global_pool->global_mutex);
    get_pool_req_info(cache_pool, global_pool, &info, with_data);

    local_head_before = QBUF_LIST_FIRST(info.local_head);
    local_cnt_before = *info.local_buf_cnt;

    if (*info.global_buf_cnt >= batch_count) {
        count = allocate_batch(info.global_head, batch_count, info.local_head);
        *info.global_buf_cnt -= count;
        *info.local_buf_cnt += count;
        (void)pthread_spin_unlock(&global_pool->global_mutex);
        async_expand_global_pool(with_data, *info.global_buf_cnt, global_pool->disable_scale_cap);
        return count;
    }

    if (global_pool->disable_scale_cap) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "%s not enough suggestion: increase total_size\n",
            with_data ? "buf with data" : "buf with no data");
        (void)pthread_spin_unlock(&global_pool->global_mutex);
        return -UMQ_ERR_ENOMEM;
    }

    if (*info.global_buf_cnt > 0) {
        uint32_t take = allocate_batch(info.global_head, (uint32_t)*info.global_buf_cnt, info.local_head);
        *info.global_buf_cnt -= take;
        *info.local_buf_cnt += take;
        count += take;
    }
    (void)pthread_spin_unlock(&global_pool->global_mutex);

    count += fetch_from_expansion_pools(with_data, batch_count - count, info.local_head, info.local_buf_cnt);
    while (count < batch_count) {
        int ret = expand_global_pool(with_data);
        if (ret != UMQ_SUCCESS) {
            goto ROLLBACK;
        }

        count += fetch_from_expansion_pools(with_data, batch_count - count, info.local_head, info.local_buf_cnt);
    }
    async_expand_global_pool(with_data, *info.global_buf_cnt, global_pool->disable_scale_cap);
    return count;

ROLLBACK:
    local_pool_rollback(local_head_before, local_cnt_before, cache_pool, global_pool, with_data);
    return -UMQ_ERR_ENOMEM;
}

// flush list from local to global, threshold means the local pool size that needs to be returned
static ALWAYS_INLINE void return_to_global(global_block_pool_t *global_pool, local_block_pool_t *cache,
    local_qbuf_pool_stats_t *stats, bool with_data, uint32_t threshold)
{
    umq_qbuf_pool_req_info_t info;
    uint64_t return_buf_cnt;
    uint64_t *tls_return_buf_cnt;
    (void)pthread_spin_lock(&global_pool->global_mutex);
    get_pool_req_info(cache, global_pool, &info, with_data);
    if (with_data) {
        tls_return_buf_cnt = &stats->tls_return_buf_cnt_with_data;
    } else {
        tls_return_buf_cnt = &stats->tls_return_buf_cnt_without_data;
    }

    if (threshold == 0) {
        umq_buf_t *head = QBUF_LIST_FIRST(info.local_head);
        QBUF_LIST_FIRST(info.local_head) = NULL;
        return_buf_cnt = return_list_to_pools(head, info.global_head, info.global_buf_cnt, with_data);
        *info.local_buf_cnt -= return_buf_cnt;
        *tls_return_buf_cnt += return_buf_cnt;
        (void)pthread_spin_unlock(&global_pool->global_mutex);
        return;
    }

    umq_buf_t *switch_node = NULL;
    uint32_t cnt = 0;
    QBUF_LIST_FOR_EACH(switch_node, info.local_head) {
        if (++cnt == threshold) {
            break;
        }
    }

    if (switch_node != NULL && QBUF_LIST_NEXT(switch_node) != NULL) {
        umq_buf_t *head = QBUF_LIST_NEXT(switch_node);
        QBUF_LIST_NEXT(switch_node) = NULL;
        return_buf_cnt = return_list_to_pools(head, info.global_head, info.global_buf_cnt, with_data);
        *info.local_buf_cnt -= return_buf_cnt;
        *tls_return_buf_cnt += return_buf_cnt;
    }

    (void)pthread_spin_unlock(&global_pool->global_mutex);
}

static ALWAYS_INLINE void release_thread_cache_impl(
    thread_local_qbuf_pool_t *thread_cache, local_qbuf_pool_ctrl_t *tls_pools, global_block_pool_t *global_pool)
{
    if (!thread_cache->inited) {
        return;
    }

    (void)pthread_spin_lock(&tls_pools->tls_stats_lock);
    urpc_list_remove(&thread_cache->tls_node);
    (void)pthread_spin_unlock(&tls_pools->tls_stats_lock);

    local_block_pool_t *local_pool = get_thread_local_cache(thread_cache, tls_pools);
    uint64_t return_buf_cnt;
    (void)pthread_spin_lock(&global_pool->global_mutex);
    if (local_pool->head_with_data.first != NULL) {
        return_buf_cnt = return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_with_data),
            &global_pool->head_with_data, &global_pool->buf_cnt_with_data, true);
        local_pool->buf_cnt_with_data -= return_buf_cnt;
        thread_cache->stats.tls_return_buf_cnt_with_data += return_buf_cnt;
    }

    if (local_pool->head_without_data.first != NULL) {
        return_buf_cnt = return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_without_data),
            &global_pool->head_without_data, &global_pool->buf_cnt_without_data, false);
        local_pool->buf_cnt_without_data -= return_buf_cnt;
        thread_cache->stats.tls_return_buf_cnt_without_data += return_buf_cnt;
    }
    (void)pthread_spin_unlock(&global_pool->global_mutex);

    thread_cache->inited = false;
}

static ALWAYS_INLINE uint64_t qbuf_tls_capacity_grow(uint64_t local_cap, volatile uint64_t *total_cap,
    uint64_t total_cap_limit, uint64_t local_cap_limit, uint64_t requested_grow)
{
    uint64_t grow = requested_grow;
    if (local_cap + grow > local_cap_limit) {
        grow = local_cap >= local_cap_limit ? 0 : local_cap_limit - local_cap;
    }
    uint64_t current_total_cap = __atomic_load_n(total_cap, __ATOMIC_ACQ_REL);
    if (current_total_cap + grow > total_cap_limit) {
        grow = current_total_cap >= total_cap_limit ? 0 : total_cap_limit - current_total_cap;
    }
    return grow;
}

static ALWAYS_INLINE void qbuf_tls_capacity_add(uint64_t *local_cap, volatile uint64_t *total_cap, uint64_t grow)
{
    if (grow == 0) {
        return;
    }
    *local_cap += grow;
    __atomic_fetch_add(total_cap, grow, __ATOMIC_ACQ_REL);
}

static ALWAYS_INLINE void qbuf_tls_capacity_sub(uint64_t *local_cap, volatile uint64_t *total_cap, uint64_t shrink)
{
    if (shrink == 0) {
        return;
    }
    if (shrink > *local_cap) {
        shrink = *local_cap;
    }
    *local_cap -= shrink;
    __atomic_fetch_sub(total_cap, shrink, __ATOMIC_ACQ_REL);
}

static ALWAYS_INLINE void qbuf_tls_capacity_self_shrink(global_block_pool_t *global_pool,
    thread_local_qbuf_pool_t *thread_cache, bool with_data, volatile uint64_t *total_cap, uint32_t shrink_threshold)
{
    local_block_pool_t *local_pool = &thread_cache->block_pool;
    local_qbuf_pool_stats_t *stats = &thread_cache->stats;
    uint64_t remaining = with_data ? local_pool->buf_cnt_with_data : local_pool->buf_cnt_without_data;
    uint64_t *cap_ptr = with_data ? &local_pool->capacity_with_data : &local_pool->capacity_without_data;
    uint64_t shrink = remaining / QBUF_POOL_SELF_SHRINK_RATIO;
    if (shrink < shrink_threshold || *cap_ptr == 0) {
        return;
    }

    qbuf_tls_capacity_sub(cap_ptr, total_cap, shrink);
    if (*cap_ptr >= remaining) {
        return;
    }

    uint32_t threshold = (uint32_t)*cap_ptr;
    return_to_global(global_pool, local_pool, stats, with_data, threshold);
    if (with_data) {
        stats->tls_return_cnt_with_data++;
    } else {
        stats->tls_return_cnt_without_data++;
    }
}

// flush polled buf to global
static ALWAYS_INLINE void return_qbuf_to_global(global_block_pool_t *global_pool, umq_buf_t *buf, bool with_data)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node = NULL;
    umq_buf_t *last_node = NULL;

    uint64_t *global_buf_cnt;
    umq_buf_list_t *global_head;

    (void)pthread_spin_lock(&global_pool->global_mutex);
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

    (void)pthread_spin_unlock(&global_pool->global_mutex);
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

static ALWAYS_INLINE void buf_init_with_mode(char *data_buffer, char *header_buffer, uint64_t blk_num,
    uint32_t block_size, uint16_t mempool_id, bool with_data, umq_buf_mode_t mode, umq_buf_list_t *head)
{
    for (uint64_t i = 0; i < blk_num; i++) {
        umq_buf_t *buf = NULL;
        if (mode == UMQ_BUF_SPLIT) {
            buf = id_to_buf_with_data_split(header_buffer, i);
            buf->buf_size = block_size + (uint32_t)sizeof(umq_buf_t);
            buf->data_size = block_size;
            buf->buf_data = data_buffer + i * block_size;
        } else {
            buf = id_to_buf_combine(data_buffer, i, block_size);
            buf->buf_size = block_size;
            buf->data_size = block_size - (uint32_t)sizeof(umq_buf_t);
            buf->buf_data = (char *)buf + sizeof(umq_buf_t);
        }
        buf->umqh = UMQ_INVALID_HANDLE;
        buf->total_data_size = buf->data_size;
        buf->headroom_size = 0;
        buf->mempool_without_data = !with_data;
        buf->mempool_id = mempool_id;
        buf->alloc_state = QBUF_ALLOC_STATE_FREE;
        (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
        QBUF_LIST_INSERT_HEAD(head, buf);
    }
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
    qbuf_alloc_param_t *param, umq_buf_list_t *list, uint32_t block_size)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t headroom_size_temp = param->headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_capacity = block_size - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_with_data) {
        cur_node->buf_data = (char *)floor_to_align(cur_node->buf_data, block_size) + headroom_size_temp;
        cur_node->buf_size = block_size + (uint32_t)sizeof(umq_buf_t);
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
            max_data_capacity = block_size - param->headroom_size;
        } else {
            headroom_size_temp = 0;
            total_data_size = 0;
            first_fragment = false;
            max_data_capacity = block_size;
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
    qbuf_alloc_param_t *param, umq_buf_list_t *list, uint32_t block_size)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t headroom_size_temp = param->headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_size = block_size - sizeof(umq_buf_t);
    uint32_t max_data_capacity = max_data_size - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_with_data) {
        cur_node->buf_data = cur_node->data + headroom_size_temp;
        cur_node->buf_size = block_size;
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

static ALWAYS_INLINE uint32_t umq_qbuf_base_actual_buf_count(
    const qbuf_pool_base_t *base, uint32_t request_size, uint32_t num, uint32_t headroom_size)
{
    if (base->mode == UMQ_BUF_SPLIT) {
        return num * ((request_size + headroom_size + base->block_size - 1) / base->block_size);
    }

    uint32_t align_size = base->block_size - sizeof(umq_buf_t);
    return num * ((request_size + headroom_size + align_size - 1) / align_size);
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
    (void)pthread_spin_init(&block_pool->global_mutex, PTHREAD_PROCESS_PRIVATE);
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE void umq_qbuf_block_pool_uninit(global_block_pool_t *block_pool)
{
    (void)pthread_spin_destroy(&block_pool->global_mutex);
}

int qbuf_pool_base_init(qbuf_pool_base_t *base, const qbuf_pool_cfg_t *cfg, uint32_t split_extra_header_count);
void *umq_qbuf_base_io_buf_malloc(uint64_t total_len, uint64_t min_size);
void umq_qbuf_base_uninit(qbuf_pool_base_t *base, void (*release_thread_cache)(uint64_t));

int umq_qbuf_base_alloc(qbuf_pool_base_t *base, thread_local_qbuf_pool_t *thread_cache,
    umq_alloc_option_t *option, qbuf_alloc_param_t *param);
void umq_qbuf_base_free(qbuf_pool_base_t *base, thread_local_qbuf_pool_t *thread_cache, umq_buf_list_t *list,
    bool shm);
umq_buf_t *umq_qbuf_base_data_to_head(qbuf_pool_base_t *base, void *data);

int umq_qbuf_pool_base_info_get(qbuf_pool_base_t *base, umq_qbuf_pool_stats_t *qbuf_pool_stats,
    bool reset_local_stats, umq_qbuf_pool_type_t type);

#ifdef __cplusplus
}
#endif

#endif
