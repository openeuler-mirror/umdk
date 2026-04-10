/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize qbuf pool function
 * Create: 2025-7-26
 * Note:
 * History: 2025-7-26
 */

#include <malloc.h>
#include <unistd.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "urpc_thread_closure.h"
#include "urpc_util.h"
#include "urpc_list.h"
#include "umq_qbuf_pool.h"

#define QBUF_POOL_BATCH_CNT (64) // batch size when fetch from global or return to global
#define QBUF_POOL_TLS_QBUF_POOL_DEPTH (12 * 1024) // all thread-local pool capacity sum budget
#define QBUF_POOL_EXPAND_MAX(__total_size) ((__total_size) - (__total_size) / 8) // single thread capacity cap
#define QBUF_POOL_SHRINK_THRESHOLD (64) // self-driven shrink threshold: N/4 >= this value (N >= 256)
#define QBUF_POOL_SELF_SHRINK_RATIO (4) // adaptive shrink ratio(1/4)
#define QBUF_POOL_SHRINK_IDLE_S (1) // idle threshold for global shrink trigger (1s)
#define QBUF_POOL_SHRINK_CLEAR_THRESHOLD (64) // clear to zero if capacity below this

#define QBUF_POOL_EXPANSION_RATIO 10 // percentage that triggers expansion

#define QBUF_POOL_DEFAULT_EXPANSION_COUNT 8192
#define QBUF_POOL_SLOT_ARRAY_INIT_CAP 4
#define QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE (2ULL * 1024 * 1024 * 1024)
#define QBUF_POOL_EXPANSION_MEM_SIZE_MAX (6ULL * 1024 * 1024 * 1024)
#define QBUF_POOL_CHECK_ASYNC_PERIOD_US (1000)
#define QBUF_POOL_WITH_ASYNC_EXIT_TIMEOUT_S (60)

typedef struct qbuf_expansion_pool_slot {
    uint32_t slot_id;
    void *buffer;
    void *header_buffer;
    uint64_t total_buf_size;

    uint64_t total_block_cnt;
    uint64_t free_block_cnt;
    umq_buf_list_t free_block_list;
} qbuf_expansion_pool_slot_t;

typedef struct local_qbuf_pool {
    bool inited;
    local_block_pool_t block_pool;
} local_qbuf_pool_t;

typedef struct async_shrink_pool_param {
    urpc_list_t node;
    uint32_t slot_id;
    bool with_data;
} async_shrink_pool_param_t;

typedef struct async_shrink_pool_param_list {
    urpc_list_t head;
    pthread_spinlock_t lock;
} async_shrink_pool_task_list_t;

typedef struct expansion_qbuf_pool {
    bool inited;
    pthread_spinlock_t expansion_pool_lock;
    volatile uint32_t is_async_expanding;
    volatile uint32_t is_async_shrinking;
    uint64_t trigger_expand_block_num;
    uint32_t expansion_block_count; // number of blocks per expansion
    uint32_t expansion_pool_id_min; // minimum id for dynamically expanding qbuf pool
    uint32_t expansion_pool_cnt_max; // maximum number for dynamic expansion
    uint32_t expansion_count; // number of expansions already performed
    qbuf_expansion_pool_slot_t **exp_slot_list; // expand qbuf pool list, dynamically increase
    urpc_id_generator_t dynamic_id_gen; // dynamic expansion qbuf pool id allocator
    uint64_t exp_total_block_num;
    async_shrink_pool_task_list_t shrink_task_list;
} qbuf_expansion_pool_t;

typedef struct local_qbuf_pool_cfg {
    uint64_t tls_qbuf_pool_depth;
    uint64_t tls_expand_qbuf_pool_depth;
} local_qbuf_pool_cfg_t;

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

    uint64_t expansion_mem_size_max;
    volatile uint64_t exp_total_mem_pool_size;
    mempool_segment_ops_t seg_ops;
    qbuf_expansion_pool_t exp_pool_with_date;
    qbuf_expansion_pool_t exp_pool_without_date;
    local_qbuf_pool_cfg_t local_pool_cfg;
} qbuf_pool_t;

static qbuf_pool_t g_qbuf_pool = {0};
static __thread local_qbuf_pool_t g_thread_cache = {0};
static uint8_t g_umq_qbuf_size_pow_samll = UMQ_QBUF_SIZE_POW_8K;

// --- global registry and capacity counters for elastic scaling ---
static volatile uint64_t g_total_local_cap_with_data = 0;     // sum of all threads' capacity_with_data
static volatile uint64_t g_total_local_cap_without_data = 0;  // sum of all threads' capacity_without_data

static void *g_buffer_addr = NULL;
static uint64_t g_total_len = 0;

static void free_expansion_pool_slot(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    urpc_id_generator_free(&exp_pool->dynamic_id_gen, slot->slot_id);

    if (slot->buffer != NULL) {
        free(slot->buffer);
    }
    free(slot);
}

static int alloc_expansion_pool_slot(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t **slot)
{
    uint32_t id = 0;
    int ret = urpc_id_generator_alloc(&exp_pool->dynamic_id_gen, 0, &id);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to alloc dynamic id, ret: %d\n", ret);
        return ret;
    }
    qbuf_expansion_pool_slot_t *tmp_slot = (qbuf_expansion_pool_slot_t *)calloc(1, sizeof(qbuf_expansion_pool_slot_t));
    if (tmp_slot == NULL) {
        // not roll back the slot list expansion operation, use directly next time.
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to alloc qbuf_expansion_pool_slot_t\n");
        urpc_id_generator_free(&exp_pool->dynamic_id_gen, id);
        return -UMQ_ERR_ENOMEM;
    }

    tmp_slot->slot_id = id;
    QBUF_LIST_INIT(&tmp_slot->free_block_list);

    *slot = tmp_slot;
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE bool try_inc_atomic_exp_mem_size(uint64_t add_size)
{
    uint64_t before = __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED);
    uint64_t sum;
    do {
        sum = before + add_size;
        if (sum > g_qbuf_pool.expansion_mem_size_max) {
            return false;   
        }
    } while(!__atomic_compare_exchange_n(
        &g_qbuf_pool.exp_total_mem_pool_size, &before, sum, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return true;
}

static void slot_uninit(bool with_data, qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    if (with_data && g_qbuf_pool.seg_ops.unregister_seg_callback != NULL) {
        g_qbuf_pool.seg_ops.unregister_seg_callback(
            NULL, (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min));
    }

    __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, slot->total_buf_size, __ATOMIC_RELEASE);

    if (slot->buffer != NULL) {
        free(slot->buffer);
        slot->buffer = NULL;
    }
}

static int slot_with_data_init(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    uint64_t blk_size = umq_buf_size_small();
    uint64_t blk_count = exp_pool->expansion_block_count;
    uint64_t total_size;
    uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        uint64_t header_size = blk_count * sizeof(umq_buf_t);
        total_size = blk_count * blk_size + header_size;
        if (!try_inc_atomic_exp_mem_size(total_size)) {
            UMQ_VLOG_ERR(VLOG_UMQ, "expansion mem size max: %llu, now expansion mem size: %llu\n",
                g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size);
            return -UMQ_ERR_ENOMEM;
        }

        slot->buffer = (void *)memalign(blk_size, total_size);
        if (slot->buffer == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion pool memory\n");
            goto ROLLBACK_MEM_SIZE;
        }

        slot->header_buffer = (char *)slot->buffer + blk_count * blk_size;
        slot->total_buf_size = total_size;
        slot->total_block_cnt = blk_count;
        slot->free_block_cnt = blk_count;

        for (uint64_t i = 0; i < blk_count; i++) {
            umq_buf_t *buf = (umq_buf_t *)((char *)slot->header_buffer + i * sizeof(umq_buf_t));
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
            buf->data_size = blk_size;
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = (char *)slot->buffer + i * blk_size;
            buf->mempool_without_data = 0;
            buf->mempool_id = mempool_id;
            buf->alloc_state = QBUF_ALLOC_STATE_FREE;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&slot->free_block_list, buf);
        }
    } else {
        total_size = blk_count * blk_size;
        if (!try_inc_atomic_exp_mem_size(total_size)) {
            UMQ_VLOG_ERR(VLOG_UMQ, "expansion mem size max: %llu, now expansion mem size: %llu\n",
            g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size);
            return -UMQ_ERR_ENOMEM;
        }

        slot->buffer = (void *)memalign(blk_size, total_size);
        if (slot->buffer == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion pool memory\n");
            goto ROLLBACK_MEM_SIZE;
        }

        slot->header_buffer = NULL;
        slot->total_buf_size = total_size;
        slot->total_block_cnt = blk_count;
        slot->free_block_cnt = blk_count;

        for (uint64_t i = 0; i < blk_count; i++) {
            umq_buf_t *buf = (umq_buf_t *)((char *)slot->buffer + i * blk_size);
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = blk_size;
            buf->data_size = blk_size - (uint32_t)sizeof(umq_buf_t);
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = (char *)buf + sizeof(umq_buf_t);
            buf->mempool_without_data = 0;
            buf->mempool_id = mempool_id;
            buf->alloc_state = QBUF_ALLOC_STATE_FREE;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&slot->free_block_list, buf);
        }
    }

    int ret = g_qbuf_pool.seg_ops.register_seg_callback(NULL, mempool_id, slot->buffer, slot->total_buf_size);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to register expansion pool seg, ret: %d\n", ret);
        goto FREE_BUFFER;
    }

    return UMQ_SUCCESS;

FREE_BUFFER:
    free(slot->buffer);
    slot->buffer = NULL;

ROLLBACK_MEM_SIZE:
    __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, total_size, __ATOMIC_RELEASE);

    return ret;
}

static int slot_without_data_init(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    uint64_t blk_count = exp_pool->expansion_block_count;
    uint64_t total_size = blk_count * sizeof(umq_buf_t);;

    if (!try_inc_atomic_exp_mem_size(total_size)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "expansion mem size max: %llu, now expansion mem size: %llu\n",
        g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size);
        return -UMQ_ERR_ENOMEM;
    }

    slot->buffer = (void *)memalign(umq_buf_size_small(), total_size);
    if (slot->buffer == NULL) {
        __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, total_size, __ATOMIC_RELEASE);
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion pool memory\n");
        return -UMQ_ERR_ENOMEM;
    }

    slot->header_buffer = (char *)slot->buffer;
    slot->total_buf_size = total_size;
    slot->total_block_cnt = blk_count;
    slot->free_block_cnt = blk_count;

    for (uint64_t i = 0; i < slot->total_block_cnt; i++) {
        umq_buf_t *buf = (umq_buf_t *)((char *)slot->header_buffer + i * sizeof(umq_buf_t));
        buf->umqh = UMQ_INVALID_HANDLE;
        buf->buf_size = (uint32_t)sizeof(umq_buf_t);
        buf->data_size = 0;
        buf->total_data_size = 0;
        buf->headroom_size = 0;
        buf->buf_data = NULL;
        buf->mempool_without_data = 1;
        buf->mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
        buf->alloc_state = QBUF_ALLOC_STATE_FREE;
        (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
        QBUF_LIST_INSERT_HEAD(&slot->free_block_list, buf);
    }
    return UMQ_SUCCESS;
}

static void async_shrink_push_param(bool with_data, qbuf_expansion_pool_t *exp_pool, uint32_t slot_id)
{
    async_shrink_pool_param_t *param = (async_shrink_pool_param_t *)calloc(1, sizeof(async_shrink_pool_param_t));
    if (param == NULL) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "malloc async shrink param failed\n");
        return;
    }
    param->slot_id = slot_id;
    param->with_data = with_data;
    (void)pthread_spin_lock(&exp_pool->shrink_task_list.lock);
    urpc_list_push_back(&exp_pool->shrink_task_list.head, &param->node);
    (void)pthread_spin_unlock(&exp_pool->shrink_task_list.lock);
}

static async_shrink_pool_param_t *async_shrink_pop_param(qbuf_expansion_pool_t *exp_pool)
{
    async_shrink_pool_param_t *param = NULL;
    (void)pthread_spin_lock(&exp_pool->shrink_task_list.lock);
    URPC_LIST_FIRST_NODE(param, node, &exp_pool->shrink_task_list.head);
    if (param != NULL) {
        urpc_list_remove(&param->node);
    }
    (void)pthread_spin_unlock(&exp_pool->shrink_task_list.lock);
    return param;
}

static void *async_shrink_global_pool_callback(void *arg)
{
    qbuf_expansion_pool_t *exp_pool = (qbuf_expansion_pool_t *)arg;
    if (exp_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "expansion pool invalid\n");
        return NULL;
    }

    async_shrink_pool_param_t *shrink_param = NULL;
    while ((shrink_param = async_shrink_pop_param(exp_pool)) != NULL) {
        (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
        if (!exp_pool->inited) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            free(shrink_param);
            break;
        }
        qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[shrink_param->slot_id];
        if (slot == NULL) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "exp slot not exist, slot id %u\n", shrink_param->slot_id);
            continue;
        }

        // if the expansion pool is used again, do not release it
        if (slot->free_block_cnt != slot->total_block_cnt) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            continue;
        }
        exp_pool->exp_slot_list[shrink_param->slot_id] = NULL;

        exp_pool->expansion_count -= 1;
        exp_pool->exp_total_block_num -= slot->total_block_cnt;
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);

        slot_uninit(shrink_param->with_data, exp_pool, slot);
        free_expansion_pool_slot(exp_pool, slot);
        free(shrink_param);
    }

    __atomic_store_n(&exp_pool->is_async_shrinking, 0, __ATOMIC_RELEASE);
    return NULL;
}

void async_shrink_global_pool(bool with_data, qbuf_expansion_pool_t *exp_pool, uint32_t slot_id)
{
    async_shrink_push_param(with_data, exp_pool, slot_id);
    uint32_t async_shrink_expected = 0;
    if (!__atomic_compare_exchange_n(
        &exp_pool->is_async_shrinking, &async_shrink_expected, 1, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, async_shrink_global_pool_callback, (void*)exp_pool) != 0) {
        __atomic_store_n(&exp_pool->is_async_shrinking, 0, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "async shrink global pool create failed, errno: %d\n", errno);
    } else {
        pthread_detach(tid);
    }
}

static ALWAYS_INLINE void return_batch_to_expansion_pool(
    uint16_t mempool_id, umq_buf_t *batch_head, umq_buf_t *batch_tail, uint32_t batch_cnt, bool with_data)
{
    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_date : &g_qbuf_pool.exp_pool_without_date;
    uint32_t slot_id = mempool_id - exp_pool->expansion_pool_id_min;
    if (slot_id >= exp_pool->expansion_pool_cnt_max) {
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "slot id %u invalid, expansion pool capacity %u\n",
            slot_id, exp_pool->expansion_pool_cnt_max);
        return;
    }

    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[slot_id];
    if (slot == NULL) {
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "expansion pool invalid, id %u\n", slot_id);
        return;
    }

    QBUF_LIST_NEXT(batch_tail) = QBUF_LIST_FIRST(&slot->free_block_list);
    QBUF_LIST_FIRST(&slot->free_block_list) = batch_head;
    slot->free_block_cnt += batch_cnt;
    exp_pool->exp_total_block_num += batch_cnt;
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    if (slot->free_block_cnt == slot->total_block_cnt) {
        async_shrink_global_pool(with_data, exp_pool, slot_id);
    }
}

void return_list_to_pools(umq_buf_t *local_head, uint64_t *local_buf_cnt,
    umq_buf_list_t *global_head, uint64_t *global_buf_cnt, bool with_data)
{
    umq_buf_t *batch_head = local_head;
    umq_buf_t *batch_tail = local_head;
    uint32_t batch_cnt = 1;
    uint64_t return_buf_cnt = 1;
    uint32_t batch_mempool_id = local_head->mempool_id;
    umq_buf_t *cur = QBUF_LIST_NEXT(local_head);

    while (cur != NULL) {
        umq_buf_t *next = QBUF_LIST_NEXT(cur);
        if (batch_mempool_id == cur->mempool_id) {
            batch_tail = cur;
            batch_cnt++;
        } else {
            QBUF_LIST_NEXT(batch_tail) = NULL;
            if (batch_mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
                return_batch_to_expansion_pool(batch_mempool_id, batch_head, batch_tail, batch_cnt, with_data);
            } else {
                QBUF_LIST_NEXT(batch_tail) = QBUF_LIST_FIRST(global_head);
                QBUF_LIST_FIRST(global_head) = batch_head;
                *global_buf_cnt += batch_cnt;
            }
            batch_head = cur;
            batch_tail = cur;
            batch_cnt = 1;
            batch_mempool_id = cur->mempool_id;
        }
        return_buf_cnt++;
        cur = next;
    }

    if (batch_head != NULL) {
        QBUF_LIST_NEXT(batch_tail) = NULL;
        if (batch_mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
            return_batch_to_expansion_pool(batch_mempool_id, batch_head, batch_tail, batch_cnt, with_data);
        } else {
            QBUF_LIST_NEXT(batch_tail) = QBUF_LIST_FIRST(global_head);
            QBUF_LIST_FIRST(global_head) = batch_head;
            *global_buf_cnt += batch_cnt;
        }
    }
    *local_buf_cnt -= return_buf_cnt;
}

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
            UMQ_VLOG_ERR(VLOG_UMQ, "memory size %lu invalid, expect at least %lu\n", size, min_size);
            return NULL;
        }

        g_total_len = size;
    } else {
        g_total_len = UMQ_BUF_DEFAULT_TOTAL_SIZE;
    }

    g_buffer_addr = (void *)memalign(umq_buf_size_small(), g_total_len);
    if (g_buffer_addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "memalign for qbuf pool failed, errno: %d\n", errno);
        return NULL;
    }

    UMQ_VLOG_INFO(VLOG_UMQ, "malloc umq io buf %lu bytes\n", g_total_len);

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
        UMQ_VLOG_ERR(VLOG_UMQ, "block size %d is invalid\n", block_size);
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

uint64_t umq_buf_to_id(char *buf, bool shm, bool with_data)
{
    // not support shm buf to id and name
    if (shm) {
        return 0;
    }

    if (umq_qbuf_mode_get() != UMQ_BUF_COMBINE) {
        return with_data ?
            buf_to_id_with_data_split((char *)g_qbuf_pool.header_buffer, buf) :
            buf_to_id_without_data_split((char *)g_qbuf_pool.ext_header_buffer, buf);
    }

    return buf_to_id_combine((char *)g_qbuf_pool.data_buffer, buf, g_qbuf_pool.block_size);
}

uint64_t umq_buf_to_id_with_header(umq_buf_list_t *header, char *buf, bool shm, bool *with_data)
{
    // not support shm buf to id and name
    if (shm) {
        return 0;
    }

    *with_data = true;

    if (umq_qbuf_mode_get() == UMQ_BUF_SPLIT && QBUF_LIST_FIRST(header)->mempool_without_data == 1) {
        *with_data = false;
    }

    return umq_buf_to_id(buf, shm, *with_data);
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
        g_thread_cache.block_pool.capacity_with_data = 0;
        g_thread_cache.block_pool.capacity_without_data = 0;
        g_thread_cache.block_pool.last_used_with_data = urpc_get_cpu_cycles();
        g_thread_cache.block_pool.last_used_without_data = urpc_get_cpu_cycles();
        QBUF_LIST_INIT(&g_thread_cache.block_pool.head_with_data);
        g_thread_cache.block_pool.buf_cnt_with_data = 0;
        QBUF_LIST_INIT(&g_thread_cache.block_pool.head_without_data);
        g_thread_cache.block_pool.buf_cnt_without_data = 0;
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
    (void)pthread_spin_lock(&g_qbuf_pool.block_pool.global_mutex);
    if (local_pool->head_with_data.first != NULL) {
        return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_with_data), &local_pool->buf_cnt_with_data,
            &g_qbuf_pool.block_pool.head_with_data, &g_qbuf_pool.block_pool.buf_cnt_with_data, true);
    }

    if (local_pool->head_without_data.first != NULL) {
        return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_without_data), &local_pool->buf_cnt_without_data,
            &g_qbuf_pool.block_pool.head_without_data, &g_qbuf_pool.block_pool.buf_cnt_without_data, false);
    }
    (void)pthread_spin_unlock(&g_qbuf_pool.block_pool.global_mutex);

    __atomic_fetch_sub(&g_total_local_cap_with_data, local_pool->capacity_with_data, __ATOMIC_RELAXED);
    __atomic_fetch_sub(&g_total_local_cap_without_data, local_pool->capacity_without_data, __ATOMIC_RELAXED);

    g_thread_cache.inited = false;
}

static void umq_qbuf_exp_pool_inner_uninit(qbuf_expansion_pool_t *exp_pool, bool with_data)
{
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    exp_pool->inited = false;
    if (exp_pool->exp_slot_list != NULL) {
        for (uint32_t i = 0; i < exp_pool->expansion_pool_cnt_max; i++) {
            qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[i];
            if (slot == NULL) {
                continue;
            }
            if (with_data && g_qbuf_pool.seg_ops.unregister_seg_callback != NULL && slot->buffer != NULL) {
                uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
                g_qbuf_pool.seg_ops.unregister_seg_callback(NULL, mempool_id);
            }
            if (slot->buffer != NULL) {
                free(slot->buffer);
            }
            free(slot);
        }
        free(exp_pool->exp_slot_list);
        exp_pool->exp_slot_list = NULL;
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);

    (void)pthread_spin_lock(&exp_pool->shrink_task_list.lock);
    async_shrink_pool_param_t *cur_node, *next_node;
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &exp_pool->shrink_task_list.head) {
        urpc_list_remove(&cur_node->node);
        free(cur_node);
    }
    (void)pthread_spin_unlock(&exp_pool->shrink_task_list.lock);

    // wait async expand
    uint64_t start_time = urpc_get_cpu_cycles();
    uint32_t async_expand_expected = 0;
    while (!__atomic_compare_exchange_n(
        &exp_pool->is_async_expanding, &async_expand_expected, 1, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) &&
        ((urpc_get_cpu_cycles() - start_time) / urpc_get_cpu_hz()) < QBUF_POOL_WITH_ASYNC_EXIT_TIMEOUT_S) {
        async_expand_expected = 0;
        // wait 1 ms
        usleep(QBUF_POOL_CHECK_ASYNC_PERIOD_US);
    }

    // wait async shrink
    async_expand_expected = 0;
    while (!__atomic_compare_exchange_n(
        &exp_pool->is_async_shrinking, &async_expand_expected, 1, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) &&
        ((urpc_get_cpu_cycles() - start_time) / urpc_get_cpu_hz()) < QBUF_POOL_WITH_ASYNC_EXIT_TIMEOUT_S) {
        async_expand_expected = 0;
        usleep(QBUF_POOL_CHECK_ASYNC_PERIOD_US);
    }
    urpc_id_generator_uninit(&exp_pool->dynamic_id_gen);

    (void)pthread_spin_destroy(&exp_pool->expansion_pool_lock);
    (void)pthread_spin_destroy(&exp_pool->shrink_task_list.lock);
}

static int umq_qbuf_exp_pool_inner_init(qbuf_expansion_pool_t *exp_pool, const qbuf_pool_cfg_t *cfg, bool with_data)
{
    exp_pool->exp_slot_list = NULL;
    exp_pool->expansion_count = 0;
    if (with_data) {
        exp_pool->expansion_block_count = (cfg->expansion_block_count == 0) ?
            QBUF_POOL_DEFAULT_EXPANSION_COUNT : cfg->expansion_block_count;
    } else {
        exp_pool->expansion_block_count = UMQ_EMPTY_HEADER_COEFFICIENT *
            ((cfg->expansion_block_count == 0) ? QBUF_POOL_DEFAULT_EXPANSION_COUNT : cfg->expansion_block_count);
        exp_pool->trigger_expand_block_num = exp_pool->expansion_block_count / QBUF_POOL_EXPANSION_RATIO;
    }
    exp_pool->expansion_pool_id_min = cfg->expansion_pool_id_min;
    exp_pool->expansion_pool_cnt_max = cfg->expansion_pool_cnt_max;

    int ret = urpc_id_generator_init(&exp_pool->dynamic_id_gen, URPC_ID_GENERATOR_TYPE_BITMAP,
        exp_pool->expansion_pool_cnt_max);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to init dynamic_id_gen, ret: %d\n", ret);
        return -UMQ_ERR_ENOMEM;
    }

    exp_pool->exp_slot_list = (qbuf_expansion_pool_slot_t **)calloc(exp_pool->expansion_pool_cnt_max,
        sizeof(qbuf_expansion_pool_slot_t *));
    if (exp_pool->exp_slot_list == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion_pool array\n");
        goto UNINIT_ID_GEN;
    }
    urpc_list_init(&exp_pool->shrink_task_list.head);
    (void)pthread_spin_init(&exp_pool->expansion_pool_lock, PTHREAD_PROCESS_PRIVATE);
    (void)pthread_spin_init(&exp_pool->shrink_task_list.lock, PTHREAD_PROCESS_PRIVATE);
    exp_pool->inited = true;
    return UMQ_SUCCESS;

UNINIT_ID_GEN:
    urpc_id_generator_uninit(&exp_pool->dynamic_id_gen);

    return -UMQ_ERR_ENOMEM;
}

static int umq_qbuf_expansion_pool_init(const qbuf_pool_cfg_t *cfg)
{
    // with data;
    int ret = umq_qbuf_exp_pool_inner_init(&g_qbuf_pool.exp_pool_with_date, cfg, true);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "init expansion pool with data failed, ret %d\n", ret);
        return ret;
    }
    // without data
    ret = umq_qbuf_exp_pool_inner_init(&g_qbuf_pool.exp_pool_without_date, cfg, false);
    if (ret != UMQ_SUCCESS) {
        umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_with_date, true);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "init expansion pool without data failed, ret %d\n", ret);
        return ret;
    }
    return UMQ_SUCCESS;
}

int umq_qbuf_pool_init(qbuf_pool_cfg_t *cfg)
{
    if (g_qbuf_pool.inited) {
        UMQ_VLOG_INFO(VLOG_UMQ, "qbuf pool has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    if (cfg->umq_buf_pool_max_size > QBUF_POOL_EXPANSION_MEM_SIZE_MAX) {
        UMQ_VLOG_INFO(VLOG_UMQ, "the maximum value of expansion mem size max %llu exceed %llu\n",
            cfg->umq_buf_pool_max_size, QBUF_POOL_EXPANSION_MEM_SIZE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->umq_buf_pool_max_size > 0 && cfg->umq_buf_pool_max_size < g_total_len) {
        UMQ_VLOG_INFO(VLOG_UMQ, "the maximum value of expansion mem size max %llu invalid\n",
            cfg->umq_buf_pool_max_size);
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq_qbuf_block_pool_init(&g_qbuf_pool.block_pool);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq qbuf block pool init failed, status: %d\n", ret);
        return UMQ_FAIL;
    }

    g_qbuf_pool.mode = cfg->mode;
    g_qbuf_pool.total_size = cfg->total_size;
    g_qbuf_pool.headroom_size = cfg->headroom_size;
    g_qbuf_pool.data_size = cfg->data_size;
    g_qbuf_pool.expansion_mem_size_max = (cfg->umq_buf_pool_max_size == 0 ?
        QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE : cfg->umq_buf_pool_max_size) - g_total_len;
    g_qbuf_pool.seg_ops = cfg->seg_ops;
    g_qbuf_pool.local_pool_cfg.tls_qbuf_pool_depth =
        (cfg->tls_qbuf_pool_depth == 0) ? QBUF_POOL_TLS_QBUF_POOL_DEPTH : cfg->tls_qbuf_pool_depth;
    g_qbuf_pool.local_pool_cfg.tls_expand_qbuf_pool_depth = cfg->tls_expand_qbuf_pool_depth == 0 ?
        QBUF_POOL_EXPAND_MAX(g_qbuf_pool.local_pool_cfg.tls_qbuf_pool_depth) :  cfg->tls_expand_qbuf_pool_depth;

    ret = umq_qbuf_expansion_pool_init(cfg);
    if (ret != UMQ_SUCCESS) {
        umq_qbuf_block_pool_uninit(&g_qbuf_pool.block_pool);
        return ret;
    }

    if (cfg->mode == UMQ_BUF_SPLIT) {
        uint32_t blk_size = umq_buf_size_small();
        uint64_t blk_num = cfg->total_size / ((uint32_t)sizeof(umq_buf_t) + blk_size);

        g_qbuf_pool.block_size = blk_size;
        g_qbuf_pool.total_block_num = blk_num;
        g_qbuf_pool.exp_pool_with_date.trigger_expand_block_num = blk_num / QBUF_POOL_EXPANSION_RATIO;

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
            buf->mempool_without_data = 0;
            buf->mempool_id = 0;
            buf->alloc_state = QBUF_ALLOC_STATE_FREE;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool.head_with_data, buf);
        }
        g_qbuf_pool.block_pool.buf_cnt_with_data = blk_num;
        g_qbuf_pool.block_pool.buf_cnt_without_data = 0;
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        uint32_t blk_size = umq_buf_size_small();
        uint64_t blk_num = cfg->total_size / blk_size;

        g_qbuf_pool.data_buffer = cfg->buf_addr;
        g_qbuf_pool.header_buffer = NULL;
        g_qbuf_pool.ext_header_buffer = NULL;

        g_qbuf_pool.block_size = blk_size;
        g_qbuf_pool.total_block_num = blk_num;
        g_qbuf_pool.exp_pool_with_date.trigger_expand_block_num = blk_num / QBUF_POOL_EXPANSION_RATIO;

        for (uint64_t i = 0; i < blk_num; i++) {
            umq_buf_t *buf = id_to_buf_combine((char *)g_qbuf_pool.data_buffer, i, g_qbuf_pool.block_size);
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = blk_size;
            buf->data_size = blk_size - (uint32_t)sizeof(umq_buf_t);
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = (char *)buf + sizeof(umq_buf_t);
            buf->mempool_without_data = 0;
            buf->mempool_id = 0;
            buf->alloc_state = QBUF_ALLOC_STATE_FREE;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool.head_with_data, buf);
        }
        g_qbuf_pool.block_pool.buf_cnt_with_data = blk_num;
        g_qbuf_pool.block_pool.buf_cnt_without_data = 0;
    } else {
        umq_qbuf_block_pool_uninit(&g_qbuf_pool.block_pool);
        UMQ_VLOG_ERR(VLOG_UMQ, "buf mode: %d is invalid\n", cfg->mode);
        return -UMQ_ERR_EINVAL;
    }

    g_qbuf_pool.inited = true;
    return UMQ_SUCCESS;
}

static void umq_qbuf_expansion_pool_uninit(void)
{
    // with data uninit
    umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_with_date, true);

    // without data uninit
    umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_without_date, false);
}

void umq_qbuf_pool_uninit(void)
{
    if (!g_qbuf_pool.inited) {
        return;
    }

    release_thread_cache(0);

    umq_qbuf_expansion_pool_uninit();

    umq_qbuf_block_pool_uninit(&g_qbuf_pool.block_pool);
    memset(&g_qbuf_pool, 0, sizeof(qbuf_pool_t));

    __atomic_store_n(&g_total_local_cap_with_data, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_total_local_cap_without_data, 0, __ATOMIC_RELAXED);
}

// expand local pool capacity and fetch bufs from global
static ALWAYS_INLINE int umq_qbuf_local_pool_fetch_and_expand(
    uint32_t needed, local_block_pool_t *local_pool, bool with_data)
{
    uint64_t *cap;
    volatile uint64_t *g_total;
    if (with_data) {
        cap = &local_pool->capacity_with_data;
        g_total = &g_total_local_cap_with_data;
    } else {
        cap = &local_pool->capacity_without_data;
        g_total = &g_total_local_cap_without_data;
    }

    // Round up based on QBUF_POOL_BATCH_CNT, with a minimum expansion of QBUF_POOL_BATCH_CNT each time
    uint32_t batch_cnt = (needed + QBUF_POOL_BATCH_CNT - 1) / QBUF_POOL_BATCH_CNT * QBUF_POOL_BATCH_CNT;
    uint64_t grow = batch_cnt;
    if ((*cap) + grow > g_qbuf_pool.local_pool_cfg.tls_expand_qbuf_pool_depth) {
        grow = ((*cap) >= g_qbuf_pool.local_pool_cfg.tls_expand_qbuf_pool_depth) ?
            0 : (g_qbuf_pool.local_pool_cfg.tls_expand_qbuf_pool_depth - (*cap));
    }
    if ((*g_total) + grow > g_qbuf_pool.local_pool_cfg.tls_qbuf_pool_depth) {
        grow = ((*g_total) >= g_qbuf_pool.local_pool_cfg.tls_qbuf_pool_depth) ?
            0 : (g_qbuf_pool.local_pool_cfg.tls_qbuf_pool_depth - (*g_total));
    }

    uint32_t fetch_count = 0;
    while (fetch_count < batch_cnt) {
        int32_t ret = fetch_from_global(&g_qbuf_pool.block_pool, local_pool, with_data, QBUF_POOL_BATCH_CNT);
        if (ret <= 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "fetch from global failed, fetch count: %u\n", batch_cnt);
            return ret;
        }
        fetch_count += (uint32_t)ret;
    }

    if (grow > 0) {
        *cap = (*cap) + grow;
        __atomic_fetch_add(g_total, grow, __ATOMIC_RELAXED);
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE void thread_cache_self_shrink(bool with_data)
{
    uint64_t remaining;
    uint64_t *cap_ptr;
    volatile uint64_t *g_total;

    if (with_data) {
        remaining = (uint32_t)g_thread_cache.block_pool.buf_cnt_with_data;
        cap_ptr = &g_thread_cache.block_pool.capacity_with_data;
        g_total = &g_total_local_cap_with_data;
    } else {
        remaining = (uint32_t)g_thread_cache.block_pool.buf_cnt_without_data;
        cap_ptr = &g_thread_cache.block_pool.capacity_without_data;
        g_total = &g_total_local_cap_without_data;
    }

    uint64_t shrink = remaining / QBUF_POOL_SELF_SHRINK_RATIO;
    if (shrink < QBUF_POOL_SHRINK_THRESHOLD || (*cap_ptr) == 0) {
        return;
    }
    *cap_ptr = (*cap_ptr) - shrink;
    __atomic_fetch_sub(g_total, shrink, __ATOMIC_RELAXED);

    if ((*cap_ptr) < remaining) {
        return_to_global(&g_qbuf_pool.block_pool, &g_thread_cache.block_pool, with_data, (*cap_ptr));
    }
}

int expand_global_pool(bool with_data)
{
    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_date : &g_qbuf_pool.exp_pool_without_date;
    qbuf_expansion_pool_slot_t *slot = NULL;
    int ret = alloc_expansion_pool_slot(exp_pool, &slot);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "expansion pool count %u reached max %u\n",
            exp_pool->expansion_count, exp_pool->expansion_pool_cnt_max);
        return -UMQ_ERR_ENOMEM;
    }

    ret = with_data ? slot_with_data_init(exp_pool, slot) : slot_without_data_init(exp_pool, slot);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "init %s slot failed\n", with_data ? "with data" : "without_data\n");
        goto FREE_SLOT;
    }

    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    if (!exp_pool->inited) {
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "expansion pool not init\n");
        goto UNINIT_SLOT;
    }
    exp_pool->exp_slot_list[slot->slot_id] = slot;

    exp_pool->expansion_count += 1;
    exp_pool->exp_total_block_num += slot->total_block_cnt;
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    return UMQ_SUCCESS;

UNINIT_SLOT:
    slot_uninit(with_data, exp_pool, slot);

FREE_SLOT:
    free_expansion_pool_slot(exp_pool, slot);
    return -UMQ_ERR_ENOMEM;
}

typedef struct async_expand_pool_param {
    qbuf_expansion_pool_t *exp_pool;
    bool with_data;
} async_expand_pool_param_t;

static void *async_expand_global_pool_callback(void *arg)
{
    async_expand_pool_param_t *async_param = (async_expand_pool_param_t *)arg;
    if (async_param == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "async param invalid\n");
        return NULL;
    }
    (void)expand_global_pool(async_param->with_data);
    __atomic_store_n(&async_param->exp_pool->is_async_expanding, 0, __ATOMIC_RELEASE);
    free(arg);
    return NULL;
}

void async_expand_global_pool(bool with_data, uint64_t g_buf_cnt)
{
    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_date : &g_qbuf_pool.exp_pool_without_date;
    if (g_buf_cnt + exp_pool->exp_total_block_num >= exp_pool->trigger_expand_block_num) {
        return;
    }

    uint32_t async_expand_expected = 0;
    if (!__atomic_compare_exchange_n(
        &exp_pool->is_async_expanding, &async_expand_expected, 1, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return;
    }

    pthread_t tid;
    async_expand_pool_param_t *arg = (async_expand_pool_param_t *)malloc(sizeof(async_expand_pool_param_t));
    arg->exp_pool = exp_pool;
    arg->with_data = with_data;
    if (pthread_create(&tid, NULL, async_expand_global_pool_callback, arg) != 0) {
        __atomic_store_n(&exp_pool->is_async_expanding, 0, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "async expand global pool failed, errno: %d\n", errno);
    } else {
        pthread_detach(tid);
    }
}

uint32_t fetch_from_expansion_pools(bool with_data, uint32_t need, umq_buf_list_t *local_head, uint64_t *local_buf_cnt)
{
    uint32_t count = 0;
    uint32_t valid_slot = 0;
    uint32_t request = need;
    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_date : &g_qbuf_pool.exp_pool_without_date;
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    for (uint32_t i = 0;
        i < exp_pool->expansion_pool_cnt_max && request > 0 && valid_slot < exp_pool->expansion_count; i++) {
        qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[i];
        if (slot == NULL) {
            continue;
        }
        valid_slot++;

        umq_buf_list_t *exp_free_list = &slot->free_block_list;
        uint64_t take_cnt = (request < slot->free_block_cnt) ? request : slot->free_block_cnt;
        if (take_cnt > 0) {
            (void)allocate_batch(exp_free_list, take_cnt, local_head);
            *local_buf_cnt += take_cnt;
            slot->free_block_cnt -= take_cnt;
            count += take_cnt;
            request -= take_cnt;
            exp_pool->exp_total_block_num -= take_cnt;
        }
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    return count;
}

int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    bool flag = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0);
    qbuf_alloc_param_t param;
    param.shm = false;
    param.headroom_size = flag ? option->headroom_size : g_qbuf_pool.headroom_size;

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        param.actual_buf_count =
            num * ((request_size + param.headroom_size + umq_buf_size_small() - 1) >> umq_buf_size_pow_small());
    } else {
        uint32_t align_size = umq_buf_size_small() - sizeof(umq_buf_t);
        param.actual_buf_count = num * ((request_size + param.headroom_size + align_size - 1) / align_size);
    }

    if (request_size == 0) {
        if (flag && param.headroom_size > 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "headroom_size not supported when request_size is 0\n");
            return -UMQ_ERR_EINVAL;
        }

        if (g_qbuf_pool.mode != UMQ_BUF_SPLIT) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "cannot alloc memory size 0 in combine mode\n");
            return -UMQ_ERR_ENOMEM;
        }

        if (local_pool->buf_cnt_without_data < num) {
            int ret = umq_qbuf_local_pool_fetch_and_expand(num - local_pool->buf_cnt_without_data, local_pool, false);
            if (ret != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq qbuf local pool fetch and expand failed, ret: %d\n", ret);
                return ret;
            }
        }

        umq_qbuf_alloc_nodata(local_pool, num, list, param.shm);
        thread_cache_self_shrink(false);

        local_pool->last_used_without_data = urpc_get_cpu_cycles();
        return 0;
    }

    uint32_t needed = param.actual_buf_count;
    uint32_t buf_cnt = (uint32_t)local_pool->buf_cnt_with_data;

    if (buf_cnt < needed) {
        int ret = umq_qbuf_local_pool_fetch_and_expand(needed, local_pool, true);
        if (ret != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq qbuf local pool fetch and expand failed, ret: %d\n", ret);
            return ret;
        }
    }

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        umq_qbuf_alloc_data_with_split(local_pool, request_size, &param, list);
    } else {
        umq_qbuf_alloc_data_with_combine(local_pool, request_size, &param, list);
    }

    thread_cache_self_shrink(true);

    local_pool->last_used_with_data = urpc_get_cpu_cycles();
    return UMQ_SUCCESS;
}

void umq_qbuf_free(umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    // split mode and buf is in head no data zone
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT && QBUF_LIST_FIRST(list)->mempool_without_data == 1) {
        // put buf list before head of head_without_data
        uint32_t cnt = release_batch(list, &local_pool->head_without_data, false);
        local_pool->buf_cnt_without_data += cnt;

        uint32_t cap = local_pool->capacity_without_data;
        if (local_pool->buf_cnt_without_data > cap) {
            return_to_global(&g_qbuf_pool.block_pool, local_pool, false, cap);
        }

        local_pool->last_used_without_data = urpc_get_cpu_cycles();
        return;
    }

    uint32_t cnt = release_batch(list, &local_pool->head_with_data, false);
    local_pool->buf_cnt_with_data += cnt;

    uint32_t cap = local_pool->capacity_with_data;
    uint32_t buf_cnt = (uint32_t)local_pool->buf_cnt_with_data;

    if (buf_cnt > cap) {
        uint32_t threshold = cap > QBUF_POOL_BATCH_CNT ? cap - QBUF_POOL_BATCH_CNT : 0;
        return_to_global(&g_qbuf_pool.block_pool, local_pool, true, threshold);
    }

    local_pool->last_used_with_data = urpc_get_cpu_cycles();
}

int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    return headroom_reset(qbuf, headroom_size, g_qbuf_pool.mode, g_qbuf_pool.block_size);
}

umq_buf_t *umq_qbuf_data_to_head(void *data)
{
    if (!g_qbuf_pool.inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return NULL;
    }

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        if (data >= g_qbuf_pool.data_buffer && data < g_qbuf_pool.header_buffer) {
            uint64_t id =
                ((uint64_t)(uintptr_t)data - (uint64_t)(uintptr_t)g_qbuf_pool.data_buffer) / g_qbuf_pool.block_size;
            return (umq_buf_t *)(g_qbuf_pool.header_buffer + id * sizeof(umq_buf_t));
        }
    } else {
        if (data >= g_qbuf_pool.data_buffer && data < g_qbuf_pool.data_buffer + g_qbuf_pool.total_size) {
            uint64_t id =
                ((uint64_t)(uintptr_t)data - (uint64_t)(uintptr_t)g_qbuf_pool.data_buffer) / g_qbuf_pool.block_size;
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

int umq_qbuf_pool_info_get(umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    if (!g_qbuf_pool.inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    if (qbuf_pool_stats->num >= UMQ_STATS_QBUF_POOL_TYPE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "count of qbuf pool info exceeds maximum %u\n", UMQ_STATS_QBUF_POOL_TYPE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    umq_qbuf_pool_info_t *qbuf_pool_info = &qbuf_pool_stats->qbuf_pool_info[qbuf_pool_stats->num];
    uint32_t block_size = g_qbuf_pool.block_size;
    uint32_t umq_buf_t_size = (uint32_t)sizeof(umq_buf_t);
    umq_buf_mode_t mode = g_qbuf_pool.mode;
    qbuf_pool_info->mode = mode;
    qbuf_pool_info->total_size = g_qbuf_pool.total_size;
    qbuf_pool_info->headroom_size = g_qbuf_pool.headroom_size;
    qbuf_pool_info->block_size = block_size;
    qbuf_pool_info->total_block_num = g_qbuf_pool.total_block_num;
    qbuf_pool_info->umq_buf_t_size = umq_buf_t_size;
    if (mode == UMQ_BUF_SPLIT) {
        qbuf_pool_info->data_size = block_size;
        qbuf_pool_info->buf_size = block_size + umq_buf_t_size;
        qbuf_pool_info->available_mem.split.block_num_with_data = g_qbuf_pool.block_pool.buf_cnt_with_data;
        qbuf_pool_info->available_mem.split.size_with_data = g_qbuf_pool.block_pool.buf_cnt_with_data *
            (block_size + umq_buf_t_size);
        qbuf_pool_info->available_mem.split.block_num_without_data =
            g_qbuf_pool.block_pool.buf_cnt_without_data;
        qbuf_pool_info->available_mem.split.size_without_data =
            g_qbuf_pool.block_pool.buf_cnt_without_data * umq_buf_t_size;
    } else {
        qbuf_pool_info->data_size = block_size - umq_buf_t_size;
        qbuf_pool_info->buf_size = block_size;
        qbuf_pool_info->available_mem.combine.block_num_with_data =
            g_qbuf_pool.block_pool.buf_cnt_with_data;
        qbuf_pool_info->available_mem.combine.size_with_data = g_qbuf_pool.block_pool.buf_cnt_with_data * block_size;
    }
    qbuf_pool_stats->num++;
    return UMQ_SUCCESS;
}

int umq_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    int ret = ops->register_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID, g_qbuf_pool.data_buffer, g_qbuf_pool.total_size);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_date;
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    uint32_t slot_idx = 0;
    for (slot_idx = 0; slot_idx < exp_pool->expansion_pool_cnt_max; slot_idx++) {
        qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[slot_idx];
        if (slot == NULL) {
            continue;
        }

        uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
        ret = ops->register_seg_callback(ctx, mempool_id, slot->buffer, slot->total_buf_size);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "failed to register expansion pool seg, ret: %d\n", ret);
            goto UNREGISTER_SEG;
        }
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    return UMQ_SUCCESS;

UNREGISTER_SEG:
    for (uint32_t i = 0; i < slot_idx; i++) {
        qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[i];
        if (slot == NULL) {
            continue;
        }

        uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
        ops->unregister_seg_callback(ctx, mempool_id);
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    ops->unregister_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
    return ret;
}

void umq_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    ops->unregister_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
    qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_date;
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    for (uint32_t i = 0; i < exp_pool->expansion_pool_cnt_max; i++) {
        qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[i];
        if (slot == NULL) {
            continue;
        }

        uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
        ops->unregister_seg_callback(ctx, mempool_id);
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
}
