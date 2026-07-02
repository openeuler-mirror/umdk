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
#include <sys/mman.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "urpc_util.h"
#include "urpc_list.h"
#include "umq_qbuf_pool.h"

#define QBUF_POOL_TLS_QBUF_POOL_DEPTH (12 * 1024) // all thread-local pool capacity sum budget

#define QBUF_POOL_EXPANSION_RATIO 10 // percentage that triggers expansion

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
    uint64_t total_expansion_count;
    uint64_t total_shrink_count;

    uint64_t sub_slot_blk_count;
    uint64_t sub_slot_count;
    uint64_t sub_slot_data_buf_size;
} qbuf_expansion_pool_t;

typedef struct qbuf_pool {
    qbuf_pool_base_t base;
    void *ext_header_buffer;    // ext头部区起始地址，数据区指针为空，仅有头部，数量为分片数*16。combine模式为NULL

    uint64_t expansion_mem_size_max;
    volatile uint64_t exp_total_mem_pool_size;
    qbuf_expansion_pool_t exp_pool_with_date;
    qbuf_expansion_pool_t exp_pool_without_date;

    // escape
    bool disable_malloc_escape;
} qbuf_pool_t;

static qbuf_pool_t g_qbuf_pool = {0};
static __thread thread_local_qbuf_pool_t g_thread_cache = {0};
static uint8_t g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_4K;

// --- global registry and capacity counters for elastic scaling ---
static volatile uint64_t g_total_local_cap_with_data = 0;     // sum of all threads' capacity_with_data
static volatile uint64_t g_total_local_cap_without_data = 0;  // sum of all threads' capacity_without_data

static volatile uint64_t g_total_escape_buf_cnt = 0;  // sum of all threads' capacity_without_data

static void *g_buffer_addr = NULL;
static uint64_t g_total_len = 0;

static inline uint32_t umq_qbuf_pool_batch_cnt(void)
{
    return QBUF_POOL_BATCH_CNT;
}

static inline uint32_t umq_qbuf_pool_tls_depth(void)
{
    return QBUF_POOL_TLS_QBUF_POOL_DEPTH;
}

static inline uint32_t umq_qbuf_pool_shrink_threshold(void)
{
    return QBUF_POOL_SHRINK_THRESHOLD;
}

static inline uint32_t umq_qbuf_expansion_count(void)
{
    return QBUF_POOL_DEFAULT_EXPANSION_COUNT;
}

static int normal_qbuf_base_fetch(uint32_t needed, local_block_pool_t *local_pool, bool with_data);
static void normal_qbuf_base_self_shrink(bool with_data);

static void free_expansion_pool_slot(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    urpc_id_generator_free(&exp_pool->dynamic_id_gen, slot->slot_id);

    if (slot->buffer != NULL) {
        free(slot->buffer);
        slot->buffer = NULL;
    }
    free(slot);
}

static int alloc_expansion_pool_slot(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t **slot)
{
    uint32_t id = 0;
    int ret = urpc_id_generator_alloc(&exp_pool->dynamic_id_gen, 0, &id);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc dynamic id, ret: %d\n", ret);
        return ret;
    }
    qbuf_expansion_pool_slot_t *tmp_slot = (qbuf_expansion_pool_slot_t *)calloc(1, sizeof(qbuf_expansion_pool_slot_t));
    if (tmp_slot == NULL) {
        // not roll back the slot list expansion operation, use directly next time.
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc qbuf_expansion_pool_slot_t\n");
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
    uint64_t before = __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_ACQUIRE);
    uint64_t sum;
    do {
        sum = before + add_size;
        if (sum > g_qbuf_pool.expansion_mem_size_max) {
            return false;
        }
    } while (!__atomic_compare_exchange_n(
        &g_qbuf_pool.exp_total_mem_pool_size, &before, sum, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return true;
}

static void slot_uninit(bool with_data, qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    if (with_data && g_qbuf_pool.base.seg_ops.unregister_seg_callback != NULL) {
        g_qbuf_pool.base.seg_ops.unregister_seg_callback(
            NULL, (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min));
    }

    __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, slot->total_buf_size, __ATOMIC_ACQ_REL);

    if (slot->buffer != NULL) {
        free(slot->buffer);
        slot->buffer = NULL;
    }
}

/**
 * Slice strategy for slot expansion (split into multiple 2MB segments via sub-slot):
 * Each sub-slot has a fixed size of QBUF_MEMALIGN_SIZE
 * Its start address is calculated as slot->buffer + i * QBUF_MEMALIGN_SIZE
 * Layout of sub-slots within a slot:
 *   +-------------------- slot address space ----------------------+
 *   | sub-slot[0] | sub-slot[1] | ... | sub-slot[i] | ... | last   |
 *   +--------------------------------------------------------------+
 *   Fixed size per sub-slot: QBUF_MEMALIGN_SIZE
 * [SPLIT Mode]
 *   All blk_data are arranged first inside one sub-slot, followed by all buffer headers:
 *   +------------------- data region ----------------+ +----- hdr region -----+
 *   | [blk_data0] [blk_data1] ... [blk_dataN]        | | [buf0] [buf1] ...[N] |
 *   +------------------------------------------------+ +----------------------+
 *   Mapping: buf[i].buf_data -> blk_data[i]
 *
 * [COMBINE Mode]
 *   Each block embeds [bufi][blk_datai] internally, blocks are arranged contiguously within a single sub-slot:
 *   +------------------- one sub-slot -----------------------+
 *   | [buf0|blk_data0] [buf1|blk_data1] ... [bufN|blk_dataN] |
 *   +--------------------------------------------------------+
 */

static int slot_with_data_init(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    uint64_t blk_size = umq_buf_size_small();
    uint64_t blk_count = exp_pool->expansion_block_count;
    uint64_t sub_slot_blk_count = exp_pool->sub_slot_blk_count;
    uint64_t sub_slot_count = exp_pool->sub_slot_count;
    uint64_t total_size = QBUF_MEMALIGN_SIZE * sub_slot_count;
    if (!try_inc_atomic_exp_mem_size(total_size)) {
        if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_ACQUIRE) == 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                "expand mem size max: %llu, now expand mem size: %llu, expand buf pool need: %llu, expand failed\n",
                g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size, total_size);
        }
        return -UMQ_ERR_ENOMEM;
    }
    uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);

    slot->buffer = (void *)memalign(QBUF_MEMALIGN_SIZE, total_size);
    if (slot->buffer == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion pool memory\n");
        goto ROLLBACK_MEM_SIZE;
    }
    madvise(slot->buffer, total_size, MADV_HUGEPAGE);
    slot->header_buffer = (void *)((char *)slot->buffer + total_size);
    slot->total_buf_size = total_size;
    slot->total_block_cnt = blk_count;
    slot->free_block_cnt = blk_count;

    char *sub_data_buf_head;
    uint64_t remain_blk_count = blk_count;
    for (uint64_t i = 0; i < sub_slot_count; i++) {
        uint32_t blk_num = sub_slot_blk_count < remain_blk_count ? sub_slot_blk_count : remain_blk_count;
        char *header_buffer = NULL;

        sub_data_buf_head = (char *)slot->buffer + i * QBUF_MEMALIGN_SIZE;
        if (g_qbuf_pool.base.mode == UMQ_BUF_SPLIT) {
            header_buffer = sub_data_buf_head + g_qbuf_pool.exp_pool_with_date.sub_slot_data_buf_size;
        }
        buf_init_with_mode(sub_data_buf_head, header_buffer, blk_num, blk_size, mempool_id, true, g_qbuf_pool.base.mode,
            &slot->free_block_list);
        remain_blk_count -= sub_slot_blk_count;
    }

    int ret = g_qbuf_pool.base.seg_ops.register_seg_callback(NULL, mempool_id, slot->buffer, slot->total_buf_size);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to register expansion pool seg, ret: %d\n", ret);
        goto FREE_BUFFER;
    }

    return UMQ_SUCCESS;

FREE_BUFFER:
    free(slot->buffer);
    slot->buffer = NULL;

ROLLBACK_MEM_SIZE:
    __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, total_size, __ATOMIC_ACQ_REL);

    return ret;
}

static int slot_without_data_init(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    uint64_t blk_count = exp_pool->expansion_block_count;
    uint64_t total_size = blk_count * (uint32_t)sizeof(umq_buf_t);

    if (!try_inc_atomic_exp_mem_size(total_size)) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "expand mem size max: %llu, now expand mem size: %llu, expand buf pool need: %llu, expand failed\n",
            g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size, total_size);
        return -UMQ_ERR_ENOMEM;
    }

    slot->buffer = (void *)memalign(umq_buf_size_small(), total_size);
    if (slot->buffer == NULL) {
        __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, total_size, __ATOMIC_ACQ_REL);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion pool memory\n");
        return -UMQ_ERR_ENOMEM;
    }

    slot->header_buffer = (char *)slot->buffer;
    slot->total_buf_size = total_size;
    slot->total_block_cnt = blk_count;
    slot->free_block_cnt = blk_count;
    buf_init_with_mode(NULL, slot->header_buffer, slot->total_block_cnt, 0,
        (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min), false, UMQ_BUF_SPLIT, &slot->free_block_list);
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
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "expansion pool invalid\n");
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
            free(shrink_param);
            continue;
        }

        // if the expansion pool is used again, do not release it
        if (slot->free_block_cnt != slot->total_block_cnt) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            free(shrink_param);
            continue;
        }
        exp_pool->exp_slot_list[shrink_param->slot_id] = NULL;

        exp_pool->expansion_count -= 1;
        exp_pool->exp_total_block_num -= slot->total_block_cnt;
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);

        slot_uninit(shrink_param->with_data, exp_pool, slot);
        free_expansion_pool_slot(exp_pool, slot);
        free(shrink_param);
        exp_pool->total_shrink_count++;
    }

    __atomic_store_n(&exp_pool->is_async_shrinking, 0, __ATOMIC_RELEASE);
    return NULL;
}

void async_shrink_global_pool(bool with_data, qbuf_expansion_pool_t *exp_pool, uint32_t slot_id)
{
    if (g_qbuf_pool.base.block_pool.disable_scale_cap) {
        return;
    }

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

uint64_t return_list_to_pools(umq_buf_t *local_head,
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
            if (batch_mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID && batch_mempool_id != UMQ_TINY_QBUF_MEMPOOL_ID) {
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
        if (batch_mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID && batch_mempool_id != UMQ_TINY_QBUF_MEMPOOL_ID) {
            return_batch_to_expansion_pool(batch_mempool_id, batch_head, batch_tail, batch_cnt, with_data);
        } else {
            QBUF_LIST_NEXT(batch_tail) = QBUF_LIST_FIRST(global_head);
            QBUF_LIST_FIRST(global_head) = batch_head;
            *global_buf_cnt += batch_cnt;
        }
    }

    return return_buf_cnt;
}

void *umq_io_buf_malloc(umq_buf_mode_t buf_mode, uint64_t size)
{
    if (g_buffer_addr != NULL) {
        return g_buffer_addr;
    }

    uint64_t min_size = umq_buf_size_small();
    if (buf_mode == UMQ_BUF_SPLIT) {
        min_size = umq_buf_size_small() +
            ((uint64_t)UMQ_EMPTY_HEADER_COEFFICIENT + 1) * (uint32_t)sizeof(umq_buf_t);
    }
    g_total_len = size == 0 ? UMQ_BUF_DEFAULT_TOTAL_SIZE : size;
    g_buffer_addr = umq_qbuf_base_io_buf_malloc(g_total_len, min_size);
    if (g_buffer_addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq qbuf memory alloc failed, size %lu, expect at least %lu\n",
            g_total_len, min_size);
        g_total_len = 0;
        return NULL;
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "malloc umq qbuf io buf %lu bytes\n", g_total_len);
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
    if (block_size < BLOCK_SIZE_4K || block_size >= BLOCK_SIZE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "block size %d is invalid\n", block_size);
        return -UMQ_ERR_EINVAL;
    }

    if (block_size == BLOCK_SIZE_4K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_4K;
    } else if (block_size == BLOCK_SIZE_8K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_8K;
    } else if (block_size == BLOCK_SIZE_16K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_16K;
    } else if (block_size == BLOCK_SIZE_32K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_32K;
    } else {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_64K;
    }

    return UMQ_SUCCESS;
}

uint8_t umq_buf_size_pow_small(void)
{
    return g_umq_qbuf_size_pow_small;
}

uint64_t umq_buf_to_id(char *buf, bool shm, bool with_data)
{
    // not support shm buf to id and name
    if (shm) {
        return 0;
    }

    if (umq_qbuf_mode_get() != UMQ_BUF_COMBINE) {
        return with_data ?
            buf_to_id_with_data_split((char *)g_qbuf_pool.base.header_buffer, buf) :
            buf_to_id_without_data_split((char *)g_qbuf_pool.ext_header_buffer, buf);
    }

    return buf_to_id_combine((char *)g_qbuf_pool.base.data_buffer, buf, g_qbuf_pool.base.block_size);
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
    cfg->buf_addr = g_qbuf_pool.base.data_buffer;
    cfg->total_size = g_qbuf_pool.base.total_size;
    cfg->data_size = g_qbuf_pool.base.data_size;
    cfg->headroom_size = g_qbuf_pool.base.headroom_size;
    cfg->mode = g_qbuf_pool.base.mode;
}

// release all thread cache to global pool. should be called when thread exits
static void release_thread_cache(uint64_t id)
{
    if (!g_qbuf_pool.base.inited || !g_thread_cache.inited) {
        return;
    }

    release_thread_cache_impl(&g_thread_cache, &g_qbuf_pool.base.tls_pools, &g_qbuf_pool.base.block_pool);

    __atomic_fetch_sub(&g_total_local_cap_with_data, g_thread_cache.block_pool.capacity_with_data, __ATOMIC_ACQ_REL);
    __atomic_fetch_sub(&g_total_local_cap_without_data, g_thread_cache.block_pool.capacity_without_data,
        __ATOMIC_ACQ_REL);
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
            if (with_data && g_qbuf_pool.base.seg_ops.unregister_seg_callback != NULL && slot->buffer != NULL) {
                uint16_t mempool_id = (uint16_t)(slot->slot_id + exp_pool->expansion_pool_id_min);
                g_qbuf_pool.base.seg_ops.unregister_seg_callback(NULL, mempool_id);
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

    __atomic_store_n(&exp_pool->is_async_expanding, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&exp_pool->is_async_shrinking, 0, __ATOMIC_RELEASE);
}

static int umq_qbuf_exp_pool_inner_init(qbuf_expansion_pool_t *exp_pool, const qbuf_pool_cfg_t *cfg, bool with_data)
{
    exp_pool->exp_slot_list = NULL;
    exp_pool->expansion_count = 0;
    if (with_data) {
        exp_pool->expansion_block_count = (cfg->expansion_block_count == 0) ?
            umq_qbuf_expansion_count() : cfg->expansion_block_count;
        if (g_qbuf_pool.base.mode == UMQ_BUF_SPLIT) {
            exp_pool->sub_slot_blk_count = QBUF_MEMALIGN_SIZE / (umq_buf_size_small() + (uint32_t)sizeof(umq_buf_t));
        } else {
            exp_pool->sub_slot_blk_count = QBUF_MEMALIGN_SIZE / umq_buf_size_small();
        }
        exp_pool->sub_slot_count =
            (exp_pool->expansion_block_count + exp_pool->sub_slot_blk_count - 1) / exp_pool->sub_slot_blk_count;
        exp_pool->sub_slot_data_buf_size = exp_pool->sub_slot_blk_count * umq_buf_size_small();
    } else {
        exp_pool->expansion_block_count = UMQ_EMPTY_HEADER_COEFFICIENT *
            ((cfg->expansion_block_count == 0) ? umq_qbuf_expansion_count() : cfg->expansion_block_count);
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

static int umq_qbuf_expansion_pool_cfg_check(const qbuf_pool_cfg_t *cfg, uint64_t *max_umq_buf_pool_size)
{
    if (cfg->umq_buf_pool_max_size > QBUF_POOL_MEM_SIZE_MAX) {
        UMQ_VLOG_INFO(VLOG_UMQ, "the maximum value of expansion mem size max %llu exceed %llu\n",
            cfg->umq_buf_pool_max_size, QBUF_POOL_MEM_SIZE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    *max_umq_buf_pool_size = cfg->umq_buf_pool_max_size == 0 ?
        QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE : cfg->umq_buf_pool_max_size;
    uint64_t without_data_expand_mem_size = 0;
    if (cfg->mode == UMQ_BUF_SPLIT) {
        without_data_expand_mem_size = (uint64_t)sizeof(umq_buf_t) * UMQ_EMPTY_HEADER_COEFFICIENT *
            ((cfg->expansion_block_count == 0) ? umq_qbuf_expansion_count() : cfg->expansion_block_count);
    }

    if (*max_umq_buf_pool_size < cfg->total_size ||
        *max_umq_buf_pool_size - cfg->total_size < without_data_expand_mem_size) {
        UMQ_VLOG_INFO(VLOG_UMQ,
            "max buf pool size %llu is too small to support expand without data buf, required %llu\n",
            *max_umq_buf_pool_size, cfg->total_size + without_data_expand_mem_size);
        return -UMQ_ERR_EINVAL;
    }
    return UMQ_SUCCESS;
}

static int umq_qbuf_expansion_pool_init(const qbuf_pool_cfg_t *cfg)
{
    if (cfg->disable_scale_cap) {
        return UMQ_SUCCESS;
    }
    uint64_t max_umq_buf_pool_size = 0;
    int ret = umq_qbuf_expansion_pool_cfg_check(cfg, &max_umq_buf_pool_size);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    g_qbuf_pool.expansion_mem_size_max = max_umq_buf_pool_size - cfg->total_size;

    // with data;
    ret = umq_qbuf_exp_pool_inner_init(&g_qbuf_pool.exp_pool_with_date, cfg, true);
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

static void umq_qbuf_expansion_pool_uninit(void)
{
    if (g_qbuf_pool.base.block_pool.disable_scale_cap) {
        return;
    }
    // with data uninit
    umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_with_date, true);

    // without data uninit
    umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_without_date, false);
}

int umq_qbuf_pool_init(qbuf_pool_cfg_t *cfg)
{
    if (g_qbuf_pool.base.inited) {
        UMQ_VLOG_INFO(VLOG_UMQ, "qbuf pool has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    g_qbuf_pool.base.tls_pools.type = THREAD_CLOSURE_QBUF;
    g_qbuf_pool.base.tls_pools.closure = release_thread_cache;
    g_qbuf_pool.base.block_size = umq_buf_size_small();
    g_qbuf_pool.base.data_size = cfg->data_size;
    g_qbuf_pool.base.mempool_id = UMQ_QBUF_DEFAULT_MEMPOOL_ID;
    g_qbuf_pool.base.block_pool.disable_scale_cap = cfg->disable_scale_cap;
    g_qbuf_pool.base.tls_pools.default_tls_qbuf_pool_depth =
        cfg->disable_scale_cap ? QBUF_POOL_TLS_MAX : umq_qbuf_pool_tls_depth();
    g_qbuf_pool.base.tls_pools.batch_count = umq_qbuf_pool_batch_cnt();
    g_qbuf_pool.base.tls_pools.enable_tls_expand_qbuf_pool = true;
    g_qbuf_pool.base.support_without_data = true;
    g_qbuf_pool.base.fetch_fn = normal_qbuf_base_fetch;
    g_qbuf_pool.base.self_shrink_fn = normal_qbuf_base_self_shrink;
    uint32_t split_extra_header_count = cfg->disable_scale_cap ? UMQ_EMPTY_HEADER_COEFFICIENT : 0;
    int ret = qbuf_pool_base_init(&g_qbuf_pool.base, cfg, split_extra_header_count);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    g_qbuf_pool.disable_malloc_escape = cfg->disable_malloc_escape;

    ret = umq_qbuf_expansion_pool_init(cfg);
    if (ret != UMQ_SUCCESS) {
        goto BLOCK_POOL_UNINIT;
    }

    g_qbuf_pool.exp_pool_with_date.trigger_expand_block_num =
        g_qbuf_pool.base.total_block_num / QBUF_POOL_EXPANSION_RATIO;
    if (cfg->mode == UMQ_BUF_SPLIT) {
        g_qbuf_pool.ext_header_buffer = g_qbuf_pool.base.header_buffer +
            g_qbuf_pool.base.total_block_num * sizeof(umq_buf_t);
        if (cfg->disable_scale_cap) {
            uint64_t head_without_data_count = g_qbuf_pool.base.total_block_num * UMQ_EMPTY_HEADER_COEFFICIENT;
            buf_init_with_mode(NULL, g_qbuf_pool.ext_header_buffer, head_without_data_count, 0,
                UMQ_QBUF_DEFAULT_MEMPOOL_ID, false, UMQ_BUF_SPLIT, &g_qbuf_pool.base.block_pool.head_without_data);
            g_qbuf_pool.base.block_pool.buf_cnt_without_data = head_without_data_count;
        }
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        g_qbuf_pool.ext_header_buffer = NULL;
    } else {
        UMQ_VLOG_ERR(VLOG_UMQ, "buf mode: %d is invalid\n", cfg->mode);
        ret = -UMQ_ERR_EINVAL;
        goto EXPANSION_POOL_UNINIT;
    }
    g_total_escape_buf_cnt = 0;

    /* move without data expansion to control plane for reduce the first-packet I/O latency */
    ret = expand_global_pool(false);
    if (ret != UMQ_SUCCESS) {
        goto EXPANSION_POOL_UNINIT;
    }
    return UMQ_SUCCESS;

EXPANSION_POOL_UNINIT:
    umq_qbuf_expansion_pool_uninit();

BLOCK_POOL_UNINIT:
    umq_qbuf_base_uninit(&g_qbuf_pool.base, NULL);

    return ret;
}

void umq_qbuf_pool_uninit(void)
{
    if (!g_qbuf_pool.base.inited) {
        return;
    }

    release_thread_cache(0);

    umq_qbuf_expansion_pool_uninit();

    umq_qbuf_base_uninit(&g_qbuf_pool.base, NULL);
    memset(&g_qbuf_pool, 0, sizeof(qbuf_pool_t));

    __atomic_store_n(&g_total_local_cap_with_data, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_total_local_cap_without_data, 0, __ATOMIC_RELEASE);
}

// expand local pool capacity and fetch bufs from global
static ALWAYS_INLINE int umq_qbuf_local_pool_fetch_and_expand(
    uint32_t needed, local_block_pool_t *local_pool, bool with_data)
{
    if (g_qbuf_pool.base.block_pool.disable_scale_cap) {
        uint32_t fetch_count = 0;
        while (fetch_count < needed) {
            int32_t ret = fetch_from_global(&g_qbuf_pool.base.block_pool, local_pool, with_data,
                umq_qbuf_pool_batch_cnt());
            if (ret <= 0) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "fetch from global failed, fetch count: %u\n", needed);
                return ret;
            }
            fetch_count += (uint32_t)ret;
        }
        return UMQ_SUCCESS;
    }

    uint64_t *cap;
    volatile uint64_t *g_total;
    uint64_t *stats_fetch_buf_cnt;
    uint64_t *local_buf_cnt;
    umq_buf_list_t *local_head;
    if (with_data) {
        cap = &local_pool->capacity_with_data;
        g_total = &g_total_local_cap_with_data;
        stats_fetch_buf_cnt = &g_thread_cache.stats.tls_fetch_buf_cnt_with_data;

        local_buf_cnt = &local_pool->buf_cnt_with_data;
        local_head = &local_pool->head_with_data;
    } else {
        cap = &local_pool->capacity_without_data;
        g_total = &g_total_local_cap_without_data;
        stats_fetch_buf_cnt = &g_thread_cache.stats.tls_fetch_buf_cnt_without_data;

        local_buf_cnt = &local_pool->buf_cnt_without_data;
        local_head = &local_pool->head_without_data;
    }

    umq_buf_t *local_head_before = QBUF_LIST_FIRST(local_head);
    uint64_t local_cnt_before = *local_buf_cnt;

    // Round up based on batch size, with a minimum expansion of one batch each time.
    uint32_t batch_size = umq_qbuf_pool_batch_cnt();
    uint32_t target_fetch_count = qbuf_tls_round_batch(needed, batch_size);
    uint64_t grow = target_fetch_count;
    if ((*cap) + grow > g_qbuf_pool.base.tls_pools.tls_expand_qbuf_pool_depth) {
        grow = ((*cap) >= g_qbuf_pool.base.tls_pools.tls_expand_qbuf_pool_depth) ?
            0 : (g_qbuf_pool.base.tls_pools.tls_expand_qbuf_pool_depth - (*cap));
    }
    if ((*g_total) + grow > g_qbuf_pool.base.tls_pools.tls_qbuf_pool_depth) {
        grow = ((*g_total) >= g_qbuf_pool.base.tls_pools.tls_qbuf_pool_depth) ?
            0 : (g_qbuf_pool.base.tls_pools.tls_qbuf_pool_depth - (*g_total));
    }

    uint32_t fetch_count = 0;
    int32_t ret = 0;
    while (fetch_count < target_fetch_count) {
        ret = fetch_from_global(&g_qbuf_pool.base.block_pool, local_pool, with_data, batch_size);
        if (ret <= 0) {
            if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_ACQUIRE) == 0) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "fetch from global failed, fetch count: %u\n", target_fetch_count);
            }
            goto ROLLBACK;
        }
        fetch_count += (uint32_t)ret;
    }

    if (grow > 0) {
        *cap = (*cap) + grow;
        __atomic_fetch_add(g_total, grow, __ATOMIC_ACQ_REL);
    }

    *stats_fetch_buf_cnt += fetch_count;
    return UMQ_SUCCESS;

ROLLBACK:
    local_pool_rollback(local_head_before, local_cnt_before, local_pool, &g_qbuf_pool.base.block_pool, with_data);
    return ret;
}

static ALWAYS_INLINE void thread_cache_self_shrink(bool with_data)
{
    if (g_qbuf_pool.base.block_pool.disable_scale_cap) {
        return;
    }
    volatile uint64_t *g_total;
    if (with_data) {
        g_total = &g_total_local_cap_with_data;
    } else {
        g_total = &g_total_local_cap_without_data;
    }
    qbuf_tls_capacity_self_shrink(&g_qbuf_pool.base.block_pool, &g_thread_cache, with_data, g_total,
        umq_qbuf_pool_shrink_threshold());
}

static int normal_qbuf_base_fetch(uint32_t needed, local_block_pool_t *local_pool, bool with_data)
{
    return umq_qbuf_local_pool_fetch_and_expand(needed, local_pool, with_data);
}

static void normal_qbuf_base_self_shrink(bool with_data)
{
    thread_cache_self_shrink(with_data);
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
        if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_ACQUIRE) == 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "init %s slot failed\n", with_data ? "with data" : "without_data\n");
        }
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
    exp_pool->total_expansion_count++;
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

void async_expand_global_pool(bool with_data, uint64_t g_buf_cnt, bool disable_scale_cap)
{
    if (disable_scale_cap) {
        return;
    }

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
    if (arg == NULL) {
        __atomic_store_n(&exp_pool->is_async_expanding, 0, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "malloc async_expand_pool_param failed\n");
        return;
    }
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

static ALWAYS_INLINE int umq_qbuf_alloc_escape(umq_buf_list_t *list)
{
    char *buf_data = (char *)memalign(umq_buf_size_small(), umq_buf_size_small() + sizeof(umq_buf_t));
    if (buf_data == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "malloc buf data failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    umq_buf_t *qbuf = (umq_buf_t *)(uintptr_t)(buf_data + umq_buf_size_small());
    QBUF_LIST_NEXT(qbuf) = NULL;
    qbuf->umqh = UMQ_INVALID_HANDLE;
    qbuf->buf_data = buf_data;
    qbuf->data_size = umq_buf_size_small();
    qbuf->mempool_id = QBUF_POOL_MEMPOOL_ID_MAX;
    qbuf->buf_size = umq_buf_size_small() + (uint32_t)sizeof(umq_buf_t);
    qbuf->headroom_size = 0;
    qbuf->total_data_size = umq_buf_size_small();
    qbuf->first_fragment = true;
    qbuf->mempool_without_data = 0;

    QBUF_LIST_FIRST(list) = qbuf;
    (void)__atomic_add_fetch(&g_total_escape_buf_cnt, 1, __ATOMIC_ACQ_REL);
    return UMQ_SUCCESS;
}

int umq_qbuf_escape_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_qbuf_pool.base.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    if (g_qbuf_pool.disable_malloc_escape || request_size == 0 || num != 1 || list == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    uint32_t headroom_size = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ?
        option->headroom_size : g_qbuf_pool.base.headroom_size;
    if (request_size + headroom_size > umq_buf_size_small()) {
        return -UMQ_ERR_EINVAL;
    }
    return umq_qbuf_alloc_escape(list);
}

int umq_normal_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (((uint64_t)request_size * (uint64_t)num) > QBUF_POOL_MEM_SIZE_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "requested size %u multiplied by the requested num %u exceeds the memory pool size %llu\n",
            request_size, num, QBUF_POOL_MEM_SIZE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    qbuf_alloc_param_t param = {
        .request_size = request_size,
        .num = num,
        .list = list,
    };
    int ret = umq_qbuf_base_alloc(&g_qbuf_pool.base, &g_thread_cache, option, &param);
    if (ret == UMQ_SUCCESS) {
        return UMQ_SUCCESS;
    }

    bool explicit_normal = option != NULL && (option->flag & UMQ_ALLOC_FLAG_POOL_TYPE) != 0 &&
        option->pool_type == UMQ_ALLOC_POOL_NORMAL;
    if (request_size != 0 && !explicit_normal && param.actual_buf_count == 1 && !g_qbuf_pool.disable_malloc_escape) {
        return umq_qbuf_alloc_escape(list);
    }

    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq qbuf base alloc failed, "
        "suggestion: increase total_size or expansion_mem_size_max, ret: %d\n", ret);
    return ret;
}

void umq_qbuf_free(umq_buf_list_t *list)
{
    if (!g_qbuf_pool.base.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return;
    }

    if (QBUF_LIST_FIRST(list)->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX && !g_qbuf_pool.disable_malloc_escape) {
        free(QBUF_LIST_FIRST(list)->buf_data);
        (void)__atomic_sub_fetch(&g_total_escape_buf_cnt, 1, __ATOMIC_ACQ_REL);
        return;
    }

    umq_qbuf_base_free(&g_qbuf_pool.base, &g_thread_cache, list, false);
}

int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_qbuf_pool.base.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    return headroom_reset(qbuf, headroom_size, g_qbuf_pool.base.mode, g_qbuf_pool.base.block_size);
}

static ALWAYS_INLINE umq_buf_t *umq_qbuf_expansion_or_escape_data_to_head(void *data)
{
    bool find = false;
    uint32_t valid_slot = 0;
    qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_date;
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    for (uint32_t i = 0; i < exp_pool->expansion_pool_cnt_max && valid_slot < exp_pool->expansion_count; i++) {
        qbuf_expansion_pool_slot_t *slot = exp_pool->exp_slot_list[i];
        if (slot == NULL) {
            continue;
        }
        if (data >= slot->buffer && data < slot->header_buffer) {
            find = true;
            break;
        }
        valid_slot++;
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);

    if (!find) {
        if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_ACQUIRE) == 0) {
            return NULL;
        }
        uint64_t buffer_head = (uint64_t)(uintptr_t)floor_to_align(data, umq_buf_size_small());
        umq_buf_t *qbuf = (umq_buf_t *)(uintptr_t)(buffer_head + umq_buf_size_small());
        if (qbuf->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX && qbuf->buf_data == (void *)(uintptr_t)buffer_head) {
            return qbuf;
        }
        return NULL;
    }

    if (g_qbuf_pool.base.mode == UMQ_BUF_SPLIT) {
        uint64_t buffer_head = (uint64_t)(uintptr_t)data & (~(QBUF_MEMALIGN_SIZE - 1));
        uint64_t id = ((uint64_t)(uintptr_t)data - buffer_head) / umq_buf_size_small();
        return (umq_buf_t *)(uintptr_t)(buffer_head +
            g_qbuf_pool.exp_pool_with_date.sub_slot_data_buf_size + id * sizeof(umq_buf_t));
    }
    uint64_t buffer_head = (uint64_t)(uintptr_t)data & (~(QBUF_MEMALIGN_SIZE - 1));
    uint64_t id = ((uint64_t)(uintptr_t)data - buffer_head) / umq_buf_size_small();
    return (umq_buf_t *)(uintptr_t)(buffer_head + id * umq_buf_size_small());
}

umq_buf_t *umq_qbuf_data_to_head(void *data)
{
    if (!g_qbuf_pool.base.inited || data == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return NULL;
    }
    return umq_qbuf_base_data_to_head(&g_qbuf_pool.base, data);
}

umq_buf_t *umq_qbuf_expansion_data_to_head(void *data)
{
    if (!g_qbuf_pool.base.inited || data == NULL) {
        return NULL;
    }
    return umq_qbuf_expansion_or_escape_data_to_head(data);
}

uint32_t umq_qbuf_headroom_get(void)
{
    return g_qbuf_pool.base.headroom_size;
}

umq_buf_mode_t umq_qbuf_mode_get(void)
{
    return g_qbuf_pool.base.mode;
}

int umq_qbuf_pool_info_get(umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    if (!g_qbuf_pool.base.inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    if (qbuf_pool_stats->num >= UMQ_STATS_QBUF_POOL_TYPE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "count of qbuf pool info exceeds maximum %u\n", UMQ_STATS_QBUF_POOL_TYPE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq_qbuf_pool_base_info_get(&g_qbuf_pool.base, qbuf_pool_stats, true, UMQ_QBUF_POOL_TYPE_SMALL);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "failed to get qbuf pool base info, ret: %d\n", ret);
        return ret;
    }
    umq_buf_mode_t mode = g_qbuf_pool.base.mode;

    // expansion pool stats - with_data
    qbuf_expansion_pool_t *exp_with_data = &g_qbuf_pool.exp_pool_with_date;
    qbuf_pool_stats->exp_pool_with_data.expansion_count = exp_with_data->expansion_count;
    qbuf_pool_stats->exp_pool_with_data.exp_total_free_block_num = exp_with_data->exp_total_block_num;
    qbuf_pool_stats->exp_pool_with_data.total_expansion_count = exp_with_data->total_expansion_count;
    qbuf_pool_stats->exp_pool_with_data.total_shrink_count = exp_with_data->total_shrink_count;
    qbuf_pool_stats->exp_pool_with_data.exp_total_block_num =
        exp_with_data->expansion_count * exp_with_data->expansion_block_count;
    if (mode == UMQ_BUF_SPLIT) {
        qbuf_pool_stats->exp_pool_with_data.exp_total_mem_size =
            qbuf_pool_stats->exp_pool_with_data.exp_total_block_num *
                (umq_buf_size_small() + (uint32_t)sizeof(umq_buf_t));
    } else {
        qbuf_pool_stats->exp_pool_with_data.exp_total_mem_size =
            qbuf_pool_stats->exp_pool_with_data.exp_total_block_num * umq_buf_size_small();
    }

    // expansion pool stats - without_data
    qbuf_expansion_pool_t *exp_without_data = &g_qbuf_pool.exp_pool_without_date;
    qbuf_pool_stats->exp_pool_without_data.expansion_count = exp_without_data->expansion_count;
    qbuf_pool_stats->exp_pool_without_data.exp_total_free_block_num = exp_without_data->exp_total_block_num;
    qbuf_pool_stats->exp_pool_without_data.total_expansion_count = exp_without_data->total_expansion_count;
    qbuf_pool_stats->exp_pool_without_data.total_shrink_count = exp_without_data->total_shrink_count;
    qbuf_pool_stats->exp_pool_without_data.exp_total_block_num =
        exp_without_data->expansion_count * exp_without_data->expansion_block_count;
    qbuf_pool_stats->exp_pool_without_data.exp_total_mem_size =
        qbuf_pool_stats->exp_pool_without_data.exp_total_block_num * (uint32_t)sizeof(umq_buf_t);

    qbuf_pool_stats->escape_buf_cnt = __atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED);
    return UMQ_SUCCESS;
}

int umq_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    int ret = ops->register_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID,
                                         g_qbuf_pool.base.data_buffer, g_qbuf_pool.base.total_size);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    if (g_qbuf_pool.base.block_pool.disable_scale_cap) {
        return UMQ_SUCCESS;
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
    if (g_qbuf_pool.base.block_pool.disable_scale_cap) {
        return;
    }

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
