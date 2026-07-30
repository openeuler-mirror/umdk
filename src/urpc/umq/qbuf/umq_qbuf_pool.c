/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize qbuf pool function
 * Create: 2025-7-26
 * Note:
 * History: 2025-7-26
 */

#include <malloc.h>
#include <sys/mman.h>
#include <unistd.h>

#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_vlog.h"
#ifndef UMQ_QBUF_DEBUG
#undef UMQ_VLOG_DEBUG
#define UMQ_VLOG_DEBUG(__type, __format, ...) ((void)0)
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
#include "urpc_list.h"
#include "urpc_thread_closure.h"
#include "urpc_util.h"

#define QBUF_POOL_TLS_MAX (2048)        // max count of thread local buffer storage
#define QBUF_POOL_BATCH_CNT (64)        // batch size when fetch from global or return to global
#define QBUF_POOL_SHRINK_THRESHOLD (64) // self-driven shrink threshold: N/4 >= this value (N >= 256)
#define QBUF_POOL_SELF_SHRINK_RATIO (4) // adaptive shrink ratio(1/4)

#define QBUF_POOL_DEFAULT_EXPANSION_COUNT 8192
#define QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE (2ULL * 1024 * 1024 * 1024)
#define QBUF_POOL_MEM_SIZE_MAX (6ULL * 1024 * 1024 * 1024)
#define QBUF_POOL_CHECK_ASYNC_PERIOD_US (1000)
#define QBUF_POOL_WITH_ASYNC_EXIT_TIMEOUT_S (60)
#define QBUF_MEMALIGN_SIZE (2ULL * 1024 * 1024)

typedef struct qbuf_expansion_pool_slot {
    urpc_list_t node;    // linkage in exp_pool.slot_list
    uint32_t slot_id;    // global id (0-indexed, mapped to mempool_id = slot_id + QBUF_POOL_EXP_SLOT_ID_MIN)
    uint32_t size_class; // which size_class this slot serves (UMQ_QBUF_SIZE_CLASS_MAX = without_data)
    void *buffer;
    void *header_buffer;
    uint64_t total_buf_size;

    uint64_t total_block_cnt;
    uint64_t free_block_cnt;
    umq_buf_list_t free_block_list;
} qbuf_expansion_pool_slot_t;

typedef struct local_qbuf_pool {
    urpc_list_t tls_node;
    bool inited;
    local_block_pool_t block_pool;
    local_qbuf_pool_stats_t stats;
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
    volatile uint32_t is_expanding;
    volatile uint32_t is_shrinking;
    uint64_t trigger_expand_block_num;
    uint32_t expansion_block_count;
    uint32_t expansion_count;
    urpc_list_t slot_list; // linked list of slots (replaces exp_slot_list array)
    uint32_t slot_count;   // number of slots in slot_list
    uint64_t exp_total_block_num;
    async_shrink_pool_task_list_t shrink_task_list;
    uint64_t total_expansion_count;
    uint64_t total_shrink_count;
    uint64_t sub_slot_blk_count;
    uint64_t sub_slot_count;
    uint64_t sub_slot_data_buf_size;

} qbuf_expansion_pool_t;

// FLAT qbuf_pool_t (no base substruct): the test includes this file directly and accesses
// g_qbuf_pool.block_pool[sc], g_qbuf_pool.tls_pool_mem_budget, etc. without .base. indirection.
// qbuf_pool_base_t in base.h is kept for tiny/huge/shm pools (single-level, use [0]).
typedef struct qbuf_pool {
    bool inited;
    void *data_buffer;
    void *header_buffer;
    void *ext_header_buffer;
    uint64_t total_size;

    // multi-level size_class: block_sizes[i] = base * step_multiplier^i
    uint32_t size_class_count;
    uint32_t size_class_step_multiplier;
    uint32_t block_sizes[UMQ_QBUF_SIZE_CLASS_MAX];
    char *data_region_start[UMQ_QBUF_SIZE_CLASS_MAX];
    char *data_region_end[UMQ_QBUF_SIZE_CLASS_MAX];
    char *header_region_start[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t per_sc_block_count; // block count per size_class (block-equal-division)
    uint32_t headroom_size;
    uint32_t data_size;

    uint64_t total_block_num;
    umq_buf_mode_t mode;

    global_block_pool_t block_pool[UMQ_QBUF_SIZE_CLASS_MAX];

    uint64_t expansion_mem_size_max;
    volatile uint64_t exp_total_mem_pool_size;
    uint64_t expansion_size;
    uint32_t expansion_threshold;
    mempool_segment_ops_t seg_ops;
    qbuf_expansion_pool_t exp_pool_with_data[UMQ_QBUF_SIZE_CLASS_MAX];
    qbuf_expansion_pool_t exp_pool_without_date;

    uint64_t tls_pool_mem_budget;        // with_data global TLS bytes cap (default 96MB)
    uint64_t tls_expand_mem_budget;      // with_data per-thread TLS bytes cap (default 7/8 of tls_pool_mem_budget)
    uint64_t tls_qbuf_pool_depth;        // without_data global TLS count cap (default 12K)
    uint64_t tls_expand_qbuf_pool_depth; // without_data per-thread TLS count cap (default 7/8 of global)

    bool disable_scale_cap;
    bool disable_malloc_escape;
} qbuf_pool_t;

static qbuf_pool_t g_qbuf_pool = {0};

static void umq_flush_tls_nodata_to_global(void);
static __thread local_qbuf_pool_t g_thread_cache = {0};
static uint8_t g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_4K;

static urpc_list_t g_tls_register_head;
static pthread_spinlock_t g_tls_stats_lock;

// multi-level: with_data uses byte budget (shared across all size_class), without_data uses count cap.
// g_total_local_cap_with_data_bytes: sum of all threads' bytes_with_data (with_data global cap tracker).
// g_total_local_cap_without_data: sum of all threads' capacity_without_data (without_data global cap tracker).
static volatile uint64_t g_total_local_cap_with_data_bytes = 0;
static volatile uint64_t g_total_local_cap_without_data = 0;

static volatile uint64_t g_total_escape_buf_cnt = 0;

#define QBUF_POOL_TLS_QBUF_POOL_DEPTH (12 * 1024) // without_data global TLS pool capacity sum budget

static inline uint32_t umq_qbuf_pool_tls_depth(void)
{
    return QBUF_POOL_TLS_QBUF_POOL_DEPTH;
}

// ===== QBUF DEBUG STATS =====
// Debug statistics for multi-sc qbuf pool observability.
// Default OFF (g_qbuf_debug_enabled=0, log level=INFO). Enable at runtime:
//   - umq_qbuf_set_debug(1)   -- sets debug flag + lowers log level to DEBUG
//   - env UMQ_QBUF_DEBUG=1    -- auto-enables at pool init
// When OFF: hot-path counter accumulation is skipped via qbuf_debug_on() guard;
//           UMQ_VLOG_DEBUG messages are dropped by log-level gate. Zero overhead.
// When ON:  counters are non-atomic (approximate, per-thread interleaving is ok
//           for trend analysis); summary printed every QBUF_DBG_SUMMARY_INTERVAL allocs.
typedef struct qbuf_debug_stats {
    // alloc path breakdown (with_data / without_data)
    uint64_t alloc_with_data_tls_hit;         // TLS per-sc cache hit
    uint64_t alloc_with_data_fetch_global;    // batch fetch from global pool
    uint64_t alloc_with_data_fetch_expansion; // batch fetch from expansion pool
    uint64_t alloc_with_data_escape;          // fallback: borrow from larger sc
    uint64_t alloc_with_data_fetch_fail;      // all sources exhausted

    uint64_t alloc_nodata_tls_hit;
    uint64_t alloc_nodata_fetch_global;
    uint64_t alloc_nodata_fetch_expansion;
    uint64_t alloc_nodata_fetch_fail;
    uint64_t alloc_nodata_tls_flush_retry; // retried after tls nodata flush

    // pool expand/shrink (sync = caller thread; async = background thread)
    uint64_t expand_with_data_sync;
    uint64_t expand_with_data_async;
    uint64_t expand_without_data_sync;
    uint64_t expand_without_data_async;

    // global pool shrink (reclaim buffers to system)
    uint64_t shrink_with_data;
    uint64_t shrink_without_data;

    // TLS nodata flush (return unused nodata bufs to global)
    uint64_t tls_flush_nodata_count; // flush call count
    uint64_t tls_flush_nodata_bufs;  // total bufs flushed

    // free path
    uint64_t free_with_data;
    uint64_t free_without_data;

    // self-shrink (thread returns its own overage directly)
    uint64_t self_shrink_with_data;
    uint64_t self_shrink_without_data;

    // per-size-class alloc distribution (with_data only)
    uint64_t alloc_with_data_by_sc[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t alloc_with_data_bytes_by_sc[UMQ_QBUF_SIZE_CLASS_MAX];
} qbuf_debug_stats_t;

static qbuf_debug_stats_t g_dbg_stats = {0};
static __thread bool g_dbg_in_async_expand = false; // prevent recursive expand
static volatile uint64_t g_dbg_alloc_count = 0;     // total allocs for summary interval
#define QBUF_DBG_SUMMARY_INTERVAL 10000             // print summary every N allocs

static volatile int g_qbuf_debug_enabled = 0;

// Check if debug mode is on. Used to guard hot-path counter accumulation
// (avoid cache-line bounce overhead when debug is off).
static inline bool qbuf_debug_on(void)
{
#ifdef UMQ_QBUF_DEBUG
    return __atomic_load_n(&g_qbuf_debug_enabled, __ATOMIC_RELAXED) != 0;
#else
    return false;
#endif
}

// Toggle debug mode: sets flag + adjusts UMQ log level accordingly.
// No recompilation needed; safe to call from any thread at any time.
void umq_qbuf_set_debug(int enable)
{
    __atomic_store_n(&g_qbuf_debug_enabled, enable ? 1 : 0, __ATOMIC_RELEASE);
    umq_get_log_config()->ctx.level = enable ? UTIL_VLOG_LEVEL_DEBUG : UTIL_VLOG_LEVEL_INFO;
    UMQ_VLOG_INFO(VLOG_UMQ, "qbuf debug %s (env UMQ_QBUF_DEBUG=1 to enable at startup)\n",
                  enable ? "ENABLED" : "DISABLED");
}

static void qbuf_dbg_print_summary(void)
{
    if (!qbuf_debug_on())
        return;
    uint64_t wd_total = g_dbg_stats.alloc_with_data_tls_hit + g_dbg_stats.alloc_with_data_fetch_global +
                        g_dbg_stats.alloc_with_data_fetch_expansion + g_dbg_stats.alloc_with_data_escape +
                        g_dbg_stats.alloc_with_data_fetch_fail;
    uint64_t nd_total = g_dbg_stats.alloc_nodata_tls_hit + g_dbg_stats.alloc_nodata_fetch_global +
                        g_dbg_stats.alloc_nodata_fetch_expansion + g_dbg_stats.alloc_nodata_fetch_fail +
                        g_dbg_stats.alloc_nodata_tls_flush_retry;

    UMQ_VLOG_DEBUG(VLOG_UMQ, "=== ALLOC HIT SUMMARY (after %llu allocs) ===\n",
                   (unsigned long long)__atomic_load_n(&g_dbg_alloc_count, __ATOMIC_RELAXED));
    UMQ_VLOG_DEBUG(VLOG_UMQ,
                   "with_data total=%llu: TLS_hit=%llu(%.1f%%) fetch_global=%llu(%.1f%%) "
                   "fetch_expansion=%llu(%.1f%%) escape=%llu(%.1f%%) fail=%llu(%.1f%%)\n",
                   (unsigned long long)wd_total, (unsigned long long)g_dbg_stats.alloc_with_data_tls_hit,
                   wd_total ? 100.0 * g_dbg_stats.alloc_with_data_tls_hit / wd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_with_data_fetch_global,
                   wd_total ? 100.0 * g_dbg_stats.alloc_with_data_fetch_global / wd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_with_data_fetch_expansion,
                   wd_total ? 100.0 * g_dbg_stats.alloc_with_data_fetch_expansion / wd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_with_data_escape,
                   wd_total ? 100.0 * g_dbg_stats.alloc_with_data_escape / wd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_with_data_fetch_fail,
                   wd_total ? 100.0 * g_dbg_stats.alloc_with_data_fetch_fail / wd_total : 0);

    UMQ_VLOG_DEBUG(VLOG_UMQ,
                   "without_data total=%llu: TLS_hit=%llu(%.1f%%) fetch_global=%llu(%.1f%%) "
                   "fetch_expansion=%llu(%.1f%%) fail=%llu(%.1f%%) tls_flush_retry=%llu(%.1f%%)\n",
                   (unsigned long long)nd_total, (unsigned long long)g_dbg_stats.alloc_nodata_tls_hit,
                   nd_total ? 100.0 * g_dbg_stats.alloc_nodata_tls_hit / nd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_nodata_fetch_global,
                   nd_total ? 100.0 * g_dbg_stats.alloc_nodata_fetch_global / nd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_nodata_fetch_expansion,
                   nd_total ? 100.0 * g_dbg_stats.alloc_nodata_fetch_expansion / nd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_nodata_fetch_fail,
                   nd_total ? 100.0 * g_dbg_stats.alloc_nodata_fetch_fail / nd_total : 0,
                   (unsigned long long)g_dbg_stats.alloc_nodata_tls_flush_retry,
                   nd_total ? 100.0 * g_dbg_stats.alloc_nodata_tls_flush_retry / nd_total : 0);

    for (uint32_t i = 0; i < g_qbuf_pool.size_class_count; i++) {
        UMQ_VLOG_DEBUG(VLOG_UMQ, "  sc=%u blk_size=%u: allocs=%llu bytes=%llu\n", i, g_qbuf_pool.block_sizes[i],
                       (unsigned long long)g_dbg_stats.alloc_with_data_by_sc[i],
                       (unsigned long long)g_dbg_stats.alloc_with_data_bytes_by_sc[i]);
    }

    UMQ_VLOG_DEBUG(VLOG_UMQ, "expand: wd_sync=%llu wd_async=%llu nd_sync=%llu nd_async=%llu\n",
                   (unsigned long long)g_dbg_stats.expand_with_data_sync,
                   (unsigned long long)g_dbg_stats.expand_with_data_async,
                   (unsigned long long)g_dbg_stats.expand_without_data_sync,
                   (unsigned long long)g_dbg_stats.expand_without_data_async);
    UMQ_VLOG_DEBUG(VLOG_UMQ, "shrink: wd=%llu nd=%llu self_shrink: wd=%llu nd=%llu\n",
                   (unsigned long long)g_dbg_stats.shrink_with_data,
                   (unsigned long long)g_dbg_stats.shrink_without_data,
                   (unsigned long long)g_dbg_stats.self_shrink_with_data,
                   (unsigned long long)g_dbg_stats.self_shrink_without_data);
    UMQ_VLOG_DEBUG(VLOG_UMQ, "tls_flush_nodata: calls=%llu bufs=%llu\n",
                   (unsigned long long)g_dbg_stats.tls_flush_nodata_count,
                   (unsigned long long)g_dbg_stats.tls_flush_nodata_bufs);
    UMQ_VLOG_DEBUG(VLOG_UMQ, "free: wd=%llu nd=%llu\n", (unsigned long long)g_dbg_stats.free_with_data,
                   (unsigned long long)g_dbg_stats.free_without_data);
    UMQ_VLOG_DEBUG(VLOG_UMQ, "=== END SUMMARY ===\n");
}
// ===== END QBUF DEBUG STATS =====

// Global expansion pool id allocator (shared by all size_class, CAS-based, range [257, 1023))
static urpc_id_generator_t g_global_exp_id_gen;
// Lookup table: expansion slot id -> slot* (indexed by [id - QBUF_POOL_EXP_SLOT_ID_MIN])
static qbuf_expansion_pool_slot_t *g_exp_slot_table[QBUF_POOL_EXP_SLOT_TABLE_SIZE];

static void *g_buffer_addr = NULL;
static uint64_t g_total_len = 0;

static inline uint32_t umq_qbuf_pool_batch_cnt(void)
{
    return QBUF_POOL_BATCH_CNT;
}

static inline uint32_t umq_qbuf_pool_shrink_threshold(void)
{
    return QBUF_POOL_SHRINK_THRESHOLD;
}

// batch size when fetch from global or return to global; uniform 64 across all size_class
static inline uint32_t get_batch_count(uint32_t sc)
{
    (void)sc;
    return QBUF_POOL_BATCH_CNT;
}

// find smallest i where block_sizes[i] >= need; if need > max, return count-1
static inline uint32_t select_size_class(uint32_t need)
{
    for (uint32_t i = 0; i < g_qbuf_pool.size_class_count; i++) {
        if (g_qbuf_pool.block_sizes[i] >= need) {
            return i;
        }
    }
    return g_qbuf_pool.size_class_count - 1;
}

// Find which size_class's data_region contains buf_data; UMQ_QBUF_SIZE_CLASS_MAX if not found.
static inline uint32_t buf_data_to_size_class(void *buf_data)
{
    char *data = (char *)buf_data;
    uint32_t count = g_qbuf_pool.size_class_count;
    if (count == 0) {
        return UMQ_QBUF_SIZE_CLASS_MAX;
    }
    if (data < g_qbuf_pool.data_region_start[0] || data >= g_qbuf_pool.data_region_end[count - 1]) {
        return UMQ_QBUF_SIZE_CLASS_MAX;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (data < g_qbuf_pool.data_region_end[i]) {
            return i;
        }
    }
    return UMQ_QBUF_SIZE_CLASS_MAX;
}

// Derive size_class index from a block's blk_size in O(1).
static inline uint32_t blk_size_to_sc(uint32_t blk_size)
{
    if (blk_size == 0) {
        return UMQ_QBUF_SIZE_CLASS_MAX;
    }
    uint32_t base = g_qbuf_pool.block_sizes[0];
    uint32_t mult_log2 = (uint32_t)__builtin_ctz(g_qbuf_pool.size_class_step_multiplier);
    if (mult_log2 == 0) {
        return UMQ_QBUF_SIZE_CLASS_MAX;
    }
    uint32_t sc = ((uint32_t)__builtin_ctz(blk_size) - (uint32_t)__builtin_ctz(base)) / mult_log2;
    if (sc >= g_qbuf_pool.size_class_count || g_qbuf_pool.block_sizes[sc] != blk_size) {
        return UMQ_QBUF_SIZE_CLASS_MAX;
    }
    return sc;
}

static inline uint32_t umq_qbuf_expansion_count(void)
{
    return QBUF_POOL_DEFAULT_EXPANSION_COUNT;
}

static void free_expansion_pool_slot(qbuf_expansion_pool_slot_t *slot)
{
    urpc_id_generator_free(&g_global_exp_id_gen, slot->slot_id);
    if (slot->slot_id < QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
        g_exp_slot_table[slot->slot_id] = NULL;
    }
    if (slot->buffer != NULL) {
        free(slot->buffer);
        slot->buffer = NULL;
    }
    free(slot);
}

static int alloc_expansion_pool_slot(qbuf_expansion_pool_slot_t **slot, uint32_t size_class)
{
    uint32_t id = 0;
    int ret = urpc_id_generator_alloc(&g_global_exp_id_gen, 0, &id);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc global id, ret: %d\n", ret);
        return ret;
    }
    if (id >= QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
        urpc_id_generator_free(&g_global_exp_id_gen, id);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "global id %u exceeds table size %u\n", id, QBUF_POOL_EXP_SLOT_TABLE_SIZE);
        return -UMQ_ERR_ENOMEM;
    }
    qbuf_expansion_pool_slot_t *tmp_slot = (qbuf_expansion_pool_slot_t *)calloc(1, sizeof(qbuf_expansion_pool_slot_t));
    if (tmp_slot == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc qbuf_expansion_pool_slot_t\n");
        urpc_id_generator_free(&g_global_exp_id_gen, id);
        return -UMQ_ERR_ENOMEM;
    }

    tmp_slot->slot_id = id;
    tmp_slot->size_class = size_class;
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
    } while (!__atomic_compare_exchange_n(&g_qbuf_pool.exp_total_mem_pool_size, &before, sum, true, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE));
    return true;
}

static void slot_uninit(bool with_data, qbuf_expansion_pool_slot_t *slot)
{
    if (with_data && g_qbuf_pool.seg_ops.unregister_seg_callback != NULL) {
        g_qbuf_pool.seg_ops.unregister_seg_callback(NULL, (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN));
    }

    __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, slot->total_buf_size, __ATOMIC_RELEASE);

    if (slot->buffer != NULL) {
        free(slot->buffer);
        slot->buffer = NULL;
    }
}

static ALWAYS_INLINE void sub_slot_with_data_slplt_init(char *buffer, qbuf_expansion_pool_slot_t *slot,
                                                        uint16_t mempool_id, uint64_t blk_size, uint64_t blk_count,
                                                        uint64_t sub_slot_data_buf_size)
{
    char *header_buffer = (char *)buffer + sub_slot_data_buf_size;
    for (uint64_t i = 0; i < blk_count; i++) {
        umq_buf_t *buf = (umq_buf_t *)(header_buffer + i * sizeof(umq_buf_t));
        buf->umqh = UMQ_INVALID_HANDLE;
        buf->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
        buf->data_size = blk_size;
        buf->total_data_size = buf->data_size;
        buf->headroom_size = 0;
        buf->buf_data = buffer + i * blk_size;
        buf->mempool_without_data = 0;
        buf->mempool_id = mempool_id;
        buf->alloc_state = QBUF_ALLOC_STATE_FREE;
        (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
        QBUF_LIST_INSERT_HEAD(&slot->free_block_list, buf);
    }
}

static ALWAYS_INLINE void sub_slot_with_data_combine_init(char *buffer, qbuf_expansion_pool_slot_t *slot,
                                                          uint16_t mempool_id, uint64_t blk_size, uint64_t blk_count)
{
    for (uint64_t i = 0; i < blk_count; i++) {
        umq_buf_t *buf = (umq_buf_t *)(buffer + i * blk_size);
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

static int slot_with_data_init(uint32_t sc, qbuf_expansion_pool_slot_t *slot)
{
    int ret = 0;
    char *sub_data_buf_head = NULL;
    uint64_t remain_blk_count = 0;
    qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_data[sc];
    uint64_t blk_size = g_qbuf_pool.block_sizes[sc];
    uint64_t blk_count = exp_pool->expansion_block_count;
    uint64_t sub_slot_blk_count = exp_pool->sub_slot_blk_count;
    uint64_t sub_slot_count = exp_pool->sub_slot_count;
    uint64_t sub_slot_data_buf_size = exp_pool->sub_slot_data_buf_size;
    uint64_t total_size = QBUF_MEMALIGN_SIZE * sub_slot_count;
    if (!try_inc_atomic_exp_mem_size(total_size)) {
        if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED) == 0) {
            UMQ_LIMIT_VLOG_ERR(
                VLOG_UMQ,
                "expand mem size max: %llu, now expand mem size: %llu, expand buf pool need: %llu, expand failed\n",
                g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size, total_size);
        }
        return -UMQ_ERR_ENOMEM;
    }
    uint16_t mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);

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

    remain_blk_count = blk_count;
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        for (uint64_t i = 0; i < sub_slot_count; i++) {
            sub_data_buf_head = (char *)slot->buffer + i * QBUF_MEMALIGN_SIZE;
            sub_slot_with_data_slplt_init(sub_data_buf_head, slot, mempool_id, blk_size,
                                          sub_slot_blk_count < remain_blk_count ? sub_slot_blk_count : remain_blk_count,
                                          sub_slot_data_buf_size);
            remain_blk_count -= sub_slot_blk_count;
        }
    } else {
        for (uint64_t i = 0; i < sub_slot_count; i++) {
            sub_data_buf_head = (char *)slot->buffer + i * QBUF_MEMALIGN_SIZE;
            sub_slot_with_data_combine_init(
                sub_data_buf_head, slot, mempool_id, blk_size,
                sub_slot_blk_count < remain_blk_count ? sub_slot_blk_count : remain_blk_count);
            remain_blk_count -= sub_slot_blk_count;
        }
    }

    ret = g_qbuf_pool.seg_ops.register_seg_callback(NULL, mempool_id, slot->buffer, slot->total_buf_size);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to register expansion pool seg, ret: %d\n", ret);
        goto FREE_BUFFER;
    }

    return UMQ_SUCCESS;

FREE_BUFFER:
    free(slot->buffer);
    slot->buffer = NULL;

ROLLBACK_MEM_SIZE:
    __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, total_size, __ATOMIC_RELEASE);

    return -UMQ_ERR_ENOMEM;
}

static int slot_without_data_init(qbuf_expansion_pool_t *exp_pool, qbuf_expansion_pool_slot_t *slot)
{
    uint64_t blk_count = exp_pool->expansion_block_count;
    uint64_t total_size = blk_count * (uint32_t)sizeof(umq_buf_t);

    if (!try_inc_atomic_exp_mem_size(total_size)) {
        UMQ_LIMIT_VLOG_ERR(
            VLOG_UMQ,
            "expand mem size max: %llu, now expand mem size: %llu, expand buf pool need: %llu, expand failed\n",
            g_qbuf_pool.expansion_mem_size_max, g_qbuf_pool.exp_total_mem_pool_size, total_size);
        return -UMQ_ERR_ENOMEM;
    }

    slot->buffer = (void *)memalign(umq_buf_size_small(), total_size);
    if (slot->buffer == NULL) {
        __atomic_fetch_sub(&g_qbuf_pool.exp_total_mem_pool_size, total_size, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "failed to alloc expansion pool memory\n");
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
        buf->mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
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
        if (shrink_param->slot_id >= QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            free(shrink_param);
            continue;
        }
        qbuf_expansion_pool_slot_t *slot = g_exp_slot_table[shrink_param->slot_id];
        if (slot == NULL) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "exp slot not exist, slot id %u\n", shrink_param->slot_id);
            free(shrink_param);
            continue;
        }

        if (slot->free_block_cnt != slot->total_block_cnt) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            free(shrink_param);
            continue;
        }
        urpc_list_remove(&slot->node);
        g_exp_slot_table[shrink_param->slot_id] = NULL;

        exp_pool->expansion_count -= 1;
        exp_pool->slot_count -= 1;
        exp_pool->exp_total_block_num -= slot->total_block_cnt;
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);

        bool shrink_wd = shrink_param->with_data;
        slot_uninit(shrink_wd, slot);
        free_expansion_pool_slot(slot);
        free(shrink_param);
        exp_pool->total_shrink_count++;
        if (shrink_wd) {
            if (qbuf_debug_on())
                g_dbg_stats.shrink_with_data++;
        } else {
            if (qbuf_debug_on())
                g_dbg_stats.shrink_without_data++;
        }
    }

    UMQ_VLOG_DEBUG(VLOG_UMQ, "%s_SHRINK_ASYNC completed, total_shrink=%llu\n",
                   exp_pool == &g_qbuf_pool.exp_pool_without_date ? "ND" : "WD",
                   (unsigned long long)exp_pool->total_shrink_count);
    __atomic_store_n(&exp_pool->is_shrinking, 0, __ATOMIC_RELEASE);
    return NULL;
}

static void async_shrink_global_pool(bool with_data, uint32_t sc, uint32_t slot_id)
{
    if (g_qbuf_pool.disable_scale_cap) {
        return;
    }

    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_data[sc] :
                                                  &g_qbuf_pool.exp_pool_without_date;
    async_shrink_push_param(with_data, exp_pool, slot_id);
    uint32_t async_shrink_expected = 0;
    if (!__atomic_compare_exchange_n(&exp_pool->is_shrinking, &async_shrink_expected, 1, true, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE)) {
        return;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, async_shrink_global_pool_callback, (void *)exp_pool) != 0) {
        __atomic_store_n(&exp_pool->is_shrinking, 0, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "async shrink global pool create failed, errno: %d\n", errno);
    } else {
        pthread_detach(tid);
    }
}

static ALWAYS_INLINE void return_batch_to_expansion_pool(uint16_t mempool_id, umq_buf_t *batch_head,
                                                         umq_buf_t *batch_tail, uint32_t batch_cnt, bool with_data,
                                                         uint32_t sc)
{
    uint32_t slot_id = mempool_id - QBUF_POOL_EXP_SLOT_ID_MIN;
    if (slot_id >= QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "slot id %u invalid, table size %u\n", slot_id, QBUF_POOL_EXP_SLOT_TABLE_SIZE);
        return;
    }

    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_data[sc] :
                                                  &g_qbuf_pool.exp_pool_without_date;

    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    qbuf_expansion_pool_slot_t *slot = g_exp_slot_table[slot_id];
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
        async_shrink_global_pool(with_data, sc, slot_id);
    }
}

uint64_t return_list_to_pools(umq_buf_t *local_head, umq_buf_list_t *global_head, uint64_t *global_buf_cnt,
                              bool with_data, uint32_t sc)
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
                UMQ_VLOG_DEBUG(VLOG_UMQ, "RETURN: %s sc=%u mpool=%u cnt=%u -> exp_slot\n",
                    with_data ? "data" : "nodata", sc, batch_mempool_id, batch_cnt);
                return_batch_to_expansion_pool(batch_mempool_id, batch_head, batch_tail, batch_cnt, with_data, sc);
            } else {
                UMQ_VLOG_DEBUG(VLOG_UMQ, "RETURN: %s sc=%u mpool=%u cnt=%u -> global_default\n",
                    with_data ? "data" : "nodata", sc, batch_mempool_id, batch_cnt);
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
            UMQ_VLOG_DEBUG(VLOG_UMQ, "RETURN: %s sc=%u mpool=%u cnt=%u -> exp_slot\n",
                with_data ? "data" : "nodata", sc, batch_mempool_id, batch_cnt);
            return_batch_to_expansion_pool(batch_mempool_id, batch_head, batch_tail, batch_cnt, with_data, sc);
        } else {
            UMQ_VLOG_DEBUG(VLOG_UMQ, "RETURN: %s sc=%u mpool=%u cnt=%u -> global_default\n",
                with_data ? "data" : "nodata", sc, batch_mempool_id, batch_cnt);
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

    g_buffer_addr = (void *)memalign(QBUF_MEMALIGN_SIZE, g_total_len);
    if (g_buffer_addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "memalign for qbuf pool failed, errno: %d\n", errno);
        g_total_len = 0;
        return NULL;
    }
    madvise(g_buffer_addr, g_total_len, MADV_HUGEPAGE);
    UMQ_VLOG_INFO(VLOG_UMQ, "malloc umq io buf %lu bytes, qbuf block size %u bytes\n", g_total_len,
                  umq_buf_size_small());

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
    } else if (block_size == BLOCK_SIZE_64K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_64K;
    } else if (block_size == BLOCK_SIZE_128K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_128K;
    } else if (block_size == BLOCK_SIZE_256K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_256K;
    } else if (block_size == BLOCK_SIZE_512K) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_512K;
    } else if (block_size == BLOCK_SIZE_1M) {
        g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_1M;
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
    if (shm) {
        return 0;
    }

    if (umq_qbuf_mode_get() != UMQ_BUF_COMBINE) {
        return with_data ? buf_to_id_with_data_split((char *)g_qbuf_pool.header_buffer, buf) :
                           buf_to_id_without_data_split((char *)g_qbuf_pool.ext_header_buffer, buf);
    }

    return buf_to_id_combine((char *)g_qbuf_pool.data_buffer, buf, g_qbuf_pool.block_sizes[0]);
}

uint64_t umq_buf_to_id_with_header(umq_buf_list_t *header, char *buf, bool shm, bool *with_data)
{
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
    cfg->data_size = g_qbuf_pool.block_sizes[0];
    cfg->headroom_size = g_qbuf_pool.headroom_size;
    cfg->mode = g_qbuf_pool.mode;
    cfg->size_class_count = g_qbuf_pool.size_class_count;
    cfg->size_class_step_multiplier = g_qbuf_pool.size_class_step_multiplier;
    cfg->expansion_size = g_qbuf_pool.expansion_size;
    cfg->expansion_threshold = g_qbuf_pool.expansion_threshold;
    cfg->tls_pool_mem_budget = g_qbuf_pool.tls_pool_mem_budget;
    cfg->tls_expand_mem_budget = g_qbuf_pool.tls_expand_mem_budget;
    cfg->disable_scale_cap = g_qbuf_pool.disable_scale_cap;
    cfg->disable_malloc_escape = g_qbuf_pool.disable_malloc_escape;
}

static void release_thread_cache(uint64_t id);

static ALWAYS_INLINE local_block_pool_t *get_thread_cache(void)
{
    if (!g_thread_cache.inited) {
        for (uint32_t i = 0; i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
            QBUF_LIST_INIT(&g_thread_cache.block_pool.head_with_data[i]);
            g_thread_cache.block_pool.buf_cnt_with_data[i] = 0;
            g_thread_cache.block_pool.bytes_with_data[i] = 0;
        }
        g_thread_cache.block_pool.capacity_without_data = 0;
        QBUF_LIST_INIT(&g_thread_cache.block_pool.head_without_data);
        g_thread_cache.block_pool.buf_cnt_without_data = 0;
        (void)memset(&g_thread_cache.stats, 0, sizeof(g_thread_cache.stats));
        g_thread_cache.stats.tid = (uint64_t)pthread_self();
        g_thread_cache.inited = true;
        urpc_thread_closure_register(THREAD_CLOSURE_QBUF, 0, release_thread_cache);
        (void)pthread_spin_lock(&g_tls_stats_lock);
        urpc_list_push_back(&g_tls_register_head, &g_thread_cache.tls_node);
        (void)pthread_spin_unlock(&g_tls_stats_lock);
    }

    return &g_thread_cache.block_pool;
}

// release all thread cache to global pool. should be called when thread exits
static ALWAYS_INLINE void release_thread_cache(uint64_t id)
{
    (void)id;
    if (!g_thread_cache.inited || !g_qbuf_pool.inited) {
        return;
    }

    (void)pthread_spin_lock(&g_tls_stats_lock);
    urpc_list_remove(&g_thread_cache.tls_node);
    (void)pthread_spin_unlock(&g_tls_stats_lock);

    local_block_pool_t *local_pool = get_thread_cache();
    uint64_t return_buf_cnt;
    uint64_t total_tls_bytes = 0;

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        if (local_pool->head_with_data[sc].first == NULL) {
            continue;
        }
        (void)pthread_spin_lock(&g_qbuf_pool.block_pool[sc].global_mutex);
        return_buf_cnt = return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_with_data[sc]),
                                              &g_qbuf_pool.block_pool[sc].head_with_data,
                                              &g_qbuf_pool.block_pool[sc].buf_cnt_with_data, true, sc);
        local_pool->buf_cnt_with_data[sc] -= return_buf_cnt;
        g_thread_cache.stats.tls_return_buf_cnt_with_data += return_buf_cnt;
        (void)pthread_spin_unlock(&g_qbuf_pool.block_pool[sc].global_mutex);
        total_tls_bytes += local_pool->bytes_with_data[sc];
    }

    if (local_pool->head_without_data.first != NULL) {
        (void)pthread_spin_lock(&g_qbuf_pool.block_pool[0].global_mutex);
        return_buf_cnt = return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_without_data),
                                              &g_qbuf_pool.block_pool[0].head_without_data,
                                              &g_qbuf_pool.block_pool[0].buf_cnt_without_data, false, 0);
        local_pool->buf_cnt_without_data -= return_buf_cnt;
        g_thread_cache.stats.tls_return_buf_cnt_without_data += return_buf_cnt;
        (void)pthread_spin_unlock(&g_qbuf_pool.block_pool[0].global_mutex);
    }

    __atomic_fetch_sub(&g_total_local_cap_with_data_bytes, total_tls_bytes, __ATOMIC_RELAXED);
    __atomic_fetch_sub(&g_total_local_cap_without_data, local_pool->capacity_without_data, __ATOMIC_RELAXED);

    g_thread_cache.inited = false;
}

static void umq_qbuf_exp_pool_inner_uninit(qbuf_expansion_pool_t *exp_pool, bool with_data)
{
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    exp_pool->inited = false;
    qbuf_expansion_pool_slot_t *slot, *next_slot;
    URPC_LIST_FOR_EACH_SAFE(slot, next_slot, node, &exp_pool->slot_list)
    {
        urpc_list_remove(&slot->node);
        if (with_data && g_qbuf_pool.seg_ops.unregister_seg_callback != NULL && slot->buffer != NULL) {
            uint16_t mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
            g_qbuf_pool.seg_ops.unregister_seg_callback(NULL, mempool_id);
        }
        if (slot->slot_id < QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
            g_exp_slot_table[slot->slot_id] = NULL;
        }
        urpc_id_generator_free(&g_global_exp_id_gen, slot->slot_id);
        if (slot->buffer != NULL) {
            free(slot->buffer);
        }
        free(slot);
    }
    urpc_list_init(&exp_pool->slot_list);
    exp_pool->slot_count = 0;
    exp_pool->expansion_count = 0;
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);

    (void)pthread_spin_lock(&exp_pool->shrink_task_list.lock);
    async_shrink_pool_param_t *cur_node, *next_node;
    URPC_LIST_FOR_EACH_SAFE(cur_node, next_node, node, &exp_pool->shrink_task_list.head)
    {
        urpc_list_remove(&cur_node->node);
        free(cur_node);
    }
    (void)pthread_spin_unlock(&exp_pool->shrink_task_list.lock);

    uint64_t start_time = urpc_get_cpu_cycles();
    uint32_t async_expand_expected = 0;
    while (!__atomic_compare_exchange_n(&exp_pool->is_expanding, &async_expand_expected, 1, true, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE) &&
           ((urpc_get_cpu_cycles() - start_time) / urpc_get_cpu_hz()) < QBUF_POOL_WITH_ASYNC_EXIT_TIMEOUT_S) {
        async_expand_expected = 0;
        usleep(QBUF_POOL_CHECK_ASYNC_PERIOD_US);
    }

    async_expand_expected = 0;
    while (!__atomic_compare_exchange_n(&exp_pool->is_shrinking, &async_expand_expected, 1, true, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE) &&
           ((urpc_get_cpu_cycles() - start_time) / urpc_get_cpu_hz()) < QBUF_POOL_WITH_ASYNC_EXIT_TIMEOUT_S) {
        async_expand_expected = 0;
        usleep(QBUF_POOL_CHECK_ASYNC_PERIOD_US);
    }

    (void)pthread_spin_destroy(&exp_pool->expansion_pool_lock);
    (void)pthread_spin_destroy(&exp_pool->shrink_task_list.lock);

    __atomic_store_n(&exp_pool->is_expanding, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&exp_pool->is_shrinking, 0, __ATOMIC_RELEASE);
}

static int umq_qbuf_exp_pool_inner_init(qbuf_expansion_pool_t *exp_pool, const qbuf_pool_cfg_t *cfg, bool with_data,
                                        uint32_t sc)
{
    exp_pool->expansion_count = 0;
    exp_pool->slot_count = 0;
    if (with_data) {
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        exp_pool->expansion_block_count = g_qbuf_pool.expansion_size / blk_size;
        if (exp_pool->expansion_block_count == 0) {
            exp_pool->expansion_block_count = 1;
        }
        if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
            exp_pool->sub_slot_blk_count = QBUF_MEMALIGN_SIZE / (blk_size + (uint32_t)sizeof(umq_buf_t));
        } else {
            exp_pool->sub_slot_blk_count = QBUF_MEMALIGN_SIZE / blk_size;
        }
        exp_pool->sub_slot_count =
            (exp_pool->expansion_block_count + exp_pool->sub_slot_blk_count - 1) / exp_pool->sub_slot_blk_count;
        exp_pool->sub_slot_data_buf_size = exp_pool->sub_slot_blk_count * blk_size;
    } else {
        exp_pool->expansion_block_count = umq_qbuf_expansion_count();
        exp_pool->trigger_expand_block_num = exp_pool->expansion_block_count * g_qbuf_pool.expansion_threshold / 100;
    }
    urpc_list_init(&exp_pool->slot_list);
    urpc_list_init(&exp_pool->shrink_task_list.head);
    (void)pthread_spin_init(&exp_pool->expansion_pool_lock, PTHREAD_PROCESS_PRIVATE);
    (void)pthread_spin_init(&exp_pool->shrink_task_list.lock, PTHREAD_PROCESS_PRIVATE);
    exp_pool->inited = true;
    return UMQ_SUCCESS;
}

static int umq_qbuf_expansion_pool_init(const qbuf_pool_cfg_t *cfg)
{
    if (cfg->disable_scale_cap) {
        return UMQ_SUCCESS;
    }
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        int ret = umq_qbuf_exp_pool_inner_init(&g_qbuf_pool.exp_pool_with_data[sc], cfg, true, sc);
        if (ret != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "init expansion pool with data sc %u failed, ret %d\n", sc, ret);
            for (uint32_t j = 0; j < sc; j++) {
                umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_with_data[j], true);
            }
            return ret;
        }
    }
    int ret = umq_qbuf_exp_pool_inner_init(&g_qbuf_pool.exp_pool_without_date, cfg, false, 0);
    if (ret != UMQ_SUCCESS) {
        for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
            umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_with_data[sc], true);
        }
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "init expansion pool without data failed, ret %d\n", ret);
        return ret;
    }
    return UMQ_SUCCESS;
}

static void umq_qbuf_expansion_pool_uninit(void)
{
    if (g_qbuf_pool.disable_scale_cap) {
        return;
    }
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_with_data[sc], true);
    }
    umq_qbuf_exp_pool_inner_uninit(&g_qbuf_pool.exp_pool_without_date, false);
}

static int init_size_class_config(const qbuf_pool_cfg_t *cfg, uint64_t max_umq_buf_pool_size)
{
    uint32_t base = umq_buf_size_small();
    uint32_t count = (cfg->size_class_count == 0) ? QBUF_POOL_DEFAULT_SIZE_CLASS_COUNT : cfg->size_class_count;
    uint32_t mult = (cfg->size_class_step_multiplier == 0) ? QBUF_POOL_DEFAULT_STEP_MULTIPLIER :
                                                             cfg->size_class_step_multiplier;

    if (mult < 2 || (mult & (mult - 1)) != 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "size_class_step_multiplier %u is not a power of 2\n", mult);
        return -UMQ_ERR_EINVAL;
    }
    if (count < 1 || count > UMQ_QBUF_SIZE_CLASS_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "size_class_count %u out of range [1, %u]\n", count, UMQ_QBUF_SIZE_CLASS_MAX);
        return -UMQ_ERR_EINVAL;
    }
    if (base < 4096 || base > (1024U * 1024U) || base % 4096 != 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "base block_size %u is not 4K * 2^n\n", base);
        return -UMQ_ERR_EINVAL;
    }
    uint32_t mult_pow = 0;
    uint32_t tmp_mult = mult;
    while (tmp_mult > 1) {
        mult_pow++;
        tmp_mult >>= 1;
    }
    for (uint32_t i = 0; i < count; i++) {
        uint64_t bs = (uint64_t)base << (i * mult_pow);
        if (bs > UINT32_MAX) {
            UMQ_VLOG_ERR(VLOG_UMQ, "block_sizes[%u]=%llu overflows uint32_t (base=%u mult=%u)\n", i,
                         (unsigned long long)bs, base, mult);
            return -UMQ_ERR_EINVAL;
        }
        if (bs > QBUF_POOL_MAX_BLOCK_SIZE) {
            UMQ_VLOG_ERR(VLOG_UMQ, "block_sizes[%u]=%llu exceeds max %u (base=%u mult=%u count=%u)\n", i,
                         (unsigned long long)bs, QBUF_POOL_MAX_BLOCK_SIZE, base, mult, count);
            return -UMQ_ERR_EINVAL;
        }
        g_qbuf_pool.block_sizes[i] = (uint32_t)bs;
    }
    uint64_t exp_size = (cfg->expansion_size == 0) ? QBUF_POOL_DEFAULT_EXPANSION_SIZE : cfg->expansion_size;
    if (!cfg->disable_scale_cap && (uint64_t)g_qbuf_pool.block_sizes[count - 1] > exp_size) {
        UMQ_VLOG_ERR(VLOG_UMQ, "max block_size %u exceeds expansion_size %llu\n", g_qbuf_pool.block_sizes[count - 1],
                     (unsigned long long)exp_size);
        return -UMQ_ERR_EINVAL;
    }
    g_qbuf_pool.size_class_count = count;
    g_qbuf_pool.size_class_step_multiplier = mult;
    g_qbuf_pool.mode = cfg->mode;
    g_qbuf_pool.total_size = cfg->total_size;
    g_qbuf_pool.headroom_size = cfg->headroom_size;
    g_qbuf_pool.data_size = base;
    g_qbuf_pool.disable_scale_cap = cfg->disable_scale_cap;
    g_qbuf_pool.expansion_mem_size_max = max_umq_buf_pool_size - g_total_len;
    g_qbuf_pool.seg_ops = cfg->seg_ops;
    g_qbuf_pool.tls_pool_mem_budget = (cfg->tls_pool_mem_budget == 0) ? QBUF_POOL_DEFAULT_TLS_POOL_MEM_BUDGET :
                                                                        cfg->tls_pool_mem_budget;
    g_qbuf_pool.tls_expand_mem_budget = (cfg->tls_expand_mem_budget == 0) ?
                                            umq_qbuf_pool_expand_max(g_qbuf_pool.tls_pool_mem_budget) :
                                            cfg->tls_expand_mem_budget;
    g_qbuf_pool.tls_qbuf_pool_depth = (cfg->tls_qbuf_pool_depth == 0) ?
                                          (cfg->disable_scale_cap ? QBUF_POOL_TLS_MAX : umq_qbuf_pool_tls_depth()) :
                                          cfg->tls_qbuf_pool_depth;
    g_qbuf_pool.tls_expand_qbuf_pool_depth = (cfg->tls_expand_qbuf_pool_depth == 0) ?
                                                 umq_qbuf_pool_expand_max(g_qbuf_pool.tls_qbuf_pool_depth) :
                                                 cfg->tls_expand_qbuf_pool_depth;
    uint32_t exp_threshold = (cfg->expansion_threshold == 0) ? QBUF_POOL_DEFAULT_EXPANSION_THRESHOLD :
                                                               cfg->expansion_threshold;
    if (exp_threshold < 1 || exp_threshold > 100) {
        UMQ_VLOG_ERR(VLOG_UMQ, "expansion_threshold %u out of range [1, 100]\n", exp_threshold);
        return -UMQ_ERR_EINVAL;
    }
    g_qbuf_pool.expansion_threshold = exp_threshold;
    g_qbuf_pool.expansion_size = exp_size;
    g_qbuf_pool.disable_malloc_escape = cfg->disable_malloc_escape;
    // block-equal-division per size_class:
    //   SPLIT    — N = total_size / (sum(block_sizes) + count * per_blk_overhead), per_blk_overhead depends on
    //              disable_scale_cap (see SPLIT layout branches below).
    //   COMBINE  — N = total_size / sum(block_sizes); the umq_buf_t header is inline in each block, no separate
    //              header region, so no per-block overhead is subtracted here.
    uint64_t sum_block_sizes = 0;
    for (uint32_t i = 0; i < count; i++) {
        sum_block_sizes += g_qbuf_pool.block_sizes[i];
    }
    uint64_t per_blk_overhead = 0;
    if (cfg->mode == UMQ_BUF_SPLIT) {
        per_blk_overhead = sizeof(umq_buf_t);
        if (cfg->disable_scale_cap) {
            per_blk_overhead = (UMQ_EMPTY_HEADER_COEFFICIENT + 1) * sizeof(umq_buf_t);
        }
    }
    g_qbuf_pool.per_sc_block_count = cfg->total_size / (sum_block_sizes + (uint64_t)count * per_blk_overhead);

    return 0;
}

static void init_split_mode_layout(const qbuf_pool_cfg_t *cfg, uint32_t count)
{
    // Layout B: centralized data, headers, ext
    uint64_t blk_nums[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t total_blk_num = 0;
    uint64_t total_header_size = 0;
    char *data_ptr = (char *)cfg->buf_addr;

    for (uint32_t sc = 0; sc < count; sc++) {
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        // per_sc_block_count already factors in disable_scale_cap (see init_size_class_config).
        uint64_t blk_num = g_qbuf_pool.per_sc_block_count;
        blk_nums[sc] = blk_num;
        total_blk_num += blk_num;
        total_header_size += blk_num * sizeof(umq_buf_t);
        data_ptr = (char *)(((uintptr_t)data_ptr + blk_size - 1) & ~((uintptr_t)blk_size - 1));
        g_qbuf_pool.data_region_start[sc] = data_ptr;
        data_ptr += blk_num * blk_size;
        g_qbuf_pool.data_region_end[sc] = data_ptr;
    }

    g_qbuf_pool.data_buffer = cfg->buf_addr;
    g_qbuf_pool.header_buffer = data_ptr;
    g_qbuf_pool.ext_header_buffer = data_ptr + total_header_size;
    g_qbuf_pool.total_block_num = total_blk_num;

    char *header_cur = (char *)g_qbuf_pool.header_buffer;
    (void)memset(g_qbuf_pool.header_region_start, 0, sizeof(g_qbuf_pool.header_region_start));
    for (uint32_t sc = 0; sc < count; sc++) {
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        uint64_t blk_num = blk_nums[sc];
        g_qbuf_pool.header_region_start[sc] = header_cur;
        for (uint64_t i = 0; i < blk_num; i++) {
            umq_buf_t *buf = (umq_buf_t *)(header_cur + i * sizeof(umq_buf_t));
            buf->umqh = UMQ_INVALID_HANDLE;
            buf->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
            buf->data_size = blk_size;
            buf->total_data_size = buf->data_size;
            buf->headroom_size = 0;
            buf->buf_data = g_qbuf_pool.data_region_start[sc] + i * blk_size;
            buf->mempool_without_data = 0;
            buf->mempool_id = 0;
            buf->alloc_state = QBUF_ALLOC_STATE_FREE;
            (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool[sc].head_with_data, buf);
        }
        g_qbuf_pool.block_pool[sc].buf_cnt_with_data = blk_num;
        g_qbuf_pool.block_pool[sc].buf_cnt_without_data = 0;
        g_qbuf_pool.exp_pool_with_data[sc].trigger_expand_block_num = blk_num * g_qbuf_pool.expansion_threshold / 100;
        header_cur += blk_num * sizeof(umq_buf_t);
        UMQ_VLOG_ERR(VLOG_UMQ, "qbuf pool SPLIT: sc=%u blk_size=%u num=%lu data_region=[%p,%p)\n", sc, blk_size,
                     (unsigned long)blk_num, (void *)g_qbuf_pool.data_region_start[sc],
                     (void *)g_qbuf_pool.data_region_end[sc]);
    }

    if (cfg->disable_scale_cap) {
        uint64_t head_without_data_count = total_blk_num * UMQ_EMPTY_HEADER_COEFFICIENT;
        for (uint64_t i = 0; i < head_without_data_count; i++) {
            umq_buf_t *head_buf = id_to_buf_without_data_split((char *)g_qbuf_pool.ext_header_buffer, i);
            head_buf->umqh = UMQ_INVALID_HANDLE;
            head_buf->buf_size = (uint32_t)sizeof(umq_buf_t);
            head_buf->data_size = 0;
            head_buf->total_data_size = 0;
            head_buf->headroom_size = 0;
            head_buf->buf_data = NULL;
            head_buf->mempool_without_data = 1;
            head_buf->mempool_id = 0;
            head_buf->alloc_state = QBUF_ALLOC_STATE_FREE;
            (void)memset(head_buf->qbuf_ext, 0, sizeof(head_buf->qbuf_ext));
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool[0].head_without_data, head_buf);
        }
        g_qbuf_pool.block_pool[0].buf_cnt_without_data = head_without_data_count;
    }
}

static void init_combine_mode_layout(const qbuf_pool_cfg_t *cfg, uint32_t count)
{
    uint64_t blk_nums[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t total_blk_num = 0;
    char *data_ptr = (char *)cfg->buf_addr;

    for (uint32_t sc = 0; sc < count; sc++) {
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        // per_sc_block_count is already the block count per SC (no extra header region in COMBINE mode).
        uint64_t blk_num = g_qbuf_pool.per_sc_block_count;
        blk_nums[sc] = blk_num;
        total_blk_num += blk_num;
        data_ptr = (char *)(((uintptr_t)data_ptr + blk_size - 1) & ~((uintptr_t)blk_size - 1));
        g_qbuf_pool.data_region_start[sc] = data_ptr;
        data_ptr += blk_num * blk_size;
        g_qbuf_pool.data_region_end[sc] = data_ptr;
    }

    g_qbuf_pool.data_buffer = cfg->buf_addr;
    g_qbuf_pool.header_buffer = NULL;
    g_qbuf_pool.ext_header_buffer = NULL;
    g_qbuf_pool.total_block_num = total_blk_num;

    for (uint32_t sc = 0; sc < count; sc++) {
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        uint64_t blk_num = blk_nums[sc];
        for (uint64_t i = 0; i < blk_num; i++) {
            umq_buf_t *buf = (umq_buf_t *)(g_qbuf_pool.data_region_start[sc] + i * blk_size);
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
            QBUF_LIST_INSERT_HEAD(&g_qbuf_pool.block_pool[sc].head_with_data, buf);
        }
        g_qbuf_pool.block_pool[sc].buf_cnt_with_data = blk_num;
        g_qbuf_pool.block_pool[sc].buf_cnt_without_data = 0;
        g_qbuf_pool.exp_pool_with_data[sc].trigger_expand_block_num = blk_num * g_qbuf_pool.expansion_threshold / 100;
    }
}

int umq_qbuf_pool_init(qbuf_pool_cfg_t *cfg)
{
    if (g_qbuf_pool.inited) {
        UMQ_VLOG_INFO(VLOG_UMQ, "qbuf pool has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    if (!cfg->disable_scale_cap && cfg->umq_buf_pool_max_size > QBUF_POOL_MEM_SIZE_MAX) {
        UMQ_VLOG_INFO(VLOG_UMQ, "the maximum value of expansion mem size max %llu exceed %llu\n",
                      cfg->umq_buf_pool_max_size, QBUF_POOL_MEM_SIZE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    uint64_t max_umq_buf_pool_size = cfg->umq_buf_pool_max_size == 0 ? QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE :
                                                                       cfg->umq_buf_pool_max_size;
    uint64_t without_data_expand_mem_size = 0;
    if (cfg->mode == UMQ_BUF_SPLIT) {
        without_data_expand_mem_size =
            (uint32_t)sizeof(umq_buf_t) * UMQ_EMPTY_HEADER_COEFFICIENT * umq_qbuf_expansion_count();
    }

    if (!cfg->disable_scale_cap && max_umq_buf_pool_size < g_total_len + without_data_expand_mem_size) {
        UMQ_VLOG_INFO(VLOG_UMQ,
                      "max buf pool size %llu is too small to support expand without data buf, required %llu\n",
                      max_umq_buf_pool_size, g_total_len + without_data_expand_mem_size);
        return -UMQ_ERR_EINVAL;
    }

    int sc_ret = init_size_class_config(cfg, max_umq_buf_pool_size);
    if (sc_ret != 0) {
        return sc_ret;
    }
    uint32_t count = g_qbuf_pool.size_class_count;

    // init global id gen and slot table
    if (!cfg->disable_scale_cap) {
        int id_ret =
            urpc_id_generator_init(&g_global_exp_id_gen, URPC_ID_GENERATOR_TYPE_BITMAP, QBUF_POOL_EXP_SLOT_TABLE_SIZE);
        if (id_ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "failed to init global_id_gen, ret: %d\n", id_ret);
            return -UMQ_ERR_ENOMEM;
        }
    }
    memset(g_exp_slot_table, 0, sizeof(g_exp_slot_table));

    // init block_pool[] array
    for (uint32_t sc = 0; sc < count; sc++) {
        int bp_ret = umq_qbuf_block_pool_init(&g_qbuf_pool.block_pool[sc]);
        if (bp_ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "block pool init sc %u failed\n", sc);
            for (uint32_t j = 0; j < sc; j++) {
                umq_qbuf_block_pool_uninit(&g_qbuf_pool.block_pool[j]);
            }
            if (!cfg->disable_scale_cap) {
                urpc_id_generator_uninit(&g_global_exp_id_gen);
            }
            return UMQ_FAIL;
        }
    }

    int ret = umq_qbuf_expansion_pool_init(cfg);
    if (ret != UMQ_SUCCESS) {
        goto BLOCK_POOL_UNINIT;
    }

    if (cfg->mode == UMQ_BUF_SPLIT) {
        init_split_mode_layout(cfg, count);
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        init_combine_mode_layout(cfg, count);
    } else {
        UMQ_VLOG_ERR(VLOG_UMQ, "buf mode: %d is invalid\n", cfg->mode);
        ret = -UMQ_ERR_EINVAL;
        goto EXPANSION_POOL_UNINIT;
    }

    (void)pthread_spin_init(&g_tls_stats_lock, PTHREAD_PROCESS_PRIVATE);
    urpc_list_init(&g_tls_register_head);
    g_qbuf_pool.inited = true;
    g_total_escape_buf_cnt = 0;
#ifdef UMQ_QBUF_DEBUG
    if (getenv("UMQ_QBUF_DEBUG") != NULL)
        umq_qbuf_set_debug(1);
#endif
    UMQ_VLOG_INFO(VLOG_UMQ, "=== QBUF POOL INIT ===\n");
    UMQ_VLOG_INFO(VLOG_UMQ, "mode=%s size_class_count=%u step_mult=%u\n",
                  g_qbuf_pool.mode == UMQ_BUF_SPLIT ? "SPLIT" : "COMBINE", g_qbuf_pool.size_class_count,
                  g_qbuf_pool.size_class_step_multiplier);
    for (uint32_t _sc = 0; _sc < g_qbuf_pool.size_class_count; _sc++) {
        UMQ_VLOG_INFO(VLOG_UMQ, "  sc=%u: blk_size=%u global_with_data=%llu trigger_expand=%llu\n", _sc,
                      g_qbuf_pool.block_sizes[_sc], (unsigned long long)g_qbuf_pool.block_pool[_sc].buf_cnt_with_data,
                      (unsigned long long)g_qbuf_pool.exp_pool_with_data[_sc].trigger_expand_block_num);
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "  global_without_data=%llu\n",
                  (unsigned long long)g_qbuf_pool.block_pool[0].buf_cnt_without_data);
    UMQ_VLOG_INFO(VLOG_UMQ, "  total_size=%llu per_sc_block_count=%llu expansion_mem_max=%llu\n",
                  (unsigned long long)g_qbuf_pool.total_size, (unsigned long long)g_qbuf_pool.per_sc_block_count,
                  (unsigned long long)g_qbuf_pool.expansion_mem_size_max);
    UMQ_VLOG_INFO(VLOG_UMQ, "  exp_size=%llu exp_threshold=%u\n", (unsigned long long)g_qbuf_pool.expansion_size,
                  g_qbuf_pool.expansion_threshold);
    UMQ_VLOG_INFO(VLOG_UMQ, "  tls_budget=%llu tls_expand_budget=%llu tls_qbuf_depth=%llu tls_expand_qbuf_depth=%llu\n",
                  (unsigned long long)g_qbuf_pool.tls_pool_mem_budget,
                  (unsigned long long)g_qbuf_pool.tls_expand_mem_budget,
                  (unsigned long long)g_qbuf_pool.tls_qbuf_pool_depth,
                  (unsigned long long)g_qbuf_pool.tls_expand_qbuf_pool_depth);
    UMQ_VLOG_INFO(VLOG_UMQ, "=== END QBUF POOL INIT ===\n");
    return UMQ_SUCCESS;

EXPANSION_POOL_UNINIT:
    umq_qbuf_expansion_pool_uninit();

BLOCK_POOL_UNINIT:
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        umq_qbuf_block_pool_uninit(&g_qbuf_pool.block_pool[sc]);
    }
    if (!cfg->disable_scale_cap) {
        urpc_id_generator_uninit(&g_global_exp_id_gen);
    }

    return ret;
}

void umq_qbuf_pool_uninit(void)
{
    if (!g_qbuf_pool.inited) {
        return;
    }

    UMQ_VLOG_DEBUG(VLOG_UMQ, "=== POOL UNINIT ===\n");
    qbuf_dbg_print_summary();
    UMQ_VLOG_DEBUG(VLOG_UMQ, "=== END POOL UNINIT ===\n");

    release_thread_cache(0);

    (void)pthread_spin_destroy(&g_tls_stats_lock);

    umq_qbuf_expansion_pool_uninit();

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        umq_qbuf_block_pool_uninit(&g_qbuf_pool.block_pool[sc]);
    }
    if (!g_qbuf_pool.disable_scale_cap) {
        urpc_id_generator_uninit(&g_global_exp_id_gen);
    }
    memset(&g_qbuf_pool, 0, sizeof(qbuf_pool_t));

    __atomic_store_n(&g_total_local_cap_with_data_bytes, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_total_local_cap_without_data, 0, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE int umq_qbuf_local_pool_fetch_and_expand(uint32_t needed, local_block_pool_t *local_pool,
                                                              bool with_data, uint32_t sc)
{
    int ret;
    uint32_t batch_cnt = get_batch_count(sc);
    uint32_t blk_size = g_qbuf_pool.block_sizes[sc];

    if (g_qbuf_pool.disable_scale_cap) {
        uint32_t fetch_count = 0;
        while (fetch_count < needed) {
            ret = fetch_from_global(&g_qbuf_pool.block_pool[sc], local_pool, with_data, sc, batch_cnt);
            if (ret <= 0) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "fetch from global failed, fetch count: %u\n", needed);
                return ret;
            }
            fetch_count += (uint32_t)ret;
        }
        return UMQ_SUCCESS;
    }

    umq_buf_list_t *local_head;
    uint64_t *local_buf_cnt;
    uint64_t *stats_fetch_buf_cnt;
    if (with_data) {
        local_buf_cnt = &local_pool->buf_cnt_with_data[sc];
        local_head = &local_pool->head_with_data[sc];
        stats_fetch_buf_cnt = &g_thread_cache.stats.tls_fetch_buf_cnt_with_data;
    } else {
        local_buf_cnt = &local_pool->buf_cnt_without_data;
        local_head = &local_pool->head_without_data;
        stats_fetch_buf_cnt = &g_thread_cache.stats.tls_fetch_buf_cnt_without_data;
    }

    umq_buf_t *local_head_before = QBUF_LIST_FIRST(local_head);
    uint64_t local_cnt_before = *local_buf_cnt;

    uint32_t need_batch = (needed + batch_cnt - 1) / batch_cnt * batch_cnt;

    uint64_t grow;
    if (with_data) {
        // with_data: byte-based two-level (per-thread tls_expand_mem_budget + global tls_pool_mem_budget)
        uint64_t grow_bytes = (uint64_t)need_batch * blk_size;
        uint64_t local_total_bytes = 0;
        for (uint32_t i = 0; i < g_qbuf_pool.size_class_count; i++) {
            local_total_bytes += local_pool->bytes_with_data[i];
        }
        if (local_total_bytes + grow_bytes > g_qbuf_pool.tls_expand_mem_budget) {
            grow_bytes = (local_total_bytes >= g_qbuf_pool.tls_expand_mem_budget) ?
                             0 :
                             (g_qbuf_pool.tls_expand_mem_budget - local_total_bytes);
        }
        uint64_t g_total = __atomic_load_n(&g_total_local_cap_with_data_bytes, __ATOMIC_RELAXED);
        if (g_total + grow_bytes > g_qbuf_pool.tls_pool_mem_budget) {
            grow_bytes = (g_total >= g_qbuf_pool.tls_pool_mem_budget) ? 0 : (g_qbuf_pool.tls_pool_mem_budget - g_total);
        }
        grow = grow_bytes / blk_size;
    } else {
        // without_data: count-based two-level (per-thread tls_expand_qbuf_pool_depth + global tls_qbuf_pool_depth)
        grow = need_batch;
        if (local_pool->capacity_without_data + grow > g_qbuf_pool.tls_expand_qbuf_pool_depth) {
            grow = (local_pool->capacity_without_data >= g_qbuf_pool.tls_expand_qbuf_pool_depth) ?
                       0 :
                       (g_qbuf_pool.tls_expand_qbuf_pool_depth - local_pool->capacity_without_data);
        }
        uint64_t g_total = __atomic_load_n(&g_total_local_cap_without_data, __ATOMIC_RELAXED);
        if (g_total + grow > g_qbuf_pool.tls_qbuf_pool_depth) {
            grow = (g_total >= g_qbuf_pool.tls_qbuf_pool_depth) ? 0 : (g_qbuf_pool.tls_qbuf_pool_depth - g_total);
        }
    }

    if (!with_data && g_qbuf_pool.block_pool[0].buf_cnt_without_data == 0 &&
        g_qbuf_pool.exp_pool_without_date.exp_total_block_num == 0) {
        umq_flush_tls_nodata_to_global();
    }
    uint32_t fetch_count = 0;
    while (fetch_count < need_batch) {
        UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH: %s sc=%u need_batch=%u fetched=%u global=%llu exp_total=%llu mpool=%u\n",
                       with_data ? "data" : "nodata", sc, need_batch, fetch_count,
                       (unsigned long long)g_qbuf_pool.block_pool[sc].buf_cnt_with_data,
                       (unsigned long long)(with_data ? g_qbuf_pool.exp_pool_with_data[sc].exp_total_block_num :
                                                        g_qbuf_pool.exp_pool_without_date.exp_total_block_num),
                       QBUF_LIST_FIRST(local_head) ? QBUF_LIST_FIRST(local_head)->mempool_id : 0xFFFF);
        ret = fetch_from_global(&g_qbuf_pool.block_pool[sc], local_pool, with_data, sc, batch_cnt);
        UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH result: ret=%d mpool=%u\n", ret,
                       (ret > 0 && QBUF_LIST_FIRST(local_head)) ? QBUF_LIST_FIRST(local_head)->mempool_id : 0xFFFF);
        if (ret > 0 && !with_data) {
            if (qbuf_debug_on())
                g_dbg_stats.alloc_nodata_fetch_global += ret;
        } else if (ret > 0 && with_data) {
            if (qbuf_debug_on())
                g_dbg_stats.alloc_with_data_fetch_global += ret;
        }
        if (ret <= 0) {
            if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED) == 0) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "fetch from global failed, fetch count: %u\n", need_batch);
                if (with_data) {
                    if (qbuf_debug_on())
                        g_dbg_stats.alloc_with_data_fetch_fail += (need_batch - fetch_count);
                }
                if (!with_data) {
                    UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH_NODATA_FAIL -> flush+retry mpool=0\n");
                    umq_flush_tls_nodata_to_global();
                    ret = fetch_from_global(&g_qbuf_pool.block_pool[sc], local_pool, with_data, sc, batch_cnt);
                    if (ret > 0) {
                        if (qbuf_debug_on())
                            g_dbg_stats.alloc_nodata_tls_flush_retry += ret;
                        fetch_count += (uint32_t)ret;
                        UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH_NODATA_RETRY_OK: ret=%d mpool=%u\n", ret,
                               (ret > 0 && QBUF_LIST_FIRST(local_head)) ? QBUF_LIST_FIRST(local_head)->mempool_id : 0xFFFF);
                        continue;
                    }
                    if (qbuf_debug_on())
                        g_dbg_stats.alloc_nodata_fetch_fail += (need_batch - fetch_count);
                    UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH_NODATA_RETRY_FAIL mpool=0\n");
                    goto ROLLBACK;
                }
            }
            goto ROLLBACK;
        }
        fetch_count += (uint32_t)ret;
    }

    if (grow > 0) {
        if (with_data) {
            uint64_t grow_bytes = grow * blk_size;
            local_pool->bytes_with_data[sc] += grow_bytes;
            __atomic_fetch_add(&g_total_local_cap_with_data_bytes, grow_bytes, __ATOMIC_RELAXED);
        } else {
            local_pool->capacity_without_data += grow;
            __atomic_fetch_add(&g_total_local_cap_without_data, grow, __ATOMIC_RELAXED);
        }
    }

    *stats_fetch_buf_cnt += fetch_count;
    return UMQ_SUCCESS;

ROLLBACK:
    UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH_ROLLBACK: %s sc=%u fetched=%u need=%u mpool=%u\n", with_data ? "data" : "nodata", sc,
                   fetch_count, need_batch,
                   local_head_before ? local_head_before->mempool_id : 0xFFFF);
    thread_local_pool_rollback(local_head_before, local_cnt_before, local_pool, &g_qbuf_pool.block_pool[sc], with_data,
                               sc);
    return ret;
}

static ALWAYS_INLINE void thread_cache_self_shrink(bool with_data, uint32_t sc)
{
    if (g_qbuf_pool.disable_scale_cap) {
        return;
    }

    if (with_data) {
        uint64_t remaining = g_thread_cache.block_pool.buf_cnt_with_data[sc];
        uint64_t shrink = remaining / QBUF_POOL_SELF_SHRINK_RATIO;
        if (shrink < umq_qbuf_pool_shrink_threshold() || g_thread_cache.block_pool.bytes_with_data[sc] == 0) {
            return;
        }
        uint64_t shrink_bytes = shrink * g_qbuf_pool.block_sizes[sc];
        g_thread_cache.block_pool.bytes_with_data[sc] -= shrink_bytes;
        __atomic_fetch_sub(&g_total_local_cap_with_data_bytes, shrink_bytes, __ATOMIC_RELAXED);

        uint64_t cap_cnt = g_thread_cache.block_pool.bytes_with_data[sc] / g_qbuf_pool.block_sizes[sc];
        if (cap_cnt < remaining) {
            return_to_global(&g_qbuf_pool.block_pool[sc], &g_thread_cache.block_pool, &g_thread_cache.stats, true, sc,
                             (uint32_t)cap_cnt);
            g_thread_cache.stats.tls_return_cnt_with_data++;
            if (qbuf_debug_on())
                g_dbg_stats.self_shrink_with_data++;
        }
    } else {
        // without_data self-shrink (old mechanism: capacity_without_data + g_total_local_cap_without_data)
        uint64_t remaining = g_thread_cache.block_pool.buf_cnt_without_data;
        uint64_t shrink = remaining / QBUF_POOL_SELF_SHRINK_RATIO;
        if (shrink < umq_qbuf_pool_shrink_threshold() || remaining == 0) {
            return;
        }
        if (g_thread_cache.block_pool.capacity_without_data == 0 && remaining > 0) {
            return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, false, 0,
                             0);
            g_thread_cache.stats.tls_return_cnt_without_data++;
            if (qbuf_debug_on())
                g_dbg_stats.self_shrink_without_data++;
            return;
        }
        if (g_thread_cache.block_pool.capacity_without_data == 0) {
            return;
        }
        if (shrink > g_thread_cache.block_pool.capacity_without_data) {
            shrink = g_thread_cache.block_pool.capacity_without_data;
        }
        g_thread_cache.block_pool.capacity_without_data -= shrink;
        __atomic_fetch_sub(&g_total_local_cap_without_data, shrink, __ATOMIC_RELAXED);
        if (g_thread_cache.block_pool.capacity_without_data < remaining) {
            return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, false, 0,
                             (uint32_t)g_thread_cache.block_pool.capacity_without_data);
            g_thread_cache.stats.tls_return_cnt_without_data++;
            if (qbuf_debug_on())
                g_dbg_stats.self_shrink_without_data++;
        }
    }
}

int expand_global_pool(bool with_data, uint32_t sc)
{
    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_data[sc] :
                                                  &g_qbuf_pool.exp_pool_without_date;
    qbuf_expansion_pool_slot_t *slot = NULL;
    uint32_t alloc_sc = with_data ? sc : UMQ_QBUF_SIZE_CLASS_MAX;
    int ret = alloc_expansion_pool_slot(&slot, alloc_sc);
    if (ret != UMQ_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "expansion pool count %u reached max %u\n", exp_pool->expansion_count,
                           QBUF_POOL_EXP_SLOT_TABLE_SIZE);
        return -UMQ_ERR_ENOMEM;
    }

    ret = with_data ? slot_with_data_init(sc, slot) : slot_without_data_init(exp_pool, slot);
    if (ret != UMQ_SUCCESS) {
        if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED) == 0) {
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
    urpc_list_push_back(&exp_pool->slot_list, &slot->node);
    g_exp_slot_table[slot->slot_id] = slot;
    exp_pool->slot_count++;
    exp_pool->expansion_count += 1;
    exp_pool->exp_total_block_num += slot->total_block_cnt;
    exp_pool->total_expansion_count++;
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    UMQ_VLOG_DEBUG(VLOG_UMQ,
                   "%s_EXPAND_%s sc=%u slot_id=%u mpool=%u blk_count=%llu total_size=%llu "
                   "exp_total_block=%llu exp_count=%u total_exp_mem=%llu/%llu\n",
                   with_data ? "WD" : "ND", g_dbg_in_async_expand ? "ASYNC" : "SYNC", sc, slot->slot_id,
                   (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN),
                   (unsigned long long)slot->total_block_cnt, (unsigned long long)slot->total_buf_size,
                   (unsigned long long)exp_pool->exp_total_block_num, exp_pool->expansion_count,
                   (unsigned long long)__atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED),
                   (unsigned long long)g_qbuf_pool.expansion_mem_size_max);
    if (qbuf_debug_on()) {
        if (g_dbg_in_async_expand) {
            if (with_data)
                g_dbg_stats.expand_with_data_async++;
            else
                g_dbg_stats.expand_without_data_async++;
            g_dbg_in_async_expand = false;
        } else {
            if (with_data)
                g_dbg_stats.expand_with_data_sync++;
            else
                g_dbg_stats.expand_without_data_sync++;
        }
    }
    return UMQ_SUCCESS;

UNINIT_SLOT:
    if (slot->slot_id < QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
        g_exp_slot_table[slot->slot_id] = NULL;
    }
    slot_uninit(with_data, slot);

FREE_SLOT:
    free_expansion_pool_slot(slot);
    return -UMQ_ERR_ENOMEM;
}

typedef struct async_expand_pool_param {
    qbuf_expansion_pool_t *exp_pool;
    bool with_data;
    uint32_t sc;
} async_expand_pool_param_t;

static void *async_expand_global_pool_callback(void *arg)
{
    async_expand_pool_param_t *async_param = (async_expand_pool_param_t *)arg;
    if (async_param == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "async param invalid\n");
        return NULL;
    }
    if (qbuf_debug_on())
        g_dbg_in_async_expand = true;
    (void)expand_global_pool(async_param->with_data, async_param->sc);
    __atomic_store_n(&async_param->exp_pool->is_expanding, 0, __ATOMIC_RELEASE);
    free(arg);
    return NULL;
}

void async_expand_global_pool(bool with_data, uint32_t sc, uint64_t g_buf_cnt)
{
    if (g_qbuf_pool.disable_scale_cap) {
        return;
    }

    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_data[sc] :
                                                  &g_qbuf_pool.exp_pool_without_date;
    if (g_buf_cnt + exp_pool->exp_total_block_num >= exp_pool->trigger_expand_block_num) {
        return;
    }

    uint32_t async_expand_expected = 0;
    if (!__atomic_compare_exchange_n(&exp_pool->is_expanding, &async_expand_expected, 1, true, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE)) {
        return;
    }

    pthread_t tid;
    async_expand_pool_param_t *arg = (async_expand_pool_param_t *)malloc(sizeof(async_expand_pool_param_t));
    if (arg == NULL) {
        __atomic_store_n(&exp_pool->is_expanding, 0, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "malloc async_expand_pool_param failed\n");
        return;
    }
    arg->exp_pool = exp_pool;
    arg->with_data = with_data;
    arg->sc = sc;
    if (pthread_create(&tid, NULL, async_expand_global_pool_callback, arg) != 0) {
        __atomic_store_n(&exp_pool->is_expanding, 0, __ATOMIC_RELEASE);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "async expand global pool failed, errno: %d\n", errno);
    } else {
        pthread_detach(tid);
        UMQ_VLOG_DEBUG(VLOG_UMQ, "%s_EXPAND_ASYNC_LAUNCH sc=%u g_buf_cnt=%llu trigger=%llu\n", with_data ? "WD" : "ND",
                       sc, (unsigned long long)g_buf_cnt, (unsigned long long)exp_pool->trigger_expand_block_num);
    }
}

uint32_t fetch_from_expansion_pools(bool with_data, uint32_t sc, uint32_t need, umq_buf_list_t *local_head,
                                    uint64_t *local_buf_cnt)
{
    uint32_t count = 0;
    uint32_t request = need;
    qbuf_expansion_pool_t *exp_pool = with_data ? &g_qbuf_pool.exp_pool_with_data[sc] :
                                                  &g_qbuf_pool.exp_pool_without_date;
    UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH_EXPANSION: %s sc=%u need=%u mpool_first=%u\n",
            with_data ? "data" : "nodata", sc, need,
            (urpc_list_is_empty(&exp_pool->slot_list) ? 0xFFFFu :
                ((qbuf_expansion_pool_slot_t *)(exp_pool->slot_list.next))->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN));
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    qbuf_expansion_pool_slot_t *slot;
    URPC_LIST_FOR_EACH(slot, node, &exp_pool->slot_list)
    {
        if (request == 0) {
            break;
        }
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
    if (count > 0) {
        if (with_data) {
            if (qbuf_debug_on())
                g_dbg_stats.alloc_with_data_fetch_expansion += count;
        } else {
            if (qbuf_debug_on())
                g_dbg_stats.alloc_nodata_fetch_expansion += count;
        }
    }
    UMQ_VLOG_DEBUG(VLOG_UMQ, "FETCH_EXPANSION result: %s sc=%u got=%u/%u mpool=%u\n", with_data ? "data" : "nodata", sc, count,
                   need,
                   (count > 0 && QBUF_LIST_FIRST(local_head)) ? QBUF_LIST_FIRST(local_head)->mempool_id : 0xFFFF);
    return count;
}

static ALWAYS_INLINE int umq_qbuf_alloc_escape(umq_buf_list_t *list, uint32_t sc)
{
    uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
    char *buf_data = (char *)memalign(blk_size, blk_size + sizeof(umq_buf_t));
    if (buf_data == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "malloc buf data failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    umq_buf_t *qbuf = (umq_buf_t *)(uintptr_t)(buf_data + blk_size);
    QBUF_LIST_NEXT(qbuf) = NULL;
    qbuf->umqh = UMQ_INVALID_HANDLE;
    qbuf->buf_data = buf_data;
    qbuf->data_size = blk_size;
    qbuf->mempool_id = QBUF_POOL_MEMPOOL_ID_MAX;
    qbuf->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
    qbuf->headroom_size = 0;
    qbuf->total_data_size = blk_size;
    qbuf->first_fragment = true;
    qbuf->mempool_without_data = 0;

    QBUF_LIST_FIRST(list) = qbuf;
    (void)__atomic_add_fetch(&g_total_escape_buf_cnt, 1, __ATOMIC_RELAXED);
    if (qbuf_debug_on())
        g_dbg_stats.alloc_with_data_escape++;
    UMQ_VLOG_DEBUG(VLOG_UMQ, "ALLOC_ESCAPE: sc=%u blk_size=%u total_escape=%llu mpool=1023\n", sc, blk_size,
                   (unsigned long long)__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED));
    return UMQ_SUCCESS;
}

int umq_qbuf_escape_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    if (g_qbuf_pool.disable_malloc_escape || request_size == 0 || num != 1 || list == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    uint32_t headroom_size = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ?
                                 option->headroom_size :
                                 g_qbuf_pool.headroom_size;
    if (request_size + headroom_size > g_qbuf_pool.block_sizes[0]) {
        return -UMQ_ERR_EINVAL;
    }
    return umq_qbuf_alloc_escape(list, 0);
}

int umq_normal_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }

    if (((uint64_t)request_size * (uint64_t)num) > QBUF_POOL_MEM_SIZE_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                           "requested size %u multiplied by the requested num %u exceeds the memory pool size %llu\n",
                           request_size, num, QBUF_POOL_MEM_SIZE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    bool flag = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0);
    qbuf_alloc_param_t param;
    param.shm = false;
    param.headroom_size = flag ? option->headroom_size : g_qbuf_pool.headroom_size;

    if (request_size == 0) {
        if (flag && param.headroom_size > 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "headroom_size not supported when request_size is 0\n");
            return -UMQ_ERR_EINVAL;
        }

        if (g_qbuf_pool.mode != UMQ_BUF_SPLIT) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "cannot alloc memory size 0 in combine mode\n");
            return -UMQ_ERR_ENOMEM;
        }

        UMQ_VLOG_DEBUG(VLOG_UMQ, "ALLOC nodata: need=%u tls=%llu %s mpool=%u\n", num,
                       (unsigned long long)local_pool->buf_cnt_without_data,
                       local_pool->buf_cnt_without_data >= num ? "TLS_HIT" : "TLS_MISS",
                       QBUF_LIST_FIRST(&local_pool->head_without_data) ? QBUF_LIST_FIRST(&local_pool->head_without_data)->mempool_id : 0xFFFF);
        if (local_pool->buf_cnt_without_data >= num) {
            if (qbuf_debug_on())
                g_dbg_stats.alloc_nodata_tls_hit += num;
        }
        if (local_pool->buf_cnt_without_data < num) {
            int ret =
                umq_qbuf_local_pool_fetch_and_expand(num - local_pool->buf_cnt_without_data, local_pool, false, 0);
            if (ret != UMQ_SUCCESS) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                                   "umq nodata qbuf local pool fetch and expand failed, "
                                   "suggestion: increase total_size or expansion_mem_size_max, ret: %d\n",
                                   ret);
                return ret;
            }
            g_thread_cache.stats.tls_fetch_cnt_without_data++;
        }

        umq_qbuf_alloc_nodata(local_pool, num, list, param.shm);
        thread_cache_self_shrink(false, 0);
        g_thread_cache.stats.alloc_cnt_without_data += num;
        if (qbuf_debug_on() &&
            __atomic_add_fetch(&g_dbg_alloc_count, num, __ATOMIC_RELAXED) % QBUF_DBG_SUMMARY_INTERVAL < num) {
            qbuf_dbg_print_summary();
        }
        return 0;
    }

    // multi-level: select size_class based on need
    uint32_t need = request_size + param.headroom_size;
    uint32_t sc = select_size_class(need);
    uint32_t blk_size = g_qbuf_pool.block_sizes[sc];

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        if (need <= blk_size) {
            param.actual_buf_count = num;
        } else {
            param.actual_buf_count = num * ((need + blk_size - 1) / blk_size);
        }
    } else {
        uint32_t align_size = blk_size - (uint32_t)sizeof(umq_buf_t);
        if (need <= align_size) {
            param.actual_buf_count = num;
        } else {
            param.actual_buf_count = num * ((need + align_size - 1) / align_size);
        }
    }

    uint32_t needed = param.actual_buf_count;
    uint32_t buf_cnt = (uint32_t)local_pool->buf_cnt_with_data[sc];

    UMQ_VLOG_DEBUG(VLOG_UMQ, "ALLOC data: req=%u num=%u sc=%u blk=%u need=%u tls=%u %s mpool=%u\n", request_size, num, sc,
                   blk_size, needed, buf_cnt, buf_cnt >= needed ? "TLS_HIT" : "TLS_MISS",
                   QBUF_LIST_FIRST(&local_pool->head_with_data[sc]) ? QBUF_LIST_FIRST(&local_pool->head_with_data[sc])->mempool_id : 0xFFFF);
    if (buf_cnt >= needed) {
        if (qbuf_debug_on())
            g_dbg_stats.alloc_with_data_tls_hit += needed;
    }
    if (buf_cnt < needed) {
        int ret = umq_qbuf_local_pool_fetch_and_expand(needed - buf_cnt, local_pool, true, sc);
        if (ret != UMQ_SUCCESS) {
            bool explicit_normal = option != NULL && (option->flag & UMQ_ALLOC_FLAG_POOL_TYPE) != 0 &&
                                   option->pool_type == UMQ_ALLOC_POOL_NORMAL;
            if (param.actual_buf_count == 1 && !explicit_normal && !g_qbuf_pool.disable_malloc_escape) {
                return umq_qbuf_alloc_escape(list, sc);
            }
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                               "umq with data qbuf local pool fetch and expand failed, "
                               "suggestion: increase total_size or expansion_mem_size_max, ret: %d\n",
                               ret);
            return ret;
        }
        g_thread_cache.stats.tls_fetch_cnt_with_data++;
    }

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        umq_qbuf_alloc_data_with_split(local_pool, request_size, &param, list, blk_size, sc);
    } else {
        umq_qbuf_alloc_data_with_combine(local_pool, request_size, &param, list, blk_size, sc);
    }

    thread_cache_self_shrink(true, sc);
    g_thread_cache.stats.alloc_cnt_with_data += param.actual_buf_count;
    if (qbuf_debug_on())
        g_dbg_stats.alloc_with_data_by_sc[sc] += param.actual_buf_count;
    if (qbuf_debug_on())
        g_dbg_stats.alloc_with_data_bytes_by_sc[sc] += (uint64_t)param.actual_buf_count * blk_size;
    if (qbuf_debug_on() &&
        __atomic_add_fetch(&g_dbg_alloc_count, param.actual_buf_count, __ATOMIC_RELAXED) % QBUF_DBG_SUMMARY_INTERVAL <
            param.actual_buf_count) {
        qbuf_dbg_print_summary();
    }
    return UMQ_SUCCESS;
}

void umq_qbuf_free(umq_buf_list_t *list)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return;
    }

    if (QBUF_LIST_FIRST(list)->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX && !g_qbuf_pool.disable_malloc_escape) {
        free(QBUF_LIST_FIRST(list)->buf_data);
        (void)__atomic_sub_fetch(&g_total_escape_buf_cnt, 1, __ATOMIC_RELAXED);
        UMQ_VLOG_DEBUG(VLOG_UMQ, "FREE_ESCAPE: buf=%p remaining_escape=%llu mpool=1023\n", QBUF_LIST_FIRST(list),
                       (unsigned long long)__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED));
        return;
    }

    local_block_pool_t *local_pool = get_thread_cache();
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT && QBUF_LIST_FIRST(list)->mempool_without_data == 1) {
        uint32_t cnt = release_batch(list, &local_pool->head_without_data, false);
        local_pool->buf_cnt_without_data += cnt;

        uint32_t cap = g_qbuf_pool.disable_scale_cap ? QBUF_POOL_TLS_MAX : (uint32_t)local_pool->capacity_without_data;
        if (local_pool->buf_cnt_without_data > cap) {
            uint32_t threshold = cap > umq_qbuf_pool_batch_cnt() ? cap - umq_qbuf_pool_batch_cnt() : 0;
            return_to_global(&g_qbuf_pool.block_pool[0], local_pool, &g_thread_cache.stats, false, 0, threshold);
            g_thread_cache.stats.tls_return_cnt_without_data++;
        }

        g_thread_cache.stats.free_cnt_without_data += cnt;
        if (qbuf_debug_on())
            g_dbg_stats.free_without_data += cnt;
        return;
    }

    // with_data: partition by size_class so each buf returns to its correct sc bucket
    umq_buf_t *sc_heads[UMQ_QBUF_SIZE_CLASS_MAX] = {NULL};
    umq_buf_t *sc_tails[UMQ_QBUF_SIZE_CLASS_MAX] = {NULL};
    uint32_t total_cnt = 0;
    umq_buf_t *cur = QBUF_LIST_FIRST(list);
    while (cur != NULL) {
        umq_buf_t *next = QBUF_LIST_NEXT(cur);
        uint32_t cur_blk = (g_qbuf_pool.mode == UMQ_BUF_SPLIT) ? cur->buf_size - (uint32_t)sizeof(umq_buf_t) :
                                                                 cur->buf_size;
        uint32_t cur_sc = blk_size_to_sc(cur_blk);
        QBUF_LIST_NEXT(cur) = NULL;
        if (cur_sc >= g_qbuf_pool.size_class_count) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "blk_size_to_sc: unmatched blk_size=%u, buf=%p\n", cur_blk, (void *)cur);
            cur = next;
            continue;
        }
        if (sc_heads[cur_sc] == NULL) {
            sc_heads[cur_sc] = cur;
            sc_tails[cur_sc] = cur;
        } else {
            QBUF_LIST_NEXT(sc_tails[cur_sc]) = cur;
            sc_tails[cur_sc] = cur;
        }
        total_cnt++;
        cur = next;
    }
    QBUF_LIST_FIRST(list) = NULL;

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        if (sc_heads[sc] == NULL) {
            continue;
        }
        umq_buf_list_t tmp;
        QBUF_LIST_FIRST(&tmp) = sc_heads[sc];
        uint32_t cnt = release_batch(&tmp, &local_pool->head_with_data[sc], false);
        local_pool->buf_cnt_with_data[sc] += cnt;

        uint32_t batch_cnt = get_batch_count(sc);
        uint64_t cap_bytes = g_qbuf_pool.disable_scale_cap ? (uint64_t)QBUF_POOL_TLS_MAX * g_qbuf_pool.block_sizes[sc] :
                                                             local_pool->bytes_with_data[sc];
        uint64_t actual_bytes = local_pool->buf_cnt_with_data[sc] * g_qbuf_pool.block_sizes[sc];
        if (actual_bytes > cap_bytes) {
            uint64_t threshold_bytes = (cap_bytes > (uint64_t)batch_cnt * g_qbuf_pool.block_sizes[sc]) ?
                                           cap_bytes - (uint64_t)batch_cnt * g_qbuf_pool.block_sizes[sc] :
                                           0;
            uint32_t threshold = (uint32_t)(threshold_bytes / g_qbuf_pool.block_sizes[sc]);
            return_to_global(&g_qbuf_pool.block_pool[sc], local_pool, &g_thread_cache.stats, true, sc, threshold);
            g_thread_cache.stats.tls_return_cnt_with_data++;
        }
    }

    g_thread_cache.stats.free_cnt_with_data += total_cnt;
    if (qbuf_debug_on())
        g_dbg_stats.free_with_data += total_cnt;
}

int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    uint32_t block_size;
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        block_size = qbuf->buf_size - (uint32_t)sizeof(umq_buf_t);
    } else {
        block_size = qbuf->buf_size;
    }
    return headroom_reset(qbuf, headroom_size, g_qbuf_pool.mode, block_size);
}

static inline umq_buf_t *escape_data_to_head(void *data)
{
    for (uint32_t i = 0; i < g_qbuf_pool.size_class_count; i++) {
        umq_buf_t *candidate = (umq_buf_t *)((char *)data + g_qbuf_pool.block_sizes[i]);
        if (candidate->buf_data == (char *)data && candidate->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
            return candidate;
        }
    }
    return (umq_buf_t *)((char *)data + umq_buf_size_small());
}

static ALWAYS_INLINE umq_buf_t *umq_qbuf_data_to_head_escape(void *data)
{
    bool find = false;
    qbuf_expansion_pool_t *found_pool = NULL;
    qbuf_expansion_pool_slot_t *found_slot = NULL;

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count && !find; sc++) {
        qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_data[sc];
        (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
        qbuf_expansion_pool_slot_t *slot;
        URPC_LIST_FOR_EACH(slot, node, &exp_pool->slot_list)
        {
            if (data >= slot->buffer && data < slot->header_buffer) {
                find = true;
                found_pool = exp_pool;
                found_slot = slot;
                break;
            }
        }
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    }

    if (!find) {
        return escape_data_to_head(data);
    }

    uint32_t blk_size = g_qbuf_pool.block_sizes[found_slot->size_class];
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        uint64_t buffer_head = (uint64_t)(uintptr_t)data & (~(QBUF_MEMALIGN_SIZE - 1));
        uint64_t id = ((uint64_t)(uintptr_t)data - buffer_head) / blk_size;
        return (umq_buf_t *)(uintptr_t)(buffer_head + found_pool->sub_slot_data_buf_size + id * sizeof(umq_buf_t));
    }
    uint64_t buffer_head = (uint64_t)(uintptr_t)data & (~(QBUF_MEMALIGN_SIZE - 1));
    uint64_t id = ((uint64_t)(uintptr_t)data - buffer_head) / blk_size;
    return (umq_buf_t *)(uintptr_t)(buffer_head + id * blk_size);
}
umq_buf_t *umq_qbuf_data_to_head(void *data)
{
    if (!g_qbuf_pool.inited || data == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return NULL;
    }

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        uint32_t sc = buf_data_to_size_class(data);
        if (sc < UMQ_QBUF_SIZE_CLASS_MAX) {
            uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
            uint64_t offset = (uint64_t)(uintptr_t)data - (uint64_t)(uintptr_t)g_qbuf_pool.data_region_start[sc];
            uint64_t id = offset / blk_size;
            umq_buf_t *candidate = (umq_buf_t *)(uintptr_t)(g_qbuf_pool.header_region_start[sc] + id * sizeof(umq_buf_t));
            /* Validate that the computed qbuf actually contains 'data'.
             * buf_data_to_size_class can return false positives for
             * expansion-pool blocks whose addresses happen to fall within
             * a normal-pool data_region's address range. */
            if (candidate->buf_data != NULL && candidate->buf_data <= (char *)data &&
                candidate->buf_data + blk_size > (char *)data) {
                return candidate;
            }
            /* Fall through to escape / expansion path. */
        }

        /* Always try expansion pool / escape lookup. Expansion-pool blocks
         * don't increment g_total_escape_buf_cnt, so we can't gate on it. */
        umq_buf_t *esc = umq_qbuf_data_to_head_escape(data);
        if (esc != NULL && esc->buf_data != NULL && esc->buf_data <= (char *)data &&
            esc->buf_data + esc->buf_size > (char *)data) {
            return esc;
        }

        uint64_t buffer_head = (uint64_t)(uintptr_t)data & (~(QBUF_MEMALIGN_SIZE - 1));
        uint64_t id = ((uint64_t)(uintptr_t)data - buffer_head) / umq_buf_size_small();
        return (umq_buf_t *)(uintptr_t)(buffer_head + g_qbuf_pool.exp_pool_with_data[0].sub_slot_data_buf_size +
                                        id * sizeof(umq_buf_t));
    }

    // COMBINE: check each sc's data_region
    uint32_t sc = buf_data_to_size_class(data);
    if (sc < UMQ_QBUF_SIZE_CLASS_MAX) {
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        uint64_t offset = (uint64_t)(uintptr_t)data - (uint64_t)(uintptr_t)g_qbuf_pool.data_region_start[sc];
        uint64_t id = offset / blk_size;
        umq_buf_t *candidate = (umq_buf_t *)(uintptr_t)(g_qbuf_pool.data_region_start[sc] + id * blk_size);
        /* Validate (see SPLIT mode comment above). */
        if (candidate->buf_data != NULL && candidate->buf_data <= (char *)data &&
            candidate->buf_data + blk_size > (char *)data) {
            return candidate;
        }
        /* Fall through to escape / expansion path. */
    }

    if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED) > 0) {
        return umq_qbuf_data_to_head_escape(data);
    }

    uint64_t buffer_head = (uint64_t)(uintptr_t)data & (~(QBUF_MEMALIGN_SIZE - 1));
    uint64_t id = ((uint64_t)(uintptr_t)data - buffer_head) / umq_buf_size_small();
    return (umq_buf_t *)(uintptr_t)(buffer_head + id * umq_buf_size_small());
}

umq_buf_t *umq_qbuf_expansion_data_to_head(void *data)
{
    if (!g_qbuf_pool.inited || data == NULL) {
        return NULL;
    }
    return umq_qbuf_data_to_head_escape(data);
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
    uint32_t block_size = g_qbuf_pool.block_sizes[0];
    uint32_t umq_buf_t_size = (uint32_t)sizeof(umq_buf_t);
    umq_buf_mode_t mode = g_qbuf_pool.mode;
    qbuf_pool_info->type = UMQ_QBUF_POOL_TYPE_SMALL;
    qbuf_pool_info->mode = mode;
    qbuf_pool_info->total_size = g_qbuf_pool.total_size;
    qbuf_pool_info->headroom_size = g_qbuf_pool.headroom_size;
    qbuf_pool_info->block_size = block_size;
    qbuf_pool_info->total_block_num = g_qbuf_pool.total_block_num;
    qbuf_pool_info->umq_buf_t_size = umq_buf_t_size;

    /* multi-level size_class config + per-sc raw state (new DFX fields).
     * These expose previously hidden g_qbuf_pool internals; the legacy sum-based
     * single-level fields above remain unchanged for existing consumers. */
    qbuf_pool_info->config.size_class_count = g_qbuf_pool.size_class_count;
    qbuf_pool_info->config.size_class_step_multiplier = g_qbuf_pool.size_class_step_multiplier;
    qbuf_pool_info->config.per_sc_block_count = g_qbuf_pool.per_sc_block_count;
    qbuf_pool_info->config.disable_scale_cap = (uint8_t)g_qbuf_pool.disable_scale_cap;
    qbuf_pool_info->config.disable_malloc_escape = (uint8_t)g_qbuf_pool.disable_malloc_escape;
    qbuf_pool_info->config.expansion_size = g_qbuf_pool.expansion_size;
    qbuf_pool_info->config.expansion_threshold = g_qbuf_pool.expansion_threshold;
    qbuf_pool_info->config.expansion_mem_size_max = g_qbuf_pool.expansion_mem_size_max;
    qbuf_pool_info->config.exp_total_mem_pool_size =
        __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED);
    qbuf_pool_info->config.tls_pool_mem_budget = g_qbuf_pool.tls_pool_mem_budget;
    qbuf_pool_info->config.tls_expand_mem_budget = g_qbuf_pool.tls_expand_mem_budget;
    qbuf_pool_info->config.tls_expand_qbuf_pool_depth = g_qbuf_pool.tls_expand_qbuf_pool_depth;
    qbuf_pool_info->sc_count = g_qbuf_pool.size_class_count;
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        umq_qbuf_sc_info_t *sci = &qbuf_pool_info->sc_info[sc];
        sci->blk_size = g_qbuf_pool.block_sizes[sc];
        sci->data_region_start = (uint64_t)(uintptr_t)g_qbuf_pool.data_region_start[sc];
        sci->data_region_end = (uint64_t)(uintptr_t)g_qbuf_pool.data_region_end[sc];
        sci->header_region_start = (uint64_t)(uintptr_t)g_qbuf_pool.header_region_start[sc];
        sci->buf_cnt_with_data = g_qbuf_pool.block_pool[sc].buf_cnt_with_data;
        sci->buf_cnt_without_data = g_qbuf_pool.block_pool[sc].buf_cnt_without_data;
        qbuf_expansion_pool_t *e = &g_qbuf_pool.exp_pool_with_data[sc];
        sci->exp_expansion_count = e->expansion_count;
        sci->exp_total_block_num = e->exp_total_block_num;
        sci->exp_total_expansion_count = e->total_expansion_count;
        sci->exp_total_shrink_count = e->total_shrink_count;
    }

    uint64_t total_buf_cnt_with_data = 0;
    uint64_t total_buf_cnt_without_data = 0;
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        total_buf_cnt_with_data += g_qbuf_pool.block_pool[sc].buf_cnt_with_data;
    }
    total_buf_cnt_without_data = g_qbuf_pool.block_pool[0].buf_cnt_without_data;

    if (mode == UMQ_BUF_SPLIT) {
        qbuf_pool_info->data_size = block_size;
        qbuf_pool_info->buf_size = block_size + umq_buf_t_size;
        qbuf_pool_info->available_mem.split.block_num_with_data = total_buf_cnt_with_data;
        qbuf_pool_info->available_mem.split.size_with_data = total_buf_cnt_with_data * (block_size + umq_buf_t_size);
        qbuf_pool_info->available_mem.split.block_num_without_data = total_buf_cnt_without_data;
        qbuf_pool_info->available_mem.split.size_without_data = total_buf_cnt_without_data * umq_buf_t_size;
    } else {
        qbuf_pool_info->data_size = block_size - umq_buf_t_size;
        qbuf_pool_info->buf_size = block_size;
        qbuf_pool_info->available_mem.combine.block_num_with_data = total_buf_cnt_with_data;
        qbuf_pool_info->available_mem.combine.size_with_data = total_buf_cnt_with_data * block_size;
    }
    qbuf_pool_stats->num++;

    uint64_t exp_count = 0;
    uint64_t exp_free_blocks = 0;
    uint64_t exp_total_blocks = 0;
    uint64_t exp_total_expansion = 0;
    uint64_t exp_total_shrink = 0;
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        qbuf_expansion_pool_t *e = &g_qbuf_pool.exp_pool_with_data[sc];
        exp_count += e->expansion_count;
        exp_free_blocks += e->exp_total_block_num;
        exp_total_blocks += (uint64_t)e->expansion_count * e->expansion_block_count;
        exp_total_expansion += e->total_expansion_count;
        exp_total_shrink += e->total_shrink_count;
    }
    qbuf_pool_stats->exp_pool_with_data.expansion_count = exp_count;
    qbuf_pool_stats->exp_pool_with_data.exp_total_free_block_num = exp_free_blocks;
    qbuf_pool_stats->exp_pool_with_data.total_expansion_count = exp_total_expansion;
    qbuf_pool_stats->exp_pool_with_data.total_shrink_count = exp_total_shrink;
    qbuf_pool_stats->exp_pool_with_data.exp_total_block_num = exp_total_blocks;
    if (mode == UMQ_BUF_SPLIT) {
        qbuf_pool_stats->exp_pool_with_data.exp_total_mem_size = exp_total_blocks * (block_size + umq_buf_t_size);
    } else {
        qbuf_pool_stats->exp_pool_with_data.exp_total_mem_size = exp_total_blocks * block_size;
    }

    qbuf_expansion_pool_t *exp_without_data = &g_qbuf_pool.exp_pool_without_date;
    qbuf_pool_stats->exp_pool_without_data.expansion_count = exp_without_data->expansion_count;
    qbuf_pool_stats->exp_pool_without_data.exp_total_free_block_num = exp_without_data->exp_total_block_num;
    qbuf_pool_stats->exp_pool_without_data.total_expansion_count = exp_without_data->total_expansion_count;
    qbuf_pool_stats->exp_pool_without_data.total_shrink_count = exp_without_data->total_shrink_count;
    qbuf_pool_stats->exp_pool_without_data.exp_total_block_num =
        exp_without_data->expansion_count * exp_without_data->expansion_block_count;
    qbuf_pool_stats->exp_pool_without_data.exp_total_mem_size =
        qbuf_pool_stats->exp_pool_without_data.exp_total_block_num * umq_buf_t_size;

    qbuf_pool_stats->local_qbuf_pool_num = 0;
    (void)pthread_spin_lock(&g_tls_stats_lock);
    local_qbuf_pool_t *pool_iter = NULL;
    URPC_LIST_FOR_EACH(pool_iter, tls_node, &g_tls_register_head)
    {
        if (qbuf_pool_stats->local_qbuf_pool_num >= UMQ_LOCAL_QBUF_POOL_MAX_NUM) {
            break;
        }
        umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[qbuf_pool_stats->local_qbuf_pool_num];
        (void)memset(s, 0, sizeof(*s));
        s->type = UMQ_QBUF_POOL_TYPE_SMALL;
        uint64_t sum_bytes = 0;
        uint64_t sum_cnt = 0;
        for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
            sum_bytes += pool_iter->block_pool.bytes_with_data[sc];
            sum_cnt += pool_iter->block_pool.buf_cnt_with_data[sc];
            /* per-sc TLS breakdown (new DFX field). capacity_with_data/buf_cnt_with_data
             * above are the SUM of these per-sc entries. */
            s->sc_bytes_with_data[sc] = pool_iter->block_pool.bytes_with_data[sc];
            s->sc_buf_cnt_with_data[sc] = pool_iter->block_pool.buf_cnt_with_data[sc];
        }
        s->sc_count = g_qbuf_pool.size_class_count;
        s->capacity_with_data = sum_bytes;
        s->buf_cnt_with_data = sum_cnt;
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
    (void)pthread_spin_unlock(&g_tls_stats_lock);
    qbuf_pool_stats->escape_buf_cnt = __atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED);

    /* count non-NULL slots in g_exp_slot_table (new DFX field) */
    uint32_t slot_used = 0;
    for (uint32_t i = 0; i < QBUF_POOL_EXP_SLOT_TABLE_SIZE; i++) {
        if (g_exp_slot_table[i] != NULL) {
            ++slot_used;
        }
    }
    qbuf_pool_info->exp_slot_used_count = slot_used;
    return UMQ_SUCCESS;
}

int umq_qbuf_register_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    int ret =
        ops->register_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID, g_qbuf_pool.data_buffer, g_qbuf_pool.total_size);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_data[sc];
        (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
        qbuf_expansion_pool_slot_t *slot;
        URPC_LIST_FOR_EACH(slot, node, &exp_pool->slot_list)
        {
            uint16_t mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
            ret = ops->register_seg_callback(ctx, mempool_id, slot->buffer, slot->total_buf_size);
            if (ret != UMQ_SUCCESS) {
                UMQ_VLOG_ERR(VLOG_UMQ, "failed to register expansion pool seg, ret: %d\n", ret);
                (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
                goto UNREGISTER_SEG;
            }
        }
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    }
    return UMQ_SUCCESS;

UNREGISTER_SEG:
    for (uint32_t i = 0; i < QBUF_POOL_EXP_SLOT_TABLE_SIZE; i++) {
        qbuf_expansion_pool_slot_t *slot = g_exp_slot_table[i];
        if (slot != NULL && slot->buffer != NULL) {
            uint16_t mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
            ops->unregister_seg_callback(ctx, mempool_id);
        }
    }
    ops->unregister_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
    return ret;
}

void umq_qbuf_unregister_seg(uint8_t *ctx, mempool_segment_ops_t *ops)
{
    ops->unregister_seg_callback(ctx, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_data[sc];
        (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
        qbuf_expansion_pool_slot_t *slot;
        URPC_LIST_FOR_EACH(slot, node, &exp_pool->slot_list)
        {
            uint16_t mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
            ops->unregister_seg_callback(ctx, mempool_id);
        }
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    }
}

bool umq_disable_scale_cap(void)
{
    return g_qbuf_pool.disable_scale_cap;
}

static void umq_flush_tls_nodata_to_global(void)
{
    if (qbuf_debug_on())
        g_dbg_stats.tls_flush_nodata_count++;
    UMQ_VLOG_DEBUG(VLOG_UMQ, "TLS_FLUSH_NODATA: global_nodata=%llu exp_total=%llu mpool=0\n",
                   (unsigned long long)g_qbuf_pool.block_pool[0].buf_cnt_without_data,
                   (unsigned long long)g_qbuf_pool.exp_pool_without_date.exp_total_block_num);
    (void)pthread_spin_lock(&g_tls_stats_lock);
    local_qbuf_pool_t *pool_iter = NULL;
    URPC_LIST_FOR_EACH(pool_iter, tls_node, &g_tls_register_head)
    {
        if (pool_iter->block_pool.buf_cnt_without_data == 0) {
            continue;
        }
        (void)pthread_spin_lock(&g_qbuf_pool.block_pool[0].global_mutex);
        uint64_t return_buf_cnt = return_list_to_pools(QBUF_LIST_FIRST(&pool_iter->block_pool.head_without_data),
                                                       &g_qbuf_pool.block_pool[0].head_without_data,
                                                       &g_qbuf_pool.block_pool[0].buf_cnt_without_data, false, 0);
        (void)__atomic_fetch_sub(&pool_iter->block_pool.buf_cnt_without_data, return_buf_cnt, __ATOMIC_RELAXED);
        uint64_t cap_sub = (return_buf_cnt > pool_iter->block_pool.capacity_without_data) ?
                               pool_iter->block_pool.capacity_without_data :
                               return_buf_cnt;
        pool_iter->block_pool.capacity_without_data -= cap_sub;
        __atomic_fetch_sub(&g_total_local_cap_without_data, cap_sub, __ATOMIC_RELAXED);
        (void)pthread_spin_unlock(&g_qbuf_pool.block_pool[0].global_mutex);
        if (qbuf_debug_on())
            g_dbg_stats.tls_flush_nodata_bufs += return_buf_cnt;
    }
    (void)pthread_spin_unlock(&g_tls_stats_lock);
}
