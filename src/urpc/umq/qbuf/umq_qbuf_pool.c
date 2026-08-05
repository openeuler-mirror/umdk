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
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>

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
    uint32_t partial_slot_count; // DFX: slots with 0 < free_block_cnt < total_block_cnt
    urpc_list_t slot_list;       // linked list of slots (replaces exp_slot_list array)
    uint32_t slot_count;         // number of slots in slot_list
    uint64_t exp_total_block_num;
    async_shrink_pool_task_list_t shrink_task_list;
    uint64_t total_expansion_count;
    uint64_t total_shrink_count;
    uint64_t sub_slot_blk_count;
    uint64_t sub_slot_count;
    uint64_t sub_slot_data_buf_size;

} qbuf_expansion_pool_t;

// FLAT qbuf_pool_t (no base substruct): the test includes this file directly and accesses
// g_qbuf_pool.block_pool[sc], g_qbuf_pool.tls_qbuf_pool_depth, etc. without .base. indirection.
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

    uint64_t tls_qbuf_pool_depth;        // global TLS count cap (default 1.5K, per-SC for normal pool)
    uint64_t tls_expand_qbuf_pool_depth; // per-thread TLS count cap (default 1/2 of global)

    bool disable_scale_cap;
    bool disable_malloc_escape;
    uint32_t lazy_sc_mask;
} qbuf_pool_t;

static qbuf_pool_t g_qbuf_pool = {0};

static void umq_flush_tls_nodata_to_global(void);
static __thread local_qbuf_pool_t g_thread_cache = {0};
static uint8_t g_umq_qbuf_size_pow_small = UMQ_QBUF_SIZE_POW_4K;

static urpc_list_t g_tls_register_head;
static pthread_spinlock_t g_tls_stats_lock;

// multi-level: with_data and without_data both use count-based caps (per-SC for with_data).
// g_total_local_cap_with_data_cnt[sc]: sum of all threads' capacity_with_data[sc] (with_data global cap tracker).
// g_total_local_cap_without_data: sum of all threads' capacity_without_data (without_data global cap tracker).
static volatile uint64_t g_total_local_cap_with_data_cnt[UMQ_QBUF_SIZE_CLASS_MAX] = {0};
static volatile uint64_t g_total_local_cap_without_data = 0;

static volatile uint64_t g_total_escape_buf_cnt = 0;

#define QBUF_POOL_TLS_QBUF_POOL_DEPTH (1536) // without_data global TLS pool capacity sum budget

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
    // alloc/free timing (nanoseconds)
    uint64_t alloc_ns_total;
    uint64_t alloc_ns_max;
    uint64_t alloc_count;
    uint64_t free_ns_total;
    uint64_t free_ns_max;
    uint64_t free_count;
    // latency histogram buckets (7 buckets)
#define QBUF_LAT_BUCKETS 8
    // alloc latency: <100ns, 100ns-1us, 1-5us, 5-10us, 10-100us, 100us-1ms, 1-10ms, >10ms
    uint64_t alloc_lat[QBUF_LAT_BUCKETS];
    // free latency: same buckets (8 buckets)
    uint64_t free_lat[QBUF_LAT_BUCKETS];
    // per-lifecycle-path timing (alloc only)
#define QBUF_LC_PATHS 4  // TLS_hit, fetch_global, fetch_expansion, escape
    uint64_t alloc_lc_count[QBUF_LC_PATHS];      // call count per path
    uint64_t alloc_lc_ns_total[QBUF_LC_PATHS];   // cumulative ns per path
    uint64_t alloc_lc_ns_max[QBUF_LC_PATHS];     // max ns per path
    // per-size-class timing (alloc only, with_data)
    uint64_t alloc_sc_count[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t alloc_sc_ns_total[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t alloc_sc_ns_max[UMQ_QBUF_SIZE_CLASS_MAX];
} qbuf_debug_stats_t;

static inline uint64_t qbuf_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Map nanosecond latency to histogram bucket index.
// Buckets: [0,100ns) [100ns,1us) [1us,10us) [10us,100us) [100us,1ms) [1ms,10ms) [10ms,+inf)
static inline int qbuf_lat_bucket(uint64_t ns)
{
    if (ns < 100ULL)          return 0;  // <100ns
    if (ns < 1000ULL)         return 1;  // 100ns-1us
    if (ns < 5000ULL)         return 2;  // 1-5us
    if (ns < 10000ULL)        return 3;  // 5-10us
    if (ns < 100000ULL)       return 4;  // 10us-100us
    if (ns < 1000000ULL)      return 5;  // 100us-1ms
    if (ns < 10000000ULL)     return 6;  // 1ms-10ms
    return 7;                             // >10ms
}

static const char *qbuf_lat_labels[QBUF_LAT_BUCKETS] = {
    "<0.1us", "0.1-1us", "1-5us", "5-10us", "10-100us", "100us-1ms", "1-10ms", ">10ms"
};
static const char *qbuf_lc_labels[4] = {
    "TLS_hit", "fetch_global", "fetch_expansion", "escape"
};

static qbuf_debug_stats_t g_dbg_stats = {0};
static __thread bool g_dbg_in_async_expand = false; // 防止异步扩容递归重入
__thread bool g_dbg_expansion_happened = false; // 线程局部标志: expansion pool/mmap路径标识，fetch前reset，alloc后读取
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
    if (g_dbg_stats.alloc_count > 0) {
        fprintf(stderr, "[UMQ TIMING] alloc timing: avg=%.1f us  max=%.1f us  count=%llu\n",
        (double)(g_dbg_stats.alloc_ns_total / g_dbg_stats.alloc_count) / 1000.0,
        (double)g_dbg_stats.alloc_ns_max / 1000.0,
        (unsigned long long)g_dbg_stats.alloc_count);
    }
    if (g_dbg_stats.free_count > 0) {
        fprintf(stderr, "[UMQ TIMING] free timing: avg=%.1f us  max=%.1f us  count=%llu\n",
        (double)(g_dbg_stats.free_ns_total / g_dbg_stats.free_count) / 1000.0,
        (double)g_dbg_stats.free_ns_max / 1000.0,
        (unsigned long long)g_dbg_stats.free_count);
    }
    UMQ_VLOG_DEBUG(VLOG_UMQ, "=== END SUMMARY ===\n");
    // latency histogram
    if (g_dbg_stats.alloc_count > 0) {
        fprintf(stderr, "[UMQ TIMING] alloc latency histogram (count=%llu):\n",
                (unsigned long long)g_dbg_stats.alloc_count);
        for (int b = 0; b < QBUF_LAT_BUCKETS; b++) {
            fprintf(stderr, "  %-12s: %8llu (%5.1f%%)\n", qbuf_lat_labels[b],
                    (unsigned long long)g_dbg_stats.alloc_lat[b],
                    100.0 * g_dbg_stats.alloc_lat[b] / g_dbg_stats.alloc_count);
        }
    }
    if (g_dbg_stats.free_count > 0) {
        fprintf(stderr, "[UMQ TIMING] free latency histogram (count=%llu):\n",
                (unsigned long long)g_dbg_stats.free_count);
        for (int b = 0; b < QBUF_LAT_BUCKETS; b++) {
            fprintf(stderr, "  %-12s: %8llu (%5.1f%%)\n", qbuf_lat_labels[b],
                    (unsigned long long)g_dbg_stats.free_lat[b],
                    100.0 * g_dbg_stats.free_lat[b] / g_dbg_stats.free_count);
        }
    }
    // ===== END QBUF DEBUG STATS =====
    // per lifecycle path
    fprintf(stderr, "[UMQ TIMING] alloc by lifecycle path:\n");
    for (int p = 0; p < 4; p++) {
        uint64_t cnt = g_dbg_stats.alloc_lc_count[p];
        double avg = cnt > 0 ? (double)(g_dbg_stats.alloc_lc_ns_total[p] / cnt) / 1000.0 : 0.0;
        double mx = (double)g_dbg_stats.alloc_lc_ns_max[p] / 1000.0;
        fprintf(stderr, "  %-20s: count=%-8llu avg=%.1f us  max=%.1f us\n",
                qbuf_lc_labels[p], (unsigned long long)cnt, avg, mx);
    }
    // per size_class
    fprintf(stderr, "[UMQ TIMING] alloc by size_class:\n");
    for (uint32_t s = 0; s < g_qbuf_pool.size_class_count; s++) {
        uint64_t cnt = g_dbg_stats.alloc_sc_count[s];
        double avg = cnt > 0 ? (double)(g_dbg_stats.alloc_sc_ns_total[s] / cnt) / 1000.0 : 0.0;
        double mx = (double)g_dbg_stats.alloc_sc_ns_max[s] / 1000.0;
        fprintf(stderr, "  sc=%-2u blk=%-8u: count=%-8llu avg=%.1f us  max=%.1f us\n",
                s, g_qbuf_pool.block_sizes[s], (unsigned long long)cnt, avg, mx);
    }
}
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
    // Data regions are laid out in descending block_size order (larger SC at lower addresses),
    // so data_region_start[]/end[] are NOT monotonic in sc. Search every non-lazy region for one
    // that contains buf_data. count <= UMQ_QBUF_SIZE_CLASS_MAX(16), so O(count) is acceptable on
    // the data_to_head path (free/lookup, not core alloc fast path).
    for (uint32_t i = 0; i < count; i++) {
        if (g_qbuf_pool.data_region_end[i] == NULL) {
            continue;
        }
        if (data >= g_qbuf_pool.data_region_start[i] && data < g_qbuf_pool.data_region_end[i]) {
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
        // Slot is full-empty here; return_batch_to_expansion_pool already
        // decremented partial_slot_count on the partial->full transition.
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
    // Approximate: only return-path transitions are tracked; alloc-path
    // (full->partial, partial->empty) is intentionally uninstrumented.
    uint64_t old_free = slot->free_block_cnt - batch_cnt;
    uint64_t new_free = slot->free_block_cnt;
    bool was_partial = (old_free > 0 && old_free < slot->total_block_cnt);
    bool is_partial = (new_free > 0 && new_free < slot->total_block_cnt);
    if (!was_partial && is_partial) {
        __atomic_fetch_add(&exp_pool->partial_slot_count, 1, __ATOMIC_RELAXED);
    } else if (was_partial && !is_partial) {
        __atomic_fetch_sub(&exp_pool->partial_slot_count, 1, __ATOMIC_RELAXED);
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    if (slot->free_block_cnt == slot->total_block_cnt) {
        async_shrink_global_pool(with_data, sc, slot_id);
    }
}

uint64_t return_list_to_pools(umq_buf_t *local_head, umq_buf_list_t *global_head, uint64_t *global_buf_cnt,
                              bool with_data, uint32_t sc)
{
    if (local_head == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "return_list_to_pools: local_head is NULL, with_data=%d sc=%u\n",
                           with_data, sc);
        return 0;
    }
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
    cfg->disable_scale_cap = g_qbuf_pool.disable_scale_cap;
    cfg->disable_malloc_escape = g_qbuf_pool.disable_malloc_escape;
    cfg->tls_qbuf_pool_depth = g_qbuf_pool.tls_qbuf_pool_depth;
    cfg->tls_expand_qbuf_pool_depth = g_qbuf_pool.tls_expand_qbuf_pool_depth;
}

static void release_thread_cache(uint64_t id);

static ALWAYS_INLINE local_block_pool_t *get_thread_cache(void)
{
    /* During TLS destruction the list may hold dangling nodes; never re-init
     * (which would push_back into the poisoned list) once we are exiting. */
    if (!g_thread_cache.inited && !g_tls_dtors_running) {
        for (uint32_t i = 0; i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
            QBUF_LIST_INIT(&g_thread_cache.block_pool.head_with_data[i]);
            g_thread_cache.block_pool.buf_cnt_with_data[i] = 0;
            g_thread_cache.block_pool.capacity_with_data[i] = 0;
        }
        g_thread_cache.block_pool.capacity_without_data = 0;
        QBUF_LIST_INIT(&g_thread_cache.block_pool.head_without_data);
        g_thread_cache.block_pool.buf_cnt_without_data = 0;
        (void)pthread_spin_init(&g_thread_cache.block_pool.list_lock, PTHREAD_PROCESS_PRIVATE);
        (void)memset(&g_thread_cache.stats, 0, sizeof(g_thread_cache.stats));
        /* Use kernel TID (gettid via syscall, compatible with all glibc versions)
         * instead of pthread_self() (pthread_t address = ~15-digit number with
         * no mapping to ps/top). Kernel TID is a small integer matching what
         * `ps -L` / `top -H` report, so testers can correlate DFX TID rows
         * with OS-level per-thread diagnostics. */
        g_thread_cache.stats.tid = (uint64_t)syscall(SYS_gettid);
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
    if (!g_thread_cache.inited) {
        return;
    }

    /* During process exit, glibc runs __call_tls_dtors() which destroys each
     * thread's urpc_thread_closure, in turn calling us. By this point other
     * threads' TLS nodes in g_tls_register_head may already be dangling (their
     * storage freed) but still linked into the list. Any urpc_list_remove()
     * dereferences adjacent nodes -> SEGV. Skip all cross-thread list ops and
     * global-pool returns; the per-thread buf memory points into the global
     * pool (not thread-malloc'd), so leaking it is acceptable at exit. */
    if (g_tls_dtors_running) {
        g_thread_cache.inited = false;
        return;
    }

    if (!g_qbuf_pool.inited) {
        if (urpc_list_is_in_list(&g_thread_cache.tls_node)) {
            urpc_list_remove(&g_thread_cache.tls_node);
        }
        g_thread_cache.inited = false;
        return;
    }

    (void)pthread_spin_lock(&g_tls_stats_lock);
    if (urpc_list_is_in_list(&g_thread_cache.tls_node)) {
        urpc_list_remove(&g_thread_cache.tls_node);
    }
    /* Set inited=false AFTER we're done with the list, but BEFORE touching
     * block_pool below. Do NOT call get_thread_cache() here: it would see
     * inited==false and re-register us into g_tls_register_head (which may
     * hold dangling nodes from threads killed by exit()). Access block_pool
     * directly via &g_thread_cache.block_pool. */
    g_thread_cache.inited = false;
    (void)pthread_spin_unlock(&g_tls_stats_lock);

    local_block_pool_t *local_pool = &g_thread_cache.block_pool;
    uint64_t return_buf_cnt;
    uint64_t total_tls_cap[UMQ_QBUF_SIZE_CLASS_MAX] = {0};

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
        total_tls_cap[sc] = local_pool->capacity_with_data[sc];
    }

    if (local_pool->head_without_data.first != NULL) {
        (void)pthread_spin_lock(&g_qbuf_pool.block_pool[0].global_mutex);
        return_buf_cnt = return_list_to_pools(QBUF_LIST_FIRST(&local_pool->head_without_data),
                                              &g_qbuf_pool.block_pool[0].head_without_data,
                                              &g_qbuf_pool.block_pool[0].buf_cnt_without_data, false, 0);
        (void)__atomic_fetch_sub(&local_pool->buf_cnt_without_data, return_buf_cnt, __ATOMIC_RELAXED);
        g_thread_cache.stats.tls_return_buf_cnt_without_data += return_buf_cnt;
        (void)pthread_spin_unlock(&g_qbuf_pool.block_pool[0].global_mutex);
    }

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        if (total_tls_cap[sc] > 0) {
            __atomic_fetch_sub(&g_total_local_cap_with_data_cnt[sc], total_tls_cap[sc], __ATOMIC_RELAXED);
        }
    }
    __atomic_fetch_sub(&g_total_local_cap_without_data, local_pool->capacity_without_data, __ATOMIC_RELAXED);

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
    exp_pool->partial_slot_count = 0;
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
    exp_pool->partial_slot_count = 0;
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
    // lazy init: SCs with block_size >= threshold get zero initial memory
    uint64_t lazy_threshold = (cfg->lazy_init_block_size_threshold == 0) ?
                                  QBUF_POOL_DEFAULT_LAZY_INIT_BLOCK_SIZE_THRESHOLD :
                                  cfg->lazy_init_block_size_threshold;
    g_qbuf_pool.lazy_sc_mask = 0;
    uint32_t nonlazy_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (g_qbuf_pool.block_sizes[i] >= lazy_threshold) {
            g_qbuf_pool.lazy_sc_mask |= (1U << i);
        } else {
            nonlazy_count++;
        }
    }
    // block-equal-division per size_class (only non-lazy SCs get initial memory):
    //   SPLIT    — N = total_size / (sum(nonlazy_block_sizes) + nonlazy_count * per_blk_overhead)
    //   COMBINE  — N = total_size / sum(nonlazy_block_sizes)
    uint64_t sum_block_sizes = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (g_qbuf_pool.lazy_sc_mask & (1U << i)) continue;
        sum_block_sizes += g_qbuf_pool.block_sizes[i];
    }
    uint64_t per_blk_overhead = 0;
    if (cfg->mode == UMQ_BUF_SPLIT) {
        per_blk_overhead = sizeof(umq_buf_t);
        if (cfg->disable_scale_cap) {
            per_blk_overhead = (UMQ_EMPTY_HEADER_COEFFICIENT + 1) * sizeof(umq_buf_t);
        }
    }
    if (nonlazy_count == 0) {
        g_qbuf_pool.per_sc_block_count = 0;
    } else {
        // Compute per_sc_block_count by exactly simulating the real layout. The old closed-form
        // division `total_size / denom` omits per-SC data-region alignment padding between non-lazy
        // SCs; with multiple SCs of differing block sizes the real layout overflows total_size.
        // Layout is written in DESCENDING block_size order (see init_split_mode_layout /
        // init_combine_mode_layout): since block_sizes[i] = base * mult^i with mult a power of two,
        // each larger block_size is an exact multiple of every smaller one, so a descending layout
        // makes every prev_end already aligned to the next SC's block_size -> padding is always 0.
        // layout_end(N) is then linear in N (= N * denom), so the closed-form value is the max N
        // and the decrement loop below exits in one iteration. The simulation is kept as a
        // defensive guard against future non-multiple block_size configurations (it would shrink
        // N until the layout fits). One-shot init, perf-insensitive.
        uint32_t order[UMQ_QBUF_SIZE_CLASS_MAX];
        uint32_t order_cnt = 0;
        for (int32_t si = (int32_t)count - 1; si >= 0; si--) {
            uint32_t i = (uint32_t)si;
            if (g_qbuf_pool.lazy_sc_mask & (1U << i)) {
                continue;
            }
            order[order_cnt++] = i;
        }
        uint64_t per_sc = cfg->total_size / (sum_block_sizes + (uint64_t)nonlazy_count * per_blk_overhead);
        while (per_sc > 0) {
            uint64_t data_end = 0;
            uint64_t hdr_size = 0;
            for (uint32_t k = 0; k < order_cnt; k++) {
                uint32_t bs = g_qbuf_pool.block_sizes[order[k]];
                data_end = (data_end + bs - 1) & ~((uint64_t)bs - 1);
                data_end += per_sc * bs;
                if (cfg->mode == UMQ_BUF_SPLIT) {
                    hdr_size += per_sc * sizeof(umq_buf_t);
                }
            }
            uint64_t layout_end = data_end;
            if (cfg->mode == UMQ_BUF_SPLIT) {
                layout_end += hdr_size;
                if (cfg->disable_scale_cap) {
                    layout_end += (uint64_t)nonlazy_count * per_sc * UMQ_EMPTY_HEADER_COEFFICIENT * sizeof(umq_buf_t);
                }
            }
            if (layout_end <= cfg->total_size) {
                break;
            }
            per_sc--;
        }
        g_qbuf_pool.per_sc_block_count = per_sc;
    }

    return 0;
}

static void init_split_mode_layout(const qbuf_pool_cfg_t *cfg, uint32_t count)
{
    // Layout B: centralized data, headers, ext. Data regions are laid out in DESCENDING
    // block_size order: block_sizes[i] = base * mult^i with mult a power of two, so every
    // larger block_size is an exact multiple of every smaller one; placing larger SCs first
    // keeps prev_end aligned to each subsequent (smaller) block_size, eliminating per-SC
    // alignment padding. The sc index space is left untouched (block_sizes[block_pool[]],
    // data_region_start[] etc. still indexed by sc); only the write order changes.
    uint64_t blk_nums[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t total_blk_num = 0;
    uint64_t total_header_size = 0;
    char *data_ptr = (char *)cfg->buf_addr;

    // Build descending (largest block_size first) write order over non-lazy SCs only.
    uint32_t order[UMQ_QBUF_SIZE_CLASS_MAX];
    uint32_t order_cnt = 0;
    for (int32_t si = (int32_t)count - 1; si >= 0; si--) {
        uint32_t sc = (uint32_t)si;
        if (g_qbuf_pool.lazy_sc_mask & (1U << sc)) {
            continue;
        }
        order[order_cnt++] = sc;
    }

    // Initialize bookkeeping for ALL SCs first (lazy SCs get zero regions), then write
    // non-lazy data regions in descending order.
    for (uint32_t sc = 0; sc < count; sc++) {
        blk_nums[sc] = 0;
        if (g_qbuf_pool.lazy_sc_mask & (1U << sc)) {
            g_qbuf_pool.data_region_start[sc] = NULL;
            g_qbuf_pool.data_region_end[sc] = NULL;
        }
    }
    for (uint32_t k = 0; k < order_cnt; k++) {
        uint32_t sc = order[k];
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
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

    // Header region is laid out in the same descending order as data regions. header_region_start[sc]
    // still indexes by sc; the physical placement just follows `order[]`.
    char *header_cur = (char *)g_qbuf_pool.header_buffer;
    (void)memset(g_qbuf_pool.header_region_start, 0, sizeof(g_qbuf_pool.header_region_start));
    for (uint32_t k = 0; k < order_cnt; k++) {
        uint32_t sc = order[k];
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
    // Lazy SCs: zero block pool counts + expansion trigger (no data region allocated).
    for (uint32_t sc = 0; sc < count; sc++) {
        if (!(g_qbuf_pool.lazy_sc_mask & (1U << sc))) {
            continue;
        }
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
        g_qbuf_pool.block_pool[sc].buf_cnt_with_data = 0;
        g_qbuf_pool.block_pool[sc].buf_cnt_without_data = 0;
        uint64_t exp_blk_cnt = g_qbuf_pool.expansion_size / blk_size;
        if (exp_blk_cnt == 0) exp_blk_cnt = 1;
        g_qbuf_pool.exp_pool_with_data[sc].trigger_expand_block_num = exp_blk_cnt * g_qbuf_pool.expansion_threshold / 100;
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
    // Data regions are laid out in DESCENDING block_size order (same rationale as SPLIT:
    // block_sizes[i] = base * mult^i with mult a power of two -> larger SCs are exact
    // multiples of smaller ones -> descending order makes every prev_end already aligned
    // to the next SC's block_size, eliminating alignment padding). The sc index space is
    // untouched; only the write order changes.
    uint64_t blk_nums[UMQ_QBUF_SIZE_CLASS_MAX];
    uint64_t total_blk_num = 0;
    char *data_ptr = (char *)cfg->buf_addr;

    uint32_t order[UMQ_QBUF_SIZE_CLASS_MAX];
    uint32_t order_cnt = 0;
    for (int32_t si = (int32_t)count - 1; si >= 0; si--) {
        uint32_t sc = (uint32_t)si;
        if (g_qbuf_pool.lazy_sc_mask & (1U << sc)) {
            continue;
        }
        order[order_cnt++] = sc;
    }

    for (uint32_t sc = 0; sc < count; sc++) {
        blk_nums[sc] = 0;
        if (g_qbuf_pool.lazy_sc_mask & (1U << sc)) {
            g_qbuf_pool.data_region_start[sc] = NULL;
            g_qbuf_pool.data_region_end[sc] = NULL;
        }
    }
    for (uint32_t k = 0; k < order_cnt; k++) {
        uint32_t sc = order[k];
        uint32_t blk_size = g_qbuf_pool.block_sizes[sc];
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
        if (g_qbuf_pool.lazy_sc_mask & (1U << sc)) {
            g_qbuf_pool.block_pool[sc].buf_cnt_with_data = 0;
            g_qbuf_pool.block_pool[sc].buf_cnt_without_data = 0;
            uint64_t exp_blk_cnt = g_qbuf_pool.expansion_size / blk_size;
            if (exp_blk_cnt == 0) exp_blk_cnt = 1;
            g_qbuf_pool.exp_pool_with_data[sc].trigger_expand_block_num = exp_blk_cnt * g_qbuf_pool.expansion_threshold / 100;
            continue;
        }
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
    UMQ_VLOG_INFO(VLOG_UMQ, "  lazy_sc_mask=0x%x\n", g_qbuf_pool.lazy_sc_mask);
    UMQ_VLOG_INFO(VLOG_UMQ, "  total_size=%llu per_sc_block_count=%llu expansion_mem_max=%llu\n",
                  (unsigned long long)g_qbuf_pool.total_size, (unsigned long long)g_qbuf_pool.per_sc_block_count,
                  (unsigned long long)g_qbuf_pool.expansion_mem_size_max);
    UMQ_VLOG_INFO(VLOG_UMQ, "  exp_size=%llu exp_threshold=%u\n", (unsigned long long)g_qbuf_pool.expansion_size,
                  g_qbuf_pool.expansion_threshold);
    UMQ_VLOG_INFO(VLOG_UMQ, "  tls_qbuf_depth=%llu tls_expand_qbuf_depth=%llu\n",
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

    for (uint32_t sc = 0; sc < UMQ_QBUF_SIZE_CLASS_MAX; sc++) {
        __atomic_store_n(&g_total_local_cap_with_data_cnt[sc], 0, __ATOMIC_RELAXED);
    }
    __atomic_store_n(&g_total_local_cap_without_data, 0, __ATOMIC_RELAXED);
}

static ALWAYS_INLINE int umq_qbuf_local_pool_fetch_and_expand(uint32_t needed, local_block_pool_t *local_pool,
                                                              bool with_data, uint32_t sc)
{
    int ret;
    uint32_t batch_cnt = get_batch_count(sc);
    uint32_t blk_size = g_qbuf_pool.block_sizes[sc];

    if (g_qbuf_pool.disable_scale_cap) {
        g_dbg_expansion_happened = false; // 本次alloc开始前重置expansion标志(sticky:一旦为true不再变回false)
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

    // High-water mark cap update: cap = max(cap, actual_holding), clamped by two-level budget
    if (with_data) {
        uint64_t actual_cnt = local_pool->buf_cnt_with_data[sc];
        uint64_t cur_cap = local_pool->capacity_with_data[sc];
        if (actual_cnt > cur_cap) {
            uint64_t delta = actual_cnt - cur_cap;
            // Clamp by per-thread budget
            if (cur_cap + delta > g_qbuf_pool.tls_expand_qbuf_pool_depth) {
                delta = (cur_cap >= g_qbuf_pool.tls_expand_qbuf_pool_depth) ?
                             0 :
                            (g_qbuf_pool.tls_expand_qbuf_pool_depth - cur_cap);
            }
            // Clamp by global budget
            uint64_t g_total = __atomic_load_n(&g_total_local_cap_with_data_cnt[sc], __ATOMIC_RELAXED);
            if (g_total + delta > g_qbuf_pool.tls_qbuf_pool_depth) {
                delta = (g_total >= g_qbuf_pool.tls_qbuf_pool_depth) ? 0 : (g_qbuf_pool.tls_qbuf_pool_depth - g_total);
            }
            if (delta > 0) {
                local_pool->capacity_with_data[sc] += delta;
                __atomic_fetch_add(&g_total_local_cap_with_data_cnt[sc], delta, __ATOMIC_RELAXED);
            }
        }
    } else {
        uint64_t actual_cnt = __atomic_load_n(&local_pool->buf_cnt_without_data, __ATOMIC_RELAXED);
        uint64_t cur_cap = __atomic_load_n(&local_pool->capacity_without_data, __ATOMIC_RELAXED);
        if (actual_cnt > cur_cap) {
            uint64_t delta = actual_cnt - cur_cap;
            if (cur_cap + delta > g_qbuf_pool.tls_expand_qbuf_pool_depth) {
                delta = (cur_cap >= g_qbuf_pool.tls_expand_qbuf_pool_depth) ?
                            0 :
                            (g_qbuf_pool.tls_expand_qbuf_pool_depth - cur_cap);
            }
            uint64_t g_total = __atomic_load_n(&g_total_local_cap_without_data, __ATOMIC_RELAXED);
            if (g_total + delta > g_qbuf_pool.tls_qbuf_pool_depth) {
                delta = (g_total >= g_qbuf_pool.tls_qbuf_pool_depth) ? 0 : (g_qbuf_pool.tls_qbuf_pool_depth - g_total);
            }
            if (delta > 0) {
                (void)__atomic_fetch_add(&local_pool->capacity_without_data, (uint32_t)delta, __ATOMIC_RELAXED);
                __atomic_fetch_add(&g_total_local_cap_without_data, delta, __ATOMIC_RELAXED);
            }
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
        if (shrink < umq_qbuf_pool_shrink_threshold() || g_thread_cache.block_pool.capacity_with_data[sc] == 0) {
            return;
        }
        uint64_t cur_cap = __atomic_load_n(&g_thread_cache.block_pool.capacity_with_data[sc], __ATOMIC_RELAXED);
        if (shrink > cur_cap) {
            shrink = cur_cap;
        }
        (void)__atomic_fetch_sub(&g_thread_cache.block_pool.capacity_with_data[sc], shrink, __ATOMIC_RELAXED);
        __atomic_fetch_sub(&g_total_local_cap_with_data_cnt[sc], shrink, __ATOMIC_RELAXED);

        uint64_t new_cap = __atomic_load_n(&g_thread_cache.block_pool.capacity_with_data[sc], __ATOMIC_RELAXED);
        if (new_cap < remaining) {
            return_to_global(&g_qbuf_pool.block_pool[sc], &g_thread_cache.block_pool, &g_thread_cache.stats, true, sc,
                             (uint32_t)new_cap);
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
        uint64_t cur_cap = __atomic_load_n(&g_thread_cache.block_pool.capacity_without_data, __ATOMIC_RELAXED);
        if (cur_cap == 0) {
            return;
        }
        if (shrink > cur_cap) {
            shrink = cur_cap;
        }
        (void)__atomic_fetch_sub(&g_thread_cache.block_pool.capacity_without_data, shrink, __ATOMIC_RELAXED);
        __atomic_fetch_sub(&g_total_local_cap_without_data, shrink, __ATOMIC_RELAXED);
        uint64_t new_cap = __atomic_load_n(&g_thread_cache.block_pool.capacity_without_data, __ATOMIC_RELAXED);
        if (new_cap < remaining) {
            return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, false, 0,
                             (uint32_t)new_cap);
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
            uint32_t got = allocate_batch(exp_free_list, (uint32_t)take_cnt, local_head);
            if (got > 0) {
                *local_buf_cnt += got;
                slot->free_block_cnt -= got;
                count += got;
                request -= got;
                exp_pool->exp_total_block_num -= got;
            }
            if (got < take_cnt) {
                /* free_block_cnt disagreed with the real free list length
                 * (list shorter than the count). allocate_batch drained the
                 * real list; realign the bookkeeping so future fetches do not
                 * keep over-counting this slot and eventually crash. */
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                    "expansion slot free_block_cnt mismatch: claimed=%lu moved=%u, realigning to 0\n",
                    (unsigned long)take_cnt, got);
                slot->free_block_cnt = 0;
            }
            /* realign free_block_cnt with actual list to prevent drift */
            {
                uint32_t _rc = 0;
                umq_buf_t *_rp = QBUF_LIST_FIRST(&slot->free_block_list);
                while (_rp && _rc < 8200) { _rc++; _rp = QBUF_LIST_NEXT(_rp); }
                if (_rc != slot->free_block_cnt) {
                    slot->free_block_cnt = _rc;
                }
            }
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

uint32_t umq_qbuf_expansion_slot_dist(umq_expansion_slot_info_t *infos, uint32_t cap)
{
    if (infos == NULL || cap == 0) {
        return 0;
    }
    if (!g_qbuf_pool.inited || g_qbuf_pool.disable_scale_cap) {
        return 0;
    }

    uint32_t n = 0;
     /* with_data: traverse exp_pool_with_data[sc].slot_list bu size class */
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_data[sc];
        (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
        qbuf_expansion_pool_slot_t *slot;
        URPC_LIST_FOR_EACH(slot, node, &exp_pool->slot_list)
        {
            if (n >= cap) {
                (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
                return n;
            }
            infos[n].mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
            infos[n].size_class = (uint16_t)sc;
            infos[n].slot_id = slot->slot_id;
            infos[n].total_block_cnt = slot->total_block_cnt;
            infos[n].free_block_cnt = slot->free_block_cnt;
            infos[n].in_use_cnt = slot->total_block_cnt - slot->free_block_cnt;
            n++;
        }
        (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    }

    /* without_data: traverse exp_pool_without_date.slot_list */
    qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_without_date;
    (void)pthread_spin_lock(&exp_pool->expansion_pool_lock);
    qbuf_expansion_pool_slot_t *slot;
    URPC_LIST_FOR_EACH(slot, node, &exp_pool->slot_list)
    {
        if (n >= cap) {
            (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
            return n;
        }
        infos[n].mempool_id = (uint16_t)(slot->slot_id + QBUF_POOL_EXP_SLOT_ID_MIN);
        infos[n].size_class = UMQ_QBUF_SIZE_CLASS_MAX;
        infos[n].slot_id = slot->slot_id;
        infos[n].total_block_cnt = slot->total_block_cnt;
        infos[n].free_block_cnt = slot->free_block_cnt;
        infos[n].in_use_cnt = slot->total_block_cnt - slot->free_block_cnt;
        n++;
    }
    (void)pthread_spin_unlock(&exp_pool->expansion_pool_lock);
    return n;
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
    uint64_t _t0 = qbuf_mono_ns();
    int _lc = 0; // 生命周期路径标识: 0=TLS命中 1=global pool fetch 2=expansion/mmap 3=escape堆分配
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
            _lc = 0; // TLS命中: 线程本地缓存有足够buf，无需访问全局池
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
            // 根据expansion标志区分生命周期路径:
            // _lc=1: 纯global pool fetch(global pool中有空闲buf直接分配)
            // _lc=2: 走expansion pool或mmap扩容(global pool空，需从expansion slot或新mmap分配)
            _lc = g_dbg_expansion_happened ? 2 : 1;
        }

        umq_qbuf_alloc_nodata(local_pool, num, list, param.shm);
        thread_cache_self_shrink(false, 0);
        g_thread_cache.stats.alloc_cnt_without_data += num;
        if (qbuf_debug_on() &&
            __atomic_add_fetch(&g_dbg_alloc_count, num, __ATOMIC_RELAXED) % QBUF_DBG_SUMMARY_INTERVAL < num) {
            qbuf_dbg_print_summary();
        }
        // 累计nodata路径的时延统计:
        // alloc_ns_total/count/max: 全局时延
        // alloc_lat[]: 时延直方图(7个区间: <0.1us,0.1-1us,1-10us,10-100us,100us-1ms,1-10ms,>10ms)
        // alloc_lc_count/ns_total/ns_max[]: 按生命周期路径(TLS_hit/fetch_global/fetch_expansion/escape)分别统计
        if (qbuf_debug_on()) {
            uint64_t _dt = qbuf_mono_ns() - _t0;
            g_dbg_stats.alloc_ns_total += _dt;
            g_dbg_stats.alloc_count++;
            g_dbg_stats.alloc_lat[qbuf_lat_bucket(_dt)]++;
            g_dbg_stats.alloc_lc_count[_lc]++;
            g_dbg_stats.alloc_lc_ns_total[_lc] += _dt;
            if (_dt > g_dbg_stats.alloc_lc_ns_max[_lc]) g_dbg_stats.alloc_lc_ns_max[_lc] = _dt;
            if (_dt > g_dbg_stats.alloc_ns_max) g_dbg_stats.alloc_ns_max = _dt;
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
        _lc = 0; // TLS命中: 线程本地缓存有足够buf，无需访问全局池
    }
    if (buf_cnt < needed) {
        int ret = umq_qbuf_local_pool_fetch_and_expand(needed - buf_cnt, local_pool, true, sc);
        if (ret != UMQ_SUCCESS) {
            bool explicit_normal = option != NULL && (option->flag & UMQ_ALLOC_FLAG_POOL_TYPE) != 0 &&
                                   option->pool_type == UMQ_ALLOC_POOL_NORMAL;
            if (param.actual_buf_count == 1 && !explicit_normal && !g_qbuf_pool.disable_malloc_escape) {
                _lc = 3; // escape路径: 所有pool耗尽，回退到memalign堆分配，最慢路径
                // 累计escape路径时延(仅lc维度，无sc维度，escape不走size_class)
                if (qbuf_debug_on()) {
                    uint64_t _dt = qbuf_mono_ns() - _t0;
                    g_dbg_stats.alloc_ns_total += _dt;
                    g_dbg_stats.alloc_count++;
                    g_dbg_stats.alloc_lat[qbuf_lat_bucket(_dt)]++;
                    g_dbg_stats.alloc_lc_count[_lc]++;
                    g_dbg_stats.alloc_lc_ns_total[_lc] += _dt;
                    if (_dt > g_dbg_stats.alloc_lc_ns_max[_lc]) g_dbg_stats.alloc_lc_ns_max[_lc] = _dt;
                    if (_dt > g_dbg_stats.alloc_ns_max) g_dbg_stats.alloc_ns_max = _dt;
                }
                return umq_qbuf_alloc_escape(list, sc);
            }
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                               "umq with data qbuf local pool fetch and expand failed, "
                               "suggestion: increase total_size or expansion_mem_size_max, ret: %d\n",
                               ret);
            return ret;
        }
        g_thread_cache.stats.tls_fetch_cnt_with_data++;
        // 同nodata路径，区分纯global fetch vs expansion/mmap路径
        _lc = g_dbg_expansion_happened ? 2 : 1;
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
    if (qbuf_debug_on()) {
        uint64_t _dt = qbuf_mono_ns() - _t0;
        g_dbg_stats.alloc_ns_total += _dt;
        g_dbg_stats.alloc_count++;
        g_dbg_stats.alloc_lat[qbuf_lat_bucket(_dt)]++;
        g_dbg_stats.alloc_lc_count[_lc]++;
        g_dbg_stats.alloc_lc_ns_total[_lc] += _dt;
        if (_dt > g_dbg_stats.alloc_lc_ns_max[_lc]) g_dbg_stats.alloc_lc_ns_max[_lc] = _dt;
        if (_dt > g_dbg_stats.alloc_ns_max) g_dbg_stats.alloc_ns_max = _dt;
        // per size_class timing
        g_dbg_stats.alloc_sc_count[sc]++;
        g_dbg_stats.alloc_sc_ns_total[sc] += _dt;
        if (_dt > g_dbg_stats.alloc_sc_ns_max[sc]) g_dbg_stats.alloc_sc_ns_max[sc] = _dt;
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

    uint64_t _t0 = qbuf_mono_ns();
    local_block_pool_t *local_pool = get_thread_cache();
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT && QBUF_LIST_FIRST(list)->mempool_without_data == 1) {
        (void)pthread_spin_lock(&local_pool->list_lock);
        uint32_t cnt = release_batch(list, &local_pool->head_without_data, false);
        local_pool->buf_cnt_without_data += cnt;
        (void)pthread_spin_unlock(&local_pool->list_lock);

        uint32_t cap = g_qbuf_pool.disable_scale_cap ? QBUF_POOL_TLS_MAX : (uint32_t)__atomic_load_n(&local_pool->capacity_without_data, __ATOMIC_RELAXED);
        if (local_pool->buf_cnt_without_data > cap) {
            uint32_t threshold = cap > umq_qbuf_pool_batch_cnt() ? cap - umq_qbuf_pool_batch_cnt() : 0;
            return_to_global(&g_qbuf_pool.block_pool[0], local_pool, &g_thread_cache.stats, false, 0, threshold);
            g_thread_cache.stats.tls_return_cnt_without_data++;
        }

        thread_cache_self_shrink(false, 0);

        g_thread_cache.stats.free_cnt_without_data += cnt;
        if (qbuf_debug_on())
            g_dbg_stats.free_without_data += cnt;
        return;
    }

    // with_data: partition by size_class so each buf returns to its correct sc bucket
    umq_buf_t *sc_heads[UMQ_QBUF_SIZE_CLASS_MAX] = {NULL};
    umq_buf_t *sc_tails[UMQ_QBUF_SIZE_CLASS_MAX] = {NULL};
    uint32_t total_cnt = 0;
    umq_buf_t *nodata_head = NULL;
    umq_buf_t *nodata_tail = NULL;
    umq_buf_t *cur = QBUF_LIST_FIRST(list);
    while (cur != NULL) {
        umq_buf_t *next = QBUF_LIST_NEXT(cur);
        QBUF_LIST_NEXT(cur) = NULL;

        if (g_qbuf_pool.mode == UMQ_BUF_SPLIT && cur->mempool_without_data == 1) {
            if (nodata_head == NULL) {
                nodata_head = cur;
            } else {
                QBUF_LIST_NEXT(nodata_tail) = cur;
            }
            nodata_tail = cur;
            cur = next;
            continue;
        }

        uint32_t cur_blk;
        if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
            if (cur->buf_size < (uint32_t)sizeof(umq_buf_t)) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                    "umq_qbuf_free: buf_size=%u underflow (< %zu), buf=%p mpool=%u nodata=%u\n",
                    cur->buf_size, sizeof(umq_buf_t), (void *)cur, cur->mempool_id, cur->mempool_without_data);
                cur = next;
                continue;
            }
            cur_blk = cur->buf_size - (uint32_t)sizeof(umq_buf_t);
        } else {
            cur_blk = cur->buf_size;
        }

        uint32_t cur_sc = blk_size_to_sc(cur_blk);
        if (cur_sc >= g_qbuf_pool.size_class_count) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                "umq_qbuf_free: blk_size_to_sc unmatched blk_size=%u buf=%p mpool=%u nodata=%u\n",
                cur_blk, (void *)cur, cur->mempool_id, cur->mempool_without_data);
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

    if (nodata_head != NULL) {
        umq_buf_list_t nodata_list;
        QBUF_LIST_FIRST(&nodata_list) = nodata_head;
        (void)pthread_spin_lock(&local_pool->list_lock);
        uint32_t cnt = release_batch(&nodata_list, &local_pool->head_without_data, false);
        local_pool->buf_cnt_without_data += cnt;
        (void)pthread_spin_unlock(&local_pool->list_lock);
        uint32_t cap = g_qbuf_pool.disable_scale_cap ? QBUF_POOL_TLS_MAX : (uint32_t)__atomic_load_n(&local_pool->capacity_without_data, __ATOMIC_RELAXED);
        if (local_pool->buf_cnt_without_data > cap) {
            uint32_t threshold = cap > umq_qbuf_pool_batch_cnt() ? cap - umq_qbuf_pool_batch_cnt() : 0;
            return_to_global(&g_qbuf_pool.block_pool[0], local_pool, &g_thread_cache.stats, false, 0, threshold);
            g_thread_cache.stats.tls_return_cnt_without_data++;
        }
        g_thread_cache.stats.free_cnt_without_data += cnt;
        if (qbuf_debug_on())
            g_dbg_stats.free_without_data += cnt;
    }

    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        if (sc_heads[sc] == NULL) {
            continue;
        }
        umq_buf_list_t tmp;
        QBUF_LIST_FIRST(&tmp) = sc_heads[sc];
        (void)pthread_spin_lock(&local_pool->list_lock);
        uint32_t cnt = release_batch(&tmp, &local_pool->head_with_data[sc], false);
        local_pool->buf_cnt_with_data[sc] += cnt;
        (void)pthread_spin_unlock(&local_pool->list_lock);

        uint32_t batch_cnt = get_batch_count(sc);
        uint64_t cap_cnt = g_qbuf_pool.disable_scale_cap ? (uint64_t)QBUF_POOL_TLS_MAX :
                                                           local_pool->capacity_with_data[sc];
        uint64_t actual_cnt = local_pool->buf_cnt_with_data[sc];
        if (actual_cnt > cap_cnt) {
            uint64_t threshold_cnt = (cap_cnt > (uint64_t)batch_cnt) ? cap_cnt - (uint64_t)batch_cnt : 0;
            return_to_global(&g_qbuf_pool.block_pool[sc], local_pool, &g_thread_cache.stats, true, sc,
                             (uint32_t)threshold_cnt);
            g_thread_cache.stats.tls_return_cnt_with_data++;
        }

        thread_cache_self_shrink(true, sc);
    }

    g_thread_cache.stats.free_cnt_with_data += total_cnt;
    if (qbuf_debug_on())
        g_dbg_stats.free_with_data += total_cnt;
    // 累计free时延统计: 全局avg/max + 时延直方图(无生命周期/size_class维度)
    if (qbuf_debug_on()) {
        uint64_t _dt = qbuf_mono_ns() - _t0;
        g_dbg_stats.free_ns_total += _dt;
        g_dbg_stats.free_count++;
        g_dbg_stats.free_lat[qbuf_lat_bucket(_dt)]++;
        if (_dt > g_dbg_stats.free_ns_max) g_dbg_stats.free_ns_max = _dt;
    }
}

int umq_qbuf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_qbuf_pool.inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "qbuf pool has not been inited\n");
        return -UMQ_ERR_ENOMEM;
    }
    uint32_t block_size;
    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        if (qbuf->buf_size < (uint32_t)sizeof(umq_buf_t)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                "umq_qbuf_headroom_reset: buf_size=%u underflow (< %zu), buf=%p\n",
                qbuf->buf_size, sizeof(umq_buf_t), (void *)qbuf);
            return -UMQ_ERR_EINVAL;
        }
        block_size = qbuf->buf_size - (uint32_t)sizeof(umq_buf_t);
    } else {
        block_size = qbuf->buf_size;
    }
    return headroom_reset(qbuf, headroom_size, g_qbuf_pool.mode, block_size);
}

static inline umq_buf_t *escape_data_to_head(void *data)
{
    /* Escape-pool blocks are only allocated when g_total_escape_buf_cnt > 0. Without this guard
     * the speculative dereference of (data + block_size) below would read out-of-bounds for
     * pointers that belong to other pools (e.g. rx / tiny), which allocate their data buffers
     * independently and do not place a umq_buf_t header right after each data block. */
    if (__atomic_load_n(&g_total_escape_buf_cnt, __ATOMIC_RELAXED) == 0) {
        return NULL;
    }
    for (uint32_t i = 0; i < g_qbuf_pool.size_class_count; i++) {
        umq_buf_t *candidate = (umq_buf_t *)((char *)data + g_qbuf_pool.block_sizes[i]);
        if (candidate->buf_data == (char *)data && candidate->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
            return candidate;
        }
    }
    return NULL;
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

    /* Fast path only applies to blocks inside the main pool's allocated buffer. Pointers
     * belonging to other pools (rx / tiny / escape) would otherwise be misclassified by
     * buf_data_to_size_class, yielding an out-of-bounds candidate header read. The main
     * pool buffer spans [data_buffer, data_buffer + total_size) regardless of the
     * descending block_size write order used inside. */
    char *pool_start = (char *)g_qbuf_pool.data_buffer;
    char *pool_end = pool_start + g_qbuf_pool.total_size;
    bool in_main_pool = ((char *)data >= pool_start && (char *)data < pool_end);

    if (g_qbuf_pool.mode == UMQ_BUF_SPLIT) {
        if (in_main_pool) {
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
        }

        /* Always try expansion pool / escape lookup. Expansion-pool blocks
         * don't increment g_total_escape_buf_cnt, so we can't gate on it. */
        umq_buf_t *esc = umq_qbuf_data_to_head_escape(data);
        if (esc != NULL && esc->buf_data != NULL && esc->buf_data <= (char *)data &&
            esc->buf_data + esc->buf_size > (char *)data) {
            return esc;
        }
        return NULL;
    }

    if (in_main_pool) {
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
    }

    return umq_qbuf_data_to_head_escape(data);
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
    qbuf_pool_info->config.tls_expand_qbuf_pool_depth = g_qbuf_pool.tls_expand_qbuf_pool_depth;
    /* batch_count: actual effective batch granularity used by fetch_from_global
     * / return_to_global paths (currently uniform across all sc via
     * umq_qbuf_pool_batch_cnt() / get_batch_count(sc), both return
     * QBUF_POOL_BATCH_CNT). Calling the accessor instead of the macro so
     * future runtime-configurable batch (per-sc or cfg-driven) propagates
     * automatically without DFX code change. */
    qbuf_pool_info->config.batch_count = umq_qbuf_pool_batch_cnt();
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
    uint32_t exp_partial_slots = 0;
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        qbuf_expansion_pool_t *e = &g_qbuf_pool.exp_pool_with_data[sc];
        exp_count += e->expansion_count;
        exp_free_blocks += e->exp_total_block_num;
        exp_total_blocks += (uint64_t)e->expansion_count * e->expansion_block_count;
        exp_total_expansion += e->total_expansion_count;
        exp_total_shrink += e->total_shrink_count;
        exp_partial_slots += __atomic_load_n(&e->partial_slot_count, __ATOMIC_RELAXED);
    }
    qbuf_pool_stats->exp_pool_with_data.expansion_count = exp_count;
    qbuf_pool_stats->exp_pool_with_data.partial_slot_count = exp_partial_slots;
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
    qbuf_pool_stats->exp_pool_without_data.partial_slot_count =
        __atomic_load_n(&exp_without_data->partial_slot_count, __ATOMIC_RELAXED);
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
        /* Skip nodes whose owner thread already tore down its TLS cache during
         * exit() but left the node linked (g_tls_dtors_running fast path). */
        if (!pool_iter->inited) {
            continue;
        }
        if (qbuf_pool_stats->local_qbuf_pool_num >= UMQ_LOCAL_QBUF_POOL_MAX_NUM) {
            break;
        }
        umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[qbuf_pool_stats->local_qbuf_pool_num];
        (void)memset(s, 0, sizeof(*s));
        s->type = UMQ_QBUF_POOL_TYPE_SMALL;
        uint64_t sum_cap = 0;
        uint64_t sum_cnt = 0;
        for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
            sum_cap += pool_iter->block_pool.capacity_with_data[sc];
            sum_cnt += pool_iter->block_pool.buf_cnt_with_data[sc];
            /* per-sc TLS breakdown (new DFX field). capacity_with_data/buf_cnt_with_data
             * above are the SUM of these per-sc entries. */
            s->sc_capacity_with_data[sc] = pool_iter->block_pool.capacity_with_data[sc];
            s->sc_buf_cnt_with_data[sc] = pool_iter->block_pool.buf_cnt_with_data[sc];
        }
        s->sc_count = g_qbuf_pool.size_class_count;
        s->capacity_with_data = sum_cap;
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
        if (!pool_iter->inited) {
            continue;
        }
        (void)pthread_spin_lock(&g_qbuf_pool.block_pool[0].global_mutex);
        (void)pthread_spin_lock(&pool_iter->block_pool.list_lock);
        umq_buf_t *detached_head = QBUF_LIST_FIRST(&pool_iter->block_pool.head_without_data);
        QBUF_LIST_FIRST(&pool_iter->block_pool.head_without_data) = NULL;
        pool_iter->block_pool.buf_cnt_without_data = 0;
        (void)pthread_spin_unlock(&pool_iter->block_pool.list_lock);
        if (detached_head == NULL) {
            (void)pthread_spin_unlock(&g_qbuf_pool.block_pool[0].global_mutex);
            continue;
        }
        uint64_t return_buf_cnt = return_list_to_pools(detached_head,
                                                       &g_qbuf_pool.block_pool[0].head_without_data,
                                                       &g_qbuf_pool.block_pool[0].buf_cnt_without_data, false, 0);
        /* buf_cnt already zeroed under list_lock */
        uint64_t cap = __atomic_load_n(&pool_iter->block_pool.capacity_without_data, __ATOMIC_RELAXED);
        uint64_t cap_sub = (return_buf_cnt > cap) ? cap : return_buf_cnt;
        (void)__atomic_fetch_sub(&pool_iter->block_pool.capacity_without_data, cap_sub, __ATOMIC_RELAXED);
        __atomic_fetch_sub(&g_total_local_cap_without_data, cap_sub, __ATOMIC_RELAXED);
        (void)pthread_spin_unlock(&g_qbuf_pool.block_pool[0].global_mutex);
        if (qbuf_debug_on())
            g_dbg_stats.tls_flush_nodata_bufs += return_buf_cnt;
    }
    (void)pthread_spin_unlock(&g_tls_stats_lock);
}
