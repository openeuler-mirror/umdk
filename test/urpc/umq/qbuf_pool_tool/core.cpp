/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* Core TU: tool state + command dispatch. No longer #includes umq_qbuf_pool.c
 * — the .c is compiled into the tool target via CMakeLists.txt (alongside
 * umq_qbuf_pool_base.c and umq_dfx_api_str.c). All access to umq pool state
 * goes through the public DFX API (umq_stats_qbuf_pool_get +
 * umq_qbuf_pool_stats_to_str) and the public umq_qbuf_pool.h functions
 * (init/uninit/normal_qbuf_alloc/qbuf_free/mode_get/buf_size_small). */

#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "qbuf_pool_tool.h"
#include "umq_dfx_api.h" /* umq_stats_qbuf_pool_get + umq_qbuf_pool_stats_to_str */
#include "umq_rx_qbuf_pool.h"
#include "umq_tiny_qbuf_pool.h"

/* ===================== tool state (definitions) ===================== */
std::vector<std::unique_ptr<Worker>> g_workers;
std::vector<std::string> g_actions;
void *g_buf_addr = nullptr;
uint64_t g_buf_size = 0;
bool g_inited = false;
bool g_scale_cap_enabled = true;
uint32_t g_block_sizes[UMQ_SIZE_CLASS_MAX] = {0};
uint32_t g_block_size_count = 0;

static uint32_t BlkSizeToScFallback(uint32_t blk_size)
{
    for (uint32_t s = 0; s < g_block_size_count; s++) {
        if (blk_size == g_block_sizes[s]) return s;
    }
    return 0;
}


/* stress mode globals — set by DoStressRepeatBlock via StressModeGuard RAII.
 * DrainWorkerResult reads g_stress_mode to skip g_actions writes + per-buf
 * printf so memory stays bounded for days-long infinite-loop runs. g_stress
 * counters are bumped in DrainWorkerResult (main thread only, no atomic
 * needed). g_stop_requested is set by SIGINT/SIGTERM handler installed in
 * DoStressRepeatBlock; the loop checks it at iter boundary and breaks
 * gracefully. */
bool g_stress_mode = false;
volatile sig_atomic_t g_stop_requested = 0;
StressCounters g_stress = {0, 0, 0, 0, 0, 0, 0, 0, false};

/* Verbose timing instrumentation: enabled by env var QBUF_TOOL_VERBOSE=1.
 * Off by default to keep stress-case output clean. When on, prints to
 * stderr so it doesn't mix with buf[i] stdout lines (the user can
 * 2>/dev/null to silence or 2>&1 to interleave). */
static bool g_verbose = false;
static bool g_verbose_inited = false;
static void InitVerbose()
{
    if (g_verbose_inited) {
        return;
    }
    const char *v = getenv("QBUF_TOOL_VERBOSE");
    g_verbose = (v != nullptr && (strcmp(v, "1") == 0 || strcmp(v, "true") == 0));
    g_verbose_inited = true;
}
bool VerboseEnabled()
{
    InitVerbose();
    return g_verbose;
}
uint64_t NowMicros()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* GetRssKb: read VmRSS from /proc/self/status (Linux-only, matches `ps` RSS).
 * Used by stress snapshot to track memory growth — if RSS grows linearly with
 * iterations, there's a leak; if it's stable, alloc/free is balanced. */
static uint64_t GetRssKb()
{
    FILE *f = fopen("/proc/self/status", "r");
    if (f == nullptr) {
        return 0;
    }
    char line[256];
    uint64_t rss = 0;
    while (fgets(line, sizeof(line), f) != nullptr) {
        if (sscanf(line, "VmRSS: %lu kB", (unsigned long *)&rss) == 1) {
            break;
        }
    }
    fclose(f);
    return rss;
}

/* Stub for mempool_segment_ops_t.register_seg_callback (C linkage). Used by
 * DoInit when scaleCap is enabled. */
extern "C" {
static int stub_register_seg(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size)
{
    (void)ctx;
    (void)mempool_id;
    (void)addr;
    (void)size;
    return 0;
}
}

/* ===================== helpers ===================== */
/* SPLIT mode: buf_size = block_size + sizeof(umq_buf_t); COMBINE: buf_size = block_size.
 * Replaces the previous direct read of g_qbuf_pool.mode with the public
 * umq_qbuf_mode_get() accessor. */
uint32_t BufToBlkSize(umq_buf_t *buf)
{
    if (umq_qbuf_mode_get() == UMQ_BUF_SPLIT) {
        return buf->buf_size - (uint32_t)sizeof(umq_buf_t);
    }
    return buf->buf_size;
}

/* Map a buf's blk_size back to a size_class index by linear-scanning the
 * sc_info[] array from DFX stats. Equivalent to the production static helper
 * blk_size_to_sc() in umq_qbuf_pool.c, which is no longer visible to the
 * tool after removing the #include of umq_qbuf_pool.c. Returns 0 for any
 * blk_size not in sc_info[] (matching blk_size_to_sc's fallback). */
uint32_t BlkSizeToSc(uint32_t blk_size, const umq_qbuf_sc_info_t *sc_info, uint32_t sc_count)
{
    for (uint32_t sc = 0; sc < sc_count; ++sc) {
        if (sc_info[sc].blk_size == blk_size) {
            return sc;
        }
    }
    return 0;
}

/* PoolMemBreakdown: breakdown of memory the pool has claimed from OS.
 * Used by DoInfo / DoStatus to print "Pool OS Mem Claimed" — to verify that
 * RSS growth is NOT from the pool (which is bounded by these three counters).
 *
 * The pool claims OS memory at exactly 3 places (see umq_qbuf_pool.c):
 *   1) initial   — g_buf_addr (cfg.total_size, memalign'd by tool DoInit,
 *                  passed via cfg.buf_addr). Recorded as g_qbuf_pool.total_size.
 *   2) expansion — slot->buffer (memalign in slot_with_data_init /
 *                  slot_without_data_init). Sum tracked by CAS-protected
 *                  g_qbuf_pool.exp_total_mem_pool_size (see
 *                  try_inc_atomic_exp_mem_size / slot_uninit).
 *   3) escape    — buf_data (memalign in umq_qbuf_alloc_escape). Per-buf size =
 *                  sc_info[sc].blk_size + umq_buf_t_size. Count tracked by
 *                  g_escape_buf_cnt[sc] (per-size_class).
 *
 * NOT in pool's claim (tool's own bookkeeping, separate from this number):
 *   - g_actions vector buffer / std::string heap chunks (tool's history log)
 *   - worker pthread stacks / shared lib Private_Dirty
 *   - slot metadata calloc / async_expand_pool_param (transient, <1 KB total)
 *
 * All 3 components derived from existing DFX fields — no production code change. */
struct PoolMemBreakdown {
    uint64_t initial;   /* cfg.total_size (g_buf_addr) */
    uint64_t expansion; /* exp_total_mem_pool_size (CAS-tracked) */
    uint64_t escape;    /* sum(escape_buf_cnt_by_sc[sc] * (blk_size[sc] + umq_buf_t_size)) */
    uint64_t total;     /* sum of the three */
};
static PoolMemBreakdown CalcPoolOsMemClaimed(const umq_qbuf_pool_stats_t &stats)
{
    PoolMemBreakdown r = {0, 0, 0, 0};
    if (stats.num == 0) {
        return r;
    }
    const umq_qbuf_pool_info_t *pinfo = &stats.qbuf_pool_info[0];
    /* total_size now includes expansion memory; subtract it to get init-only size. */
    r.expansion = pinfo->config.exp_total_mem_pool_size;
    r.initial = pinfo->total_size - r.expansion;
    /* escape alloc: per-sc buf count * (blk_size[sc] + sizeof(umq_buf_t)). */
    r.escape = 0;
    for (uint32_t sc = 0; sc < pinfo->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
        r.escape += stats.escape_buf_cnt_by_sc[sc] * (uint64_t)(pinfo->sc_info[sc].blk_size + pinfo->umq_buf_t_size);
    }
    r.total = r.initial + r.expansion + r.escape;
    return r;
}

/* ===================== worker thread ===================== */
/* WorkerMain: worker thread loop. Waits for task, executes it, signals done.
 * Worker owns its alloced/alloc_ops vectors — free returns bufs to this
 * worker's TLS (g_thread_cache is __thread). */
void *WorkerMain(void *arg)
{
    Worker *w = (Worker *)arg;
    /* Record OS kernel TID for DFX matching. Production code stores
     * syscall(SYS_gettid) in g_thread_cache.stats.tid, so DoStatus must
     * compare with the same value (not pthread_self address). */
    w->kernel_tid = (uint64_t)syscall(SYS_gettid);
    pthread_mutex_lock(&w->task.mtx);
    while (true) {
        while (!w->task.has_task) {
            pthread_cond_wait(&w->task.ready, &w->task.mtx);
        }
        /* Record worker-side start timestamp — proves task picked up by
         * worker thread (vs. main thread). Concurrent workers will have
         * start timestamps within microseconds of each other. */
        w->task.worker_start_us = NowMicros();
        switch (w->task.type) {
            case ThreadTask::ALLOC: {
                umq_alloc_option_t opt;
                memset(&opt, 0, sizeof(opt));
                opt.flag |= UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
                opt.headroom_size = w->task.headroom;
                QBUF_LIST_INIT(&w->task.alloc_list);
                int ret = umq_normal_qbuf_alloc(w->task.size, w->task.num, &opt, &w->task.alloc_list);
                w->task.ret = ret;
                w->task.alloc_cnt = 0;
                w->task.first_sc = 0;
                w->task.first_blk_size = 0;
                if (ret == 0) {
                    umq_buf_t *b = QBUF_LIST_FIRST(&w->task.alloc_list);
                    bool has_blk = false;
                    while (b != nullptr) {
                        if (!has_blk) {
                            /* Record first buf's blk_size; main thread resolves it
                         * to a size_class via BlkSizeToSc + DFX sc_info[]. */
                            w->task.first_blk_size = BufToBlkSize(b);
                            has_blk = true;
                        }
                        ++w->task.alloc_cnt;
                        b = QBUF_LIST_NEXT(b);
                    }
                }
                break;
            }
            case ThreadTask::FREE_IDX: {
                /* Stable orig_idx lookup: scan alloced for each buf whose orig_idx
                 * matches the user-requested index. orig_idx is assigned at drain
                 * time (DrainWorkerResult) and doesn't shift on erase — so
                 * `free 0; free 1; free 2; free 3; free 4` correctly frees 5
                 * bufs in original allocation order, regardless of prior frees.
                 * Supports multi-idx syntax `free 0,1,2` — one command frees
                 * multiple bufs, so parallel blocks can free multiple bufs per
                 * worker without violating "thread_K appears more than once" rule. */
                int freed_cnt = 0;
                int not_found_cnt = 0;
                for (uint32_t fi = 0; fi < w->task.free_count; fi++) {
                    uint32_t target = w->task.free_indices[fi];
                    auto it = std::find_if(w->alloced.begin(), w->alloced.end(),
                                           [target](const AllocedBuf &ab) { return ab.orig_idx == target; });
                    if (it == w->alloced.end()) {
                        ++not_found_cnt;
                        continue; /* orig_idx not found — already freed or never allocated */
                    }
                    AllocedBuf &ab = *it;
                    umq_buf_t *buf = ab.buf;
                    umq_buf_list_t list;
                    QBUF_LIST_INIT(&list);
                    QBUF_LIST_NEXT(buf) = QBUF_LIST_FIRST(&list);
                    QBUF_LIST_FIRST(&list) = buf;
                    if (w->alloc_ops[ab.op_idx].remaining > 0) {
                        --w->alloc_ops[ab.op_idx].remaining;
                    }
                    w->alloced.erase(it); /* erase doesn't affect other bufs' orig_idx */
                    umq_qbuf_free(&list);
                    ++freed_cnt;
                }
                w->task.ret = (not_found_cnt > 0) ? -not_found_cnt : freed_cnt;
                break;
            }
            case ThreadTask::FREE_ALL: {
                if (w->alloced.empty()) {
                    w->task.ret = 0;
                    break;
                }
                /* Separate with_data and nodata bufs into independent lists,
                 * matching production usage where they are freed separately. */
                umq_buf_list_t wd_list;
                umq_buf_list_t nd_list;
                umq_buf_list_t es_list;
                QBUF_LIST_INIT(&wd_list);
                QBUF_LIST_INIT(&nd_list);
                QBUF_LIST_INIT(&es_list);
                for (auto &ab : w->alloced) {
                    if (ab.buf->mempool_without_data == 1) {
                        QBUF_LIST_NEXT(ab.buf) = QBUF_LIST_FIRST(&nd_list);
                        QBUF_LIST_FIRST(&nd_list) = ab.buf;
                    } else if (ab.buf->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
                        QBUF_LIST_NEXT(ab.buf) = QBUF_LIST_FIRST(&es_list);
                        QBUF_LIST_FIRST(&es_list) = ab.buf;
                        umq_qbuf_free(&es_list);
                        QBUF_LIST_INIT(&es_list);
                    } else {
                        QBUF_LIST_NEXT(ab.buf) = QBUF_LIST_FIRST(&wd_list);
                        QBUF_LIST_FIRST(&wd_list) = ab.buf;
                    }
                }
                uint32_t cnt = (uint32_t)w->alloced.size();
                w->alloced.clear();
                w->alloc_ops.clear();
                w->next_orig_idx = 0; /* reset stable index counter — next alloc starts from 0 */
                if (QBUF_LIST_FIRST(&nd_list) != nullptr) {
                    umq_qbuf_free(&nd_list);
                }
                if (QBUF_LIST_FIRST(&wd_list) != nullptr) {
                    umq_qbuf_free(&wd_list);
                }
                w->task.ret = (int)cnt;
                break;
            }
            case ThreadTask::EXIT:
                w->task.has_task = false;
                w->task.finished = true;
                pthread_cond_signal(&w->task.done);
                pthread_mutex_unlock(&w->task.mtx);
                return NULL;
        }
        /* Record worker-side end timestamp — combined with start_us,
         * gives worker execution interval [start, end]. Concurrent workers
         * will have overlapping intervals (proves parallel execution). */
        w->task.worker_end_us = NowMicros();
        w->task.has_task = false;
        w->task.finished = true;
        pthread_cond_signal(&w->task.done);
    }
}

/* Dispatch: synchronous — fill task, signal worker, block on done.
 * Used by serial commands. After return, worker is idle and task results
 * (task.ret / task.alloc_list / task.first_blk_size) are stable for the
 * caller to read. */
void Dispatch(size_t widx, ThreadTask::Type type, uint32_t size, uint32_t num, uint16_t headroom,
              const uint32_t *free_indices, uint32_t free_count)
{
    Worker &w = *g_workers[widx];
    pthread_mutex_lock(&w.task.mtx);
    w.task.type = type;
    w.task.size = size;
    w.task.num = num;
    w.task.headroom = headroom;
    if (free_indices != nullptr && free_count > 0) {
        memcpy(w.task.free_indices, free_indices, sizeof(uint32_t) * free_count);
        w.task.free_count = free_count;
    } else {
        w.task.free_count = 0;
    }
    w.task.has_task = true;
    w.task.finished = false;
    QBUF_LIST_INIT(&w.task.alloc_list);
    pthread_cond_signal(&w.task.ready);
    while (!w.task.finished) {
        pthread_cond_wait(&w.task.done, &w.task.mtx);
    }
    pthread_mutex_unlock(&w.task.mtx);
}

/* DispatchAsync: asynchronous — fill task, signal worker, RETURN WITHOUT
 * waiting for done. The worker begins executing in parallel with other
 * workers dispatched in the same parallel/join block. Results must be
 * drained by SyncAll() before the caller touches w.task fields again. */
void DispatchAsync(size_t widx, ThreadTask::Type type, uint32_t size, uint32_t num, uint16_t headroom,
                   const uint32_t *free_indices, uint32_t free_count)
{
    Worker &w = *g_workers[widx];
    pthread_mutex_lock(&w.task.mtx);
    w.task.type = type;
    w.task.size = size;
    w.task.num = num;
    w.task.headroom = headroom;
    if (free_indices != nullptr && free_count > 0) {
        memcpy(w.task.free_indices, free_indices, sizeof(uint32_t) * free_count);
        w.task.free_count = free_count;
    } else {
        w.task.free_count = 0;
    }
    w.task.has_task = true;
    w.task.finished = false;
    QBUF_LIST_INIT(&w.task.alloc_list);
    w.has_async = true;
    pthread_cond_signal(&w.task.ready);
    pthread_mutex_unlock(&w.task.mtx);
}

/* SyncAll: barrier — for every worker with has_async==true, wait for done,
 * drain the result, clear has_async. After return, no worker is mutating
 * TLS, so DFX (umq_stats_qbuf_pool_get) is safe to call from main thread.
 *
 * Verbose mode: collects per-worker wait_us (time spent in
 * pthread_cond_wait for done — small if worker already finished before
 * we got to it = parallel execution) and prints a summary to stderr.
 * In a serial implementation every wait would be ~worker_exec_time; in
 * parallel execution, the first wait is ~max(worker_exec_time) and
 * subsequent waits are ~0 (workers already done). */
void SyncAll()
{
    bool verbose = VerboseEnabled();
    uint64_t barrier_start = verbose ? NowMicros() : 0;
    size_t pending_count = 0;
    uint64_t wait_min = UINT64_MAX;
    uint64_t wait_max = 0;
    uint64_t wait_sum = 0;
    uint64_t earliest_worker_start = UINT64_MAX;
    uint64_t latest_worker_end = 0;

    for (auto &w : g_workers) {
        if (w->has_async) {
            ++pending_count;
        }
    }
    if (verbose && pending_count > 0) {
        fprintf(stderr, "[sync] barrier start: %zu pending workers\n", pending_count);
    }

    for (auto &w : g_workers) {
        if (!w->has_async) {
            continue;
        }
        uint64_t wait_start = verbose ? NowMicros() : 0;
        pthread_mutex_lock(&w->task.mtx);
        while (!w->task.finished) {
            pthread_cond_wait(&w->task.done, &w->task.mtx);
        }
        uint64_t wait_end = verbose ? NowMicros() : 0;
        DrainWorkerResult(*w);
        w->has_async = false;
        pthread_mutex_unlock(&w->task.mtx);

        if (verbose) {
            uint64_t wait_us = wait_end - wait_start;
            if (wait_us < wait_min) {
                wait_min = wait_us;
            }
            if (wait_us > wait_max) {
                wait_max = wait_us;
            }
            wait_sum += wait_us;
            if (w->task.worker_start_us < earliest_worker_start) {
                earliest_worker_start = w->task.worker_start_us;
            }
            if (w->task.worker_end_us > latest_worker_end) {
                latest_worker_end = w->task.worker_end_us;
            }
            fprintf(stderr,
                    "[sync] t%u drained: worker ran [%lu..%lu]μs (dur=%luμs), "
                    "main waited %luμs for done\n",
                    w->idx, (unsigned long)w->task.worker_start_us, (unsigned long)w->task.worker_end_us,
                    (unsigned long)(w->task.worker_end_us - w->task.worker_start_us), (unsigned long)wait_us);
        }
    }

    if (verbose && pending_count > 0) {
        uint64_t barrier_end = NowMicros();
        uint64_t barrier_total = barrier_end - barrier_start;
        /* Parallel execution window: from earliest worker_start to latest
         * worker_end. If workers truly ran in parallel, this window is
         * much smaller than the sum of per-worker durations (which would
         * be the case in serial execution). */
        uint64_t parallel_window = (earliest_worker_start < UINT64_MAX) ? (latest_worker_end - earliest_worker_start) :
                                                                          0;
        fprintf(stderr,
                "[sync] barrier complete: total=%luμs, parallel_exec_window=%luμs, "
                "per-worker wait: min=%luμs max=%luμs avg=%luμs\n",
                (unsigned long)barrier_total, (unsigned long)parallel_window, (unsigned long)wait_min,
                (unsigned long)wait_max, (unsigned long)(pending_count > 0 ? wait_sum / pending_count : 0));
        fprintf(stderr, "[sync]   (if serial, expected total ~= sum of per-worker durations; "
                        "if parallel, total ~= max + drain overhead)\n");
    }
}

/* FreeAllOnWorkers: dispatch FREE_ALL to every worker (reinit path — bufs
 * still valid, workers still alive, free returns to each worker's TLS). */
void FreeAllOnWorkers()
{
    for (auto &w : g_workers) {
        if (w->running) {
            Dispatch(w->idx, ThreadTask::FREE_ALL);
        }
    }
}

/* StopWorkers: dispatch EXIT + join every worker. */
void StopWorkers()
{
    for (auto &w : g_workers) {
        if (w->running) {
            Dispatch(w->idx, ThreadTask::EXIT);
            pthread_join(w->tid, NULL);
            w->running = false;
        }
    }
}

/* Cleanup at program exit: do NOT auto-free worker allocs — let testers
 * free themselves so leak scenarios are observable via 'status' (alloced>0).
 * Leak check per-worker, then stop workers + uninit pool + free buf.
 * SyncAll first so any pending async tasks (e.g. user forgot 'join' or
 * script aborted mid-parallel-block) are drained before the leak check. */
void Cleanup()
{
    if (g_inited) {
        SyncAll();
        for (auto &w : g_workers) {
            if (w->running && !w->alloced.empty()) {
                fprintf(stderr, "NOTE: thread %u has %zu bufs unfreed (leak scenario)\n", w->idx, w->alloced.size());
            }
        }
        StopWorkers();
        umq_qbuf_pool_uninit();
        g_inited = false;
    }
    if (g_buf_addr != nullptr) {
        free(g_buf_addr);
        g_buf_addr = nullptr;
        g_buf_size = 0;
    }
    g_workers.clear();
    g_actions.clear();
}

/* ===================== commands ===================== */
int DoInit(const std::vector<std::string> &args)
{
    uint32_t count = 2;
    umq_buf_mode_t mode = UMQ_BUF_SPLIT;
    bool scaleCapEnable = true; /* enable expansion/shrink */
    uint64_t totalSz = 200ULL * 1024 * 1024;
    uint64_t tlsBudget = 0;
    /* expSlotSz: per-expansion slot target memory (cfg.expansion_size, default 32MB when 0).
     * poolMaxSz: total buf pool ceiling = initial pool + all expansion slots
     *            (cfg.umq_buf_pool_max_size, default 2GB when 0, hard cap 6GB).
     * The two are independent — poolMaxSz caps the cumulative expansion memory
     * (via derived expansion_mem_size_max), expSlotSz only suggests per-slot
     * granularity. Setting expSlotSz > poolMaxSz yields expansion slots that
     * can never fit under the cap, so any expansion trigger fails with ENOMEM. */
    uint64_t expSlotSz = 0;
    uint64_t poolMaxSz = 0;
    /* blockSizes: explicit per-SC block sizes (cfg.explicit_block_sizes[],
     * umq_qbuf_pool_base.h:106). Format: "4K,64K" or "4096,65536" — comma
     * separated, count must match `count` param. REQUIRED (no fallback) —
     * previous `mult` parameter was removed because all cases now use
     * blockSizes= directly. Production sets this to UmqSetting::UMQ_EXPLICIT_BLOCK_SIZES
     * via memcpy (umq_backend.cpp:67-69). */
    uint32_t blockSizes[UMQ_SIZE_CLASS_MAX] = {0};
    bool blockSizesSet = false;
    /* blockCounts: per-SC initial block counts (cfg.per_sc_block_counts[],
     * umq_qbuf_pool_base.h:103). Format: "1024,16" — comma separated, count must
     * match `count` param. Value 0 means lazy SC (no initial reserve, expansion pool
     * only — replaces the old lazy_init_block_size_threshold
     * When not set, cfg.per_sc_block_counts stays all-zero; production
     * init_size_class_config() uses total_size to auto-derive block counts.
     * Replaces the removed per_sc_weights[] (commit 099abae). */
    uint64_t blockCounts[UMQ_SIZE_CLASS_MAX] = {0};
    bool blockCountsSet = false;
    uint64_t tlsDepths[UMQ_SIZE_CLASS_MAX] = {0};
    bool tlsDepthsSet = false;
    /* escapeEnable: malloc escape fallback switch (cfg.disable_malloc_escape =
     * !escapeEnable). Default true — escape enabled, matches production default.
     * When off, umq_qbuf_escape_alloc returns EINVAL immediately (umq_qbuf_pool.c:2034)
     * and umq_normal_qbuf_alloc skips internal escape paths (:2143/:2182). */
    bool escapeEnable = true;
    /* expThreshold: expansion trigger water level % (cfg.expansion_threshold,
     * default 30 when 0 — QBUF_POOL_DEFAULT_EXPANSION_THRESHOLD). Controls
     * trigger_expand_block_num = expansion_block_count * threshold / 100.
     * Production validates [1, 100] (umq_qbuf_pool.c:1225-1228). */
    uint32_t expThreshold = 0;
    /* tlsExpandBudget: per-thread TLS bytes cap (cfg.tls_expand_qbuf_pool_depth,
     * default 7/8 of tlsBudget when 0 — umq_qbuf_pool_expand_max). Caps
     * per-thread TLS fetch: local_total_bytes + delta > tlsExpandBudget
     * truncates delta (umq_qbuf_pool.c:1666-1669). Independent from
     * tlsBudget (global cap across all threads). */
    uint64_t tlsExpandBudget = 0;
    uint32_t threads = 1; /* number of worker threads (default 1) */

    for (size_t i = 1; i < args.size(); ++i) {
        std::string k, v;
        if (!SplitKv(args[i], k, v)) {
            fprintf(stderr, "ERROR: init bad token '%s' (expect key=value)\n", args[i].c_str());
            return -1;
        }
        if (k == "count") {
            count = (uint32_t)strtoul(v.c_str(), nullptr, 10);
        } else if (k == "mode") {
            mode = ModeStrToEnum(v.c_str());
        } else if (k == "scaleCap") {
            scaleCapEnable = OnOffToBool(v.c_str(), true);
        } else if (k == "totalSz") {
            totalSz = ParseSize(v.c_str());
        } else if (k == "tlsBudget") {
            tlsBudget = ParseSize(v.c_str());
        } else if (k == "expSlotSz") {
            expSlotSz = ParseSize(v.c_str());
        } else if (k == "poolMaxSz") {
            poolMaxSz = ParseSize(v.c_str());
        } else if (k == "blockSizes") {
            /* Parse "4K,64K" / "4096,65536" / "4K,32K,128K" into blockSizes[].
             * Each token supports K/M/G suffix (ParseSize). Token count must
             * equal `count` — checked after loop. */
            uint32_t bi = 0;
            std::string tok;
            for (size_t p = 0; p <= v.size(); ++p) {
                if (p == v.size() || v[p] == ',') {
                    if (!tok.empty()) {
                        if (bi >= UMQ_SIZE_CLASS_MAX) {
                            fprintf(stderr, "ERROR: blockSizes has > %u tokens\n", UMQ_SIZE_CLASS_MAX);
                            return -1;
                        }
                        blockSizes[bi++] = (uint32_t)ParseSize(tok.c_str());
                        tok.clear();
                    }
                } else {
                    tok.push_back(v[p]);
                }
            }
            if (bi == 0) {
                fprintf(stderr, "ERROR: blockSizes is empty\n");
                return -1;
            }
            if (bi != count) {
                fprintf(stderr, "ERROR: blockSizes has %u tokens but count=%u\n", bi, count);
                return -1;
            }
            blockSizesSet = true;
        } else if (k == "blockCounts") {
            /* Parse "1024,16" / "1024,16,0" into blockCounts[]. Token count must equal
             * `count`. Value 0 means lazy SC (no initial reserve, expansion pool only). */
            uint32_t bi = 0;
            std::string tok;
            for (size_t p = 0; p <= v.size(); ++p) {
                if (p == v.size() || v[p] == ',') {
                    if (!tok.empty()) {
                        if (bi >= UMQ_SIZE_CLASS_MAX) {
                            fprintf(stderr, "ERROR: blockCounts has > %u tokens\n", UMQ_SIZE_CLASS_MAX);
                            return -1;
                        }
                        blockCounts[bi++] = ParseSize(tok.c_str());
                        tok.clear();
                    }
                } else {
                    tok.push_back(v[p]);
                }
            }
            if (bi == 0) {
                fprintf(stderr, "ERROR: blockCounts is empty\n");
                return -1;
            }
            if (bi != count) {
                fprintf(stderr, "ERROR: blockCounts has %u tokens but count=%u\n", bi, count);
                return -1;
            }
            blockCountsSet = true;
                } else if (k == "tlsDepths") {
            /* Parse "2048,256" into tlsDepths[]. Token count must equal `count`.
             * Value 0 means use global tls_qbuf_pool_depth default. */
            uint32_t di = 0;
            std::string tok;
            for (size_t p = 0; p <= v.size(); ++p) {
                if (p == v.size() || v[p] == ',') {
                    if (!tok.empty()) {
                        if (di >= UMQ_SIZE_CLASS_MAX) {
                            fprintf(stderr, "ERROR: tlsDepths has > %u tokens\n", UMQ_SIZE_CLASS_MAX);
                            return -1;
                        }
                        tlsDepths[di++] = ParseSize(tok.c_str());
                        tok.clear();
                    }
                } else {
                    tok.push_back(v[p]);
                }
            }
            if (di == 0) {
                fprintf(stderr, "ERROR: tlsDepths is empty\n");
                return -1;
            }
            if (di != count) {
                fprintf(stderr, "ERROR: tlsDepths has %u tokens but count=%u\n", di, count);
                return -1;
            }
            tlsDepthsSet = true;
} else if (k == "escape") {
            escapeEnable = OnOffToBool(v.c_str(), true);
        } else if (k == "expThreshold") {
            expThreshold = (uint32_t)strtoul(v.c_str(), nullptr, 10);
        } else if (k == "tlsExpandBudget") {
            tlsExpandBudget = ParseSize(v.c_str());
        } else if (k == "threads") {
            threads = (uint32_t)strtoul(v.c_str(), nullptr, 10);
        } else {
            fprintf(stderr, "ERROR: init unknown key '%s'\n", k.c_str());
            return -1;
        }
    }

    if (threads == 0) {
        fprintf(stderr, "ERROR: threads must be >= 1\n");
        return -1;
    }
    if (!blockSizesSet) {
        fprintf(stderr, "ERROR: blockSizes= is required (e.g. blockSizes=4K,64K)\n");
        return -1;
    }

    /* reinit: free outstanding bufs to old TLS, stop old workers, uninit pool */
    if (g_inited || g_buf_addr != nullptr) {
        if (g_inited) {
            FreeAllOnWorkers();
        }
        Cleanup();
    }

    g_buf_addr = memalign(2UL * 1024 * 1024, totalSz);
    if (g_buf_addr == nullptr) {
        fprintf(stderr, "ERROR: memalign %lu failed\n", (unsigned long)totalSz);
        return -1;
    }
    memset(g_buf_addr, 0, totalSz);
    g_buf_size = totalSz;

    /* Derive base enum from blockSizes[0]. Production umq_qbuf_pool.c:1529
     * requires explicit_block_sizes[0] == umq_buf_size_small() (which is
     * set by umq_buf_size_pow_small_set). The old `base=` init parameter
     * was removed — base is now derived automatically from blockSizes[0],
     * removing the redundant param that had to match blockSizes[0] anyway. */
    (void)umq_buf_size_pow_small_set(BlkSizeToEnum(blockSizes[0]));

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = g_buf_addr;
    cfg.total_size = totalSz;
    cfg.data_size = umq_buf_size_small();
    cfg.mode = mode;
    cfg.size_class_count = count;
    /* explicit_block_sizes[]: required, set from blockSizes= param. Matches
     * production umq_backend.cpp:67-69 memcpy of UmqSetting::UMQ_EXPLICIT_BLOCK_SIZES. */
    for (uint32_t i = 0; i < count; i++) {
        cfg.explicit_block_sizes[i] = blockSizes[i];
    }
    cfg.disable_scale_cap = !scaleCapEnable; g_scale_cap_enabled = scaleCapEnable; g_block_size_count = count; for (uint32_t i = 0; i < count; i++) g_block_sizes[i] = blockSizes[i];
    /* tlsBudget/tlsExpandBudget: count-based depth caps (tls_qbuf_pool_depth/
     * tls_expand_qbuf_pool_depth). When 0, production uses defaults. */
    cfg.tls_qbuf_pool_depth = tlsBudget;
    cfg.expansion_size = expSlotSz;
    cfg.umq_buf_pool_max_size = poolMaxSz;
    /* per_sc_block_counts[]: when blockCounts= is set, use the explicit values.
     * Otherwise fill defaults (QBUF_POOL_BLOCK_COUNT_DEFAULT) to match production
     * umq_qbuf_pool_cfg_check() behavior — without this, init_split_mode_layout
     * skips SCs with count==0 (no data region allocated, TotalSize shows 0). */
    if (blockCountsSet) {
        for (uint32_t i = 0; i < count; i++) {
            cfg.per_sc_block_counts[i] = blockCounts[i];
        }
    } else {
        for (uint32_t i = 0; i < count; i++) {
            cfg.per_sc_block_counts[i] = QBUF_POOL_BLOCK_COUNT_DEFAULT;
        }
    }
    /* per_sc_tls_qbuf_pool_depth[]: when tlsDepths= is set, use the explicit
     * values. Otherwise fill defaults (QBUF_POOL_TLS_DEPTH_DEFAULT). */
    if (tlsDepthsSet) {
        for (uint32_t i = 0; i < count; i++) {
            cfg.per_sc_tls_qbuf_pool_depth[i] = tlsDepths[i];
        }
    } else {
        for (uint32_t i = 0; i < count; i++) {
            cfg.per_sc_tls_qbuf_pool_depth[i] = QBUF_POOL_TLS_DEPTH_DEFAULT;
        }
    }
    cfg.disable_malloc_escape = !escapeEnable;
    cfg.expansion_threshold = expThreshold;
    cfg.tls_expand_qbuf_pool_depth = tlsExpandBudget;
    if (scaleCapEnable) {
        cfg.seg_ops.register_seg_callback = stub_register_seg;
    }

    int ret = umq_qbuf_pool_init(&cfg);
    if (ret != 0) {
        fprintf(stderr, "ERROR: umq_qbuf_pool_init failed ret=%d\n", ret);
        free(g_buf_addr);
        g_buf_addr = nullptr;
        g_buf_size = 0;
        return -1;
    }

    /* RX pool: production sets rx_block_count = UBS_RX_PORT_NUM * UBS_RX_DEPTH (default 4*1024=4096).
     * Each RX block = 4K data + 128B header = 4224B; total = 4096 * 4224 ≈ 16.5MB. */
    const uint32_t rx_blk_count = 4096;
    const uint32_t rx_blk_size = UMQ_RX_QBUF_BLOCK_SIZE;
    const uint64_t rx_total_size = (uint64_t)rx_blk_count * (rx_blk_size + sizeof(umq_buf_t));
    if (umq_rx_io_buf_malloc(mode, rx_total_size) != NULL) {
        qbuf_pool_cfg_t rx_cfg;
        memset(&rx_cfg, 0, sizeof(rx_cfg));
        rx_cfg.buf_addr = umq_rx_io_buf_addr();
        rx_cfg.total_size = umq_rx_io_buf_size();
        rx_cfg.data_size = rx_blk_size;
        rx_cfg.mode = mode;
        int rx_ret = umq_rx_qbuf_pool_init(&rx_cfg);
        if (rx_ret != 0 && rx_ret != -UMQ_ERR_EEXIST) {
            fprintf(stderr, "WARN: umq_rx_qbuf_pool_init failed ret=%d (RX pool will show 0)\n", rx_ret);
        }
    }

    /* Tiny pool: production defaults block_count=8192, block_size=1024.
     * Each tiny block = 1K data + 128B header = 1152B; total = 8192 * 1152 ≈ 9MB. */
    const uint32_t tiny_blk_count = TINY_QBUF_POOL_DEFAULT_BLOCK_COUNT;
    const uint32_t tiny_blk_size = UMQ_TINY_QBUF_BLOCK_SIZE;
    const uint64_t tiny_total_size = (uint64_t)tiny_blk_count * (tiny_blk_size + sizeof(umq_buf_t));
    if (umq_tiny_io_buf_malloc(mode, tiny_total_size) != NULL) {
        qbuf_pool_cfg_t tiny_cfg;
        memset(&tiny_cfg, 0, sizeof(tiny_cfg));
        tiny_cfg.buf_addr = umq_tiny_io_buf_addr();
        tiny_cfg.total_size = umq_tiny_io_buf_size();
        tiny_cfg.data_size = tiny_blk_size;
        tiny_cfg.mode = mode;
        int tiny_ret = umq_tiny_qbuf_pool_init(&tiny_cfg);
        if (tiny_ret != 0 && tiny_ret != -UMQ_ERR_EEXIST) {
            fprintf(stderr, "WARN: umq_tiny_qbuf_pool_init failed ret=%d (Tiny pool will show 0)\n", tiny_ret);
        }
    }
    g_inited = true;

    /* start worker threads — each gets its own TLS (g_thread_cache) */
    g_workers.clear();
    for (uint32_t i = 0; i < threads; ++i) {
        std::unique_ptr<Worker> w(new Worker());
        w->idx = i;
        int r = pthread_create(&w->tid, NULL, WorkerMain, w.get());
        if (r != 0) {
            fprintf(stderr, "ERROR: pthread_create worker %u failed ret=%d\n", i, r);
            StopWorkers();
            umq_qbuf_pool_uninit();
            g_inited = false;
            free(g_buf_addr);
            g_buf_addr = nullptr;
            g_buf_size = 0;
            return -1;
        }
        w->running = true;
        g_workers.push_back(std::move(w));
    }

    /* Build blockSizes/weights display strings for printf + action log.
     * When not set, show "default" so the log reflects which path was taken
     * (all-zero → production all-1 fallback). */
    char blockSizesStr[128] = {0};
    {
        int n = 0;
        for (uint32_t i = 0; i < count; i++) {
            n += snprintf(blockSizesStr + n, sizeof(blockSizesStr) - n, "%s%u", (i ? "," : ""), blockSizes[i]);
        }
    }
    char blockCountsStr[128] = {0};
    if (blockCountsSet) {
        int n = 0;
        for (uint32_t i = 0; i < count; i++) {
            n += snprintf(blockCountsStr + n, sizeof(blockCountsStr) - n, "%s%lu", (i ? "," : ""), (unsigned long)blockCounts[i]);
        }
    } else {
        snprintf(blockCountsStr, sizeof(blockCountsStr), "auto");
    }
    char tlsDepthsStr[128] = {0};
    if (tlsDepthsSet) {
        int n = 0;
        for (uint32_t i = 0; i < count; i++) {
            n += snprintf(tlsDepthsStr + n, sizeof(tlsDepthsStr) - n, "%s%lu", (i ? "," : ""), (unsigned long)tlsDepths[i]);
        }
    } else {
        snprintf(tlsDepthsStr, sizeof(tlsDepthsStr), "default");
    }

    printf("pool inited ok (threads=%u count=%u mode=%s scaleCap=%s totalSz=%lu poolMaxSz=%lu "
           "expSlotSz=%lu blockSizes=%s blockCounts=%s tlsDepths=%s escape=%s expThreshold=%u tlsExpandBudget=%lu)\n",
           threads, count, (mode == UMQ_BUF_SPLIT ? "split" : "combine"),
           (scaleCapEnable ? "on" : "off"), (unsigned long)totalSz, (unsigned long)poolMaxSz,
           (unsigned long)expSlotSz, blockSizesStr, blockCountsStr, tlsDepthsStr,
           (escapeEnable ? "on" : "off"), expThreshold, (unsigned long)tlsExpandBudget);
    char act[512];
    snprintf(act, sizeof(act),
             "init threads=%u count=%u mode=%s scaleCap=%s totalSz=%lu poolMaxSz=%lu "
             "expSlotSz=%lu blockSizes=%s blockCounts=%s tlsDepths=%s escape=%s expThreshold=%u tlsExpandBudget=%lu",
             threads, count, (mode == UMQ_BUF_SPLIT ? "split" : "combine"),
             (scaleCapEnable ? "on" : "off"), (unsigned long)totalSz, (unsigned long)poolMaxSz,
             (unsigned long)expSlotSz, blockSizesStr, blockCountsStr, tlsDepthsStr,
             (escapeEnable ? "on" : "off"), expThreshold, (unsigned long)tlsExpandBudget);
    g_actions.push_back(act);
    return 0;
}

int DoAlloc(const std::vector<std::string> &args, size_t widx, bool async)
{
    if (!g_inited) {
        fprintf(stderr, "ERROR: pool not inited\n");
        return -1;
    }
    if (widx >= g_workers.size()) {
        fprintf(stderr, "ERROR: thread_%zu not started (have %zu workers)\n", widx, g_workers.size());
        return -1;
    }
    if (args.size() < 2) {
        fprintf(stderr, "ERROR: alloc needs <size> [num] [headroom]\n");
        return -1;
    }
    uint32_t size = (uint32_t)ParseSize(args[1].c_str());
    uint32_t num = (args.size() >= 3) ? (uint32_t)strtoul(args[2].c_str(), nullptr, 10) : 1;
    uint16_t headroom = (args.size() >= 4) ? (uint16_t)strtoul(args[3].c_str(), nullptr, 10) : 0;
    if (num == 0) {
        fprintf(stderr, "ERROR: alloc num invalid\n");
        return -1;
    }
    if (size == 0) {
        /* without_data path: request_size=0 triggers header-only borrow in
         * umq_normal_qbuf_alloc (umq_qbuf_pool.c:1942). Production constraints:
         *   - headroom not supported when size=0 (umq_qbuf_pool.c:1943-1946)
         *   - mode must be SPLIT (umq_qbuf_pool.c:1948-1951, COMBINE has no
         *     separate header region for without_data pool)
         * Tool previously rejected size=0 as "invalid"; now routed to the
         * production without_data path. buf->mempool_without_data=1 marks
         * these bufs so DrainWorkerResult / DoStatus can distinguish them
         * from with_data bufs (which would otherwise mis-route to sc=0
         * because BufToBlkSize returns 0 for header-only bufs). */
        if (headroom > 0) {
            fprintf(stderr, "ERROR: headroom not supported when size=0 (without_data path)\n");
            return -1;
        }
        if (umq_qbuf_mode_get() != UMQ_BUF_SPLIT) {
            fprintf(stderr, "ERROR: alloc size=0 (without_data) only supported in SPLIT mode\n");
            return -1;
        }
    }
    /* Parallel-mode safety cap: avoids OOM in long-running stress blocks
     * where repeat*alloc*num accumulates bufs before the matching free. */
    if (num > 1000) {
        fprintf(stderr, "ERROR: alloc num must be <= 1000 (got %u)\n", num);
        return -1;
    }

    Worker &w = *g_workers[widx];

    /* Per-worker total held buf cap. Bounds alloced vector memory and O(n)
     * scan time in FREE_IDX (which scans by orig_idx). Pool exhaustion
     * (umq_normal_qbuf_alloc returns ENOMEM) is the natural backstop and
     * usually kicks in first; this cap is a safety net for cases where the
     * pool is large but a worker accumulates bufs without freeing. */
    if (w.alloced.size() + num > WORKER_ALLOCED_CAP) {
        fprintf(stderr, "ERROR: [t%zu] alloc %u would exceed per-worker buf cap %u (current=%zu, requested=%u). "
                        "Free some bufs first (free <orig_idx>) or use `free all` to reset.\n",
                widx, num, WORKER_ALLOCED_CAP, w.alloced.size(), num);
        return -1;
    }

    if (async) {
        /* Reserve g_actions slot at dispatch time so the actions log
         * preserves dispatch order regardless of completion order.
         * DrainWorkerResult() will back-fill the string at SyncAll() time.
         * In stress mode, skip the reservation — pending_action_idx = SIZE_MAX
         * sentinel tells DrainWorkerResult not to touch g_actions. */
        if (!g_stress_mode) {
            g_actions.push_back(std::string());
            w.pending_action_idx = g_actions.size() - 1;
        } else {
            w.pending_action_idx = SIZE_MAX;
        }
        DispatchAsync(widx, ThreadTask::ALLOC, size, num, headroom);
        return 0;
    }

    /* Synchronous path: dispatch + drain inline. */
    Dispatch(widx, ThreadTask::ALLOC, size, num, headroom);
    if (w.task.ret != 0) {
        fprintf(stderr, "ERROR: [t%zu] alloc size=%u num=%u ret=%d\n", widx, size, num, w.task.ret);
        return -1;
    }
    DrainWorkerResult(w);
    return 0;
}

/* DrainWorkerResult: drain the worker's just-finished ALLOC task into
 * w.alloced / g_actions / w.alloc_ops. Called from DoAlloc (serial path)
 * and SyncAll (parallel path). Worker must be idle (task.finished==true,
 * mutex held by caller) when invoked — this guarantees DFX reads are safe.
 *
 * FREE_IDX/FREE_ALL tasks: action string was already back-filled at dispatch
 * time (see DoFree async path). SyncAll still calls us to clear has_async,
 * but we skip the alloc-drain path for non-ALLOC tasks. The only thing we
 * do for FREE tasks is patch the action string if ret indicates failure
 * (FREE_IDX returns -1 on out-of-range idx — but the dispatch-time check
 * already rejected that case, so this is a defensive backstop). */
void DrainWorkerResult(Worker &w)
{
    /* Non-ALLOC tasks: action string already back-filled at dispatch time.
     * Defensive: patch action if worker reported failure. */
    if (w.task.type == ThreadTask::FREE_IDX) {
        /* ret > 0: freed count; ret < 0: -(not found count); ret = 0: empty list (shouldn't happen) */
        if (w.task.ret > 0) {
            g_stress.total_frees++;
            g_stress.total_bufs_freed += (uint64_t)w.task.ret;
        } else {
            g_stress.total_free_errors++;
        }
        if (w.task.ret < 0 && w.has_async && !g_stress_mode) {
            char act[128];
            snprintf(act, sizeof(act), "[t%u] free FAILED (%d not found)", w.idx, -w.task.ret);
            g_actions[w.pending_action_idx] = act;
        }
        return;
    }
    if (w.task.type == ThreadTask::FREE_ALL) {
        /* FREE_ALL: ret is freed_cnt (>= 0). ret < 0 never happens. */
        if (w.task.ret >= 0) {
            g_stress.total_frees++;
            g_stress.total_bufs_freed += (uint64_t)w.task.ret;
        } else {
            g_stress.total_free_errors++;
        }
        return;
    }

    /* ALLOC task path: drain alloc_list, resolve sc, back-fill action. */
    if (w.task.ret != 0) {
        g_stress.total_alloc_errors++;
        /* Worker alloc failed — back-fill error action, leave alloced empty. */
        if (!g_stress_mode) {
            char act[128];
            snprintf(act, sizeof(act), "[t%u] alloc %u FAILED ret=%d", w.idx, w.task.size, w.task.ret);
            if (w.has_async) {
                g_actions[w.pending_action_idx] = act;
            } else {
                g_actions.push_back(act);
            }
        }
        return;
    }

    /* Fetch DFX sc_info[] so we can map blk_size -> sc for each drained buf.
     * Safe to call here: serial path has only one worker active (others idle);
     * parallel path requires SyncAll() to wait for all workers first.
     * scaleCap=off skips DFX: exp_pool slot_list is uninitialized, causing
     * SIGSEGV in umq_qbuf_pool_info_get. Use simple size-class fallback. */
    uint32_t first_sc = 0;
    if (g_scale_cap_enabled) {
        umq_qbuf_pool_stats_t stats;
        memset(&stats, 0, sizeof(stats));
        if (umq_stats_qbuf_pool_get(UMQ_INVALID_HANDLE, &stats) != 0 || stats.num == 0) {
            fprintf(stderr, "ERROR: [t%u] umq_stats_qbuf_pool_get failed during drain\n", w.idx);
            g_stress.total_alloc_errors++;
            if (!g_stress_mode && w.has_async) {
                char act[128];
                snprintf(act, sizeof(act), "[t%u] alloc %u -> DFX FAILED", w.idx, w.task.size);
                g_actions[w.pending_action_idx] = act;
            }
            return;
        }
        const umq_qbuf_pool_info_t *pinfo = &stats.qbuf_pool_info[0];
        first_sc = BlkSizeToSc(w.task.first_blk_size, pinfo->sc_info, pinfo->sc_count);
    } else if (w.task.first_blk_size > 0) {
        for (uint32_t s = 0; s < g_block_size_count; s++) {
            if (w.task.first_blk_size == g_block_sizes[s]) { first_sc = s; break; }
        }
    }

    /* For async path: g_actions slot already reserved at dispatch time
     * (SIZE_MAX sentinel in stress mode — see DoAlloc async path).
     * For serial path: reserve now (Dispatch returned, no slot was reserved).
     * In stress mode, skip the reservation entirely — actions_idx stays at
     * SIZE_MAX sentinel; status display recognises this and skips the action
     * cross-reference (since g_actions wasn't pushed for this op). */
    size_t actions_idx;
    if (w.has_async) {
        actions_idx = w.pending_action_idx;
    } else if (!g_stress_mode) {
        g_actions.push_back(std::string());
        actions_idx = g_actions.size() - 1;
    } else {
        actions_idx = SIZE_MAX;
    }

    /* Drain the buf list into w.alloced, print sc routing for each buf.
     * In stress mode, skip per-buf printf to keep output bounded for
     * long-running tests (millions of iters × N bufs would flood stdout).
     * orig_idx_start: captured before the buf loop — first buf of this op
     * gets orig_idx = orig_idx_start, subsequent bufs get +1, +2, ...
     * Display uses buf#<orig_idx> so user can directly `free <orig_idx>`. */
    uint32_t orig_idx_start = w.next_orig_idx;
    w.alloc_ops.push_back({w.task.size, 0, 0, 0, 0, w.idx, orig_idx_start});
    size_t op_idx = w.alloc_ops.size() - 1;
    uint32_t idx = 0;
    umq_buf_t *buf = QBUF_LIST_FIRST(&w.task.alloc_list);
    while (buf != nullptr) {
        umq_buf_t *next = QBUF_LIST_NEXT(buf);
        QBUF_LIST_NEXT(buf) = nullptr; /* detach */
        bool isNoData = (buf->mempool_without_data == 1);
        if (!g_stress_mode) {
            if (isNoData) {
                /* without_data buf: buf_size=sizeof(umq_buf_t), buf_data=NULL,
                 * no sc concept. Print [nodata] tag so tester can distinguish
                 * from with_data bufs (which would show sc=N ptr=0x... data_size=N).
                 * buf#<orig_idx> is the stable index for `free <orig_idx>`. */
                printf("[t%u] buf#%u: sc=- ptr=%p buf_size=%u data_size=%u headroom=%u [nodata]\n", w.idx,
                       w.next_orig_idx, (void *)buf->buf_data, buf->buf_size, buf->data_size, buf->headroom_size);
            } else {
                uint32_t blk = BufToBlkSize(buf);
                uint32_t sc = 0; if (g_scale_cap_enabled) { sc = BlkSizeToScFallback(blk); } else { for (uint32_t s = 0; s < g_block_size_count; s++) { if (blk == g_block_sizes[s]) { sc = s; break; } } }
                bool isEscape = (buf->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX);
                printf("[t%u] buf#%u: sc=%u ptr=%p buf_size=%u data_size=%u headroom=%u%s\n", w.idx, w.next_orig_idx,
                       sc, (void *)buf->buf_data, buf->buf_size, buf->data_size, buf->headroom_size,
                       isEscape ? " [escape]" : "");
            }
        }
        w.alloced.push_back({buf, op_idx, w.next_orig_idx});
        ++w.next_orig_idx;
        buf = next;
        ++idx;
    }
    /* Bump stress counters (single-threaded — main thread calls us).
     * Per-sc detail is not tracked here; see DFX stats (DoStatus section 3). */
    g_stress.total_allocs++;
    g_stress.total_bufs_alloced += idx;
    if (!g_stress_mode) {
        char act[128];
        if (w.task.size == 0) {
            snprintf(act, sizeof(act), "[t%u] alloc 0 -> nodata, %u buf%s", w.idx, idx, idx > 1 ? "s" : "");
        } else {
            snprintf(act, sizeof(act), "[t%u] alloc %u -> sc=%u, %u buf%s", w.idx, w.task.size, first_sc, idx,
                     idx > 1 ? "s" : "");
        }
        g_actions[actions_idx] = act;
    }
    w.alloc_ops[op_idx] = {w.task.size, first_sc, idx, idx, actions_idx, w.idx, orig_idx_start};
}

int DoFree(const std::vector<std::string> &args, size_t widx, bool async)
{
    if (!g_inited) {
        fprintf(stderr, "ERROR: pool not inited\n");
        return -1;
    }
    if (widx >= g_workers.size()) {
        fprintf(stderr, "ERROR: thread_%zu not started\n", widx);
        return -1;
    }
    if (args.size() < 2) {
        fprintf(stderr, "ERROR: free needs <idx|all>\n");
        return -1;
    }
    Worker &w = *g_workers[widx];

    if (args[1] == "all") {
        uint32_t cnt = (uint32_t)w.alloced.size();
        if (async) {
            /* Reserve g_actions slot now; back-fill string after SyncAll.
             * FREE_ALL touches w.alloced inside WorkerMain — safe because
             * the parallel-mode rule forbids the same worker from having
             * an ALLOC task in the same block (no alloc+free mix), so no
             * DrainWorkerResult on this worker will race with this FREE.
             * In stress mode, skip the reservation (SIZE_MAX sentinel). */
            if (!g_stress_mode) {
                g_actions.push_back(std::string());
                w.pending_action_idx = g_actions.size() - 1;
            } else {
                w.pending_action_idx = SIZE_MAX;
            }
            DispatchAsync(widx, ThreadTask::FREE_ALL);
            /* Worker sets task.ret = (int)freed_cnt; back-fill action string
             * at SyncAll via DrainFreeResult. For simplicity we back-fill
             * here based on the count we observed before dispatch; if worker
             * actually freed a different number (shouldn't happen since
             * FREE_ALL is deterministic), the count will be slightly off. */
            if (!g_stress_mode) {
                char act[64];
                snprintf(act, sizeof(act), "[t%zu] free all -> %u buf%s", widx, cnt, cnt > 1 ? "s" : "");
                g_actions[w.pending_action_idx] = act;
                printf("[t%zu] free all dispatched (async, %u bufs pending)\n", widx, cnt);
            }
            return 0;
        }
        Dispatch(widx, ThreadTask::FREE_ALL);
        cnt = (w.task.ret > 0) ? (uint32_t)w.task.ret : 0;
        /* Bump stress counters in serial path too — async path bumps in
         * DrainWorkerResult, but serial DoFree reads task.ret directly
         * without going through DrainWorkerResult. */
        if (w.task.ret >= 0) {
            g_stress.total_frees++;
            g_stress.total_bufs_freed += cnt;
        } else {
            g_stress.total_free_errors++;
        }
        if (!g_stress_mode) {
            printf("[t%zu] freed %u bufs\n", widx, cnt);
            char act[64];
            snprintf(act, sizeof(act), "[t%zu] free all -> %u buf%s", widx, cnt, cnt > 1 ? "s" : "");
            g_actions.push_back(act);
        }
        return 0;
    }

    /* Parse free idx list: "0" (single) or "0,1,2" (multi-idx).
     * Multi-idx allows parallel blocks to free multiple bufs per worker
     * in one command, avoiding the "thread_K appears more than once" rule. */
    uint32_t free_indices[64];
    uint32_t free_count = 0;
    {
        std::string tok;
        const std::string &s = args[1];
        for (size_t p = 0; p <= s.size(); ++p) {
            if (p == s.size() || s[p] == ',') {
                if (!tok.empty()) {
                    if (free_count >= 64) {
                        fprintf(stderr, "ERROR: [t%zu] free idx list too long (>64)\n", widx);
                        return -1;
                    }
                    long v = strtol(tok.c_str(), nullptr, 10);
                    if (v < 0) {
                        fprintf(stderr, "ERROR: [t%zu] free idx %ld must be non-negative\n", widx, v);
                        return -1;
                    }
                    free_indices[free_count++] = (uint32_t)v;
                    tok.clear();
                }
            } else {
                tok.push_back(s[p]);
            }
        }
    }
    if (free_count == 0) {
        fprintf(stderr, "ERROR: [t%zu] free needs <idx|idx,idx,...|all>\n", widx);
        return -1;
    }
    /* Build display string of requested indices for action log/printf */
    char idxStr[128] = {0};
    {
        int n = 0;
        for (uint32_t i = 0; i < free_count; i++) {
            n += snprintf(idxStr + n, sizeof(idxStr) - n, "%s%u", (i ? "," : ""), free_indices[i]);
        }
    }
    if (async) {
        /* Reserve g_actions slot for the free action (skip in stress mode). */
        if (!g_stress_mode) {
            g_actions.push_back(std::string());
            w.pending_action_idx = g_actions.size() - 1;
        } else {
            w.pending_action_idx = SIZE_MAX;
        }
        DispatchAsync(widx, ThreadTask::FREE_IDX, 0, 1, 0, free_indices, free_count);
        if (!g_stress_mode) {
            char act[128];
            snprintf(act, sizeof(act), "[t%zu] free %s -> dispatched", widx, idxStr);
            g_actions[w.pending_action_idx] = act;
            printf("[t%zu] free %s dispatched (async, %u bufs)\n", widx, idxStr, free_count);
        }
        return 0;
    }
    Dispatch(widx, ThreadTask::FREE_IDX, 0, 1, 0, free_indices, free_count);
    /* WorkerMain FREE_IDX returns: positive = freed count, negative = -(not found count) */
    if (w.task.ret < 0) {
        fprintf(stderr, "ERROR: [t%zu] free %s: %d orig_idx not found (already freed or never allocated; "
                        "use 'status' to see held allocs with valid orig_idx range)\n",
                widx, idxStr, -w.task.ret);
        g_stress.total_free_errors++;
        return -1;
    }
    uint32_t freed_cnt = (uint32_t)w.task.ret;
    /* Bump stress counters in serial path (async path bumps in DrainWorkerResult). */
    g_stress.total_frees++;
    g_stress.total_bufs_freed += freed_cnt;
    if (!g_stress_mode) {
        printf("[t%zu] freed %u buf%s (%s)\n", widx, freed_cnt, freed_cnt > 1 ? "s" : "", idxStr);
        char act[128];
        snprintf(act, sizeof(act), "[t%zu] free %s -> %u buf%s", widx, idxStr, freed_cnt,
                 freed_cnt > 1 ? "s" : "");
        g_actions.push_back(act);
    }
    return 0;
}

/* DoInfo: directly probes the multi-level size_class state added in 5e5b88e.
 * Reads new g_qbuf_pool fields (block_sizes[], data_region_start[], per-sc
 * block_pool[]/exp_pool_with_data[] arrays) and calls new routing functions
 * (select_size_class, blk_size_to_sc, get_batch_count). If these print sane
 * values, the multi-level code path was initialised and executed — proving
 * the tool exercises the new (not legacy single-level) mempool code. */
int DoInfo(const std::vector<std::string> &args)
{
    (void)args;
    if (!g_inited) {
        fprintf(stderr, "ERROR: pool not inited\n");
        return -1;
    }
    /* Pure DFX output: call umq_stats_qbuf_pool_get + umq_qbuf_pool_stats_to_str
     * and print the formatted string. Replaces the previous direct reads of
     * g_qbuf_pool.* / g_tls_register_head / g_exp_slot_table (the tool no
     * longer #includes umq_qbuf_pool.c).
     * scaleCap=off: exp_pool slot_list uninitialized, DFX would SIGSEGV. */
    if (!g_scale_cap_enabled) {
        printf("(info unavailable: scaleCap=off, expansion pool not initialized)\n");
        return 0;
    }
    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    int ret = umq_stats_qbuf_pool_get(UMQ_INVALID_HANDLE, &stats);
    if (ret != 0) {
        fprintf(stderr, "ERROR: umq_stats_qbuf_pool_get failed ret=%d\n", ret);
        return -1;
    }
    /* UMQ_DFX_TO_STRING_DEFAULT_LEN covers ~20 KB; the multi-level DFX output
     * (Pool Config + Per-SizeClass + Per-Thread TLS) fits comfortably. */
    char buf[UMQ_DFX_TO_STRING_DEFAULT_LEN];
    ret = umq_qbuf_pool_stats_to_str(&stats, buf, sizeof(buf));
    if (ret < 0) {
        fprintf(stderr, "ERROR: umq_qbuf_pool_stats_to_str failed ret=%d\n", ret);
        return -1;
    }
    fputs(buf, stdout);
    /* Tool-layer overlay: pool's OS memory claim (initial + expansion + escape).
     * All three components come from existing DFX fields (no production code
     * change). Printed as a separate framed section after the DFX to make the
     * "what the pool actually claimed from OS" view easy to find vs the
     * "what the pool currently holds" view (Per-SizeClass State / TLS etc). */
    PoolMemBreakdown mem = CalcPoolOsMemClaimed(stats);
    const umq_qbuf_pool_info_t *pinfo = (stats.num > 0) ? &stats.qbuf_pool_info[0] : nullptr;
    printf("\n== [ Pool OS Mem Claimed ] ==\n");
    printf("  total:     %lu bytes (%.2f MB)\n", (unsigned long)mem.total,
           (double)mem.total / (1024.0 * 1024.0));
    printf("  initial:   %lu bytes (cfg.total_size / g_buf_addr)\n", (unsigned long)mem.initial);
    printf("  expansion: %lu bytes (sum of slot.total_buf_size, CAS-tracked)\n",
           (unsigned long)mem.expansion);
    if (pinfo != nullptr) {
        uint64_t escape_cnt_total = 0;
        for (uint32_t sc = 0; sc < pinfo->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            escape_cnt_total += stats.escape_buf_cnt_by_sc[sc];
        }
        printf("  escape:    %lu bytes (%lu bufs, per-sc breakdown:\n",
               (unsigned long)mem.escape, (unsigned long)escape_cnt_total);
        for (uint32_t sc = 0; sc < pinfo->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            if (stats.escape_buf_cnt_by_sc[sc] > 0) {
                printf("             sc%u: %lu bufs * (blk_size %u + umq_buf_t_size %u)\n", sc,
                       (unsigned long)stats.escape_buf_cnt_by_sc[sc], pinfo->sc_info[sc].blk_size,
                       pinfo->umq_buf_t_size);
            }
        }
        printf("  )\n");
    }
    return 0;
}

/* DoStatus: minimal test-facing view — only two things a tester needs:
 *   1) actions: what the user did so far (init/alloc/free sequence)
 *   2) pool state: per-sc layer sizes (global / tls / alloced / expansion)
 * Intentionally terse, contrasts with DoInfo which dumps everything. */
int DoStatus(const std::vector<std::string> &args)
{
    (void)args;
    if (!g_inited) {
        fprintf(stderr, "ERROR: pool not inited\n");
        return -1;
    }
    /* one outer frame wrapping all sections */
    printf("====================[ status ]====================\n");

    /* section 0 (optional): stress progress / summary — shown when
     * g_stress_mode is active (inside stress_repeat loop) or after a
     * stress_repeat finished (iters_done > 0). Bounded counters; never
     * grows with iter count. stress_repeat runs infinitely, so no
     * `/total` — only current iter count + (running|interrupted) state. */
    if (g_stress_mode || g_stress.iters_done > 0) {
        uint64_t now = NowMicros();
        uint64_t uptime_s = (now - g_stress.start_time_us) / 1000000;
        size_t sum_alloced = 0;
        for (auto &w : g_workers) {
            sum_alloced += w->alloced.size();
        }
        const char *state = g_stress_mode ? "running" : (g_stress.interrupted ? "interrupted" : "done");
        printf("stress %s:\n", state);
        printf("  iters: %lu\n", (unsigned long)g_stress.iters_done);
        printf("  uptime: %luh %lum %lus\n", (unsigned long)(uptime_s / 3600),
               (unsigned long)((uptime_s % 3600) / 60), (unsigned long)(uptime_s % 60));
        printf("  total: allocs=%lu frees=%lu alloc_errors=%lu free_errors=%lu\n",
               (unsigned long)g_stress.total_allocs, (unsigned long)g_stress.total_frees,
               (unsigned long)g_stress.total_alloc_errors, (unsigned long)g_stress.total_free_errors);
        printf("  bufs:  alloced=%lu freed=%lu (outstanding=%zu)\n",
               (unsigned long)g_stress.total_bufs_alloced, (unsigned long)g_stress.total_bufs_freed,
               sum_alloced);
    }

    /* section 1: actions history (skipped in stress mode — g_actions not
     * pushed for stress_repeat iters; show only what was recorded before
     * entering stress mode, typically just `init`). */
    if (g_stress_mode) {
        printf("actions (%zu, stress mode — per-iter actions not recorded):\n", g_actions.size());
    } else {
        printf("actions (%zu):\n", g_actions.size());
    }
    for (size_t i = 0; i < g_actions.size(); ++i) {
        printf("  [%zu] %s\n", i + 1, g_actions[i].c_str());
    }

    /* section 2: currently held allocs — per-worker alloc ops still alive,
     * excluding alloc-then-freed pairs (what each thread is still holding).
     * Shows the orig_idx range so user knows which `free N` to use. */
    printf("held allocs:\n");
    bool any_held = false;
    for (auto &w : g_workers) {
        for (size_t i = 0; i < w->alloc_ops.size(); ++i) {
            const AllocOp &op = w->alloc_ops[i];
            if (op.remaining == 0) {
                continue; /* fully freed — drop the alloc+free pair */
            }
            any_held = true;
            /* Build orig_idx hint: e.g. "free 3-4" for 2 bufs, "free 0" for 1 buf */
            char origHint[64];
            if (op.total > 1) {
                snprintf(origHint, sizeof(origHint), " (free %u-%u)", op.orig_idx_start,
                         op.orig_idx_start + op.total - 1);
            } else {
                snprintf(origHint, sizeof(origHint), " (free %u)", op.orig_idx_start);
            }
            if (op.size == 0) {
                /* without_data alloc — no sc concept, mark as nodata so tester
                 * doesn't confuse it with sc=0 with_data bufs. */
                printf("  [t%u][%zu] alloc 0 -> nodata, %u/%u buf%s held%s\n", w->idx, op.actions_idx + 1,
                       op.remaining, op.total, op.total > 1 ? "s" : "", origHint);
            } else {
                printf("  [t%u][%zu] alloc %u -> sc=%u, %u/%u buf%s held%s\n", w->idx, op.actions_idx + 1, op.size,
                       op.sc, op.remaining, op.total, op.total > 1 ? "s" : "", origHint);
            }
        }
    }
    if (!any_held) {
        printf("  (none — all allocs freed)\n");
    }

    /* section 3: per-sc global/alloced/exp + per-thread TLS (sc per row + tid).
     * Pool state now sourced from DFX stats (umq_stats_qbuf_pool_get) instead
     * of direct reads of g_qbuf_pool.* / g_tls_register_head; the alloced
     * column stays tool-tracked (umq does not know which bufs are outstanding).
     * The three-section visual frame is preserved.
     * scaleCap=off: exp_pool slot_list uninitialized, DFX would SIGSEGV. */
    if (!g_scale_cap_enabled) {
        printf("pool state: (DFX unavailable: scaleCap=off)\n");
        printf("==================================================\n");
        return 0;
    }
    printf("pool state (per-sc global/alloced/exp + per-thread tls):\n");
    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    if (umq_stats_qbuf_pool_get(UMQ_INVALID_HANDLE, &stats) != 0 || stats.num == 0) {
        fprintf(stderr, "ERROR: umq_stats_qbuf_pool_get failed\n");
        printf("==================================================\n");
        return -1;
    }
    const umq_qbuf_pool_info_t *pinfo = &stats.qbuf_pool_info[0];

    uint64_t alloced[UMQ_DFX_QBUF_SIZE_CLASS_MAX] = {0};
    uint64_t escape_cnt = 0;
    uint64_t nodata_cnt = 0;
    for (auto &w : g_workers) {
        for (auto &ab : w->alloced) {
            if (ab.buf->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
                ++escape_cnt;
                continue;
            }
            if (ab.buf->mempool_without_data == 1) {
                /* without_data buf — buf_size=sizeof(umq_buf_t), would
                 * BlkSizeToSc-fallback to sc=0 incorrectly. Count separately
                 * so per-sc alloced column reflects only with_data bufs. */
                ++nodata_cnt;
                continue;
            }
            uint32_t sc = BlkSizeToSc(BufToBlkSize(ab.buf), pinfo->sc_info, pinfo->sc_count);
            if (sc < pinfo->sc_count) {
                ++alloced[sc];
            }
        }
    }
    printf("  sc | blk_size | global | alloced | exp\n");
    for (uint32_t i = 0; i < pinfo->sc_count; ++i) {
        printf("  %-2u | %-8u | %-6lu | %-8lu | %lu\n", i, pinfo->sc_info[i].blk_size,
               (unsigned long)pinfo->sc_info[i].buf_cnt_with_data, (unsigned long)alloced[i],
               (unsigned long)pinfo->sc_info[i].exp_total_block_num);
    }
    if (escape_cnt > 0) {
        printf("  escape: %lu bufs (not counted in per-sc)\n", (unsigned long)escape_cnt);
    }
    if (nodata_cnt > 0) {
        printf("  without_data: %lu bufs (not counted in per-sc with_data)\n", (unsigned long)nodata_cnt);
    }

    /* Expansion slot details: list total/free/in_use block counts for each active slot by mempool_id */
    constexpr uint32_t SLOT_CAP = 256; /* Actual slot count is far less than this; truncation hint if exceeded */
    umq_expansion_slot_info_t slots[SLOT_CAP];
    uint32_t slot_n = umq_qbuf_expansion_slot_dist(slots, SLOT_CAP);
    if (slot_n > 0) {
        printf("  exp per-slot (by mempool_id):\n");
        printf("    mempool_id | sc | slot_id | total | free  | in_use\n");
        uint64_t sum_total = 0, sum_free = 0, sum_inuse = 0;
        for (uint32_t k = 0; k < slot_n; ++k) {
            printf("    %-9u | %-2u | %-7u | %-5lu | %-5lu | %lu\n", slots[k].mempool_id,
                   slots[k].size_class, slots[k].slot_id, (unsigned long)slots[k].total_block_cnt,
                   (unsigned long)slots[k].free_block_cnt, (unsigned long)slots[k].in_use_cnt);
            sum_total += slots[k].total_block_cnt;
            sum_free += slots[k].free_block_cnt;
            sum_inuse += slots[k].in_use_cnt;
        }
        printf("    %-9s |    | %-7s | %-5lu | %-5lu | %lu   (sum)\n", "", "",
               (unsigned long)sum_total, (unsigned long)sum_free, (unsigned long)sum_inuse);
        if (slot_n == SLOT_CAP) {
            printf("    (cap %u reached, truncated)\n", SLOT_CAP);
        }
    }
    printf("  per-thread TLS:\n");
    for (uint32_t t = 0; t < stats.local_qbuf_pool_num; ++t) {
        const umq_local_qbuf_pool_stats_t *tls = &stats.local_qbuf_pool_stats[t];
        uint32_t match = 0xFFFFFFFFu;
        for (size_t k = 0; k < g_workers.size(); ++k) {
            /* tls->tid is the OS kernel TID (set by production code via
             * syscall(SYS_gettid) in umq_qbuf_pool.c get_thread_cache path).
             * Compare against Worker.kernel_tid (also via syscall), not
             * Worker.tid (which is pthread_t address — different namespace). */
            if (g_workers[k]->kernel_tid == tls->tid) {
                match = (uint32_t)k;
                break;
            }
        }
        printf("    t%u (tid=%lu)\n", (match == 0xFFFFFFFFu ? 999 : match), (unsigned long)tls->tid);
        for (uint32_t i = 0; i < tls->sc_count; ++i) {
            printf("      sc%u: buf=%-4lu cap=%lu\n", i, (unsigned long)tls->sc_buf_cnt_with_data[i],
                   (unsigned long)tls->sc_capacity_with_data[i]);
        }
    }
    /* pool's OS memory claim — single line in status (info command shows the
     * full breakdown). Helps tester verify at a glance that pool claim is
     * constant (= initial 200MB) regardless of repeat count, so any RSS growth
     * beyond this number is tool residue (g_actions vector / glibc cache). */
    PoolMemBreakdown mem = CalcPoolOsMemClaimed(stats);
    printf("  Pool OS Mem Claimed: %lu bytes (initial=%lu + expansion=%lu + escape=%lu)\n",
           (unsigned long)mem.total, (unsigned long)mem.initial, (unsigned long)mem.expansion,
           (unsigned long)mem.escape);
    printf("==================================================\n");
    return 0;
}

/* ===================== sleep command ===================== */

/* DoSleep: pause script execution for a specified duration.
 * Syntax: sleep <N> [ms|us|s]
 *   - N is a positive integer (or float for seconds)
 *   - Unit defaults to milliseconds if omitted
 *   - Examples: sleep 100     (sleep 100ms)
 *              sleep 500 ms   (sleep 500ms)
 *              sleep 2 s      (sleep 2 seconds)
 *              sleep 1 us     (sleep 1 microsecond)
 * Useful for waiting on async operations (e.g. expansion pool shrink). */
int DoSleep(const std::vector<std::string> &args)
{
    if (args.size() < 2) {
        fprintf(stderr, "ERROR: sleep needs a duration (sleep <N> [ms|us|s])\n");
        return -1;
    }
    double val = strtod(args[1].c_str(), nullptr);
    if (val <= 0) {
        fprintf(stderr, "ERROR: sleep duration must be > 0 (got %s)\n", args[1].c_str());
        return -1;
    }
    std::string unit = "ms";
    if (args.size() >= 3) {
        unit = args[2];
    }
    struct timespec ts;
    if (unit == "us") {
        ts.tv_sec = (time_t)(val / 1000000.0);
        ts.tv_nsec = (long)((val - ts.tv_sec * 1000000.0) * 1000.0);
    } else if (unit == "s") {
        ts.tv_sec = (time_t)val;
        ts.tv_nsec = (long)((val - ts.tv_sec) * 1e9);
    } else {
        /* default: ms */
        ts.tv_sec = (time_t)(val / 1000.0);
        ts.tv_nsec = (long)((val - ts.tv_sec * 1000.0) * 1e6);
    }
    printf("sleep: %.3g %s ...\n", val, unit.c_str());
    fflush(stdout);
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        /* interrupted by signal, resume */
    }
    printf("sleep: done\n");
    return 0;
}

/* ===================== parallel/repeat block commands ===================== */

/* TokenizeBlock: convert raw source lines to vector of token vectors,
 * dropping comment-only and blank lines. Tokenization reuses Tokenize
 * from utils.cpp (handles inline '#' comments + whitespace). */
std::vector<std::vector<std::string>> TokenizeBlock(const std::vector<std::string> &raw)
{
    std::vector<std::vector<std::string>> out;
    out.reserve(raw.size());
    for (const std::string &line : raw) {
        std::vector<std::string> toks = Tokenize(line.c_str());
        if (toks.empty()) {
            continue; /* comment or blank */
        }
        out.push_back(std::move(toks));
    }
    return out;
}

/* ValidateParallelBlock: enforce the parallel-mode safety rules.
 *   1) every line must start with 'thread_K'
 *   2) sub-command must be 'alloc' or 'free'
 *   3) no worker mixes alloc+free in the same block (avoids w.alloced
 *      being mutated by a FREE task while a same-worker ALLOC drain
 *      might race — though the rule also serves readability)
 * Returns 0 ok, -1 invalid (error message printed). */
int ValidateParallelBlock(const std::vector<std::vector<std::string>> &block)
{
    if (block.empty()) {
        fprintf(stderr, "ERROR: parallel block is empty\n");
        return -1;
    }
    /* track per-worker sub-command types seen: 0=none, 1=alloc, 2=free */
    std::map<size_t, int> worker_cmd;
    for (size_t i = 0; i < block.size(); ++i) {
        const std::vector<std::string> &toks = block[i];
        if (toks[0].compare(0, 7, "thread_") != 0) {
            fprintf(stderr, "ERROR: parallel block line %zu: '%s' is not a thread_K command\n", i + 1, toks[0].c_str());
            return -1;
        }
        if (toks.size() < 2) {
            fprintf(stderr, "ERROR: parallel block line %zu: missing sub-command\n", i + 1);
            return -1;
        }
        if (toks[1] != "alloc" && toks[1] != "free") {
            fprintf(stderr, "ERROR: parallel block line %zu: sub-command must be alloc/free, got '%s'\n", i + 1,
                    toks[1].c_str());
            return -1;
        }
        size_t widx = (size_t)strtoul(toks[0].c_str() + 7, nullptr, 10);
        int cmd = (toks[1] == "alloc") ? 1 : 2;
        auto it = worker_cmd.find(widx);
        if (it == worker_cmd.end()) {
            worker_cmd[widx] = cmd;
        } else if (it->second != cmd) {
            fprintf(stderr,
                    "ERROR: parallel block: thread_%zu mixes alloc+free (forbidden — "
                    "use two separate parallel blocks)\n",
                    widx);
            return -1;
        } else {
            fprintf(stderr,
                    "ERROR: parallel block: thread_%zu appears more than once "
                    "(use a single alloc num=N instead)\n",
                    widx);
            return -1;
        }
    }
    return 0;
}

/* ValidateRepeatBlock: enforce the repeat-mode safety rules.
 *   1) block may contain thread_K commands and any number of parallel/join
 *      sub-blocks (multiple parallel blocks per repeat iteration are fine —
 *      e.g. alloc block followed by free block)
 *   2) block must NOT contain info/status/init/quit (control commands
 *      that would corrupt repeat semantics)
 *   3) no nested repeat or stress_repeat (would be confusing + parser
 *      state complexity)
 *   4) `snapshot N` directive is allowed — handled by the outer repeat
 *      loop (DoRepeatBlock / DoStressRepeatBlock), ExecuteBlockLines skips it
 * Returns 0 ok, -1 invalid. */
int ValidateRepeatBlock(const std::vector<std::vector<std::string>> &block)
{
    for (size_t i = 0; i < block.size(); ++i) {
        const std::vector<std::string> &toks = block[i];
        const std::string &cmd = toks[0];
        if (cmd == "info" || cmd == "status" || cmd == "init" || cmd == "quit" || cmd == "exit") {
            fprintf(stderr,
                    "ERROR: repeat block line %zu: '%s' forbidden inside repeat "
                    "(check conservation after repeat instead)\n",
                    i + 1, cmd.c_str());
            return -1;
        }
        if (cmd == "repeat" || cmd == "stress_repeat") {
            fprintf(stderr, "ERROR: repeat block line %zu: nested '%s' not allowed\n", i + 1, cmd.c_str());
            return -1;
        }
        /* parallel/join, thread_K, and snapshot are all OK inside repeat */
    }
    return 0;
}

/* ExecuteBlockLines: run a vector of pre-parsed token vectors in serial
 * (one repeat iteration). Lines may be thread_K commands (executed serially
 * with async=false) or a single parallel/join sub-block (executed via
 * DoParallelBlock). Returns 0 on success, -1 on any failure. */
int ExecuteBlockLines(const std::vector<std::vector<std::string>> &block)
{
    for (size_t i = 0; i < block.size(); ++i) {
        const std::vector<std::string> &toks = block[i];
        const std::string &cmd = toks[0];
        if (cmd == "snapshot") {
            /* Snapshot directive — handled by the outer repeat loop
             * (DoRepeatBlock / DoStressRepeatBlock pre-scan and apply).
             * Skip here as a no-op. */
            continue;
        }
        if (cmd == "iterations") {
            /* Iteration cap — pre-scanned by DoStressRepeatBlock. Skip. */
            continue;
        }
        if (cmd == "parallel") {
            /* Collect until matching 'join'. Repeat iteration may contain
             * multiple parallel sub-blocks (e.g. alloc block + free block);
             * we run each in turn via DoParallelBlock. */
            std::vector<std::vector<std::string>> sub;
            size_t j = i + 1;
            while (j < block.size() && block[j][0] != "join") {
                sub.push_back(block[j]);
                ++j;
            }
            if (j >= block.size()) {
                fprintf(stderr, "ERROR: repeat block: parallel without matching join\n");
                return -1;
            }
            if (ValidateParallelBlock(sub) != 0) {
                return -1;
            }
            if (DoParallelBlock(sub) != 0) {
                return -1;
            }
            i = j; /* skip past 'join' */
            continue;
        }
        /* thread_K command — serial execution */
        if (cmd.compare(0, 7, "thread_") == 0) {
            size_t widx = (size_t)strtoul(cmd.c_str() + 7, nullptr, 10);
            if (toks.size() < 2) {
                fprintf(stderr, "ERROR: '%s' needs sub-command\n", cmd.c_str());
                return -1;
            }
            std::vector<std::string> subargs(toks.begin() + 1, toks.end());
            if (toks[1] == "alloc") {
                if (DoAlloc(subargs, widx, /*async=*/false) != 0) {
                    return -1;
                }
            } else if (toks[1] == "free") {
                if (DoFree(subargs, widx, /*async=*/false) != 0) {
                    return -1;
                }
            } else {
                fprintf(stderr, "ERROR: thread_%zu only supports alloc/free, got '%s'\n", widx, toks[1].c_str());
                return -1;
            }
            continue;
        }
        fprintf(stderr, "ERROR: repeat block line %zu: unexpected command '%s'\n", i + 1, cmd.c_str());
        return -1;
    }
    return 0;
}

/* DoParallelBlock: dispatch every thread_K line in `block` asynchronously,
 * then SyncAll. `block` must have passed ValidateParallelBlock already (the
 * caller in main.cpp is responsible; we re-validate defensively here).
 *
 * Implementation note: lines are dispatched in source order; the g_actions
 * log reflects dispatch order because DoAlloc/DoFree(async) reserve the
 * slot at dispatch time and DrainWorkerResult/SyncAll back-fill by slot idx.
 *
 * Verbose mode prints two-phase timing: dispatch (should be tiny, μs) +
 * barrier wait (should be ~max worker execution time, NOT sum — proving
 * workers ran concurrently rather than sequentially). */
int DoParallelBlock(const std::vector<std::vector<std::string>> &block)
{
    if (ValidateParallelBlock(block) != 0) {
        return -1;
    }
    bool verbose = VerboseEnabled();
    uint64_t disp_start = verbose ? NowMicros() : 0;
    int errors = 0;
    for (const auto &toks : block) {
        size_t widx = (size_t)strtoul(toks[0].c_str() + 7, nullptr, 10);
        std::vector<std::string> subargs(toks.begin() + 1, toks.end());
        int r = 0;
        if (toks[1] == "alloc") {
            r = DoAlloc(subargs, widx, /*async=*/true);
        } else { /* toks[1] == "free" (validated above) */
            r = DoFree(subargs, widx, /*async=*/true);
        }
        if (r != 0) {
            ++errors;
        }
    }
    uint64_t disp_end = verbose ? NowMicros() : 0;
    if (verbose) {
        fprintf(stderr,
                "[parallel] dispatched %zu commands in %luμs, "
                "entering barrier (workers now running concurrently)\n",
                block.size(), (unsigned long)(disp_end - disp_start));
    }
    /* Barrier — wait for all workers, drain results. */
    SyncAll();
    if (errors > 0) {
        fprintf(stderr, "ERROR: parallel block had %d dispatch error(s)\n", errors);
        return -1;
    }
    return 0;
}

/* DoRepeatBlock: execute `block` `count` times. Block is pre-validated to
 * contain no info/status/init/quit and no nested repeat. Each iteration
 * calls ExecuteBlockLines which serially dispatches the block's commands
 * (multiple parallel/join sub-blocks supported via DoParallelBlock). */
int DoRepeatBlock(int count, const std::vector<std::vector<std::string>> &block)
{
    if (count <= 0) {
        fprintf(stderr, "ERROR: repeat count must be > 0 (got %d)\n", count);
        return -1;
    }
    if (count > 10000) {
        fprintf(stderr, "ERROR: repeat count must be <= 10000 (got %d)\n", count);
        return -1;
    }
    if (ValidateRepeatBlock(block) != 0) {
        return -1;
    }
    /* Pre-scan for `snapshot N` directive (also valid in plain repeat). */
    int snapshot_interval = 0;
    for (const auto &toks : block) {
        if (toks.size() == 2 && toks[0] == "snapshot") {
            snapshot_interval = (int)strtol(toks[1].c_str(), nullptr, 10);
            if (snapshot_interval <= 0) {
                fprintf(stderr, "ERROR: snapshot interval must be > 0\n");
                return -1;
            }
        }
    }
    for (int i = 0; i < count; ++i) {
        if (ExecuteBlockLines(block) != 0) {
            fprintf(stderr, "ERROR: repeat iteration %d failed\n", i + 1);
            return -1;
        }
        if (snapshot_interval > 0 && (i + 1) % snapshot_interval == 0) {
            uint64_t now = NowMicros();
            uint64_t uptime_s = (now - g_stress.start_time_us) / 1000000;
            size_t sum_alloced = 0;
            for (auto &w : g_workers) {
                sum_alloced += w->alloced.size();
            }
            printf("[snapshot] iter=%d/%d uptime=%luh %lum %lus allocs=%lu frees=%lu errors=%lu alloced_held=%zu\n",
                   i + 1, count, (unsigned long)(uptime_s / 3600), (unsigned long)((uptime_s % 3600) / 60),
                   (unsigned long)(uptime_s % 60), (unsigned long)g_stress.total_allocs,
                   (unsigned long)g_stress.total_frees,
                   (unsigned long)(g_stress.total_alloc_errors + g_stress.total_free_errors), sum_alloced);
        }
    }
    return 0;
}

/* StressModeGuard: RAII to ensure g_stress_mode is restored even if
 * DoStressRepeatBlock returns early on error. Preserves the previous
 * value (false in normal use) so nested stress is detectable. */
struct StressModeGuard {
    bool prev;
    StressModeGuard() : prev(g_stress_mode) { g_stress_mode = true; }
    ~StressModeGuard() { g_stress_mode = prev; }
};

/* SignalGuard: RAII to install OnStopSignal for SIGINT/SIGTERM during the
 * stress loop and restore the previous handlers on exit (normal, error,
 * or interrupt). Saves old handlers so we don't affect the rest of the
 * program (e.g. default SIGINT termination behavior outside stress_repeat).
 *
 * OnStopSignal: first signal sets g_stop_requested (stress loop checks at
 * iter boundary and breaks gracefully). Second signal re-installs default
 * handler and re-raises so user can force-kill if cleanup hangs (e.g.
 * worker stuck in unresponsive syscall). */
static void OnStopSignal(int sig)
{
    (void)sig;
    if (g_stop_requested) {
        /* Second signal — restore default and re-raise so process dies. */
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        dfl.sa_flags = 0;
        sigaction(sig, &dfl, NULL);
        raise(sig);
        return;
    }
    g_stop_requested = 1;
}

struct SignalGuard {
    struct sigaction old_int;
    struct sigaction old_term;
    SignalGuard()
    {
        g_stop_requested = 0;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = OnStopSignal;
        sigemptyset(&sa.sa_mask);
        /* SA_RESTART so pthread_cond_wait / epoll_wait auto-restart; the
         * stress loop checks g_stop_requested at iter boundary (not in
         * signal context), so we don't need EINTR to break syscalls. */
        sa.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sa, &old_int);
        sigaction(SIGTERM, &sa, &old_term);
    }
    ~SignalGuard()
    {
        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
    }
};

/* DoStressRepeatBlock: like DoRepeatBlock but executes in stress mode —
 * DrainWorkerResult skips g_actions writes and per-buf printf so memory
 * stays bounded for days-long runs (g_actions, alloc_ops, alloced all
 * bounded; alloc_ops is cleared at iter boundary when alloced.empty()).
 *
 * User MUST ensure alloc/free pairing at iter boundary; this function does
 * NOT enforce conservation. If user leaks (alloced not empty at iter end),
 * alloc_ops is left untouched to preserve FREE_IDX cross-ref, and memory
 * grows linearly with leaked ops — that's user's responsibility. The exit-
 * time Cleanup NOTE will still report the leak.
 *
 * Optional `snapshot N` directive prints a one-line progress summary every
 * N iters to stdout (does NOT push to any vector — output goes to stdout
 * only, so memory stays bounded regardless of iter count).
 *
 * Runs INFINITELY — no count parameter. The loop breaks only on:
 *   - ExecuteBlockLines returning non-zero (alloc/free failure) — exits 1
 *   - SIGINT/SIGTERM (Ctrl-C) — sets g_stop_requested, breaks after
 *     current iter completes, prints interrupt message + final summary,
 *     returns 0 (graceful exit; user can then `status` or `quit`)
 *   - Second signal — OnStopSignal re-installs default handler and
 *     re-raises; process dies immediately (for stuck cleanup) */
int DoStressRepeatBlock(const std::vector<std::vector<std::string>> &block)
{
    if (ValidateRepeatBlock(block) != 0) {
        return -1;
    }
    /* Pre-scan for `snapshot N` and optional `iterations N` directives.
     * `iterations N` caps the otherwise-infinite loop to N iters so the
     * case can run to success without a signal — absent, runs forever. */
    int snapshot_interval = 0;
    uint64_t iter_limit = 0;
    for (const auto &toks : block) {
        if (toks.size() == 2 && toks[0] == "snapshot") {
            snapshot_interval = (int)strtol(toks[1].c_str(), nullptr, 10);
            if (snapshot_interval <= 0) {
                fprintf(stderr, "ERROR: snapshot interval must be > 0\n");
                return -1;
            }
        } else if (toks.size() == 2 && toks[0] == "iterations") {
            iter_limit = (uint64_t)strtoull(toks[1].c_str(), nullptr, 10);
            if (iter_limit == 0) {
                fprintf(stderr, "ERROR: iterations must be > 0\n");
                return -1;
            }
        }
    }
    if (snapshot_interval == 0) {
        fprintf(stderr,
                "WARNING: stress_repeat without `snapshot N` — no periodic progress "
                "will be printed; consider adding `snapshot 1000` to the block\n");
    }
    /* Reset counters, install signal handlers, mark stress mode. */
    g_stress = StressCounters{0, 0, 0, 0, 0, 0, 0, NowMicros(), false};
    SignalGuard sig_guard;
    StressModeGuard mode_guard;
    for (uint64_t i = 0;; ++i) {
        if (iter_limit != 0 && i >= iter_limit) {
            printf("[stress] reached iterations limit %lu, exiting gracefully\n",
                   (unsigned long)iter_limit);
            break;
        }
        if (g_stop_requested) {
            g_stress.interrupted = true;
            printf("[stress] interrupted by signal at iter %lu (waiting for current "
                   "iter to complete, then exiting gracefully)\n",
                   (unsigned long)g_stress.iters_done);
            break;
        }
        if (ExecuteBlockLines(block) != 0) {
            fprintf(stderr, "ERROR: stress_repeat iteration %lu failed\n",
                    (unsigned long)(i + 1));
            return -1;
        }
        /* Per-iter memory bounding: if user paired alloc/free correctly,
         * alloced is empty at iter end — safe to clear alloc_ops (no held
         * bufs reference it) AND reset next_orig_idx (next iter starts from 0,
         * keeping orig_idx bounded across infinite iterations). This mirrors
         * FREE_ALL's reset behavior for the `free <idx>` pattern (case_23)
         * which doesn't call FREE_ALL. If user leaked, leave both alone to
         * preserve FREE_IDX cross-ref; memory grows linearly with leak
         * count (exit-time Cleanup NOTE will report the leak) and per-worker
         * cap (WORKER_ALLOCED_CAP=65536) eventually aborts the stress loop. */
        for (auto &w : g_workers) {
            if (w->alloced.empty()) {
                w->alloc_ops.clear();
                w->next_orig_idx = 0;
            }
        }
        g_stress.iters_done = i + 1;
        if (snapshot_interval > 0 && (i + 1) % (uint64_t)snapshot_interval == 0) {
            uint64_t now = NowMicros();
            uint64_t uptime_s = (now - g_stress.start_time_us) / 1000000;
            size_t sum_alloced = 0;
            for (auto &w : g_workers) {
                sum_alloced += w->alloced.size();
            }
            printf("[stress] iter=%lu uptime=%luh %lum %lus allocs=%lu frees=%lu "
                   "errors=%lu bufs_alloced=%lu bufs_freed=%lu alloced_held=%zu\n",
                   (unsigned long)g_stress.iters_done, (unsigned long)(uptime_s / 3600),
                   (unsigned long)((uptime_s % 3600) / 60), (unsigned long)(uptime_s % 60),
                   (unsigned long)g_stress.total_allocs, (unsigned long)g_stress.total_frees,
                   (unsigned long)(g_stress.total_alloc_errors + g_stress.total_free_errors),
                   (unsigned long)g_stress.total_bufs_alloced, (unsigned long)g_stress.total_bufs_freed,
                   sum_alloced);
            printf("[stress]   RSS=%luMB\n", (unsigned long)(GetRssKb() / 1024));
            DoInfo(std::vector<std::string>{});
            fflush(stdout);
        }
    }
    /* Final summary to stdout (reached on signal interrupt or never on
     * infinite loop without interrupt). */
    uint64_t now = NowMicros();
    uint64_t uptime_s = (now - g_stress.start_time_us) / 1000000;
    printf("[stress %s] iters=%lu uptime=%luh %lum %lus allocs=%lu frees=%lu "
           "alloc_errors=%lu free_errors=%lu bufs_alloced=%lu bufs_freed=%lu\n",
           g_stress.interrupted ? "interrupted" : "done", (unsigned long)g_stress.iters_done,
           (unsigned long)(uptime_s / 3600), (unsigned long)((uptime_s % 3600) / 60),
           (unsigned long)(uptime_s % 60), (unsigned long)g_stress.total_allocs,
           (unsigned long)g_stress.total_frees, (unsigned long)g_stress.total_alloc_errors,
           (unsigned long)g_stress.total_free_errors, (unsigned long)g_stress.total_bufs_alloced,
           (unsigned long)g_stress.total_bufs_freed);
    return 0;
}
