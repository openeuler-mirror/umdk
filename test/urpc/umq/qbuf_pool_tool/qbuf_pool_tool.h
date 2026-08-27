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

/* Shared declarations for qbuf_pool_tool — split across stubs/utils/core/main. */

#ifndef QBUF_POOL_TOOL_H
#define QBUF_POOL_TOOL_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <memory>
#include <string>
#include <vector>

#include "umq_qbuf_pool.h" /* umq_buf_t/umq_buf_list_t/umq_alloc_option_t/umq_buf_block_size_t/qbuf_list.h */

/* ===================== timing helpers ===================== */
/* NowMicros: cheap monotonic clock in microseconds. Used to instrument
 * parallel-block dispatch + barrier to provide evidence that workers
 * truly run concurrently (vs. serial drain of completion order).
 *
 * Verbose mode (env var QBUF_TOOL_VERBOSE=1) enables per-block timing
 * summary to stderr: dispatch time, barrier time, per-worker wait min/max.
 * Default off — keeps stress-case output clean. */
uint64_t NowMicros();
bool VerboseEnabled();

/* ===================== tool state ===================== */
/* Per-worker total held buf cap. Bounds alloced vector memory and O(n) scan
 * time in FREE_IDX (which now scans by orig_idx). Pool exhaustion (umq_normal_qbuf_alloc
 * returns ENOMEM) is the natural backstop and usually kicks in first; this cap
 * is a safety net for cases where the pool is large but a worker accumulates
 * bufs without freeing (e.g. user error in stress_repeat without free all).
 * 65536 bufs × sizeof(AllocedBuf) ≈ 1.8 MB per worker — acceptable. */
constexpr uint32_t WORKER_ALLOCED_CAP = 65536;

struct AllocOp {
    uint32_t size;       /* request size */
    uint32_t sc;         /* size_class routed */
    uint32_t total;      /* bufs in this op */
    uint32_t remaining;  /* bufs still held */
    size_t actions_idx;  /* index into g_actions, for cross-reference */
    uint32_t thread_idx; /* which worker performed this alloc */
    uint32_t orig_idx_start; /* first buf's stable orig_idx; subsequent bufs are +1, +2, ... */
};
struct AllocedBuf {
    umq_buf_t *buf;
    size_t op_idx;     /* index into owning worker's alloc_ops */
    uint32_t orig_idx; /* stable per-buf index, assigned at drain time, monotonic per worker */
};
/* Task passed from main thread to a worker via Dispatch(). Worker executes
 * it, fills result fields (alloc_list/first_sc/ret), then signals done. */
struct ThreadTask {
    enum Type {
        ALLOC,
        FREE_IDX,
        FREE_ALL,
        EXIT
    } type;
    /* input */
    uint32_t size;
    uint32_t num;
    uint16_t headroom;
    /* free_indices: orig_idx list for FREE_IDX (supports `free 0,1,2` multi-idx
     * syntax so parallel blocks can free multiple bufs per worker in one command,
     * avoiding the "thread_K appears more than once" validation rule).
     * free_count = number of valid entries; 0 = not a multi-idx free. */
    uint32_t free_indices[64];
    uint32_t free_count;
    /* sync */
    pthread_mutex_t mtx;
    pthread_cond_t ready;
    pthread_cond_t done;
    bool has_task;
    bool finished;
    /* result (alloc) */
    int ret;
    umq_buf_list_t alloc_list;
    uint32_t alloc_cnt;
    uint32_t first_sc;
    uint32_t first_blk_size; /* blk_size of the first allocated buf; main thread
                              * resolves it to a size_class via BlkSizeToSc +
                              * the sc_info[] array from umq_stats_qbuf_pool_get
                              * (the worker cannot call blk_size_to_sc directly
                              * now that the tool no longer #includes
                              * umq_qbuf_pool.c). */
    /* Worker-side timestamps (microseconds since some monotonic epoch).
     * WorkerMain records start (task picked up) and end (task completed)
     * to provide evidence of parallel execution — when verbose mode is on,
     * DrainWorkerResult prints "[tN] worker ran: start=Xμs end=Yμs
     * duration=Zμs". Concurrent workers will have overlapping
     * [start, end] intervals, proving parallel execution. */
    uint64_t worker_start_us;
    uint64_t worker_end_us;
};
struct Worker {
    pthread_t tid;
    uint64_t kernel_tid; /* OS kernel TID (syscall SYS_gettid), matches DFX
                           * tls->tid after the production code switched from
                           * pthread_self() (pthread_t address) to gettid.
                           * Kept separate from pthread_t tid (used for
                           * pthread_join) so we can still join the worker. */
    uint32_t idx;
    ThreadTask task;
    std::vector<AllocOp> alloc_ops;
    std::vector<AllocedBuf> alloced;
    bool running;
    /* next_orig_idx: monotonic counter for AllocedBuf::orig_idx. Incremented
     * each time a buf is pushed into alloced (in DrainWorkerResult). Reset to 0
     * on Worker construction, on FREE_ALL, and on DoInit reinit. Stable across
     * individual FREE_IDX (orig_idx of other bufs doesn't change on erase). */
    uint32_t next_orig_idx;
    /* Parallel-mode state:
     *   has_async — worker has a dispatched-but-not-yet-drained async task
     *   pending_action_idx — slot in g_actions pre-reserved at dispatch time,
     *       so the actions log preserves dispatch order regardless of which
     *       worker finishes first. DrainWorkerResult() back-fills the string
     *       into g_actions[pending_action_idx] at SyncAll() time. */
    bool has_async;
    size_t pending_action_idx;
    Worker() : idx(0), kernel_tid(0), running(false), next_orig_idx(0), has_async(false), pending_action_idx(0)
    {
        pthread_mutex_init(&task.mtx, NULL);
        pthread_cond_init(&task.ready, NULL);
        pthread_cond_init(&task.done, NULL);
        task.has_task = false;
        task.finished = false;
        task.type = ThreadTask::ALLOC;
        task.size = 0;
        task.num = 1;
        task.headroom = 0;
        task.free_count = 0;
        memset(task.free_indices, 0, sizeof(task.free_indices));
        task.ret = 0;
        task.alloc_cnt = 0;
        task.first_sc = 0;
        task.first_blk_size = 0;
        task.worker_start_us = 0;
        task.worker_end_us = 0;
        QBUF_LIST_INIT(&task.alloc_list);
    }
    ~Worker()
    {
        pthread_mutex_destroy(&task.mtx);
        pthread_cond_destroy(&task.ready);
        pthread_cond_destroy(&task.done);
    }
    Worker(const Worker &) = delete;
    Worker &operator=(const Worker &) = delete;
};

extern std::vector<std::unique_ptr<Worker>> g_workers;
extern std::vector<std::string> g_actions;
extern void *g_buf_addr;
extern uint64_t g_buf_size;
extern bool g_inited;

/* stress_repeat mode: when true, DrainWorkerResult skips g_actions writes and
 * per-buf printf to bound memory for days-long infinite-loop runs. Main thread
 * bumps g_stress counters (single-threaded, no atomic needed). Cleared by
 * StressModeGuard RAII at DoStressRepeatBlock exit. */
extern bool g_stress_mode;

/* Stop request flag — set by SIGINT/SIGTERM handler installed in
 * DoStressRepeatBlock. The stress loop checks this at iter boundary and
 * breaks gracefully (run Cleanup, exit). Second signal re-installs default
 * handler and re-raises so user can force-kill if cleanup hangs. */
extern volatile sig_atomic_t g_stop_requested;

struct StressCounters {
    uint64_t iters_done;
    uint64_t total_allocs;
    uint64_t total_frees;
    uint64_t total_alloc_errors;
    uint64_t total_free_errors;
    uint64_t total_bufs_alloced;
    uint64_t total_bufs_freed;
    uint64_t start_time_us;
    bool interrupted; /* true if last stress_repeat was stopped by signal */
};
extern StressCounters g_stress;

/* ===================== utils.cpp ===================== */
uint64_t ParseSize(const char *s);
umq_buf_block_size_t BaseStrToEnum(const char *s);
/* Reverse map: byte count (e.g. 4096) → umq_buf_block_size_t enum (BLOCK_SIZE_4K).
 * Used by DoInit to derive base from blockSizes[0] automatically, removing
 * the need for a separate `base=` init parameter (base must equal
 * explicit_block_sizes[0], enforced by umq_qbuf_pool.c:1529). */
umq_buf_block_size_t BlkSizeToEnum(uint32_t bytes);
umq_buf_mode_t ModeStrToEnum(const char *s);
bool OnOffToBool(const char *s, bool def);
bool SplitKv(const std::string &tok, std::string &k, std::string &v);
std::vector<std::string> Tokenize(const char *line);

/* ===================== core.cpp ===================== */
/* SPLIT mode: buf_size = block_size + sizeof(umq_buf_t); COMBINE: buf_size = block_size */
uint32_t BufToBlkSize(umq_buf_t *buf);
/* Map a blk_size to its size_class index by scanning sc_info[]. Equivalent
 * to the production static helper blk_size_to_sc() in umq_qbuf_pool.c. */
uint32_t BlkSizeToSc(uint32_t blk_size, const umq_qbuf_sc_info_t *sc_info, uint32_t sc_count);
void *WorkerMain(void *arg);

/* Synchronous dispatch: fill task → signal ready → block on done → return.
 * Used by serial commands (default execution path). */
void Dispatch(size_t widx, ThreadTask::Type type, uint32_t size = 0, uint32_t num = 1, uint16_t headroom = 0,
              const uint32_t *free_indices = nullptr, uint32_t free_count = 0);
/* Asynchronous dispatch: fill task → signal ready → return immediately
 * WITHOUT waiting for done. Result is drained later by SyncAll().
 * Caller must NOT touch w.task fields after this returns until SyncAll(). */
void DispatchAsync(size_t widx, ThreadTask::Type type, uint32_t size = 0, uint32_t num = 1, uint16_t headroom = 0,
                   const uint32_t *free_indices = nullptr, uint32_t free_count = 0);
/* SyncAll: barrier — wait for every worker with has_async==true to finish
 * its pending async task, drain the result into w.alloced/g_actions/
 * alloc_ops, clear has_async. Safe to call DFX (umq_stats_qbuf_pool_get)
 * after barrier since no worker is mutating TLS. */
void SyncAll();
/* DrainWorkerResult: shared by serial DoAlloc (immediate drain) and SyncAll
 * (deferred drain). Fetches DFX sc_info[], resolves first_sc from
 * task.first_blk_size, drains task.alloc_list into w.alloced, back-fills
 * g_actions[pending_action_idx] with the action string, updates alloc_ops. */
void DrainWorkerResult(Worker &w);
void FreeAllOnWorkers();
void StopWorkers();
void Cleanup();
int DoInit(const std::vector<std::string> &args);
/* async parameter: when true, DispatchAsync + pre-reserve g_actions slot,
 * return without draining; when false (default), Dispatch + drain inline. */
int DoAlloc(const std::vector<std::string> &args, size_t widx, bool async = false);
int DoFree(const std::vector<std::string> &args, size_t widx, bool async = false);
int DoInfo(const std::vector<std::string> &args);
int DoStatus(const std::vector<std::string> &args);
int DoSleep(const std::vector<std::string> &args);
/* DoParallelBlock: dispatch every thread_K line in block asynchronously,
 * then SyncAll. Validates block contents: only thread_K alloc/free, no
 * info/status/init/quit, no worker mixing alloc+free. Returns 0 on success.
 * On validation error prints ERROR and returns -1 (block is not executed). */
int DoParallelBlock(const std::vector<std::vector<std::string>> &block);
/* DoRepeatBlock: execute block `count` times serially. Block may contain
 * thread_K lines (serial) or a single nested parallel/join block. Validates
 * block contents: no info/status/init/quit. count must be <= 10000. */
int DoRepeatBlock(int count, const std::vector<std::vector<std::string>> &block);
/* DoStressRepeatBlock: like DoRepeatBlock but executes in stress mode —
 * DrainWorkerResult skips g_actions writes and per-buf printf so memory
 * stays bounded for days-long runs. User MUST ensure alloc/free pairing
 * at iter boundary; this function does NOT enforce conservation (clears
 * Worker::alloc_ops silently when alloced.empty() to bound memory for
 * `free <idx>` patterns). Optional `snapshot N` directive in block prints
 * a one-line progress summary every N iters to stdout.
 *
 * Runs INFINITELY — no count parameter. The loop breaks only on:
 *   - ExecuteBlockLines returning non-zero (alloc/free failure) — exits 1
 *   - SIGINT/SIGTERM (Ctrl-C) — sets g_stop_requested, breaks after current
 *     iter, prints "[stress] interrupted by signal at iter N" + summary,
 *     returns 0 (graceful)
 *   - Second SIGINT — re-installs default handler, force-kills process */
int DoStressRepeatBlock(const std::vector<std::vector<std::string>> &block);
/* ExecuteBlockLines: dispatch a vector of pre-parsed lines in serial mode
 * (the contents of one repeat iteration). Lines may be thread_K commands
 * or a parallel/join sub-block. Returns 0 on success, -1 on any failure. */
int ExecuteBlockLines(const std::vector<std::vector<std::string>> &block);
/* TokenizeBlock: split a raw block (vector of source lines) into a vector
 * of token vectors, dropping comments/blank lines. */
std::vector<std::vector<std::string>> TokenizeBlock(const std::vector<std::string> &raw);
/* ValidateParallelBlock: ensure block contains only thread_K alloc/free
 * lines and no worker mixes alloc+free. Returns 0 ok, -1 invalid. */
int ValidateParallelBlock(const std::vector<std::vector<std::string>> &block);
/* ValidateRepeatBlock: ensure block contains no info/status/init/quit and
 * no nested repeat. Multiple parallel/join sub-blocks per repeat iteration
 * are allowed (e.g. alloc block + free block). Returns 0 ok, -1 invalid. */
int ValidateRepeatBlock(const std::vector<std::vector<std::string>> &block);

#endif /* QBUF_POOL_TOOL_H */
