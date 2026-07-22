/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq trace
 * Create: 2026-6-18
 */

#include <stdarg.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "umq_thread_local.h"
#include "urpc_timer.h"
#include "urpc_thread_closure.h"
#include "urpc_util.h"
#include "perf.h"

#define UMQ_TRACE_DEFAULT_RECORD_NUM   8192
#define UMQ_TRACE_DEFAULT_RECORD_LIMIT 0
#define UMQ_TRACE_LOG_BUF_SIZE         512

/*
 * Per-thread trace state mirrors the perf.c / umq_ub_thread_wr pattern: a
 * thread's slot in trace_buf[] is indexed directly by umq_thread_id_get() --
 * no private thread key, no bitmap, no per-thread encode. The thread id
 * allocator (umq_thread_local.c) already provides an idempotent per-thread
 * fast path and recycles ids on thread exit.
 *
 * trace_buf[] is sized UMQ_THREAD_ID_MAX so the id can index it directly. The
 * first UMQ_THREAD_ID_RANGE_DEFAULT slots' data_record is pre-allocated at
 * init (the common data path is allocation-free); ids beyond that allocate
 * lazily on first use. Every data_record is freed ONLY in umq_trace_uninit,
 * never on thread exit -- a recycled id reuses the still-live buffer (the data
 * path rewrites contents each call). This is the umq_ub_thread_wr ownership
 * model.
 *
 * The currently-open record index (record_index) is one-per-slot, so it lives
 * in the shared umq_trace_buf_t itself rather than per-thread: a slot is owned
 * by exactly one thread at a time, so writing trace_buf[id] from the owning
 * thread never races with another thread. When == -1 there is no active
 * record; sub_record/item_record are then no-ops. This is how helper functions
 * (e.g. the FC poll functions, shared-credit send) automatically skip tracing
 * when called from outside a traced context.
 *
 * Thread-exit cleanup (resetting the slot's record_index/counters so a
 * recycled id starts clean) is done by the THREAD_CLOSURE_UMQ_DATA_PERF
 * closure, a thread_local C++ object -- same mechanism perf.c uses. Like
 * perf.c, no lock is needed: uninit assumes the data-path threads have exited
 * (framework teardown joins them first), and the only residual late-closure
 * race is bounded by the ctx==NULL check, identical to perf.c's closure.
 */
static uint32_t g_umq_trace_output_limit = UMQ_TRACE_DEFAULT_RECORD_LIMIT;
static uint32_t g_umq_trace_record_num = UMQ_TRACE_DEFAULT_RECORD_NUM;
static bool g_umq_trace_enable = false;

/* unified trace — single ring buffer for all types, one per thread */
typedef struct umq_trace_buf {
    uint32_t record_cnt;
    uint32_t previous_output_cnt;
    int32_t record_index;              /* ring index of the currently-open record, -1 if none */
    umq_data_record_t *data_record;    /* dynamically allocated, size = g_umq_trace_record_num */
    volatile bool inited;
} umq_trace_buf_t;

typedef struct umq_trace_ctx {
    umq_trace_buf_t trace_buf[UMQ_THREAD_ID_MAX];
    urpc_timer_t *timer;
} umq_trace_ctx_t;

static umq_trace_ctx_t *g_umq_trace_ctx;

static int umq_trace_init(umq_trace_cfg_t *cfg)
{
    if (g_umq_trace_ctx != NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq trace has been inited\n");
        return -UMQ_ERR_EEXIST;
    }
    if ((cfg->flag & UMQ_TRACE_FLAG_RECORD_NUM) != 0) {
        if (cfg->record_num == 0) {
            UMQ_VLOG_ERR(VLOG_UMQ, "record_num must be non-zero\n");
            return -UMQ_ERR_EINVAL;
        }
        g_umq_trace_record_num = cfg->record_num;
    }
    if ((cfg->flag & UMQ_TRACE_FLAG_OUTPUT_LIMIT) != 0) {
        g_umq_trace_output_limit = cfg->output_limit;
    }

    g_umq_trace_ctx = (umq_trace_ctx_t *)calloc(1, sizeof(umq_trace_ctx_t));
    if (g_umq_trace_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc for umq_trace failed\n");
        goto RESET_CFG;
    }

    /* Pre-allocate the data_record ring for the first UMQ_THREAD_ID_RANGE_DEFAULT
     * ids so the common data path is allocation-free; ids beyond that allocate
     * lazily in umq_trace_alloc. */
    for (uint32_t i = 0; i < UMQ_THREAD_ID_RANGE_DEFAULT; i++) {
        g_umq_trace_ctx->trace_buf[i].data_record =
            (umq_data_record_t *)calloc(g_umq_trace_record_num, sizeof(umq_data_record_t));
        if (g_umq_trace_ctx->trace_buf[i].data_record == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "calloc for umq_trace data_record failed, trace_record_num %u\n",
                g_umq_trace_record_num);
            goto FREE_DATA_RECORD;
        }
    }

    return UMQ_SUCCESS;

FREE_DATA_RECORD:
    for (uint32_t i = 0; i < UMQ_THREAD_ID_MAX; i++) {
        if (g_umq_trace_ctx->trace_buf[i].data_record != NULL) {
            free(g_umq_trace_ctx->trace_buf[i].data_record);
            g_umq_trace_ctx->trace_buf[i].data_record = NULL;
        }
    }
    free(g_umq_trace_ctx);
    g_umq_trace_ctx = NULL;

RESET_CFG:
    g_umq_trace_output_limit = UMQ_TRACE_DEFAULT_RECORD_LIMIT;
    g_umq_trace_record_num = UMQ_TRACE_DEFAULT_RECORD_NUM;

    return -UMQ_ERR_ENOMEM;
}

void umq_trace_timer_delete(void)
{
    if (g_umq_trace_ctx == NULL) {
        return;
    }
    if (g_umq_trace_ctx->timer != NULL) {
        urpc_timer_destroy(g_umq_trace_ctx->timer);
        g_umq_trace_ctx->timer = NULL;
    }
}

void umq_trace_uninit(void)
{
    if (g_umq_trace_ctx == NULL) {
        return;
    }

    /* Caller guarantees data-path threads have exited (framework teardown
     * joins them first), so no concurrent writers here. Free every slot's
     * data_record uniformly -- both the init-time and lazily-allocated ones. */
    g_umq_trace_enable = false;
    for (uint32_t i = 0; i < UMQ_THREAD_ID_MAX; i++) {
        if (g_umq_trace_ctx->trace_buf[i].data_record != NULL) {
            free(g_umq_trace_ctx->trace_buf[i].data_record);
            g_umq_trace_ctx->trace_buf[i].data_record = NULL;
        }
    }
    free(g_umq_trace_ctx);
    g_umq_trace_ctx = NULL;
    g_umq_trace_output_limit = UMQ_TRACE_DEFAULT_RECORD_LIMIT;
    g_umq_trace_record_num = UMQ_TRACE_DEFAULT_RECORD_NUM;
}

/* Reset a slot's record state (not its data_record, which is freed only at
 * uninit). Called at alloc and on thread exit so a recycled id starts clean. */
static void umq_trace_record_clear(uint32_t idx)
{
    umq_trace_buf_t *cur_record = &g_umq_trace_ctx->trace_buf[idx];
    cur_record->record_cnt = 0;
    cur_record->previous_output_cnt = 0;
    cur_record->record_index = -1;
}

static void umq_trace_closure(uint64_t idx)
{
    /* Thread-exit cleanup: reset this thread's slot state so a recycled id
     * (reclaimed by the umq_thread_id destructor) starts clean. The slot's
     * data_record is NOT freed here -- it lives until umq_trace_uninit, per
     * the umq_ub_thread_wr ownership model. No lock: like perf.c's closure,
     * the only residual race vs uninit is bounded by the ctx==NULL check. */
    if (g_umq_trace_ctx == NULL) {
        return;
    }
    g_umq_trace_ctx->trace_buf[idx].inited = false;
}

void umq_trace_alloc(void)
{
    /* umq_thread_id_get() is idempotent per thread (it caches the id in its own
     * thread-key fast path), so this is lock-free on the steady state. Thread
     * ids are unique per-thread, so each thread indexes a distinct trace_buf[id]. */
    uint32_t id = umq_thread_id_get();
    if (g_umq_trace_ctx == NULL || id >= UMQ_THREAD_ID_MAX) {
        return;
    }

    umq_trace_buf_t *cur_rec = &g_umq_trace_ctx->trace_buf[id];
    if (cur_rec->data_record != NULL && cur_rec->inited) {
        return;
    }

    if (cur_rec->data_record == NULL) {
        /* Slow path: id >= UMQ_THREAD_ID_RANGE_DEFAULT, first use by this thread. */
        cur_rec->data_record = (umq_data_record_t *)calloc(g_umq_trace_record_num, sizeof(umq_data_record_t));
        if (cur_rec->data_record == NULL) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq trace data_record alloc failed for id %u\n", id);
            return;
        }
    }

    umq_trace_record_clear(id);
    cur_rec->inited = true;
    urpc_thread_closure_register(THREAD_CLOSURE_UMQ_DATA_PERF, id, umq_trace_closure);
}

uint64_t umq_trace_start_timestamp_get(void)
{
    if (!g_umq_trace_enable) {
        return 0;
    }
    /* umq_thread_id_get() is idempotent per thread, so repeated calls take the
     * fast path. On first use, lazily allocate this thread's data_record if the
     * id was beyond the init-pre-allocated range; allocation is skipped on
     * subsequent calls once data_record is non-NULL. */
    umq_trace_alloc();
    return get_timestamp_ns();
}

uint64_t umq_trace_timestamp_get(void)
{
    if (!g_umq_trace_enable) {
        return 0;
    }
    return get_timestamp_ns();
}

/* ================================================================
 *  New unified record APIs
 * ================================================================ */

static ALWAYS_INLINE umq_trace_buf_t *umq_trace_buf_get(void)
{
    /* Index directly by the calling thread's umq id. umq_thread_id_get() is a
     * lock-free thread-local read on the steady state (it caches the id in its
     * own thread-key fast path). */
    uint32_t id = umq_thread_id_get();
    if (g_umq_trace_ctx == NULL || id >= UMQ_THREAD_ID_MAX) {
        return NULL;
    }
    return &g_umq_trace_ctx->trace_buf[id];
}

uint64_t umq_trace_write_delta(uint64_t start)
{
    if (!g_umq_trace_enable || start == 0) {
        return 0;
    }
    return get_timestamp_ns() - start;
}

void umq_trace_start_record(umq_trace_type_t type, uint64_t time, uint64_t tag_timestamp, uint32_t umq_id)
{
    if (!g_umq_trace_enable) {
        return;
    }

    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL) {
        return;
    }

    uint32_t idx = cur_rec->record_cnt % g_umq_trace_record_num;
    umq_data_record_t *rec = &cur_rec->data_record[idx];

    rec->timestamp = get_timestamp_ns();
    rec->tag_timestamp = tag_timestamp;
    rec->type = type;
    rec->start_time = time;
    rec->end_time = 0;
    rec->sub_time_cnt = 0;
    rec->item_cnt = 0;
    rec->umq_id = umq_id;
    if (cur_rec->record_cnt - cur_rec->previous_output_cnt >= g_umq_trace_record_num) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "new data num exceeds the capacity, resulting in data overwriting\n");
    }
    cur_rec->record_cnt++;
    cur_rec->record_index = (int32_t)idx;
}

void umq_trace_sub_record(umq_trace_type_t type, umq_urma_func_type_t func_type,
                          uint64_t start_time, uint64_t exec_time)
{
    if (!g_umq_trace_enable) {
        return;
    }
    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL || cur_rec->record_index < 0) {
        return;
    }
    uint32_t idx = (uint32_t)cur_rec->record_index;
    if (idx >= g_umq_trace_record_num) {
        return;
    }
    umq_data_record_t *rec = &cur_rec->data_record[idx];
    if (rec->sub_time_cnt >= UMQ_PERF_MAX_SUB_TIME_NUM) {
        return;
    }
    umq_sub_time_t *sub = &rec->sub_time[rec->sub_time_cnt];
    sub->start_time = start_time;
    sub->exec_time = exec_time;
    sub->func_type = func_type;
    rec->sub_time_cnt++;
}

void umq_trace_item_record(uint32_t msn, uint32_t size, uint32_t sub_umq_id)
{
    if (!g_umq_trace_enable) {
        return;
    }

    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL || cur_rec->record_index < 0) {
        return;
    }
    uint32_t idx = (uint32_t)cur_rec->record_index;
    if (idx >= g_umq_trace_record_num) {
        return;
    }
    umq_data_record_t *rec = &cur_rec->data_record[idx];
    if (rec->item_cnt >= UMQ_BATCH_SIZE) {
        return;
    }
    rec->items[rec->item_cnt].msn = msn;
    rec->items[rec->item_cnt].size = size;
    rec->items[rec->item_cnt].sub_umq_id = sub_umq_id;
    rec->item_cnt++;
}

void umq_trace_end_record(umq_trace_type_t type, uint64_t time)
{
    if (!g_umq_trace_enable) {
        return;
    }

    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL || cur_rec->record_index < 0) {
        return;
    }

    uint32_t idx = (uint32_t)cur_rec->record_index;
    if (idx >= g_umq_trace_record_num) {
        return;
    }
    umq_data_record_t *rec = &cur_rec->data_record[idx];
    if (rec->type == type && rec->end_time == 0) {
        rec->end_time = time;
    }
    cur_rec->record_index = -1;
}

/* ================================================================
 *  Unified output
 * ================================================================ */

static const char *umq_trace_type_str(umq_trace_type_t type)
{
    static const char *type_str[] = {
        [UMQ_TRACE_TYPE_POST]  = "POST",
        [UMQ_TRACE_TYPE_POLL]  = "POLL",
        [UMQ_TRACE_TYPE_WAIT]  = "WAIT",
        [UMQ_TRACE_TYPE_REARM] = "REARM",
    };
    return (type < UMQ_TRACE_TYPE_MAX) ? type_str[type] : "UNKNOWN";
}

static const char *umq_urma_func_str(umq_urma_func_type_t func_type)
{
    static const char *func_str[] = {
        [UMQ_URMA_FUNC_POST_TX]       = "urma_post_jetty_send_wr",
        [UMQ_URMA_FUNC_POST_RX]       = "urma_post_jetty_recv_wr",
        [UMQ_URMA_FUNC_POLL_TX]       = "urma_poll_jfc(tx)",
        [UMQ_URMA_FUNC_POLL_RX]       = "urma_poll_jfc(rx)",
        [UMQ_URMA_FUNC_WAIT_TX_JFC]   = "urma_wait_jfc(tx)",
        [UMQ_URMA_FUNC_WAIT_RX_JFC]   = "urma_wait_jfc(rx)",
        [UMQ_URMA_FUNC_ACK_TX_JFC]    = "urma_ack_jfc(tx)",
        [UMQ_URMA_FUNC_ACK_RX_JFC]    = "urma_ack_jfc(rx)",
        [UMQ_URMA_FUNC_REARM_JFC]     = "urma_rearm_jfc",
        [UMQ_URMA_FUNC_FC_REARM_JFC]  = "urma_rearm_jfc(fc)",
        [UMQ_URMA_FUNC_FC_POST_TX]    = "urma_post_jetty_send_wr(fc)",
        [UMQ_URMA_FUNC_FC_POLL_TX]    = "urma_poll_jfc(fc tx)",
        [UMQ_URMA_FUNC_FC_POST_RX]    = "urma_post_jetty_recv_wr(fc)",
        [UMQ_URMA_FUNC_FC_POLL_RX]    = "urma_poll_jfc(fc rx)",
    };
    return (func_type < UMQ_URMA_FUNC_MAX) ? func_str[func_type] : "UNKNOWN";
}

static void umq_trace_output_single(umq_trace_buf_t *cur_rec, uint32_t thread_id)
{
    uint32_t record_cnt = cur_rec->record_cnt;
    uint32_t previous_output_cnt = cur_rec->previous_output_cnt;
    uint32_t new_records;
    char buf[UMQ_TRACE_LOG_BUF_SIZE] = {0};

    if (record_cnt >= previous_output_cnt) {
        new_records = record_cnt - previous_output_cnt;
    } else {
        new_records = (g_umq_trace_record_num - previous_output_cnt) + record_cnt;
    }
    if (new_records <= g_umq_trace_output_limit) {
        return;
    }
    UMQ_VLOG_INFO(VLOG_UMQ, "============ thread %u records: %u--%u ===========\n",
                  thread_id, previous_output_cnt, record_cnt);
    if (cur_rec->data_record == NULL) {
        return;
    }
    for (uint32_t i = 0; i < new_records; i++) {
        uint32_t idx = (previous_output_cnt + i) % g_umq_trace_record_num;
        umq_data_record_t *rec = &cur_rec->data_record[idx];
        uint64_t umq_exec = (rec->end_time > rec->start_time) ? (rec->end_time - rec->start_time) : 0;
        int pos = 0;
        int need = 0;
        pos = snprintf(buf, UMQ_TRACE_LOG_BUF_SIZE,
            "#%u type=%s umq_id=%u umq_start=%lu umq_end=%lu umq_exec=%lu item_cnt=%u ts=%lu tag_ts=%lu;",
            i, umq_trace_type_str(rec->type), rec->umq_id, rec->start_time, rec->end_time, umq_exec,
            rec->item_cnt, rec->timestamp, rec->tag_timestamp);
        for (uint32_t k = 0; k < rec->item_cnt; k++) {
            need = snprintf(NULL, 0, " item[%u] umq_id=%u sub_umq_id=%u msn=%u size=%u;",
                k, rec->umq_id, rec->items[k].sub_umq_id, rec->items[k].msn, rec->items[k].size);
            if (pos + need >= UMQ_TRACE_LOG_BUF_SIZE - 1) {
                buf[pos] = '\0';
                UMQ_VLOG_INFO(VLOG_UMQ, "%s\n", buf);
                pos = 0;
            }
            pos += snprintf(buf + pos, UMQ_TRACE_LOG_BUF_SIZE - pos,
                " item[%u] umq_id=%u sub_umq_id=%u msn=%u size=%u;",
                k, rec->umq_id, rec->items[k].sub_umq_id, rec->items[k].msn, rec->items[k].size);
        }
        buf[pos] = '\0';
        UMQ_VLOG_INFO(VLOG_UMQ, "%s\n", buf);
        pos = 0;
        for (uint32_t j = 0; j < rec->sub_time_cnt; j++) {
            umq_sub_time_t *sub = &rec->sub_time[j];
            need = snprintf(NULL, 0, " sub[%u] umq_id=%u func=%s start=%lu exec=%lu;",
                j, rec->umq_id, umq_urma_func_str(sub->func_type), sub->start_time, sub->exec_time);
            if (pos + need >= UMQ_TRACE_LOG_BUF_SIZE - 1) {
                buf[pos] = '\0';
                UMQ_VLOG_INFO(VLOG_UMQ, "%s\n", buf);
                pos = 0;
            }
            pos += snprintf(buf + pos, UMQ_TRACE_LOG_BUF_SIZE - pos, " sub[%u] umq_id=%u func=%s start=%lu exec=%lu;",
                j, rec->umq_id, umq_urma_func_str(sub->func_type), sub->start_time, sub->exec_time);
        }
        if (pos > 0) {
            buf[pos] = '\0';
            UMQ_VLOG_INFO(VLOG_UMQ, "%s\n", buf);
        }
    }
    cur_rec->previous_output_cnt = record_cnt;
}

static void umq_trace_output(void *args __attribute__((unused)))
{
    if (!g_umq_trace_enable) {
        return;
    }
    for (uint32_t i = 0; i < UMQ_THREAD_ID_MAX; ++i) {
        umq_trace_buf_t *cur_rec = &g_umq_trace_ctx->trace_buf[i];
        if (cur_rec->data_record == NULL || cur_rec->record_cnt == 0) {
            continue;
        }
        umq_trace_output_single(cur_rec, i);
    }
}

void umq_trace_remain_output(void)
{
    g_umq_trace_output_limit = 0;
    umq_trace_output(NULL);
}

static int umq_ub_trace_output_timer_create(void)
{
    g_umq_trace_ctx->timer = urpc_timer_create(0xFFFFFFFF, false);
    if (URPC_UNLIKELY(g_umq_trace_ctx->timer == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq timer create failed\n");
        return UMQ_FAIL;
    }
    int ret = urpc_timer_start(g_umq_trace_ctx->timer, 1, umq_trace_output, NULL, true);
    if (URPC_UNLIKELY(ret != UMQ_SUCCESS)) {
        urpc_timer_destroy(g_umq_trace_ctx->timer);
        g_umq_trace_ctx->timer = NULL;
        return UMQ_FAIL;
    }
    return UMQ_SUCCESS;
}

int umq_trace_start(umq_trace_cfg_t *cfg)
{
    if (g_umq_trace_enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq trace already started\n");
        return -UMQ_ERR_EINVAL;
    }
    if (g_umq_trace_ctx == NULL) {
        int ret = umq_trace_init(cfg);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq trace init failed\n");
            return ret;
        }
    }
    if (umq_ub_trace_output_timer_create() != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq trace output timer create failed\n");
        return UMQ_FAIL;
    }
    g_umq_trace_enable = true;
    return UMQ_SUCCESS;
}

int umq_trace_stop(void)
{
    if (!g_umq_trace_enable || g_umq_trace_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq trace already stopped\n");
        return -UMQ_ERR_EINVAL;
    }
    if (g_umq_trace_ctx->timer != NULL) {
        urpc_timer_destroy(g_umq_trace_ctx->timer);
        g_umq_trace_ctx->timer = NULL;
    }
    g_umq_trace_enable = false;
    return UMQ_SUCCESS;
}