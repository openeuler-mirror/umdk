/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq trace
 * Create: 2026-6-18
 */

#include <pthread.h>
#include <stdarg.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "urpc_timer.h"
#include "urpc_thread_closure.h"
#include "urpc_util.h"
#include "perf.h"

#define UMQ_TRACE_DEFAULT_RECORD_NUM   10240
#define UMQ_TRACE_DEFAULT_RECORD_LIMIT 1

/*
 * Thread-local trace state — one per thread, no lock needed.
 *
 * g_umq_trace_buf_index:    slot index into g_umq_trace_ctx->trace_buf[], allocated once
 *                   by umq_trace_alloc() via pthread_once.  Persists for the
 *                   lifetime of the thread; all trace records for this thread
 *                   live in that single slot.
 *
 * g_umq_trace_record_index: ring-buffer index of the currently-open record, set by
 *                    umq_trace_start_record() and cleared to -1 by
 *                    umq_trace_end_record().  While >= 0, any call to
 *                    umq_trace_sub_record() or umq_trace_item_record() will
 *                    append to that record — no need to pass an explicit id
 *                    through intermediate call stacks.
 *
 *                    When == -1, there is no active record; sub_write /
 *                    data_write are immediate no-ops.  This is the
 *                    mechanism by which helper functions (e.g. the FC poll
 *                    functions, shared-credit send) automatically skip
 *                    tracing when called from outside a traced context.
 */
static __thread uint32_t g_umq_trace_buf_index = -1;
static __thread int32_t g_umq_trace_record_index = -1;
static __thread pthread_once_t g_umq_trace_thread_run_once = PTHREAD_ONCE_INIT;
static uint32_t g_umq_trace_output_limit = UMQ_TRACE_DEFAULT_RECORD_LIMIT;
static uint32_t g_umq_trace_record_num = UMQ_TRACE_DEFAULT_RECORD_NUM;
static bool g_umq_trace_enable = false;
static pthread_spinlock_t g_umq_trace_lock;

/* unified trace — single ring buffer for all types, one per thread */
typedef struct umq_trace_buf {
    uint32_t record_cnt;
    uint32_t previous_output_cnt;
    umq_data_record_t *data_record;    /* dynamically allocated, size = g_umq_trace_record_num */
    bool is_used;
} umq_trace_buf_t;

typedef struct umq_trace_ctx {
    pthread_once_t *dp_thread_run_once[UMQ_PERF_REC_MAX_NUM];
    umq_trace_buf_t trace_buf[UMQ_PERF_REC_MAX_NUM];
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

    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; i++) {
        g_umq_trace_ctx->trace_buf[i].data_record =
            (umq_data_record_t *)calloc(g_umq_trace_record_num, sizeof(umq_data_record_t));
        if (g_umq_trace_ctx->trace_buf[i].data_record == NULL) {
            UMQ_VLOG_ERR(VLOG_UMQ, "calloc for umq_trace data_record failed, trace_record_num %u\n",
                g_umq_trace_record_num);
            goto FREE_DATA_RECORD;
        }
    }

    (void)pthread_spin_init(&g_umq_trace_lock, PTHREAD_PROCESS_PRIVATE);
    return UMQ_SUCCESS;

FREE_DATA_RECORD:
    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; i++) {
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
    (void)pthread_spin_lock(&g_umq_trace_lock);
    if (g_umq_trace_ctx->timer != NULL) {
        urpc_timer_destroy(g_umq_trace_ctx->timer);
        g_umq_trace_ctx->timer = NULL;
    }
    (void)pthread_spin_unlock(&g_umq_trace_lock);
}

void umq_trace_uninit(void)
{
    if (g_umq_trace_ctx == NULL) {
        return;
    }

    (void)pthread_spin_lock(&g_umq_trace_lock);
    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; i++) {
        if (g_umq_trace_ctx->dp_thread_run_once[i] != NULL) {
            *g_umq_trace_ctx->dp_thread_run_once[i] = PTHREAD_ONCE_INIT;
        }
        if (g_umq_trace_ctx->trace_buf[i].data_record != NULL) {
            free(g_umq_trace_ctx->trace_buf[i].data_record);
            g_umq_trace_ctx->trace_buf[i].data_record = NULL;
        }
    }

    g_umq_trace_enable = false;
    free(g_umq_trace_ctx);
    g_umq_trace_ctx = NULL;
    (void)pthread_spin_unlock(&g_umq_trace_lock);
    (void)pthread_spin_destroy(&g_umq_trace_lock);
    g_umq_trace_output_limit = UMQ_TRACE_DEFAULT_RECORD_LIMIT;
    g_umq_trace_record_num = UMQ_TRACE_DEFAULT_RECORD_NUM;
}


static void umq_trace_closure(uint64_t idx)
{
    (void)pthread_spin_lock(&g_umq_trace_lock);
    if (g_umq_trace_ctx == NULL) {
        (void)pthread_spin_unlock(&g_umq_trace_lock);
        return;
    }
    g_umq_trace_ctx->trace_buf[idx].is_used = false;
    g_umq_trace_ctx->dp_thread_run_once[idx] = NULL;
    (void)pthread_spin_unlock(&g_umq_trace_lock);
}

static void umq_trace_record_clear(uint32_t idx)
{
    umq_trace_buf_t *cur_record = &g_umq_trace_ctx->trace_buf[idx];
    cur_record->record_cnt = 0;
    cur_record->previous_output_cnt = 0;
}

void umq_trace_alloc(void)
{
    uint32_t idx;
    (void)pthread_spin_lock(&g_umq_trace_lock);
    if (g_umq_trace_ctx == NULL) {
        (void)pthread_spin_unlock(&g_umq_trace_lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "trace ctx invalid\n");
        return;
    }

    for (idx = 0; idx < UMQ_PERF_REC_MAX_NUM; ++idx) {
        if (!g_umq_trace_ctx->trace_buf[idx].is_used) {
            break;
        }
    }
    if (idx == UMQ_PERF_REC_MAX_NUM) {
        (void)pthread_spin_unlock(&g_umq_trace_lock);
        UMQ_VLOG_WARN(VLOG_UMQ, "trace buf capacity %u were exhausted, alloc trace_rec failed\n",
            UMQ_PERF_REC_MAX_NUM);
        return;
    }

    umq_trace_record_clear(idx);
    g_umq_trace_ctx->trace_buf[idx].is_used = true;
    (void)pthread_spin_unlock(&g_umq_trace_lock);

    g_umq_trace_buf_index = idx;
    g_umq_trace_ctx->dp_thread_run_once[idx] = &g_umq_trace_thread_run_once;
    urpc_thread_closure_register(THREAD_CLOSURE_UMQ_DATA_PERF, idx, umq_trace_closure);
}

static void umq_dp_thread_run_once(void)
{
    umq_trace_alloc();
}

uint64_t umq_trace_start_timestamp_get(void)
{
    if (!g_umq_trace_enable) {
        return 0;
    }
    pthread_once(&g_umq_trace_thread_run_once, umq_dp_thread_run_once);
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
    if (g_umq_trace_ctx == NULL || g_umq_trace_buf_index >= UMQ_PERF_REC_MAX_NUM) {
        return NULL;
    }
    return &g_umq_trace_ctx->trace_buf[g_umq_trace_buf_index];
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
    g_umq_trace_record_index = (int32_t)idx;
}

void umq_trace_sub_record(umq_trace_type_t type, umq_urma_func_type_t func_type,
                          uint64_t start_time, uint64_t exec_time)
{
    if (!g_umq_trace_enable || g_umq_trace_record_index < 0) {
        return;
    }
    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL) {
        return;
    }
    uint32_t idx = (uint32_t)g_umq_trace_record_index;
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
    if (!g_umq_trace_enable || g_umq_trace_record_index < 0) {
        return;
    }

    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL) {
        return;
    }
    uint32_t idx = (uint32_t)g_umq_trace_record_index;
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
    if (!g_umq_trace_enable || g_umq_trace_record_index < 0) {
        return;
    }

    umq_trace_buf_t *cur_rec = umq_trace_buf_get();
    if (cur_rec == NULL || cur_rec->data_record == NULL) {
        return;
    }

    uint32_t idx = (uint32_t)g_umq_trace_record_index;
    if (idx >= g_umq_trace_record_num) {
        return;
    }
    umq_data_record_t *rec = &cur_rec->data_record[idx];
    if (rec->type == type && rec->end_time == 0) {
        rec->end_time = time;
    }
    g_umq_trace_record_index = -1;
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
    (void)pthread_spin_lock(&g_umq_trace_lock);
    if (cur_rec->data_record == NULL) {
        (void)pthread_spin_unlock(&g_umq_trace_lock);
        return;
    }
    for (uint32_t i = 0; i < new_records; i++) {
        uint32_t idx = (previous_output_cnt + i) % g_umq_trace_record_num;
        umq_data_record_t *rec = &cur_rec->data_record[idx];
        uint64_t umq_exec = (rec->end_time > rec->start_time) ? (rec->end_time - rec->start_time) : 0;

        /* header line: record index + type + meta */
        UMQ_VLOG_INFO(VLOG_UMQ, "#%u type=%s umq_id=%u umq_start=%lu umq_end=%lu umq_exec=%lu item_cnt=%u ts=%lu "
            "tag_ts=%lu\n", i, umq_trace_type_str(rec->type), rec->umq_id, rec->start_time, rec->end_time, umq_exec,
            rec->item_cnt, rec->timestamp, rec->tag_timestamp);
        /* item lines */
        for (uint32_t k = 0; k < rec->item_cnt; k++) {
            UMQ_VLOG_INFO(VLOG_UMQ, "  item[%u] umq_id=%u sub_umq_id=%u msn=%u size=%u\n", k, rec->umq_id,
                rec->items[k].sub_umq_id, rec->items[k].msn, rec->items[k].size);
        }
        /* sub_time lines */
        for (uint32_t j = 0; j < rec->sub_time_cnt; j++) {
            umq_sub_time_t *sub = &rec->sub_time[j];
            UMQ_VLOG_INFO(VLOG_UMQ, "  sub[%u] umq_id=%u func=%s start=%lu exec=%lu\n",
                          j, rec->umq_id, umq_urma_func_str(sub->func_type), sub->start_time, sub->exec_time);
        }
    }
    (void)pthread_spin_unlock(&g_umq_trace_lock);
    cur_rec->previous_output_cnt = record_cnt;
}

static void umq_trace_output(void *args __attribute__((unused)))
{
    if (!g_umq_trace_enable) {
        return;
    }
    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; ++i) {
        if (!g_umq_trace_ctx->trace_buf[i].is_used) {
            continue;
        }
        umq_trace_buf_t *cur_rec = &g_umq_trace_ctx->trace_buf[i];
        if (cur_rec->record_cnt == 0) {
            continue;
        }
        umq_trace_output_single(cur_rec, i);
    }
}

void umq_trace_remain_output(void)
{
    if (!g_umq_trace_enable) {
        return;
    }
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
