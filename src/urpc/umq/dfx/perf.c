/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perf
 * Create: 2025-10-29
 */

#include <pthread.h>

#include "umq_errno.h"
#include "urpc_util.h"
#include "umq_vlog.h"
#include "perf.h"

#define UMQ_PERF_MAX_THRESH_NS         (100000u)
#define UMQ_PERF_REC_MAX_NUM           (64u)

#define UMQ_PERF_IO_DIRECTION_ALL_OFFSET     (0)
#define UMQ_PERF_IO_DIRECTION_TX_OFFSET      (1)
#define UMQ_PERF_IO_DIRECTION_RX_OFFSET      (2)

static __thread uint32_t g_perf_record_index = -1;
static __thread pthread_once_t g_dp_thread_run_once = PTHREAD_ONCE_INIT;
static bool g_umq_perf_record_enable = false;

typedef struct umq_perf_record_ctx {
    umq_perf_record_t perf_record_table[UMQ_PERF_REC_MAX_NUM];
    uint64_t perf_quantile_thresh[UMQ_PERF_QUANTILE_MAX_NUM + 1];
    umq_perf_infos_t *perf_record_msg;
    pthread_mutex_t lock;
} umq_perf_record_ctx_t;

static umq_perf_record_ctx_t *g_umq_perf_record_ctx;

int umq_perf_init(void)
{
    if (g_umq_perf_record_ctx != NULL) {
        UMQ_VLOG_ERR("umq perf has been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    g_umq_perf_record_ctx = (umq_perf_record_ctx_t *)calloc(1, sizeof(umq_perf_record_ctx_t));
    if (g_umq_perf_record_ctx == NULL) {
        UMQ_VLOG_ERR("malloc for umq_perf_record failed\n");
        return -UMQ_ERR_ENOMEM;
    }
    pthread_mutex_init(&g_umq_perf_record_ctx->lock, NULL);
    return UMQ_SUCCESS;
}

void umq_perf_uninit(void)
{
    if (g_umq_perf_record_ctx == NULL) {
        UMQ_VLOG_ERR("umq perf has not been inited\n");
        return;
    }
    g_umq_perf_record_enable = false;
    (void)pthread_mutex_lock(&g_umq_perf_record_ctx->lock);
    if (g_umq_perf_record_ctx->perf_record_msg != NULL) {
        free(g_umq_perf_record_ctx->perf_record_msg);
        g_umq_perf_record_ctx->perf_record_msg = NULL;
    }
    (void)pthread_mutex_unlock(&g_umq_perf_record_ctx->lock);
    pthread_mutex_destroy(&g_umq_perf_record_ctx->lock);
    free(g_umq_perf_record_ctx);
    g_umq_perf_record_ctx = NULL;
}

static void umq_clear_perf_record_item(uint32_t record_idx)
{
    umq_perf_record_t *cur_record = &g_umq_perf_record_ctx->perf_record_table[record_idx];
    for (int type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; ++type) {
        cur_record->type_record[type].accumulation = 0;
        cur_record->type_record[type].min = UINT64_MAX;
        cur_record->type_record[type].max = 0;
        cur_record->type_record[type].cnt = 0;
        (void)memset(cur_record->type_record[type].bucket, 0, sizeof(cur_record->type_record[type].bucket));
    }
}

void umq_perf_record_alloc(void)
{
    uint32_t idx;
    (void)pthread_mutex_lock(&g_umq_perf_record_ctx->lock);
    for (idx = 0; idx < UMQ_PERF_REC_MAX_NUM; ++idx) {
        if (!g_umq_perf_record_ctx->perf_record_table[idx].is_used) {
            break;
        }
    }
    if (idx == UMQ_PERF_REC_MAX_NUM) {
        (void)pthread_mutex_unlock(&g_umq_perf_record_ctx->lock);
        UMQ_VLOG_WARN("perf_rec table capacity %u were exhausted, alloc perf_rec failed\n", UMQ_PERF_REC_MAX_NUM);
        return;
    }

    umq_clear_perf_record_item(idx);
    g_umq_perf_record_ctx->perf_record_table[idx].is_used = true;
    (void)pthread_mutex_unlock(&g_umq_perf_record_ctx->lock);

    g_perf_record_index = idx;
}

static void umq_dp_thread_run_once(void)
{
    umq_perf_record_alloc();
}

uint64_t umq_perf_get_start_timestamp(void)
{
    if (!g_umq_perf_record_enable) {
        return 0;
    }
    pthread_once(&g_dp_thread_run_once, umq_dp_thread_run_once);
    return urpc_get_cpu_cycles();
}

static inline uint32_t find_perf_record_bucket(uint64_t delta)
{
    if (g_umq_perf_record_ctx->perf_quantile_thresh[0] == 0) {
        // quantile thresh is not set, don't fill the bucket
        return UINT32_MAX;
    }
    uint32_t idx;
    for (idx = 0; idx < UMQ_PERF_QUANTILE_MAX_NUM; ++idx) {
        if (delta <= g_umq_perf_record_ctx->perf_quantile_thresh[idx]) {
            break;
        }
    }
    return idx;
}

static inline void umq_perf_fill_perf_record(umq_perf_record_type_t type, uint64_t start)
{
    uint64_t delta = urpc_get_cpu_cycles() - start;
    umq_perf_record_t *cur_rec = &g_umq_perf_record_ctx->perf_record_table[g_perf_record_index];
    cur_rec->type_record[type].accumulation += delta;
    (delta < cur_rec->type_record[type].min) ? cur_rec->type_record[type].min = delta : 0;
    (delta > cur_rec->type_record[type].max) ? cur_rec->type_record[type].max = delta : 0;
    uint32_t bucket_idx = find_perf_record_bucket(delta);
    if (bucket_idx != UINT32_MAX) {
        ++cur_rec->type_record[type].bucket[bucket_idx];
    }
    ++cur_rec->type_record[type].cnt;
}

void umq_perf_record_write(umq_perf_record_type_t type, uint64_t start)
{
    if (!g_umq_perf_record_enable || start == 0 || g_perf_record_index >= UMQ_PERF_REC_MAX_NUM) {
        return;
    }
    umq_perf_fill_perf_record(type, start);
}

void umq_perf_record_write_with_direction(umq_perf_record_type_t type, uint64_t start, umq_io_direction_t direction)
{
    if (!g_umq_perf_record_enable || start == 0 || g_perf_record_index >= UMQ_PERF_REC_MAX_NUM) {
        return;
    }

    static const umq_perf_record_type_t perf_record_type_map[UMQ_IO_MAX] = {
        [UMQ_IO_ALL] = UMQ_PERF_IO_DIRECTION_ALL_OFFSET,
        [UMQ_IO_TX]  = UMQ_PERF_IO_DIRECTION_TX_OFFSET,
        [UMQ_IO_RX]  = UMQ_PERF_IO_DIRECTION_RX_OFFSET,
    };
    umq_perf_fill_perf_record(type + perf_record_type_map[direction], start);
}

int umq_perf_start(uint64_t *thresh_array, uint32_t thresh_num)
{
    // IO perf record has been started, user must stop it first before restart
    if (g_umq_perf_record_ctx == NULL || g_umq_perf_record_enable || thresh_array == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; ++i) {
        umq_clear_perf_record_item(i);
    }

    if (thresh_num > UMQ_PERF_QUANTILE_MAX_NUM) {
        UMQ_VLOG_ERR(
            "configured thresh num %u exceeds the max thresh_num %u, only the minimum %d of them are used\n",
            thresh_num, UMQ_PERF_QUANTILE_MAX_NUM, UMQ_PERF_QUANTILE_MAX_NUM);
        return -UMQ_ERR_EAGAIN;
    }

    // set quantile bucket
    uint32_t idx = 0;
    for (uint32_t i = 0; i < thresh_num; ++i) {
        if (thresh_array[i] > UMQ_PERF_MAX_THRESH_NS) {
            continue;
        }
        if (idx == 0 || thresh_array[i] > g_umq_perf_record_ctx->perf_quantile_thresh[idx - 1]) {
            g_umq_perf_record_ctx->perf_quantile_thresh[idx++] = thresh_array[i] * urpc_get_cpu_hz() / NS_PER_SEC;
        }
    }

    g_umq_perf_record_enable = true;
    UMQ_VLOG_INFO("IO perf record started successfully, set %u thresh\n", idx);
    return UMQ_SUCCESS;
}

int umq_perf_stop(void)
{
    if (g_umq_perf_record_ctx == NULL || !g_umq_perf_record_enable) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    g_umq_perf_record_enable = false;
    UMQ_VLOG_INFO("IO perf record stopped\n");
    return UMQ_SUCCESS;
}

int umq_perf_clear(void)
{
    if (g_umq_perf_record_enable) {
        UMQ_VLOG_ERR("IO perf has been started\n");
        return -UMQ_ERR_EEXIST;
    }

    (void)pthread_mutex_lock(&g_umq_perf_record_ctx->lock);
    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; ++i) {
        umq_clear_perf_record_item(i);
    }

    (void)memset(g_umq_perf_record_ctx->perf_quantile_thresh, 0, UMQ_PERF_QUANTILE_MAX_NUM * sizeof(uint64_t));
    if (g_umq_perf_record_ctx->perf_record_msg != NULL) {
        free(g_umq_perf_record_ctx->perf_record_msg);
        g_umq_perf_record_ctx->perf_record_msg = NULL;
    }
    (void)pthread_mutex_unlock(&g_umq_perf_record_ctx->lock);
    UMQ_VLOG_INFO("IO perf record clear\n");
    return UMQ_SUCCESS;
}

static inline uint64_t cpu_cycles_to_ns(uint64_t cycles)
{
    // The CPU frequency is around X GHz, so dividing by CPU hz will solve the overflow issue.
    if (cycles != 0 && UINT64_MAX / cycles <= NS_PER_SEC) {
        return cycles / urpc_get_cpu_hz() * NS_PER_SEC;
    } else {
        return cycles * NS_PER_SEC / urpc_get_cpu_hz();
    }
}

static inline void umq_perf_convert_cycles_to_ns(umq_perf_record_t *perf_rec)
{
    for (int type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; ++type) {
        perf_rec->type_record[type].accumulation = cpu_cycles_to_ns(perf_rec->type_record[type].accumulation);
        // min default value is inited as UINT64_MAX, we output it as 0 for readability
        perf_rec->type_record[type].min =
            perf_rec->type_record[type].min == UINT64_MAX ? 0 : cpu_cycles_to_ns(perf_rec->type_record[type].min);
        perf_rec->type_record[type].max = cpu_cycles_to_ns(perf_rec->type_record[type].max);
    }
}

int umq_perf_info_get(umq_perf_infos_t **perf_info)
{
    if (g_umq_perf_record_ctx == NULL || g_umq_perf_record_enable) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    (void)pthread_mutex_lock(&g_umq_perf_record_ctx->lock);
    if (g_umq_perf_record_ctx->perf_record_msg == NULL) {
        g_umq_perf_record_ctx->perf_record_msg =
            (umq_perf_infos_t *)malloc(sizeof(umq_perf_record_t) * UMQ_PERF_REC_MAX_NUM + sizeof(uint32_t));
        if (g_umq_perf_record_ctx->perf_record_msg == NULL) {
            UMQ_VLOG_ERR("malloc for perf_record_msg failed\n");
            return UMQ_FAIL;
        }
    }

    g_umq_perf_record_ctx->perf_record_msg->perf_record_num = 0;
    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; ++i) {
        if (!g_umq_perf_record_ctx->perf_record_table[i].is_used) {
            continue;
        }
        g_umq_perf_record_ctx->perf_record_msg->perf_record[i] = &g_umq_perf_record_ctx->perf_record_table[i];
        g_umq_perf_record_ctx->perf_record_msg->perf_record_num++;
        umq_perf_convert_cycles_to_ns(g_umq_perf_record_ctx->perf_record_msg->perf_record[i]);
    }

    *perf_info = g_umq_perf_record_ctx->perf_record_msg;
    UMQ_VLOG_INFO("Perf record stopped\n");
    (void)pthread_mutex_unlock(&g_umq_perf_record_ctx->lock);
    return 0;
}
