/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perf
 * Create: 2025-10-29
 */

#include <pthread.h>
#include <stdarg.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "urpc_thread_closure.h"
#include "urpc_util.h"
#include "urpc_bitmap.h"
#include "umq_perf_hdr.h"
#include "umq_thread_local.h"
#include "perf.h"

#define UMQ_PERF_IO_DIRECTION_ALL_OFFSET     (0)
#define UMQ_PERF_IO_DIRECTION_TX_OFFSET      (1)
#define UMQ_PERF_IO_DIRECTION_RX_OFFSET      (2)

#define UMQ_PERF_INTERRUPT_DIRECTION_TX_OFFSET      (0)
#define UMQ_PERF_INTERRUPT_DIRECTION_RX_OFFSET      (1)

typedef struct umq_perf_record {
    struct {
        umq_perf_record_type_t type; // types of probe points supported by perf probe
        uint64_t accumulation; // total latency
        uint64_t min; // min latency
        uint64_t max; // max latency
        uint64_t cnt; // statistical count
        umq_perf_hdr_t *hdr; // hdr histogram for quantile estimation
    } type_record[UMQ_PERF_RECORD_TYPE_MAX]; // statistical results list for each type of probe point
    volatile bool inited;
} umq_perf_record_t;

typedef struct umq_perf_record_ctx {
    umq_perf_record_t perf_record_table[UMQ_THREAD_ID_MAX];
} umq_perf_record_ctx_t;

/* hardcoded quantile percentages: p50, p90, p99, p9999 */
static const double g_umq_perf_quantile[UMQ_PERF_QUANTILE_CNT] = {
    50.0,   /* p50  */
    90.0,   /* p90  */
    99.0,   /* p99  */
    99.99   /* p9999 */
};
static bool g_umq_perf_record_enable = false;
static umq_perf_record_ctx_t *g_umq_perf_record_ctx;

static inline uint64_t umq_perf_hdr_max_cycles_get(void)
{
    /* convert default 1000ms to cycles via CPU frequency */
    return (uint64_t)UMQ_PERF_HDR_DEFAULT_MAX_MS * urpc_get_cpu_hz() / MS_PER_SEC;
}

static void umq_perf_destroy_all_hdrs(uint32_t idx)
{
    umq_perf_record_t *rec = &g_umq_perf_record_ctx->perf_record_table[idx];
    for (int type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; ++type) {
        if (rec->type_record[type].hdr != NULL) {
            umq_perf_hdr_destroy(rec->type_record[type].hdr);
            rec->type_record[type].hdr = NULL;
        }
        rec->inited = false;
    }
}

static int umq_perf_type_record_init(uint32_t idx)
{
    int type;
    umq_perf_record_t *rec = &g_umq_perf_record_ctx->perf_record_table[idx];
    for (type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; ++type) {
        rec->type_record[type].accumulation = 0;
        rec->type_record[type].min = UINT64_MAX;
        rec->type_record[type].max = 0;
        rec->type_record[type].cnt = 0;
        if (rec->type_record[type].hdr != NULL) {
            umq_perf_hdr_reset(rec->type_record[type].hdr);
        } else {
            rec->type_record[type].hdr = umq_perf_hdr_create(umq_perf_hdr_max_cycles_get());
            if (rec->type_record[type].hdr == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq_perf_hdr_create failed, quantile data of type %d missing\n", type);
                goto ERROR;
            }
        }

        rec->inited = true;
    }

    return UMQ_SUCCESS;

ERROR:
    umq_perf_destroy_all_hdrs(idx);
    return -UMQ_ERR_ENOMEM;
}

int umq_perf_init(void)
{
    int ret = UMQ_SUCCESS;
    if (g_umq_perf_record_ctx != NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq perf has been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    g_umq_perf_record_ctx = (umq_perf_record_ctx_t *)calloc(1, sizeof(umq_perf_record_ctx_t));
    if (g_umq_perf_record_ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc for umq_perf_record failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    // initialize UMQ_THREAD_ID_RANGE_DEFAULT perf_hdrs is enough in most cases,
    // other perf_hdr initialized when necessary
    for (uint32_t i = 0; i < UMQ_THREAD_ID_RANGE_DEFAULT; i++) {
        ret = umq_perf_type_record_init(i);
        if (ret != UMQ_SUCCESS) {
            for (uint32_t j = 0; j < i; j++) {
                umq_perf_destroy_all_hdrs(j);
            }
            goto FREE_CTX;
        }
    }

    return UMQ_SUCCESS;

FREE_CTX:
    free(g_umq_perf_record_ctx);
    g_umq_perf_record_ctx = NULL;

    return ret;
}

void umq_perf_uninit(void)
{
    if (g_umq_perf_record_ctx == NULL) {
        return;
    }

    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; i++) {
        umq_perf_destroy_all_hdrs(i);
    }

    g_umq_perf_record_enable = false;
    free(g_umq_perf_record_ctx);
    g_umq_perf_record_ctx = NULL;
}

static void umq_clear_perf_record_item(uint32_t record_idx)
{
    if (g_umq_perf_record_ctx == NULL) {
        return;
    }

    umq_perf_record_t *cur_record = &g_umq_perf_record_ctx->perf_record_table[record_idx];
    for (int type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; ++type) {
        cur_record->type_record[type].accumulation = 0;
        cur_record->type_record[type].min = UINT64_MAX;
        cur_record->type_record[type].max = 0;
        cur_record->type_record[type].cnt = 0;
        if (cur_record->type_record[type].hdr != NULL) {
            umq_perf_hdr_reset(cur_record->type_record[type].hdr);
        }
    }
    cur_record->inited = false;
}

static void umq_perf_record_closure(uint64_t idx)
{
    umq_clear_perf_record_item(idx);
}

uint64_t umq_perf_get_start_timestamp(void)
{
    if (!g_umq_perf_record_enable) {
        return 0;
    }

    uint32_t thead_id = umq_thread_id_get();
    if (thead_id < UMQ_THREAD_ID_MAX && !g_umq_perf_record_ctx->perf_record_table[thead_id].inited) {
        umq_perf_type_record_init(thead_id);
        urpc_thread_closure_register(THREAD_CLOSURE_UMQ_PERF, thead_id, umq_perf_record_closure);
    }

    return urpc_get_cpu_cycles();
}

static umq_perf_hdr_t *umq_perf_ensure_hdr(umq_perf_record_t *rec, umq_perf_record_type_t type)
{
    umq_perf_hdr_t *h = rec->type_record[type].hdr;
    if (h != NULL) {
        return h;
    }
    h = umq_perf_hdr_create(umq_perf_hdr_max_cycles_get());
    if (h == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq_perf_hdr_create failed, quantile data of type %d missing\n", type);
        return NULL;
    }
    rec->type_record[type].hdr = h;
    return h;
}

static void umq_perf_fill_perf_record(umq_perf_record_type_t type, uint64_t start)
{
    uint64_t delta = urpc_get_cpu_cycles() - start;
    uint32_t thead_id = umq_thread_id_get();
    if (thead_id >= UMQ_THREAD_ID_MAX) {
        return;
    }

    umq_perf_record_t *cur_rec = &g_umq_perf_record_ctx->perf_record_table[thead_id];
    cur_rec->type_record[type].accumulation += delta;
    (delta < cur_rec->type_record[type].min) ? cur_rec->type_record[type].min = delta : 0;
    (delta > cur_rec->type_record[type].max) ? cur_rec->type_record[type].max = delta : 0;
    ++cur_rec->type_record[type].cnt;

    umq_perf_hdr_t *h = umq_perf_ensure_hdr(cur_rec, type);
    if (h != NULL) {
        umq_perf_hdr_record(h, delta);
    }
}

void umq_perf_record_write(umq_perf_record_type_t type, uint64_t start)
{
    if (!g_umq_perf_record_enable || start == 0) {
        return;
    }
    umq_perf_fill_perf_record(type, start);
}

void umq_perf_record_write_with_direction(umq_perf_record_type_t type, uint64_t start, umq_io_direction_t direction)
{
    if (!g_umq_perf_record_enable || start == 0 || direction >= UMQ_IO_MAX) {
        return;
    }

    static const umq_perf_record_type_t perf_record_type_map[UMQ_IO_MAX] = {
        [UMQ_IO_ALL] = UMQ_PERF_IO_DIRECTION_ALL_OFFSET,
        [UMQ_IO_TX]  = UMQ_PERF_IO_DIRECTION_TX_OFFSET,
        [UMQ_IO_RX]  = UMQ_PERF_IO_DIRECTION_RX_OFFSET,
    };
    umq_perf_fill_perf_record(type + perf_record_type_map[direction], start);
}

void umq_perf_record_write_interrupt_with_direction(
    umq_perf_record_type_t type, uint64_t start, umq_io_direction_t direction)
{
    if (!g_umq_perf_record_enable || start == 0 || direction >= UMQ_IO_MAX || direction == UMQ_IO_ALL) {
        return;
    }

    static const umq_perf_record_type_t perf_record_type_map[UMQ_IO_MAX] = {
        [UMQ_IO_TX]  = UMQ_PERF_INTERRUPT_DIRECTION_TX_OFFSET,
        [UMQ_IO_RX]  = UMQ_PERF_INTERRUPT_DIRECTION_RX_OFFSET,
    };
    umq_perf_fill_perf_record(type + perf_record_type_map[direction], start);
}

int umq_perf_start(void)
{
    // initialize perf at first start
    if (g_umq_perf_record_ctx == NULL) {
        int ret = umq_perf_init();
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq perf init failed\n");
            return ret;
        }
    }

    // IO perf record has been started, user must stop it first before restart
    if (g_umq_perf_record_enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    g_umq_perf_record_enable = true;
    return UMQ_SUCCESS;
}

int umq_perf_reset(umq_perf_stats_cfg_t *perf_stats_cfg)
{
    // IO perf record has been started, user must stop it first before restart
    if (g_umq_perf_record_ctx == NULL || perf_stats_cfg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; ++i) {
        umq_clear_perf_record_item(i);
    }

    return UMQ_SUCCESS;
}

int umq_perf_stop(void)
{
    if (g_umq_perf_record_ctx == NULL || !g_umq_perf_record_enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    g_umq_perf_record_enable = false;
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

static ALWAYS_INLINE void umq_perf_record_add(umq_perf_record_t *total_perf_record, umq_perf_record_t *perf_record)
{
    for (uint32_t i = 0; i < UMQ_PERF_RECORD_TYPE_MAX; i++) {
        if (perf_record->type_record[i].cnt == 0) {
            continue;
        }
        total_perf_record->type_record[i].accumulation += perf_record->type_record[i].accumulation;
        total_perf_record->type_record[i].min =
            (total_perf_record->type_record[i].min != 0 &&
            total_perf_record->type_record[i].min < perf_record->type_record[i].min) ?
            total_perf_record->type_record[i].min : perf_record->type_record[i].min;
        total_perf_record->type_record[i].max =
            total_perf_record->type_record[i].max > perf_record->type_record[i].max ?
            total_perf_record->type_record[i].max : perf_record->type_record[i].max;
        total_perf_record->type_record[i].cnt += perf_record->type_record[i].cnt;
        if (perf_record->type_record[i].hdr != NULL) {
            if (total_perf_record->type_record[i].hdr == NULL) {
                total_perf_record->type_record[i].hdr = umq_perf_hdr_create(umq_perf_hdr_max_cycles_get());
            }
            if (total_perf_record->type_record[i].hdr == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                    "umq_perf_hdr_create failed, quantile data of type %u missing\n", i);
                continue;
            }
            umq_perf_hdr_merge(total_perf_record->type_record[i].hdr, perf_record->type_record[i].hdr);
        }
    }
}

int umq_perf_info_get(umq_perf_stats_t *perf_info)
{
    if (g_umq_perf_record_ctx == NULL || perf_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_perf_record_t total_perf_record = {0};
    for (uint32_t i = 0; i < UMQ_PERF_REC_MAX_NUM; ++i) {
        if (!g_umq_perf_record_ctx->perf_record_table[i].inited) {
            continue;
        }
        umq_perf_record_add(&total_perf_record, &g_umq_perf_record_ctx->perf_record_table[i]);
    }
    umq_perf_convert_cycles_to_ns(&total_perf_record);

    for (uint32_t i = 0; i < UMQ_PERF_RECORD_TYPE_MAX; i++) {
        uint64_t cnt = total_perf_record.type_record[i].cnt;
        perf_info->type_record[i].type = i;
        perf_info->type_record[i].sample_num = cnt;
        perf_info->type_record[i].average = cnt != 0 ?
            (total_perf_record.type_record[i].accumulation / cnt) : 0;
        perf_info->type_record[i].maxinum = total_perf_record.type_record[i].max;
        perf_info->type_record[i].mininum = total_perf_record.type_record[i].min;

        // compute hardcoded quantiles: p50, p90, p99, p9999
        umq_perf_hdr_t *h = total_perf_record.type_record[i].hdr;
        for (uint32_t j = 0; j < UMQ_PERF_QUANTILE_CNT; j++) {
            if (cnt > 0 && h != NULL) {
                perf_info->type_record[i].quantile[j] = cpu_cycles_to_ns(
                    umq_perf_hdr_value_at_quantile(h, g_umq_perf_quantile[j]));
            } else {
                perf_info->type_record[i].quantile[j] = 0;
            }
        }

        if (h != NULL) {
            umq_perf_hdr_destroy(h);
        }
    }

    return 0;
}
