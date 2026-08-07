/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize str-conversion func for umq dfx api
 * Create: 2026-2-4
 */

/* Separated from umq_dfx_api.c so the string-conversion (to_str) functions
 * can be compiled by consumers that do NOT pull in umq_inner.h / perf.h /
 * transport_layer headers (e.g. the qbuf_pool_tool test driver). The original
 * umq_dfx_api.c retains the *_get() functions which require umq_t / dfx_tp_ops
 * and thus the heavy transport-layer dependency chain. */

#include <string.h>

#include "umq_dfx_api.h"
#include "umq_dfx_types.h"
#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_vlog.h"

/* Mirrors the macros in umq_dfx_api.c (each TU defines them independently;
 * they are not shared via a header to avoid pulling umq_inner.h here).
 * _120 variants use string-literal concatenation instead of backslash line
 * continuation for readability and to avoid fragile edits on width changes. */
#define UMQ_DFX_EQUALS "=================================================================================="
#define UMQ_DFX_UNDERLINE "----------------------------------------------------------------------------------"
static const char UMQ_DFX_EQUALS_120[] =
    "================================================================================"
    "========================================"; /* 80 + 40 = 120 */
static const char UMQ_DFX_UNDERLINE_120[] =
    "--------------------------------------------------------------------------------"
    "----------------------------------------"; /* 80 + 40 = 120 */
#define UMQ_DFX_QBUF_POOL_TYPE_NAME_MAX_LEN 20

#define UMQ_DFX_SNPRINTF_BUF(__buf, __max_buf_len, __offset, __format, ...)                                \
    do {                                                                                                   \
        int __ret;                                                                                         \
        if ((__max_buf_len) <= (__offset)) {                                                               \
            __ret = snprintf(NULL, 0, __format, ##__VA_ARGS__);                                            \
        } else {                                                                                           \
            __ret = snprintf((__buf) + (__offset), (__max_buf_len) - (__offset), __format, ##__VA_ARGS__); \
        }                                                                                                  \
        (__offset) += __ret;                                                                               \
    } while (0)

static const char *umq_qbuf_pool_type_name(umq_qbuf_pool_type_t type)
{
    static const char qbuf_pool_type[UMQ_QBUF_POOL_TYPE_MAX][UMQ_DFX_QBUF_POOL_TYPE_NAME_MAX_LEN] = {
        [UMQ_QBUF_POOL_TYPE_SMALL] = "Normal",      [UMQ_QBUF_POOL_TYPE_MEDIUM] = "Medium",
        [UMQ_QBUF_POOL_TYPE_BIG] = "Big",           [UMQ_QBUF_POOL_TYPE_HUGE] = "Huge",
        [UMQ_QBUF_POOL_TYPE_GIGANTIC] = "Gigantic", [UMQ_QBUF_POOL_TYPE_TINY] = "Tiny",
        [UMQ_QBUF_POOL_TYPE_IOBUF] = "IOBuf",
    };

    if (type >= UMQ_QBUF_POOL_TYPE_MAX) {
        return "Unknown";
    }
    return qbuf_pool_type[type];
}

/* Format a byte count as "<raw> (<human>)" where human uses K/M/G suffix with
 * 2-decimal precision. Examples: "209715200 (200.00M)", "0 (0B)". Used in
 * the Derived Metrics section so testers can scan both raw and readable
 * values in one column. */
static void umq_format_size_hr(uint64_t bytes, char *out, size_t out_size)
{
    if (bytes >= (1ULL << 30)) {
        snprintf(out, out_size, "%lu (%.2fG)", (unsigned long)bytes, (double)bytes / (1ULL << 30));
    } else if (bytes >= (1ULL << 20)) {
        snprintf(out, out_size, "%lu (%.2fM)", (unsigned long)bytes, (double)bytes / (1ULL << 20));
    } else if (bytes >= (1ULL << 10)) {
        snprintf(out, out_size, "%lu (%.2fK)", (unsigned long)bytes, (double)bytes / (1ULL << 10));
    } else {
        snprintf(out, out_size, "%lu (%luB)", (unsigned long)bytes, (unsigned long)bytes);
    }
}

int umq_qbuf_pool_stats_to_str(const umq_qbuf_pool_stats_t *qbuf_pool_stats, char *buf, int max_buf_len)
{
    if (qbuf_pool_stats == NULL || buf == NULL || max_buf_len <= 0 ||
        qbuf_pool_stats->num > UMQ_STATS_QBUF_POOL_TYPE_MAX ||
        qbuf_pool_stats->local_qbuf_pool_num > UMQ_LOCAL_QBUF_POOL_MAX_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    int str_size = 0;
    (void)memset(buf, 0, max_buf_len);

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Qbuf Pool Statistics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);

    // === Global Pool Config ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Global Pool Config");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-9s %-11s %-8s %-8s %-8s %-8s %-8s %-11s %-11s %-11s %-13s %-13s\n",
                         "Type", "Mode", "TotalSize", "TotalBlk", "BlkSize", "Headroom", "DataSize", "BufSize",
                         "UmqBufSize", "FreeBlk", "FreeSize", "NoBufFreeBlk", "NoBufFreeSize");
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "%-13s %-9s %-11lu %-8lu %-8u %-8u %-8u %-8u %-11u %-11lu %-11lu %-13lu %-13lu\n",
                             umq_qbuf_pool_type_name(info->type), info->mode == UMQ_BUF_SPLIT ? "SPLIT" : "COMBINE",
                             info->total_size, info->total_block_num, info->block_size, info->headroom_size,
                             info->data_size, info->buf_size, info->umq_buf_t_size,
                             info->available_mem.split.block_num_with_data, info->available_mem.split.size_with_data,
                             info->available_mem.split.block_num_without_data, info->available_mem.split.size_without_data);
    }

    // === Pool Config (multi-level size_class + expansion settings) ===
    // Exposes per-pool multi-level config fields previously hidden in g_qbuf_pool.
    // Only the SMALL pool uses multi-level; Huge/Tiny report sc_count=1.
    // Ordering: placed right after Global Pool Config so init-verification flow
    // is summary -> config -> per-sc state -> ... (config was previously buried
    // after the TLS sections).
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        const umq_qbuf_pool_config_t *cfg = &info->config;
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "                                  Pool Config [%s]\n",
                             umq_qbuf_pool_type_name(info->type));
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u %-30s %-12u\n", "size_class_count",
                             cfg->size_class_count, "size_class_step_multiplier", cfg->size_class_step_multiplier);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12u\n", "per_sc_block_count",
                             cfg->per_sc_block_count, "disable_scale_cap", (uint32_t)cfg->disable_scale_cap);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u %-30s %-12lu\n", "disable_malloc_escape",
                             (uint32_t)cfg->disable_malloc_escape, "expansion_size", cfg->expansion_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u %-30s %-12u\n", "expansion_threshold",
                             cfg->expansion_threshold, "batch_count", cfg->batch_count);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12lu\n", "expansion_mem_size_max",
                             cfg->expansion_mem_size_max, "exp_total_mem_pool_size", cfg->exp_total_mem_pool_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12lu\n", "tls_qbuf_pool_depth",
                             cfg->tls_qbuf_pool_depth, "tls_expand_qbuf_pool_depth", cfg->tls_expand_qbuf_pool_depth);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "exp_slot_used_count",
                             info->exp_slot_used_count);
    }

    // === Per-SizeClass State (per-sc raw values, NOT summed) ===
    // Per-sc breakdown of block_pool and exp_pool_with_data arrays. Replaces the
    // single-level view (where only block_sizes[0] was exposed and per-sc counts
    // were summed in umq_qbuf_pool_info_get's legacy path).
    // Columns: g_with -> g_w_data, g_without -> g_wo_data (clearer abbreviation).
    // Address columns replaced by relative offsets from pool base
    // (sc_info[0].data_region_start). The absolute pointers remain available in
    // the stats struct for callers that need them; the to_str view shows offsets
    // because they are smaller and more meaningful for layout verification.
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        if (info->sc_count == 0) {
            continue;
        }
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "                       Per-SizeClass State [%s, sc_count=%u]\n",
                             umq_qbuf_pool_type_name(info->type), info->sc_count);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "%-4s %-10s %-10s %-10s %-10s %-14s %-14s %-14s %-10s %-8s %-10s %-10s\n",
                             "sc", "blk_size", "glbl_free", "hdr_free", "exp_slots",
                             "exp_total_blk", "exp_total_exp", "exp_total_shrink", "glbl_total", "cap", "exp_free", "trig_expand");
        for (uint32_t sc = 0; sc < info->sc_count; sc++) {
            const umq_qbuf_sc_info_t *sci = &info->sc_info[sc];
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-4u %-10u %-10lu %-10lu %-10u %-14lu %-14lu %-14lu %-10lu %-8lu %-10lu %-10lu\n", sc,
                                 sci->blk_size, (unsigned long)sci->buf_cnt_with_data,
                                 (unsigned long)sci->buf_cnt_without_data, sci->exp_slots,
                                 (unsigned long)sci->exp_total_block_num, (unsigned long)sci->exp_total_expansion_count,
                                 (unsigned long)sci->exp_total_shrink_count, (unsigned long)sci->global_total,
                                 (unsigned long)sci->capacity, (unsigned long)sci->exp_free_blk, (unsigned long)sci->trigger_expand);
        }
    }

    // === Expansion Pool ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Expansion Pool");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-15s %-17s %-15s %-17s %-17s %-17s\n", "Type", "ExpandCnt",
                         "TotalBlk", "FreeBlk", "MemSize", "AccExpCnt", "AccShrinkCnt");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-15u %-17lu %-15lu %-17lu %-17lu %-17lu\n", "WithData",
                         qbuf_pool_stats->exp_pool_with_data.expansion_count,
                         qbuf_pool_stats->exp_pool_with_data.exp_total_block_num,
                         qbuf_pool_stats->exp_pool_with_data.exp_total_free_block_num,
                         qbuf_pool_stats->exp_pool_with_data.exp_total_mem_size,
                         qbuf_pool_stats->exp_pool_with_data.total_expansion_count,
                         qbuf_pool_stats->exp_pool_with_data.total_shrink_count);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-15u %-17lu %-15lu %-17lu %-17lu %-17lu\n", "WithoutData",
                         qbuf_pool_stats->exp_pool_without_data.expansion_count,
                         qbuf_pool_stats->exp_pool_without_data.exp_total_block_num,
                         qbuf_pool_stats->exp_pool_without_data.exp_total_free_block_num,
                         qbuf_pool_stats->exp_pool_without_data.exp_total_mem_size,
                         qbuf_pool_stats->exp_pool_without_data.total_expansion_count,
                         qbuf_pool_stats->exp_pool_without_data.total_shrink_count);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "partial_slot_count: WithData=%u WithoutData=%u\n",
                         qbuf_pool_stats->exp_pool_with_data.partial_slot_count,
                         qbuf_pool_stats->exp_pool_without_data.partial_slot_count);

    // Per-SC Expansion Slot Detail
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        if (info->sc_count == 0) continue;
        int has_exp = 0;
        for (uint32_t sc = 0; sc < info->sc_count; sc++) {
            if (info->sc_info[sc].exp_slots > 0 || info->sc_info[sc].exp_total_expansion_count > 0) {
                has_exp = 1;
                break;
            }
        }
        if (!has_exp) continue;
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "                       Per-SC Expansion Detail [%s]\n",
                             umq_qbuf_pool_type_name(info->type));
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-4s %-10s %-10s %-14s %-14s %-14s %-14s\n",
                             "sc", "blk_size", "exp_slots", "exp_total_blk", "exp_free_blk", "exp_expand_cnt", "exp_shrink_cnt");
        for (uint32_t sc = 0; sc < info->sc_count; sc++) {
            const umq_qbuf_sc_info_t *sci = &info->sc_info[sc];
            if (sci->exp_slots == 0 && sci->exp_total_expansion_count == 0) continue;
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-4u %-10u %-10u %-14lu %-14lu %-14lu %-14lu\n",
                                 sc, sci->blk_size, sci->exp_slots,
                                 (unsigned long)sci->exp_total_block_num,
                                 (unsigned long)sci->exp_free_blk,
                                 (unsigned long)sci->exp_total_expansion_count,
                                 (unsigned long)sci->exp_total_shrink_count);
        }
    }

    // === Per-Thread TLS Pool Stats (WithData) ===
    // Column rename: AccAlloc -> AccAllocCnt, AccFree -> AccFreeCnt (Cnt suffix
    // consistent with AccFetchCnt/AccReturnCnt).
    uint64_t total_tls_capacity_with_data = 0;
    uint64_t total_tls_buf_cnt_with_data = 0;
    uint64_t total_tls_capacity_without_data = 0;
    uint64_t total_tls_buf_cnt_without_data = 0;
    uint64_t total_tls_fetch_cnt_with_data = 0;
    uint64_t total_tls_fetch_buf_cnt_with_data = 0;
    uint64_t total_tls_fetch_cnt_without_data = 0;
    uint64_t total_tls_fetch_buf_cnt_without_data = 0;
    uint64_t total_tls_return_cnt_with_data = 0;
    uint64_t total_tls_return_buf_cnt_with_data = 0;
    uint64_t total_tls_return_cnt_without_data = 0;
    uint64_t total_tls_return_buf_cnt_without_data = 0;
    uint64_t total_alloc_cnt_with_data = 0;
    uint64_t total_alloc_cnt_without_data = 0;
    uint64_t total_free_cnt_with_data = 0;
    uint64_t total_free_cnt_without_data = 0;

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Per-Thread TLS Pool Stats (WithData)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-16s %-13s %-13s %-13s %-13s %-13s %-13s %-14s %-14s\n",
                         "Type", "TID", "CurCap", "CurBuf", "AccFetchCnt", "AccFetchBuf", "AccReturnCnt",
                         "AccReturnBuf", "AccAllocCnt", "AccFreeCnt");

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        total_tls_capacity_with_data += s->capacity_with_data;
        total_tls_buf_cnt_with_data += s->buf_cnt_with_data;
        total_tls_fetch_cnt_with_data += s->tls_fetch_cnt_with_data;
        total_tls_fetch_buf_cnt_with_data += s->tls_fetch_buf_cnt_with_data;
        total_tls_return_cnt_with_data += s->tls_return_cnt_with_data;
        total_tls_return_buf_cnt_with_data += s->tls_return_buf_cnt_with_data;
        total_alloc_cnt_with_data += s->alloc_cnt_with_data;
        total_free_cnt_with_data += s->free_cnt_with_data;
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                         "%-13s %-16s %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-14lu %-14lu\n", "total", "-",
                         total_tls_capacity_with_data, total_tls_buf_cnt_with_data, total_tls_fetch_cnt_with_data,
                         total_tls_fetch_buf_cnt_with_data, total_tls_return_cnt_with_data,
                         total_tls_return_buf_cnt_with_data, total_alloc_cnt_with_data, total_free_cnt_with_data);

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "%-13s %-16lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-14lu %-14lu\n",
                             umq_qbuf_pool_type_name(s->type), s->tid, s->capacity_with_data, s->buf_cnt_with_data,
                             s->tls_fetch_cnt_with_data, s->tls_fetch_buf_cnt_with_data, s->tls_return_cnt_with_data,
                             s->tls_return_buf_cnt_with_data, s->alloc_cnt_with_data, s->free_cnt_with_data);
    }

    // === Per-Thread TLS Pool Stats (WithoutData) ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Per-Thread TLS Pool Stats (WithoutData)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-16s %-13s %-13s %-13s %-13s %-13s %-13s %-14s %-14s\n",
                         "Type", "TID", "CurCap", "CurBuf", "AccFetchCnt", "AccFetchBuf", "AccReturnCnt",
                         "AccReturnBuf", "AccAllocCnt", "AccFreeCnt");

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        total_tls_capacity_without_data += s->capacity_without_data;
        total_tls_buf_cnt_without_data += s->buf_cnt_without_data;
        total_tls_fetch_cnt_without_data += s->tls_fetch_cnt_without_data;
        total_tls_fetch_buf_cnt_without_data += s->tls_fetch_buf_cnt_without_data;
        total_tls_return_cnt_without_data += s->tls_return_cnt_without_data;
        total_tls_return_buf_cnt_without_data += s->tls_return_buf_cnt_without_data;
        total_alloc_cnt_without_data += s->alloc_cnt_without_data;
        total_free_cnt_without_data += s->free_cnt_without_data;
    }
    UMQ_DFX_SNPRINTF_BUF(
        buf, max_buf_len, str_size, "%-13s %-16s %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-14lu %-14lu\n", "total",
        "-", total_tls_capacity_without_data, total_tls_buf_cnt_without_data, total_tls_fetch_cnt_without_data,
        total_tls_fetch_buf_cnt_without_data, total_tls_return_cnt_without_data, total_tls_return_buf_cnt_without_data,
        total_alloc_cnt_without_data, total_free_cnt_without_data);

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        UMQ_DFX_SNPRINTF_BUF(
            buf, max_buf_len, str_size, "%-13s %-16lu %-13lu %-13lu %-13lu %-13lu %-13lu %-13lu %-14lu %-14lu\n",
            umq_qbuf_pool_type_name(s->type), s->tid, s->capacity_without_data, s->buf_cnt_without_data,
            s->tls_fetch_cnt_without_data, s->tls_fetch_buf_cnt_without_data, s->tls_return_cnt_without_data,
            s->tls_return_buf_cnt_without_data, s->alloc_cnt_without_data, s->free_cnt_without_data);
    }

    // === Per-Thread Per-SC TLS (with_data breakdown) ===
    // Per-thread per-size_class TLS bytes/buf_cnt. The Per-Thread TLS Pool Stats
    // (WithData) section above reports per-thread SUM across sc levels; this
    // section exposes the per-sc breakdown (matches the multi-level model).
    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        if (s->sc_count == 0) {
            continue; /* skip pools that did not fill per-sc arrays */
        }
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "            Per-Thread Per-SC TLS (WithData) [%s, tid=%lu, sc_count=%u]\n",
                             umq_qbuf_pool_type_name(s->type), (unsigned long)s->tid, s->sc_count);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-4s %-18s %-18s\n", "sc", "tls_buf_cnt", "tls_cap_cnt");
        for (uint32_t sc = 0; sc < s->sc_count; sc++) {
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-4u %-18lu %-18lu\n", sc,
                                 (unsigned long)s->sc_buf_cnt_with_data[sc],
                                 (unsigned long)s->sc_capacity_with_data[sc]);
        }
    }

    // === Derived Metrics ===
    // Pulls raw counts into tester-facing indicators plus human-readable sizes:
    //   utilization   = (total - free) / total * 100  -- pool pressure
    //   tls_locality  = tls_buf / (tls_buf + global_buf) * 100  -- TLS cache hit
    //   alloc_minus_free = AccAlloc - AccFree  -- leak sanity (should equal
    //   tls cur_buf; printed value 0 at init is the expected clean state)
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Derived Metrics");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-10s %-26s %-26s %-13s %-13s %-18s\n", "Pool", "TotalSize",
                         "FreeSize", "Utilization", "TlsLocality", "AllocMinusFree");
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        char total_hr[32];
        char free_hr[32];
        char util_str[16];
        char tls_loc_str[16];
        umq_format_size_hr(info->total_size, total_hr, sizeof(total_hr));
        umq_format_size_hr(info->available_mem.split.size_with_data, free_hr, sizeof(free_hr));
        double util = (info->total_block_num == 0) ?
                          0.0 :
                          (double)(info->total_block_num - info->available_mem.split.block_num_with_data) /
                              (double)info->total_block_num * 100.0;
        uint64_t tls_buf_sum = total_tls_buf_cnt_with_data;
        uint64_t global_buf = info->available_mem.split.block_num_with_data;
        uint64_t denom = tls_buf_sum + global_buf;
        double tls_loc = (denom == 0) ? 0.0 : (double)tls_buf_sum / (double)denom * 100.0;
        int64_t alloc_minus_free = (int64_t)total_alloc_cnt_with_data - (int64_t)total_free_cnt_with_data;
        /* Pre-format "X.XX%" so the % sign is inside the aligned field,
         * not appended after the padding (which left it stranded visually). */
        snprintf(util_str, sizeof(util_str), "%.2f%%", util);
        snprintf(tls_loc_str, sizeof(tls_loc_str), "%.2f%%", tls_loc);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-10s %-26s %-26s %-13s %-13s %-18ld\n",
                             umq_qbuf_pool_type_name(info->type), total_hr, free_hr, util_str, tls_loc_str,
                             (long)alloc_minus_free);
    }

    // === Escape (properly framed section, consistent with other tables) ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", "                                             Escape");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %lu\n", "escape_buf_cnt",
                         (unsigned long)qbuf_pool_stats->escape_buf_cnt);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);

    return str_size;
}
