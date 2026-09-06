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
#include "umq_rx_qbuf_pool.h"
#include "umq_vlog.h"

/* Mirrors the macros in umq_dfx_api.c (each TU defines them independently;
 * they are not shared via a header to avoid pulling umq_inner.h here).
 * _120 variants use string-literal concatenation instead of backslash line
 * continuation for readability and to avoid fragile edits on width changes. */
#define UMQ_DFX_EQUALS "=================================================================================="
#define UMQ_DFX_UNDERLINE "----------------------------------------------------------------------------------"
#define QBUF_SIZING_ALIGN_BLOCKS 32
#define QBUF_SIZING_SCALING_NUMER 10
#define QBUF_SIZING_SCALING_DENOM 7
#define QBUF_SIZING_TLS_RATIO_NUMER 2
#define QBUF_SIZING_TLS_RATIO_DENOM 3
#define QBUF_ALIGN_UP(val, align) (((val) + (align) - 1) / (align) * (align))
static const char UMQ_DFX_EQUALS_120[] =
    "================================================================================"
    "========================================"; /* 80 + 40 = 120 */
static const char UMQ_DFX_UNDERLINE_120[] =
    "--------------------------------------------------------------------------------"
    "----------------------------------------"; /* 80 + 40 = 120 */

/* Size-class display names shared across all per-SC DFX rows (file-level to
 * avoid local-variable shadowing across the three emitters below). */
static const char *umq_dfx_sc_names[] = {"Small", "Medium", "Large", "Huge", "Gigantic"};

/* Bytes-per-MB divisor for human-readable size strings (e.g. "%lu(%.1fMB)"). */
#define UMQ_DFX_BYTES_PER_MB (1024.0 * 1024.0)

#define UMQ_DFX_QBUF_POOL_TYPE_NAME_MAX_LEN 20
#define UMQ_DFX_LABEL_BUF_SIZE 32

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

    // === Global Pool Config (merged with Per-SizeClass) ===
    // Multi-level pools (Normal) are expanded per-SC (Small/Medium/...) instead of a
    // single misleading row; single-level pools (Tiny) stay one row. RX pool and
    // without-data are appended as their own rows under the Small pool that owns
    // them. A trailing Total row sums every row's TotalSize for a quick memory
    // footprint check.
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Global Pool Config");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-6s %-21s %-8s %-8s %-8s %-8s %-8s %-11s %-11s %-11s\n",
                         "Type", "Mode", "TotalSize", "TotalBlk", "BlkSize", "Headroom", "DataSize", "BufSize",
                         "UmqBufSize", "FreeBlk", "FreeSize");
    uint64_t grand_total_size = 0;
    const umq_qbuf_pool_info_t *small_info = NULL; /* remembered for without-data row */
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        const char *mode_str = info->mode == UMQ_BUF_SPLIT ? "SPLIT" : "COMBINE";
        if (info->sc_count > 1) {
            small_info = info;
            /* Multi-level: expand each SC as its own row (Small/Medium/...).
             * Per-SC TotalSize = data_region size, TotalBlk = global_total, BlkSize
             * = sc blk_size; Headroom/UmqBufSize are pool-level (shared across SCs);
             * DataSize/BufSize are per-SC (depend on blk_size[sc] + mode). */
            for (uint32_t sc = 0; sc < info->sc_count; sc++) {
                const umq_qbuf_sc_info_t *sci = &info->sc_info[sc];
                /* TotalBlk/TotalSize = initial reserved only (per_sc_block_counts,
                 * set once at init, NOT including expansion); FreeBlk = current free.
                 * TotalSize counts each block's umq_buf_t header (128B) on top of data. */
                uint64_t sc_total_size = (uint64_t)sci->init_block_count * (sci->blk_size + info->umq_buf_t_size);
                uint64_t sc_free_size = (uint64_t)sci->buf_cnt_with_data * sci->blk_size;
                /* DataSize/BufSize vary per-SC: SPLIT -> data=blk_size, buf=blk_size+hdr;
                 * COMBINE -> data=blk_size-hdr, buf=blk_size. The pool-level
                 * info->data_size/buf_size only holds SC0's values and must not be
                 * reused for SC>=1 (would show Small's 4096/4224 on Medium's row). */
                uint32_t sc_data_size;
                uint32_t sc_buf_size;
                if (info->mode == UMQ_BUF_SPLIT) {
                    sc_data_size = sci->blk_size;
                    sc_buf_size = sci->blk_size + info->umq_buf_t_size;
                } else {
                    sc_data_size = sci->blk_size - info->umq_buf_t_size;
                    sc_buf_size = sci->blk_size;
                }
                static const char *sc_names[] = {"Small", "Medium", "Large", "Huge", "Gigantic"};
                const char *sc_name = (sc < sizeof(sc_names) / sizeof(sc_names[0])) ?
                                       sc_names[sc] : "sc?";
                char ts_buf[UMQ_DFX_LABEL_BUF_SIZE];
                (void)snprintf(ts_buf, sizeof(ts_buf), "%lu(%.1fMB)", sc_total_size,
                               (double)sc_total_size / (UMQ_DFX_BYTES_PER_MB));
                UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                     "%-13s %-6s %-21s %-8lu %-8u %-8u %-8u %-8u %-11u %-11lu %-11lu\n",
                                     sc_name, mode_str, ts_buf,
                                     (unsigned long)sci->init_block_count,
                                     sci->blk_size, info->headroom_size, sc_data_size, sc_buf_size,
                                     info->umq_buf_t_size, (unsigned long)sci->buf_cnt_with_data, sc_free_size);
                grand_total_size += sc_total_size;
            }
            /* RX pool row: owned by the multi-level Small pool, carried in its config.
             * rx_pool_total_size already counts each block's umq_buf_t header, matching
             * the other type rows that add TotalBlk * umq_buf_t_size to the data bytes. */
            const umq_qbuf_pool_config_t *cfg = &info->config;
            uint64_t rx_total_size = cfg->rx_pool_total_size;
            uint32_t rx_data_size;
            uint32_t rx_buf_size;
            if (info->mode == UMQ_BUF_SPLIT) {
                rx_data_size = cfg->rx_pool_block_size;
                rx_buf_size = cfg->rx_pool_block_size + info->umq_buf_t_size;
            } else {
                rx_data_size = cfg->rx_pool_block_size - info->umq_buf_t_size;
                rx_buf_size = cfg->rx_pool_block_size;
            }
            char rx_ts_buf[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(rx_ts_buf, sizeof(rx_ts_buf), "%lu(%.1fMB)", rx_total_size,
                           (double)rx_total_size / (UMQ_DFX_BYTES_PER_MB));
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-13s %-6s %-21s %-8lu %-8u %-8u %-8u %-8u %-11u %-11lu %-11lu\n",
                                 "RX_pool", mode_str, rx_ts_buf,
                                 (unsigned long)cfg->rx_pool_depth,
                                 cfg->rx_pool_block_size, info->headroom_size, rx_data_size,
                                 rx_buf_size, info->umq_buf_t_size,
                                 (unsigned long)cfg->rx_pool_free_depth,
                                 (uint64_t)cfg->rx_pool_free_depth * cfg->rx_pool_block_size);
            grand_total_size += rx_total_size;
        } else {
            /* single-level pool (Tiny/etc): one row. TotalBlk/TotalSize = initial
             * reserved (sc_info[0].capacity, NOT including expansion); FreeBlk =
             * current free. */
            const umq_qbuf_sc_info_t *sci0 = &info->sc_info[0];
            uint64_t init_total_size = (uint64_t)sci0->init_block_count * (sci0->blk_size + info->umq_buf_t_size);
            uint64_t free_size = (uint64_t)info->available_mem.split.block_num_with_data * sci0->blk_size;
            char tiny_ts_buf[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(tiny_ts_buf, sizeof(tiny_ts_buf), "%lu(%.1fMB)", init_total_size,
                           (double)init_total_size / (UMQ_DFX_BYTES_PER_MB));
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-13s %-6s %-21s %-8lu %-8u %-8u %-8u %-8u %-11u %-11lu %-11lu\n",
                                 umq_qbuf_pool_type_name(info->type), mode_str, tiny_ts_buf,
                                 (unsigned long)sci0->init_block_count, sci0->blk_size,
                                 info->headroom_size, info->data_size,
                                 info->buf_size, info->umq_buf_t_size,
                                 info->available_mem.split.block_num_with_data, free_size);
            grand_total_size += init_total_size;
        }
    }
    /* without-data row (placed after Tiny): the Small pool's header-only blocks
     * (sc0 carries the count). Only the umq_buf_t header (128B) is stored;
     * TotalSize = header count * umq_buf_t_size. No Mode/BlkSize/etc (header-only,
     * not a data block) — show "-" for those. without-data blocks are separate
     * from the with-data blocks (not counted in any sc's init_block_count), so
     * their header space IS added to grand_total. */
    if (small_info != NULL && small_info->mode == UMQ_BUF_SPLIT) {
        /* TotalSize/TotalBlk should reflect total capacity (fixed at init), not
         * the current free count (block_num_without_data decreases on alloc).
         * Use total_block_num_without_data / total_size_without_data. */
        uint64_t nodata_total_size = small_info->available_mem.split.total_size_without_data;
        uint64_t nodata_total_blk = small_info->available_mem.split.total_block_num_without_data;
        char nodata_ts_buf[UMQ_DFX_LABEL_BUF_SIZE];
        (void)snprintf(nodata_ts_buf, sizeof(nodata_ts_buf), "%lu(%.1fMB)", nodata_total_size,
                       (double)nodata_total_size / (UMQ_DFX_BYTES_PER_MB));
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "%-13s %-6s %-21s %-8lu %-8s %-8s %-8s %-8s %-11u %-11s %-11s\n",
                             "without-data", "-", nodata_ts_buf,
                             (unsigned long)nodata_total_blk,
                             "-", "-", "-", "-", small_info->umq_buf_t_size, "-", "-");
        grand_total_size += nodata_total_size;
    }
    /* Total row: sum of every row's TotalSize, with a human-readable MB suffix. */
    char total_ts_buf[UMQ_DFX_LABEL_BUF_SIZE];
    (void)snprintf(total_ts_buf, sizeof(total_ts_buf), "%lu(%.1fMB)", grand_total_size,
                   (double)grand_total_size / (UMQ_DFX_BYTES_PER_MB));
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                         "%-13s %-6s %-21s\n", "Total", "-", total_ts_buf);

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
        /* Tiny pool: single-level, no expansion/escape/TLS-expand. Show only
         * the 3 meaningful config items instead of misleading zeros. */
        if (info->type == UMQ_QBUF_POOL_TYPE_TINY) {
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "tiny_pool_block_size",
                                 cfg->tiny_pool_block_size);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "tiny_pool_block_count",
                                 cfg->tiny_pool_block_count);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu\n", "tls_tiny_pool_depth",
                                 (unsigned long)cfg->tls_tiny_pool_depth);
            continue;
        }
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "size_class_count",
                             cfg->size_class_count);
        for (uint32_t sc = 0; sc < cfg->size_class_count; sc++) {
            char name[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(name, sizeof(name), "blk_size[%u]", sc);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", name,
                                 cfg->explicit_block_sizes[sc]);
        }
        /* Fix P1-2: per_sc_block_count removed -- multi-level model has per-sc
         * counts in sc_info[].cap, a single uint64 cannot represent them. */
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "disable_scale_cap",
                             (uint32_t)cfg->disable_scale_cap);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u %-30s %-12lu\n", "disable_malloc_escape",
                             (uint32_t)cfg->disable_malloc_escape, "expansion_size", cfg->expansion_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "expansion_threshold",
                             cfg->expansion_threshold);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12lu\n", "expansion_mem_size_max",
                             cfg->expansion_mem_size_max, "exp_total_mem_pool_size", cfg->exp_total_mem_pool_size);
         /* tls_qbuf_pool_depth / tls_expand_qbuf_pool_depth are block counts
         * (not bytes), so they can be compared directly with Per-Thread TLS CurCap. */
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12lu\n",
                             "tls_qbuf_pool_depth", cfg->tls_qbuf_pool_depth,
                             "tls_expand_qbuf_pool_depth", cfg->tls_expand_qbuf_pool_depth);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", "exp_slot_used_count",
                             info->exp_slot_used_count);
        for (uint32_t sc = 0; sc < cfg->size_class_count; sc++) {
            char name[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(name, sizeof(name), "batch_count[sc%u]", sc);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u\n", name,
                                 cfg->per_sc_batch_count[sc]);
        }
        for (uint32_t sc = 0; sc < cfg->size_class_count; sc++) {
            char name[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(name, sizeof(name), "block_counts[sc%u]", sc);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu\n", name,
                                 (unsigned long)cfg->per_sc_block_counts[sc]);
        }
        for (uint32_t sc = 0; sc < cfg->size_class_count; sc++) {
            char name[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(name, sizeof(name), "tls_depth[sc%u]", sc);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu\n", name,
                                 (unsigned long)cfg->per_sc_tls_qbuf_pool_depth[sc]);
        }
    }

    /* Pool Config [RX_pool]: RX pool config fields are carried on the Small pool's
     * config (rx_pool_*), but displayed as their own section for clarity. */
    if (small_info != NULL && small_info->type == UMQ_QBUF_POOL_TYPE_SMALL) {
        const umq_qbuf_pool_config_t *cfg = &small_info->config;
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "                                  Pool Config [RX_pool]\n");
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu\n", "rx_pool_total_size",
                             cfg->rx_pool_total_size);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12u %-30s %-12u\n", "rx_pool_block_size",
                             cfg->rx_pool_block_size, "rx_pool_depth", cfg->rx_pool_depth);
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12ld\n", "rx_pool_free_depth",
                             cfg->rx_pool_free_depth, "rx_pool_outstanding",
                             (long)(qbuf_pool_stats->alloc_stats.rx_pool_alloc_count -
                                    qbuf_pool_stats->alloc_stats.rx_pool_free_count));
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %-12lu %-30s %-12lu\n", "rx_pool_alloc_cnt",
                             qbuf_pool_stats->alloc_stats.rx_pool_alloc_count, "rx_pool_free_cnt",
                             qbuf_pool_stats->alloc_stats.rx_pool_free_count);
    }

    // === Global Pool State (unified: all pool types with alloc/free/outstanding) ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Global Pool State");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                         "%-13s %-10s %-10s %-11s %-11s %-11s %-11s %-11s %-11s %-15s\n",
                         "Type", "free_blk", "blk_size", "exp_blk", "exp_cnt", "exp_shrink",
                         "alloc_cnt", "free_cnt", "outstanding", "outstanding_max");
    /* Normal pool: per-SC with_data rows + RX + without-data */
    static const char *sc_names[] = {"Small", "Medium", "Large", "Huge", "Gigantic"};
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        if (info->mode != UMQ_BUF_SPLIT || info->sc_count <= 1) {
            continue;
        }
        for (uint32_t sc = 0; sc < info->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            const umq_qbuf_sc_info_t *sci = &info->sc_info[sc];
            const char *sc_name =
                (sc < sizeof(umq_dfx_sc_names) / sizeof(umq_dfx_sc_names[0])) ? umq_dfx_sc_names[sc] : "sc?";
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-13s %-10lu %-10u %-11lu %-11lu %-11lu %-11lu %-11lu %-11ld %-15lu\n",
                                 sc_name,
                                 (unsigned long)sci->buf_cnt_with_data,
                                 sci->blk_size,
                                 (unsigned long)sci->exp_total_block_num,
                                 (unsigned long)sci->exp_total_expansion_count,
                                 (unsigned long)sci->exp_total_shrink_count,
                                 (unsigned long)qbuf_pool_stats->alloc_stats.sc_alloc_count[sc],
                                 (unsigned long)qbuf_pool_stats->alloc_stats.sc_free_count[sc],
                                 (long)(qbuf_pool_stats->alloc_stats.sc_alloc_count[sc] -
                                        qbuf_pool_stats->alloc_stats.sc_free_count[sc]),
                                 (unsigned long)qbuf_pool_stats->alloc_stats.sc_outstanding_max[sc]);
        }
        /* RX pool row */
        {
            const umq_qbuf_pool_config_t *cfg = &info->config;
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-13s %-10lu %-10u %-11s %-11s %-11s %-11lu %-11lu %-11ld %-15lu\n",
                                 "RX_pool",
                                 (unsigned long)cfg->rx_pool_free_depth,
                                 cfg->rx_pool_block_size,
                                 "-", "-", "-",
                                 (unsigned long)qbuf_pool_stats->alloc_stats.rx_pool_alloc_count,
                                 (unsigned long)qbuf_pool_stats->alloc_stats.rx_pool_free_count,
                                 (long)(qbuf_pool_stats->alloc_stats.rx_pool_alloc_count -
                                        qbuf_pool_stats->alloc_stats.rx_pool_free_count),
                                 (unsigned long)qbuf_pool_stats->alloc_stats.rx_pool_outstanding_max);
        }
        /* without-data row */
        {
            const umq_expansion_pool_stats_t *exp = &qbuf_pool_stats->exp_pool_without_data;
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-13s %-10lu %-10u %-11lu %-11lu %-11lu %-11lu %-11lu %-11ld %-15lu\n",
                                 "without-data",
                                 (unsigned long)info->available_mem.split.block_num_without_data,
                                 info->umq_buf_t_size,
                                 (unsigned long)exp->exp_total_block_num,
                                 (unsigned long)exp->total_expansion_count,
                                 (unsigned long)exp->total_shrink_count,
                                 (unsigned long)qbuf_pool_stats->alloc_stats.nodata_alloc_count,
                                 (unsigned long)qbuf_pool_stats->alloc_stats.nodata_free_count,
                                 (long)(qbuf_pool_stats->alloc_stats.nodata_alloc_count -
                                        qbuf_pool_stats->alloc_stats.nodata_free_count),
                                 (unsigned long)qbuf_pool_stats->alloc_stats.nodata_outstanding_max);
        }
    }
    /* Tiny pool row (separate pool, no expansion, no global alloc/free counters) */
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        if (info->type != UMQ_QBUF_POOL_TYPE_TINY) {
            continue;
        }
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "%-13s %-10lu %-10u %-11s %-11s %-11s %-11s %-11s %-11s %-15s\n",
                             "Tiny",
                             (unsigned long)info->available_mem.split.block_num_with_data,
                             info->block_size,
                             "-", "-", "-", "-", "-", "-", "-");
    }

    /* Sizing advice: check if outstanding_max exceeds initial pool capacity.
     * If peak outstanding > initial blocks, the initial pool was too small and
     * expansion was needed — suggest increasing the initial size. */
    for (uint32_t i = 0; i < qbuf_pool_stats->num; i++) {
        const umq_qbuf_pool_info_t *info = &qbuf_pool_stats->qbuf_pool_info[i];
        if (info->mode != UMQ_BUF_SPLIT || info->sc_count <= 1) {
            continue;
        }
        static const char *sc_names[] = {"Small", "Medium", "Large", "Huge", "Gigantic"};
        static const char *tls_param_names[] = {
            "--ubsocket_small_buf_pool_depth",
            "--ubsocket_middle_buf_pool_depth",
            "--ubsocket_large_buf_pool_depth",
            "--ubsocket_huge_buf_pool_depth",
            "--ubsocket_gigantic_buf_pool_depth"
        };
        static const char *global_param_names[] = {
            "--ubsocket_small_global_pool_depth",
            "--ubsocket_middle_global_pool_depth",
            "--ubsocket_large_global_pool_depth",
            "--ubsocket_huge_global_pool_depth",
            "--ubsocket_gigantic_global_pool_depth"
        };
        for (uint32_t sc = 0; sc < info->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            const umq_qbuf_sc_info_t *sci = &info->sc_info[sc];
            uint64_t outstanding_max = qbuf_pool_stats->alloc_stats.sc_outstanding_max[sc];
            uint64_t init_blocks = sci->init_block_count;
            if (init_blocks == 0 || outstanding_max <= init_blocks) {
                continue;
            }
            const char *sc_name = (sc < sizeof(sc_names) / sizeof(sc_names[0])) ? sc_names[sc] : "sc?";
            const char *tls_param = (sc < sizeof(tls_param_names) / sizeof(tls_param_names[0])) ?
                                    tls_param_names[sc] : "--ubsocket_unknown_buf_pool_depth";
            const char *global_param = (sc < sizeof(global_param_names) / sizeof(global_param_names[0])) ?
                                       global_param_names[sc] : "--ubsocket_unknown_global_pool_depth";
            double peak_mem_mb = (double)(outstanding_max * (sci->blk_size + info->umq_buf_t_size)) / (1024.0 * 1024.0);
            double init_mem_mb = (double)(init_blocks * (sci->blk_size + info->umq_buf_t_size)) / (1024.0 * 1024.0);
            /* recommended total = outstanding_max / 0.7, 2/3 for TLS, 1/3 for global,
             * aligned up to QBUF_SIZING_ALIGN_BLOCKS */
            uint64_t recommended = (uint64_t)((outstanding_max + QBUF_SIZING_SCALING_DENOM - 1) /
                                              QBUF_SIZING_SCALING_DENOM * QBUF_SIZING_SCALING_NUMER);
            recommended = QBUF_ALIGN_UP(recommended, QBUF_SIZING_ALIGN_BLOCKS);
            uint64_t rec_tls = (recommended * QBUF_SIZING_TLS_RATIO_NUMER + QBUF_SIZING_TLS_RATIO_DENOM - 1) /
                               QBUF_SIZING_TLS_RATIO_DENOM;
            rec_tls = QBUF_ALIGN_UP(rec_tls, QBUF_SIZING_ALIGN_BLOCKS);
            uint64_t rec_global = recommended - rec_tls;
            rec_global = QBUF_ALIGN_UP(rec_global, QBUF_SIZING_ALIGN_BLOCKS);
            double rec_mem_mb = (double)(recommended * (sci->blk_size + info->umq_buf_t_size)) / (1024.0 * 1024.0);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "[SIZING] %s: outstanding_max=%llu (%.1fMB) > initial=%llu (%.1fMB), "
                                 "recommended: %llu (%.1fMB) %s=%llu %s=%llu\n",
                                 sc_name,
                                 (unsigned long long)outstanding_max, peak_mem_mb,
                                 (unsigned long long)init_blocks, init_mem_mb,
                                 (unsigned long long)recommended, rec_mem_mb,
                                 tls_param, (unsigned long long)rec_tls,
                                 global_param, (unsigned long long)rec_global);
        }
        /* without-data check */
        uint64_t nodata_outstanding_max = qbuf_pool_stats->alloc_stats.nodata_outstanding_max;
        uint64_t nodata_init_blocks = info->available_mem.split.block_num_without_data;
        if (nodata_init_blocks > 0 && nodata_outstanding_max > nodata_init_blocks) {
            double nodata_peak_mem_mb = (double)(nodata_outstanding_max * info->umq_buf_t_size) / (1024.0 * 1024.0);
            double nodata_init_mem_mb = (double)(nodata_init_blocks * info->umq_buf_t_size) / (1024.0 * 1024.0);
            uint64_t nodata_recommended = (uint64_t)((nodata_outstanding_max + QBUF_SIZING_SCALING_DENOM - 1) /
                                                      QBUF_SIZING_SCALING_DENOM * QBUF_SIZING_SCALING_NUMER);
            nodata_recommended = QBUF_ALIGN_UP(nodata_recommended, QBUF_SIZING_ALIGN_BLOCKS);
            double nodata_rec_mem_mb = (double)(nodata_recommended * info->umq_buf_t_size) / (1024.0 * 1024.0);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "[SIZING] without-data: outstanding_max=%llu (%.1fMB) > initial=%llu (%.1fMB), "
                                 "recommended: %llu (%.1fMB)\n",
                                 (unsigned long long)nodata_outstanding_max, nodata_peak_mem_mb,
                                 (unsigned long long)nodata_init_blocks, nodata_init_mem_mb,
                                 (unsigned long long)nodata_recommended, nodata_rec_mem_mb);
        }
    }

    // === Expansion Pool ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Expansion Pool");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-10s %-10s %-10s %-11s %-11s %-11s %-11s %-12s\n", "Type", "ExpandCnt",
                         "TotalBlk", "FreeBlk", "MemSize", "AccExpCnt", "SyncExpCnt", "AsyncExpCnt", "AccShrinkCnt");
    /* WithData: per-SC breakdown for multi-level pools (Small/Medium/...). */
    if (small_info != NULL && small_info->sc_count > 1) {
        static const char *sc_names[] = {"Small", "Medium", "Large", "Huge", "Gigantic"};
        for (uint32_t sc = 0; sc < small_info->sc_count; sc++) {
            const umq_qbuf_sc_info_t *sci = &small_info->sc_info[sc];
            const char *sc_name =
                (sc < sizeof(umq_dfx_sc_names) / sizeof(umq_dfx_sc_names[0])) ? umq_dfx_sc_names[sc] : "sc?";
            uint64_t exp_mem_size = sci->exp_total_block_num * sci->blk_size;
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-13s %-10u %-10lu %-10lu %-11lu %-11lu %-11lu %-11lu %-12lu\n",
                                 sc_name, sci->exp_expansion_count,
                                 (unsigned long)sci->exp_total_block_num,
                                 (unsigned long)sci->exp_free_blk, (unsigned long)exp_mem_size,
                                 (unsigned long)sci->exp_total_expansion_count,
                                 (unsigned long)sci->exp_sync_expansion_count,
                                 (unsigned long)sci->exp_async_expansion_count,
                                 (unsigned long)sci->exp_total_shrink_count);
        }
    } else if (small_info != NULL && small_info->sc_count == 1) {
        /* single-level pool: one WithData row */
        const umq_qbuf_sc_info_t *sci = &small_info->sc_info[0];
        uint64_t exp_mem_size = sci->exp_total_block_num * sci->blk_size;
        UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                             "%-13s %-10u %-10lu %-10lu %-11lu %-11lu %-11lu %-11lu %-12lu\n", "WithData",
                             sci->exp_expansion_count,
                             (unsigned long)sci->exp_total_block_num,
                             (unsigned long)sci->exp_free_blk, (unsigned long)exp_mem_size,
                             (unsigned long)sci->exp_total_expansion_count,
                             (unsigned long)sci->exp_sync_expansion_count,
                             (unsigned long)sci->exp_async_expansion_count,
                             (unsigned long)sci->exp_total_shrink_count);
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-13s %-10u %-10lu %-10lu %-11lu %-11lu %-11lu %-11lu %-12lu\n", "WithoutData",
                         qbuf_pool_stats->exp_pool_without_data.expansion_count,
                         qbuf_pool_stats->exp_pool_without_data.exp_total_block_num,
                         qbuf_pool_stats->exp_pool_without_data.exp_total_free_block_num,
                         qbuf_pool_stats->exp_pool_without_data.exp_total_mem_size,
                         qbuf_pool_stats->exp_pool_without_data.total_expansion_count,
                         qbuf_pool_stats->exp_pool_without_data.sync_expansion_count,
                         qbuf_pool_stats->exp_pool_without_data.async_expansion_count,
                         qbuf_pool_stats->exp_pool_without_data.total_shrink_count);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "partial_slot_count: WithData=%u WithoutData=%u\n",
                         qbuf_pool_stats->exp_pool_with_data.partial_slot_count,
                         qbuf_pool_stats->exp_pool_without_data.partial_slot_count);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                         "rx_pool_fallback_to_normal: alloc=%llu outstanding=%llu outstanding_max=%llu\n",
                         (unsigned long long)umq_rx_qbuf_pool_fallback_count_get(),
                         (unsigned long long)umq_rx_qbuf_pool_fallback_outstanding_get(),
                         (unsigned long long)umq_rx_qbuf_pool_fallback_outstanding_max_get());

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
                             "sc", "blk_size", "exp_slots", "exp_total_blk",
                             "exp_free_blk", "exp_expand_cnt", "exp_shrink_cnt");
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

    /* Per-SC TLS accumulation for Derived Metrics breakdown.
     * Indexed by [sc], valid range [0..sc_count-1]. */
    uint64_t total_tls_buf_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_tls_capacity_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_tls_fetch_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_tls_fetch_buf_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_tls_return_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_tls_return_buf_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_alloc_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};
    uint64_t total_free_cnt_with_data_per_sc[UMQ_SIZE_CLASS_MAX] = {0};

    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Per-Thread TLS Pool Stats (WithData)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-10s %-8s %-8s %-8s %-11s %-11s %-11s %-11s %-11s %-11s\n",
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
        /* accumulate per-SC TLS for Derived Metrics */
        for (uint32_t sc = 0; sc < s->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            total_tls_buf_cnt_with_data_per_sc[sc] += s->sc_buf_cnt_with_data[sc];
            total_tls_capacity_with_data_per_sc[sc] += s->sc_capacity_with_data[sc];
            total_tls_fetch_cnt_with_data_per_sc[sc] += s->sc_tls_fetch_cnt[sc];
            total_tls_fetch_buf_cnt_with_data_per_sc[sc] += s->sc_tls_fetch_buf_cnt[sc];
            total_tls_return_cnt_with_data_per_sc[sc] += s->sc_tls_return_cnt[sc];
            total_tls_return_buf_cnt_with_data_per_sc[sc] += s->sc_tls_return_buf_cnt[sc];
            total_alloc_cnt_with_data_per_sc[sc] += s->sc_alloc_cnt[sc];
            total_free_cnt_with_data_per_sc[sc] += s->sc_free_cnt[sc];
        }
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                         "%-10s %-8s %-8lu %-8lu %-11lu %-11lu %-11lu %-11lu %-11lu %-11lu\n", "total", "-",
                         total_tls_capacity_with_data, total_tls_buf_cnt_with_data, total_tls_fetch_cnt_with_data,
                         total_tls_fetch_buf_cnt_with_data, total_tls_return_cnt_with_data,
                         total_tls_return_buf_cnt_with_data, total_alloc_cnt_with_data, total_free_cnt_with_data);
    /* per-SC total rows (total-Small/total-Medium/...) for multi-level pools */
    if (small_info != NULL && small_info->sc_count > 1) {
        for (uint32_t sc = 0; sc < small_info->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            const char *sc_name =
                (sc < sizeof(umq_dfx_sc_names) / sizeof(umq_dfx_sc_names[0])) ? umq_dfx_sc_names[sc] : "sc?";
            char total_sc_label[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(total_sc_label, sizeof(total_sc_label), "total-%s", sc_name);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-10s %-8s %-8lu %-8lu %-11lu %-11lu %-11lu %-11lu %-11lu %-11lu\n",
                                 total_sc_label, "-",
                                 total_tls_capacity_with_data_per_sc[sc],
                                 total_tls_buf_cnt_with_data_per_sc[sc],
                                 total_tls_fetch_cnt_with_data_per_sc[sc],
                                 total_tls_fetch_buf_cnt_with_data_per_sc[sc],
                                 total_tls_return_cnt_with_data_per_sc[sc],
                                 total_tls_return_buf_cnt_with_data_per_sc[sc],
                                 total_alloc_cnt_with_data_per_sc[sc],
                                 total_free_cnt_with_data_per_sc[sc]);
        }
    }

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        if (s->sc_count > 1) {
            /* Multi-level pool: split per-SC into Small/Medium rows.
             * All columns show per-SC values (fetch/return/alloc/free are per-sc). */
            for (uint32_t sc = 0; sc < s->sc_count; sc++) {
                const char *sc_name =
                (sc < sizeof(umq_dfx_sc_names) / sizeof(umq_dfx_sc_names[0])) ? umq_dfx_sc_names[sc] : "sc?";
                UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                     "%-10s %-8lu %-8lu %-8lu %-11lu %-11lu %-11lu %-11lu %-11lu %-11lu\n",
                                     sc_name, s->tid,
                                     (unsigned long)s->sc_capacity_with_data[sc],
                                     (unsigned long)s->sc_buf_cnt_with_data[sc],
                                     (unsigned long)s->sc_tls_fetch_cnt[sc],
                                     (unsigned long)s->sc_tls_fetch_buf_cnt[sc],
                                     (unsigned long)s->sc_tls_return_cnt[sc],
                                     (unsigned long)s->sc_tls_return_buf_cnt[sc],
                                     (unsigned long)s->sc_alloc_cnt[sc],
                                     (unsigned long)s->sc_free_cnt[sc]);
            }
        } else {
            /* single-level pool (Tiny/etc): one row */
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size,
                                 "%-10s %-8lu %-8lu %-8lu %-11lu %-11lu %-11lu %-11lu %-11lu %-11lu\n",
                                 umq_qbuf_pool_type_name(s->type), s->tid, s->capacity_with_data, s->buf_cnt_with_data,
                                 s->tls_fetch_cnt_with_data, s->tls_fetch_buf_cnt_with_data,
                                 s->tls_return_cnt_with_data, s->tls_return_buf_cnt_with_data,
                                 s->alloc_cnt_with_data, s->free_cnt_with_data);
        }
    }

    // === Per-Thread TLS Pool Stats (WithoutData) ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n",
                         "                                             Per-Thread TLS Pool Stats (WithoutData)");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-10s %-8s %-8s %-8s %-11s %-11s %-11s %-11s %-11s %-11s\n",
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
        buf, max_buf_len, str_size, "%-10s %-8s %-8lu %-8lu %-11lu %-11lu %-11lu %-11lu %-11lu %-11lu\n", "total",
        "-", total_tls_capacity_without_data, total_tls_buf_cnt_without_data, total_tls_fetch_cnt_without_data,
        total_tls_fetch_buf_cnt_without_data, total_tls_return_cnt_without_data, total_tls_return_buf_cnt_without_data,
        total_alloc_cnt_without_data, total_free_cnt_without_data);

    for (uint32_t i = 0; i < qbuf_pool_stats->local_qbuf_pool_num; i++) {
        const umq_local_qbuf_pool_stats_t *s = &qbuf_pool_stats->local_qbuf_pool_stats[i];
        UMQ_DFX_SNPRINTF_BUF(
            buf, max_buf_len, str_size, "%-10s %-8lu %-8lu %-8lu %-11lu %-11lu %-11lu %-11lu %-11lu %-11lu\n",
            umq_qbuf_pool_type_name(s->type), s->tid, s->capacity_without_data, s->buf_cnt_without_data,
            s->tls_fetch_cnt_without_data, s->tls_fetch_buf_cnt_without_data, s->tls_return_cnt_without_data,
            s->tls_return_buf_cnt_without_data, s->alloc_cnt_without_data, s->free_cnt_without_data);
    }

    // === Escape (properly framed section, consistent with other tables) ===
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", "                                             Escape");
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_UNDERLINE_120);
    uint64_t escape_total = 0;
    for (uint32_t sc = 0; sc < UMQ_SIZE_CLASS_MAX; sc++) {
        escape_total += qbuf_pool_stats->escape_buf_cnt_by_sc[sc];
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%-30s %lu\n", "escape_buf_cnt(total)",
                         (unsigned long)escape_total);
    if (small_info != NULL) {
        for (uint32_t sc = 0; sc < small_info->sc_count && sc < UMQ_SIZE_CLASS_MAX; sc++) {
            char sc_label[UMQ_DFX_LABEL_BUF_SIZE];
            (void)snprintf(sc_label, sizeof(sc_label), "escape_buf_cnt_sc[%u]", sc);
            UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "  %-28s %lu  (blk_size=%u)\n",
                                 sc_label,
                                 (unsigned long)qbuf_pool_stats->escape_buf_cnt_by_sc[sc],
                                 small_info->sc_info[sc].blk_size);
        }
    }
    UMQ_DFX_SNPRINTF_BUF(buf, max_buf_len, str_size, "%s\n", UMQ_DFX_EQUALS_120);

    return str_size;
}
