/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize qbuf pool config check function
 * Create: 2026-6-12
 */

#include "umq_huge_qbuf_pool.h"
#include "umq_qbuf_pool.h"
#include "umq_qbuf_pool_helper.h"
#include "umq_tiny_qbuf_pool.h"

static inline bool umq_is_power_of_2(uint32_t x)
{
    return x > 0 && (x & (x - 1)) == 0;
}

static int umq_tiny_pool_cfg_check(const umq_init_cfg_t *cfg, umq_qbuf_pool_plan_t *plan)
{
    if (!cfg->buf_pool_cfg.enable_tiny_pool) {
        return UMQ_SUCCESS;
    }

    uint64_t tiny_block_count = cfg->buf_pool_cfg.tiny_pool_block_count == 0 ? TINY_QBUF_POOL_DEFAULT_BLOCK_COUNT :
                                                                                cfg->buf_pool_cfg.tiny_pool_block_count;

    if (tiny_block_count < QBUF_POOL_BATCH_CNT || tiny_block_count < cfg->buf_pool_cfg.tls_tiny_pool_depth) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tiny block count %llu is less than QBUF_POOL_BATCH_CNT or tls_tiny_pool_depth %llu\n",
            tiny_block_count, cfg->buf_pool_cfg.tls_tiny_pool_depth);
        return -UMQ_ERR_EINVAL;
    }

    plan->tiny_block_size = umq_tiny_buf_block_size_bytes(cfg->buf_pool_cfg.tiny_pool_block_size);
    if (plan->tiny_block_size == 0 || plan->tiny_block_size > umq_buf_size_small()) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tiny pool block size %u invalid, normal block size %u\n", plan->tiny_block_size,
                     umq_buf_size_small());
        return -UMQ_ERR_EINVAL;
    }

    plan->tiny_io_buf_size = tiny_block_count * plan->tiny_block_size;
    if (cfg->buf_mode == UMQ_BUF_SPLIT) {
        plan->tiny_io_buf_size += tiny_block_count * sizeof(umq_buf_t);
    }

    if (plan->tiny_io_buf_size > UMQ_TINY_QBUF_POOL_MAX_SIZE) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tiny pool io buf size %llu exceed max size %llu\n", plan->tiny_io_buf_size,
                     UMQ_TINY_QBUF_POOL_MAX_SIZE);
        return -UMQ_ERR_EINVAL;
    }

    return UMQ_SUCCESS;
}

int umq_qbuf_pool_cfg_check(const umq_init_cfg_t *cfg, umq_qbuf_pool_plan_t *plan)
{
    if (cfg == NULL || plan == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    (void)memset(plan, 0, sizeof(*plan));

    int ret = umq_tiny_pool_cfg_check(cfg, plan);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    plan->rx_block_count = cfg->buf_pool_cfg.rx_block_count;
    if (plan->rx_block_count > 0) {
        uint64_t rx_blk_size = umq_buf_size_small();
        plan->rx_io_buf_size = (uint64_t)plan->rx_block_count * (rx_blk_size + sizeof(umq_buf_t));
        if (plan->rx_io_buf_size / (rx_blk_size + sizeof(umq_buf_t)) != plan->rx_block_count) {
            UMQ_VLOG_ERR(VLOG_UMQ, "rx_io_buf_size overflow: rx_block_count %llu * blk_size %llu\n",
                         (unsigned long long)plan->rx_block_count,
                         (unsigned long long)(rx_blk_size + sizeof(umq_buf_t)));
            return -UMQ_ERR_EINVAL;
        }
    }

    uint32_t count = (cfg->buf_pool_cfg.size_class_count == 0) ? QBUF_POOL_DEFAULT_SIZE_CLASS_COUNT :
                                                                  cfg->buf_pool_cfg.size_class_count;
    if (count < 1 || count > UMQ_SIZE_CLASS_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "size_class_count %u out of range [1, %u]\n", count, UMQ_SIZE_CLASS_MAX);
        return -UMQ_ERR_EINVAL;
    }
    plan->size_class_count = count;

    // tls_qbuf_pool_depth: 0 = use default; out-of-range values will be clamped to default in umq_qbuf_pool_init
    if (cfg->buf_pool_cfg.tls_qbuf_pool_depth != 0 &&
        (cfg->buf_pool_cfg.tls_qbuf_pool_depth < QBUF_POOL_TLS_QBUF_DEPTH_MIN ||
         cfg->buf_pool_cfg.tls_qbuf_pool_depth > QBUF_POOL_TLS_QBUF_DEPTH_MAX)) {
        UMQ_VLOG_WARN(VLOG_UMQ, "tls_qbuf_pool_depth %llu out of range [%u, %u], will use default\n",
                      (unsigned long long)cfg->buf_pool_cfg.tls_qbuf_pool_depth,
                      QBUF_POOL_TLS_QBUF_DEPTH_MIN, QBUF_POOL_TLS_QBUF_DEPTH_MAX);
    }

    // tls_expand_qbuf_pool_depth: 0 = use default; out-of-range values will be clamped to default in umq_qbuf_pool_init
    if (cfg->buf_pool_cfg.tls_expand_qbuf_pool_depth != 0 &&
        (cfg->buf_pool_cfg.tls_expand_qbuf_pool_depth < QBUF_POOL_TLS_QBUF_DEPTH_MIN ||
         cfg->buf_pool_cfg.tls_expand_qbuf_pool_depth > QBUF_POOL_TLS_QBUF_DEPTH_MAX)) {
        UMQ_VLOG_WARN(VLOG_UMQ, "tls_expand_qbuf_pool_depth %llu out of range [%u, %u], will use default\n",
                      (unsigned long long)cfg->buf_pool_cfg.tls_expand_qbuf_pool_depth,
                      QBUF_POOL_TLS_QBUF_DEPTH_MIN, QBUF_POOL_TLS_QBUF_DEPTH_MAX);
    }

    uint64_t normal_io_buf_size = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t blk_cnt = cfg->buf_pool_cfg.per_sc_block_counts[i];
        uint64_t tls = cfg->buf_pool_cfg.per_sc_tls_qbuf_pool_depth[i];
        uint32_t blk_sz = cfg->buf_pool_cfg.explicit_block_sizes[i];

        // 0 = use default (fail-fast in plan stage, before allocation)
        if (blk_cnt == 0) {
            blk_cnt = QBUF_POOL_BLOCK_COUNT_DEFAULT;
        }
        if (tls == 0) {
            tls = QBUF_POOL_TLS_DEPTH_DEFAULT;
        }
        // Size class roles: see QBUF_POOL_SMALL/MIDDLE/LARGE_SIZE_CLASS_ID in umq_qbuf_pool_base.h.
        // SMALL  -> block size defaults to small_block_size when caller passes 0
        // MIDDLE -> block size defaults to QBUF_POOL_MIDDLE_BLOCK_SIZE_DEFAULT when caller passes 0
        // LARGE+  -> block size must be set explicitly (no default, cfg_check rejects 0)
        if (i == QBUF_POOL_SMALL_SIZE_CLASS_ID && blk_sz == 0) {
            blk_sz = umq_buf_size_small();
        }
        if (i == QBUF_POOL_MIDDLE_SIZE_CLASS_ID && blk_sz == 0) {
            blk_sz = QBUF_POOL_MIDDLE_BLOCK_SIZE_DEFAULT;
        }

        // composite constraint: blk_cnt >= tls (prevents uint64 underflow downstream)
        if (tls < QBUF_POOL_TLS_DEPTH_MIN || tls > QBUF_POOL_TLS_DEPTH_MAX) {
            UMQ_VLOG_ERR(VLOG_UMQ, "per_sc_tls_qbuf_pool_depth[%u]=%llu out of range [%u, %u]\n",
                         i, (unsigned long long)tls, QBUF_POOL_TLS_DEPTH_MIN, QBUF_POOL_TLS_DEPTH_MAX);
            return -UMQ_ERR_EINVAL;
        }
        if (blk_cnt < QBUF_POOL_BLOCK_COUNT_MIN || blk_cnt > QBUF_POOL_BLOCK_COUNT_MAX) {
            UMQ_VLOG_ERR(VLOG_UMQ, "per_sc_block_counts[%u]=%llu out of range [%u, %u]\n",
                         i, (unsigned long long)blk_cnt, QBUF_POOL_BLOCK_COUNT_MIN, QBUF_POOL_BLOCK_COUNT_MAX);
            return -UMQ_ERR_EINVAL;
        }
        if (blk_cnt < tls) {
            UMQ_VLOG_ERR(VLOG_UMQ, "per_sc_block_counts[%u]=%llu < per_sc_tls_qbuf_pool_depth[%u]=%llu\n",
                         i, (unsigned long long)blk_cnt, i, (unsigned long long)tls);
            return -UMQ_ERR_EINVAL;
        }
        if (i >= QBUF_POOL_LARGE_SIZE_CLASS_ID_MIN && blk_sz == 0) {
            UMQ_VLOG_ERR(VLOG_UMQ,
                         "explicit_block_sizes[%u]=0 is invalid for SC index > 1, must be set explicitly\n", i);
            return -UMQ_ERR_EINVAL;
        }
        if (i == QBUF_POOL_MIDDLE_SIZE_CLASS_ID) {
            if (blk_sz < QBUF_POOL_MIDDLE_BLOCK_SIZE_MIN || blk_sz > QBUF_POOL_MIDDLE_BLOCK_SIZE_MAX) {
                UMQ_VLOG_ERR(VLOG_UMQ, "explicit_block_sizes[%u]=%u out of range [%u, %u]\n",
                             i, blk_sz, QBUF_POOL_MIDDLE_BLOCK_SIZE_MIN, QBUF_POOL_MIDDLE_BLOCK_SIZE_MAX);
                return -UMQ_ERR_EINVAL;
            }
            if (blk_sz % QBUF_POOL_BLOCK_SIZE_ALIGN != 0) {
                UMQ_VLOG_ERR(VLOG_UMQ, "explicit_block_sizes[%u]=%u not aligned to %u\n",
                             i, blk_sz, QBUF_POOL_BLOCK_SIZE_ALIGN);
                return -UMQ_ERR_EINVAL;
            }
            if (!umq_is_power_of_2(blk_sz)) {
                UMQ_VLOG_ERR(VLOG_UMQ, "explicit_block_sizes[%u]=%u not power of 2\n", i, blk_sz);
                return -UMQ_ERR_EINVAL;
            }
        }

        plan->per_sc_block_counts[i] = blk_cnt;
        plan->per_sc_tls_qbuf_pool_depth[i] = tls;
        plan->explicit_block_sizes[i] = blk_sz;
        normal_io_buf_size += (uint64_t)blk_cnt * blk_sz;
        if (cfg->buf_mode == UMQ_BUF_SPLIT) {
            normal_io_buf_size += blk_cnt * sizeof(umq_buf_t);
        }
    }

    if (normal_io_buf_size == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "normal pool has zero blocks (all per_sc_block_counts are 0)\n");
        return -UMQ_ERR_EINVAL;
    }

    uint64_t without_data_expand_mem_size = (uint64_t)QBUF_POOL_INITIAL_NODATA_BUF_CNT * sizeof(umq_buf_t);

    if (cfg->buf_mode == UMQ_BUF_SPLIT) {
        normal_io_buf_size += without_data_expand_mem_size;
    }

    plan->normal_io_buf_size = normal_io_buf_size;

    if (!cfg->buf_pool_cfg.disable_scale_cap && cfg->buf_pool_cfg.umq_buf_pool_max_size > QBUF_POOL_MEM_SIZE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "the maximum value of expansion mem size max %llu exceed %llu\n",
                     cfg->buf_pool_cfg.umq_buf_pool_max_size, QBUF_POOL_MEM_SIZE_MAX);
        return -UMQ_ERR_EINVAL;
    }

    uint64_t max_umq_buf_pool_size = cfg->buf_pool_cfg.umq_buf_pool_max_size == 0 ?
                                         QBUF_POOL_DEFAULT_EXPANSION_MEM_SIZE :
                                         cfg->buf_pool_cfg.umq_buf_pool_max_size;
    uint64_t total_initial_size = plan->tiny_io_buf_size + plan->rx_io_buf_size + plan->normal_io_buf_size;
    if (max_umq_buf_pool_size < total_initial_size) {
        UMQ_VLOG_ERR(VLOG_UMQ,
                     "max buf pool size %llu is too small for total initial %llu (tiny %llu + rx %llu + normal %llu)\n",
                     max_umq_buf_pool_size, total_initial_size,
                     plan->tiny_io_buf_size, plan->rx_io_buf_size, plan->normal_io_buf_size);
        return -UMQ_ERR_EINVAL;
    }

    if (max_umq_buf_pool_size < plan->tiny_io_buf_size + plan->rx_io_buf_size) {
        UMQ_VLOG_ERR(VLOG_UMQ, "max buf pool size %llu < tiny %llu + rx %llu, normal pool max would underflow\n",
                     (unsigned long long)max_umq_buf_pool_size,
                     (unsigned long long)plan->tiny_io_buf_size,
                     (unsigned long long)plan->rx_io_buf_size);
        return -UMQ_ERR_EINVAL;
    }
    plan->normal_pool_max_size = max_umq_buf_pool_size - plan->tiny_io_buf_size - plan->rx_io_buf_size;
    return UMQ_SUCCESS;
}
