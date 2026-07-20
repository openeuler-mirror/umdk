/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider health check declarations
 */

#ifndef BONDP_HEALTH_H
#define BONDP_HEALTH_H

#include <stdbool.h>
#include <stdint.h>
#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bondp_context;
struct bondp_target_jetty;
struct urma_bond_seg_info_out;
struct urma_bond_id_info_out;

#define BONDP_HC_DEFAULT_PROBE_INTERVAL_MS (1000)
#define BONDP_HC_DEFAULT_PROBE_NODE_NUM    (1024)

typedef struct bondp_hc_cfg {
    /*
     * Interval between two health probe batches.
     * Set to 0 to use BONDP_HC_DEFAULT_PROBE_INTERVAL_MS.
     */
    uint64_t probe_interval_ms;
    /*
     * Maximum nodes probed in one batch.
     * Set to 0 to use BONDP_HC_DEFAULT_PROBE_NODE_NUM.
     */
    uint32_t probe_node_num;
} bondp_hc_cfg_t;

int bondp_hc_init(struct bondp_context *bdp_ctx, const bondp_hc_cfg_t *cfg);
void bondp_hc_uninit(struct bondp_context *bdp_ctx);

/**
 * Register a target jetty for health path tracking.
 * The peer topo node is resolved by the target EID.
 */
int bondp_hc_register_tjetty(struct bondp_context *bdp_ctx,
                             struct bondp_target_jetty *bdp_tjetty);

/**
 * Unregister a target jetty from health path tracking.
 */
void bondp_hc_unregister_tjetty(struct bondp_context *bdp_ctx,
                                struct bondp_target_jetty *bdp_tjetty);

int bondp_hc_fill_seg_info(const struct bondp_context *bdp_ctx,
                           struct urma_bond_seg_info_out *seg_info,
                           bool *enabled);
int bondp_hc_import_tseg(const struct bondp_context *bdp_ctx,
                         struct bondp_target_jetty *bdp_tjetty,
                         const struct urma_bond_id_info_out *rjetty_info);
urma_status_t bondp_hc_unimport_tseg(struct bondp_target_jetty *bdp_tjetty);

/**
 * Synchronise the authoritative per-path node->valid matrix into the target
 * jetty's own valid matrix, skipping the path (skip_local_idx, skip_target_idx)
 * which is owned by the caller. No-op when health check is not registered for
 * this target jetty.
 */
void bondp_hc_tjetty_sync_valid(const struct bondp_target_jetty *bdp_tjetty,
                                uint32_t skip_local_idx, uint32_t skip_target_idx);

#ifdef __cplusplus
}
#endif

#endif // BONDP_HEALTH_H
