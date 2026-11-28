/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider cold/hot standby pjetty manager
 */

#ifndef BONDP_CP_COLDHOT_H
#define BONDP_CP_COLDHOT_H

#include <stdbool.h>
#include <stdint.h>

#include "bondp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Lazily create the single global cold/hot manager thread. Idempotent. */
int bondp_coldhot_start(void);

/* Stop and destroy the global manager thread. Called on provider uninit. */
void bondp_coldhot_stop(void);

/* Post a fault event: the pjetty at pjetty_idx failed and must be removed, then
 * the highest-priority COLD candidate is promoted and pending WRs are replayed. */
int bondp_coldhot_post_fault(bondp_context_t *bdp_ctx, uint32_t vjetty_id, uint32_t pjetty_idx);

/* Post a failback event: the local path at pjetty_idx recovered. If it is a
 * higher-priority COLD candidate than the lowest-priority HOT, swap them. */
int bondp_coldhot_post_failback(bondp_context_t *bdp_ctx, uint32_t vjetty_id, uint32_t pjetty_idx);

/* Apply the current hot_pjetty_cnt of the vjetty (promote/demote to match). */
int bondp_coldhot_post_reconcile(bondp_context_t *bdp_ctx, uint32_t vjetty_id);

/* Drop pending events that reference bdp_ctx (context teardown). */
void bondp_coldhot_cancel_ctx(bondp_context_t *bdp_ctx);

/* True when at least one enabled pjetty of the component is in COLD state. */
bool bondp_coldhot_has_cold(const bondp_comp_t *bdp_comp);

/* Activate a COLD pjetty: create it if needed, then publish it as HOT.
 * Returns 0 on success. Caller must not hold send_lock. */
int bondp_coldhot_activate_cold(bondp_comp_t *bdp_comp, uint32_t pjetty_idx);

#ifdef __cplusplus
}
#endif

#endif // BONDP_CP_COLDHOT_H
