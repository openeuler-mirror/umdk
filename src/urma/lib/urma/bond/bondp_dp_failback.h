/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider failback helpers.
 */

#ifndef BONDP_DP_FAILBACK_H
#define BONDP_DP_FAILBACK_H

#include "bondp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool bondp_fb_need_switch_path(bondp_comp_t *bdp_comp);
uint32_t bondp_fb_switch_path(bondp_comp_t *bdp_comp);

/* Delay (ms) before rebuilding a failed-back pjetty on the bond worker. */
#define BONDP_FB_REBUILD_DELAY_MS 2000U

int bondp_fb_add_task(bondp_context_t *bond_ctx, uint32_t vjetty_id, uint32_t pjetty_idx,
                      uint32_t delay_ms, bool backup_rebuild);
void bondp_fb_cancel_tasks(bondp_context_t *bond_ctx, uint32_t vjetty_id);

int bondp_fb_init(bondp_context_t *bond_ctx);
void bondp_fb_uninit(bondp_context_t *bond_ctx);

#ifdef __cplusplus
}
#endif

#endif // BONDP_DP_FAILBACK_H
