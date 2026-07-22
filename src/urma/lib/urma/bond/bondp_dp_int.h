/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bonding provider datapath interrupt interface
 * Create: 2026-07-21
 * Note:
 * History: 2026-07-21  Create file
 */

#ifndef BONDP_DP_INT_H
#define BONDP_DP_INT_H

#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Provider ops */
urma_status_t bondp_rearm_jfc(urma_jfc_t *jfc, bool solicited_only);

int bondp_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);

void bondp_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

urma_status_t bondp_get_async_event(urma_context_t *ctx, urma_async_event_t *event);
void bondp_ack_async_event(urma_async_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // BONDP_DP_INT_H
