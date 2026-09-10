/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond RNR retry helpers.
 */

#ifndef BONDP_DP_RNR_RETRY_H
#define BONDP_DP_RNR_RETRY_H

#include <stdbool.h>
#include <stdint.h>

struct bondp_comp;

/* Caller must hold bdp_comp->send_lock. */
int bondp_rnr_retry_schedule(struct bondp_comp *bdp_comp, uint32_t send_idx,
                             uint32_t retry_cnt, bool *new_task);

/* Return the number of scheduled tasks currently holding a component reference. */
uint32_t bondp_rnr_retry_pending_task_num(struct bondp_comp *bdp_comp);

/* Cancel all scheduled tasks. The caller must prevent new tasks from being scheduled. */
int bondp_rnr_retry_cancel_all(struct bondp_comp *bdp_comp);

#endif /* BONDP_DP_RNR_RETRY_H */
