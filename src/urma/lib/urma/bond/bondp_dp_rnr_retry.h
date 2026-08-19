/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond RNR retry helpers.
 */

#ifndef BONDP_DP_RNR_RETRY_H
#define BONDP_DP_RNR_RETRY_H

#include <stdint.h>

struct bondp_context;

void bondp_rnr_retry_sleep_before_resend(const struct bondp_context *bdp_ctx, uint32_t retry_cnt);

#endif /* BONDP_DP_RNR_RETRY_H */
