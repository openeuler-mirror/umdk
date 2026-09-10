/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bonding provider control-plane user control interface
 * Create: 2026-07-22
 * Note:
 * History: 2026-07-22  Create file
 */

#ifndef BONDP_CP_USER_CTL_H
#define BONDP_CP_USER_CTL_H

#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int bondp_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out);

#ifdef __cplusplus
}
#endif

#endif // BONDP_CP_USER_CTL_H
