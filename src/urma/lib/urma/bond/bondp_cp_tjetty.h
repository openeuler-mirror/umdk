/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bonding provider control-plane target jetty interface
 * Create: 2026-07-21
 * Note:
 * History: 2026-07-21  Create file
 */

#ifndef BONDP_CP_TJETTY_H
#define BONDP_CP_TJETTY_H

#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void bondp_tjetty_get(urma_target_jetty_t *target_jetty);
void bondp_tjetty_put(urma_target_jetty_t *target_jetty);

int bondp_get_rjetty(urma_context_t *ctx, urma_user_ctl_in_t *in,
                     urma_user_ctl_out_t *out);

/* Provider ops */
urma_target_jetty_t *bondp_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty,
                                        urma_token_t *rjetty_token);
urma_status_t bondp_unimport_jetty(urma_target_jetty_t *target_jetty);

urma_status_t bondp_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);
urma_status_t bondp_unbind_jetty(urma_jetty_t *jetty);

urma_target_jetty_t *bondp_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token);
urma_status_t bondp_unimport_jfr(urma_target_jetty_t *target_jfr);

#ifdef __cplusplus
}
#endif

#endif // BONDP_CP_TJETTY_H
