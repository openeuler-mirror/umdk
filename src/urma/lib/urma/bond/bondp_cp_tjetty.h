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
#include "bondp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline bondp_p_target_jetty_t *bondp_find_p_tjetty(bondp_target_jetty_t *t,
                                                          uint32_t local_idx, uint32_t target_idx)
{
    for (uint32_t i = 0; i < t->p_tjetty_count; i++) {
        if (t->p_tjettys[i].local_indice == (uint8_t)local_idx &&
            t->p_tjettys[i].remote_indice == (uint8_t)target_idx) {
            return &t->p_tjettys[i];
        }
    }
    return NULL;
}

static inline const bondp_p_target_jetty_t *bondp_find_p_tjetty_const(const bondp_target_jetty_t *t,
                                                                      uint32_t local_idx, uint32_t target_idx)
{
    for (uint32_t i = 0; i < t->p_tjetty_count; i++) {
        if (t->p_tjettys[i].local_indice == (uint8_t)local_idx &&
            t->p_tjettys[i].remote_indice == (uint8_t)target_idx) {
            return &t->p_tjettys[i];
        }
    }
    return NULL;
}

static inline bool bondp_p_tjetty_available(const bondp_p_target_jetty_t *path)
{
    return path != NULL && atomic_load(&path->valid) && path->p_tjetty != NULL;
}

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
