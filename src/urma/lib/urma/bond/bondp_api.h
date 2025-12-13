/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond API header
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05   Create File
 */

#ifndef BONDP_API_H
#define BONDP_API_H

#include "urma_types.h"

/* Bonding jetty ops */
urma_jfce_t *bondp_create_jfce(urma_context_t *ctx);

urma_status_t bondp_delete_jfce(urma_jfce_t *jfc);

urma_jfc_t *bondp_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg);

urma_status_t bondp_delete_jfc(urma_jfc_t *jfc);

urma_status_t bondp_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr);

urma_jfs_t *bondp_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg);

urma_status_t bondp_delete_jfs(urma_jfs_t *jfs);

urma_status_t bondp_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr);

urma_jfr_t *bondp_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg);

urma_status_t bondp_delete_jfr(urma_jfr_t *jfr);

urma_status_t bondp_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr);

urma_status_t bondp_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr);

urma_jetty_t *bondp_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg);

urma_status_t bondp_delete_jetty(urma_jetty_t *jetty);

urma_status_t bondp_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr);

urma_target_jetty_t *bondp_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty,
    urma_token_t *rjetty_token);

urma_status_t bondp_unimport_jetty(urma_target_jetty_t *target_jetty);

urma_status_t bondp_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

urma_status_t bondp_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

urma_status_t bondp_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

urma_status_t bondp_unbind_jetty(urma_jetty_t *jetty);

urma_target_jetty_t *bondp_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token);

urma_status_t bondp_unimport_jfr(urma_target_jetty_t *target_jfr);

/* Jfce ops */

urma_status_t bondp_rearm_jfc(urma_jfc_t *jfc, bool solicited_only);

int bondp_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);

void bondp_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

/* event */
urma_status_t bondp_get_async_event(urma_context_t *ctx, urma_async_event_t *event);
void bondp_ack_async_event(urma_async_event_t *event);

/* Other ops */
int bondp_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out);

int bondp_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);
#endif // BONDP_API_H