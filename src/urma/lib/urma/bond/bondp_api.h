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

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif
#endif // BONDP_API_H
