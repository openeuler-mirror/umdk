/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond device ops header file
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05   Create File
 */

#ifndef BONDP_PROVIDER_OPS_H
#define BONDP_PROVIDER_OPS_H

#include "urma_types.h"
#include "urma_ubagg.h"

#ifdef __cplusplus
extern "C" {
#endif

urma_context_t *bondp_create_context(urma_device_t *dev, uint32_t eid_index, int dev_fd);

urma_status_t bondp_delete_context(urma_context_t *ctx);

int bondp_set_bonding_mode(urma_context_t *ctx, bondp_bonding_mode_t bonding_mode,
                        bondp_bonding_level_t bonding_level);

urma_status_t bondp_init(urma_init_attr_t *conf);

urma_status_t bondp_uninit(void);

#ifdef __cplusplus
}
#endif
#endif // BONDP_PROVIDER_OPS_H
