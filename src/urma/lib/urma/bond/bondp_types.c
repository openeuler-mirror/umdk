/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Implementation of bonding provider support functions in bondp_types
 * Author: Ma Chuan
 * Create: 2025-02-12
 * Note:
 * History: 2025-02-12  Create file
 */
#include "bondp_types.h"

bool is_valid_ctx(bondp_context_t *ctx)
{
    return ctx && is_valid_dev_num(ctx->dev_num);
}

bool is_valid_bdp_tjetty(bondp_target_jetty_t *bdp_tjetty)
{
    return bdp_tjetty;
}

bool is_valid_import_tseg(bondp_import_tseg_t *rtseg)
{
    return rtseg;
}
