/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: liburma_bond main file
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05
 */

#include "bondp_provider_ops.h"
#include "urma_log.h"
#include "urma_provider.h"

static urma_provider_ops_t g_bondp_provider_ops = {
    .name = "ub_agg",
    .attr = {
        .version = 0,
        .transport_type = URMA_TRANSPORT_UB,
    },
    .match_table = NULL,
    .init = bondp_init,
    .uninit = bondp_uninit,
    .query_device = NULL,
    .create_context = bondp_create_context,
    .delete_context = bondp_delete_context,
    .get_uasid = NULL,
};

static __attribute__((constructor)) void urma_provider_bond_init(void)
{
    int ret;

    ret = urma_register_provider_ops(&g_bondp_provider_ops);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to register bond provider ops during so load, ret=%d.\n", ret);
    }
    return;
}

static __attribute__((destructor)) void urma_provider_bond_uninit(void)
{
    int ret;
    ret = urma_unregister_provider_ops(&g_bondp_provider_ops);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to unregister bond provider ops during so unload, ret=%d.\n", ret);
    }
    return;
}
