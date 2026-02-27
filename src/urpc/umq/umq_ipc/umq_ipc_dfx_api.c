/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: realize func for umq ipc dfx api
 * Create: 2026-2-11
 * Note:
 * History: 2026-2-11
 */

#include "umq_tp_dfx_api.h"

static umq_dfx_ops_t g_umq_ipc_dfx_ops = {
    .mode = UMQ_TRANS_MODE_IPC,
};

umq_dfx_ops_t *umq_ipc_dfx_ops_get(void)
{
    return &g_umq_ipc_dfx_ops;
}