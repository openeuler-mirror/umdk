/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ IPC share memory function
 * Create: 2025-8-28
 * Note:
 * History: 2025-8-28
 */

#ifndef UMQ_IPC_API_H
#define UMQ_IPC_API_H

#include "umq_tp_api.h"
#include "umq_pro_tp_api.h"
#include "umq_tp_dfx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

umq_ops_t *umq_ipc_ops_get(void);
umq_pro_ops_t *umq_pro_ipc_ops_get(void);
umq_dfx_ops_t *umq_ipc_dfx_ops_get(void);

umq_ops_t *umq_ipc_plus_ops_get(void);
umq_pro_ops_t *umq_pro_ipc_plus_ops_get(void);
umq_dfx_ops_t *umq_ipc_plus_dfx_ops_get(void);

#ifdef __cplusplus
}
#endif

#endif
