/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ UB function
 * Create: 2025-7-7
 * Note:
 * History: 2025-7-7
 */

#ifndef UMQ_UB_API_H
#define UMQ_UB_API_H

#include "umq_tp_api.h"
#include "umq_pro_tp_api.h"
#include "umq_tp_dfx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

umq_ops_t *umq_ub_ops_get(void);
umq_pro_ops_t *umq_pro_ub_ops_get(void);
umq_dfx_ops_t *umq_ub_dfx_ops_get(void);

umq_ops_t *umq_ub_plus_ops_get(void);
umq_pro_ops_t *umq_pro_ub_plus_ops_get(void);
umq_dfx_ops_t *umq_ub_plus_dfx_ops_get(void);

#ifdef __cplusplus
}
#endif

#endif
