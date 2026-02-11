/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ UB share memory function
 * Create: 2025-7-7
 * Note:
 * History: 2025-7-7
 */

#ifndef UMQ_UBMM_API_H
#define UMQ_UBMM_API_H

#include "umq_tp_api.h"
#include "umq_pro_tp_api.h"
#include "umq_tp_dfx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

umq_ops_t *umq_ubmm_ops_get(void);
umq_pro_ops_t *umq_pro_ubmm_ops_get(void);
umq_dfx_ops_t *umq_ubmm_dfx_ops_get(void);

umq_ops_t *umq_ubmm_plus_ops_get(void);
umq_pro_ops_t *umq_pro_ubmm_plus_ops_get(void);
umq_dfx_ops_t *umq_ubmm_plus_dfx_ops_get(void);

#ifdef __cplusplus
}
#endif

#endif
