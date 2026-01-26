/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq dfx
 * Create: 2025-10-29
 */

#ifndef UMQ_DFX_H
#define UMQ_DFX_H

#include <stdint.h>
#include <stdbool.h>

#include "umq_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int umq_dfx_init(umq_init_cfg_t *cfg);
void umq_dfx_uninit(void);

#ifdef __cplusplus
}
#endif

#endif