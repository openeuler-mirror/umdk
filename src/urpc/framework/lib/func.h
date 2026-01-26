/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc func
 */

#ifndef FUNC_H
#define FUNC_H

#include <stdint.h>
#include "urpc_framework_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int urpc_func_init(uint16_t device_class, uint16_t sub_class);
void urpc_func_uninit(void);
int urpc_func_info_get(void **addr, uint32_t *len);
int urpc_func_info_set(struct urpc_hmap *table, uint64_t addr, uint32_t len);
void urpc_func_tbl_release(struct urpc_hmap *func_table);

#ifdef __cplusplus
}
#endif

#endif