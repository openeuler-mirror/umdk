/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UVS API
 * Author: Zheng Hongqin
 * Create: 2025-11-21
 * Note:
 * History:
 */

#ifndef UVS_TYPES_H
#define UVS_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_EID_SIZE 16

typedef union uvs_eid {
    uint8_t raw[UVS_EID_SIZE]; /* Network Order */
    struct {
        uint64_t resv;
        uint32_t prefix;
        uint32_t addr;
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} uvs_eid_t;

#ifdef __cplusplus
}
#endif

#endif