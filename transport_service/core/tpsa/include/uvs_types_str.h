/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: UVS type string header file
 * Author: Zheng Hongqin
 * Create: 2023-10-16
 * Note:
 * History:
 */

#ifndef UVS_TYPES_STR_H
#define UVS_TYPES_STR_H
#include "uvs_types.h"

static const char * const g_uvs_mtu_str[] = {
    [UVS_MTU_256] = "256",
    [UVS_MTU_512] = "512",
    [UVS_MTU_1024] = "1024",
    [UVS_MTU_2048] = "2048",
    [UVS_MTU_4096] = "4096",
    [UVS_MTU_8192] = "8192",
};

static inline const char *uvs_mtu_to_str(uvs_mtu_t mtu)
{
    if (mtu < UVS_MTU_256 || mtu > UVS_MTU_8192) {
        return "Invalid Value";
    }
    return g_uvs_mtu_str[mtu];
}

#endif