/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs types header file
 * Author: Zheng Hongqin
 * Create: 2023-10-11
 * Note:
 * History:
 */

#ifndef UVS_TYPES_H
#define UVS_TYPES_H

#include <stdint.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uvs_init_attr {
    struct in_addr server_ip;
    uint16_t server_port;
} uvs_init_attr_t;

typedef enum uvs_mtu {
    UVS_MTU_256      = 1,
    UVS_MTU_512,
    UVS_MTU_1024,
    UVS_MTU_2048,
    UVS_MTU_4096,
    UVS_MTU_8192,
    UVS_MTU_CNT
} uvs_mtu_t;

/* global info data structure */
typedef union uvs_global_flag {
    struct {
        uint32_t pattern : 2;  // pattern 1 or pattern 3
        uint32_t um_en : 1;    // UM mode enable
        uint32_t resereved : 29;
    } bs;
    uint32_t value;
} uvs_global_flag_t;

typedef union uvs_global_mask {
    struct {
        uint32_t mtu : 1;
        uint32_t slice : 1;
        uint32_t suspend_period : 1;
        uint32_t suspend_cnt : 1;
        uint32_t sus2err_period : 1;
        uint32_t flag_pattern : 1;
        uint32_t flag_um_en : 1;
        uint32_t resereved : 25;
    } bs;
    uint32_t value;
} uvs_global_mask_t;

typedef struct uvs_global_info {
    uvs_global_mask_t mask;

    uvs_mtu_t mtu;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
    uvs_global_flag_t flag;
} uvs_global_info_t;

typedef struct uvs_global_mod_info {
    uvs_global_mask_t mask;  // can modify anything!

    uvs_mtu_t mtu;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
    uvs_global_flag_t flag;
} uvs_global_mod_info_t;

#ifdef __cplusplus
}
#endif

#endif
