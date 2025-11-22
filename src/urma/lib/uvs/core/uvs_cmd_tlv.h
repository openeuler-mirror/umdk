/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * Description: uvs cmd tlv parse header
 * Author: Chen Yutao
 * Create: 2024-08-06
 * Note:
 * History: 2024-08-06 create this file to support uvs cmd tlv
 */

#ifndef UVS_CMD_TLV_H
#define UVS_CMD_TLV_H

#include <stdint.h>

#include "tpsa_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_CMD_OUT_TYPE_INIT 0x80

typedef struct uvs_cmd_attr {
    uint8_t type; /* See uvs_cmd_xxx_type_t */
    uint8_t flag;
    uint16_t field_size;
    union {
        struct {
            uint32_t el_num   : 20; /* Array element number if field is in an array */
            uint32_t el_size  : 12; /* Array element size if field is in an array */
        } bs;
        uint32_t value;
    } attr_data;
    uint64_t data;
} uvs_cmd_attr_t;

typedef enum uvs_cmd_set_topo_type {
    /* In type */
    SET_TOPO_IN_TOPO_INFO,
    SET_TOPO_IN_TOPO_NUM,
    SET_TOPO_IN_NUM /* Only for calculating number of types */
} uvs_cmd_set_topo_type_t;

typedef enum uvs_cmd_get_topo_eid_type {
    GET_TOPO_EID_IN_TP_TYPE,
    GET_TOPO_EID_IN_SRC_V_EID,
    GET_TOPO_EID_IN_DST_V_EID,
    GET_TOPO_EID_IN_NUM, /* Only for calculating number of types */
    GET_TOPO_EID_OUT_SRC_P_EID = UVS_CMD_OUT_TYPE_INIT,
    GET_TOPO_EID_OUT_DST_P_EID,
    GET_TOPO_EID_OUT_NUM
} uvs_cmd_get_topo_eid_type_t;

#ifdef __cplusplus
}
#endif

#endif
