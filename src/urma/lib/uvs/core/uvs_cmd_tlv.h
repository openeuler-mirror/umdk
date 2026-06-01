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

#define UVS_CMD_OUT_TYPE_INIT 0x80 // 128B

typedef struct uvs_cmd_attr {
    uint8_t type; /* See uvs_cmd_xxx_type_t */
    uint8_t flag;
    uint16_t field_size;
    union {
        struct {
            uint32_t el_num  : 20; /* Array element number if field is in an array */
            uint32_t el_size : 12; /* Array element size if field is in an array */
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

typedef enum uvs_cmd_get_topo_type {
    /* In type */
    GET_TOPO_OUT_TOPO_MAP,
    GET_TOPO_OUT_NUM /* Only for calculating number of types */
} uvs_cmd_get_topo_type_t;

typedef enum uvs_cmd_get_route_list_type {
    GET_ROUTE_LIST_IN_ROUTE_PAIR,
    GET_ROUTE_LIST_IN_NUM,
    GET_ROUTE_LIST_OUT_ROUTE_LIST = UVS_CMD_OUT_TYPE_INIT,
    GET_ROUTE_LIST_OUT_NUM
} uvs_cmd_get_route_list_type_t;

typedef enum uvs_cmd_set_path_set_type {
    GET_PATH_SET_IN_SRC_BONDING_EID,
    GET_PATH_SET_IN_DST_BONDING_EID,
    GET_PATH_SET_IN_TP_TYPE,
    GET_PATH_SET_IN_MULTI_PATH,
    GET_PATH_SET_IN_NUM,
    GET_PATH_LIST_OUT_PATH_SET = UVS_CMD_OUT_TYPE_INIT,
    GET_PATH_SET_OUT_NUM
} uvs_cmd_set_path_set_type_t;

typedef enum uvs_cmd_insert_main_ue_eid_type {
    INSERT_MAIN_UE_EID_IN_ENTRY,
    INSERT_MAIN_UE_EID_IN_NUM
} uvs_cmd_insert_main_ue_eid_type_t;

typedef enum uvs_cmd_delete_main_ue_eid_type {
    DELETE_MAIN_UE_EID_IN_EID,
    DELETE_MAIN_UE_EID_IN_NUM
} uvs_cmd_delete_main_ue_eid_type_t;

typedef enum uvs_cmd_lookup_main_ue_eid_type {
    LOOKUP_MAIN_UE_EID_IN_EID,
    LOOKUP_MAIN_UE_EID_IN_NUM,
    LOOKUP_MAIN_UE_EID_OUT_MAIN_UE_EID = UVS_CMD_OUT_TYPE_INIT,
    LOOKUP_MAIN_UE_EID_OUT_NUM
} uvs_cmd_lookup_main_ue_eid_type_t;

typedef enum uvs_cmd_flush_main_ue_eid_type {
    FLUSH_MAIN_UE_EID_OUT_STATUS = UVS_CMD_OUT_TYPE_INIT,
    FLUSH_MAIN_UE_EID_OUT_NUM
} uvs_cmd_flush_main_ue_eid_type_t;

typedef enum uvs_cmd_insert_main_ue_eid_batch_type {
    INSERT_MAIN_UE_EID_BATCH_IN_ENTRY,
    INSERT_MAIN_UE_EID_BATCH_IN_NUM
} uvs_cmd_insert_main_ue_eid_batch_type_t;

#ifdef __cplusplus
}
#endif

#endif
