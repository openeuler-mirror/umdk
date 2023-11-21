/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of 'uvs_admin dip_table show/add/del' command
 * Author: Chen Wen
 * Create: 2023-08-23
 * Note:
 * History: 2023-08-23 Chen Wen Initial version
 */

#ifndef DIP_TABLE_CMD_H
#define DIP_TABLE_CMD_H

#include <netinet/in.h>
#include "urma_types.h"
#include "uvs_admin_cmd_util.h"
#include "uvs_admin_cmd.h"

union tpsa_dip_table_modify_mask {
    struct {
        uint32_t dip            : 1;
        uint32_t peer_tpsa      : 1;
        uint32_t underlay_eid   : 1;
        uint32_t netaddr        : 1;
        uint32_t reserved       : 28;
    } bs;
    uint32_t value;
};

typedef struct uvs_admin_dip_table_args {
    urma_eid_t dip;
    urma_eid_t peer_tpsa_ip;
    urma_eid_t underlay_eid;
    uvs_admin_net_addr_t net_addr;
    urma_eid_t new_dip;
    union tpsa_dip_table_modify_mask mask;
} uvs_admin_dip_table_args_t;

typedef struct uvs_admin_dip_table_show_req {
    urma_eid_t dip;
} uvs_admin_dip_table_show_req_t;

typedef struct uvs_admin_dip_table_show_rsp {
    int res;
    urma_eid_t dip;
    urma_eid_t peer_tpsa_ip;
    urma_eid_t underlay_eid;
    uvs_admin_net_addr_t net_addr;
} uvs_admin_dip_table_show_rsp_t;

typedef struct uvs_admin_dip_table_add_req {
    urma_eid_t dip;
    urma_eid_t peer_tpsa_ip;
    urma_eid_t underlay_eid;
    uvs_admin_net_addr_t net_addr;
} uvs_admin_dip_table_add_req_t;

typedef struct uvs_admin_dip_table_add_rsp {
    int32_t res;
} uvs_admin_dip_table_add_rsp_t;

typedef struct uvs_admin_dip_table_del_req {
    urma_eid_t dip;
} uvs_admin_dip_table_del_req_t;

typedef struct uvs_admin_dip_table_del_rsp {
    int32_t res;
} uvs_admin_dip_table_del_rsp_t;

typedef struct uvs_admin_dip_table_modify_req {
    urma_eid_t old_dip;
    urma_eid_t new_dip;
    urma_eid_t new_peer_tpsa;
    urma_eid_t new_underlay_eid;
    uvs_admin_net_addr_t new_netaddr;
    union tpsa_dip_table_modify_mask mask;
} uvs_admin_dip_table_modify_req_t;

typedef struct uvs_admin_dip_table_modify_rsp {
    int32_t res;
} uvs_admin_dip_table_modify_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_dip_table_cmd;

#endif /* DIP_TABLE_CMD_H */
