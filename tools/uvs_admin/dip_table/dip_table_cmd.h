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
        uint32_t eid            : 1;
        uint32_t upi            : 1;
        uint32_t uvs_ip         : 1;
        uint32_t net_addr       : 1;
        uint32_t reserved       : 28;
    } bs;
    uint32_t value;
};

typedef struct uvs_admin_dip_table_args {
    urma_eid_t eid;
    uint32_t upi;
    uvs_admin_net_addr_t uvs_ip;
    uvs_admin_net_addr_info_t net_addr;
    urma_eid_t new_eid;
    uint32_t new_upi;
    union tpsa_dip_table_modify_mask mask;
} uvs_admin_dip_table_args_t;

typedef struct uvs_admin_dip_table_show_req {
    urma_eid_t eid;
    uint32_t upi;
} uvs_admin_dip_table_show_req_t;

typedef struct uvs_admin_dip_table_show_rsp {
    int res;
    urma_eid_t eid;
    uint32_t upi;
    uvs_admin_net_addr_t uvs_ip;
    uvs_admin_net_addr_info_t net_addr;
} uvs_admin_dip_table_show_rsp_t;

typedef struct uvs_admin_dip_table_add_req {
    urma_eid_t eid;
    uint32_t upi;
    uvs_admin_net_addr_t uvs_ip;
    uvs_admin_net_addr_info_t net_addr;
} uvs_admin_dip_table_add_req_t;

typedef struct uvs_admin_dip_table_add_rsp {
    int32_t res;
} uvs_admin_dip_table_add_rsp_t;

typedef struct uvs_admin_dip_table_del_req {
    urma_eid_t eid;
    uint32_t upi;
} uvs_admin_dip_table_del_req_t;

typedef struct uvs_admin_dip_table_del_rsp {
    int32_t res;
} uvs_admin_dip_table_del_rsp_t;

typedef struct uvs_admin_dip_table_modify_req {
    urma_eid_t old_eid;
    uint32_t old_upi;
    urma_eid_t new_eid;
    uint32_t new_upi;
    uvs_admin_net_addr_t new_uvs_ip;
    uvs_admin_net_addr_info_t new_net_addr;
    union tpsa_dip_table_modify_mask mask;
} uvs_admin_dip_table_modify_req_t;

typedef struct uvs_admin_dip_table_modify_rsp {
    int32_t res;
} uvs_admin_dip_table_modify_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_dip_table_cmd;

#endif /* DIP_TABLE_CMD_H */
