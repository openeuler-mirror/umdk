/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of 'uvs_admin sip_table show/add/del' command
 * Author: Ji Lei
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14 Ji Lei Initial version
 */

#ifndef SIP_TABLE_CMD_H
#define SIP_TABLE_CMD_H

#include <netinet/in.h>
#include "urma_types.h"
#include "uvs_admin_cmd_util.h"
#include "uvs_admin_cmd.h"
#include "uvs_admin_types.h"

typedef union uvs_admin_sip_table_mask {
    struct {
        uint64_t sip_idx          : 1;
        uint64_t net_addr         : 1;
        uint64_t vlan             : 1;
        uint64_t mac              : 1;
        uint64_t dev_name         : 1;
        uint64_t port_id          : 1;
        uint64_t net_addr_type    : 1;
        uint64_t prefix_len       : 1;
        uint64_t mtu              : 1;
        uint64_t reserved         : 23;
    } bs;
    uint32_t value;
} uvs_admin_sip_table_mask_t;

typedef struct uvs_admin_sip_table_args {
    uint32_t sip_idx;
    uvs_admin_net_addr_t net_addr;
    uint16_t vlan;
    uint8_t mac[UVS_ADMIN_MAC_BYTES];
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint8_t port_id;
    bool net_addr_type;
    uint32_t prefix_len;
    uvs_admin_mtu_t mtu;
    uvs_admin_sip_table_mask_t mask;
    uvs_admin_net_addr_type_t input_net_type;
} uvs_admin_sip_table_args_t;

typedef struct uvs_admin_sip_table_show_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint32_t sip_idx;
} uvs_admin_sip_table_show_req_t;

typedef struct uvs_admin_sip_table_show_rsp {
    int res;
    uvs_admin_net_addr_t net_addr;
    uint16_t vlan;
    uint8_t mac[UVS_ADMIN_MAC_BYTES];
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint8_t port_cnt;
    uint8_t port[UVS_ADMIN_PORT_CNT_MAX];
    bool net_addr_type;
    uint32_t prefix_len;
    uvs_admin_mtu_t mtu;
} uvs_admin_sip_table_show_rsp_t;

typedef struct uvs_admin_sip_table_add_req {
    uvs_admin_net_addr_t net_addr;
    uint16_t vlan;
    uint8_t mac[UVS_ADMIN_MAC_BYTES];
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint8_t port_id;
    bool net_addr_type;
    uint32_t prefix_len;
    uvs_admin_mtu_t mtu;
} uvs_admin_sip_table_add_req_t;

typedef struct uvs_admin_sip_table_add_rsp {
    int32_t res;
    uint32_t index;
} uvs_admin_sip_table_add_rsp_t;

typedef struct uvs_admin_sip_table_del_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint32_t sip_idx;
} uvs_admin_sip_table_del_req_t;

typedef struct uvs_admin_sip_table_del_rsp {
    int32_t res;
} uvs_admin_sip_table_del_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_sip_table_cmd;

#endif /* SIP_TABLE_CMD_H */
