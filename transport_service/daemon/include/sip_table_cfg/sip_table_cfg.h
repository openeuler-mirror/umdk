/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa service process sip table ops header file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#ifndef SIP_TABLE_CFG_H
#define SIP_TABLE_CFG_H

#include <netinet/in.h>
#include "tpsa_service.h"
#include "tpsa_table.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_sip_table_show_req {
    char tpf_name[UVS_MAX_DEV_NAME];
    uint32_t sip_idx;
} tpsa_sip_table_show_req_t;

typedef struct tpsa_sip_table_show_rsp {
    int res;
    uvs_net_addr_t net_addr;
    uint16_t vlan;
    uint8_t mac[ETH_ADDR_LEN];
    char dev_name[UVS_MAX_DEV_NAME];
    uint8_t port_cnt;
    uint8_t port_id[TPSA_PORT_CNT_MAX];
    bool net_addr_type;
    uint32_t prefix_len;
    uvs_mtu_t mtu;
} tpsa_sip_table_show_rsp_t;

typedef struct tpsa_sip_table_add_req {
    uvs_net_addr_t net_addr;
    uint16_t vlan;
    uint8_t mac[ETH_ADDR_LEN];
    char dev_name[UVS_MAX_DEV_NAME];
    uint8_t port_id;
    bool net_addr_type;
    uint32_t prefix_len;
    uvs_mtu_t mtu;
} tpsa_sip_table_add_req_t;

typedef struct tpsa_sip_table_add_rsp {
    int32_t res;
    uint32_t index;
} tpsa_sip_table_add_rsp_t;

typedef struct tpsa_sip_table_del_req {
    char tpf_name[UVS_MAX_DEV_NAME];
    uint32_t sip_idx;
} tpsa_sip_table_del_req_t;

typedef struct tpsa_sip_table_del_rsp {
    int32_t res;
} tpsa_sip_table_del_rsp_t;

tpsa_response_t *process_sip_table_show(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_sip_table_add(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_sip_table_del(tpsa_request_t *req, ssize_t read_len);


#ifdef __cplusplus
}

#endif

#endif /* SIP_TABLE_CFG_H */
