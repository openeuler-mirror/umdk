/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa service process dip table ops header file
 * Author: Chen Wen
 * Create: 2023-08-23
 * Note:
 * History: 2023-08-23 Chen Wen Initial version
 */
#ifndef DIP_TABLE_CFG_H
#define DIP_TABLE_CFG_H

#include <netinet/in.h>
#include "tpsa_service.h"
#include "tpsa_table.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_dip_table_show_req {
    urma_eid_t eid;
    uint32_t upi;
} tpsa_dip_table_show_req_t;

typedef struct tpsa_dip_table_show_rsp {
    int res;
    urma_eid_t eid;
    uint32_t upi;
    uvs_net_addr_t uvs_ip;
    uvs_net_addr_info_t net_addr;
} tpsa_dip_table_show_rsp_t;

typedef struct tpsa_dip_table_add_req {
    urma_eid_t eid;
    uint32_t upi;
    uvs_net_addr_t uvs_ip;
    uvs_net_addr_info_t net_addr;
} tpsa_dip_table_add_req_t;

typedef struct tpsa_dip_table_add_rsp {
    int32_t res;
} tpsa_dip_table_add_rsp_t;

typedef struct tpsa_dip_table_del_req {
    urma_eid_t eid;
    uint32_t upi;
} tpsa_dip_table_del_req_t;

typedef struct tpsa_dip_table_del_rsp {
    int32_t res;
} tpsa_dip_table_del_rsp_t;

typedef struct tpsa_dip_table_modify_req {
    urma_eid_t old_eid;
    uint32_t old_upi;
    urma_eid_t new_eid;
    uint32_t new_upi;
    uvs_net_addr_t new_uvs_ip;
    uvs_net_addr_info_t new_net_addr;
    dip_table_modify_mask_t mask;
} tpsa_dip_table_modify_req_t;

typedef struct tpsa_dip_table_modify_rsp {
    int32_t res;
} tpsa_dip_table_modify_rsp_t;

tpsa_response_t *process_dip_table_show(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_dip_table_add(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_dip_table_del(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_dip_table_modify(tpsa_request_t *req, ssize_t read_len);

#ifdef __cplusplus
}

#endif

#endif /* DIP_TABLE_CFG_H */
