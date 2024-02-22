/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa vport table config header file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#ifndef VPORT_TABLE_CFG_H
#define VPORT_TABLE_CFG_H

#include <netinet/in.h>
#include "tpsa_service.h"
#include "tpsa_table.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union uvs_vport_args_mask {
    struct {
        uint64_t dev_name            : 1;
        uint64_t fe_idx              : 1;
        uint64_t sip_idx             : 1;
        uint64_t tp_cnt              : 1;
        uint64_t flow_label          : 1;
        uint64_t oor_cnt             : 1;
        uint64_t retry_num           : 1;
        uint64_t retry_factor        : 1;
        uint64_t ack_timeout         : 1;
        uint64_t dscp                : 1;
        uint64_t cc_pattern_idx      : 1;
        uint64_t data_udp_start      : 1;
        uint64_t ack_udp_start       : 1;
        uint64_t udp_range           : 1;
        uint64_t hop_limit           : 1;
        uint64_t port                : 1;
        uint64_t mn                  : 1;
        uint64_t loop_back           : 1;
        uint64_t ack_resp            : 1;
        uint64_t bonding             : 1;
        uint64_t oos_cnt             : 1;
        uint64_t rc_cnt              : 1;
        uint64_t rc_depth            : 1;
        uint64_t slice               : 1;
        uint64_t eid                 : 1;
        uint64_t eid_index           : 1;
        uint64_t upi                 : 1;
        uint64_t pattern             : 1;
        uint64_t virtualization      : 1;
        uint64_t min_jetty_cnt       : 1;
        uint64_t max_jetty_cnt       : 1;
        uint64_t min_jfr_cnt         : 1;
        uint64_t max_jfr_cnt         : 1;
        uint64_t reserved            : 27;
    } bs;
    uint64_t value;
} uvs_vport_args_mask_t;

typedef struct tpsa_vport_args {
    uvs_vport_args_mask_t mask;
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t sip_idx;
    uint32_t tp_cnt;
    tpsa_tp_mod_cfg_t tp_cfg;
    tpsa_rc_cfg_t rc_cfg;
    urma_eid_t eid;
    uint32_t eid_index;
    uint32_t upi;
    uint32_t pattern;
    uint32_t virtualization;
    uint32_t min_jetty_cnt;
    uint32_t max_jetty_cnt;
    uint32_t min_jfr_cnt;
    uint32_t max_jfr_cnt;
} tpsa_vport_args_t;

typedef struct tpsa_vport_show_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
} tpsa_vport_show_req_t;

typedef struct tpsa_vport_show_rsp {
    int res;
    tpsa_vport_args_t args;
} tpsa_vport_show_rsp_t;

typedef struct tpsa_vport_add_req {
    tpsa_vport_args_t args;
} tpsa_vport_add_req_t;

typedef struct tpsa_vport_add_rsp {
    int32_t res;
} tpsa_vport_add_rsp_t;

typedef struct tpsa_vport_del_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
} tpsa_vport_del_req_t;

typedef struct tpsa_vport_del_rsp {
    int32_t res;
} tpsa_vport_del_rsp_t;

typedef struct tpsa_vport_show_ueid_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t eid_index;
} tpsa_vport_show_ueid_req_t;

typedef struct tpsa_vport_show_ueid_rsp {
    int res;
    uint32_t upi;
    urma_eid_t eid;
} tpsa_vport_show_ueid_rsp_t;

typedef struct tpsa_vport_add_ueid_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t upi;
    urma_eid_t eid;
    uint32_t eid_index;
} tpsa_vport_add_ueid_req_t;

typedef struct tpsa_vport_add_ueid_rsp {
    int32_t res;
} tpsa_vport_add_ueid_rsp_t;

typedef struct tpsa_vport_del_ueid_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t eid_index;
} tpsa_vport_del_ueid_req_t;

typedef struct tpsa_vport_del_ueid_rsp {
    int32_t res;
} tpsa_vport_del_ueid_rsp_t;

typedef struct tpsa_set_upi_req {
    uint32_t upi;
    char dev_name[TPSA_MAX_DEV_NAME];
} tpsa_set_upi_req_t;

typedef struct tpsa_set_upi_rsp {
    int32_t res;
} tpsa_set_upi_rsp_t;

typedef struct tpsa_show_upi_req {
    char dev_name[TPSA_MAX_DEV_NAME];
} tpsa_show_upi_req_t;

typedef struct tpsa_show_upi_rsp {
    int32_t res;
    uint32_t upi;
} tpsa_show_upi_rsp_t;

tpsa_response_t *process_vport_table_show(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_add(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_del(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_show_ueid(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_add_ueid(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_del_ueid(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_set_upi(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_vport_table_show_upi(tpsa_request_t *req, ssize_t read_len);

#ifdef __cplusplus
}

#endif

#endif /* VPORT_TABLE_CFG_H */
