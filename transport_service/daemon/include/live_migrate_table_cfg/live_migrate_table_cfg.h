/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa vport table config header file
 * Author: Sun Fang
 * Create: 2023-08-02
 * Note:
 * History: 2023-08-02 Sun Fang Initial version
 */
#ifndef LIVE_MIGRATE_TABLE_CFG_H
#define LIVE_MIGRATE_TABLE_CFG_H

#include <netinet/in.h>
#include "tpsa_service.h"
#include "tpsa_table.h"
#include "uvs_lm_table.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_live_migrate_show_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
} tpsa_live_migrate_show_req_t;

typedef struct tpsa_live_migrate_show_rsp {
    int res;
    urma_eid_t dip;
    int flag;
    char dev_name[TPSA_MAX_DEV_NAME];
} tpsa_live_migrate_show_rsp_t;

typedef struct tpsa_live_migrate_add_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
    urma_eid_t dip;
} tpsa_live_migrate_add_req_t;

typedef struct tpsa_live_migrate_add_rsp {
    int32_t res;
} tpsa_live_migrate_add_rsp_t;

typedef struct tpsa_live_migrate_del_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
} tpsa_live_migrate_del_req_t;

typedef struct tpsa_live_migrate_del_rsp {
    int32_t res;
} tpsa_live_migrate_del_rsp_t;

tpsa_response_t *process_live_migrate_table_show(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_live_migrate_table_add(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_live_migrate_table_del(tpsa_request_t *req, ssize_t read_len);

#ifdef __cplusplus
}

#endif

#endif /* LIVE_MIGRATE_TABLE_CFG_H */
