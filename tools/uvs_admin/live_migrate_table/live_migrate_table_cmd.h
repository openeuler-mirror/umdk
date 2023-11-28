/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of 'uvs_admin live_migrate xxx' command
 * Author: Sun Fang
 * Create: 2023-08-02
 * Note:
 * History: 2023-08-02 Sun Fang Initial version
 */

#ifndef LIVE_MIGRATE_TABLE_CMD_H
#define LIVE_MIGRATE_TABLE_CMD_H

#include <netinet/in.h>
#include "uvs_admin_cmd.h"
#include "uvs_admin_types.h"
#include "urma_types.h"

typedef union uvs_admin_lm_table_mask {
    struct {
        uint32_t dev_name            : 1;
        uint32_t fe_idx              : 1;
        uint32_t dip                 : 1;
        uint32_t reserved            : 29;
    } bs;
    uint32_t value;
} uvs_admin_lm_table_mask_t;
typedef struct uvs_admin_live_migrate_table_args {
    uvs_admin_lm_table_mask_t mask;
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    urma_eid_t dip;
} uvs_admin_live_migrate_table_args_t;

typedef struct uvs_admin_live_migrate_table_show_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
} uvs_admin_live_migrate_table_show_req_t;

typedef struct uvs_admin_live_migrate_table_show_rsp {
    int res;
    urma_eid_t dip;
    int flag;
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
} uvs_admin_live_migrate_table_show_rsp_t;

typedef struct uvs_admin_live_migrate_table_add_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    urma_eid_t dip;
} uvs_admin_live_migrate_table_add_req_t;

typedef struct uvs_admin_live_migrate_table_add_rsp {
    int32_t res;
} uvs_admin_live_migrate_table_add_rsp_t;

typedef struct uvs_admin_live_migrate_table_del_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
} uvs_admin_live_migrate_table_del_req_t;

typedef struct uvs_admin_live_migrate_table_del_rsp {
    int32_t res;
} uvs_admin_live_migrate_table_del_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_live_migrate_table_cmd;

#endif /* LIVE_MIGRATE_TABLE_CMD_H */
