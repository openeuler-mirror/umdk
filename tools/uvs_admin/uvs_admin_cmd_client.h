/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of generic client ops of uvs_admin
 * Author: Ji Lei
 * Create: 2023-07-11
 * Note:
 * History: 2023-07-11 Ji Lei Initial version
 */

#ifndef UVS_ADMIN_CMD_CLIENT_H
#define UVS_ADMIN_CMD_CLIENT_H

#include "netinet/in.h"
#include "uvs_admin_cmd.h"

#define MAX_MSG_LEN            1024
#define UVS_ADMIN_SHOW_PREFIX "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"

typedef struct uvs_admin_request {
    uint32_t cmd_type;
    ssize_t req_len;
    char req[0];
} uvs_admin_request_t;

typedef struct uvs_admin_response {
    uint32_t cmd_type;
    ssize_t rsp_len;
    char rsp[0];
} uvs_admin_response_t;

enum UVS_COMMAND_TYPE {
    UVS_ADMIN_SERVICE_SHOW = 0,
    UVS_ADMIN_VPORT_TABLE_SHOW,
    UVS_ADMIN_VPORT_TABLE_ADD,
    UVS_ADMIN_VPORT_TABLE_DEL,
    UVS_ADMIN_LIVE_MIGRATE_TABLE_SHOW,
    UVS_ADMIN_LIVE_MIGRATE_TABLE_ADD,
    UVS_ADMIN_LIVE_MIGRATE_TABLE_DEL,
    UVS_ADMIN_SIP_TABLE_SHOW,
    UVS_ADMIN_SIP_TABLE_ADD,
    UVS_ADMIN_SIP_TABLE_DEL,
    UVS_ADMIN_DIP_TABLE_SHOW,
    UVS_ADMIN_DIP_TABLE_ADD,
    UVS_ADMIN_DIP_TABLE_DEL,
    UVS_ADMIN_DIP_TABLE_MODIFY,
    UVS_ADMIN_UEID_TABLE_SHOW,
    UVS_ADMIN_UEID_TABLE_ADD,
    UVS_ADMIN_UEID_TABLE_DEL,
    UVS_ADMIN_SET_UPI,
    UVS_ADMIN_SHOW_UPI,
    UVS_ADMIN_GLOBAL_CFG_SHOW,
    UVS_ADMIN_GLOBAL_CFG_SET
};

uvs_admin_response_t *client_get_rsp(uvs_admin_cmd_ctx_t *ctx,
    uvs_admin_request_t *req, char *buf);

#endif /* UVS_ADMIN_CMD_CLIENT_H */
