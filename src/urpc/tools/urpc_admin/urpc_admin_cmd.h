/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc admin cmd definition
 * Create: 2024-4-23
 */

#ifndef URPC_ADMIN_CMD_H
#define URPC_ADMIN_CMD_H

#include "unix_server.h"
#include "urpc_admin_param.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*request_func)(urpc_ipc_ctl_head_t *req_ctl, char **request, urpc_admin_config_t *cfg);
typedef int (*response_func)(urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg);

typedef struct urpc_admin_cmd {
    uint16_t module_id;
    uint16_t cmd_id;
    request_func create_request;
    response_func process_response;
} urpc_admin_cmd_t;

void urpc_admin_cmds_register(urpc_admin_cmd_t *cmds, int num);

urpc_admin_cmd_t *urpc_admin_cmd_get(uint16_t module_id, uint16_t cmd_id);

#ifdef __cplusplus
}
#endif

#endif