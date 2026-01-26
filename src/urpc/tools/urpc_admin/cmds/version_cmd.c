/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc version cmd process
 * Create: 2024-4-23
 */

#include "version.h"

#include "urpc_admin_cmd.h"
#include "urpc_admin_log.h"
#include "urpc_admin_param.h"

static int version_request_create(urpc_ipc_ctl_head_t *req_ctl, char **request __attribute__((unused)),
                                  urpc_admin_config_t *cfg __attribute__((unused)))
{
    req_ctl->module_id = (uint16_t)URPC_IPC_MODULE_VERSION;
    req_ctl->cmd_id = (uint16_t)URPC_VERSION_CMD_ID_GET;
    req_ctl->error_code = 0;
    req_ctl->data_size = 0;

    (void)printf("Name       : urpc_admin\n");
    (void)printf("Version    : %s\n", URPC_VERSION);
    (void)printf("Release    : %s\n", URPC_RELEASE_VERSION);
    (void)printf("Build Date : %s\n\n", URPC_BUILD_DATE);

    return 0;
}

static int version_response_process(
    urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg __attribute__((unused)))
{
    if (rsp_ctl->error_code != 0) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        return -1;
    }

    if (rsp_ctl->data_size == 0) {
        LOG_PRINT("recv empty response\n");
        return -1;
    }

    (void)printf("%s", reply);

    return 0;
}

static urpc_admin_cmd_t g_version_cmd = {
    .module_id = (uint16_t)URPC_IPC_MODULE_VERSION,
    .cmd_id = (uint16_t)URPC_VERSION_CMD_ID_GET,
    .create_request = version_request_create,
    .process_response = version_response_process,
};

static void __attribute__((constructor)) urpc_version_cmd_init(void)
{
    urpc_admin_cmds_register(&g_version_cmd, 1);
}
