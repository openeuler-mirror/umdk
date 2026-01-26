/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc statistics cmd
 * Create: 2024-5-29
 */

#include "stats.h"

#include "urpc_admin_cmd.h"
#include "urpc_admin_log.h"
#include "urpc_admin_param.h"

static int stats_request_create(urpc_ipc_ctl_head_t *req_ctl, char **request __attribute__((unused)),
                                urpc_admin_config_t *cfg __attribute__((unused)))
{
    req_ctl->module_id = (uint16_t)URPC_IPC_MODULE_STAT;
    req_ctl->cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET;
    req_ctl->error_code = 0;
    req_ctl->data_size = 0;

    return 0;
}

// only support query all statistics at once
static int stats_response_process(
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

static int stats_by_qid_request_create(urpc_ipc_ctl_head_t *req_ctl, char **request, urpc_admin_config_t *cfg)
{
    urpc_stats_cmd_input_t *stats_cmd = (urpc_stats_cmd_input_t *)malloc(sizeof(urpc_stats_cmd_input_t));
    if (stats_cmd == NULL) {
        LOG_PRINT("malloc request info failed\n");
        return -1;
    }
    stats_cmd->queue_id = cfg->queue_id;
    *request = (char *)stats_cmd;
    req_ctl->module_id = (uint16_t)cfg->module_id;
    req_ctl->cmd_id = (uint16_t)cfg->cmd_id;
    req_ctl->error_code = 0;
    req_ctl->data_size = (uint32_t)sizeof(urpc_stats_cmd_input_t);

    return 0;
}

static urpc_admin_cmd_t g_stats_cmd[URPC_STATS_CMD_ID_MAX] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_STAT,
        .cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET,
        .create_request = stats_request_create,
        .process_response = stats_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_STAT,
        .cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET_BY_QID,
        .create_request = stats_by_qid_request_create,
        .process_response = stats_response_process,
    },
};

static void __attribute__((constructor)) urpc_stats_cmd_init(void)
{
    urpc_admin_cmds_register(g_stats_cmd, URPC_STATS_CMD_ID_MAX);
}
