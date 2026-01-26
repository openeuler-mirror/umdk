/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc queue information cmd
 * Create: 2025-05-28
 */

#include "unix_server.h"
#include "urpc_lib_log.h"
#include "channel.h"
#include "../control/dfx/channel_info.h"

static void process_channel_all(urpc_ipc_ctl_head_t *req_ctl, char *request __attribute__((unused)),
                                urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_channel_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    uint32_t acqi_size = (uint32_t)sizeof(all_channel_query_info_t);
    all_channel_query_info_t *acqi = urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, acqi_size);
    if (acqi == NULL) {
        URPC_LIB_LOG_ERR("failed to malloc, errno: %d\n", errno);
        rsp_ctl->error_code = -URPC_ERR_ENOMEM;
        return;
    }
    acqi->total_num = channel_num_get();
    rsp_ctl->data_size = acqi_size;
    *reply = (char *)acqi;
}

static void process_channel_by_chid(urpc_ipc_ctl_head_t *req_ctl, char *request,
                                    urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_channel_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    char *output = NULL;
    uint32_t output_size = 0;
    urpc_channel_cmd_input_t *input = (urpc_channel_cmd_input_t *)(uintptr_t)request;
    int ret = channel_info_get(input->channel_id, &output, &output_size);
    if (ret != URPC_SUCCESS) {
        rsp_ctl->error_code = ret;
        return;
    }

    rsp_ctl->data_size = output_size;
    *reply = output;
    return;
}

static urpc_ipc_cmd_t g_urpc_channel_cmd[URPC_CHANNEL_CMD_ID_MAX] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_CHANNEL,
        .cmd_id = (uint16_t)URPC_CHANNEL_CMD_ID_ALL_CHANNEL,
        .func = process_channel_all,
        .reply_malloced = true,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_CHANNEL,
        .cmd_id = (uint16_t)URPC_CHANNEL_CMD_ID_BY_CHID,
        .func = process_channel_by_chid,
        .reply_malloced = true,
    },
};

int channel_info_cmd_init(void)
{
    return unix_server_cmds_register(g_urpc_channel_cmd, URPC_CHANNEL_CMD_ID_MAX);
}

void channel_info_cmd_uninit(void)
{
    unix_server_cmds_unregister(g_urpc_channel_cmd, URPC_CHANNEL_CMD_ID_MAX);
}