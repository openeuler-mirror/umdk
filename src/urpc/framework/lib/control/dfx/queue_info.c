/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc queue information cmd
 * Create: 2024-11-18
 */

#include "unix_server.h"
#include "urpc_lib_log.h"
#include "channel.h"
#include "queue.h"
#include "queue_info.h"

static void process_queue_local_all(urpc_ipc_ctl_head_t *req_ctl, char *request __attribute__((unused)),
                                    urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_queue_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    char *output = NULL;
    uint32_t output_size = 0;
    int ret = get_queue_trans_info(&output, &output_size);
    if (ret != URPC_SUCCESS) {
        rsp_ctl->error_code = ret;
        return;
    }

    rsp_ctl->data_size = output_size;
    *reply = output;
}

static void process_queue_by_client_chid(urpc_ipc_ctl_head_t *req_ctl, char *request,
                                         urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_queue_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    char *output = NULL;
    uint32_t output_size = 0;
    urpc_queue_cmd_input_t *input = (urpc_queue_cmd_input_t *)(uintptr_t)request;
    int ret = channel_get_queue_trans_info(input->channel_id, &output, &output_size);
    if (ret != URPC_SUCCESS) {
        rsp_ctl->error_code = ret;
        return;
    }

    rsp_ctl->data_size = output_size;
    *reply = output;
    return;
}

static void process_queue_by_server_chid(urpc_ipc_ctl_head_t *req_ctl, char *request,
                                         urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_queue_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    char *output = NULL;
    uint32_t output_size = 0;
    urpc_queue_cmd_input_t *input = (urpc_queue_cmd_input_t *)(uintptr_t)request;
    int ret = server_channel_get_queue_trans_info(input->channel_id, &output, &output_size);
    if (ret != URPC_SUCCESS) {
        rsp_ctl->error_code = ret;
        return;
    }

    rsp_ctl->data_size = output_size;
    *reply = output;
    return;
}

static void process_queue_by_qid(urpc_ipc_ctl_head_t *req_ctl, char *request,
                                 urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_queue_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    char *output = NULL;
    uint32_t output_size = 0;
    urpc_queue_cmd_input_t *input = (urpc_queue_cmd_input_t *)(uintptr_t)request;
    int ret = queue_info_get(input->queue_id, &output, &output_size);
    if (ret != URPC_SUCCESS) {
        rsp_ctl->error_code = ret;
        return;
    }

    rsp_ctl->data_size = output_size;
    *reply = output;
}

static urpc_ipc_cmd_t g_urpc_queue_cmd[URPC_QUEUE_CMD_ID_MAX] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_LOCAL_ALL,
        .func = process_queue_local_all,
        .reply_malloced = true,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_CLIENT_CHID,
        .func = process_queue_by_client_chid,
        .reply_malloced = true,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_SERVER_CHID,
        .func = process_queue_by_server_chid,
        .reply_malloced = true,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_QID,
        .func = process_queue_by_qid,
        .reply_malloced = true,
    },
};

int queue_info_cmd_init(void)
{
    return unix_server_cmds_register(g_urpc_queue_cmd, URPC_QUEUE_CMD_ID_MAX);
}

void queue_info_cmd_uninit(void)
{
    unix_server_cmds_unregister(g_urpc_queue_cmd, URPC_QUEUE_CMD_ID_MAX);
}