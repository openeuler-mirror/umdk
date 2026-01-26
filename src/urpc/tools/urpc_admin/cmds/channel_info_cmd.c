/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc channel cmd
 * Create: 2025-5-28
 */

#include "channel_info.h"

#include "channel.h"
#include "urpc_framework_types.h"
#include "urpc_admin_cmd.h"
#include "urpc_admin_log.h"
#include "urpc_admin_param.h"

static int channel_request_create(urpc_ipc_ctl_head_t *req_ctl, char **request, urpc_admin_config_t *cfg)
{
    urpc_channel_cmd_input_t *channel_info = (urpc_channel_cmd_input_t *)malloc(sizeof(urpc_channel_cmd_input_t));
    if (channel_info == NULL) {
        LOG_PRINT("malloc request info failed\n");
        return -1;
    }

    channel_info->channel_id = cfg->channel_id;
    *request = (char *)channel_info;
    req_ctl->module_id = (uint16_t)cfg->module_id;
    req_ctl->cmd_id = (uint16_t)cfg->cmd_id;
    req_ctl->error_code = 0;
    req_ctl->data_size = (uint32_t)sizeof(urpc_channel_cmd_input_t);

    return 0;
}

static int all_channel_response_process(
    urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg __attribute__((unused)))
{
    if (rsp_ctl->error_code != 0) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        return -1;
    }

    if (rsp_ctl->data_size == 0 || rsp_ctl->data_size < sizeof(all_channel_query_info_t)) {
        LOG_PRINT("recv size invaild, recv size: %u, except greater than or equal to size: %zu\n",
            rsp_ctl->data_size, sizeof(all_channel_query_info_t));
        return -1;
    }

    (void)printf("-------------------------------------------------------------------\n");
    (void)printf("Total num:                  %u\n", ((all_channel_query_info_t *)reply)->total_num);
    (void)printf("-------------------------------------------------------------------\n");

    return 0;
}

static int single_channel_response_process(
    urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg __attribute__((unused)))
{
    if (rsp_ctl->error_code != 0) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        return -1;
    }

    if (rsp_ctl->data_size == 0 || rsp_ctl->data_size < sizeof(channel_query_info_t)) {
        LOG_PRINT("recv size invaild, recv size: %u, except greater than or equal to size: %zu\n",
            rsp_ctl->data_size, sizeof(channel_query_info_t));
        return -1;
    }

    channel_query_info_t *cqi = (channel_query_info_t *)reply;
    (void)printf("-------------------------------------------------------------------\n");
    (void)printf("Total req entry num:        %lu\n", cqi->req_entry_stats[CHANNEL_REQ_ENTRY_TOTAL_NUM]);
    (void)printf("Used req entry num:         %lu\n", cqi->req_entry_stats[CHANNEL_REQ_ENTRY_TOTAL_NUM] -
        cqi->req_entry_stats[CHANNEL_REQ_ENTRY_FREE_NUM]);
    (void)printf("Free req entry num:         %lu\n", cqi->req_entry_stats[CHANNEL_REQ_ENTRY_FREE_NUM]);
    (void)printf("Last alloc req id:          %lu\n", cqi->req_entry_stats[CHANNEL_LAST_ALLOC_REQ_ID]);
    (void)printf("Last free req id:           %lu\n", cqi->req_entry_stats[CHANNEL_LAST_FREE_REQ_ID]);
    (void)printf("-------------------------------------------------------------------\n");
    (void)printf("Total timer entry num:      %lu\n", cqi->timer_stats[TIMER_ENTRY_TOTAL_NUM]);
    (void)printf("Used timer entry num:       %lu\n", cqi->timer_stats[TIMER_ENTRY_TOTAL_NUM] -
        cqi->timer_stats[TIMER_ENTRY_FREE_NUM]);
    (void)printf("Free timer entry num:       %lu\n", cqi->timer_stats[TIMER_ENTRY_FREE_NUM]);
    (void)printf("-------------------------------------------------------------------\n");

    if (rsp_ctl->data_size <
        (uint32_t)(sizeof(channel_query_info_t) + sizeof(channel_server_info_t) * cqi->server_cnt)) {
        LOG_PRINT("recv size invaild, recv size: %u, server count: %u\n", rsp_ctl->data_size, cqi->server_cnt);
        return -1;
    }

    uint32_t offset = (uint32_t)sizeof(channel_query_info_t);
    for (uint32_t i = 0; i < cqi->server_cnt && offset <= rsp_ctl->data_size - sizeof(channel_server_info_t); i++) {
        channel_server_info_t *server = &cqi->server[i];
        if (server->info.host_type == HOST_TYPE_IPV4) {
            (void)printf("Server ip:                  %s\n", server->info.ipv4.ip_addr);
            (void)printf("Port:                       %u\n", server->info.ipv4.port);
        } else if (server->info.host_type == HOST_TYPE_IPV6) {
            (void)printf("Server ip:                  %s\n", server->info.ipv6.ip_addr);
            (void)printf("Port:                       %u\n", server->info.ipv6.port);
        }
        (void)printf("EID:                        " EID_FMT "\n", EID_ARGS(server->key.eid));
        (void)printf("PID:                        %u\n", server->key.pid);
        (void)printf("-------------------------------------------------------------------\n");
    }

    // channel task information
    (void)printf("Total task num:             %lu\n", cqi->req_entry_stats[CHANNEL_TASK_TOTAL_NUM]);
    (void)printf("Running task num:           %lu\n", cqi->req_entry_stats[CHANNEL_TASK_RUNNING_NUM]);

    (void)printf("Pending task num:           %lu\n",
        cqi->req_entry_stats[CHANNEL_TASK_TOTAL_NUM] - cqi->req_entry_stats[CHANNEL_TASK_RUNNING_NUM] -
            cqi->req_entry_stats[CHANNEL_TASK_SUCCEEDED_NUM] - cqi->req_entry_stats[CHANNEL_TASK_FAILED_NUM]);
    (void)printf("Succeeded task num:         %lu\n", cqi->req_entry_stats[CHANNEL_TASK_SUCCEEDED_NUM]);
    (void)printf("Failed task num:            %lu\n", cqi->req_entry_stats[CHANNEL_TASK_FAILED_NUM]);
    (void)printf("-------------------------------------------------------------------\n");
    return 0;
}

static urpc_admin_cmd_t g_channel_cmd[URPC_CHANNEL_CMD_ID_MAX] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_CHANNEL,
        .cmd_id = (uint16_t)URPC_CHANNEL_CMD_ID_ALL_CHANNEL,
        .create_request = channel_request_create,
        .process_response = all_channel_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_CHANNEL,
        .cmd_id = (uint16_t)URPC_CHANNEL_CMD_ID_BY_CHID,
        .create_request = channel_request_create,
        .process_response = single_channel_response_process,
    },
};

static void __attribute__((constructor)) urpc_channel_info_cmd_init(void)
{
    urpc_admin_cmds_register(g_channel_cmd, URPC_CHANNEL_CMD_ID_MAX);
}
