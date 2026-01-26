/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc statistics cmd
 * Create: 2024-5-29
 */

#include "queue_info.h"

#include "queue.h"
#include "urpc_framework_types.h"
#include "urpc_admin_cmd.h"
#include "urpc_admin_log.h"
#include "urpc_admin_param.h"

typedef enum queue_info_queue_usage {
    QUEUE_INFO_USAGE_NORMAL,
    QUEUE_INFO_USAGE_KEEPALIVE,
    QUEUE_INFO_USAGE_MAX
} queue_info_queue_usage_t;

static char *g_queue_usage[QUEUE_INFO_USAGE_MAX] = {
    "User",
    "Keepalive "
};

typedef enum queue_info_queue_type {
    QUEUE_INFO_TYPE_LOCAL,
    QUEUE_INFO_TYPE_REMOTE,
    QUEUE_INFO_TYPE_MAX
} queue_info_queue_type_t;

static char *g_lisq_queue_type[QUEUE_INFO_TYPE_MAX] = {
    "Local",
    "Remote",
};

static int queue_info_request_create(urpc_ipc_ctl_head_t *req_ctl, char **request, urpc_admin_config_t *cfg)
{
    urpc_queue_cmd_input_t *queue_info_info = (urpc_queue_cmd_input_t *)malloc(sizeof(urpc_queue_cmd_input_t));
    if (queue_info_info == NULL) {
        LOG_PRINT("malloc request info failed\n");
        return -1;
    }
    queue_info_info->channel_id = cfg->channel_id;
    queue_info_info->queue_id = cfg->queue_id;
    *request = (char *)queue_info_info;
    req_ctl->module_id = (uint16_t)cfg->module_id;
    req_ctl->cmd_id = (uint16_t)cfg->cmd_id;
    req_ctl->error_code = 0;
    req_ctl->data_size = (uint32_t)sizeof(urpc_queue_cmd_input_t);

    return 0;
}

static void print_queue_trans_info_line(uint32_t queue_idx, queue_info_queue_type_t type,
    queue_info_queue_usage_t usage, queue_trans_info_t *qti, uint32_t i)
{
    if (queue_idx == UINT32_MAX) {
        if (qti->trans_spec[i].uasid == URPC_U32_FAIL && qti->trans_spec[i].tpn == URPC_U32_FAIL) {
            (void)printf("                                 %-8u   %-9u   " EID_FMT "   %-10u   -"
                "            -         \n", i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id);
        } else if (qti->trans_spec[i].uasid == URPC_U32_FAIL) {
            (void)printf("                                 %-8u   %-9u   " EID_FMT "   %-10u   -"
                "            %-10u\n", i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id,
                qti->trans_spec[i].tpn);
        } else if (qti->trans_spec[i].tpn == URPC_U32_FAIL) {
            (void)printf("                                 %-8u   %-9u   " EID_FMT "   %-10u   %-10u   -"
                "         \n", i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id, qti->trans_spec[i].uasid);
        } else {
            (void)printf("                                 %-8u   %-9u   " EID_FMT "   %-10u   %-10u   %-10u\n",
                i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id, qti->trans_spec[i].uasid,
                qti->trans_spec[i].tpn);
        }
        return;
    }

    if (qti->trans_spec[i].uasid == URPC_U32_FAIL && qti->trans_spec[i].tpn == URPC_U32_FAIL) {
        (void)printf("%-8u   %-6s   %-10s   %-8u   %-9u   " EID_FMT "   %-10u   -            -         \n",
            queue_idx, g_lisq_queue_type[type], g_queue_usage[usage],
            i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id);
    } else if (qti->trans_spec[i].uasid == URPC_U32_FAIL) {
        (void)printf("%-8u   %-6s   %-10s   %-8u   %-9u   " EID_FMT "   %-10u   -            %-10u\n",
            queue_idx, g_lisq_queue_type[type], g_queue_usage[usage],
            i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id, qti->trans_spec[i].tpn);
    } else if (qti->trans_spec[i].tpn == URPC_U32_FAIL) {
        (void)printf("%-8u   %-6s   %-10s   %-8u   %-9u   " EID_FMT "   %-10u   %-10u   -         \n",
            queue_idx, g_lisq_queue_type[type], g_queue_usage[usage],
            i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id, qti->trans_spec[i].uasid);
    } else {
        (void)printf("%-8u   %-6s   %-10s   %-8u   %-9u   " EID_FMT "   %-10u   %-10u   %-10u\n",
            queue_idx, g_lisq_queue_type[type], g_queue_usage[usage],
            i, qti->qid, EID_ARGS(qti->eid), qti->trans_spec[i].id, qti->trans_spec[i].uasid,
            qti->trans_spec[i].tpn);
    }
}

static void print_queue_trans_info(uint32_t idx, queue_trans_info_t *qti)
{
    queue_info_queue_type_t type = qti->flag.is_remote ? QUEUE_INFO_TYPE_REMOTE : QUEUE_INFO_TYPE_LOCAL;
    queue_info_queue_usage_t usage;
    if (qti->flag.is_keepalive) {
        usage = QUEUE_INFO_USAGE_KEEPALIVE;
    } else {
        usage = QUEUE_INFO_USAGE_NORMAL;
    }

    print_queue_trans_info_line(idx, type, usage, qti, 0);
    for (uint32_t i = 1; i < qti->trans_spec_cnt; i++) {
        print_queue_trans_info_line(UINT32_MAX, type, usage, qti, i);
    }
}

static int queue_info_response_process(
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

    (void)printf("Idx        L/R      Usage        Sub idx    Queue id    EID                                    "
        "   Jetty id     Uasid        Tpn       \n");
    (void)printf("--------   ------   ----------   --------   ---------   ---------------------------------------"
        "   ----------   ----------   ----------\n");
    uint32_t offset = 0;
    uint32_t idx = 0;
    while (offset < rsp_ctl->data_size) {
        if (rsp_ctl->data_size - offset < sizeof(queue_trans_info_t)) {
            LOG_PRINT("recv size invaild, recv size: %u, offset: %u, size: %zu\n",
                rsp_ctl->data_size, offset, sizeof(queue_trans_info_t));
            return 0;
        }
        queue_trans_info_t *qti = (queue_trans_info_t *)(uintptr_t)(reply + offset);
        if (rsp_ctl->data_size - offset <
            sizeof(queue_trans_info_t) + qti->trans_spec_cnt * sizeof(queue_trans_resource_spec_t)) {
            LOG_PRINT("recv size invaild, recv size: %u, offset: %u, size: %zu, cnt: %u\n",
                rsp_ctl->data_size, offset, sizeof(queue_trans_resource_spec_t), qti->trans_spec_cnt);
            return 0;
        }
        print_queue_trans_info(idx++, qti);
        offset += (uint32_t)(sizeof(queue_trans_info_t) + qti->trans_spec_cnt * sizeof(queue_trans_resource_spec_t));
    }

    return 0;
}

static int queue_id_request_create(urpc_ipc_ctl_head_t *req_ctl, char **request, urpc_admin_config_t *cfg)
{
    urpc_queue_cmd_input_t *queue_info = (urpc_queue_cmd_input_t *)malloc(sizeof(urpc_queue_cmd_input_t));
    if (queue_info == NULL) {
        LOG_PRINT("malloc request info failed\n");
        return -1;
    }
    queue_info->channel_id = URPC_U32_FAIL;
    queue_info->queue_id = cfg->queue_id;
    *request = (char *)queue_info;
    req_ctl->module_id = (uint16_t)cfg->module_id;
    req_ctl->cmd_id = (uint16_t)cfg->cmd_id;
    req_ctl->error_code = 0;
    req_ctl->data_size = (uint32_t)sizeof(urpc_queue_cmd_input_t);

    return 0;
}

static int queue_id_response_process(
    urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg __attribute__((unused)))
{
    if (rsp_ctl->error_code != 0) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        return -1;
    }

    if (rsp_ctl->data_size == 0 || rsp_ctl->data_size < sizeof(queue_trans_info_t)) {
        LOG_PRINT("recv size invaild, recv size: %u, except greater than or equal to size: %zu\n",
            rsp_ctl->data_size, sizeof(queue_trans_info_t));
        return -1;
    }

    queue_trans_info_t *qti = (queue_trans_info_t *)reply;
    if (rsp_ctl->data_size < sizeof(queue_trans_info_t) + qti->trans_spec_cnt * sizeof(queue_trans_resource_spec_t)) {
        LOG_PRINT("recv size invaild, recv size: %u, queue_trans_info size: %zu, resource size: %zu, cnt: %u\n",
            rsp_ctl->data_size, sizeof(queue_trans_info_t), sizeof(queue_trans_resource_spec_t), qti->trans_spec_cnt);
        return -1;
    }
    (void)printf("-------------------------------------------------------------------\n");
    (void)printf("EID:                        " EID_FMT "\n", EID_ARGS(qti->eid));
    (void)printf("Custom flag:                %lu\n", qti->custom_flag);
    for (uint32_t i = 0; i < qti->trans_spec_cnt; i++) {
        (void)printf("Jetty id:                   %u\n", qti->trans_spec[i].id);
    }
    (void)printf("-------------------------------------------------------------------\n");

    return 0;
}

static urpc_admin_cmd_t g_queue_info_cmd[URPC_QUEUE_CMD_ID_MAX] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_LOCAL_ALL,
        .create_request = queue_info_request_create,
        .process_response = queue_info_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_CLIENT_CHID,
        .create_request = queue_info_request_create,
        .process_response = queue_info_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_SERVER_CHID,
        .create_request = queue_info_request_create,
        .process_response = queue_info_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_QID,
        .create_request = queue_id_request_create,
        .process_response = queue_id_response_process,
    },
};

static void __attribute__((constructor)) urpc_queue_info_cmd_init(void)
{
    urpc_admin_cmds_register(g_queue_info_cmd, URPC_QUEUE_CMD_ID_MAX);
}
