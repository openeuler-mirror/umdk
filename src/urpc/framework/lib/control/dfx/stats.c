/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc statistics cmd
 * Create: 2024-5-29
 */

#include <string.h>

#include "queue.h"
#include "unix_server.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_dbuf_stat.h"

#include "stats.h"

#define URPC_STATS_INFO_LEN 8192

static int format_stats_string(char *buf, int len, uint64_t *stats, int stats_len, const char *(*name_get)(int))
{
    int ret;
    int offset = 0, remain = len;

    if (remain <= 1) {
        URPC_LIB_LOG_ERR("format stats info failed, buffer size %d not enough\n", len);
        return -1;
    }

    for (int i = 0; i < stats_len; i++) {
        ret = snprintf(buf + offset, remain, "%s: %lu\n", name_get(i), stats[i]);
        if (ret < 0 || ret >= remain) {
            URPC_LIB_LOG_ERR("format stats info failed, error %d\n", ret);
            return ret;
        }

        offset += ret;
        remain -= ret;
    }

    return offset;
}

// get all queue statistics and format into string
static void stats_cmd_process(urpc_ipc_ctl_head_t *req_ctl __attribute__((unused)),
    char *request __attribute__((unused)), urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    uint64_t stats[STATS_TYPE_MAX] = {0};
    uint64_t error_stats[ERR_STATS_TYPE_MAX] = {0};
    uint64_t total_error_stats[ERR_STATS_TYPE_MAX] = {0};

    queue_common_error_stats_get(total_error_stats, ERR_STATS_TYPE_MAX);
    // get all queue stats
    query_queues_stats(stats, STATS_TYPE_MAX, error_stats, ERR_STATS_TYPE_MAX);

    for (int i = 0; i < (int)ERR_STATS_TYPE_MAX; i++) {
        total_error_stats[i] += error_stats[i];
    }

    char *stats_info = urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, URPC_STATS_INFO_LEN);
    if (stats_info == NULL) {
        URPC_LIB_LOG_ERR("malloc stats info failed\n");
        return;
    }

    int offset = format_stats_string(stats_info, URPC_STATS_INFO_LEN, stats, STATS_TYPE_MAX, queue_stats_name_get);
    if (offset < 0) {
        urpc_dbuf_free(stats_info);
        return;
    }

    offset = format_stats_string(stats_info + offset, URPC_STATS_INFO_LEN - offset, total_error_stats,
        ERR_STATS_TYPE_MAX, queue_error_stats_name_get);
    if (offset < 0) {
        urpc_dbuf_free(stats_info);
        return;
    }

    rsp_ctl->data_size = (uint32_t)strlen(stats_info) + 1;
    *reply = stats_info;
}

// get queue statistics by qid and format into string
static void stats_by_qid_cmd_process(
    urpc_ipc_ctl_head_t *req_ctl, char *request, urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (req_ctl->data_size != sizeof(urpc_stats_cmd_input_t)) {
        URPC_LIB_LOG_ERR("invalid request control header\n");
        rsp_ctl->error_code = -EINVAL;
        return;
    }

    uint64_t stats[STATS_TYPE_MAX] = {0};
    uint64_t error_stats[ERR_STATS_TYPE_MAX] = {0};
    urpc_stats_cmd_input_t *input = (urpc_stats_cmd_input_t *)(uintptr_t)request;
    int ret = query_queues_stats_by_id(input->queue_id, stats, STATS_TYPE_MAX, error_stats, ERR_STATS_TYPE_MAX);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("stats queue info by qid failed, qid[%u] not found\n", input->queue_id);
        rsp_ctl->error_code = URPC_FAIL;
        return;
    }

    char *stats_info = urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, URPC_STATS_INFO_LEN);
    if (stats_info == NULL) {
        URPC_LIB_LOG_ERR("malloc stats info failed\n");
        rsp_ctl->error_code = URPC_FAIL;
        return;
    }

    int offset = format_stats_string(stats_info, URPC_STATS_INFO_LEN, stats, STATS_TYPE_MAX, queue_stats_name_get);
    if (offset < 0) {
        urpc_dbuf_free(stats_info);
        rsp_ctl->error_code = URPC_FAIL;
        return;
    }

    offset = format_stats_string(stats_info + offset, URPC_STATS_INFO_LEN - offset, error_stats,
        ERR_STATS_TYPE_MAX, queue_error_stats_name_get);
    if (offset < 0) {
        urpc_dbuf_free(stats_info);
        rsp_ctl->error_code = URPC_FAIL;
        return;
    }

    rsp_ctl->data_size = (uint32_t)strlen(stats_info) + 1;
    *reply = stats_info;
}

static urpc_ipc_cmd_t g_urpc_stats_cmd[URPC_STATS_CMD_ID_MAX] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_STAT,
        .cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET,
        .func = stats_cmd_process,
        .reply_malloced = true
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_STAT,
        .cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET_BY_QID,
        .func = stats_by_qid_cmd_process,
        .reply_malloced = true
    },
};

int stats_cmd_init(void)
{
    return unix_server_cmds_register(g_urpc_stats_cmd, URPC_STATS_CMD_ID_MAX);
}

void stats_cmd_uninit(void)
{
    unix_server_cmds_unregister(g_urpc_stats_cmd, URPC_STATS_CMD_ID_MAX);
}