/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc dynamic buffer cmd
 * Create: 2024-11-27
 */

#include <string.h>

#include "unix_server.h"
#include "urpc_lib_log.h"
#include "urpc_dbuf_stat.h"

#include "dbuf.h"

#define URPC_DBUF_INFO_LEN 8192

static int format_stats_string(char *buf, int len, const uint64_t *stats,
                               int stats_len, const char *(*name_get)(int))
{
    int ret;
    int offset = 0, remain = len;

    if (remain <= 1) {
        URPC_LIB_LOG_ERR("format stats info failed, buffer size %d not enough\n", len);
        return -1;
    }

    for (int i = 0; i < stats_len; i++) {
        ret = snprintf(buf + offset, remain, "%-15s: %20lu Byte(s)\n", name_get(i), stats[i]);
        if (ret < 0) {
            URPC_LIB_LOG_ERR("format stats info failed, error %d\n", ret);
            return ret;
        }

        if (remain <= ret) {
            break;
        }
        offset += ret;
        remain -= ret;
    }

    return offset;
}

// get all queue statistics and format into string
static void dbuf_cmd_process(urpc_ipc_ctl_head_t *req_ctl __attribute__((unused)),
    char *request __attribute__((unused)), urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    uint64_t stat[URPC_DBUF_STAT_NUM] = {0};
    urpc_dbuf_stat_get(stat, URPC_DBUF_STAT_NUM);

    char *stat_info = urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, URPC_DBUF_INFO_LEN);
    if (stat_info == NULL) {
        URPC_LIB_LOG_ERR("malloc stats info failed\n");
        return;
    }

    int offset = format_stats_string(stat_info, URPC_DBUF_INFO_LEN, stat, URPC_DBUF_STAT_NUM, urpc_dbuf_stat_name_get);
    if (offset < 0) {
        urpc_dbuf_free(stat_info);
        return;
    }

    rsp_ctl->data_size = (uint32_t)(strlen(stat_info) + 1);
    *reply = stat_info;
}

static urpc_ipc_cmd_t g_urpc_dbuf_cmd = {
    .module_id = (uint16_t)URPC_IPC_MODULE_DBUF,
    .cmd_id = (uint16_t)URPC_DBUF_CMD_ID_GET,
    .func = dbuf_cmd_process,
    .reply_malloced = true,
};

int dbuf_cmd_init(void)
{
    return unix_server_cmds_register(&g_urpc_dbuf_cmd, 1);
}

void dbuf_cmd_uninit(void)
{
    unix_server_cmds_unregister(&g_urpc_dbuf_cmd, 1);
}