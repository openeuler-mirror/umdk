/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc version cmd
 * Create: 2024-4-24
 */

#include <string.h>

#include "unix_server.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_dbuf_stat.h"
#include "version.h"

/* version format
Name       : urpc_framework
Version    :
Release    :
Build Date :
*/

#define URPC_VERSION_INFO_LEN 128

static void version_cmd_process(urpc_ipc_ctl_head_t *req_ctl __attribute__((unused)),
    char *request __attribute__((unused)), urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    char *version_info = urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, URPC_VERSION_INFO_LEN);
    if (version_info == NULL) {
        URPC_LIB_LOG_ERR("malloc version info failed\n");
        rsp_ctl->error_code = -URPC_ERR_ENOMEM;
        return;
    }

    (void)snprintf(version_info, URPC_VERSION_INFO_LEN,
        "Name       : urpc_framework\nVersion    : %s\nRelease    : %s\nBuild Date : %s\n", URPC_VERSION,
        URPC_RELEASE_VERSION, URPC_BUILD_DATE);

    rsp_ctl->data_size = strlen(version_info) + 1;
    *reply = version_info;
}

static urpc_ipc_cmd_t g_urpc_version_cmd = {
    .module_id = (uint16_t)URPC_IPC_MODULE_VERSION,
    .cmd_id = (uint16_t)URPC_VERSION_CMD_ID_GET,
    .func = version_cmd_process,
    .reply_malloced = true,
};

int version_cmd_init(void)
{
    return unix_server_cmds_register(&g_urpc_version_cmd, 1);
}

void version_cmd_uninit(void)
{
    unix_server_cmds_unregister(&g_urpc_version_cmd, 1);
}