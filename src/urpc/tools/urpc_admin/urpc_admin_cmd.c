/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc admin cmd definition
 * Create: 2024-4-23
 */

#include <unistd.h>

#include "urpc_admin_cmd.h"

typedef struct urpc_admin_cmds {
    urpc_admin_cmd_t *cmds;
    int num;
} urpc_admin_cmds_t;

static urpc_admin_cmds_t g_urpc_admin_cmds[URPC_IPC_MODULE_MAX];

// only support same module_id cmds register
void urpc_admin_cmds_register(urpc_admin_cmd_t *cmds, int num)
{
    g_urpc_admin_cmds[cmds[0].module_id].cmds = cmds;
    g_urpc_admin_cmds[cmds[0].module_id].num = num;
}

urpc_admin_cmd_t *urpc_admin_cmd_get(uint16_t module_id, uint16_t cmd_id)
{
    if (module_id > URPC_IPC_MODULE_MAX - 1) {
        return NULL;
    }

    for (int i = 0; i < g_urpc_admin_cmds[module_id].num; i++) {
        if (g_urpc_admin_cmds[module_id].cmds[i].cmd_id == cmd_id) {
            return &g_urpc_admin_cmds[module_id].cmds[i];
        }
    }

    return NULL;
}
