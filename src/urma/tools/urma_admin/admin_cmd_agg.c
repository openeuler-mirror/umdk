/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: agg sub-command source file for urma_admin
 * Author: Wang Hang
 * Create: 2025-12-26
 * Note:
 * History: 2025-12-26   create file
 */

#include <stdio.h>

#include "admin_cmd.h"

static int cmd_agg_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin agg add [ EID ]\n"
           "       urma_admin agg del [ EID ]\n");
    return 0;
}

static int cmd_agg_add(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_eid(cfg)) != 0) {
        return ret;
    }

    printf("TODO add agg dev\n");
    return 0;
}

static int cmd_agg_del(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_eid(cfg)) != 0) {
        return ret;
    }

    printf("TODO del agg dev\n");
    return 0;
}

int admin_cmd_agg(admin_config_t *cfg)
{
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_agg_usage}, //
        {"add", cmd_agg_add},  //
        {"del", cmd_agg_del},  //
        {0},                   //
    };
    return exec_cmd(cfg, cmds);
}
