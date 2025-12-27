/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: eid sub-command source file for urma_admin
 * Author: Wang Hang
 * Create: 2025-12-26
 * Note:
 * History: 2025-12-26   create file
 */

#include <stdio.h>

#include "admin_cmd.h"

static int cmd_eid_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin eid add [ DEV ] [ EID_IDX ] [ EID ] --ns [ NETNS ] --mode [ EID_MODE ]\n"
           "       urma_admin eid del [ DEV ] [ EID_IDX ]\n"
           "       urma_admin eid set [ DEV ] [ EID_IDX ] ns [ NETNS ]\n"
           "       urma_admin eid set [ DEV ] [ EID_IDX ] mode { static | dynamic }\n"
           "where  NETNS := /proc/$pid/ns/net\n");
    return 0;
}

static int cmd_eid_add(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid_idx(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid(cfg)) != 0) {
        return ret;
    }

    printf("TODO add eid %s %u\n", cfg->dev_name, cfg->idx);
    return 0;
}

static int cmd_eid_del(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid_idx(cfg)) != 0) {
        return ret;
    }

    printf("TODO del eid %s %u\n", cfg->dev_name, cfg->idx);
    return 0;
}

static int cmd_eid_set_mode(admin_config_t *cfg)
{
    printf("TODO set eid mode %s %u\n", cfg->dev_name, cfg->idx);
    return 0;
}

static int cmd_eid_set_ns(admin_config_t *cfg)
{
    printf("TODO set eid ns %s %u\n", cfg->dev_name, cfg->idx);
    return 0;
}

static int cmd_eid_set(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid_idx(cfg)) != 0) {
        return ret;
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_eid_usage},      //
        {"mode", cmd_eid_set_mode}, //
        {"ns", cmd_eid_set_ns},     //
        {0},                        //
    };
    return exec_cmd(cfg, cmds);
}

int admin_cmd_eid(admin_config_t *cfg)
{
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_eid_usage}, //
        {"add", cmd_eid_add},  //
        {"del", cmd_eid_del},  //
        {"set", cmd_eid_set},  //
        {0},                   //
    };
    return exec_cmd(cfg, cmds);
}
