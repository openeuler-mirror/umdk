/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dev sub-command source file for urma_admin
 * Author: Wang Hang
 * Create: 2025-12-26
 * Note:
 * History: 2025-12-26   create file
 */

#include <stdio.h>

#include "admin_cmd.h"

static int cmd_dev_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin dev set [ DEV ] ns [ NETNS ]\n"
           "       urma_admin dev set [ DEV ] sharing { on | off }\n"
           "       urma_admin dev expose [ DEV ] [ NETNS ]\n"
           "       urma_admin dev unexpose [ DEV ] [ NETNS ]\n"
           "where  NETNS := /proc/$pid/ns/net\n");
    return 0;
}

static int cmd_dev_set_sharing(admin_config_t *cfg)
{
    printf("TODO set sharing %s\n", cfg->dev_name);
    return 0;
}

static int cmd_dev_set_ns(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_ns(cfg)) != 0) {
        return ret;
    }

    printf("TODO set ns %s to %s\n", cfg->dev_name, cfg->ns);
    return 0;
}

static int cmd_dev_set(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_dev_usage},            //
        {"sharing", cmd_dev_set_sharing}, //
        {"ns", cmd_dev_set_ns},           //
        {0},                              //
    };
    return exec_cmd(cfg, cmds);
}

static int cmd_dev_expose(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_ns(cfg)) != 0) {
        return ret;
    }

    printf("TODO expose %s to %s\n", cfg->dev_name, cfg->ns);
    return 0;
}

static int cmd_dev_unexpose(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_ns(cfg)) != 0) {
        return ret;
    }

    printf("TODO unexpose %s to %s\n", cfg->dev_name, cfg->ns);
    return 0;
}

int admin_cmd_dev(admin_config_t *cfg)
{
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_dev_usage},          //
        {"set", cmd_dev_set},           //
        {"expose", cmd_dev_expose},     //
        {"unexpose", cmd_dev_unexpose}, //
        {0},                            //
    };
    return exec_cmd(cfg, cmds);
}
