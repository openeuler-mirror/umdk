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
#include <unistd.h>

#include "admin_netlink.h"

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

    int ns_fd = admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("Failed to get ns fd, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_DEV_NS, 0);
    if (msg == NULL) {
        ret = -ENOMEM;
        goto close_ns_fd;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, ns_fd);
    ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);

close_ns_fd:
    (void)close(ns_fd);
    return ret;
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
