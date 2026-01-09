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
#include "admin_file_ops.h"

#include "admin_cmd.h"

static int cmd_dev_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin dev sharing { on | off }\n"
           "       urma_admin dev set [ DEV ] ns [ NETNS ]\n"
           "       urma_admin dev expose [ DEV ] [ NETNS ]\n"
           "       urma_admin dev unexpose [ DEV ] [ NETNS ]\n"
           "where  NETNS := /proc/$pid/ns/net\n");
    return 0;
}

static int cmd_dev_toggle_sharing(admin_config_t *cfg)
{
    int ret;

    if ((ret = pop_arg_sharing(cfg)) != 0) {
        return ret;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_NS_MODE, 0);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    admin_nl_put_u8(msg, UBCORE_ATTR_NS_MODE, cfg->ns_mode);
    ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);

    return ret;
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
        {"ns", cmd_dev_set_ns},           //
        {0},                              //
    };
    return exec_cmd(cfg, cmds);
}

int admin_cmd_dev_expose(const char *dev_name, const char *ns)
{
    int ret = 0;

    int ns_fd = admin_get_ns_fd(ns);
    if (ns_fd < 0) {
        (void)printf("Failed to get ns fd, ns %s.\n", ns);
        return ns_fd;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_EXPOSE_DEV_NS, 0);
    if (msg == NULL) {
        ret = -ENOMEM;
        goto close_ns_fd;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, ns_fd);
    ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);

close_ns_fd:
    (void)close(ns_fd);
    return ret;
}

static int cmd_dev_expose(admin_config_t *cfg)
{
    int ret = 0;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_ns(cfg)) != 0) {
        return ret;
    }
    ret = admin_cmd_dev_expose(cfg->dev_name, cfg->ns);
    if (ret != 0) {
        printf("Failed to expose dev\n");
        return ret;
    }
    return ret;
}

int admin_cmd_dev_unexpose(const char *dev_name, const char *ns)
{
    int ret = 0;
    int ns_fd = admin_get_ns_fd(ns);
    if (ns_fd < 0) {
        (void)printf("Failed to get ns fd, ns %s.\n", ns);
        return ns_fd;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_UNEXPOSE_DEV_NS, 0);
    if (msg == NULL) {
        ret = -ENOMEM;
        goto close_ns_fd;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, ns_fd);
    ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);

close_ns_fd:
    (void)close(ns_fd);
    return ret;
}

static int cmd_dev_unexpose(admin_config_t *cfg)
{
    int ret = 0;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_ns(cfg)) != 0) {
        return ret;
    }
    ret = admin_cmd_dev_unexpose(cfg->dev_name, cfg->ns);
    if (ret != 0) {
        printf("Failed to unexpose dev\n");
        return ret;
    }
    return ret;
}

int admin_cmd_dev(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_dev_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_dev_usage},          //
        {"sharing", cmd_dev_toggle_sharing},       //
        {"set", cmd_dev_set},           //
        {"expose", cmd_dev_expose},     //
        {"unexpose", cmd_dev_unexpose}, //
        {0},                            //
    };
    return exec_cmd(cfg, cmds);
}

// Legacy cmd
int admin_cmd_set_ns_mode_legacy(admin_config_t *cfg)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_NS_MODE, 0);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    admin_nl_put_u8(msg, UBCORE_ATTR_NS_MODE, cfg->ns_mode);

    int ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);
    return ret;
}

int admin_cmd_set_dev_ns_legacy(admin_config_t *cfg)
{
    int ns_fd = admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("set ns failed, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_DEV_NS, 0);
    if (msg == NULL) {
        close(ns_fd);
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, ns_fd);

    int ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);
    close(ns_fd);
    return ret;
}
