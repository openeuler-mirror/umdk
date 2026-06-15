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

#include "admin_file_ops.h"
#include "admin_netlink.h"

#include "admin_cmd.h"

static int admin_nl_set_dev_ns(const char *dev_name, int ns_fd)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_DEV_NS, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, (uint32_t)ns_fd);
    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    return ret;
}

int admin_nl_expose_dev_ns(const char *dev_name, int ns_fd)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_EXPOSE_DEV_NS, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, (uint32_t)ns_fd);
    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    return ret;
}

int admin_nl_unexpose_dev_ns(const char *dev_name, int ns_fd)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_UNEXPOSE_DEV_NS, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, (uint32_t)ns_fd);
    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    return ret;
}

static int cmd_dev_usage(admin_config_t *cfg)
{
    printf("Usage:\n"
           "  urma_admin dev set <dev> ns <netns>\n"
           "  urma_admin dev set <dev> sl --sl <sl> --priority <priority>\n"
           "  urma_admin dev expose <dev> <netns>\n"
           "  urma_admin dev unexpose <dev> <netns>\n"
           "\n"
           "Options:\n"
           "  <dev>    Device name (e.g., udma1)\n"
           "  <netns>  Network namespace path (e.g., /proc/$pid/ns/net)\n");
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

    if ((ret = admin_nl_set_dev_ns(cfg->dev_name, ns_fd)) != 0) {
        close(ns_fd);
        return ret;
    }

    close(ns_fd);
    return ret;
}

static int cmd_dev_set_sl(admin_config_t *cfg)
{
    int ret = 0;

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_SL, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_PRIORITY, (uint32_t)cfg->priority);
    admin_nl_put_u32(msg, UBCORE_ATTR_SL, (uint32_t)cfg->SL);
    ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    if (ret < 0) {
        (void)printf("set_sl fail, please check input, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    return 0;
}

static int cmd_dev_set(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_dev_usage},
        {"ns", cmd_dev_set_ns},
        {"sl", cmd_dev_set_sl},
        {0},
    };
    return exec_cmd(cfg, cmds);
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

    int ns_fd = admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("Failed to get ns fd, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    if ((ret = admin_nl_expose_dev_ns(cfg->dev_name, ns_fd)) != 0) {
        close(ns_fd);
        return ret;
    }

    close(ns_fd);
    return 0;
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

    int ns_fd = admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("Failed to get ns fd, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    if ((ret = admin_nl_unexpose_dev_ns(cfg->dev_name, ns_fd)) != 0) {
        close(ns_fd);
        return ret;
    }

    close(ns_fd);
    return 0;
}

int admin_cmd_dev(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_dev_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_dev_usage},
        {"set", cmd_dev_set},
        {"expose", cmd_dev_expose},
        {"unexpose", cmd_dev_unexpose},
        {0},
    };
    return exec_cmd(cfg, cmds);
}

// Legacy cmd
int admin_cmd_set_ns_mode_legacy(admin_config_t *cfg)
{
    return admin_nl_set_dev_sharing(cfg->dev_ns_mode == 1);
}

int admin_cmd_set_dev_ns_legacy(admin_config_t *cfg)
{
    int ns_fd = admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("set ns failed, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    int ret = admin_nl_set_dev_ns(cfg->dev_name, ns_fd);

    close(ns_fd);
    return ret;
}
