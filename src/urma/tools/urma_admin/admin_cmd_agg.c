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
#include <sys/ioctl.h>

#include "admin_cmd.h"
#include "ub_util.h"

#define ADMIN_AGG_DEVICE_PATH "/dev/ubagg"

static int cmd_agg_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin agg add [ EID ]\n"
           "       urma_admin agg del [ EID ]\n");
    return 0;
}

static int admin_cmd_agg_add(urma_eid_t eid)
{
    struct cmd_agg_add_arg args = {0};
    struct admin_cmd_hdr hdr = {0};
    int ret;

    args.in.agg_eid = eid;

    hdr.command = CMD_AGG_ADD;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(ADMIN_AGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        printf("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, ADMIN_AGG_CMD, &hdr);
    if (ret != 0) {
        printf("Failed to create aggr dev, ret: %d, errno: %d.\n", ret, errno);
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

static int cmd_agg_add(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_eid(cfg)) != 0) {
        return ret;
    }

    ret = admin_cmd_agg_add(cfg->eid);
    if (ret != 0) {
        printf("Failed to add agg dev\n");
        return ret;
    }

    return 0;
}

static int admin_cmd_agg_del(urma_eid_t eid)
{
    struct cmd_agg_del_arg args = {0};
    struct admin_cmd_hdr hdr = {0};
    int ret;

    args.in.agg_eid = eid;

    hdr.command = CMD_AGG_DEL;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(ADMIN_AGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        printf("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, ADMIN_AGG_CMD, &hdr);
    if (ret != 0) {
        printf("Failed to del aggr dev, ret: %d, errno: %d.\n", ret, errno);
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

static int cmd_agg_del(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_eid(cfg)) != 0) {
        return ret;
    }

    ret = admin_cmd_agg_del(cfg->eid);
    if (ret != 0) {
        printf("Failed to del agg dev\n");
        return ret;
    }
    return 0;
}

int admin_cmd_agg(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_agg_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_agg_usage}, //
        {"add", cmd_agg_add},  //
        {"del", cmd_agg_del},  //
        {0},                   //
    };
    return exec_cmd(cfg, cmds);
}
