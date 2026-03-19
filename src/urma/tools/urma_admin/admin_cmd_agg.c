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

#include "ub_util.h"
#include "urma_api.h"

#include "admin_cmd.h"

#define ADMIN_AGG_DEVICE_PATH "/dev/ubagg"

static int cmd_agg_usage(admin_config_t *cfg)
{
    printf("Usage:\n"
           "  urma_admin agg add <eid>\n"
           "  urma_admin agg del <eid>\n"
           "  urma_admin agg expose <eid> <netns>\n"
           "\n"
           "Options:\n"
           "  <eid>    EID value\n"
           "  <netns>  Network namespace path (e.g., /proc/$pid/ns/net)\n");
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

    /* Hacky: bonding_dev_0 is hardcoded in other components. Deletion is disabled for now. */
    urma_init_attr_t init_attr = {0};

    urma_init(&init_attr);
    urma_device_t *urma_dev = urma_get_device_by_eid(eid, URMA_TRANSPORT_UB);
    bool is_dev_disallowed = strcmp(urma_dev->name, "bonding_dev_0");
    urma_uninit();

    if (is_dev_disallowed == 0) {
        printf("bonding_dev_0 cannot be deleted now.\n");
        return -1;
    }

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

static void nl_unexpose_device_by_dev_name(char *dev_name, int ns_fd)
{
    printf("Unexposing device %s in netns %d.\n", dev_name, ns_fd);
    int ret = admin_nl_unexpose_dev_ns(dev_name, ns_fd);
    if (ret != 0) {
        (void)printf("Failed to unexpose device %s in netns %d, ret=%d.\n", dev_name, ns_fd, ret);
    }
}

static int expose_agg_device(admin_urma_topo_bonding_dev_t *bonding_info, int ns_fd)
{
    int ret = 0;
    int ue_idx = 0;

    printf("Exposing bonding device %s in netns %d\n", bonding_info->dev_name, ns_fd);
    ret = admin_nl_expose_dev_ns(bonding_info->dev_name, ns_fd);
    if (ret != 0) {
        printf("Failed to expose bonding device %s in netns %d, ret=%d\n", bonding_info->dev_name, ns_fd, ret);
        return ret;
    }

    printf("Setting EID index %d in bonding device %s, netns %d\n",
        bonding_info->bonding_eid_idx, bonding_info->dev_name, ns_fd);
    ret = admin_nl_set_eid_ns(bonding_info->dev_name, bonding_info->bonding_eid_idx, ns_fd);
    if (ret != 0) {
        printf("Failed to set EID index %d in bonding device %s, netns %d, ret=%d\n", bonding_info->bonding_eid_idx,
               bonding_info->dev_name, ns_fd, ret);
        admin_nl_unexpose_dev_ns(bonding_info->dev_name, ns_fd);
        return ret;
    }

    for (ue_idx = 0; ue_idx < IODIE_NUM; ue_idx++) {
        admin_urma_topo_physical_dev_t *dev_info = &bonding_info->physical_devs[ue_idx];
        if (dev_info->primary_eid_idx == UINT32_MAX) {
            printf("DIE %u is empty.\n", ue_idx);
            continue;
        }
        printf("Exposing primary device %s in netns %d\n", dev_info->dev_name, ns_fd);
        ret = admin_nl_expose_dev_ns(dev_info->dev_name, ns_fd);
        if (ret != 0) {
            printf("Failed to expose primary device %s in netns %d, ret=%d\n", dev_info->dev_name, ns_fd, ret);
            goto unexpose_agg_dev;
        }

        printf("Setting EID index %d in primary device %s, netns %d\n", dev_info->primary_eid_idx, dev_info->dev_name,
               ns_fd);
        ret = admin_nl_set_eid_ns(dev_info->dev_name, dev_info->primary_eid_idx, ns_fd);
        if (ret != 0) {
            printf("Failed to set EID index %d in primary device %s, netns %d, ret=%d\n", dev_info->primary_eid_idx,
                   dev_info->dev_name, ns_fd, ret);
            admin_nl_unexpose_dev_ns(dev_info->dev_name, ns_fd);
            goto unexpose_agg_dev;
        }

        for (int i = 0; i < PORT_NUM; i++) {
            if (dev_info->port_eid_idx[i] == UINT32_MAX) {
                printf("DIE %u port %u is empty.\n", ue_idx, i);
                continue;
            }
            printf("Setting port EID index %d in primary device %s, netns %d\n", dev_info->port_eid_idx[i],
                   dev_info->dev_name, ns_fd);
            ret = admin_nl_set_eid_ns(dev_info->dev_name, dev_info->port_eid_idx[i], ns_fd);
            if (ret != 0) {
                printf("Failed to set port EID index %d in primary device %s, netns %d, ret=%d\n",
                       dev_info->port_eid_idx[i], dev_info->dev_name, ns_fd, ret);
            }
        }
    }

    return 0;

unexpose_agg_dev:
    if (ue_idx > 0) {
        for (int i = ue_idx - 1; i >= 0; i--) {
            nl_unexpose_device_by_dev_name(bonding_info->physical_devs[i].dev_name, ns_fd);
        }
    }

    admin_nl_unexpose_dev_ns(bonding_info->dev_name, ns_fd);
    return ret;
}

static int admin_cmd_agg_expose(urma_eid_t *eid, int ns_fd)
{
    admin_urma_topo_bonding_dev_t bonding_dev;
    int ret;

    (void)ns_fd;
    ret = admin_cmd_get_topo_bonding_dev_by_eid(eid, &bonding_dev);
    if (ret != 0) {
        (void)printf("Failed to get topo bonding dev by eid, ret=%d.\n", ret);
        return ret;
    }
    ret = expose_agg_device(&bonding_dev, ns_fd);
    return 0;
}

static int cmd_agg_expose(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_eid(cfg)) != 0) {
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

    ret = admin_cmd_agg_expose(&cfg->eid, ns_fd);
    if (ret != 0) {
        printf("Failed to expose agg dev\n");
        close(ns_fd);
        return ret;
    }
    close(ns_fd);
    return 0;
}

int admin_cmd_agg(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_agg_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_agg_usage},
        {"add", cmd_agg_add},
        {"del", cmd_agg_del},
        {"expose", cmd_agg_expose},
        {0},
    };
    return exec_cmd(cfg, cmds);
}
