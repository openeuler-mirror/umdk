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

static inline bool urma_eid_is_valid(urma_eid_t *eid)
{
    return !(eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0);
}

static tool_topo_agg_dev_t *get_topo_agg_dev_by_agg_eid(tool_topo_map_t *topo_map, urma_eid_t *agg_eid)
{
    for (int i = 0; i < topo_map->node_num; i++) {
        tool_topo_info_t *topo_info = &topo_map->topo_infos[i];
        for (uint32_t j = 0; j < DEV_NUM; j++) {
            tool_topo_agg_dev_t *agg_dev = &topo_info->agg_devs[j];
            if (memcmp(agg_dev->agg_eid, agg_eid, sizeof(urma_eid_t)) == 0) {
                return agg_dev;
            }
        }
    }
    return NULL;
}

static int get_eid_idx_from_list(urma_eid_info_t *eid_list, urma_eid_t *target_eid)
{
    if (urma_eid_is_valid(target_eid) == false) {
        return -1;
    }

    for (uint32_t i = 0; i < URMA_MAX_EID_CNT; i++) {
        if (memcmp(&eid_list[i].eid, target_eid, sizeof(urma_eid_t)) == 0) {
            return eid_list[i].eid_index;
        }
    }

    return -1;
}

static void nl_unexpose_device_by_eid(const char *eid, int ns_fd)
{
    char dev_name[URMA_ADMIN_MAX_DEV_NAME];
    int ret = admin_get_device_name_by_eid((urma_eid_t *)eid, dev_name, sizeof(dev_name));
    if (ret != 0) {
        printf("Failed to get dev by eid.\n");
        return;
    }
    printf("Unexposing device %s in netns %d.\n", dev_name, ns_fd);
    ret = admin_nl_unexpose_dev_ns(dev_name, ns_fd);
    if (ret != 0) {
        (void)printf("Failed to unexpose device %s in netns %d, ret=%d.\n", dev_name, ns_fd, ret);
    }
}

static int nl_expose_agg_device(struct tool_topo_agg_dev *agg_dev, int ns_fd)
{
    int ret = 0;
    int ue_idx = 0;
    urma_eid_info_t *bonding_eid_list = NULL;
    char bonding_dev_name[URMA_MAX_NAME] = {0};

    (void)printf("bonding EID: " EID_FMT "\n", EID_RAW_ARGS(agg_dev->agg_eid));

    ret = admin_get_eid_list_by_eid((urma_eid_t *)agg_dev->agg_eid, &bonding_eid_list, bonding_dev_name);
    if (ret != 0) {
        printf("Failed to get device info for bonding device, ret=%d\n", ret);
        return ret;
    }

    int bonding_eid_idx = get_eid_idx_from_list(bonding_eid_list, (urma_eid_t *)agg_dev->agg_eid);
    if (bonding_eid_idx < 0) {
        printf("Failed to get EID index for bonding device\n");
        urma_free_eid_list(bonding_eid_list);
        return -EINVAL;
    }

    printf("Exposing bonding device %s in netns %d\n", bonding_dev_name, ns_fd);
    ret = admin_nl_expose_dev_ns(bonding_dev_name, ns_fd);
    if (ret != 0) {
        printf("Failed to expose bonding device %s in netns %d, ret=%d\n", bonding_dev_name, ns_fd, ret);
        urma_free_eid_list(bonding_eid_list);
        return ret;
    }

    printf("Setting EID index %d in bonding device %s, netns %d\n", bonding_eid_idx, bonding_dev_name, ns_fd);
    ret = admin_nl_set_eid_ns(bonding_dev_name, bonding_eid_idx, ns_fd);
    if (ret != 0) {
        printf("Failed to set EID index %d in bonding device %s, netns %d, ret=%d\n", bonding_eid_idx,
               bonding_dev_name, ns_fd, ret);
        admin_nl_unexpose_dev_ns(bonding_dev_name, ns_fd);
        urma_free_eid_list(bonding_eid_list);
        return ret;
    }

    for (ue_idx = 0; ue_idx < IODIE_NUM; ue_idx++) {
        tool_topo_ue_t *ue = &agg_dev->ues[ue_idx];
        urma_eid_info_t *primary_eid_list = NULL;
        char primary_dev_name[URMA_MAX_NAME] = {0};
        ret = admin_get_eid_list_by_eid((urma_eid_t *)ue->primary_eid, &primary_eid_list, primary_dev_name);
        if (ret != 0) {
            printf("Failed to get device info for primary device, ret=%d\n", ret);
            goto unexpose_agg_dev;
        }

        int primary_eid_idx = get_eid_idx_from_list(primary_eid_list, (urma_eid_t *)ue->primary_eid);
        if (primary_eid_idx < 0) {
            printf("Failed to get EID index for primary device\n");
            urma_free_eid_list(primary_eid_list);
            goto unexpose_agg_dev;
        }

        printf("Exposing primary device %s in netns %d\n", primary_dev_name, ns_fd);
        ret = admin_nl_expose_dev_ns(primary_dev_name, ns_fd);
        if (ret != 0) {
            printf("Failed to expose primary device %s in netns %d, ret=%d\n", primary_dev_name, ns_fd, ret);
            urma_free_eid_list(primary_eid_list);
            goto unexpose_agg_dev;
        }

        printf("Setting EID index %d in primary device %s, netns %d\n", primary_eid_idx, primary_dev_name,
               ns_fd);
        ret = admin_nl_set_eid_ns(primary_dev_name, primary_eid_idx, ns_fd);
        if (ret != 0) {
            printf("Failed to set EID index %d in primary device %s, netns %d, ret=%d\n", primary_eid_idx,
                   primary_dev_name, ns_fd, ret);
            admin_nl_unexpose_dev_ns(primary_dev_name, ns_fd);
            urma_free_eid_list(primary_eid_list);
            goto unexpose_agg_dev;
        }

        for (int i = 0; i < PORT_NUM; i++) {
            int port_eid_idx = get_eid_idx_from_list(primary_eid_list, (urma_eid_t *)ue->port_eid[i]);
            if (port_eid_idx < 0) {
                continue;
            }

            printf("Setting port EID index %d in primary device %s, netns %d\n", port_eid_idx,
                   primary_dev_name, ns_fd);
            ret = admin_nl_set_eid_ns(primary_dev_name, port_eid_idx, ns_fd);
            if (ret != 0) {
                printf("Failed to set port EID index %d in primary device %s, netns %d, ret=%d\n", port_eid_idx,
                       primary_dev_name, ns_fd, ret);
            }
        }

        urma_free_eid_list(primary_eid_list);
    }

    urma_free_eid_list(bonding_eid_list);

    return 0;

unexpose_agg_dev:
    if (ue_idx > 0) {
        for (int i = ue_idx - 1; i >= 0; i--) {
            tool_topo_ue_t *ue = &agg_dev->ues[i];
            nl_unexpose_device_by_eid(ue->primary_eid, ns_fd);
        }
    }

    admin_nl_unexpose_dev_ns(bonding_dev_name, ns_fd);
    urma_free_eid_list(bonding_eid_list);

    return ret;
}

static int admin_cmd_agg_expose(urma_eid_t *eid, int ns_fd)
{
    tool_topo_map_t *topo_map = calloc(1, sizeof(tool_topo_map_t));
    if (topo_map == NULL) {
        return -ENOMEM;
    }
    int ret = admin_cmd_get_topo_info(topo_map);
    if (ret != 0) {
        (void)printf("Failed to get topo info, ret=%d.\n", ret);
        goto free_topo;
    }
    struct tool_topo_agg_dev *agg_dev = get_topo_agg_dev_by_agg_eid(topo_map, eid);
    if (agg_dev == NULL) {
        (void)printf("Failed to get agg dev by eid.\n");
        ret = -EINVAL;
        goto free_topo;
    }
    ret = nl_expose_agg_device(agg_dev, ns_fd);
    if (ret != 0) {
        (void)printf("Failed to expose agg device, ret=%d.\n", ret);
        goto free_topo;
    }
free_topo:
    free(topo_map);
    return ret;
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
