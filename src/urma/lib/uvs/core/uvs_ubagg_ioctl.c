/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: uvs ubagg ioctl source file
 * Author: Jiajun Liu
 * Create: 2025-06-05
 * Note:
 * History:
 */
#include "uvs_ubagg_ioctl.h"
#include "tpsa_ioctl.h"
#include "tpsa_log.h"
#include "ub_util.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#define UVS_UBAGG_DEVICE_PATH  "/dev/ubagg"
#define UVS_UBCORE_DEVICE_PATH "/dev/ubcore/ubcore"

int uvs_ubagg_ioctl_create_agg_dev(uvs_eid_t *agg_eid, const char *dev_name)
{
    struct uvs_ubagg_create_dev_arg args = {0};
    struct uvs_ubagg_cmd_hdr hdr = {0};
    int ret;
    size_t dev_name_len;

    if (agg_eid == NULL || dev_name == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    dev_name_len = strnlen(dev_name, UVS_MAX_DEV_NAME_LEN);
    if (dev_name_len == 0 || dev_name_len >= UVS_MAX_DEV_NAME_LEN) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    args.in.agg_eid = *agg_eid;
    (void)snprintf(args.in.dev_name, UVS_MAX_DEV_NAME_LEN, "%s", dev_name);

    hdr.command = UVS_UBAGG_CMD_CREATE_DEV;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(UVS_UBAGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, UVS_UBAGG_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create aggr dev, ret: %d, errno: %d.\n", ret, errno);
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubagg_ioctl_delete_agg_dev(uvs_eid_t *agg_eid)
{
    struct uvs_ubagg_delete_dev_arg args = {0};
    struct uvs_ubagg_cmd_hdr hdr = {0};
    int ret;

    args.in.agg_eid = *agg_eid;

    hdr.command = UVS_UBAGG_CMD_DELETE_DEV;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(UVS_UBAGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, UVS_UBAGG_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to remove aggr dev, ret: %d, errno: %d.\n", ret, errno);
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubagg_ioctl_get_dev_name_by_eid(uvs_eid_t *eid, char *buf, size_t len)
{
    struct uvs_ubagg_get_dev_name_arg args = {0};
    struct uvs_ubagg_cmd_hdr hdr = {0};
    int ret;

    args.in.eid = *eid;

    hdr.command = UVS_UBAGG_CMD_GET_DEV_NAME;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(UVS_UBAGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, UVS_UBAGG_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get dev name by eid, ret: %d, errno: %d.\n", ret, errno);
        close(dev_fd);
        return -1;
    }

    strncpy(buf, args.out.dev_name, len);

    close(dev_fd);
    return 0;
}

int uvs_ubagg_ioctl_set_topo(void *topo_info, int topo_num)
{
    struct uvs_ubagg_set_topo_info args = {0};
    struct uvs_ubagg_cmd_hdr hdr = {0};
    int ret;

    args.in.topo = topo_info;
    args.in.topo_num = (uint32_t)topo_num;

    hdr.command = UVS_UBAGG_CMD_SET_TOPO_INFO;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(UVS_UBAGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, UVS_UBAGG_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to set topo info, ret: %d, errno: %d.\n", ret, errno);
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_get_topo(void *topo_map)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_get_topo_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.out.topo_map = topo_map;

    ret = uvs_ioctl_get_topo(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_get_topo fail\n");
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_set_topo(void *topo_info, int topo_num)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_set_topo_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in.topo_info = topo_info;
    arg.in.topo_num = (uint32_t)topo_num;

    ret = uvs_ioctl_set_topo(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_set_topo fail\n");
        close(dev_fd);
        return -1;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_insert_main_ue_eid(const uvs_main_ue_eid_entry_t *entry)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_main_ue_eid_entry_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in.entry = *entry;

    ret = uvs_ioctl_insert_main_ue_eid(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_insert_main_ue_eid fail\n");
        close(dev_fd);
        return ret;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_delete_main_ue_eid(const uvs_eid_t *eid)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_main_ue_eid_delete_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in.eid = *eid;

    ret = uvs_ioctl_delete_main_ue_eid(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_delete_main_ue_eid fail\n");
        close(dev_fd);
        return ret;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_lookup_main_ue_eid(const uvs_eid_t *eid,
    uvs_eid_t *main_ue_eid)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_main_ue_eid_lookup_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in.eid = *eid;

    ret = uvs_ioctl_lookup_main_ue_eid(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_lookup_main_ue_eid fail\n");
        close(dev_fd);
        return ret;
    }

    *main_ue_eid = arg.out.main_ue_eid;
    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_flush_main_ue_eid(void)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;

    ret = uvs_ioctl_flush_main_ue_eid(&ioctl_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_flush_main_ue_eid fail\n");
        close(dev_fd);
        return ret;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_insert_main_ue_eid_batch(
    const uvs_main_ue_eid_batch_entry_t *entry)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_main_ue_eid_batch_t arg = {0};
    int ret = 0;
    int dev_fd;

    if (entry == NULL) {
        return -EINVAL;
    }

    dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in.entry = *entry;

    ret = uvs_ioctl_insert_main_ue_eid_batch(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("uvs_ubcore_ioctl_insert_main_ue_eid_batch fail\n");
        close(dev_fd);
        return ret;
    }

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_get_route_list(const uvs_route_t *route, uvs_route_list_t *route_list)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_get_route_list_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in = *route;

    ret = uvs_ioctl_get_route_list(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get route list, ret: %d, errno: %d.\n",
                     ret, errno);
        close(dev_fd);
        return ret;
    }

    *route_list = arg.out;

    close(dev_fd);
    return 0;
}

int uvs_ubcore_ioctl_get_path_set(const uvs_eid_t *src_bondind_eid,
                                  const uvs_eid_t *dst_bonding_eid,
                                  enum uvs_tp_type tp_type, bool iodie_level,
                                  uvs_path_set_t *uvs_path_set)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_get_path_set_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    memcpy(&arg.in.src_bonding_eid, src_bondind_eid, sizeof(uvs_eid_t));
    memcpy(&arg.in.dst_bonding_eid, dst_bonding_eid, sizeof(uvs_eid_t));
    arg.in.tp_type = tp_type;
    arg.in.iodie_level = iodie_level;

    ret = uvs_ioctl_get_path_set(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get path set, ret: %d, errno: %d.\n",
                     ret, errno);
        close(dev_fd);
        return ret;
    }

    *uvs_path_set = arg.out;

    close(dev_fd);
    return 0;
}
