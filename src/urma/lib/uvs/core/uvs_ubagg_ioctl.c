/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: uvs ubagg ioctl source file
 * Author: Jiajun Liu
 * Create: 2025-06-05
 * Note:
 * History:
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "ub_util.h"
#include "tpsa_log.h"
#include "tpsa_ioctl.h"
#include "uvs_ubagg_ioctl.h"

#define UVS_UBAGG_DEVICE_PATH "/dev/ubagg"
#define UVS_UBCORE_DEVICE_PATH "/dev/ubcore/ubcore"

int uvs_ubagg_ioctl_set_topo(void *topo_info, int topo_num)
{
    struct uvs_ubagg_set_topo_info args = {0};
    struct uvs_ubagg_cmd_hdr hdr = {0};
    int ret;

    args.in.topo = topo_info;
    args.in.topo_num = (uint32_t)topo_num;

    hdr.command = UVS_UBAGG_CMD_SET_TOPO;
    hdr.args_addr = (uint64_t)(uintptr_t)&args;
    hdr.args_len = sizeof(args);

    int dev_fd = open(UVS_UBAGG_DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ret = ioctl(dev_fd, UVS_UBAGG_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("ioctl to set topo info fail\n");
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

int uvs_ubcore_ioctl_get_topo_eid(uint32_t tp_type,
    uvs_eid_t *src_v_eid, uvs_eid_t *dst_v_eid,
    uvs_eid_t *src_p_eid, uvs_eid_t *dst_p_eid)
{
    tpsa_ioctl_ctx_t ioctl_ctx = {0};
    uvs_cmd_get_topo_eid_t arg = {0};
    int ret = 0;

    int dev_fd = open(UVS_UBCORE_DEVICE_PATH, O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_ctx.ubcore_fd = dev_fd;
    arg.in.tp_type = tp_type;
    arg.in.src_v_eid = *src_v_eid;
    arg.in.dst_v_eid = *dst_v_eid;

    ret = uvs_ioctl_get_topo_eid(&ioctl_ctx, &arg);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get topo eid, ret: %d, errno: %d.\n",
            ret, errno);
        close(dev_fd);
        return ret;
    }

    *src_p_eid = arg.out.src_p_eid;
    *dst_p_eid = arg.out.dst_p_eid;

    close(dev_fd);
    return 0;
}
