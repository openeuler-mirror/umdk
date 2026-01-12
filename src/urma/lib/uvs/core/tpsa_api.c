/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: tpsa api file
 * Author: Zheng Hongqin
 * Create: 2023-11-22
 * Note:
 * History:
 */

#include <sys/syscall.h>
#include <errno.h>
#include "uvs_api.h"
#include "uvs_cmd_tlv.h"
#include "tpsa_ioctl.h"
#include "uvs_private_api.h"
#include "uvs_ubagg_ioctl.h"

#define UVS_MAX_TOPO_NUM 16

int uvs_create_agg_dev(uvs_eid_t *agg_eid)
{
    int ret = 0;

    if (agg_eid == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_create_agg_dev(agg_eid);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to create agg dev in ubagg.\n");
        return ret;
    }

    return ret;
}

int uvs_delete_agg_dev(uvs_eid_t *agg_eid)
{
    int ret = 0;

    if (agg_eid == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_delete_agg_dev(agg_eid);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to delete agg dev in ubagg.\n");
        return ret;
    }

    return ret;
}

int uvs_get_device_name_by_eid(uvs_eid_t *eid, char *buf, size_t len)
{
    int ret = 0;

    if (buf == NULL || len == 0) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_get_dev_name_by_eid(eid, buf, len);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to get dev name by eid in ubagg.\n");
        return ret;
    }

    return 0;
}

int uvs_set_topo_info_inner(void *topo, uint32_t topo_num)
{
    int ret;

    if (!topo || topo_num > UVS_MAX_TOPO_NUM || topo_num == 0) {
        TPSA_LOG_ERR("topo is NULL or topo_num is invalid.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_set_topo(topo, topo_num);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to set topo info in ubagg.\n");
        return ret;
    } else {
        TPSA_LOG_INFO("success to set topo info in ubagg\n");
    }

    ret = uvs_ubcore_ioctl_set_topo(topo, topo_num);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to set topo info in ubcore.\n");
    } else {
        TPSA_LOG_INFO("success to set topo info in ubcore\n");
    }

    return ret;
}

int uvs_set_topo_info(void *topo, uint32_t topo_num)
{
    int ret = 0;
    uvs_get_api_rdlock();
    ret = uvs_set_topo_info_inner(topo, topo_num);
    put_uvs_lock();
    return ret;
}

int uvs_get_route_list(const uvs_route_t *route, uvs_route_list_t *route_list)
{
    int ret = 0;
    if (route == NULL || route_list == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }
    ret = uvs_ubcore_ioctl_get_route_list(route, route_list);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get route list, ret: %d.\n", ret);
    }
    return ret;
}
