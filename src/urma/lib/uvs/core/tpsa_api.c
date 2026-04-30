/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: tpsa api file
 * Author: Zheng Hongqin
 * Create: 2023-11-22
 * Note:
 * History:
 */

#include "tpsa_ioctl.h"
#include "uvs_api.h"
#include "uvs_cmd_tlv.h"
#include "uvs_private_api.h"
#include "uvs_ubagg_ioctl.h"
#include <errno.h>
#include <sys/syscall.h>

#define UVS_MAX_TOPO_NUM 64

static inline bool uvs_eid_is_valid(const uvs_eid_t *eid)
{
    return !(eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0);
}

int uvs_create_agg_dev(uvs_eid_t *agg_eid, const char *dev_name)
{
    int ret = 0;
    size_t dev_name_len;

    if (agg_eid == NULL || dev_name == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    dev_name_len = strnlen(dev_name, UVS_MAX_DEV_NAME_LEN);
    if (dev_name_len == 0 || dev_name_len >= UVS_MAX_DEV_NAME_LEN) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_create_agg_dev(agg_eid, dev_name);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to create agg dev in ubagg, ret = %d.\n", ret);
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
        TPSA_LOG_ERR("failed to delete agg dev in ubagg, ret = %d.\n", ret);
        return ret;
    }

    return ret;
}

int uvs_get_device_name_by_eid(uvs_eid_t *eid, char *buf, size_t len)
{
    int ret = 0;

    if (buf == NULL || len == 0 || len > UVS_MAX_DEV_NAME_LEN || eid == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_get_dev_name_by_eid(eid, buf, len);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to get dev name by eid in ubagg, ret = %d.\n", ret);
        return ret;
    }

    return 0;
}

static int uvs_set_topo_info_inner(void *topo, uint32_t topo_num)
{
    int ret;

    if (!topo || topo_num > UVS_MAX_TOPO_NUM || topo_num == 0) {
        TPSA_LOG_ERR("topo is NULL or topo_num is invalid.\n");
        return -EINVAL;
    }

    ret = uvs_ubagg_ioctl_set_topo(topo, (int)topo_num);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to set topo info in ubagg, ret = %d.\n", ret);
        return ret;
    } else {
        TPSA_LOG_INFO("success to set topo info in ubagg\n");
    }

    ret = uvs_ubcore_ioctl_set_topo(topo, (int)topo_num);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to set topo info in ubcore, ret = %d.\n", ret);
    } else {
        TPSA_LOG_INFO("success to set topo info in ubcore\n");
    }

    return ret;
}

static int uvs_get_topo_info_inner(void *topo)
{
    int ret;

    if (!topo) {
        TPSA_LOG_ERR("topo is NULL.\n");
        return -EINVAL;
    }

    ret = uvs_ubcore_ioctl_get_topo(topo);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to get topo info in ubcore.\n");
        return ret;
    } else {
        TPSA_LOG_INFO("success to get topo info in ubcore\n");
    }

    return ret;
}

int uvs_set_topo_info(void *topo_buf, uint32_t node_size, uint32_t node_num)
{
    uint32_t size = sizeof(struct urma_topo_node);

    if (size != node_size) {
        TPSA_LOG_ERR("node size not match, urma=%u, ubse=%u\n", size, node_size);
        return -EINVAL;
    }

    uvs_get_api_rdlock();
    int ret = uvs_set_topo_info_inner(topo_buf, node_num);
    put_uvs_lock();
    return ret;
}

int uvs_get_topo_info(void *topo)
{
    int ret = 0;
    uvs_get_api_rdlock();
    ret = uvs_get_topo_info_inner(topo);
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
        TPSA_LOG_ERR("Failed to get route list, ret = %d.\n", ret);
    }
    return ret;
}

static void uvs_filter_path_set(uvs_path_set_t *uvs_path_set, bool multi_path)
{
    uvs_path_set_t filtered = *uvs_path_set;
    uint32_t i, j;

    filtered.path_count = 0;
    for (i = 0, j = 0; i < uvs_path_set->path_count; i++) {
        uvs_path_t *path_src = &uvs_path_set->paths[i];
        uvs_path_t *path_dst = &filtered.paths[j];

        if (multi_path && path_src->src_port.port_idx != 255) {
            continue;
        }

        if (!multi_path && path_src->src_port.port_idx == 255) {
            continue;
        }

        *path_dst = *path_src;
        j++;
    }
    filtered.path_count = j;
    *uvs_path_set = filtered;
}

int uvs_get_path_set(const uvs_eid_t *src_bondind_eid,
                     const uvs_eid_t *dst_bonding_eid,
                     enum uvs_tp_type tp_type, bool multi_path,
                     uvs_path_set_t *uvs_path_set)
{
    int ret = 0;

    if (src_bondind_eid == NULL || dst_bonding_eid == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    if (tp_type > UVS_UTP || tp_type < UVS_RTP) {
        TPSA_LOG_ERR("Invalid tp_type.\n");
        return -EINVAL;
    }

    if (!uvs_eid_is_valid(src_bondind_eid) ||
        !uvs_eid_is_valid(dst_bonding_eid) ||
        uvs_path_set == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }
    ret = uvs_ubcore_ioctl_get_path_set(src_bondind_eid,
                                        dst_bonding_eid, tp_type, multi_path, uvs_path_set);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get path set, ret = %d.\n", ret);
        return ret;
    }
    // Temporary fix for the issue where kernel FULLMESH_1D returns all eids
    if (uvs_path_set->topo_type == UVS_TOPO_TYPE_FULLMESH_1D) {
        uvs_filter_path_set(uvs_path_set, multi_path);
        TPSA_LOG_DEBUG("Filtered path set for FULLMESH_1D\n");
    }
    return ret;
}
