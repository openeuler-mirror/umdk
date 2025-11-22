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

int uvs_get_topo_eid(uint32_t tp_type, uvs_eid_t *src_v_eid,
    uvs_eid_t *dst_v_eid, uvs_eid_t *src_p_eid,
    uvs_eid_t *dst_p_eid)
{
    int ret = 0;

    if (src_v_eid == NULL || dst_v_eid == NULL ||
        src_p_eid == NULL || dst_p_eid == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ret = uvs_ubcore_ioctl_get_topo_eid(tp_type,
        src_v_eid, dst_v_eid, src_p_eid, dst_p_eid);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to get topo eid, ret: %d, tp_type: %u.\n",
            ret, tp_type);
    } else {
        TPSA_LOG_INFO("Finish to get topo eid, tp_type: %u.\n",
            tp_type);
    }

    return ret;
}
