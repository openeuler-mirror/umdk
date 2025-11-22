/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: UVS API
 * Author: Zheng Hongqin
 * Create: 2023-10-11
 * Note:
 * History:
 */

#ifndef UVS_API_H
#define UVS_API_H

#include <stdint.h>
#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * UVS set topo info which gets from MXE module.
 * @param[in] topo: topo info of one bonding device
 * @param[in] topo_num: number of bonding devices
 * Return: 0 on success, other value on error
 */
int uvs_set_topo_info(void *topo, uint32_t topo_num);

/**
 * Get primary or port eid from topo info.
 * @param[in] tp_type: tp type, 0-RTP, 1-CTP, 2-UTP,
                       refer to urma_tp_type_t;
 * @param[in] src_v_eid: source virtual eid, refer to
                       source bonding eid;
 * @param[in] dst_v_eid: dest virtual eid, refer to
                       dest bonding eid;
 * @param[out] src_p_eid: source physical eid, refer to
                       source primary or port eid;
 * @param[out] src_v_eid: dest physical eid, refer to
                       dest primary or port eid;
 * Return: 0 on success, other value on error
 */
int uvs_get_topo_eid(uint32_t tp_type, uvs_eid_t *src_v_eid,
    uvs_eid_t *dst_v_eid, uvs_eid_t *src_p_eid,
    uvs_eid_t *dst_p_eid);

#ifdef __cplusplus
}
#endif

#endif