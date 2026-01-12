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
#include <stddef.h>
#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_MAX_ROUTES 16

typedef union uvs_route_flag {
    struct {
        uint32_t rtp: 1;
        uint32_t ctp: 1;
        uint32_t utp: 1;
        uint32_t reserved: 29;
    } bs;
    uint32_t value;
} uvs_route_flag_t;

typedef struct uvs_route {
    uvs_eid_t src;
    uvs_eid_t dst;
    uvs_route_flag_t flag;
    uint32_t hops;	// Only supports direct routes, currently 0.
    uint32_t chip_id;
} uvs_route_t;

typedef struct uvs_route_list {
    uint32_t len;
    uvs_route_t buf[UVS_MAX_ROUTES];
} uvs_route_list_t;

/**
 * Create an aggregation device in UVS.
 * @param[in] agg_eid  EID of the aggregation device to be created.
 * @return 0 on success, other value on error.
 */
int uvs_create_agg_dev(uvs_eid_t *agg_eid);

/**
 * Delete an aggregation device from UVS.
 * @param[in] agg_eid  EID of the aggregation device to be deleted.
 * @return 0 on success, other value on error.
 */
int uvs_delete_agg_dev(uvs_eid_t *agg_eid);

/**
 * Get device name by EID.
 * @param[in] eid  EID of the device.
 * @param[in] buf  Buffer to hold the device name.
 * @param[in] len  Length of the buffer.
 * @return 0 on success, other value on error.
 */
int uvs_get_device_name_by_eid(uvs_eid_t *eid, char *buf, size_t len);

/**
 * UVS set topo info which gets from MXE module.
 * @param[in] topo: topo info of one bonding device
 * @param[in] topo_num: number of bonding devices
 * Return: 0 on success, other value on error
 */
int uvs_set_topo_info(void *topo, uint32_t topo_num);

/**
 * Get primary and port eid from topo info.
 * @param[in] route: parameter that contains src_v_eid and dst_v_eid,
 *                          refers to uvs_route_t;
 * @param[out] route_list: a list buffer, containing all routes returned;
 * Return: 0 on success, other value on error
 */
int uvs_get_route_list(const uvs_route_t *route, uvs_route_list_t *route_list);

#ifdef __cplusplus
}
#endif

#endif