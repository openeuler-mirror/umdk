/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * Description: uvs cmd tlv parse source file
 * Author: Chen Yutao
 * Create: 2024-08-06
 * Note:
 * History: 2024-08-06 create this file to support uvs cmd tlv
 */

#include <stdlib.h>
#include <errno.h>

#include "tpsa_log.h"
#include "tpsa_ioctl.h"
#include "uvs_cmd_tlv.h"

static inline void fill_attr(uvs_cmd_attr_t *attr, uint16_t type, uint16_t field_size, uint16_t el_num,
    uint16_t el_size, uintptr_t data)
{
    *attr = (uvs_cmd_attr_t) {
        .type = type,
        .flag = 0,
        .field_size = field_size,
        .attr_data.bs = {.el_num = el_num, .el_size = el_size},
        .data = data,
    };
}

/**
 * Fill attr with a field, which is a value or an array taken as a whole.
 * @param v Full path of field, e.g. `arg->out.attr.dev_cap.feature`
 */
#define ATTR(attr, type, v) fill_attr(attr, type, sizeof(v), 1, 0, (uintptr_t)(&(v)))

/**
 * Fill attr with a field, which belongs to an array of structs.
 * @param v1 Full path of struct array, e.g. `arg->out.attr.port_attr`
 * @param v2 Path relative to struct in array, e.g. `active_speed`
 */
#define ATTR_ARRAY(attr, type, v1, v2) \
    fill_attr(attr, type, sizeof((v1)->v2), ARRAY_SIZE(v1), sizeof((v1)[0]), (uintptr_t)(&((v1)->v2)))
#define ATTR_ARRAY_DYNAMIC(attr, type, v1, el_num) \
    fill_attr(attr, type, sizeof((v1)[0]), el_num, sizeof((v1)[0]), (uintptr_t)(&((v1)[0])))

int uvs_ioctl_set_topo(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_set_topo_t *arg)
{
    uvs_cmd_attr_t attrs[SET_TOPO_IN_NUM] = {0};
    uvs_cmd_attr_t *a = attrs;

    ATTR(a++, SET_TOPO_IN_TOPO_INFO, arg->in.topo_info);
    ATTR(a++, SET_TOPO_IN_TOPO_NUM, arg->in.topo_num);

    return uvs_ioctl_in_global(ioctl_ctx, UVS_CMD_SET_TOPO, (void *)attrs, sizeof(attrs));
}

int uvs_ioctl_get_route_list(tpsa_ioctl_ctx_t *ioctl_ctx, uvs_cmd_get_route_list_t *arg)
{
    uvs_cmd_attr_t attrs[GET_ROUTE_LIST_IN_NUM + GET_ROUTE_LIST_OUT_NUM - UVS_CMD_OUT_TYPE_INIT] = {0};
    uvs_cmd_attr_t *a = attrs;

    ATTR(a++, GET_ROUTE_LIST_IN_ROUTE_PAIR, arg->in);
    ATTR(a++, GET_ROUTE_LIST_OUT_ROUTE_LIST, arg->out);

    return uvs_ioctl_in_global(ioctl_ctx, UVS_CMD_GET_TOPO_EID, (void *)attrs, sizeof(attrs));
}
