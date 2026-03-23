/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ubagg ioctl and user ctl cmd and struct header
 * Author: Ma Chuan
 * Create: 2025-06-10
 * Note:
 * History:
 */
#ifndef UBAGG_IOCTL_H
#define UBAGG_IOCTL_H

#include <stdint.h>
#include "topo_info.h"
#include "urma_ubagg.h"
#include "urma_types.h"

#define UBAGG_MAX_DEV_NAME_LEN    (64)

struct ubagg_set_topo_info {
    struct {
        void *topo;
        uint32_t topo_num;
    } in;
};

typedef enum ubagg_userctl_opcode {
    GET_SLAVE_DEVICE = 1,
    GET_TOPO_INFO    = 2,
} ubagg_userctl_opcode_t;

struct ubagg_slave_device {
    int slave_dev_num;
    char slave_dev_name[URMA_UBAGG_DEV_MAX_NUM][UBAGG_MAX_DEV_NAME_LEN];
};

struct ubagg_topo_info_out {
    bondp_topo_node_t topo_info[MAX_NODE_NUM];
    uint32_t node_num;
};
#endif // UBAGG_IOCTL_H
