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
#define UBAGG_EID_SIZE            (sizeof(urma_eid_t))

typedef enum ubagg_cmd {
    UBAGG_ADD_DEV = 1,
    UBAGG_RMV_DEV,
	UBAGG_SET_TOPO_INFO
} ubagg_cmd_t;

struct ubagg_cmd_hdr {
    uint32_t command;
    uint32_t args_len;
    uint64_t args_addr;
};

#define UBAGG_CMD_MAGIC 'B'
#define UBAGG_CMD _IOWR(UBAGG_CMD_MAGIC, 1, struct ubagg_cmd_hdr)

struct ubagg_add_dev {
    struct {
        int slave_dev_num;
        char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
        char slave_dev_name[URMA_UBAGG_DEV_MAX_NUM][UBAGG_MAX_DEV_NAME_LEN];
        urma_eid_t eid;
        struct urma_device_cap dev_cap;
    } in;
};

struct ubagg_rmv_dev {
    struct {
        char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
    } in;
};

struct ubagg_set_topo_info {
    struct {
        void *topo;
        uint32_t topo_num;
    } in;
};

typedef enum ubagg_userctl_opcode {
    GET_SLAVE_DEVICE = 1,
    GET_TOPO_INFO    = 2,
    GET_JFR_ID = 3,
    GET_JETTY_ID = 4,
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