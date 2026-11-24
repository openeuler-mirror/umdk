/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping netlink helper header file
 * Author: Wang Hang
 * Create: 2026-06-18
 * Note:
 * History: 2026-06-18 Create file
 */

#ifndef URMA_PING_NETLINK_H
#define URMA_PING_NETLINK_H

#include "ping_run.h"

typedef struct ping_core_cmd_topo_info {
    struct {
        int node_idx;
    } in;
    struct {
        uint32_t node_num;
        struct urma_ping_ubcore_topo_node topo_info;
    } out;
} ping_core_cmd_topo_info_t;

/* The caller owns and may reuse arg; its output is valid only on success. */
int ping_get_topo_info(uint32_t node_idx, ping_core_cmd_topo_info_t *arg);

#endif
