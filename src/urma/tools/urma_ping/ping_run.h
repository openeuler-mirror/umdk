/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping run head file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#ifndef URMA_PING_RUN_H
#define URMA_PING_RUN_H

#include "ping_parameters.h"

#define EID_LEN            (16)
#define MAX_PORT_NUM       (9)
#define MAX_NODE_NUM       (64)
#define IODIE_NUM_PER_CHIP (1)
#define IODIE_NUM          (2)
#define PORT_NUM           (9)
#define DEV_NUM            (256)
#define ENTITY_AGG_DEV_NUM (3) // bonding device number per entity

struct urma_ping_ubcore_topo_ue {
    uint32_t chip_id;
    uint32_t die_id;
    uint32_t entity_id;
    char primary_eid[EID_LEN];
    char port_eid[PORT_NUM][EID_LEN];
};

struct urma_ping_ubcore_topo_agg_dev {
    char agg_eid[EID_LEN];
    struct urma_ping_ubcore_topo_ue ues[IODIE_NUM];
};

struct urma_ping_ubcore_topo_link {
    uint32_t peer_node;  // node id
    uint32_t peer_iodie; // iodie idx
    uint32_t peer_port;  // port idx, UINT32_MAX indicates no connection
};

struct urma_ping_ubcore_topo_node {
    uint32_t type;
    uint32_t super_node_id;
    uint32_t node_id;
    uint32_t is_current;
    struct urma_ping_ubcore_topo_link links[IODIE_NUM][PORT_NUM];
    struct urma_ping_ubcore_topo_agg_dev agg_devs[DEV_NUM];
};

typedef struct urma_ping_ubcore_topo_map {
    struct urma_ping_ubcore_topo_node topo_infos[MAX_NODE_NUM];
    uint32_t node_num;
} urma_ping_ubcore_topo_map_t;

int start_ping(ping_cfg_t *cfg);

#endif
