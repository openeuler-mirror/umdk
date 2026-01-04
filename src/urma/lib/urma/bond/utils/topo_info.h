/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Helper structure and functions to handle topo info
 * Author: Ma Chuan
 * Create: 2025-06-04
 * Note:
 * History: 2025-06-04
 */
#ifndef TOPO_INFO_H
#define TOPO_INFO_H

#include <stdbool.h>
#include <stdint.h>
#include "urma_types.h"
#include "bondp_hash_table.h"

#define CNA_LEN (3)
#define EID_LEN (16)
#define PORT_NUM (9)
#define MAX_ALL_PORT_NUM (18)
#define MAX_NODE_NUM (16)
#define IODIE_NUM (2)
#define DEV_NUM (128)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bondp_topo_ue {
    uint32_t socket_id;
    char primary_eid[EID_LEN];
    char port_eid[PORT_NUM][EID_LEN];
} bondp_topo_ue_t;

/* Locate a specific port in topo_infos */
/* All params set to -1 means doesn't exist */
typedef struct bondp_topo_link {
    uint32_t peer_node;
    uint32_t peer_iodie;
    uint32_t peer_port;
} bondp_topo_link_t;

typedef struct bondp_topo_agg_dev {
    char agg_eid[EID_LEN];
    bondp_topo_ue_t ues[IODIE_NUM];
} bondp_topo_agg_dev_t;

typedef struct bondp_topo_node {
    uint32_t id;
    uint32_t is_current;
    bondp_topo_link_t links[IODIE_NUM][PORT_NUM];
    bondp_topo_agg_dev_t agg_devs[DEV_NUM];
} bondp_topo_node_t;

/**
 * Records information about all direct connections between the current device and the target device.
 */
typedef struct direct_connect_device_info {
    bondp_topo_link_t local_map_idx[MAX_ALL_PORT_NUM];
    bondp_topo_link_t target_map_idx[MAX_ALL_PORT_NUM];
    uint32_t direct_num;
} direct_dev_info_t;

typedef struct {
    hmap_node_t hmap_node;
    urma_eid_t agg_eid; /* key: eid of target dev */
    direct_dev_info_t direct_dev_info;
} direct_dev_node_t;

int direct_dev_hash_table_create(bondp_hash_table_t *tbl, uint32_t size);

int direct_dev_hash_table_add(bondp_hash_table_t *tbl, bondp_topo_agg_dev_t *topo_info,
    bondp_topo_link_t *local_map_idx, bondp_topo_link_t *target_map_idx);

direct_dev_node_t *direct_dev_hash_table_lookup(bondp_hash_table_t *tbl, urma_eid_t *key);

typedef struct topo_map {
    bondp_topo_node_t topo_infos[MAX_NODE_NUM];
    uint32_t node_num;
    bondp_hash_table_t direct_dev_hash_table;
} topo_map_t;

/* The following functions needs the caller to check the validity of the parameters */

topo_map_t *create_topo_map(bondp_topo_node_t *topo_infos, uint32_t node_num);

void delete_topo_map(topo_map_t *topo_map);

/**
 * This function requires traversing all EIDS in the topo_map to return a result,
 * with a maximum time complexity of O(MAX_NODE_NUM(16) * (BONDING_EID_NUM(1) +
 * IODIE_NUM(2) * (PRIMARY_EID_NUM(1) + PORT_NUM(9)))) = O(336).
 * @return 0 for success, other for error or not found
 */
int get_bonding_eid_by_target_eid(topo_map_t *topo_map, urma_eid_t *target_eid, urma_eid_t *output);

bondp_topo_agg_dev_t *get_topo_dev_info_by_agg_eid(topo_map_t *topo_map, urma_eid_t *agg_eid);

bool has_direct_route(topo_map_t *topo_map, urma_eid_t *agg_eid);

direct_dev_info_t *get_direct_dev_info_by_agg_eid(topo_map_t *topo_map, urma_eid_t *agg_eid);

#ifdef __cplusplus
}
#endif
#endif // TOPO_INFO_H

