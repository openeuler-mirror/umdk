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

#include "bondp_hash_table.h"
#include "urma_types.h"

#define CNA_LEN            (3)
#define EID_LEN            (16)
#define PORT_NUM           (9)
#define MAX_ALL_PORT_NUM   (18)
#define MAX_NODE_NUM       (1024)
#define IODIE_NUM_PER_CHIP (1)
#define CHIP_NUM           (2)
#define IODIE_NUM          (2)
#define DEV_NUM            (256)
#define TOPO_CONNECTED_MAX_NUM (IODIE_NUM + IODIE_NUM * PORT_NUM)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bondp_topo_ue {
    uint32_t chip_id;
    uint32_t die_id;
    uint32_t entity_id;
    char primary_eid[EID_LEN];
    char port_eid[PORT_NUM][EID_LEN];
    char cna[PORT_NUM][EID_LEN]; // Only for CTP
} bondp_topo_ue_t;

typedef struct bondp_topo_agg_dev {
    char agg_eid[EID_LEN];
    bondp_topo_ue_t ues[IODIE_NUM];
} bondp_topo_agg_dev_t;

typedef struct bondp_topo_node {
    uint32_t type;
    uint32_t super_node_id;
    uint32_t node_id;
    uint32_t is_current;
    bool links[IODIE_NUM * PORT_NUM][IODIE_NUM * PORT_NUM];
    bondp_topo_agg_dev_t agg_devs[DEV_NUM];
} bondp_topo_node_t;

/**
 * Records information about all direct connections between the current device and the target device.
 */
typedef struct eid_mapping_entry {
    hmap_node_t hmap_node;
    urma_eid_t key_eid;
    urma_eid_t bonding_eid;
} eid_mapping_entry_t;

typedef struct topo_map {
    uint32_t node_num;
    bondp_hash_table_t eid_mapping_hash_table;
    bondp_topo_node_t topo_infos[];
} topo_map_t;

/* The following functions needs the caller to check the validity of the parameters */

topo_map_t *create_topo_map(bondp_topo_node_t *topo_infos, uint32_t node_num);

void delete_topo_map(topo_map_t *topo_map);

/**
 * create_topo_map builds the EID mapping from the actual node_num.
 * This function looks up the prebuilt mapping hash table.
 * @return 0 for success, other for error or not found
 */
int get_bonding_eid_by_target_eid(topo_map_t *topo_map, urma_eid_t *target_eid, urma_eid_t *output);

/*
 * Build connection matrix between local bonding context and dst node in topo map.
 * Primary-primary connectivity is derived from port-port connectivity:
 * if any local port can reach any target port, this primary pair is connected.
 */
int bondp_find_linked_port_by_topo(const topo_map_t *topo_map, const urma_eid_t *dst_eid,
                                   bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM]);

#ifdef __cplusplus
}
#endif
#endif // TOPO_INFO_H
