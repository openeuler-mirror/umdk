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

#define CNA_LEN                (3)
#define EID_LEN                (16)
#define PORT_NUM               (9)
#define MAX_ALL_PORT_NUM       (18)
#define MAX_NODE_NUM           (1024)
#define IODIE_NUM_PER_CHIP     (1)
#define CHIP_NUM               (2)
#define IODIE_NUM              (2)
#define DEV_NUM                (256)
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

int bondp_topo_init(const bondp_topo_node_t *topo_infos, uint32_t node_num);
void bondp_topo_uninit(void);
bool bondp_topo_is_initialized(void);

uint32_t bondp_topo_get_node_num(void);

int bondp_topo_query_node_idx(const urma_eid_t *bonding_eid, uint32_t *node_idx);

/*
 * Build connection matrix between local bonding context and target node in topo map.
 * Primary-primary connectivity is derived from port-port connectivity:
 * if any local port can reach any target port, this primary pair is connected.
 */
int bondp_topo_query_linked_port(const urma_eid_t *bonding_eid,
                                 bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM]);

/**
 * bondp_topo_query_bonding_eid looks up the prebuilt EID mapping hash table.
 * @return 0 for success, other for error or not found
 */
int bondp_topo_query_bonding_eid(const urma_eid_t *target_eid, urma_eid_t *output);

#ifdef __cplusplus
}
#endif
#endif // TOPO_INFO_H
