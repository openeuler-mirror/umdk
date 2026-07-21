/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Helper structure and functions to handle topo info
 * Author: Ma Chuan
 * Create: 2025-06-04
 * Note:
 * History: 2025-06-04
 */

#ifndef BONDP_TOPO_INFO_H
#define BONDP_TOPO_INFO_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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

/**
 * @brief Query the topology node index of a bonding EID.
 * @param[in] bonding_eid bonding EID used to identify the target node.
 * @param[out] node_idx index of the target node in the topology information array.
 * @return 0 on success, -1 when the topology is not initialized, a parameter is
 * invalid, or the bonding EID is not found.
 */
int bondp_topo_query_node_idx(const urma_eid_t *bonding_eid, uint32_t *node_idx);

/**
 * @brief Query the connection matrix from the local node to a target node.
 * @param[in] bonding_eid bonding EID used to identify the target node.
 * @param[out] connected connection matrix. Indices [0, IODIE_NUM) represent
 * primary EIDs, and the remaining indices represent port EIDs grouped by I/O die.
 * Primary-to-primary connectivity is set when any corresponding port pair is linked.
 * @return 0 on success, -1 when the topology is not initialized, a parameter is
 * invalid, or the local or target node is not found.
 */
int bondp_topo_query_linked_port(const urma_eid_t *bonding_eid,
                                 bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM]);

/**
 * @brief Query the bonding EID associated with a topology EID.
 * @param[in] target_eid aggregate, primary, or port EID to query.
 * @param[out] output bonding EID associated with target_eid.
 * @return 0 on success, -1 when the topology is not initialized, a parameter is
 * invalid, or target_eid is not found.
 */
int bondp_topo_query_bonding_eid(const urma_eid_t *target_eid, urma_eid_t *output);

static inline bool is_empty_eid(const urma_eid_t *eid)
{
    return eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0;
}

static inline bool is_eid_equal(const urma_eid_t *eid1, const urma_eid_t *eid2)
{
    return !memcmp(eid1, eid2, sizeof(urma_eid_t));
}

#ifdef __cplusplus
}
#endif

#endif // BONDP_TOPO_INFO_H
