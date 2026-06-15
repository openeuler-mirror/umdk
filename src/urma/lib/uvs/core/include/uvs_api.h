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

#include "uvs_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_MAX_ROUTES     (16)
#define EID_LEN            (16)
#define MAX_PORT_NUM       (9)
#define MAX_NODE_NUM       (1024)
#define IODIE_NUM_PER_CHIP (1)
#define PORT_NUM           (9)
#define CHIP_NUM           (2)
#define DEV_NUM            (256)
#define IODIE_NUM          (2)
#define UVS_MAIN_UE_EID_BATCH_EID_MAX 128U

typedef enum uvs_tp_type {
    UVS_RTP,
    UVS_CTP,
    UVS_UTP
} uvs_tp_type_t;

typedef union uvs_route_flag {
    struct {
        uint32_t rtp      : 1;
        uint32_t ctp      : 1;
        uint32_t utp      : 1;
        uint32_t reserved : 29;
    } bs;
    uint32_t value;
} uvs_route_flag_t;

typedef struct uvs_route {
    uvs_eid_t src;
    uvs_eid_t dst;
    uvs_route_flag_t flag;
    uint32_t hops; // Only supports direct routes, currently 0.
    uint32_t chip_id;
} uvs_route_t;

typedef struct uvs_route_list {
    uint32_t len;
    uvs_route_t buf[UVS_MAX_ROUTES];
} uvs_route_list_t;

typedef struct uvs_node_id {
    uint32_t super_node_id;
    uint32_t node_id;
} uvs_node_id_t;

union uvs_port_id {
    struct {
        uint8_t chip_id;
        uint8_t die_id;
        uint8_t port_idx;
        uint8_t reserved;
    };
    uint64_t value;
};

enum uvs_topo_type_t {
    UVS_TOPO_TYPE_FULLMESH_1D,
    UVS_TOPO_TYPE_CLOS
};

typedef struct uvs_path {
    union uvs_port_id src_port;
    union uvs_port_id dst_port;
    uvs_eid_t src_eid;
    uvs_eid_t dst_eid;
} uvs_path_t;

typedef struct uvs_path_set {
    enum uvs_topo_type_t topo_type;
    uvs_node_id_t src_node;
    uvs_node_id_t dst_node;
    uint32_t chip_count;
    uint32_t die_count;
    uint32_t path_count;
    uvs_path_t paths[UVS_MAX_ROUTES];
} uvs_path_set_t;

struct urma_topo_ue {
    uint32_t chip_id;
    uint32_t die_id;
    uint32_t entity_id;
    char primary_eid[EID_LEN];
    char port_eid[PORT_NUM][EID_LEN];
    char cna[PORT_NUM][EID_LEN]; // Only for CTP
};

struct urma_topo_agg_dev {
    char agg_eid[EID_LEN];
    struct urma_topo_ue ues[IODIE_NUM];
};

struct urma_topo_node {
    uint32_t type; // 0:1D-fullmesh, 1: Clos topology with parallel planes
    uint32_t super_node_id;
    uint32_t node_id;
    uint32_t is_current;
    bool links[IODIE_NUM * PORT_NUM][IODIE_NUM * PORT_NUM]; /* links[local_idx][remote_idx] represents
            connectivity between this node's port local_idx and node i's port remote_idx. */
    struct urma_topo_agg_dev agg_devs[DEV_NUM];
};

typedef struct urma_topo_map {
    struct urma_topo_node topo_infos[MAX_NODE_NUM];
    uint32_t node_num;
} urma_topo_map_t;

typedef struct uvs_main_ue_eid_entry {
    uvs_eid_t eid;
    uvs_eid_t main_ue_eid;
} uvs_main_ue_eid_entry_t;

typedef struct uvs_main_ue_eid_batch_entry {
    uvs_eid_t main_ue_eid;
    uint32_t eid_num;
    uvs_eid_t eids[UVS_MAIN_UE_EID_BATCH_EID_MAX];
} uvs_main_ue_eid_batch_entry_t;

/**
 * Create an aggregation device in UVS.
 * @param[in] agg_eid  EID of the aggregation device to be created.
 * @param[in] dev_name  Name of the aggregation device to be created.
 * @return 0 on success, other value on error.
 */
int uvs_create_agg_dev(uvs_eid_t *agg_eid, const char *dev_name);

/**
 * Delete an aggregation device from UVS.
 * @param[in] agg_eid  EID of the aggregation device to be deleted.
 * @return 0 on success, other value on error.
 */
int uvs_delete_agg_dev(uvs_eid_t *agg_eid);

/**
 * Get device name by EID.
 * @param[in] eid  EID of the device.
 * @param[out] buf  Buffer to hold the device name.
 * @param[in] len  Length of the buffer.
 * @return 0 on success, other value on error.
 */
int uvs_get_device_name_by_eid(uvs_eid_t *eid, char *buf, size_t len);

/**
 * UVS set topo info which gets from MXE module.
 * @param[in] topo: topo info of one bonding device
 * @param[in] topo_num: number of nodes
 * Return: 0 on success, other value on error
 */
int uvs_set_topo_info(void *topo_buf, uint32_t node_size, uint32_t node_num);

/**
 * UVS set share topo info which gets from MXE module.
 * @param[in] topo_buf: share topo info of host eid
 * @param[in] node_size: size of one topo node
 * @param[in] node_num: number of nodes
 * Return: 0 on success, other value on error
 */
int uvs_set_share_topo_info(void *topo_buf, uint32_t node_size, uint32_t node_num);

int uvs_insert_main_ue_eid(const uvs_main_ue_eid_entry_t *entry);

int uvs_insert_main_ue_eid_batch(const uvs_main_ue_eid_batch_entry_t *entry);

int uvs_delete_main_ue_eid(const uvs_eid_t *eid);

int uvs_lookup_main_ue_eid(const uvs_eid_t *eid, uvs_eid_t *main_ue_eid);

int uvs_flush_main_ue_eid(void);

/**
 * UVS get topo info.
 * @param[out] topo: topo map, refers to urma_topo_map_t
 * Return: 0 on success, other value on error
 */
int uvs_get_topo_info(void *topo);

/**
 * UVS get path set between two bonding devices.
 * @param[in] src_bondind_eid: eid of the source bonding device.
 * @param[in] dst_bonding_eid: eid of the destination bonding device.
 * @param[in] tp_type: transport path type, refers to enum uvs_tp_type.
 * @param[in] iodie_level: true for iodie-level paths, false for port-level paths.
 * @param[out] uvs_path_set: a buffer containing the returned path set.
 * Return: 0 on success, other value on error
 */
int uvs_get_path_set(const uvs_eid_t *src_bondind_eid,
                     const uvs_eid_t *dst_bonding_eid,
                     enum uvs_tp_type tp_type, bool iodie_level,
                     uvs_path_set_t *uvs_path_set);

#ifdef __cplusplus
}
#endif

#endif
