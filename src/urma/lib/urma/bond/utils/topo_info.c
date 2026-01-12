/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Helper structure and functions to handle topo info. Implementation.
 * Author: Ma Chuan
 * Create: 2025-06-04
 * Note:
 * History: 2025-06-04
 */
#include <stdlib.h>
#include <string.h>
#include "ub_hash.h"
#include "urma_log.h"
#include "urma_types.h"
#include "topo_info.h"

#define DIRECT_DEV_HASH_BASIS (9819876)

static bool direct_dev_comp(struct ub_hmap_node *node, void *key)
{
    direct_dev_node_t *direct_dev_node = CONTAINER_OF_FIELD(node, direct_dev_node_t, hmap_node);
    return memcmp(&direct_dev_node->agg_eid, key, sizeof(urma_eid_t)) == 0;
}

static void direct_dev_free(struct ub_hmap_node *node)
{
    direct_dev_node_t *direct_dev_node = CONTAINER_OF_FIELD(node, direct_dev_node_t, hmap_node);
    free(direct_dev_node);
}

static uint32_t direct_dev_hash(void *key)
{
    urma_eid_t *eid = (urma_eid_t *)key;
    return ub_hash_bytes(eid, sizeof(urma_eid_t), DIRECT_DEV_HASH_BASIS);
}

int direct_dev_hash_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, direct_dev_comp, direct_dev_free, direct_dev_hash);
}

int direct_dev_hash_table_add(bondp_hash_table_t *tbl, bondp_topo_agg_dev_t *topo_info,
    bondp_topo_link_t *local_map_idx, bondp_topo_link_t *target_map_idx)
{
    urma_eid_t *target_bonding_eid = (urma_eid_t *)topo_info->agg_eid;
    hmap_node_t *node = NULL;
    uint32_t hash = tbl->hash_f(target_bonding_eid);
    node = bondp_hash_table_lookup_without_lock(tbl, target_bonding_eid, hash);
    if (node) {
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    direct_dev_node_t *direct_dev_node = calloc(1, sizeof(direct_dev_node_t));
    if (direct_dev_node == NULL) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    direct_dev_node->agg_eid = *target_bonding_eid;
    direct_dev_node->direct_dev_info.direct_num = 1;
    direct_dev_node->direct_dev_info.local_map_idx[0] = *local_map_idx;
    direct_dev_node->direct_dev_info.target_map_idx[0] = *target_map_idx;
    bondp_hash_table_add_with_hash(tbl, &direct_dev_node->hmap_node, hash);
    return 0;
}

direct_dev_node_t *direct_dev_hash_table_lookup(bondp_hash_table_t *tbl, urma_eid_t *key)
{
    hmap_node_t *node = NULL;
    node = bondp_hash_table_lookup(tbl, key, tbl->hash_f(key));
    if (node == NULL) {
        return NULL;
    }
    return CONTAINER_OF_FIELD(node, direct_dev_node_t, hmap_node);
}

static inline bool is_topo_map_idx_equal(bondp_topo_link_t *map_idx, bondp_topo_link_t* target_map_idx)
{
    return !memcmp(map_idx, target_map_idx, sizeof(bondp_topo_link_t));
}

static int update_each_direct_dev_table_entry(topo_map_t *topo_map, bondp_topo_agg_dev_t *topo_info,
                                              bondp_topo_link_t *local_map_idx, bondp_topo_link_t* target_map_idx)
{
    urma_eid_t *target_bonding_eid = (urma_eid_t *)topo_info->agg_eid;
    direct_dev_node_t *dev_node = NULL;
    int ret = 0;

    /* If this target bonding eid doesn't exist, then add a new node in the hash table */
    dev_node = direct_dev_hash_table_lookup(&topo_map->direct_dev_hash_table, target_bonding_eid);
    if (dev_node == NULL) {
        ret = direct_dev_hash_table_add(&topo_map->direct_dev_hash_table, topo_info, local_map_idx, target_map_idx);
        if (ret) {
            URMA_LOG_ERR("Failed to add direct dev hash table %d\n", ret);
            return -1;
        }
        return 0;
    }

    /* If we already have target dev in hash map. Try to add a new route */
    direct_dev_info_t *dev_info = &dev_node->direct_dev_info;
    bool has_local_map_idx = false;
    /* Check if this route already exists */
    for (uint32_t i = 0; i < dev_info->direct_num; ++i) {
        if (is_topo_map_idx_equal(&dev_info->local_map_idx[i], local_map_idx)) {
            has_local_map_idx = true;
            break;
        }
    }
    if (!has_local_map_idx) {
        if (dev_info->direct_num >= MAX_ALL_PORT_NUM) {
            URMA_LOG_ERR("Try to append dev_info when the array is full\n");
            return -1;
        }
        /* Append this route if it doesn't exist */
        dev_info->local_map_idx[dev_info->direct_num] = *local_map_idx;
        dev_info->target_map_idx[dev_info->direct_num] = *target_map_idx;
        dev_info->direct_num++;
    }
    return 0;
}

int update_direct_dev_table_entry(topo_map_t *topo_map,
    bondp_topo_link_t *local_map_idx, bondp_topo_link_t* target_map_idx)
{
    bondp_topo_agg_dev_t *topo_info = NULL;
    int ret = 0;

    for (uint32_t dev_idx = 0; dev_idx < DEV_NUM; ++dev_idx) {
        topo_info = &topo_map->topo_infos[target_map_idx->peer_node].agg_devs[dev_idx];
        ret = update_each_direct_dev_table_entry(topo_map, topo_info, local_map_idx, target_map_idx);
        if (ret) {
            URMA_LOG_ERR("Failed to add direct dev hash table %d\n", ret);
            return -1;
        }
    }
    return 0;
}

static inline bool is_empty_eid(urma_eid_t *eid)
{
    return eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0;
}

static inline bool is_eid_equal(urma_eid_t *eid1, urma_eid_t *eid2)
{
    return !memcmp(eid1, eid2, sizeof(urma_eid_t));
}

int update_direct_dev_table(topo_map_t *topo_map, uint32_t cur_node_idx)
{
    bondp_topo_node_t *cur_node = &topo_map->topo_infos[cur_node_idx];
    bondp_topo_link_t *peer_map_idx = NULL;
    int ret = 0;

    for (uint32_t plane_idx = 0; plane_idx < IODIE_NUM; ++plane_idx) {
        for (uint32_t port_idx = 0; port_idx < PORT_NUM; ++port_idx) {
            peer_map_idx = (bondp_topo_link_t *)&cur_node->links[plane_idx][port_idx];
            if (peer_map_idx->peer_port > PORT_NUM - 1) {
                continue;
            }
            bondp_topo_link_t local_map_idx = {
                .peer_node = cur_node_idx,
                .peer_iodie = plane_idx,
                .peer_port = port_idx
            };
            ret = update_direct_dev_table_entry(topo_map, &local_map_idx, peer_map_idx);
            if (ret) {
                URMA_LOG_ERR("Failed to update direct dev table entry %d\n", ret);
                return -1;
            }
        }
    }
    return 0;
}

topo_map_t *create_topo_map(bondp_topo_node_t *topo_infos, uint32_t node_num)
{
    if (topo_infos == NULL || node_num == 0 || node_num > MAX_NODE_NUM) {
        URMA_LOG_ERR("Invalid topo info to create topo map\n");
        return NULL;
    }
    topo_map_t *topo_map = calloc(1, sizeof(topo_map_t));
    if (topo_map == NULL) {
        URMA_LOG_ERR("Failed to alloc topo_map\n");
        return NULL;
    }
    (void)memcpy(topo_map->topo_infos, topo_infos, sizeof(bondp_topo_node_t) * node_num);
    topo_map->node_num = node_num;

    uint32_t cur_node_idx = UINT32_MAX;
    for (uint32_t i = 0; i < node_num; ++i) {
        if (topo_map->topo_infos[i].is_current) {
            cur_node_idx = i;
            break;
        }
    }
    if (cur_node_idx == UINT32_MAX) {
        URMA_LOG_ERR("topo info doesn't have cur_node\n");
        free(topo_map);
        return NULL;
    }

    int ret = direct_dev_hash_table_create(&topo_map->direct_dev_hash_table, MAX_NODE_NUM);
    if (ret) {
        URMA_LOG_ERR("Failed to create direct_dev_hash_table\n");
        free(topo_map);
        return NULL;
    }
    update_direct_dev_table(topo_map, cur_node_idx);

    return topo_map;
}

void delete_topo_map(topo_map_t *topo_map)
{
    if (topo_map != NULL) {
        bondp_hash_table_destroy(&topo_map->direct_dev_hash_table);
        free(topo_map);
    }
}

static bool is_target_eid_in_cur_iodie(topo_map_t *topo_map, uint32_t node_idx, uint32_t dev_idx, uint32_t iodie_idx, urma_eid_t *target_eid)
{
    urma_eid_t *primary_eid = NULL;
    urma_eid_t *port_eid = NULL;
    uint32_t port_idx = 0;

    bondp_topo_agg_dev_t *cur_dev = &topo_map->topo_infos[node_idx].agg_devs[dev_idx];
    primary_eid = (urma_eid_t *)cur_dev->ues[iodie_idx].primary_eid;
    if (!is_empty_eid(primary_eid) && is_eid_equal(target_eid, primary_eid)) {
        return true;
    }
    for (port_idx = 0; port_idx < PORT_NUM; ++port_idx) {
        port_eid = (urma_eid_t *)cur_dev->ues[iodie_idx].port_eid[port_idx];
        if (!is_empty_eid(port_eid) && is_eid_equal(target_eid, port_eid)) {
            return true;
        }
    }
    return false;
}

static bool is_target_eid_in_cur_dev(topo_map_t *topo_map, uint32_t node_idx, uint32_t dev_idx, urma_eid_t *target_eid)
{
    bondp_topo_node_t *cur_node = &topo_map->topo_infos[node_idx];
    urma_eid_t *agg_eid = NULL;

    agg_eid = (urma_eid_t *)cur_node->agg_devs[dev_idx].agg_eid;
    if (!is_empty_eid(agg_eid) && is_eid_equal(target_eid, agg_eid)) {
        return true;
    }
    for (uint32_t iodie_idx = 0; iodie_idx < IODIE_NUM; ++iodie_idx) {
        if (is_target_eid_in_cur_iodie(topo_map, node_idx, dev_idx, iodie_idx, target_eid)) {
            return true;
        }
    }
    return false;
}

int get_bonding_eid_by_target_eid(topo_map_t *topo_map, urma_eid_t *target_eid, urma_eid_t *output)
{
    if (topo_map == NULL || target_eid == NULL) {
        URMA_LOG_ERR("Invalid param\n");
        return -1;
    }
    for (uint32_t node_idx = 0; node_idx < topo_map->node_num; ++node_idx) {
        for (uint32_t dev_idx = 0; dev_idx < DEV_NUM; ++dev_idx) {
            urma_eid_t *agg_eid = (urma_eid_t *)topo_map->topo_infos[node_idx].agg_devs[dev_idx].agg_eid;
            if (is_target_eid_in_cur_dev(topo_map, node_idx, dev_idx, target_eid)) {
                *output = *agg_eid;
                return 0;
            }

        }
    }
    return -1;
}

bondp_topo_agg_dev_t *get_topo_dev_info_by_agg_eid(topo_map_t *topo_map, urma_eid_t *agg_eid)
{
    if (topo_map == NULL) {
        URMA_LOG_ERR("invalid param\n");
        return NULL;
    }
    for (uint32_t i = 0; i < MAX_NODE_NUM; ++i) {
        for (uint32_t j = 0; j < DEV_NUM; ++j) {
            if (is_eid_equal((urma_eid_t *)topo_map->topo_infos[i].agg_devs[j].agg_eid, agg_eid)) {
                return &topo_map->topo_infos[i].agg_devs[j];
            }
        }
    }
    return NULL;
}

bool has_direct_route(topo_map_t *topo_map, urma_eid_t *agg_eid)
{
    return direct_dev_hash_table_lookup(&topo_map->direct_dev_hash_table, agg_eid) != NULL;
}

direct_dev_info_t *get_direct_dev_info_by_agg_eid(topo_map_t *topo_map, urma_eid_t *agg_eid)
{
    direct_dev_node_t *node = direct_dev_hash_table_lookup(&topo_map->direct_dev_hash_table, agg_eid);
    if (node == NULL) {
        return NULL;
    }
    return &node->direct_dev_info;
}