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

#include "bondp_hash_table.h"

#include "topo_info.h"

#define DIRECT_DEV_HASH_BASIS (9819876)
#define TL_EID_CACHE_SLOTS    (8)

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

static topo_map_t *g_topo_map;

static inline bool is_empty_eid(urma_eid_t *eid)
{
    return eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0;
}

static inline bool is_eid_equal(urma_eid_t *eid1, urma_eid_t *eid2)
{
    return !memcmp(eid1, eid2, sizeof(urma_eid_t));
}

static bool eid_comp_func(struct ub_hmap_node *node, void *key)
{
    eid_mapping_entry_t *entry = CONTAINER_OF_FIELD(node, eid_mapping_entry_t, hmap_node);
    urma_eid_t *target = (urma_eid_t *)key;
    return is_eid_equal(&entry->key_eid, target);
}

static void eid_free_func(struct ub_hmap_node *node)
{
    eid_mapping_entry_t *entry = CONTAINER_OF_FIELD(node, eid_mapping_entry_t, hmap_node);
    free(entry);
}

static uint32_t eid_hash_func(void *key)
{
    urma_eid_t *eid = (urma_eid_t *)key;
    return ub_hash_bytes(eid, sizeof(urma_eid_t), DIRECT_DEV_HASH_BASIS);
}

static int eid_mapping_hash_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, eid_comp_func, eid_free_func, eid_hash_func);
}

static bool get_topo_map_alloc_size(uint32_t node_num, size_t *size)
{
    if (node_num > (SIZE_MAX - sizeof(topo_map_t)) / sizeof(bondp_topo_node_t)) {
        return false;
    }

    *size = sizeof(topo_map_t) + node_num * sizeof(bondp_topo_node_t);
    return true;
}

static bool get_eid_mapping_hash_size(uint32_t node_num, uint32_t *size)
{
    const uint32_t per_node = DEV_NUM * (1 + IODIE_NUM * (1 + PORT_NUM));

    if (node_num > UINT32_MAX / per_node) {
        return false;
    }

    *size = node_num * per_node;
    return true;
}

static int eid_mapping_hash_table_add(bondp_hash_table_t *tbl, urma_eid_t *key, urma_eid_t *bonding_eid)
{
    hmap_node_t *node = NULL;
    uint32_t hash = tbl->hash_f(key);
    node = bondp_hash_table_lookup_without_lock(tbl, key, hash);
    if (node) {
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    eid_mapping_entry_t *entry = calloc(1, sizeof(eid_mapping_entry_t));
    if (entry == NULL) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    entry->key_eid = *key;
    entry->bonding_eid = *bonding_eid;
    bondp_hash_table_add_with_hash(tbl, &entry->hmap_node, hash);
    return 0;
}

static eid_mapping_entry_t *eid_mapping_hash_table_lookup(bondp_hash_table_t *tbl, urma_eid_t *key)
{
    hmap_node_t *node = NULL;
    node = bondp_hash_table_lookup(tbl, key, tbl->hash_f(key));
    if (node == NULL) {
        return NULL;
    }
    return CONTAINER_OF_FIELD(node, eid_mapping_entry_t, hmap_node);
}

static int update_mapping_hash_table(topo_map_t *topo_map)
{
    for (int node_idx = 0; node_idx < topo_map->node_num; ++node_idx) {
        bondp_topo_node_t *cur_node = &topo_map->topo_infos[node_idx];
        for (int dev_idx = 0; dev_idx < DEV_NUM; ++dev_idx) {
            bondp_topo_agg_dev_t *cur_dev = &cur_node->agg_devs[dev_idx];
            if (is_empty_eid((urma_eid_t *)cur_dev->agg_eid)) {
                continue;
            }
            if (eid_mapping_hash_table_add(&topo_map->eid_mapping_hash_table, (urma_eid_t *)cur_dev->agg_eid,
                                           (urma_eid_t *)cur_dev->agg_eid)) {
                URMA_LOG_ERR("Failed to add agg eid to mapping hash table\n");
                return -1;
            }
            for (int iodie_idx = 0; iodie_idx < IODIE_NUM; ++iodie_idx) {
                bondp_topo_ue_t *ue_info = &cur_dev->ues[iodie_idx];
                if (!is_empty_eid((urma_eid_t *)ue_info->primary_eid)) {
                    if (eid_mapping_hash_table_add(&topo_map->eid_mapping_hash_table,
                                                   (urma_eid_t *)ue_info->primary_eid,
                                                   (urma_eid_t *)cur_dev->agg_eid)) {
                        URMA_LOG_ERR("Failed to add primary eid to mapping hash table\n");
                        return -1;
                    }
                }
                for (int port_idx = 0; port_idx < PORT_NUM; ++port_idx) {
                    if (!is_empty_eid((urma_eid_t *)ue_info->port_eid[port_idx])) {
                        if (eid_mapping_hash_table_add(&topo_map->eid_mapping_hash_table,
                                                       (urma_eid_t *)ue_info->port_eid[port_idx],
                                                       (urma_eid_t *)cur_dev->agg_eid)) {
                            URMA_LOG_ERR("Failed to add port eid to mapping hash table\n");
                            return -1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static topo_map_t *create_topo_map(const bondp_topo_node_t *topo_infos, uint32_t node_num)
{
    if (topo_infos == NULL || node_num == 0 || node_num > MAX_NODE_NUM) {
        URMA_LOG_ERR("Invalid topo info to create topo map\n");
        return NULL;
    }
    size_t topo_map_size;
    uint32_t hash_size;
    if (!get_topo_map_alloc_size(node_num, &topo_map_size) ||
        !get_eid_mapping_hash_size(node_num, &hash_size)) {
        URMA_LOG_ERR("Invalid topo info size to create topo map\n");
        return NULL;
    }

    topo_map_t *topo_map = calloc(1, topo_map_size);
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

    int ret = eid_mapping_hash_table_create(&topo_map->eid_mapping_hash_table, hash_size);
    if (ret) {
        URMA_LOG_ERR("Failed to create eid_mapping_hash_table\n");
        free(topo_map);
        return NULL;
    }

    if (update_mapping_hash_table(topo_map) != 0) {
        bondp_hash_table_destroy(&topo_map->eid_mapping_hash_table);
        free(topo_map);
        return NULL;
    }

    return topo_map;
}

static void delete_topo_map(topo_map_t *topo_map)
{
    if (topo_map != NULL) {
        bondp_hash_table_destroy(&topo_map->eid_mapping_hash_table);
        free(topo_map);
    }
}

int bondp_topo_init(const bondp_topo_node_t *topo_infos, uint32_t node_num)
{
    g_topo_map = create_topo_map(topo_infos, node_num);
    return g_topo_map == NULL ? -1 : 0;
}

void bondp_topo_uninit(void)
{
    delete_topo_map(g_topo_map);
    g_topo_map = NULL;
}

bool bondp_topo_is_initialized(void)
{
    return g_topo_map != NULL;
}

uint32_t bondp_topo_get_node_num(void)
{
    return g_topo_map == NULL ? 0 : g_topo_map->node_num;
}

int bondp_topo_query_node_idx(const urma_eid_t *bonding_eid, uint32_t *node_idx)
{
    if (g_topo_map == NULL || bonding_eid == NULL || node_idx == NULL) {
        return -1;
    }

    for (uint32_t i = 0; i < g_topo_map->node_num; ++i) {
        const bondp_topo_node_t *node = &g_topo_map->topo_infos[i];

        for (int d = 0; d < DEV_NUM; ++d) {
            const bondp_topo_agg_dev_t *dev = &node->agg_devs[d];
            if (is_empty_eid((urma_eid_t *)dev->agg_eid)) {
                continue;
            }
            if (memcmp(dev->agg_eid, bonding_eid, EID_LEN) == 0) {
                *node_idx = i;
                return 0;
            }
        }
    }

    return -1;
}

static const bondp_topo_node_t *find_current_topo_node(const topo_map_t *topo_map)
{
    if (topo_map == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < topo_map->node_num; ++i) {
        if (topo_map->topo_infos[i].is_current) {
            return &topo_map->topo_infos[i];
        }
    }
    return NULL;
}

static const bondp_topo_node_t *find_topo_node_by_agg_eid(const topo_map_t *topo_map, const urma_eid_t *eid)
{
    if (topo_map == NULL || eid == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < topo_map->node_num; ++i) {
        const bondp_topo_node_t *node = &topo_map->topo_infos[i];
        for (uint32_t j = 0; j < DEV_NUM; ++j) {
            if (memcmp(node->agg_devs[j].agg_eid, eid, EID_LEN) == 0) {
                return node;
            }
        }
    }
    return NULL;
}

static inline bool topo_connected_index_valid(uint32_t idx)
{
    return idx < TOPO_CONNECTED_MAX_NUM;
}

static void topo_fill_port_links_from_dst(const bondp_topo_node_t *dst_node,
                                          bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM])
{
    for (uint32_t local_idx = 0; local_idx < IODIE_NUM * PORT_NUM; ++local_idx) {
        uint32_t local_indice = IODIE_NUM + local_idx;
        if (!topo_connected_index_valid(local_indice)) {
            continue;
        }
        for (uint32_t remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; ++remote_idx) {
            uint32_t remote_indice = IODIE_NUM + remote_idx;
            if (!topo_connected_index_valid(remote_indice)) {
                continue;
            }
            connected[local_indice][remote_indice] = dst_node->links[local_idx][remote_idx];
        }
    }
}

static bool topo_has_port_link(const bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM],
                               uint32_t local_iodie, uint32_t remote_iodie)
{
    for (uint32_t local_port = 0; local_port < PORT_NUM; ++local_port) {
        uint32_t local_indice = IODIE_NUM + local_iodie * PORT_NUM + local_port;
        if (!topo_connected_index_valid(local_indice)) {
            continue;
        }
        for (uint32_t remote_port = 0; remote_port < PORT_NUM; ++remote_port) {
            uint32_t remote_indice = IODIE_NUM + remote_iodie * PORT_NUM + remote_port;
            if (!topo_connected_index_valid(remote_indice)) {
                continue;
            }
            if (connected[local_indice][remote_indice]) {
                return true;
            }
        }
    }
    return false;
}

static void topo_fill_primary_links(bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM])
{
    for (uint32_t local_iodie = 0; local_iodie < IODIE_NUM; ++local_iodie) {
        for (uint32_t remote_iodie = 0; remote_iodie < IODIE_NUM; ++remote_iodie) {
            if (topo_has_port_link(connected, local_iodie, remote_iodie)) {
                connected[local_iodie][remote_iodie] = true;
            }
        }
    }
}

int bondp_topo_query_linked_port(
    const urma_eid_t *bonding_eid, bool connected[TOPO_CONNECTED_MAX_NUM][TOPO_CONNECTED_MAX_NUM])
{
    if (g_topo_map == NULL || bonding_eid == NULL || connected == NULL) {
        URMA_LOG_ERR("Invalid parameter for linked port query.\n");
        return -1;
    }

    const bondp_topo_node_t *src_node = find_current_topo_node(g_topo_map);
    const bondp_topo_node_t *dst_node = find_topo_node_by_agg_eid(g_topo_map, bonding_eid);
    if (src_node == NULL) {
        URMA_LOG_ERR("Failed to find current topo node.\n");
        return -1;
    }
    if (dst_node == NULL) {
        URMA_LOG_ERR("Failed to find target topo node.\n");
        return -1;
    }

    (void)memset(connected, 0,
                 sizeof(bool) * TOPO_CONNECTED_MAX_NUM * TOPO_CONNECTED_MAX_NUM);
    topo_fill_port_links_from_dst(dst_node, connected);
    topo_fill_primary_links(connected);

    return 0;
}

int bondp_topo_query_bonding_eid(const urma_eid_t *target_eid, urma_eid_t *output)
{
    static __thread const topo_map_t *tl_topo;
    static __thread uint32_t tl_gen;
    static __thread int tl_fill_pos;
    static __thread int tl_evict_pos;
    static __thread struct {
        urma_eid_t target;
        urma_eid_t bonding;
        bool valid;
    } tl_slots[TL_EID_CACHE_SLOTS];

    if (g_topo_map == NULL || target_eid == NULL || output == NULL) {
        return -1;
    }

    uint32_t cur_gen = atomic_load(&g_topo_map->eid_mapping_hash_table.gen);
    if (tl_topo != g_topo_map || tl_gen != cur_gen) {
        for (int i = 0; i < TL_EID_CACHE_SLOTS; ++i) {
            tl_slots[i].valid = false;
        }
        tl_topo = g_topo_map;
        tl_gen = cur_gen;
        tl_fill_pos = 0;
        tl_evict_pos = 0;
    }

    for (int i = 0; i < TL_EID_CACHE_SLOTS; ++i) {
        if (tl_slots[i].valid && memcmp(&tl_slots[i].target, target_eid, sizeof(*target_eid)) == 0) {
            *output = tl_slots[i].bonding;
            return 0;
        }
    }

    eid_mapping_entry_t *entry = eid_mapping_hash_table_lookup(&g_topo_map->eid_mapping_hash_table,
                                                               (urma_eid_t *)target_eid);
    if (entry == NULL) {
        return -1;
    }

    int slot;
    if (tl_fill_pos < TL_EID_CACHE_SLOTS) {
        slot = tl_fill_pos++;
    } else {
        slot = tl_evict_pos;
        tl_evict_pos = (tl_evict_pos + 1) & (TL_EID_CACHE_SLOTS - 1);
    }
    tl_slots[slot].target = *target_eid;
    tl_slots[slot].bonding = entry->bonding_eid;
    tl_slots[slot].valid = true;
    *output = entry->bonding_eid;
    return 0;
}
