/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding dev context hash table implementation
 * Author: Ma Chuan
 * Create: 2025-03-11
 * Note:
 * History: 2025-03-11   Create File
 */
#include "ub_hash.h"
#include "urma_log.h"
#include "urma_ubagg.h"
#include "bondp_types.h"
#include "bondp_context_table.h"

/* == bdp_p_vjetty_id_table == */

#define BDP_P_VJETTY_ID_HASH_BASIS (0x983571)

static bool bdp_p_vjetty_id_comp(struct ub_hmap_node *node, void *key)
{
    bdp_p_vjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_p_vjetty_id_t, hmap_node);
    bdp_p_vjetty_id_key_t *key_item = key;
    return memcmp(&item->key.pjetty_id, &key_item->pjetty_id, sizeof(urma_jetty_id_t)) == 0 &&
        item->key.type == key_item->type;
}

static void bdp_p_vjetty_id_free(struct ub_hmap_node *node)
{
    bdp_p_vjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_p_vjetty_id_t, hmap_node);
    free(item);
}

static uint32_t bdp_p_vjetty_id_hash(void *key)
{
    bdp_p_vjetty_id_key_t *item = key;
    return ub_hash_bytes(&item->pjetty_id, sizeof(urma_jetty_id_t), BDP_P_VJETTY_ID_HASH_BASIS) + item->type;
}

int bdp_p_vjetty_id_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, bdp_p_vjetty_id_comp, bdp_p_vjetty_id_free, bdp_p_vjetty_id_hash);
}

int bdp_p_vjetty_id_table_destroy(bondp_hash_table_t *tbl)
{
    bondp_hash_table_destroy(tbl);
    return 0;
}

int bdp_p_vjetty_id_table_add_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t pjetty_id, bdp_p_vjetty_type_t type,
    uint32_t vjetty_id, bondp_comp_t *comp)
{
    bdp_p_vjetty_id_t *tmp = NULL;
    hmap_node_t *node = NULL;
    bdp_p_vjetty_id_key_t key = {
        .pjetty_id = pjetty_id,
        .type = type
    };
    if (comp == NULL) {
        return BONDP_HASH_MAP_INVALID_PARAM_ERROR;
    }
    uint32_t hash = bdp_p_vjetty_id_hash(&key);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node) {
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    tmp = calloc(1, sizeof(bdp_p_vjetty_id_t));
    if (!tmp) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    tmp->key = key;
    tmp->vjetty_id = vjetty_id;
    tmp->comp = comp;
    bondp_hash_table_add_with_hash_without_lock(tbl, &tmp->hmap_node, hash);
    return 0;
}

int bdp_p_vjetty_id_table_del_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t pjetty_id, bdp_p_vjetty_type_t type)
{
    hmap_node_t *node = NULL;
    bdp_p_vjetty_id_key_t key = {
        .pjetty_id = pjetty_id,
        .type = type
    };
    uint32_t hash = bdp_p_vjetty_id_hash(&key);

    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (!node) {
        return BONDP_HASH_MAP_NOT_FOUND_ERROR;
    }
    bondp_hash_table_remove_without_lock(tbl, node);
    bdp_p_vjetty_id_free(node);
    return 0;
}

struct bondp_comp *bdp_p_vjetty_id_table_lookup_comp_without_lock(bondp_hash_table_t *tbl,
    urma_jetty_id_t pjetty_id, bdp_p_vjetty_type_t type)
{
    hmap_node_t *node = NULL;
    bdp_p_vjetty_id_key_t key = {
        .pjetty_id = pjetty_id,
        .type = type
    };
    uint32_t hash = bdp_p_vjetty_id_hash(&key);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node == NULL) {
        return NULL;
    }
    bdp_p_vjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_p_vjetty_id_t, hmap_node);
    return item->comp;
}
