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

/* == bdp_tjetty_id_table == */

#define BDP_TJETTY_ID_HASH_BASIS (0x87237482)

static bool bdp_tjetty_id_comp(struct ub_hmap_node *node, void *key)
{
    bdp_tjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_tjetty_id_t, hmap_node);
    return item->slave_id->id == ((urma_jetty_id_t *)key)->id;
}

static void bdp_tjetty_id_free(struct ub_hmap_node *node)
{
    bdp_tjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_tjetty_id_t, hmap_node);
    free(item);
}

static uint32_t bdp_tjetty_id_hash(void *key)
{
    return ((urma_jetty_id_t *)key)->id;
}

int bdp_tjetty_id_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, bdp_tjetty_id_comp, bdp_tjetty_id_free, bdp_tjetty_id_hash);
}

int bdp_tjetty_id_table_destroy(bondp_hash_table_t *tbl)
{
    bondp_hash_table_destroy(tbl);
    return 0;
}

int bdp_tjetty_id_table_add(bondp_hash_table_t *tbl, urma_jetty_id_t *slave_id, urma_jetty_id_t *base_id)
{
    bdp_tjetty_id_t *tmp = NULL;
    hmap_node_t *node = NULL;
    uint32_t hash = bdp_tjetty_id_hash(slave_id);

    node = bondp_hash_table_lookup(tbl, slave_id, hash);
    if (node) {
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    tmp = calloc(1, sizeof(bdp_tjetty_id_t));
    if (!tmp) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    tmp->slave_id = slave_id;
    tmp->base_id = base_id;
    bondp_hash_table_add_with_hash(tbl, &tmp->hmap_node, hash);
    return 0;
}

int bdp_tjetty_id_table_del(bondp_hash_table_t *tbl, urma_jetty_id_t *slave_id)
{
    hmap_node_t *node = NULL;
    uint32_t hash = bdp_tjetty_id_hash(slave_id);

    node = bondp_hash_table_lookup(tbl, slave_id, hash);
    if (!node) {
        return BONDP_HASH_MAP_NOT_FOUND_ERROR;
    }
    bondp_hash_table_remove(tbl, node);
    bdp_tjetty_id_free(node);
    return 0;
}

urma_jetty_id_t *bdp_tjetty_id_table_lookup(bondp_hash_table_t *tbl, urma_jetty_id_t *key)
{
    hmap_node_t *node = NULL;
    node = bondp_hash_table_lookup(tbl, key, bdp_tjetty_id_hash(key));
    if (node == NULL) {
        return NULL;
    }
    return CONTAINER_OF_FIELD(node, bdp_tjetty_id_t, hmap_node)->base_id;
}

/* == bdp_seg_info_table == */

#define BDP_SEG_INFO_HASH_BASIS (0x52989218)

static bool seg_info_comp(struct ub_hmap_node *node, void *key)
{
    bdp_seg_info_t *seg_info = CONTAINER_OF_FIELD(node, bdp_seg_info_t, hmap_node);
    return memcmp(&seg_info->base.ubva, key, sizeof(urma_ubva_t)) == 0;
}

static void seg_info_free(struct ub_hmap_node *node)
{
    bdp_seg_info_t *seg_info = CONTAINER_OF_FIELD(node, bdp_seg_info_t, hmap_node);
    free(seg_info);
}

static uint32_t seg_info_hash(void *key)
{
    return ub_hash_bytes(key, sizeof(urma_ubva_t), BDP_SEG_INFO_HASH_BASIS);
}

int bdp_seg_info_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, seg_info_comp, seg_info_free, seg_info_hash);
}

int bdp_seg_info_table_destroy(bondp_hash_table_t *tbl)
{
    bondp_hash_table_destroy(tbl);
    return 0;
}

/* == bdp_p_vjetty_id_table == */

#define BDP_P_VJETTY_ID_HASH_BASIS (0x983571)

static bool bdp_p_vjetty_id_comp(struct ub_hmap_node *node, void *key)
{
    bdp_p_vjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_p_vjetty_id_t, hmap_node);
    bdp_p_vjetty_id_key_t *tmp = key;
    return item->key.pjetty_id == tmp->pjetty_id && item->key.type == tmp->type;
}

static void bdp_p_vjetty_id_free(struct ub_hmap_node *node)
{
    bdp_p_vjetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_p_vjetty_id_t, hmap_node);
    free(item);
}

static uint32_t bdp_p_vjetty_id_hash(void *key)
{
    return ub_hash_bytes(key, sizeof(bdp_p_vjetty_id_key_t), BDP_P_VJETTY_ID_HASH_BASIS);
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

int bdp_p_vjetty_id_table_add(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type,
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
    (void)pthread_rwlock_wrlock(&tbl->lock);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    tmp = calloc(1, sizeof(bdp_p_vjetty_id_t));
    if (!tmp) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    tmp->key = key;
    tmp->vjetty_id = vjetty_id;
    tmp->comp = comp;
    bondp_hash_table_add_with_hash_without_lock(tbl, &tmp->hmap_node, hash);
    (void)pthread_rwlock_unlock(&tbl->lock);
    return 0;
}

int bdp_p_vjetty_id_table_del(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type)
{
    hmap_node_t *node = NULL;
    bdp_p_vjetty_id_key_t key = {
        .pjetty_id = pjetty_id,
        .type = type
    };
    uint32_t hash = bdp_p_vjetty_id_hash(&key);

    (void)pthread_rwlock_wrlock(&tbl->lock);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (!node) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return BONDP_HASH_MAP_NOT_FOUND_ERROR;
    }
    bondp_hash_table_remove_without_lock(tbl, node);
    bdp_p_vjetty_id_free(node);
    (void)pthread_rwlock_unlock(&tbl->lock);
    return 0;
}

int bdp_p_vjetty_id_table_add_without_lock(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type,
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

int bdp_p_vjetty_id_table_del_without_lock(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type)
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

int bdp_p_vjetty_id_table_lookup(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type,
    uint32_t *vjetty_id)
{
    hmap_node_t *node = NULL;
    bdp_p_vjetty_id_key_t key = {
        .pjetty_id = pjetty_id,
        .type = type
    };
    uint32_t hash = bdp_p_vjetty_id_hash(&key);
    (void)pthread_rwlock_rdlock(&tbl->lock);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node == NULL) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return -1;
    }
    *vjetty_id = CONTAINER_OF_FIELD(node, bdp_p_vjetty_id_t, hmap_node)->vjetty_id;
    (void)pthread_rwlock_unlock(&tbl->lock);
    return 0;
}

struct bondp_comp *bdp_p_vjetty_id_table_lookup_comp_without_lock(bondp_hash_table_t *tbl,
    uint32_t pjetty_id, bdp_p_vjetty_type_t type)
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

/* == bdp_r_p2v_jetty_id_table == */
#define BDP_R_P2V_JETTY_ID_HASH_BASIS (0x614914)

static bool bdp_r_p2v_jetty_id_comp(struct ub_hmap_node *node, void *key)
{
    bdp_r_p2v_jetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_r_p2v_jetty_id_t, hmap_node);
    bdp_r_p2v_jetty_id_key_t *key_item = key;
    /* This comparison must be made; */
    /* otherwise, issues may arise due to inexplicable reasons, possibly related to alignment problems. */
    return memcmp(&item->key.rpjetty_id, &key_item->rpjetty_id, sizeof(urma_jetty_id_t)) == 0 &&
        item->key.type == key_item->type;
}

static void bdp_r_p2v_jetty_id_free(struct ub_hmap_node *node)
{
    bdp_r_p2v_jetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_r_p2v_jetty_id_t, hmap_node);
    free(item);
}

static uint32_t bdp_r_p2v_jetty_id_hash(void *key)
{
    bdp_r_p2v_jetty_id_key_t *item = key;
    return ub_hash_bytes(&item->rpjetty_id, sizeof(urma_jetty_id_t), BDP_R_P2V_JETTY_ID_HASH_BASIS) + item->type;
}

int bdp_r_p2v_jetty_id_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size,
        bdp_r_p2v_jetty_id_comp, bdp_r_p2v_jetty_id_free, bdp_r_p2v_jetty_id_hash);
}

int bdp_r_p2v_jetty_id_table_destroy(bondp_hash_table_t *tbl)
{
    bondp_hash_table_destroy(tbl);
    return 0;
}

int bdp_r_p2v_jetty_id_table_add_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t *rpjetty_id,
    bdp_r_p2v_jetty_id_type_t type, urma_jetty_id_t *rvjetty_id)
{
    bdp_r_p2v_jetty_id_key_t key = {
        .rpjetty_id = *rpjetty_id,
        .type = type
    };
    uint32_t hash = bdp_r_p2v_jetty_id_hash(&key);
    hmap_node_t *node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node) {
        bdp_r_p2v_jetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_r_p2v_jetty_id_t, hmap_node);
        item->ref_cnt += 1;
        URMA_LOG_DEBUG("The existing mapping relationship is added. The reference counting is added.");
        return 0;
    }
    bdp_r_p2v_jetty_id_t *new_node = calloc(1, sizeof(bdp_r_p2v_jetty_id_t));
    if (!new_node) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    new_node->key = key;
    new_node->rvjetty_id = *rvjetty_id;
    new_node->ref_cnt = 1;
    bondp_hash_table_add_with_hash_without_lock(tbl, &new_node->hmap_node, hash);
    return 0;
}

int bdp_r_p2v_jetty_id_table_del_without_lock(bondp_hash_table_t *tbl,
    urma_jetty_id_t *rpjetty_id, bdp_r_p2v_jetty_id_type_t type)
{
    hmap_node_t *node = NULL;
    bdp_r_p2v_jetty_id_key_t key = {
        .rpjetty_id = *rpjetty_id,
        .type = type
    };
    uint32_t hash = bdp_r_p2v_jetty_id_hash(&key);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (!node) {
        return BONDP_HASH_MAP_NOT_FOUND_ERROR;
    }
    bdp_r_p2v_jetty_id_t *item = CONTAINER_OF_FIELD(node, bdp_r_p2v_jetty_id_t, hmap_node);
    if (item->ref_cnt > 1) {
        item->ref_cnt -= 1;
        URMA_LOG_DEBUG("There are other references present. Reference count - 1.");
        return 0;
    }
    bondp_hash_table_remove_without_lock(tbl, node);
    bdp_r_p2v_jetty_id_free(node);
    return 0;
}

int bdp_r_p2v_jetty_id_table_lookup(bondp_hash_table_t *tbl, urma_jetty_id_t *rpjetty_id,
    bdp_r_p2v_jetty_id_type_t type, urma_jetty_id_t *rvjetty_id)
{
    hmap_node_t *node = NULL;
    bdp_r_p2v_jetty_id_key_t key = {
        .rpjetty_id = *rpjetty_id,
        .type = type
    };
    uint32_t hash = bdp_r_p2v_jetty_id_hash(&key);
    (void)pthread_rwlock_rdlock(&tbl->lock);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node == NULL) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return BONDP_HASH_MAP_NOT_FOUND_ERROR;
    }
    *rvjetty_id = CONTAINER_OF_FIELD(node, bdp_r_p2v_jetty_id_t, hmap_node)->rvjetty_id;
    (void)pthread_rwlock_unlock(&tbl->lock);
    return 0;
}

/* == bdp_r_v2p_token_id_table == */
 
static bool bdp_r_v2p_token_id_comp(struct ub_hmap_node *node, void *key)
{
    bondp_v2p_token_id_t *item = CONTAINER_OF_FIELD(node, bondp_v2p_token_id_t, hmap_node);
    bondp_v2p_token_id_key_t *key_item = key;
 
    return (item->key.v_token_id == key_item->v_token_id) &&
        (memcmp(&item->key.v_remote_eid, &key_item->v_remote_eid, sizeof(urma_eid_t)) == 0);
}
 
static void bdp_r_v2p_token_id_free(struct ub_hmap_node *node)
{
    bondp_v2p_token_id_t *item = CONTAINER_OF_FIELD(node, bondp_v2p_token_id_t, hmap_node);
    free(item);
}
 
static uint32_t bdp_r_v2p_token_id_hash(void *key)
{
    return ((bondp_v2p_token_id_key_t *)key)->v_token_id;
}
 
int bdp_r_v2p_token_id_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size,
        bdp_r_v2p_token_id_comp, bdp_r_v2p_token_id_free, bdp_r_v2p_token_id_hash);
}
 
int bdp_r_v2p_token_id_table_destroy(bondp_hash_table_t *tbl)
{
    bondp_hash_table_destroy(tbl);
    return 0;
}
 
int bdp_r_v2p_token_id_tabl_lookup(bondp_hash_table_t *tbl, uint32_t v_token_id,
    urma_eid_t *v_remote_eid, bondp_v2p_token_id_t *item)
{
    hmap_node_t *node = NULL;
    bondp_v2p_token_id_key_t key = {
        .v_token_id = v_token_id,
        .v_remote_eid = *v_remote_eid
    };
    uint32_t hash = v_token_id;
    (void)pthread_rwlock_rdlock(&tbl->lock);
    node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node == NULL) {
        (void)pthread_rwlock_unlock(&tbl->lock);
        return BONDP_HASH_MAP_NOT_FOUND_ERROR;
    }
    bondp_v2p_token_id_t *tmp = CONTAINER_OF_FIELD(node, bondp_v2p_token_id_t, hmap_node);
    (void)memcpy(item, tmp, sizeof(bondp_v2p_token_id_t));
    (void)pthread_rwlock_unlock(&tbl->lock);
 
    return 0;
}
 
int bdp_r_v2p_token_id_del_idx_lockless(bondp_hash_table_t *tbl, uint32_t index)
{
    bondp_v2p_token_id_t *item = NULL;
    struct ub_hmap_node *node, *next;
 
    node = ub_hmap_first(&tbl->hmap);
    while (node != NULL) {
        item = CONTAINER_OF_FIELD(node, bondp_v2p_token_id_t, hmap_node);
        next = ub_hmap_next(&tbl->hmap, node);
        if (item->index == index) {
            ub_hmap_remove(&tbl->hmap, node);
            if (tbl->free_f != NULL) {
                tbl->free_f(node);
            }
            return 0;
        }
        node = next;
    }
 
    URMA_LOG_ERR("Failed to find node, index: %u.\n", index);
    return -1;
}
 
int bdp_r_v2p_token_id_table_add_lockless(bondp_hash_table_t *tbl, bondp_v2p_token_id_t *item)
{
    bondp_v2p_token_id_key_t key = item->key;
    uint32_t hash = key.v_token_id;
    hmap_node_t *node = bondp_hash_table_lookup_without_lock(tbl, &key, hash);
    if (node != NULL) {
        URMA_LOG_DEBUG("Node already added into hash table, hash: %u, index: %u.\n", hash, item->index);
        return 0;
    }
 
    bondp_v2p_token_id_t *new_item = calloc(1, sizeof(bondp_v2p_token_id_t));
    if (new_item == NULL) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
 
    (void)memcpy(new_item->peer_p_seg, item->peer_p_seg, URMA_UBAGG_DEV_MAX_NUM * sizeof(item->peer_p_seg[0]));
    new_item->v_handle = item->v_handle;
    new_item->key = key;
    new_item->index = item->index;
 
    bondp_hash_table_add_with_hash_without_lock(tbl, &new_item->hmap_node, hash);
 
    return 0;
}