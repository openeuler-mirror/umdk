/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding dev context hash table header
 * Author: Ma Chuan
 * Create: 2025-03-11
 * Note:
 * History: 2025-03-11   Create File
 */
#ifndef BONDP_CONTEXT_TABLE_H
#define BONDP_CONTEXT_TABLE_H

#include "urma_ubagg.h"
#include "bondp_hash_table.h"

/* == bdp_p_vjetty_id_table == */
/**
 * Record the mapping relationship from pjetty_id.jetty_id.id to vjetty_id.jetty_id.id,
 * used to restore the local_id in CR
 */
typedef enum bdp_p_vjetty_type {
    JETTY,
    JFS,
    JFR
} bdp_p_vjetty_type_t;

typedef struct bdp_p_vjetty_id_key {
    uint32_t pjetty_id;
    bdp_p_vjetty_type_t type;
} bdp_p_vjetty_id_key_t;
/**
 * We do not need to add a reference count to this node structure.
 * Since the lifecycle management of the actual comp pointer is not handled by this hash table,
 * it is only used as an index.
 */
typedef struct bdp_p_vjetty_id {
    hmap_node_t hmap_node;
    bdp_p_vjetty_id_key_t key;
    uint32_t vjetty_id;      /* To support lookups without increasing the reference count of `comp`. */
    struct bondp_comp *comp; /* The corresponding bondp_comp_t pointer for vjetty. */
} bdp_p_vjetty_id_t;

int bdp_p_vjetty_id_table_create(bondp_hash_table_t *tbl, uint32_t size);

int bdp_p_vjetty_id_table_destroy(bondp_hash_table_t *tbl);
/**
 * This function does not increase the reference count of the comp.
 * The lifecycle of the comp pointer needs to be confirmed by the caller.
 * As long as the comp pointer is protected from being released when accessed externally,
 * there will be no UAF (Use-After-Free) issues.
 */
int bdp_p_vjetty_id_table_add(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type,
    uint32_t vjetty_id, struct bondp_comp *comp);
/**
 * This function is not recommended for use except in scenarios where the entire hash table is being released.
 * This is because the reference count and lifecycle of the comp pointer within the nodes may require structures beyond
 * the current hash table to manage.
 * This function only guarantees the deletion of one node mapped by a pjetty_id at a time;
 * it does not ensure that the same comp pointer will not be found by other nodes through lookup after deletion.
 * This function does not manage the lifecycle of the comp,
 * so it will not release the comp or access any resources associated with it.
 */
int bdp_p_vjetty_id_table_del(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type);

int bdp_p_vjetty_id_table_add_without_lock(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type,
    uint32_t vjetty_id, struct bondp_comp *comp);

int bdp_p_vjetty_id_table_del_without_lock(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type);
/**
 * After querying the table, only the vjetty_id is returned.
 * This function does not consider the reference count corresponding to comp.
 * It is possible that a jetty is in the process of being released, but the vjetty_id has already been returned.
 * We consider this situation reasonable because when reporting CR, the current vjetty has correctly sent data,
 * so it should be findable.
 * However, after the vjetty is deleted,
 * if a CR related to the current vjetty is obtained again, it will return an error.
 * This is also expected because the related resources no longer exist, so there is no way to recover local_id field.
 * Unless we need to increase the reference count for vjetty for each cached WR.
 * @param vjetty_id: output
 * @return: 0 for success, other for error
 */
int bdp_p_vjetty_id_table_lookup(bondp_hash_table_t *tbl, uint32_t pjetty_id, bdp_p_vjetty_type_t type,
    uint32_t *vjetty_id);
/**
 * Return the bondp_comp corresponding to pjetty_id
 * Only perform table lookup operations, do not manage reference counts, external locking is required for use.
 * @return: The pointer of `comp` field in the lookup result. NULL means error or not found.
 */
struct bondp_comp *bdp_p_vjetty_id_table_lookup_comp_without_lock(bondp_hash_table_t *tbl,
    uint32_t pjetty_id, bdp_p_vjetty_type_t type);

typedef enum bdp_remote_p_to_v_jetty_id_type {
    REMOTE_JETTY,
    REMOTE_JFR
} bdp_r_p2v_jetty_id_type_t;
/**
 * Used to record all the mapping relationships from the remote pjetty_id to vjetty_id obtained by this end.
 */
typedef struct bdp_remote_p_to_v_jetty_id_key {
    urma_jetty_id_t rpjetty_id;
    bdp_r_p2v_jetty_id_type_t type;
} bdp_r_p2v_jetty_id_key_t;

typedef struct bdp_remote_p_to_v_jetty_id {
    hmap_node_t hmap_node;
    bdp_r_p2v_jetty_id_key_t key;
    urma_jetty_id_t rvjetty_id;
    /* Since the same rjetty might be imported multiple times,
       it is possible for an entry to be created and deleted multiple times.
       Therefore, we need to manage the reference count each node.
    */
    /* This implementation will cause us to cache repeated mapping of vjetty_id->pjetty_id for
       each bondp_target_jetty_t additionally zin the aforementioned scenario.
       This may lead to an increase in memory consumption.
        A better approach is to cache the mapping between remote Jetty's vjetty and pjetty in a specific hash map.
    */
    uint32_t ref_cnt;
} bdp_r_p2v_jetty_id_t;

int bdp_r_p2v_jetty_id_table_create(bondp_hash_table_t *tbl, uint32_t size);

int bdp_r_p2v_jetty_id_table_destroy(bondp_hash_table_t *tbl);
/**
 * Try to add a mapping of rpjetty_id to rvjetty_id
 * Add the reference count of the hash map node if it already exists.
 * Add write lock of the hash table before calling this function.
 * @return: Return 0 for success, other for error.
 */
int bdp_r_p2v_jetty_id_table_add_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t *rpjetty_id,
    bdp_r_p2v_jetty_id_type_t type, urma_jetty_id_t *rvjetty_id);
/**
 * Try to delete a mapping of rpjetty_id to rvjetty_id
 * If the reference count has not yet been decremented to zero, decrement the reference count by 1;
 * otherwise, delete the table entry.
 * Add write lock of the hash table before calling this function.
 * @return: Return 0 for success, other for error.
 */
int bdp_r_p2v_jetty_id_table_del_without_lock(bondp_hash_table_t *tbl,
    urma_jetty_id_t *rpjetty_id, bdp_r_p2v_jetty_id_type_t type);

int bdp_r_p2v_jetty_id_table_lookup(bondp_hash_table_t *tbl, urma_jetty_id_t *rpjetty_id,
    bdp_r_p2v_jetty_id_type_t type, urma_jetty_id_t *rvjetty_id);

typedef struct bondp_v2p_token_id_key {
    uint32_t v_token_id;
    urma_eid_t v_remote_eid;
} bondp_v2p_token_id_key_t;
 
typedef struct bondp_v2p_token_id {
    hmap_node_t hmap_node;
    bondp_v2p_token_id_key_t key;
    urma_seg_t peer_p_seg[URMA_UBAGG_DEV_MAX_NUM];
    uint64_t v_handle;
    uint32_t index;
} bondp_v2p_token_id_t;
 
int bdp_r_v2p_token_id_table_create(bondp_hash_table_t *tbl, uint32_t size);
int bdp_r_v2p_token_id_table_destroy(bondp_hash_table_t *tbl);
 
int bdp_r_v2p_token_id_tabl_lookup(bondp_hash_table_t *tbl, uint32_t v_token_id,
    urma_eid_t *v_remote_eid, bondp_v2p_token_id_t *item);
int bdp_r_v2p_token_id_del_idx_lockless(bondp_hash_table_t *tbl, uint32_t index);
int bdp_r_v2p_token_id_table_add_lockless(bondp_hash_table_t *tbl, bondp_v2p_token_id_t *item);

#endif // BONDP_CONTEXT_TABLE