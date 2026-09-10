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

#ifdef __cplusplus
extern "C" {
#endif

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
    urma_jetty_id_t pjetty_id;
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

int bdp_p_vjetty_id_table_add_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t pjetty_id, bdp_p_vjetty_type_t type,
                                           uint32_t vjetty_id, struct bondp_comp *comp);

int bdp_p_vjetty_id_table_del_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t pjetty_id,
                                           bdp_p_vjetty_type_t type);
;
/**
 * Return the bondp_comp corresponding to pjetty_id
 * Only perform table lookup operations, do not manage reference counts, external locking is required for use.
 * @return: The pointer of `comp` field in the lookup result. NULL means error or not found.
 */
struct bondp_comp *bdp_p_vjetty_id_table_lookup_comp_without_lock(bondp_hash_table_t *tbl, urma_jetty_id_t pjetty_id,
                                                                  bdp_p_vjetty_type_t type);

#ifdef __cplusplus
}
#endif

#endif // BONDP_CONTEXT_TABLE
