/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond dev hash table header
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05   Create File
 */

#ifndef BONDP_HASH_TABLE_H
#define BONDP_HASH_TABLE_H

#include <pthread.h>
#include "ub_hmap.h"
#include "ub_hash.h"
#include "urma_types.h"
#include "urma_ubagg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BONDP_HASH_MAP_COLLIDE_ERROR (-2)
#define BONDP_HASH_MAP_ALLOC_ERROR (-3)
#define BONDP_HASH_MAP_NOT_FOUND_ERROR (-4)
#define BONDP_HASH_MAP_INVALID_PARAM_ERROR (-22)

typedef struct ub_hmap_node hmap_node_t;

/* hmap api with lock */
static inline void bondp_hmap_insert(struct ub_hmap *hmap, hmap_node_t *node,
    uint32_t hash, pthread_rwlock_t *lock)
{
    (void)pthread_rwlock_wrlock(lock);
    ub_hmap_insert(hmap, node, hash);
    (void)pthread_rwlock_unlock(lock);
}

static inline void bondp_hmap_remove(struct ub_hmap *hmap, const hmap_node_t *node,
    pthread_rwlock_t *lock)
{
    (void)pthread_rwlock_wrlock(lock);
    ub_hmap_remove(hmap, node);
    (void)pthread_rwlock_unlock(lock);
}

static inline hmap_node_t *bondp_hmap_first_with_hash(const struct ub_hmap *hmap, uint32_t hash,
    pthread_rwlock_t *lock)
{
    (void)pthread_rwlock_rdlock(lock);
    hmap_node_t *node = ub_hmap_first_with_hash(hmap, hash);
    (void)pthread_rwlock_unlock(lock);
    return node;
}

typedef bool (*comp_func_t)(hmap_node_t *node, void *key);
typedef void (*free_func_t)(hmap_node_t *node);
typedef uint32_t (*hash_func_t)(void *key);

typedef struct bondp_hash_table {
    pthread_rwlock_t lock;
    struct ub_hmap hmap;
    comp_func_t comp_f;
    free_func_t free_f;
    hash_func_t hash_f;
} bondp_hash_table_t;

int bondp_hash_table_create(bondp_hash_table_t *tbl, uint32_t size,
    comp_func_t comp_f, free_func_t free_f, hash_func_t hash_f);

static inline void bondp_hash_table_add_with_hash(bondp_hash_table_t *tbl, hmap_node_t *node, uint32_t hash)
{
    bondp_hmap_insert(&tbl->hmap, node, hash, &tbl->lock);
}

static inline void bondp_hash_table_add_with_hash_without_lock(bondp_hash_table_t *tbl, hmap_node_t *node,
    uint32_t hash)
{
    ub_hmap_insert(&tbl->hmap, node, hash);
}

static inline void bondp_hash_table_remove(bondp_hash_table_t *tbl, hmap_node_t *node)
{
    bondp_hmap_remove(&tbl->hmap, node, &tbl->lock);
}

static inline void bondp_hash_table_remove_without_lock(bondp_hash_table_t *tbl, hmap_node_t *node)
{
    ub_hmap_remove(&tbl->hmap, node);
}

void bondp_hash_table_destroy(bondp_hash_table_t *tbl);

hmap_node_t *bondp_hash_table_lookup(bondp_hash_table_t *tbl, void *key, uint32_t hash);

hmap_node_t *bondp_hash_table_lookup_without_lock(bondp_hash_table_t *tbl, void *key, uint32_t hash);

#ifdef __cplusplus
}
#endif

#endif // BONDP_HASH_TABLE_H
