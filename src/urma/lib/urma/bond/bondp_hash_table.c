/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * Description: Bond provider hash table implementation
 */
#include "urma_log.h"
#include "bondp_hash_table.h"

int bondp_hash_table_create(bondp_hash_table_t *tbl, uint32_t size,
    comp_func_t comp_f, free_func_t free_f, hash_func_t hash_f)
{
    (void)pthread_rwlock_init(&tbl->lock, NULL);
    if (ub_hmap_init(&tbl->hmap, size) != 0) {
        URMA_LOG_ERR("Failed to init hash map, size=%u, errno=%d\n", size, errno);
        (void)pthread_rwlock_destroy(&tbl->lock);
        return -1;
    }
    tbl->free_f = free_f;
    tbl->comp_f = comp_f;
    tbl->hash_f = hash_f;
    atomic_init(&tbl->gen, 0);
    return 0;
}

void bondp_hash_table_destroy(bondp_hash_table_t *tbl)
{
    struct ub_hmap_node *node, *next;

    (void)pthread_rwlock_wrlock(&tbl->lock);
    node = ub_hmap_first(&tbl->hmap);
    while (node != NULL) {
        next = ub_hmap_next(&tbl->hmap, node);
        ub_hmap_remove(&tbl->hmap, node);
        if (tbl->free_f != NULL) {
            tbl->free_f(node);
        }
        node = next;
    }
    ub_hmap_destroy(&tbl->hmap);
    (void)pthread_rwlock_unlock(&tbl->lock);
    (void)pthread_rwlock_destroy(&tbl->lock);
    /* Invalidate all thread-local caches that may still reference this table */
    bondp_hash_table_inc_gen(tbl);
}

struct ub_hmap_node *bondp_hash_table_lookup(bondp_hash_table_t *tbl, void *key, uint32_t hash)
{
    struct ub_hmap_node *node = NULL, *found = NULL;

    (void)pthread_rwlock_rdlock(&tbl->lock);
    node = ub_hmap_first_with_hash(&tbl->hmap, hash);
    if (node != NULL && tbl->comp_f == NULL) {
        /*
        * if compare function is not set, return
        * first node found when hash collision happen
        */
        (void)pthread_rwlock_unlock(&tbl->lock);
        return node;
    }
    while (node != NULL) {
        if (tbl->comp_f(node, key)) {
            found = node;
            break;
        }
        node = ub_hmap_next_with_hash(node, hash);
    }
    (void)pthread_rwlock_unlock(&tbl->lock);
    return found;
}

struct ub_hmap_node *bondp_hash_table_lookup_without_lock(bondp_hash_table_t *tbl, void *key, uint32_t hash)
{
    struct ub_hmap_node *node = NULL, *found = NULL;
    node = ub_hmap_first_with_hash(&tbl->hmap, hash);
    if (node != NULL && tbl->comp_f == NULL) {
        /*
        * if compare function is not set, return
        * first node found when hash collision happen
        */
        return node;
    }
    while (node != NULL) {
        if (tbl->comp_f(node, key)) {
            found = node;
            break;
        }
        node = ub_hmap_next_with_hash(node, hash);
    }
    return found;
}
