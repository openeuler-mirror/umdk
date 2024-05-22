/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub hmap head file
 * Author: Yan Fangfang
 * Create: 2020-9-29
 */

#ifndef UB_HMAP_H
#define UB_HMAP_H

#include "ub_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hmap uses list to resolve hash conflicts in a bucket
 * NOT multi-thread safe in the current version
 */

struct ub_hmap_node {
    struct ub_hmap_node *next;
    uint32_t hash;
};

struct ub_hmap_head {
    struct ub_hmap_node *next;
};

struct ub_hmap {
    uint32_t count;
    uint32_t mask;
    struct ub_hmap_head *bucket;
};

static inline void ub_hmap_insert(struct ub_hmap *hmap, struct ub_hmap_node *node, uint32_t hash)
{
    struct ub_hmap_head *head = &hmap->bucket[hash & hmap->mask];

    node->hash = hash;
    node->next = head->next;
    head->next = node;
    hmap->count++;
}

void ub_hmap_remove(struct ub_hmap *hmap, const struct ub_hmap_node *node);

static inline struct ub_hmap_node *ub_hmap_first_with_hash(const struct ub_hmap *hmap, uint32_t hash)
{
    if (hmap == NULL || hmap->bucket == NULL) {
        return NULL;
    }
    struct ub_hmap_head *head = &hmap->bucket[hash & hmap->mask];
    struct ub_hmap_node *node = head->next;

    while ((node != NULL) && node->hash != hash) {
        node = node->next;
    }
    return node;
}

static inline struct ub_hmap_node *ub_hmap_next_with_hash(const struct ub_hmap_node *pre_node, uint32_t hash)
{
    if (pre_node == NULL) {
        return NULL;
    }
    struct ub_hmap_node *node = pre_node->next;

    while ((node != NULL) && node->hash != hash) {
        node = node->next;
    }
    return node;
}

static inline struct ub_hmap_node *ub_hmap_first_from_idx(const struct ub_hmap *hmap, uint32_t idx)
{
    struct ub_hmap_node *node = NULL;

    if (hmap == NULL || hmap->bucket == NULL) {
        return NULL;
    }

    for (uint32_t i = idx; i < hmap->mask + 1; i++) {
        node = hmap->bucket[i].next;
        if (node != NULL) {
            break;
        }
    }
    return node;
}

static inline struct ub_hmap_node *ub_hmap_first(const struct ub_hmap *hmap)
{
    return ub_hmap_first_from_idx(hmap, 0);
}

static inline struct ub_hmap_node *ub_hmap_next(const struct ub_hmap *hmap, const struct ub_hmap_node *pre_node)
{
    if (hmap == NULL || hmap->bucket == NULL || pre_node == NULL) {
        return NULL;
    }
    struct ub_hmap_node *node = pre_node->next;

    if (node != NULL) {
        return node;
    }

    return ub_hmap_first_from_idx(hmap, (pre_node->hash & hmap->mask) + 1);
}

static inline uint32_t ub_hmap_count(const struct ub_hmap *hmap)
{
    return hmap->count;
}

#define HMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, TABLE)                       \
    for (INIT_CONTAINER_PTR(NODE, ub_hmap_first_with_hash(TABLE, HASH), MEMBER); \
        ((NODE != OBJ_CONTAINING(NULL, NODE, MEMBER)) || (NODE = NULL));           \
        ASSIGN_CONTAINER_PTR(NODE, ub_hmap_next_with_hash(&(NODE)->MEMBER, HASH), MEMBER))

#define HMAP_FOR_EACH(NODE, MEMBER, TABLE) for (INIT_CONTAINER_PTR(NODE, ub_hmap_first(TABLE), MEMBER);       \
        ((NODE != OBJ_CONTAINING(NULL, NODE, MEMBER)) || (NODE = NULL)); \
        ASSIGN_CONTAINER_PTR(NODE, ub_hmap_next(TABLE, &(NODE)->MEMBER), MEMBER))

#define HMAP_FOR_EACH_SAFE(NODE, NEXT, MEMBER, HMAP)                           \
    for (INIT_CONTAINER_PTR(NODE, ub_hmap_first(HMAP), MEMBER);                \
        (((NODE != OBJ_CONTAINING(NULL, NODE, MEMBER)) || (NODE = NULL)) ?       \
        INIT_CONTAINER_PTR(NEXT, ub_hmap_next(HMAP, &(NODE)->MEMBER), MEMBER), 1 : 0); \
        (NODE) = (NEXT))

/*
* Find target in table.
* key_len is length of byte.
*/
#define HMAP_FIND_INNER(hmap, key_ptr, key_len, target)                                  \
    do {                                                                                 \
        typeof(target) cur = NULL;                                                       \
        (target) = NULL;                                                                 \
        uint32_t hash = ub_hash_bytes((key_ptr), (key_len), 0);                          \
        HMAP_FOR_EACH_WITH_HASH(cur, node, hash, (hmap)) {                               \
            if (memcmp(&(cur)->key, (key_ptr), (key_len)) == 0) {                        \
                (target) = cur;                                                          \
                break;                                                                   \
            }                                                                            \
        }                                                                                \
    } while (0)

#define HMAP_FIND(table, key_ptr, key_len, target)  HMAP_FIND_INNER(&(table)->hmap, key_ptr, key_len, target)

#define HMAP_DESTROY_INNER(hmap, entry_type)                                             \
    do {                                                                                 \
        typeof(entry_type) *cur = NULL;                                                  \
        typeof(entry_type) *next = NULL;                                                 \
        HMAP_FOR_EACH_SAFE(cur, next, node, (hmap)) {                                    \
            ub_hmap_remove((hmap), &cur->node);                                          \
            free(cur);                                                                   \
        }                                                                                \
        ub_hmap_destroy((hmap));                                                         \
    } while (0)

#define HMAP_DESTROY(table, entry_type) HMAP_DESTROY_INNER(&(table)->hmap, entry_type)

/*
* Insert entry in table.
* key_len is length of byte
*/
#define HMAP_INSERT_INEER(hmap, entry, key_ptr, key_len)                                   \
    do {                                                                                   \
        uint32_t hash = ub_hash_bytes((key_ptr), (key_len), 0);                            \
        ub_hmap_insert((hmap), &(entry)->node, hash);                                      \
    } while (0)

#define HMAP_INSERT(table, entry, key_ptr, key_len) HMAP_INSERT_INEER(&(table)->hmap, entry, key_ptr, key_len)

static inline uint32_t calc_mask(uint32_t capacity)
{
    uint32_t mask = 0;
    uint32_t i = 0;

    while (mask < capacity) {
        mask |= 1U << i;
        i++;
    }

    return mask >> 1;
}

/*
 * When inserting more nodes than count, the lookup performance will be reduced.
 */
static inline int ub_hmap_init(struct ub_hmap *map, uint32_t count)
{
    map->count = 0;
    map->mask = calc_mask(count);
    map->bucket = (struct ub_hmap_head *)calloc(1, sizeof(struct ub_hmap_head) * (map->mask + 1));
    if (map->bucket != NULL) {
        return 0;
    }
    errno = ENOMEM;
    return -1;
}

static inline void ub_hmap_destroy(struct ub_hmap *hmap)
{
    free(hmap->bucket);
    hmap->bucket = NULL;
}

#ifdef __cplusplus
}
#endif

#endif
