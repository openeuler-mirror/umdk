/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc hash map
 */
#ifndef URPC_HMAP_H
#define URPC_HMAP_H

#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct urpc_hmap {
    uint32_t count;
    uint32_t mask;
    struct urpc_hmap_node *bucket;
};

struct urpc_hmap_node {
    struct urpc_hmap_node *next;
    uint32_t hash;
};

int urpc_hmap_init(struct urpc_hmap *hmap, uint32_t count);

void urpc_hmap_uninit(struct urpc_hmap *hmap);

void urpc_hmap_insert(struct urpc_hmap *hmap, struct urpc_hmap_node *node, uint32_t hash);

void urpc_hmap_remove(struct urpc_hmap *hmap, const struct urpc_hmap_node *node);

static inline uint32_t urpc_hmap_count(const struct urpc_hmap *hmap)
{
    return hmap->count;
}

static inline struct urpc_hmap_node *urpc_hmap_first_with_hash(const struct urpc_hmap *hmap, uint32_t hash)
{
    if (hmap == NULL || hmap->bucket == NULL) {
        return NULL;
    }
    struct urpc_hmap_node *head = &hmap->bucket[hash & hmap->mask];
    struct urpc_hmap_node *node = head->next;

    while ((node != NULL) && node->hash != hash) {
        node = node->next;
    }
    return node;
}

static inline struct urpc_hmap_node *urpc_hmap_next_with_hash(const struct urpc_hmap_node *pre_node, uint32_t hash)
{
    if (pre_node == NULL) {
        return NULL;
    }
    struct urpc_hmap_node *node = pre_node->next;

    while ((node != NULL) && node->hash != hash) {
        node = node->next;
    }
    return node;
}

static inline struct urpc_hmap_node *urpc_hmap_first_from_idx(const struct urpc_hmap *hmap, uint32_t idx)
{
    struct urpc_hmap_node *node = NULL;

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

static inline struct urpc_hmap_node *urpc_hmap_first(const struct urpc_hmap *hmap)
{
    return urpc_hmap_first_from_idx(hmap, 0);
}

static inline struct urpc_hmap_node *urpc_hmap_next(const struct urpc_hmap *hmap, const struct urpc_hmap_node *pre_node)
{
    if (hmap == NULL || hmap->bucket == NULL || pre_node == NULL) {
        return NULL;
    }
    struct urpc_hmap_node *node = pre_node->next;

    if (node != NULL) {
        return node;
    }

    return urpc_hmap_first_from_idx(hmap, (pre_node->hash & hmap->mask) + 1);
}

#define URPC_HMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, TABLE)                       \
    for (INIT_CONTAINER_PTR(NODE, urpc_hmap_first_with_hash(TABLE, HASH), MEMBER); \
        (NODE != OBJ_CONTAINING(NULL, NODE, MEMBER)) ? 1 : (NODE = NULL, 0);           \
        ASSIGN_CONTAINER_PTR(NODE, urpc_hmap_next_with_hash(&(NODE)->MEMBER, HASH), MEMBER))

#define URPC_HMAP_FOR_EACH(NODE, MEMBER, TABLE) \
    for (INIT_CONTAINER_PTR(NODE, urpc_hmap_first(TABLE), MEMBER); \
        (NODE != OBJ_CONTAINING(NULL, NODE, MEMBER)) ? 1 : (NODE = NULL, 0); \
        ASSIGN_CONTAINER_PTR(NODE, urpc_hmap_next(TABLE, &(NODE)->MEMBER), MEMBER))

#define URPC_HMAP_FOR_EACH_SAFE(NODE, NEXT, MEMBER, HMAP)                           \
    for (INIT_CONTAINER_PTR(NODE, urpc_hmap_first(HMAP), MEMBER);                \
        ((NODE != OBJ_CONTAINING(NULL, NODE, MEMBER)) ?       \
        (INIT_CONTAINER_PTR(NEXT, urpc_hmap_next(HMAP, &(NODE)->MEMBER), MEMBER), 1) :  \
        ((NODE) = NULL, 0)); \
        (NODE) = (NEXT))

#ifdef __cplusplus
}
#endif

#endif
