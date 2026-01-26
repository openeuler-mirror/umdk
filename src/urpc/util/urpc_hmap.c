/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc hash map
 */
#include <stdlib.h>
#include "urpc_framework_errno.h"
#include "urpc_dbuf_stat.h"
#include "urpc_hmap.h"

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

int urpc_hmap_init(struct urpc_hmap *hmap, uint32_t count)
{
    hmap->count = 0;
    hmap->mask = calc_mask(count);
    hmap->bucket = (struct urpc_hmap_node *)urpc_dbuf_calloc(URPC_DBUF_TYPE_UTIL,
        count, sizeof(struct urpc_hmap_node));
    if (hmap->bucket == NULL) {
        return -URPC_ERR_ENOMEM;
    }

    return 0;
}

void urpc_hmap_uninit(struct urpc_hmap *hmap)
{
    if (hmap) {
        urpc_dbuf_free((uint8_t *)hmap->bucket);
        hmap->bucket = NULL;
        hmap->count = 0;
        hmap->mask = 0;
    }
}

void urpc_hmap_insert(struct urpc_hmap *hmap, struct urpc_hmap_node *node, uint32_t hash)
{
    struct urpc_hmap_node *head = &hmap->bucket[hash & hmap->mask];

    node->hash = hash;
    node->next = head->next;
    head->next = node;
    hmap->count++;
}

void urpc_hmap_remove(struct urpc_hmap *hmap, const struct urpc_hmap_node *node)
{
    struct urpc_hmap_node *pre = &hmap->bucket[node->hash & hmap->mask];
    struct urpc_hmap_node *tmp = pre->next;

    while (tmp != NULL) {
        struct urpc_hmap_node *next = tmp->next;
        if (tmp == node) {
            pre->next = next;
            hmap->count--;
            return;
        }
        pre = tmp;
        tmp = next;
    }
}