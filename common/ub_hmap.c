/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub hmap table source file
 * Author: Yan Fangfang
 * Create: 2020-09-29
 */

#include "ub_hmap.h"

void ub_hmap_remove(struct ub_hmap *hmap, const struct ub_hmap_node *node)
{
    struct ub_hmap_node *pre_node = (struct ub_hmap_node *)&hmap->bucket[node->hash & hmap->mask];
    struct ub_hmap_node *tmp_node = pre_node->next;

    while (tmp_node != NULL) {
        struct ub_hmap_node *next_node = tmp_node->next;
        if (tmp_node == node) {
            pre_node->next = next_node;
            hmap->count--;
            return;
        }
        pre_node = tmp_node;
        tmp_node = next_node;
    }
}
