/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: bondp queue implementation
 * Author: Ma Chuan
 * Create: 2025-03-05
 * Note:
 * History:
 */
#include <stdlib.h>
#include "urma_log.h"
#include "bdp_queue.h"

void bdp_queue_init(bdp_queue_t *q, uint32_t max_node)
{
    STAILQ_INIT(&q->head);  /* Initialize the queue. */
    q->node_num = 0;
    q->max_node = max_node;
}

void bdp_queue_uninit(bdp_queue_t *q)
{
    bdp_queue_node_t *cur = NULL;

    while (STAILQ_EMPTY(&q->head) == false) {
        cur = STAILQ_FIRST(&q->head);
        STAILQ_REMOVE_HEAD(&q->head, nodes);
        free(cur);
    }
}

int bdp_queue_front(bdp_queue_t *q, void **data)
{
    if (data == NULL) {
        URMA_LOG_ERR("data is NULL\n");
        return -1;
    }
    if (STAILQ_EMPTY(&q->head)) {
        return -1;
    }
    *data = STAILQ_FIRST(&q->head)->data;
    return 0;
}

int bdp_queue_push_tail(bdp_queue_t *q, void *data)
{
    if (q->node_num >= q->max_node) {
        URMA_LOG_ERR("Failed to enqueue with invalid node_num: %u, max_node: %u.\n", q->node_num, q->max_node);
        return -1;
    }

    bdp_queue_node_t *node = NULL;

    node = malloc(sizeof(bdp_queue_node_t));
    if (node == NULL) {
        URMA_LOG_ERR("Failed to alloc bdp_queue_node\n");
        return BDP_QUEUE_ALLOC_ERR;
    }
    node->data = data;
    q->node_num++;
    STAILQ_INSERT_TAIL(&q->head, node, nodes);
    return 0;
}

int bdp_queue_pop_head(bdp_queue_t *q, void **data)
{
    if (STAILQ_EMPTY(&q->head)) {
        return -1;
    }
    if (data == NULL) {
        URMA_LOG_ERR("data is NULL\n");
        return -1;
    }

    bdp_queue_node_t *node = NULL;

    node = STAILQ_FIRST(&q->head);
    STAILQ_REMOVE_HEAD(&q->head, nodes);
    *data = node->data;
    q->node_num--;
    free(node);
    return 0;
}

int bdp_queue_pop_tail(bdp_queue_t *q, void **data)
{
    if (STAILQ_EMPTY(&q->head)) {
        return -1;
    }
    if (data == NULL) {
        URMA_LOG_ERR("data is NULL\n");
        return -1;
    }

    bdp_queue_node_t *curr = STAILQ_FIRST(&q->head);

    while (STAILQ_NEXT(curr, nodes)) {
        curr = STAILQ_NEXT(curr, nodes);
    }
    STAILQ_REMOVE(&q->head, curr, bdp_queue_node, nodes);
    *data = curr->data;
    q->node_num--;
    free(curr);
    return 0;
}

bool bdp_queue_is_empty(const bdp_queue_t *q)
{
    return STAILQ_EMPTY(&q->head);
}

void bdp_queue_for_each(bdp_queue_t *q, bdp_queue_visit_func_t func)
{
    bdp_queue_node_t *node;
    STAILQ_FOREACH(node, &q->head, nodes) {
        func(node->data);
    }
}