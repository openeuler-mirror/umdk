/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: bondp queue header
 * Author: Ma Chuan
 * Create: 2025-03-05
 * Note:
 * History:
 */
#ifndef BONDP_QUEUE_H
#define BONDP_QUEUE_H

#include <sys/queue.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BDP_QUEUE_ALLOC_ERR (-2)

STAILQ_HEAD(bdp_queue_head, bdp_queue_node);

typedef struct bdp_queue_head bdp_queue_head_t;

typedef struct bdp_queue {
    bdp_queue_head_t head;
    uint32_t node_num;
    uint32_t max_node;
} bdp_queue_t;

typedef struct bdp_queue_node {
    void *data;
    STAILQ_ENTRY(bdp_queue_node) nodes;
} bdp_queue_node_t;

typedef void (*bdp_queue_visit_func_t)(void *); // input is bdp_queue_node->data

/* User check q is NULL or not */

void bdp_queue_init(bdp_queue_t *q, uint32_t max_node);
void bdp_queue_uninit(bdp_queue_t *q);

int bdp_queue_front(bdp_queue_t *q, void **data);

int bdp_queue_push_tail(bdp_queue_t *q, void *data);

int bdp_queue_pop_head(bdp_queue_t *q, void **data);

int bdp_queue_pop_tail(bdp_queue_t *q, void **data);

bool bdp_queue_is_empty(const bdp_queue_t *q);

void bdp_queue_for_each(bdp_queue_t *q, bdp_queue_visit_func_t func);

#ifdef __cplusplus
}
#endif

#endif // BONDP_QUEUE_H