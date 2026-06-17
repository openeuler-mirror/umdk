/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: jetty pool for UMQ UB
 * Create: 2026-06-08
 * Note:
 * History: 2026-06-08
 */

#ifndef UMQ_UB_JETTY_POOL_H
#define UMQ_UB_JETTY_POOL_H

#include <stdbool.h>
#include <pthread.h>
#include "urpc_list.h"
#include "urpc_bitmap.h"
#include "urma_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jetty_pool_node jetty_pool_node_t;

typedef struct umq_ub_jetty_node_list {
    jetty_pool_node_t **node_list;
    uint32_t list_len;
    urpc_bitmap_t bitmap;
    volatile uint32_t ref_cnt;
    pthread_spinlock_t lock;       // serializes bitmap + node_list slot mutation (create/destroy)
} umq_ub_jetty_node_list_t;

// Jetty pool configuration
typedef struct jetty_pool_config {
    uint32_t notify_threshold;     // Notify via eventfd when idle_count >= threshold (0 means use default 16)
    uint32_t borrow_limit;         // Max WRs per borrow (0 means use default 1024)
} jetty_pool_config_t;

// Thread-local jetty cache (linked list based on user config)
typedef struct thread_local_jetty_cache {
    urpc_list_t cache_list;     // Linked list of cached jetty nodes
    urpc_list_t registry_node;  // Node for global thread cache registry
    uint32_t cached_count;       // Current cached jetty count
    bool inited;                 // Whether this thread cache is initialized
} thread_local_jetty_cache_t;

int umq_ub_jetty_pool_init(jetty_pool_config_t *config);
void umq_ub_jetty_pool_uninit(void);
jetty_pool_node_t *umq_ub_jetty_pool_get_free_node(void);
void umq_ub_jetty_pool_put_free_node(jetty_pool_node_t *node);
int umq_ub_jetty_node_add(jetty_pool_node_t *node);
int umq_ub_jetty_node_remove(jetty_pool_node_t *node);
jetty_pool_node_t *umq_ub_jetty_node_alloc(void);
int umq_ub_jetty_node_free(jetty_pool_node_t *node);
int umq_ub_jetty_pool_get_eventfd(void);
umq_ub_jetty_node_list_t *umq_ub_jetty_pool_get_jetty_node_list(void);
uint32_t umq_ub_jetty_pool_put_jetty_node_list(umq_ub_jetty_node_list_t *jetty_node_list);

#ifdef __cplusplus
}
#endif

#endif