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
#include "util_lock.h"
#include "urma_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jetty_pool_node jetty_pool_node_t;

// Callback fired when jetty pool's available count rises.
typedef void (*umq_ub_jetty_avail_cb_t)(void *user_data);
typedef struct umq_ub_jetty_avail_cb_node {
    urpc_list_t node;
    umq_ub_jetty_avail_cb_t cb;
    void *user_data;
} umq_ub_jetty_avail_cb_node_t;

typedef struct umq_ub_jetty_node_list {
    jetty_pool_node_t **node_list;
    uint32_t list_len;
    urpc_bitmap_t bitmap;
    volatile uint32_t ref_cnt;
    volatile uint32_t next_poll_idx;
    util_external_mutex_lock *lock;       // serializes bitmap + node_list slot mutation (create/destroy)
} umq_ub_jetty_node_list_t;

// Jetty pool configuration
typedef struct jetty_pool_config {
    uint32_t notify_threshold;     // Notify via eventfd when idle_count >= threshold (0 means use default 16)
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
// Register a jetty-availability callback; returns the node (pass to unregister later) or NULL.
umq_ub_jetty_avail_cb_node_t *umq_ub_jetty_pool_register_avail_cb(umq_ub_jetty_avail_cb_t cb, void *user_data);
// Unregister and free a callback node. No-op if NULL.
void umq_ub_jetty_pool_unregister_avail_cb(umq_ub_jetty_avail_cb_node_t *cb_node);
// Query whether at least one jetty is currently available to borrow (active_count > 0).
bool umq_ub_jetty_pool_has_avail(void);
umq_ub_jetty_node_list_t *umq_ub_jetty_pool_get_jetty_node_list(void);
uint32_t umq_ub_jetty_pool_put_jetty_node_list(umq_ub_jetty_node_list_t *jetty_node_list);
void umq_ub_jetty_node_mark_err(jetty_pool_node_t *node);

// DFX statistics
typedef struct umq_ub_jetty_pool_stats {
    uint64_t total_num;         // Total nodes currently tracked (node_count)
    uint64_t global_num;        // IDLE nodes in global active_q
    uint64_t cache_num;         // IDLE nodes in thread-local caches
    uint64_t in_use_num;        // Nodes currently borrowed by a Logic UMQ (state == IN_USE)
    uint64_t err_num;           // Nodes marked is_jetty_err == true
    uint64_t acc_alloc_num;     // Cumulative allocs (nodes borrowed by Logic UMQ)
    uint64_t acc_free_num;      // Cumulative frees (nodes returned to pool)
    uint64_t acc_miss_num;      // Cumulative allocation misses (no available jetty)
} umq_ub_jetty_pool_stats_t;

int umq_ub_jetty_pool_stats_get(umq_ub_jetty_pool_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif