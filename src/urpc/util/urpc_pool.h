/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc memory pool
 * Create: 2025-10-29
 */

#ifndef URPC_POOL_H
#define URPC_POOL_H

#include <pthread.h>
#include <stdint.h>

#include "urpc_list.h"
#include "util_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct urpc_pool_block {
    urpc_list_t node;
    uint32_t free_num;
    void *data_ptr[0];
} urpc_pool_block_t;

typedef struct urpc_pool_group {
    uint32_t num;
    void *mem_addr[0];
} urpc_pool_group_t;

typedef struct urpc_pool_config {
    uint32_t element_size;
    uint32_t element_num_per_block;
    uint32_t block_num;
} urpc_pool_config_t;

typedef struct urpc_pool {
    util_external_mutex_lock *lock;
    urpc_list_t global_free;            // container with element
    urpc_list_t global_free_container;  // only container
    urpc_pool_group_t *global_group;    // used for global uninit
    urpc_pool_config_t cfg;
    uint32_t block_size;
    uint32_t container_size;
    uint16_t id;
} urpc_pool_t;

int urpc_pool_init(urpc_pool_config_t *cfg, urpc_pool_t *pool);

void urpc_pool_uninit(urpc_pool_t *pool);

void urpc_pool_thread_closure(uint64_t arg);

void *urpc_pool_element_get(urpc_pool_t *pool);

void urpc_pool_element_put(urpc_pool_t *pool, void *element);

#ifdef __cplusplus
}
#endif

#endif