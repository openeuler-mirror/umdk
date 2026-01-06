/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc memory pool
 * Create: 2025-10-29
 */

#include <errno.h>

#include "urpc_dbuf_stat.h"
#include "urpc_id_generator.h"
#include "urpc_thread_closure.h"
#include "util_log.h"
#include "urpc_util.h"

#include "urpc_pool.h"

#define URPC_POOL_BLOCK_MAX (65536)    // max block num
#define URPC_POOL_ELEMENT_MAX (65536)  // max element num per block
#define URPC_POOL_ELEMENT_SIZE_MAX (8388608)
#define URPC_POOL_LOCAL_MAX (1024)  // support 1k different ctx pool/thread is enough for now

typedef struct urpc_pool_context {
    urpc_pool_t *global_pool;
    urpc_pool_block_t *local;
} urpc_pool_context_t;

static urpc_id_generator_t *g_urpc_pool_id;
static __thread urpc_pool_context_t g_urpc_pool_ctx[URPC_POOL_LOCAL_MAX];

URPC_DESTRUCTOR(urpc_pool_destructor, DESTRUCTOR_PRIORITY_GLOBAL)
{
    if (g_urpc_pool_id != NULL) {
        urpc_dbuf_free(g_urpc_pool_id);
        g_urpc_pool_id = NULL;
    }
}

static void urpc_pool_thread_closure(uint64_t arg __attribute__((unused)))
{
    urpc_pool_t *pool;
    for (uint32_t i = 0; i < URPC_POOL_LOCAL_MAX; i++) {
        if (g_urpc_pool_ctx[i].local == NULL || g_urpc_pool_ctx[i].global_pool == NULL) {
            continue;
        }

        pool = g_urpc_pool_ctx[i].global_pool;
        (void)pthread_mutex_lock(&pool->lock);
        if (g_urpc_pool_ctx[i].local->free_num > 0) {
            urpc_list_push_front(&pool->global_free, &g_urpc_pool_ctx[i].local->node);
        } else {
            urpc_list_push_front(&pool->global_free_container, &g_urpc_pool_ctx[i].local->node);
        }
        g_urpc_pool_ctx[i].local = NULL;
        g_urpc_pool_ctx[i].global_pool = NULL;
        (void)pthread_mutex_unlock(&pool->lock);
    }
}

static int urpc_pool_id_get(uint32_t *id)
{
    if (URPC_UNLIKELY(g_urpc_pool_id == NULL)) {
        g_urpc_pool_id = urpc_dbuf_malloc(URPC_DBUF_TYPE_UTIL, sizeof(urpc_id_generator_t));
        if (g_urpc_pool_id == NULL) {
            return -ENOMEM;
        }

        if (urpc_id_generator_init(g_urpc_pool_id, URPC_ID_GENERATOR_TYPE_BITMAP, URPC_POOL_LOCAL_MAX) != 0) {
            urpc_dbuf_free(g_urpc_pool_id);
            g_urpc_pool_id = NULL;
            return -ENOMEM;
        }
    }

    return urpc_id_generator_alloc(g_urpc_pool_id, 0, id);
}

static void urpc_pool_id_put(uint32_t id)
{
    if (URPC_UNLIKELY(g_urpc_pool_id == NULL || id >= URPC_POOL_LOCAL_MAX)) {
        return;
    }

    urpc_id_generator_free(g_urpc_pool_id, id);
}

int urpc_pool_init(urpc_pool_config_t *cfg, urpc_pool_t *pool)
{
    uint32_t id = 0;
    if (URPC_UNLIKELY(cfg->element_size > URPC_POOL_ELEMENT_SIZE_MAX ||
                      cfg->element_num_per_block > URPC_POOL_ELEMENT_MAX || cfg->block_num > URPC_POOL_BLOCK_MAX)) {
        UTIL_LOG_ERR("init urpc pool failed, element_size %u, element_num_per_block %u, block_num %u is invalid\n",
            cfg->element_size,
            cfg->element_num_per_block,
            cfg->block_num);
        return -EINVAL;
    }

    if (URPC_UNLIKELY(urpc_pool_id_get(&id) != 0)) {
        UTIL_LOG_ERR("malloc urpc pool id failed\n");
        return -ENOMEM;
    }

    pool->global_group =
        urpc_dbuf_malloc(URPC_DBUF_TYPE_UTIL, sizeof(urpc_pool_group_t) + cfg->block_num * sizeof(void *));
    if (pool->global_group == NULL) {
        urpc_pool_id_put(id);
        UTIL_LOG_ERR("malloc urpc pool group failed\n");
        return -ENOMEM;
    }
    pool->global_group->num = 0;

    pool->cfg = *cfg;
    pool->block_size = (uint32_t)sizeof(urpc_pool_block_t) + cfg->element_num_per_block * cfg->element_size;
    pool->container_size = (uint32_t)sizeof(urpc_pool_block_t) + cfg->element_num_per_block * (uint32_t)sizeof(void *);
    pthread_mutex_init(&pool->lock, NULL);
    urpc_list_init(&pool->global_free);
    urpc_list_init(&pool->global_free_container);
    pool->id = id;

    return 0;
}

void urpc_pool_uninit(urpc_pool_t *pool)
{
    urpc_pool_block_t *cur, *next;
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &pool->global_free)
    {
        urpc_list_remove(&cur->node);
        urpc_dbuf_free(cur);
    }

    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &pool->global_free_container)
    {
        urpc_list_remove(&cur->node);
        urpc_dbuf_free(cur);
    }

    if (pool->global_group != NULL) {
        for (uint32_t i = 0; i < pool->global_group->num; i++) {
            urpc_dbuf_free(pool->global_group->mem_addr[i]);
        }

        urpc_dbuf_free(pool->global_group);
        pool->global_group = NULL;
    }

    urpc_pool_id_put(pool->id);
    pthread_mutex_destroy(&pool->lock);
    pool->cfg.element_num_per_block = 0;
    pool->cfg.element_size = 0;
    pool->cfg.block_num = 0;
}

static int urpc_pool_local_init(urpc_pool_t *pool)
{
    if (URPC_LIKELY(g_urpc_pool_ctx[pool->id].local != NULL)) {
        return 0;
    }

    g_urpc_pool_ctx[pool->id].local = urpc_dbuf_malloc(URPC_DBUF_TYPE_UTIL, pool->container_size);
    if (URPC_UNLIKELY(g_urpc_pool_ctx[pool->id].local == NULL)) {
        UTIL_LIMIT_LOG_ERR("malloc local pool failed\n");
        return -ENOMEM;
    }
    g_urpc_pool_ctx[pool->id].global_pool = pool;
    g_urpc_pool_ctx[pool->id].local->free_num = 0;
    urpc_list_init(&g_urpc_pool_ctx[pool->id].local->node);

    urpc_thread_closure_register(THREAD_CLOSURE_POOL, 0, urpc_pool_thread_closure);

    return 0;
}

void *urpc_pool_element_get(urpc_pool_t *pool)
{
    if (URPC_UNLIKELY(urpc_pool_local_init(pool) != 0)) {
        return NULL;
    }

    urpc_pool_block_t *local = g_urpc_pool_ctx[pool->id].local;
    if (URPC_LIKELY(local->free_num > 0)) {
        return local->data_ptr[--local->free_num];
    }

    (void)pthread_mutex_lock(&pool->lock);
    if (URPC_LIKELY(!urpc_list_is_empty(&pool->global_free))) {
        urpc_pool_block_t *block;
        INIT_CONTAINER_PTR(block, pool->global_free.next, node);
        urpc_list_remove(&block->node);
        // copy data_ptr info to local
        memcpy(local, block, pool->container_size);
        urpc_list_push_front(&pool->global_free_container, &block->node);
    } else {
        if (URPC_UNLIKELY(pool->global_group->num >= pool->cfg.block_num)) {
            (void)pthread_mutex_unlock(&pool->lock);
            UTIL_LIMIT_LOG_ERR("global pool num %u exceed %u\n", pool->global_group->num, pool->cfg.block_num);
            return NULL;
        }

        void *block_mem = urpc_dbuf_malloc(URPC_DBUF_TYPE_UTIL, pool->block_size);
        if (block_mem == NULL) {
            (void)pthread_mutex_unlock(&pool->lock);
            UTIL_LIMIT_LOG_ERR("malloc block memory failed\n");
            return NULL;
        }
        pool->global_group->mem_addr[pool->global_group->num++] = block_mem;
        local->free_num = pool->cfg.element_num_per_block;
        for (uint32_t i = 0; i < pool->cfg.element_num_per_block; i++) {
            local->data_ptr[i] =
                (void *)((uintptr_t)block_mem + sizeof(urpc_pool_block_t) + i * pool->cfg.element_size);
        }
    }
    (void)pthread_mutex_unlock(&pool->lock);
    return local->data_ptr[--local->free_num];
}

void urpc_pool_element_put(urpc_pool_t *pool, void *element)
{
    // may put 1 element which is fetched by other thread, and local is not initialized yet
    if (URPC_UNLIKELY(urpc_pool_local_init(pool) != 0)) {
        // element will be freed when urpc_pool_uninit
        UTIL_LIMIT_LOG_ERR("put pool element failed\n");
        return;
    }

    urpc_pool_block_t *local = g_urpc_pool_ctx[pool->id].local;
    if (URPC_LIKELY(local->free_num < pool->cfg.element_num_per_block)) {
        local->data_ptr[local->free_num++] = element;
        return;
    }

    (void)pthread_mutex_lock(&pool->lock);
    urpc_pool_block_t *block;
    if (URPC_LIKELY(!urpc_list_is_empty(&pool->global_free_container))) {
        INIT_CONTAINER_PTR(block, pool->global_free_container.next, node);
        urpc_list_remove(&block->node);
    } else {
        block = urpc_dbuf_malloc(URPC_DBUF_TYPE_UTIL, pool->container_size);
        if (URPC_UNLIKELY(block == NULL)) {
            (void)pthread_mutex_unlock(&pool->lock);
            // element will be freed when urpc_pool_uninit
            UTIL_LIMIT_LOG_ERR("malloc block memory failed\n");
            return;
        }
    }

    memcpy(block, local, pool->container_size);
    local->free_num = 0;
    urpc_list_push_front(&pool->global_free, &block->node);
    (void)pthread_mutex_unlock(&pool->lock);
    local->data_ptr[local->free_num++] = element;
}
