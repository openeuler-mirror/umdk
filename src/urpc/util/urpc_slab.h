/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc slab for memory cache
 * Create: 2024-5-13
 */

#ifndef URPC_SLAB_H
#define URPC_SLAB_H

#include <pthread.h>
#include <stdint.h>

#include "urpc_framework_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eslab {
    pthread_spinlock_t lock;
    void *addr;          // Start address of this slab-controlled memory
    uint32_t obj_size;   // Object size inside the slab
    uint32_t total;      // Total number of the objects
    uint32_t next_free;  // The index of next available object
} eslab_t;

void eslab_init(eslab_t *slab, void *addr, uint32_t obj_size, uint32_t total);
void eslab_uninit(eslab_t *slab);
void *eslab_alloc(eslab_t *slab, uint32_t *id);
void eslab_free(eslab_t *slab, uint32_t id, void *buf);
void *eslab_get_first_used_object_lockless(eslab_t *slab);

static inline void *eslab_alloc_lockless(eslab_t *slab, uint32_t *id)
{
    if (slab->next_free == UINT32_MAX) {
        errno = URPC_ERR_ENOMEM;
        return NULL;
    }

    *id = slab->next_free;
    void *buf = (void *)((uintptr_t)slab->addr + slab->next_free * slab->obj_size);
    slab->next_free = *(uint32_t *)buf;
    return buf;
}

static inline void eslab_free_lockless(eslab_t *slab, uint32_t id, void *buf)
{
    *(uint32_t *)buf = slab->next_free;
    slab->next_free = id;
}

static inline void *eslab_get_buf_lockless(eslab_t *slab)
{
    uint32_t buf_id;
    return eslab_alloc_lockless(slab, &buf_id);
}

static inline void eslab_put_buf_lockless(eslab_t *slab, void *buf)
{
    uint32_t buf_id = (uint32_t)(((uintptr_t)buf - (uintptr_t)slab->addr) / slab->obj_size);
    eslab_free_lockless(slab, buf_id, buf);
}

static inline void *eslab_get_buf(eslab_t *slab)
{
    uint32_t buf_id;
    return eslab_alloc(slab, &buf_id);
}

static inline void eslab_put_buf(eslab_t *slab, void *buf)
{
    uint32_t buf_id = (uint32_t)(((uintptr_t)buf - (uintptr_t)slab->addr) / slab->obj_size);
    eslab_free(slab, buf_id, buf);
}

static inline uint32_t eslab_addr_to_id(eslab_t *slab, void *addr)
{
    return (uint32_t)((uint64_t)((uintptr_t)addr - (uintptr_t)slab->addr) / slab->obj_size);
}

static inline void *eslab_id_to_addr(eslab_t *slab, uint32_t id)
{
    return (void *)((uint8_t *)slab->addr + (uint64_t)id * slab->obj_size);
}

static inline bool eslab_validate_addr(eslab_t *slab, void *addr)
{
    return ((uint64_t)(uintptr_t)addr >= (uint64_t)(uintptr_t)slab->addr) &&
        ((uint64_t)(uintptr_t)addr <= (uint64_t)(uintptr_t)slab->addr + ((uint64_t)slab->obj_size * slab->total));
}

static inline void *eslab_get_first_used_object(eslab_t *slab)
{
    (void)pthread_spin_lock(&slab->lock);
    void *buf = eslab_get_first_used_object_lockless(slab);
    (void)pthread_spin_unlock(&slab->lock);
    return buf;
}

#ifdef __cplusplus
}
#endif

#endif