/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc slab for memory cache
 * Create: 2024-5-13
 */

#include <errno.h>
#include <string.h>

#include "util_log.h"
#include "urpc_util.h"

#include "urpc_slab.h"

void eslab_init(eslab_t *slab, void *addr, uint32_t obj_size, uint32_t total)
{
    uint64_t i;
    char *next = (char *)addr;

    for (i = 0; i < total - 1; i++) {
        *(uint32_t *)next = (uint32_t)(i + 1);
        next += obj_size;
    }
    *(uint32_t *)next = UINT32_MAX;

    slab->addr = addr;
    slab->obj_size = obj_size;
    slab->total = total;
    slab->next_free = 0;
    (void)pthread_spin_init(&slab->lock, PTHREAD_PROCESS_PRIVATE);
}

void eslab_uninit(eslab_t *slab)
{
    (void)pthread_spin_destroy(&slab->lock);
}

void *eslab_alloc(eslab_t *slab, uint32_t *id)
{
    (void)pthread_spin_lock(&slab->lock);

    if (URPC_UNLIKELY(slab->next_free == UINT32_MAX)) {
        (void)pthread_spin_unlock(&slab->lock);
        errno = URPC_ERR_ENOMEM;
        return NULL;
    }

    // Non-public interface, ensure that the parameter is not NULL.
    if (URPC_UNLIKELY(slab->next_free >= slab->total)) {
        (void)pthread_spin_unlock(&slab->lock);
        UTIL_LOG_DEBUG("eslab alloc out of range, next_free = %u, total = %u\n", slab->next_free, slab->total);
        errno = URPC_ERR_EPERM;
        return NULL;
    }

    *id = slab->next_free;
    void *buf = (void *)((uintptr_t)slab->addr + slab->next_free * slab->obj_size);
    slab->next_free = *(uint32_t *)buf;
    /* next block still in use, means use after free */
    if (URPC_UNLIKELY(slab->next_free >= slab->total && slab->next_free != UINT32_MAX)) {
        (void)pthread_spin_unlock(&slab->lock);
        UTIL_LOG_DEBUG("eslab alloc out of range, next_free = %u, total = %u\n", slab->next_free, slab->total);
        errno = URPC_ERR_EPERM;
        return NULL;
    }
    (void)pthread_spin_unlock(&slab->lock);
    return buf;
}

void eslab_free(eslab_t *slab, uint32_t id, void *buf)
{
    (void)pthread_spin_lock(&slab->lock);
    *(uint32_t *)buf = slab->next_free;
    slab->next_free = id;
    (void)pthread_spin_unlock(&slab->lock);
}

// return first used object
void *eslab_get_first_used_object_lockless(eslab_t *slab)
{
    uint32_t slab_num = slab->total;
    bool idle_slab[slab_num];
    memset(idle_slab, 0, slab_num * sizeof(bool));
    uint32_t next_free = slab->next_free;
    while (next_free != UINT32_MAX && next_free < slab_num) {
        if (idle_slab[next_free]) {
            UTIL_LIMIT_LOG_DEBUG("idle slab list must not contain any cycles\n");
            return NULL;
        }
        idle_slab[next_free] = true;
        next_free = *(uint32_t *)((uintptr_t)slab->addr + next_free * slab->obj_size);
    }

    for (uint32_t i = 0; i < slab_num; i++) {
        if (!idle_slab[i]) {
            return (void *)((uintptr_t)slab->addr + i * slab->obj_size);
        }
    }
    return NULL;
}
