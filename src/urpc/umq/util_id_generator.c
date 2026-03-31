/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: util id allocator.
 * Create: 2025-9-12
 */

#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include "util_id_generator.h"

int util_id_allocator_init(util_id_allocator_t *id_allocator, uint32_t max_num, uint32_t start_id)
{
    if (id_allocator->available_ids != NULL) {
        return -1;
    }

    id_allocator->available_ids = (uint32_t *)calloc(max_num, sizeof(uint32_t));
    if (id_allocator->available_ids == NULL) {
        return -1;
    }

    id_allocator->num_available = 0;
    id_allocator->next_id = start_id;
    id_allocator->max_num = max_num;
    id_allocator->lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (id_allocator->lock == NULL) {
        free(id_allocator->available_ids);
        return -ENOMEM;
    }
    return 0;
}

void util_id_allocator_uninit(util_id_allocator_t *id_allocator)
{
    (void)util_mutex_lock_destroy(id_allocator->lock);
    id_allocator->lock = NULL;
    free(id_allocator->available_ids);
    id_allocator->available_ids = NULL;
}

uint32_t util_id_allocator_get(util_id_allocator_t *id_allocator)
{
    uint32_t id;
    (void)util_mutex_lock(id_allocator->lock);
    if (id_allocator->num_available > 0) {
        id = id_allocator->available_ids[--id_allocator->num_available];
    } else {
        id = id_allocator->next_id++;
        if (id >= id_allocator->max_num) {
            id_allocator->next_id--;
        }
    }
    (void)util_mutex_unlock(id_allocator->lock);

    return id;
}

void util_id_allocator_release(util_id_allocator_t *id_allocator, uint32_t util_id)
{
    if (id_allocator->available_ids == NULL) {
        return;
    }
    (void)util_mutex_lock(id_allocator->lock);
    if (id_allocator->num_available < id_allocator->max_num) {
        id_allocator->available_ids[id_allocator->num_available++] = util_id;
    }
    (void)util_mutex_unlock(id_allocator->lock);
    return;
}
