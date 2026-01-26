/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize resource release timeout list
 * Create: 2024-9-3
 */

#ifndef RESOURCE_RELEASE_H
#define RESOURCE_RELEASE_H

#include <stdbool.h>
#include <stdint.h>

#include "urpc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_RESOURCE_RELEASE_DONE  0
#define URPC_RESOURCE_RELEASE_AGAIN 1

// can't call release_entry_add in release_callback_t since it's executed in list lock, just return
// URPC_RESOURCE_RELEASE_AGAIN to reinsert into release list
typedef int (*release_callback_t)(void *args, bool force);

typedef struct urpc_resource_release_entry {
    urpc_list_t node;
    release_callback_t cb;
    void *args;
    uint32_t timeout;
    uint32_t timestamp;  // when this resource need to release
    uint32_t task_id;
} urpc_resource_release_entry_t;

int urpc_resource_release_init(void);
void urpc_resource_release_uninit(void);
int urpc_resource_release_entry_add(release_callback_t cb, void *args, uint32_t timeout, uint32_t *id);
bool urpc_resource_release_entry_delete(uint32_t id);
void urpc_resource_release_clear(void);

void urpc_resource_release_ctx_lock(void);
void urpc_resource_release_ctx_unlock(void);

#ifdef __cplusplus
}
#endif

#endif