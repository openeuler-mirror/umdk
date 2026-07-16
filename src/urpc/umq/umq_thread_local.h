/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq thread local id allocator.
 * Create: 2026-07-15
 */

#ifndef UMQ_THREAD_LOCAL_H
#define UMQ_THREAD_LOCAL_H

#include <stdint.h>
#include "util_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_THREAD_ID_RANGE_DEFAULT 32u
#define UMQ_THREAD_ID_MAX           256u
#define UMQ_THREAD_ID_INVALID       0xFFFFFFFFu

/* Initialize the thread-id allocator (process-wide singleton).
 * Returns 0 on success, <0 on failure (-EEXIST if already initialized, -ENOMEM on OOM). */
int umq_thread_id_init(void);

/* Uninitialize. The caller must ensure all threads using this module have exited,
 * otherwise a destructor may fire after uninit. */
void umq_thread_id_uninit(void);

/* Get the unique ID bound to the calling thread. Idempotent per thread:
 * repeated calls from the same thread return the same value.
 * Returns an ID in [0, UMQ_THREAD_ID_MAX); UMQ_THREAD_ID_INVALID when none is
 * available or the module is uninitialized.
 * The ID is automatically reclaimed by the thread-key destructor on thread exit,
 * so explicit release is normally unnecessary. */
uint32_t umq_thread_id_get(void);

util_external_mutex_lock *umq_thread_local_mutex_lock_create(int attr);
int umq_thread_local_mutex_lock_destroy(util_external_mutex_lock *lock);
int umq_thread_local_mutex_lock(util_external_mutex_lock *lock);
int umq_thread_local_mutex_unlock(util_external_mutex_lock *lock);

#ifdef __cplusplus
}
#endif

#endif
