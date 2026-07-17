/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq thread local id allocator.
 * Create: 2026-07-15
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "umq_vlog.h"
#include "urpc_bitmap.h"
#include "util_thread_key.h"
#include "umq_thread_local.h"

#define UMQ_THREAD_ID_NUM   UMQ_THREAD_ID_MAX
#define UMQ_THREAD_ID_WORDS DIV_ROUND_UP(UMQ_THREAD_ID_NUM, URPC_ULONG_BITS)

typedef struct umq_thread_id_ctx {
    unsigned long bitmap[UMQ_THREAD_ID_WORDS];
    util_external_mutex_lock *lock;
    util_thread_key_t *key;
    bool inited;
} umq_thread_id_ctx_t;

static umq_thread_id_ctx_t g_umq_thread_id_ctx;

/* Encode the ID into the thread-key value pointer: val = id + 1, so that 0 (NULL)
 * still means "unset". This avoids any per-thread heap allocation for the value. */
static inline void *umq_thread_id_encode(uint32_t id)
{
    return (void *)((uintptr_t)id + 1);
}

static inline uint32_t umq_thread_id_decode(void *data)
{
    return (uint32_t)((uintptr_t)data - 1);
}

static void umq_thread_id_release(uint32_t id)
{
    if (!g_umq_thread_id_ctx.inited) {
        return;
    }
    if (id >= UMQ_THREAD_ID_NUM) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "umq thread id release invalid id %u, max %u\n", id, UMQ_THREAD_ID_NUM);
        return;
    }
    (void)umq_thread_local_mutex_lock(g_umq_thread_id_ctx.lock);
    urpc_bitmap_set0(g_umq_thread_id_ctx.bitmap, id);
    (void)umq_thread_local_mutex_unlock(g_umq_thread_id_ctx.lock);
}

static void umq_thread_id_destructor(void *data)
{
    /* Reclaim the ID held by the exiting thread.
     * Clear the slot first: if the underlying implementation re-checks non-NULL
     * keys and calls the destructor again (up to PTHREAD_DESTRUCTOR_ITERATIONS),
     * a repeat call would race with another thread re-acquiring the same ID via
     * umq_thread_id_release() and wrongly free it. Clearing the slot stops that. */
    (void)util_thread_setspecific(g_umq_thread_id_ctx.key, NULL);

    if (data == NULL) {
        return;
    }
    umq_thread_id_release(umq_thread_id_decode(data));
}

int umq_thread_id_init(void)
{
    if (g_umq_thread_id_ctx.inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq thread id already initialized\n");
        return -EEXIST;
    }

    g_umq_thread_id_ctx.lock = umq_thread_local_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (g_umq_thread_id_ctx.lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq thread id mutex create failed\n");
        return -ENOMEM;
    }

    g_umq_thread_id_ctx.key = util_thread_key_create(umq_thread_id_destructor);
    if (g_umq_thread_id_ctx.key == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq thread id key create failed\n");
        (void)umq_thread_local_mutex_lock_destroy(g_umq_thread_id_ctx.lock);
        g_umq_thread_id_ctx.lock = NULL;
        return -ENOMEM;
    }

    memset(g_umq_thread_id_ctx.bitmap, 0, sizeof(g_umq_thread_id_ctx.bitmap));
    g_umq_thread_id_ctx.inited = true;
    return 0;
}

void umq_thread_id_uninit(void)
{
    if (!g_umq_thread_id_ctx.inited) {
        return;
    }
    g_umq_thread_id_ctx.inited = false;
    (void)util_thread_key_delete(g_umq_thread_id_ctx.key);
    g_umq_thread_id_ctx.key = NULL;
    (void)umq_thread_local_mutex_lock_destroy(g_umq_thread_id_ctx.lock);
    g_umq_thread_id_ctx.lock = NULL;
}

uint32_t umq_thread_id_get(void)
{
    if (!g_umq_thread_id_ctx.inited) {
        return UMQ_THREAD_ID_INVALID;
    }

    /* Fast path: this thread already holds an ID. getspecific is a thread-local
     * read, lock-free and idempotent. */
    void *data = util_thread_getspecific(g_umq_thread_id_ctx.key);
    if (data != NULL) {
        return umq_thread_id_decode(data);
    }

    /* Slow path: first allocation by this thread. Always scan from bit 0 so that
     * IDs freed by release() (always a lower-or-equal bit than the last one
     * claimed) are immediately reusable; find_next_zero_bit does not wrap. */
    (void)umq_thread_local_mutex_lock(g_umq_thread_id_ctx.lock);
    unsigned long bit = urpc_bitmap_find_next_zero_bit(g_umq_thread_id_ctx.bitmap, UMQ_THREAD_ID_NUM, 0);
    if (bit < UMQ_THREAD_ID_NUM) {
        urpc_bitmap_set1(g_umq_thread_id_ctx.bitmap, bit);
    }
    (void)umq_thread_local_mutex_unlock(g_umq_thread_id_ctx.lock);

    if (bit >= UMQ_THREAD_ID_NUM) {
        UMQ_LIMIT_VLOG_WARN(VLOG_UMQ, "umq thread id exhausted, max %u reached\n", UMQ_THREAD_ID_NUM);
        return UMQ_THREAD_ID_INVALID;
    }

    uint32_t id = (uint32_t)bit;
    if (util_thread_setspecific(g_umq_thread_id_ctx.key, umq_thread_id_encode(id)) != 0) {
        /* Extremely unlikely; roll back the bit we just claimed. */
        UMQ_VLOG_ERR(VLOG_UMQ, "umq thread id setspecific failed, id %u rolled back\n", id);
        umq_thread_id_release(id);
        return UMQ_THREAD_ID_INVALID;
    }
    return id;
}

// Notice: if external_thread_key_ops is NOT registered, default mutex lock should be used
util_external_mutex_lock *umq_thread_local_mutex_lock_create(int attr)
{
    if (util_thread_key_ops_registered()) {
        return util_mutex_lock_create(attr);
    }
    return util_mutex_lock_default_ops_get()->create(attr);
}

int umq_thread_local_mutex_lock_destroy(util_external_mutex_lock *lock)
{
    if (util_thread_key_ops_registered()) {
        return util_mutex_lock_destroy(lock);
    }
    return util_mutex_lock_default_ops_get()->destroy(lock);
}

int umq_thread_local_mutex_lock(util_external_mutex_lock *lock)
{
    if (util_thread_key_ops_registered()) {
        return util_mutex_lock(lock);
    }
    return util_mutex_lock_default_ops_get()->lock(lock);
}

int umq_thread_local_mutex_unlock(util_external_mutex_lock *lock)
{
    if (util_thread_key_ops_registered()) {
        return util_mutex_unlock(lock);
    }
    return util_mutex_lock_default_ops_get()->unlock(lock);
}
