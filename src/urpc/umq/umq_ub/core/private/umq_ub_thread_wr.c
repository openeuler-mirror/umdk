/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq ub thread-local tx work-request pool.
 * Create: 2026-07-17
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "umq_ub_thread_wr.h"

typedef struct umq_ub_thread_wr_ctx {
    umq_ub_thread_wr_t *slots[UMQ_THREAD_ID_MAX];
    bool inited;
} umq_ub_thread_wr_ctx_t;

static umq_ub_thread_wr_ctx_t g_umq_ub_thread_wr_ctx;

int umq_ub_thread_wr_init(void)
{
    if (g_umq_ub_thread_wr_ctx.inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq ub thread wr already initialized\n");
        return -UMQ_ERR_EEXIST;
    }

    memset(&g_umq_ub_thread_wr_ctx, 0, sizeof(g_umq_ub_thread_wr_ctx));
    g_umq_ub_thread_wr_ctx.inited = true;
    return UMQ_SUCCESS;
}

void umq_ub_thread_wr_uninit(void)
{
    g_umq_ub_thread_wr_ctx.inited = false;

    /* Free every slot uniformly -- both the init-time allocations and the
     * lazily-allocated ones -- since thread exit never frees them. */
    for (uint32_t i = 0; i < UMQ_THREAD_ID_MAX; i++) {
        free(g_umq_ub_thread_wr_ctx.slots[i]);
        g_umq_ub_thread_wr_ctx.slots[i] = NULL;
    }
}

umq_ub_thread_wr_t *umq_ub_thread_wr_get(void)
{
    if (!g_umq_ub_thread_wr_ctx.inited) {
        return NULL;
    }

    /* umq_thread_id_get() is idempotent per thread (it caches the id in its own
     * thread-key fast path), so this is lock-free on the steady state. Thread
     * ids are unique per-thread, so writes to slots[id] from different threads
     * never collide on the same index. */
    uint32_t id = umq_thread_id_get();
    if (id >= UMQ_THREAD_ID_MAX) {
        return NULL;
    }

    /* Fast path: slot already wired up (allocated on a previous call from this thread,
     * or reused from a recycled id). */
    umq_ub_thread_wr_t *wr = g_umq_ub_thread_wr_ctx.slots[id];
    if (wr != NULL) {
        return wr;
    }

    wr = (umq_ub_thread_wr_t *)calloc(1, sizeof(umq_ub_thread_wr_t));
    if (wr == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "umq ub thread wr alloc failed for id %u\n", id);
        return NULL;
    }
    g_umq_ub_thread_wr_ctx.slots[id] = wr;
    return wr;
}
