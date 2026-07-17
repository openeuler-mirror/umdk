/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq ub thread-local tx work-request pool.
 * Create: 2026-07-17
 *
 * Each thread occupies one fixed slot in a pointer table indexed by thread id.
 * Slots [0, UMQ_THREAD_ID_RANGE_DEFAULT) are pre-allocated at init so the
 * common data path is allocation-free; slots beyond that (for threads spawned
 * after init) are allocated lazily on first use. No slot is freed on thread
 * exit -- all of them are released uniformly at uninit.
 *
 * Relies on umq_thread_id_get() (from umq_thread_local.h), which is idempotent
 * per thread and already provides a thread-key fast path; this module just
 * indexes a pointer table by the id.
 */

#ifndef UMQ_UB_THREAD_WR_H
#define UMQ_UB_THREAD_WR_H

#include "umq_inner.h"
#include "umq_thread_local.h"
#include "urma_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_ub_thread_wr {
    urma_jfs_wr_t urma_wr[UMQ_BATCH_SIZE];
    urma_sge_t sges[UMQ_BATCH_SIZE][UMQ_MAX_SGE_NUM];
} umq_ub_thread_wr_t;

/* Initialize the per-thread-id wr pool. Pre-allocates the first
 * UMQ_THREAD_ID_RANGE_DEFAULT slots. Returns 0 on success, <0 on failure. */
int umq_ub_thread_wr_init(void);

/* Release every wr ever handed out (pre-allocated + lazily allocated).
 * The caller must ensure all threads using the data path have exited. */
void umq_ub_thread_wr_uninit(void);

/* Return the calling thread's tx work-request buffer. Idempotent per thread:
 * repeated calls from the same thread return the same buffer. Returns NULL if
 * the thread has no id available or allocation fails. */
umq_ub_thread_wr_t *umq_ub_thread_wr_get(void);

#ifdef __cplusplus
}
#endif

#endif
