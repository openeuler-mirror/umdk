/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc thread local closure
 * Create: 2025-07-21
 */

#ifndef URPC_THREAD_CLOSURE_H
#define URPC_THREAD_CLOSURE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set to true by the first ~urpc_thread_closure() destructor during process exit.
 * Once set, all release_thread_cache variants skip cross-thread list operations
 * (g_tls_register_head / thread_cache_list) because nodes from already-exited
 * threads may be dangling. This guards the exit() -> __call_tls_dtors -> release
 * path which is NOT covered by umq_*_uninit()'s g_process_exiting flag (uninit is
 * not guaranteed to run before TLS dtors). */
extern volatile bool g_tls_dtors_running;

typedef enum urpc_thread_closure_type {
    THREAD_CLOSURE_PERF,
    THREAD_CLOSURE_QBUF,
    THREAD_CLOSURE_POOL,
    THREAD_CLOSURE_UMQ_PERF,
    THREAD_CLOSURE_UMQ_DATA_PERF,
    THREAD_CLOSURE_JETTY_POOL,
    THREAD_CLOSURE_TINY_QBUF,
    THREAD_CLOSURE_MAX,
} urpc_thread_closure_type_t;

void urpc_thread_closure_register(urpc_thread_closure_type_t type, uint64_t id, void (*closure)(uint64_t id));

#ifdef __cplusplus
}
#endif

#endif
