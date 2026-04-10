/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc thread local closure
 * Create: 2025-07-21
 */

#ifndef URPC_THREAD_CLOSURE_H
#define URPC_THREAD_CLOSURE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_thread_closure_type {
    THREAD_CLOSURE_PERF,
    THREAD_CLOSURE_QBUF,
    THREAD_CLOSURE_POOL,
    THREAD_CLOSURE_UMQ_PERF,
    THREAD_CLOSURE_MAX,
} urpc_thread_closure_type_t;

void urpc_thread_closure_register(urpc_thread_closure_type_t type, uint64_t id, void (*closure)(uint64_t id));

#ifdef __cplusplus
}
#endif

#endif
