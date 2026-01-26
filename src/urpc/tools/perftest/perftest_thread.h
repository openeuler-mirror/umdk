/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: perftest thread
 * Create: 2024-3-6
 */

#ifndef PERFTEST_THREAD_H
#define PERFTEST_THREAD_H

#include <pthread.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PERFTEST_THREAD_MAX_NUM (64U)

typedef enum perftest_thread_state {
    PERFTEST_THREAD_ERROR,
    PERFTEST_THREAD_INIT,
    PERFTEST_THREAD_RUNNING,
    PERFTEST_THREAD_STOP,
} perftest_thread_state_t;

typedef struct perftest_thread_arg perftest_thread_arg_t;

struct perftest_thread_arg {
    void (*func)(perftest_thread_arg_t *);
    pthread_t pid;
    uint32_t cpu_affinity;
    volatile perftest_thread_state_t state;
};

int perftest_worker_thread_create(perftest_thread_arg_t *args);
void perftest_worker_thread_destroy(perftest_thread_arg_t *args);
// thread index can only be used before perftest_worker_thread_destroy
uint32_t perftest_thread_index(void);
void perftest_thread_index_set(uint32_t index);

#ifdef __cplusplus
}
#endif

#endif  // PERFTEST_THREAD_H