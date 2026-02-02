/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq example
 * Create: 2026-1-27
 * Note:
 * History: 2026-1-27
 */

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*function)(void *);
    void *arg;
} threadpool_task_t;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    threadpool_task_t *queue;
    int thread_count;
    int queue_size;
    int head;
    int tail;
    int count;
    int shutdown;
    int started;
} threadpool_t;

threadpool_t *threadpool_create(int thread_count, int queue_size);
int threadpool_add(threadpool_t *pool, void (*function)(void *), void *arg, uint32_t arg_len);
int threadpool_destroy(threadpool_t *pool);
int threadpool_free(threadpool_t *pool);

#ifdef __cplusplus
}
#endif

#endif

