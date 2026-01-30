/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq example
 * Create: 2026-1-27
 * Note:
 * History: 2026-1-27
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "threadpool.h"

#define MAX_THREAD_NUM 100

static void *threadpool_worker(void *threadpool)
{
    threadpool_t *pool = (threadpool_t *)threadpool;
    threadpool_task_t task;

    for (;;) {
        pthread_mutex_lock(&(pool->lock));

        while ((pool->count == 0) && (pool->shutdown == 0)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if (pool->shutdown == 1) {
            break;
        }

        task.function = pool->queue[pool->head].function;
        task.arg = pool->queue[pool->head].arg;
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;
        pthread_mutex_unlock(&(pool->lock));
        (*(task.function))(task.arg);

        free(task.arg);
    }
    
    pool->started--;
    pthread_mutex_unlock(&(pool->lock));
    return NULL;
}

threadpool_t *threadpool_create(int thread_count, int queue_size)
{
    threadpool_t *pool;
    int i;
    
    if (thread_count <= 0 || thread_count > MAX_THREAD_NUM || queue_size <= 0) {
        return NULL;
    }

    if ((pool = (threadpool_t *)malloc(sizeof(threadpool_t))) == NULL) {
        goto err;
    }

    pool->thread_count = 0;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = pool->started = 0;

    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    if (pool->threads == NULL) {
        goto err;
    }

    pool->queue = (threadpool_task_t *)malloc(sizeof(threadpool_task_t) * queue_size);
    if (pool->queue == NULL) {
        goto err;
    }

    if ((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
        (pthread_cond_init(&(pool->notify), NULL) != 0)) {
        goto err;
    }
    
    for (i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, threadpool_worker, (void *)pool) != 0) {
            goto err;
        }
        pool->thread_count++;
        pool->started++;
    }
    
    return pool;

err:
    if (pool) {
        threadpool_free(pool);
    }
    return NULL;
}

int threadpool_add(threadpool_t *pool, void (*function)(void *), void *arg, uint32_t arg_len)
{
    int err = 0;
    int next;
    
    void *work_arg = malloc(arg_len);
    if (work_arg == NULL) {
        return -1;
    }

    (void)memcpy(work_arg, arg, arg_len);
    if (pool == NULL || function == NULL) {
        goto FREE_ARG;
    }

    pthread_mutex_lock(&(pool->lock));
    next = (pool->tail + 1) % pool->queue_size;
    if (pool->count == pool->queue_size || pool->shutdown != 0) {
        goto FREE_ARG;
    } else {
        pool->queue[pool->tail].function = function;
        pool->queue[pool->tail].arg = work_arg;
        pool->tail = next;
        pool->count += 1;
        err = pthread_cond_signal(&(pool->notify));
    }
    pthread_mutex_unlock(&(pool->lock));
    return err;

FREE_ARG:
    free(work_arg);
    return -1;
}

int threadpool_destroy(threadpool_t *pool)
{
    int i, err = 0;
    if (pool == NULL) {
        return -1;
    }

    pthread_mutex_lock(&(pool->lock));
    if (pool->shutdown != 0) {
        err = -1;
    } else {
        pool->shutdown = 1;
        if ((pthread_cond_broadcast(&(pool->notify)) != 0)) {
            err = -1;
        }

        for (i = 0; i < pool->thread_count; i++) {
            if (pthread_join(pool->threads[i], NULL) != 0) {
                err = -1;
            }
        }
    }
    pthread_mutex_unlock(&(pool->lock));

    if (err == 0) {
        threadpool_free(pool);
    }
    return err;
}

int threadpool_free(threadpool_t *pool)
{
    if (pool == NULL || pool->started > 0) {
        return -1;
    }
    
    if (pool->threads) {
        free(pool->threads);
        pool->threads = NULL;
        free(pool->queue);
        pool->queue = NULL;
        pthread_mutex_destroy(&(pool->lock));
        pthread_cond_destroy(&(pool->notify));
    }
    free(pool);
    return 0;
}
