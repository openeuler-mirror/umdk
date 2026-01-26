/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: perftest thread
 * Create: 2024-3-6
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#include "perftest_util.h"
#include "perftest_thread.h"

#define PERFTEST_THREAD_NAME_SIZE 32

typedef struct perftest_thread_context {
    uint32_t index;
} perftest_thread_context_t;

// 0 reserved for control thread
static atomic_uint g_perftest_thread_index = ATOMIC_VAR_INIT(1);

static __thread perftest_thread_context_t *g_perftest_thread_ctx;

static int perftest_thread_init(uint32_t cpu_affinity)
{
    if (g_perftest_thread_ctx != NULL) {
        return 0;
    }

    g_perftest_thread_ctx = (perftest_thread_context_t *)calloc(1, sizeof(perftest_thread_context_t));
    if (g_perftest_thread_ctx == NULL) {
        LOG_PRINT("malloc perftest thread context failed\n");
        return -1;
    }

    g_perftest_thread_ctx->index = atomic_fetch_add(&g_perftest_thread_index, 1);

    pthread_t pid = pthread_self();
    char name[PERFTEST_THREAD_NAME_SIZE];
    (void)sprintf(name, "perftest_wkr%u", g_perftest_thread_ctx->index);
    if (pthread_setname_np(pid, name) != 0) {
        LOG_PRINT("set worker thread name %s failed\n", name);
    }

    if (cpu_affinity == UINT32_MAX) {
        return 0;
    }

    // set cpu affinity
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_affinity, &set);
    if (pthread_setaffinity_np(pid, sizeof(set), &set) != 0) {
        LOG_PRINT("set affinity of %s on cpu %u failed\n", name, cpu_affinity);
    } else {
        LOG_PRINT("%s is running on cpu %u\n", name, cpu_affinity);
    }

    return 0;
}

static inline void perftest_thread_uninit(void)
{
    free(g_perftest_thread_ctx);
    g_perftest_thread_ctx = NULL;
}

static void *perftest_worker_func(void *arg)
{
    perftest_thread_arg_t *args = (perftest_thread_arg_t *)arg;

    args->state = PERFTEST_THREAD_INIT;
    if (perftest_thread_init(args->cpu_affinity) != 0) {
        args->state = PERFTEST_THREAD_ERROR;
        return NULL;
    }

    args->state = PERFTEST_THREAD_RUNNING;
    args->func((perftest_thread_arg_t *)args);
    args->state = PERFTEST_THREAD_STOP;

    perftest_thread_uninit();

    return NULL;
}

int perftest_worker_thread_create(perftest_thread_arg_t *args)
{
    if (pthread_create(&args->pid, NULL, perftest_worker_func, args) != 0) {
        return -1;
    }

    while (args->state == PERFTEST_THREAD_INIT) {
        (void)usleep(1);
    }

    if (args->state == PERFTEST_THREAD_ERROR) {
        (void)pthread_join(args->pid, NULL);
        return -1;
    }

    return 0;
}

void perftest_worker_thread_destroy(perftest_thread_arg_t *args)
{
    args->state = PERFTEST_THREAD_STOP;
    (void)pthread_join(args->pid, NULL);

    perftest_thread_uninit();
}

uint32_t perftest_thread_index(void)
{
    return g_perftest_thread_ctx == NULL ? 0 : g_perftest_thread_ctx->index;
}

void perftest_thread_index_set(uint32_t index)
{
    if (g_perftest_thread_ctx == NULL) {
        g_perftest_thread_ctx = (perftest_thread_context_t *)calloc(1, sizeof(perftest_thread_context_t));
        if (g_perftest_thread_ctx == NULL) {
            LOG_PRINT("malloc perftest thread context failed\n");
            return;
        }
    }

    g_perftest_thread_ctx->index = index;
}