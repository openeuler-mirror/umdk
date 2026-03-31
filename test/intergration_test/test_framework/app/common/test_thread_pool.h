/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: thread function
*/

#ifndef TEST_THREAD_POOL_H
#define TEST_THREAD_POOL_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include "test_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 20
#endif

#ifndef TEST_SUCCESS
#define TEST_SUCCESS 0
#endif

#ifndef TEST_FAILED
#define TEST_FAILED (-1)
#endif

#ifndef MAX_THREAD_NAME_LEN
#define MAX_THREAD_NAME_LEN 20
#endif

typedef struct worker {
    void *(*process)(void *arg);
    void *arg;
    struct worker *next;
} TestCThreadWorker;

typedef struct {
    pthread_mutex_t queueLock;
    pthread_cond_t queueReady;
    TestCThreadWorker *queueHead;
    int shutdown;
    pthread_t *threadid;
    int maxThreadNum;
    int curQueueSize;
    int freeThreadNum;
} TestCThreadPool;

int TestThreadPoolInit(int maxThreadNum);
int TestPoolAddWorker(void *(*process)(void *arg), void *arg);
int TestThreadPoolDestroy();
#ifdef __cplusplus
}
#endif

#endif