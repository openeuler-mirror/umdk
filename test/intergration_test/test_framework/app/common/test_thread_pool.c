/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: thread function
*/

#include "test_thread_pool.h"

static TestCThreadPool *g_testThreadPool = NULL;

static void *TestThreadRoutine(void *arg)
{
    while (1) {
        pthread_mutex_lock(&(g_testThreadPool->queueLock));

        while (g_testThreadPool->curQueueSize == 0 && !g_testThreadPool->shutdown) {
            pthread_cond_wait(&(g_testThreadPool->queueReady), &(g_testThreadPool->queueLock));
        }
    

        if (g_testThreadPool->shutdown) {
            pthread_mutex_unlock(&(g_testThreadPool->queueLock));
            TEST_LOG_INFO("thread 0x%x will exit\n", (unsigned int)pthread_self());
            break;
        }

        g_testThreadPool->curQueueSize--;
        TestCThreadWorker *worker = g_testThreadPool->queueHead;

        g_testThreadPool->queueHead = worker->next;
        g_testThreadPool->freeThreadNum--;
        pthread_mutex_unlock(&(g_testThreadPool->queueLock));

        (*(worker->process))(worker->arg);
        free(worker);
        worker = NULL;

        pthread_mutex_lock(&(g_testThreadPool->queueLock));

        g_testThreadPool->freeThreadNum++;
        pthread_mutex_unlock(&(g_testThreadPool->queueLock));
    }
    return NULL;
}

int TestThreadPoolInit(int maxThreadNum)
{
    int index = 0;

    g_testThreadPool = (TestCThreadPool *)malloc(sizeof(TestCThreadPool));
    if (g_testThreadPool == NULL) {
        TEST_LOG_ERROR("TestPoolInit:Malloc memory failed!memory size:%d\r\n", sizeof(TestCThreadPool));
        return TEST_FAILED;
    }
    (void)memset(g_testThreadPool, 0, sizeof(TestCThreadPool));

    pthread_mutex_init(&(g_testThreadPool->queueLock), NULL);
    pthread_cond_init(&(g_testThreadPool->queueReady), NULL);

    g_testThreadPool->queueHead = NULL;
    g_testThreadPool->maxThreadNum = maxThreadNum;
    g_testThreadPool->curQueueSize = 0;
    g_testThreadPool->shutdown = 0;
    g_testThreadPool->threadid = (pthread_t *)malloc(maxThreadNum * sizeof(pthread_t));

    if (g_testThreadPool->threadid == NULL) {
        TEST_LOG_ERROR("TestPoolInit:Malloc thread  memory failed!memory size:%d\r\n", maxThreadNum * sizeof(pthread_t));
        pthread_mutex_destroy(&(g_testThreadPool->queueLock));
        pthread_cond_destroy(&(g_testThreadPool->queueReady));
        free(g_testThreadPool);
        g_testThreadPool = NULL;
        return TEST_FAILED;
    }
    (void)memset(g_testThreadPool->threadid, 0, maxThreadNum * sizeof(pthread_t));

    for (index = 0; index < maxThreadNum; index++) {
        if (pthread_create(&(g_testThreadPool->threadid[index]), NULL, TestThreadRoutine, NULL) != 0) {
            TestThreadPoolDestroy();
            TEST_LOG_ERROR("TestPoolInit:Create thread failed!");
            return TEST_FAILED;
        }
        char thread_name[MAX_THREAD_NAME_LEN] = {0};
        (void)sprintf(thread_name, "test_thread_%d", index);
        pthread_setname_np(g_testThreadPool->threadid[index], thread_name);
    }

    g_testThreadPool->freeThreadNum = maxThreadNum;

    return TEST_SUCCESS;
}

int TestPoolAddWorker(void *(*process)(void *arg), void *arg)
{
    if (g_testThreadPool == NULL) {
        TEST_LOG_ERROR("TestPoolAddWorker: Thread pool can not init, please init before using!\r\n");
        return TEST_FAILED;
    }

    TestCThreadWorker *newworker = (TestCThreadWorker *)malloc(sizeof(TestCThreadWorker));
    if (newworker == NULL) {
        TEST_LOG_ERROR("TestPoolAddWorker: malloc work memory failed,memory size:%d\r\n", sizeof(TestCThreadWorker));
        return TEST_FAILED;
    }

    newworker->process = process;
    newworker->arg = arg;
    newworker->next = NULL;

    pthread_mutex_lock(&(g_testThreadPool->queueLock));

    TestCThreadWorker *member = g_testThreadPool->queueHead;

    if (member != NULL) {
        while (member->next != NULL) {
            member = member->next;
        }
        member->next = newworker;
    } else {
        g_testThreadPool->queueHead = newworker;
    }

    g_testThreadPool->curQueueSize++;
    pthread_mutex_unlock(&(g_testThreadPool->queueLock));

    pthread_cond_signal(&(g_testThreadPool->queueReady));
    return TEST_SUCCESS;
}

int TestThreadPoolDestroy()
{
    if (g_testThreadPool == NULL) {
        TEST_LOG_ERROR("TestThreadPoolDestroy:Thread Pool can not init,please init it");
        return TEST_FAILED;
    }

    if (g_testThreadPool->shutdown) {
        return TEST_FAILED;
    }

    g_testThreadPool->shutdown = 1;

    pthread_cond_broadcast(&(g_testThreadPool->queueReady));

    int index;

    for (index = 0; index < g_testThreadPool->maxThreadNum; index++) {
        if (g_testThreadPool->threadid[index] != 0) {
            pthread_join(g_testThreadPool->threadid[index], NULL);
        }
    }

    free(g_testThreadPool->threadid);
    g_testThreadPool->threadid = NULL;

    TestCThreadWorker *phead = NULL;

    while (g_testThreadPool->queueHead != NULL) {
        phead = g_testThreadPool->queueHead;
        g_testThreadPool->queueHead = g_testThreadPool->queueHead->next;
        free(phead);
    }
    pthread_mutex_destroy(&(g_testThreadPool->queueLock));
    pthread_cond_destroy(&(g_testThreadPool->queueReady));

    free(g_testThreadPool);

    g_testThreadPool = NULL;
    return TEST_SUCCESS;
}
