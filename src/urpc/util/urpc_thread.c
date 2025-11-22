/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc thread
 * Create: 2025-01-14
 */

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "urpc_framework_errno.h"
#include "urpc_id_generator.h"
#include "util_log.h"
#include "urpc_util.h"

#include "urpc_thread.h"

#define URPC_THREAD_BUSY_WAIT_US 1

typedef struct urpc_thread_param {
    char name[URPC_THREAD_NAME_SIZE];
    urpc_thread_job_t pre_job;
    urpc_thread_job_t loop_job;
    urpc_thread_job_t post_job;
    pthread_t thread;
    int id;
    volatile urpc_thread_state_t state;
} urpc_thread_param_t;

static struct {
    urpc_thread_param_t thread_param[URPC_THREAD_NUM_MAX];
    urpc_id_generator_t id_generator;
} g_urpc_thread_a_ctx;

// -1 means not urpc thread
static __thread int g_urpc_thread_index = -1;

int urpc_thread_index_get(void)
{
    return g_urpc_thread_index;
}

static inline int urpc_thread_index_alloc(void)
{
    uint32_t id = 0;
    if (urpc_id_generator_alloc(&g_urpc_thread_a_ctx.id_generator, 0, &id) != 0) {
        UTIL_LOG_ERR("urpc thread num exceeds max %d\n", URPC_THREAD_NUM_MAX);
        return -1;
    }

    return (int)id;
}

static inline void urpc_thread_index_free(int id)
{
    if (id < 0 || id >= URPC_THREAD_NUM_MAX) {
        return;
    }

    urpc_id_generator_free(&g_urpc_thread_a_ctx.id_generator, (uint32_t)id);
}

static void *urpc_thread_job_func(void *arg)
{
    pthread_t pid = pthread_self();
    urpc_thread_param_t *param = (urpc_thread_param_t *)arg;
    if (pthread_setname_np(pid, param->name) != 0) {
        param->state = URPC_THREAD_ERROR;
        UTIL_LOG_ERR("set thread name %s failed\n", param->name);
        return NULL;
    }

    g_urpc_thread_index = param->id;
    if (param->pre_job.func != NULL &&
        param->pre_job.func(param->pre_job.args) != URPC_SUCCESS) {
        param->state = URPC_THREAD_ERROR;
        UTIL_LOG_ERR("execute thread pre job failed\n");
        return NULL;
    }

    param->state = URPC_THREAD_RUNNING;

    while (param->state == URPC_THREAD_RUNNING) {
        param->loop_job.void_func(param->loop_job.args);
    }

    param->state = URPC_THREAD_STOP;

    if (param->post_job.void_func != NULL) {
        param->post_job.void_func(param->post_job.args);
    }

    return NULL;
}

static inline void urpc_thread_clear_job(urpc_thread_param_t *param)
{
    param->pre_job.func = NULL;
    param->pre_job.args = NULL;
    param->loop_job.void_func = NULL;
    param->loop_job.args = NULL;
    param->post_job.void_func = NULL;
    param->post_job.args = NULL;
}

int urpc_thread_create(const char *thread_name, urpc_thread_job_t *job, uint32_t job_num)
{
    if (job == NULL || job_num == 0) {
        UTIL_LOG_ERR("invalid arguments, thread job must be configured\n");
        return -URPC_ERR_EINVAL;
    }

    int thread_index = urpc_thread_index_alloc();
    if (thread_index < 0) {
        return URPC_FAIL;
    }

    urpc_thread_param_t *param = &g_urpc_thread_a_ctx.thread_param[thread_index];
    int ret;
    if (thread_name == NULL) {
        ret = snprintf(param->name, URPC_THREAD_NAME_SIZE, "urpc_thread_%d", thread_index);
    } else {
        ret = snprintf(param->name, URPC_THREAD_NAME_SIZE, "%s", thread_name);
    }
    if (ret < 0) {
        UTIL_LOG_ERR("urpc thread name copy failed, ret: %d\n", ret);
        goto THREAD_INDEX_FREE;
    }

    for (uint32_t i = 0; i < job_num; i++) {
        switch (job[i].type) {
            case URPC_THREAD_JOB_TYPE_LOOP_JOB:
                param->loop_job = job[i];
                break;
            case URPC_THREAD_JOB_TYPE_PRE_JOB:
                param->pre_job = job[i];
                break;
            case URPC_THREAD_JOB_TYPE_POST_JOB:
                param->post_job = job[i];
                break;
            default:
                UTIL_LOG_ERR("unsupport thread job type: %d\n", job[i].type);
                goto THREAD_INDEX_FREE;
        }
    }
    param->id = thread_index;
    param->state = URPC_THREAD_INIT;

    if (pthread_create(&param->thread, NULL, urpc_thread_job_func, (void *)param) != 0) {
        UTIL_LOG_ERR("urpc thread create failed, %s\n", strerror(errno));
        goto THREAD_INDEX_FREE;
    }

    while (param->state == URPC_THREAD_INIT) {
        (void)usleep(URPC_THREAD_BUSY_WAIT_US);
    }

    if (param->state == URPC_THREAD_RUNNING) {
        UTIL_LOG_INFO("urpc thread %s create successful, thread_index: %d\n", param->name, thread_index);
        return thread_index;
    }

    (void)pthread_join(param->thread, NULL);

THREAD_INDEX_FREE:
    urpc_thread_index_free(param->id);
    urpc_thread_clear_job(param);
    param->id = -1;
    param->state = URPC_THREAD_INIT;

    return URPC_FAIL;
}

void urpc_thread_destroy(int thread_index)
{
    if (thread_index < 0 || thread_index >= URPC_THREAD_NUM_MAX ||
        g_urpc_thread_a_ctx.thread_param[thread_index].id == -1) {
        UTIL_LOG_ERR("urpc thread: %d not found\n", thread_index);
        return;
    }

    urpc_thread_param_t *param = &g_urpc_thread_a_ctx.thread_param[thread_index];
    param->state = URPC_THREAD_STOP;
    (void)pthread_join(param->thread, NULL);

    urpc_thread_index_free(param->id);
    urpc_thread_clear_job(param);
    param->id = -1;
    param->state = URPC_THREAD_INIT;

    UTIL_LOG_INFO("urpc thread %s destroy successful, thread_index: %d\n", param->name, thread_index);
}

int urpc_thread_ctx_init(void)
{
    int ret =
        urpc_id_generator_init(&g_urpc_thread_a_ctx.id_generator, URPC_ID_GENERATOR_TYPE_BITMAP, URPC_THREAD_NUM_MAX);
    if (ret != 0) {
        UTIL_LOG_ERR("urpc thread id generator init failed, ret: %d\n", ret);
        return URPC_FAIL;
    }

    urpc_thread_param_t *param;
    for (int i = 0; i < URPC_THREAD_NUM_MAX; i++) {
        param = &g_urpc_thread_a_ctx.thread_param[i];
        urpc_thread_clear_job(param);
        param->id = -1;
        param->state = URPC_THREAD_INIT;
    }

    UTIL_LOG_INFO("urpc_thread_ctx init successful\n");

    return URPC_SUCCESS;
}

void urpc_thread_ctx_uninit(void)
{
    urpc_thread_param_t *param;
    for (int i = 0; i < URPC_THREAD_NUM_MAX; i++) {
        param = &g_urpc_thread_a_ctx.thread_param[i];
        if (param->id == -1) {
            continue;
        }

        urpc_thread_destroy(param->id);
    }

    urpc_id_generator_uninit(&g_urpc_thread_a_ctx.id_generator);

    UTIL_LOG_INFO("urpc_thread_ctx uninit successful\n");
}
