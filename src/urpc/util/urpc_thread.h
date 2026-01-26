/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc thread
 * Create: 2025-01-14
 */

#ifndef URPC_THREAD_H
#define URPC_THREAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_THREAD_NAME_SIZE (32)
#define URPC_THREAD_NUM_MAX (256)

typedef enum urpc_thread_state {
    URPC_THREAD_ERROR = (-1),
    URPC_THREAD_INIT,
    URPC_THREAD_RUNNING,
    URPC_THREAD_STOP,
} urpc_thread_state_t;

typedef enum urpc_thread_job_type {
    URPC_THREAD_JOB_TYPE_LOOP_JOB = 0,      // using void function('void_func')
    URPC_THREAD_JOB_TYPE_PRE_JOB,           // using function with int type return value('func')
    URPC_THREAD_JOB_TYPE_POST_JOB,          // using void function('void_func')
    URPC_THREAD_JOB_TYPE_NUM
} urpc_thread_job_type_t;

typedef struct urpc_thread_job {
    urpc_thread_job_type_t type;
    union {
        int (*func)(void *args);
        void (*void_func)(void *args);
    };
    void *args;
} urpc_thread_job_t;

int urpc_thread_ctx_init(void);
void urpc_thread_ctx_uninit(void);

int urpc_thread_index_get(void);
// return thread_index for success, -1 for fail
int urpc_thread_create(const char *thread_name, urpc_thread_job_t *job, uint32_t job_num);
void urpc_thread_destroy(int thread_index);

#ifdef __cplusplus
}
#endif

#endif
