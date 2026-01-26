/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc management thread job
 * Create: 2025-01-14
 */

#ifndef URPC_MANAGEMENT_H
#define URPC_MANAGEMENT_H

#include <stdint.h>

#include "urpc_cmd_queue.h"
#include "urpc_epoll.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_manage_job_type {
    URPC_MANAGE_JOB_TYPE_LISTEN = 0,

    URPC_MANAGE_JOB_TYPE_NUM,
} urpc_manage_job_type_t;

typedef void (*urpc_manage_job_func)(void *args);
typedef int (*pre_thread_start_callback)(void *args);
typedef void (*post_thread_end_callback)(void *args);

// init after other module register jobs
int urpc_manage_init(void);

// uninit before other module destroy event
void urpc_manage_uninit(void);

// only support register job before urpc_manage_init
void urpc_manage_job_register(urpc_manage_job_type_t type, urpc_manage_job_func func, void *args,
                              uint32_t schedule_time_ms);

// event register can be called anytime
int urpc_mange_event_register(urpc_manage_job_type_t type, urpc_epoll_event_t *event);
int urpc_mange_event_unregister(urpc_manage_job_type_t type, urpc_epoll_event_t *event);

int urpc_manage_get_epoll_fd(urpc_manage_job_type_t type);

/* only support to set command queue configuration before urpc_manage_init
 * command queue for manage thread is off by default */
void urpc_manage_cmd_queue_enable(urpc_manage_job_type_t type);
urpc_cmd_queue_t *urpc_manage_get_cmd_queue(urpc_manage_job_type_t type);

// register thread pre/post callback
void urpc_manage_callback_register(
    pre_thread_start_callback pre_func, post_thread_end_callback post_func, urpc_manage_job_type_t type);

#ifdef __cplusplus
}
#endif

#endif
