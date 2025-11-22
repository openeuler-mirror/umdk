/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc management thread job
 * Create: 2025-01-14
 */

#include "urpc_framework_errno.h"
#include "util_log.h"
#include "urpc_thread.h"
#include "urpc_util.h"

#include "urpc_manage.h"

// 64 is enough for now
#define URPC_MANAGE_JOB_NUM (64)
#define URPC_MANAGE_EVENT_NUM (64)

typedef struct urpc_manage_job {
    urpc_manage_job_func func;
    void *args;
    uint64_t last_time;
    uint32_t schedule_time_ms;  // 0 means no need to schedule
} urpc_manage_job_t;

typedef struct urpc_manage_jobs {
    const char *name;
    urpc_epoll_event_t *event[URPC_MANAGE_EVENT_NUM];
    urpc_manage_job_t job[URPC_MANAGE_JOB_NUM];
    urpc_cmd_queue_t cmd_queue;
    uint32_t event_num;
    uint32_t job_num;
    int epoll_fd;
    int thread_index;
    pre_thread_start_callback pre_func;
    post_thread_end_callback post_func;
    bool epoll_optional;
    bool cmd_queue_enable;
} urpc_manage_jobs_t;

static urpc_manage_jobs_t g_urpc_manage_job[URPC_MANAGE_JOB_TYPE_NUM] = {
{
    .name = "urpc_listen",
    .epoll_fd = -1,
    .thread_index = -1,
    .epoll_optional = false,
    .cmd_queue_enable = false,
}};

urpc_cmd_queue_t *urpc_manage_get_cmd_queue(urpc_manage_job_type_t type)
{
    if (type < 0 || type >= URPC_MANAGE_JOB_TYPE_NUM) {
        return NULL;
    }

    return &g_urpc_manage_job[type].cmd_queue;
}

void urpc_manage_job_register(urpc_manage_job_type_t type, urpc_manage_job_func func, void *args,
                              uint32_t schedule_time_ms)
{
    if (type >= URPC_MANAGE_JOB_TYPE_NUM || func == NULL || g_urpc_manage_job[type].job_num >= URPC_MANAGE_JOB_NUM) {
        UTIL_LOG_WARN("urpc manage job register failed, type: %d, num: %u\n", (int)type,
                      g_urpc_manage_job[type].job_num);
        return;
    }

    for (uint32_t i = 0; i < g_urpc_manage_job[type].job_num; i++) {
        if (g_urpc_manage_job[type].job[i].func == func) {
            return;
        }
    }

    g_urpc_manage_job[type].job[g_urpc_manage_job[type].job_num].func = func;
    g_urpc_manage_job[type].job[g_urpc_manage_job[type].job_num].args = args;
    g_urpc_manage_job[type].job[g_urpc_manage_job[type].job_num].schedule_time_ms = schedule_time_ms;
    g_urpc_manage_job[type].job_num++;
}

int urpc_mange_event_register(urpc_manage_job_type_t type, urpc_epoll_event_t *event)
{
    if (type >= URPC_MANAGE_JOB_TYPE_NUM || event == NULL) {
        UTIL_LOG_WARN("urpc manage event register failed, type: %d\n", (int)type);
        return URPC_FAIL;
    }
    if (g_urpc_manage_job[type].event_num >= URPC_MANAGE_EVENT_NUM) {
        UTIL_LOG_WARN("urpc manage event register failed, num: %u\n", g_urpc_manage_job[type].event_num);
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < g_urpc_manage_job[type].event_num; i++) {
        if (g_urpc_manage_job[type].event[i] == event) {
            return URPC_SUCCESS;
        }
    }

    g_urpc_manage_job[type].event[g_urpc_manage_job[type].event_num++] = event;
    if (g_urpc_manage_job[type].epoll_fd < 0) {
        return URPC_SUCCESS;
    }

    return urpc_epoll_event_add(g_urpc_manage_job[type].epoll_fd, event);
}

int urpc_mange_event_unregister(urpc_manage_job_type_t type, urpc_epoll_event_t *event)
{
    if (type >= URPC_MANAGE_JOB_TYPE_NUM || event == NULL) {
        UTIL_LOG_WARN("urpc manage event unregister failed, type: %d\n", (int)type);
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < g_urpc_manage_job[type].event_num; i++) {
        if (g_urpc_manage_job[type].event[i] != event) {
            continue;
        }
        if (g_urpc_manage_job[type].epoll_fd > 0) {
            urpc_epoll_event_delete(g_urpc_manage_job[type].epoll_fd, event);
        }
        for (uint32_t j = i; j < g_urpc_manage_job[type].event_num - 1; j++) {
            g_urpc_manage_job[type].event[j] = g_urpc_manage_job[type].event[j + 1];
        }
        g_urpc_manage_job[type].event[g_urpc_manage_job[type].event_num - 1] = NULL;
        g_urpc_manage_job[type].event_num--;
        break;
    }
    return URPC_SUCCESS;
}

static inline void urpc_manage_cmd_queue_job(void *arg)
{
    urpc_manage_jobs_t *manage_jobs = (urpc_manage_jobs_t *)arg;
    urpc_cmd_queue_process(&manage_jobs->cmd_queue);
}

static inline void urpc_manage_epoll_job(void *arg)
{
    urpc_manage_jobs_t *manage_jobs = (urpc_manage_jobs_t *)arg;
    urpc_epoll_event_process(manage_jobs->epoll_fd);
}

static inline void urpc_manage_thread_func(void *arg)
{
    urpc_manage_jobs_t *manage_jobs = (urpc_manage_jobs_t *)arg;
    uint64_t now = urpc_get_cpu_cycles();

    for (uint32_t i = 0; i < manage_jobs->job_num; i++) {
        if (manage_jobs->job[i].schedule_time_ms == 0 ||
            ((now >= manage_jobs->job[i].last_time) && ((now - manage_jobs->job[i].last_time) * MS_PER_SEC >
                                                        manage_jobs->job[i].schedule_time_ms * urpc_get_cpu_hz()))) {
            manage_jobs->job[i].func(manage_jobs->job[i].args);
            manage_jobs->job[i].last_time = now;
        }
    }
}

static inline void urpc_manage_job_reset(urpc_manage_jobs_t *manage_jobs)
{
    urpc_epoll_destroy(manage_jobs->epoll_fd);
    manage_jobs->epoll_fd = -1;
    manage_jobs->thread_index = -1;
    manage_jobs->job_num = 0;
    manage_jobs->event_num = 0;
    manage_jobs->post_func = NULL;
    manage_jobs->pre_func = NULL;
}

static int urpc_manage_job_init(urpc_manage_job_type_t type)
{
    uint32_t i = 0;
    urpc_manage_jobs_t *manage_jobs = &g_urpc_manage_job[type];
    // no need to create thread
    if (manage_jobs->event_num == 0 && manage_jobs->job_num == 0 && manage_jobs->epoll_optional) {
        return URPC_SUCCESS;
    }

    manage_jobs->epoll_fd = urpc_epoll_create();
    if (manage_jobs->epoll_fd < 0) {
        return URPC_FAIL;
    }

    for (; i < manage_jobs->event_num; i++) {
        if (urpc_epoll_event_add(manage_jobs->epoll_fd, manage_jobs->event[i]) != URPC_SUCCESS) {
            goto REMOVE_EVENT;
        }
    }

    if (manage_jobs->event_num > 0 || !manage_jobs->epoll_optional) {
        urpc_manage_job_register(type, urpc_manage_epoll_job, (void *)manage_jobs, 0);
    }

    if (manage_jobs->cmd_queue_enable) {
        urpc_cmd_queue_init(&manage_jobs->cmd_queue);
        urpc_manage_job_register(type, urpc_manage_cmd_queue_job, (void *)manage_jobs, 0);
    }

    urpc_thread_job_t job[URPC_THREAD_JOB_TYPE_NUM] = {
        {
            .type = URPC_THREAD_JOB_TYPE_PRE_JOB,
            .func = manage_jobs->pre_func,
            .args = NULL,
        },
        {
            .type = URPC_THREAD_JOB_TYPE_LOOP_JOB,
            .void_func = urpc_manage_thread_func,
            .args = (void *)manage_jobs,
        },
        {
            .type = URPC_THREAD_JOB_TYPE_POST_JOB,
            .void_func = manage_jobs->post_func,
            .args = NULL,
        }};
    manage_jobs->thread_index = urpc_thread_create(manage_jobs->name, job, URPC_THREAD_JOB_TYPE_NUM);
    if (manage_jobs->thread_index < 0) {
        goto REMOVE_EVENT;
    }

    return URPC_SUCCESS;

REMOVE_EVENT:
    for (uint32_t j = 0; j < i; j++) {
        urpc_epoll_event_delete(manage_jobs->epoll_fd, manage_jobs->event[j]);
    }

    urpc_manage_job_reset(manage_jobs);

    return URPC_FAIL;
}

static void urpc_manage_job_uninit(urpc_manage_job_type_t type)
{
    urpc_manage_jobs_t *manage_jobs = &g_urpc_manage_job[type];
    if (manage_jobs->thread_index == -1) {
        return;
    }

    urpc_thread_destroy(manage_jobs->thread_index);
    if (manage_jobs->cmd_queue_enable) {
        urpc_cmd_queue_flush(&manage_jobs->cmd_queue);
    }

    for (uint32_t i = 0; i < manage_jobs->event_num; i++) {
        urpc_epoll_event_delete(manage_jobs->epoll_fd, manage_jobs->event[i]);
    }

    urpc_manage_job_reset(manage_jobs);
}

int urpc_manage_init(void)
{
    urpc_manage_job_type_t i;
    for (i = URPC_MANAGE_JOB_TYPE_LISTEN; i < URPC_MANAGE_JOB_TYPE_NUM; i++) {
        if (urpc_manage_job_init(i) != URPC_SUCCESS) {
            goto JOB_UNINIT;
        }
    }

    UTIL_LOG_INFO("urpc manage init successful\n");

    return URPC_SUCCESS;

JOB_UNINIT:
    for (urpc_manage_job_type_t j = URPC_MANAGE_JOB_TYPE_LISTEN; j < i; j++) {
        urpc_manage_job_uninit(j);
    }
    return URPC_FAIL;
}

void urpc_manage_uninit(void)
{
    for (urpc_manage_job_type_t i = URPC_MANAGE_JOB_TYPE_LISTEN; i < URPC_MANAGE_JOB_TYPE_NUM; i++) {
        urpc_manage_job_uninit(i);
    }

    UTIL_LOG_INFO("urpc manage uninit successful\n");
}

int urpc_manage_get_epoll_fd(urpc_manage_job_type_t type)
{
    return g_urpc_manage_job[type].epoll_fd;
}

void urpc_manage_cmd_queue_enable(urpc_manage_job_type_t type)
{
    if (type < 0 || type >= URPC_MANAGE_JOB_TYPE_NUM) {
        return;
    }

    g_urpc_manage_job[type].cmd_queue_enable = true;
}

void urpc_manage_callback_register(pre_thread_start_callback pre_func, post_thread_end_callback post_func,
    urpc_manage_job_type_t type)
{
    g_urpc_manage_job[type].pre_func = pre_func;
    g_urpc_manage_job[type].post_func = post_func;
}