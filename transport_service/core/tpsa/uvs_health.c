/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: check Whether the uvs thread is processing events
 * Author: Liwenhao
 * Create: 2024-2-20
 * Note:
 * History:
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "tpsa_log.h"
#include "uvs_event.h"
#include "uvs_health.h"

#define HEALTH_CHECK_INTERVAL 60
#define HEALTH_CHECK_EACH_INTERVAL 1

struct uvs_worker_status {
    bool is_last_active;
    bool is_cur_active;
};

struct uvs_health_check_thread {
    pthread_t thread;
    bool stop;
    struct uvs_worker_status status;
};

static uint64_t g_last_event_time = 0;
struct uvs_health_check_thread g_health_thread;

static uint64_t get_cur_time(void)
{
    struct timespec time;
    (void)clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)(time.tv_sec);
}

static void process_event(struct uvs_health_check_thread *uvs_health_thread)
{
    uint64_t cur_time = get_cur_time();
    uvs_health_thread->status.is_last_active = uvs_health_thread->status.is_cur_active;
    if (cur_time > g_last_event_time + HEALTH_CHECK_INTERVAL) {
        uvs_health_thread->status.is_cur_active = false;
        struct uvs_event hang_event = {
            .type = UVS_EVENT_HANG
        };
        if (uvs_event_execute_cb(&hang_event) != 0) {
            goto next_round;
        }
    } else {
        uvs_health_thread->status.is_cur_active = true;
        if (uvs_health_thread->status.is_last_active == false) {
            struct uvs_event resume_event = {
                .type = UVS_EVENT_RESUME
            };
            if (uvs_event_execute_cb(&resume_event) != 0) {
                goto next_round;
            }
        }
    }
next_round:
    for (int i = 0; i < HEALTH_CHECK_INTERVAL; i++) {
        if (g_health_thread.stop == true) {
            break;
        }
        (void)sleep(HEALTH_CHECK_EACH_INTERVAL);
    }
}

static void *uvs_health_run(void *args)
{
    TPSA_LOG_INFO("health check thread init start\n");
    (void)pthread_setname_np(pthread_self(), (const char *)"health_check");
    while (g_health_thread.stop == false) {
        process_event(&g_health_thread);
    }
    TPSA_LOG_INFO("health check thread exited.\n");
    return NULL;
}

int uvs_health_check_service_init(void)
{
    int ret;
    g_health_thread.status.is_cur_active = true;
    g_health_thread.stop = false;
    ret = pthread_create(&g_health_thread.thread, NULL, uvs_health_run, NULL);
    if (ret != 0) {
        TPSA_LOG_ERR("fail to init uvs health check service, res: %d\n", ret);
    }
    return ret;
}

void uvs_health_check_service_uninit(void)
{
    g_health_thread.stop = true;
    if (g_health_thread.thread != 0) {
        (void)pthread_join(g_health_thread.thread, NULL);
    }
}

void uvs_health_update_event_time(void)
{
    g_last_event_time = get_cur_time();
}