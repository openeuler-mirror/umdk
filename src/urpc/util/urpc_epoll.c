/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc epoll task realization
 * Create: 2024-4-17
 */

#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "urpc_framework_errno.h"
#include "util_log.h"

#include "urpc_epoll.h"

#define MAX_EPOLL_FD_NUM 2048
#define MAX_EPOLL_EVENT_NUM 32
#define MAX_EPOLL_WAIT_MS 10

int urpc_epoll_create(void)
{
    int epoll_fd = epoll_create(MAX_EPOLL_FD_NUM);
    if (epoll_fd < 0) {
        UTIL_LOG_ERR("create epoll fd failed, %s\n", strerror(errno));
        return -1;
    }

    return epoll_fd;
}

void urpc_epoll_destroy(int epoll_fd)
{
    if (epoll_fd < 0) {
        return;
    }

    (void)close(epoll_fd);
}

int urpc_epoll_event_add(int epoll_fd, urpc_epoll_event_t *event)
{
    if (epoll_fd < 0 || event == NULL) {
        UTIL_LOG_ERR("epoll control not ready\n");
        return URPC_FAIL;
    }

    struct epoll_event ev = {0};
    ev.events = event->events;
    ev.data.ptr = event;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event->fd, &ev) != 0) {
        UTIL_LOG_ERR("epoll control add event failed, %s\n", strerror(errno));
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

int urpc_epoll_event_modify(int epoll_fd, urpc_epoll_event_t *event)
{
    struct epoll_event ev = {0};
    ev.events = event->events;
    ev.data.ptr = event;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, event->fd, &ev);
}

void urpc_epoll_event_delete(int epoll_fd, urpc_epoll_event_t *event)
{
    if (epoll_fd < 0 || event == NULL) {
        UTIL_LOG_ERR("epoll control delete event failed:%s\n", strerror(errno));
        return;
    }

    (void)epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event->fd, NULL);
}

static bool is_consume_ctx(void *consum_ctx[], int num, const void* target)
{
    for (int i = 0; i < num; i++) {
        if (consum_ctx[i] == target) {
            return true;
        }
    }
    return false;
}

void urpc_epoll_event_process(int epoll_fd)
{
    urpc_epoll_event_t *e;
    struct epoll_event events[MAX_EPOLL_EVENT_NUM];
    int ev_num = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENT_NUM, MAX_EPOLL_WAIT_MS);
    if (ev_num == -1) {
        return;
    }
    void *consum_ctx[MAX_EPOLL_EVENT_NUM] = {0};
    int index = 0;
    for (int i = 0; i < ev_num; i++) {
        e = (urpc_epoll_event_t *)events[i].data.ptr;
        if (e->func != NULL) {
            if (e->is_handshaker_ctx) {
                if (is_consume_ctx(consum_ctx, index, e->args)) {
                    continue;
                } else {
                    consum_ctx[index++] = e->args;
                }
            }
            e->func(events[i].events, e);
        }
    }
}
