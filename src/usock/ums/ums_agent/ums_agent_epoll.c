/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Epoll utility functions for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "ums_agent_log.h"
#include "ums_agent_epoll.h"

static int g_ums_agent_epoll_fd = -1;

int ums_agent_epoll_init(void)
{
    g_ums_agent_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_ums_agent_epoll_fd < 0) {
        UMS_AGENT_LOG_ERR("epoll_create1 failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }
    return 0;
}

void ums_agent_epoll_deinit(void)
{
    if (g_ums_agent_epoll_fd < 0) {
        return;
    }

    (void)close(g_ums_agent_epoll_fd);
    g_ums_agent_epoll_fd = -1;
}

int ums_agent_epoll_add_fd(int fd, uint32_t events)
{
    if (g_ums_agent_epoll_fd < 0 || fd < 0) {
        UMS_AGENT_LOG_ERR("epoll not initialized or invalid fd=%d", fd);
        return -1;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(g_ums_agent_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        UMS_AGENT_LOG_ERR("epoll_ctl ADD fd=%d failed: %s (errno=%d)",
            fd, strerror(errno), errno);
        return -1;
    }
    return 0;
}

int ums_agent_epoll_del_fd(int fd)
{
    if (g_ums_agent_epoll_fd < 0 || fd < 0) {
        UMS_AGENT_LOG_ERR("epoll not initialized or invalid fd=%d", fd);
        return -1;
    }

    if (epoll_ctl(g_ums_agent_epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        UMS_AGENT_LOG_ERR("epoll_ctl DEL fd=%d failed: %s (errno=%d)",
            fd, strerror(errno), errno);
        return -1;
    }
    return 0;
}

int ums_agent_epoll_mod_fd(int fd, uint32_t events)
{
    if (g_ums_agent_epoll_fd < 0 || fd < 0) {
        UMS_AGENT_LOG_ERR("epoll not initialized or invalid fd=%d", fd);
        return -1;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(g_ums_agent_epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        UMS_AGENT_LOG_ERR("epoll_ctl MOD fd=%d failed: %s (errno=%d)",
            fd, strerror(errno), errno);
        return -1;
    }
    return 0;
}

int ums_agent_epoll_wait(struct epoll_event *events, int max_events, int timeout)
{
    if (g_ums_agent_epoll_fd < 0) {
        UMS_AGENT_LOG_ERR("epoll not initialized");
        return -1;
    }

    return epoll_wait(g_ums_agent_epoll_fd, events, max_events, timeout);
}
