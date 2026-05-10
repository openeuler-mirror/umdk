/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Epoll utility functions for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#ifndef UMS_AGENT_EPOLL_H
#define UMS_AGENT_EPOLL_H

#include <stdint.h>
#include <sys/epoll.h>

int ums_agent_epoll_init(void);
void ums_agent_epoll_deinit(void);

int ums_agent_epoll_add_fd(int fd, uint32_t events);
int ums_agent_epoll_del_fd(int fd);
int ums_agent_epoll_mod_fd(int fd, uint32_t events);
int ums_agent_epoll_wait(struct epoll_event *events, int max_events, int timeout);

#endif /* UMS_AGENT_EPOLL_H */
