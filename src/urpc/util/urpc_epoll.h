/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc epoll task definition
 * Create: 2024-4-17
 */

#ifndef URPC_EPOLL_H
#define URPC_EPOLL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

struct urpc_epoll_event;
typedef void (*urpc_epoll_event_func_t)(uint32_t events, struct urpc_epoll_event *e);
typedef struct urpc_epoll_event {
    int fd;
    void *args;
    urpc_epoll_event_func_t func;
    uint32_t events;
    bool is_handshaker_ctx;
} urpc_epoll_event_t;

int urpc_epoll_create(void);
void urpc_epoll_destroy(int epoll_fd);

int urpc_epoll_event_add(int epoll_fd, urpc_epoll_event_t *event);
int urpc_epoll_event_modify(int epoll_fd, urpc_epoll_event_t *event);
void urpc_epoll_event_delete(int epoll_fd, urpc_epoll_event_t *event);
void urpc_epoll_event_process(int epoll_fd);

#ifdef __cplusplus
}
#endif

#endif