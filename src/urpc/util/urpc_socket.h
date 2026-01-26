/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc socket function
 * Create: 2024-4-23
 */

#ifndef URPC_SOCKET_H
#define URPC_SOCKET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "urpc_framework_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_CTL_SOCKET_IDLE_PROBE_START        1
#define URPC_CTL_SOCKET_IDLE_PROBE_COUNT        1

typedef union {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} socket_addr_t;

typedef struct urpc_host_info_inner {
    urpc_host_type_t host_type;
    union {
        struct {
            struct in_addr sin_addr;
            uint16_t port;
        } ipv4;
        struct {
            struct in6_addr sin6_addr;
            uint16_t port;
        } ipv6;
        struct {
            urpc_eid_t eid;
        } ub;
    };
} urpc_host_info_inner_t;

typedef struct urpc_endpoints {
    urpc_host_info_t server;
    urpc_host_info_t local;
    uint8_t bind_local : 1;
    uint8_t rsvd : 7;
    uint8_t version;
} urpc_endpoints_t;

// Receive data from socket, return the actual size of successfully received data.
size_t urpc_socket_recv(int fd, void *buf, size_t size);

// when successful, the actual number of bytes recv is returned; when failed, -1 is returned.
static inline ssize_t urpc_socket_recv_async(int fd, void *buf, size_t size)
{
    return recv(fd, buf, size, MSG_NOSIGNAL);
}

// Send data by socket, return the actual size of successfully sent data.
size_t urpc_socket_send(int fd, void *buf, size_t size);

// when successful, the actual number of bytes sent is returned; when failed, -1 is returned.
static inline ssize_t urpc_socket_send_async(int fd, void *buf, size_t size)
{
    return send(fd, buf, size, MSG_NOSIGNAL);
}

int urpc_socket_set_non_block(int fd);
int urpc_socket_bind_assigned_addr(urpc_host_info_t *local, int socket_fd);
int urpc_socket_set_keepalive_timeout(int sockfd, uint32_t keepalive_check_time, uint32_t keepalive_cycle_time);
int urpc_socket_addr_format(const urpc_host_info_t *server, socket_addr_t *addr, socklen_t *len);
bool urpc_socket_check_connected(int fd);

#ifdef __cplusplus
}
#endif

#endif