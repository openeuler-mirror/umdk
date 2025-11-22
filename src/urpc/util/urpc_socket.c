/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc socket function
 * Create: 2024-4-23
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "urpc_framework_errno.h"
#include "util_log.h"

#include "urpc_socket.h"

size_t urpc_socket_recv(int fd, void *buf, size_t size)
{
    char *cur = buf;
    ssize_t done;
    size_t total = size;
    while (total != 0) {
        done = recv(fd, cur, total, MSG_NOSIGNAL);
        /* nonblocking operation is not enabled. If done is 0, the link has been disconnected. */
        if (done <= 0) {
            UTIL_LOG_ERR("get ret:%ld, errno:%d\n", done, errno);
            return 0;
        }
        total -= (size_t)done;
        cur += done;
    }

    return size - total;
}

size_t urpc_socket_send(int fd, void *buf, size_t size)
{
    char *cur = buf;
    ssize_t done;
    size_t total = size;
    while (total != 0) {
        done = send(fd, cur, total, MSG_NOSIGNAL);
        /* nonblocking operation is not enabled. If done is 0, the link has been disconnected. */
        if (done <= 0) {
            UTIL_LOG_ERR("get ret:%ld, errno:%d\n", done, errno);
            return 0;
        }
        total -= (size_t)done;
        cur += done;
    }

    return size - total;
}

int urpc_socket_set_non_block(int fd)
{
    int fd_flags = fcntl(fd, F_GETFL, 0);
    if (fd_flags == -1) {
        return URPC_FAIL;
    }

    return (fcntl(fd, F_SETFL, ((uint32_t)fd_flags) | O_NONBLOCK) == -1) ? URPC_FAIL : URPC_SUCCESS;
}

static int ip_socket_addr_format_ipv4(const char *ip_addr, uint16_t port, socket_addr_t *addr, socklen_t *len)
{
    int ret;
    *len = (socklen_t)sizeof(struct sockaddr_in);
    addr->in.sin_family = AF_INET;
    addr->in.sin_port = htons(port);
    ret = inet_pton(AF_INET, ip_addr, &(addr->in.sin_addr));
    if (ret != 1) {
        UTIL_LOG_ERR("format ip address %s failed\n", ip_addr);
        return -1;
    }
    return 0;
}

static int ip_socket_addr_format_ipv6(const char *ip_addr, uint16_t port, socket_addr_t *addr, socklen_t *len)
{
    int ret;
    *len = (socklen_t)sizeof(struct sockaddr_in6);
    addr->in6.sin6_family = AF_INET6;
    addr->in6.sin6_port = htons(port);
    ret = inet_pton(AF_INET6, ip_addr, &(addr->in6.sin6_addr));
    if (ret != 1) {
        UTIL_LOG_ERR("format ip address %s failed\n", ip_addr);
        return -1;
    }
    return 0;
}

int urpc_socket_bind_assigned_addr(urpc_host_info_t *local, int socket_fd)
{
    int ret;
    socklen_t len;
    socket_addr_t addr = {0};

    const char *ip_addr;
    uint16_t port;
    if (local->host_type == HOST_TYPE_IPV4) {
        ip_addr = local->ipv4.ip_addr;
        port = local->ipv4.port;
        ret = ip_socket_addr_format_ipv4(ip_addr, port, &addr, &len);
    } else {
        ip_addr = local->ipv6.ip_addr;
        port = local->ipv6.port;
        ret = ip_socket_addr_format_ipv6(ip_addr, port, &addr, &len);
    }
    if (ret != 0) {
        return URPC_FAIL;
    }

    if (bind(socket_fd, (struct sockaddr*)&addr, len) < 0) {
        UTIL_LOG_ERR("bind assigned addr failed, ip %s port %d\n", ip_addr, port);
        return URPC_FAIL;
    }
    UTIL_LOG_DEBUG("client bind assigned addr successfully\n");

    return URPC_SUCCESS;
}

int urpc_socket_set_keepalive_timeout(int sockfd, uint32_t keepalive_check_time, uint32_t keepalive_cycle_time)
{
    int flag = 1;
    uint32_t probe_cnt = ((keepalive_check_time / keepalive_cycle_time) - URPC_CTL_SOCKET_IDLE_PROBE_COUNT) == 0
                             ? URPC_CTL_SOCKET_IDLE_PROBE_COUNT
                             : ((keepalive_check_time / keepalive_cycle_time) - URPC_CTL_SOCKET_IDLE_PROBE_COUNT);

    uint32_t first_probe_s = ((keepalive_check_time - probe_cnt * keepalive_cycle_time) == 0)
                                 ? URPC_CTL_SOCKET_IDLE_PROBE_START
                                 : (keepalive_check_time - probe_cnt * keepalive_cycle_time);
    uint32_t probe_interval_s = keepalive_cycle_time;
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) != 0) {
        UTIL_LOG_ERR("Failed to set socket option SO_KEEPALIVE: %s\n", strerror(errno));
        return URPC_FAIL;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &first_probe_s, sizeof(first_probe_s)) != 0) {
        UTIL_LOG_ERR("Failed to set socket option TCP_KEEPIDLE: %s\n", strerror(errno));
        return URPC_FAIL;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &probe_interval_s, sizeof(probe_interval_s)) != 0) {
        UTIL_LOG_ERR("Failed to set socket option TCP_KEEPINTVL: %s\n", strerror(errno));
        return URPC_FAIL;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &probe_cnt, sizeof(probe_cnt)) != 0) {
        UTIL_LOG_ERR("Failed to set socket option TCP_KEEPCNT: %s\n", strerror(errno));
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

int urpc_socket_addr_format(const urpc_host_info_t *server, socket_addr_t *addr, socklen_t *len)
{
    if (server->host_type == HOST_TYPE_IPV4) {
        return ip_socket_addr_format_ipv4(server->ipv4.ip_addr, server->ipv4.port, addr, len);
    }
    return ip_socket_addr_format_ipv6(server->ipv6.ip_addr, server->ipv6.port, addr, len);
}
bool urpc_socket_check_connected(int fd)
{
    int error = 0;
    socklen_t len = (socklen_t)sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        UTIL_LOG_ERR("failed to get sock option SO_ERROR:%s\n", strerror(errno));
        return false;
    }
    if (error != 0) {
        UTIL_LOG_ERR("socket error:%s\n", strerror(error));
        return false;
    }
    return true;
}
