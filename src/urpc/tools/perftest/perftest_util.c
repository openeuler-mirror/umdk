/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: perftest utils
 * Create: 2024-9-12
 */

#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>

#include "perftest_util.h"

#define PERFTEST_SYN "SYN"
#define PERFTEST_ACK "ACK"
#define PERFTEST_SYNC_MSG_SIZE 32

void signal_handler(int signum)
{
    switch (signum) {
        case SIGINT:
        case SIGTERM:
            perftest_force_quit();
            break;
        default:
            break;
    }
}

void init_signal_handler(void)
{
    if (signal(SIGINT, signal_handler) == SIG_ERR || signal(SIGTERM, signal_handler) == SIG_ERR) {
        LOG_PRINT("init signal failed\n");
    }
}

int recv_data(int sock, uint8_t *recv_data, uint32_t recv_len)
{
    int offset = 0;
    void *recv_buf = recv_data;
    while (1) {
        int len = recv(sock, recv_buf + offset, recv_len - offset, MSG_NOSIGNAL);
        if (len <= 0) {
            LOG_PRINT("receive data failed\n");
            return -1;
        }

        offset += len;
        if (offset == (int)recv_len) {
            break;
        }
    }

    LOG_PRINT("recv data done, len: %d\n", offset);
    return offset;
}

int recv_exchange_data(int sock, exchange_info_t *info)
{
    int offset = 0;
    void *recv_buf = info;
    uint32_t recv_size = (uint32_t)sizeof(exchange_info_t);
    while (1) {
        int len = recv(sock, recv_buf + offset, recv_size - offset, MSG_NOSIGNAL);
        if (len <= 0) {
            LOG_PRINT("receive exchange data failed\n");
            return -1;
        }

        offset += len;
        if (offset == (int)recv_size) {
            break;
        }
    }

    LOG_PRINT("recv exchange data done, len: %u\n", recv_size);
    return 0;
}

int send_exchange_data(int sock, exchange_info_t *info)
{
    int ret = send(sock, info, sizeof(exchange_info_t), 0);
    if (ret != sizeof(exchange_info_t)) {
        LOG_PRINT("send exchange data failed\n");
        return -1;
    }

    LOG_PRINT("send exchange data done, ret: %d\n", ret);
    return 0;
}

int perftest_create_socket(perftest_config_t *cfg, struct sockaddr_storage *addr, socklen_t *addr_len, bool is_server)
{
    int fd = -1;

    // 创建客户端socket
    if (is_ipv4(cfg->local_ip)) {
        fd = socket(AF_INET, (int)SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            LOG_PRINT("create socket failed, %s\n", strerror(errno));
            return -1;
        }

        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = is_server ? htons(cfg->tcp_port) : htons(cfg->tcp_port + 1);
        *addr_len = (socklen_t)sizeof(struct sockaddr_in);
        inet_pton(AF_INET, cfg->local_ip, &addr4->sin_addr);
    } else if (is_ipv6(cfg->local_ip)) {
        fd = socket(AF_INET6, (int)SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            LOG_PRINT("create socket failed, %s\n", strerror(errno));
            return -1;
        }

        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = is_server ? htons(cfg->tcp_port) : htons(cfg->tcp_port + 1);
        *addr_len = (socklen_t)sizeof(struct sockaddr_in6);
        inet_pton(AF_INET6, cfg->local_ip, &addr6->sin6_addr);
    } else {
        LOG_PRINT("ip[%s] format error\n", cfg->local_ip);
        return -1;
    }

    return fd;
}

bool perftest_get_remote_sockaddr(perftest_config_t *cfg, struct sockaddr_storage *addr, socklen_t *addr_len)
{
    if (is_ipv4(cfg->remote_ip)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(cfg->tcp_port);
        *addr_len = (socklen_t)sizeof(struct sockaddr_in);
        inet_pton(AF_INET, cfg->remote_ip, &addr4->sin_addr);
    } else if (is_ipv6(cfg->remote_ip)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(cfg->tcp_port);
        *addr_len = (socklen_t)sizeof(struct sockaddr_in6);
        inet_pton(AF_INET6, cfg->remote_ip, &addr6->sin6_addr);
    } else {
        LOG_PRINT("ip[%s] format error\n", cfg->remote_ip);
        return false;
    }

    return true;
}

int perftest_create_server_socket(perftest_config_t *cfg)
{
    struct sockaddr_storage addr = {0};
    socklen_t addr_len = {0};
    int fd = perftest_create_socket(cfg, &addr, &addr_len, true);

    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) != 0) {
        LOG_PRINT("set socket reuseport failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    // set accept non-block
    int fd_flags = fcntl(fd, F_GETFL, 0);
    if (fd_flags == -1) {
        LOG_PRINT("get socket fcntl flags failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    if (fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK) == -1) {
        LOG_PRINT("set socket non-bolck failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    if (bind(fd, (struct sockaddr *)(void *)&addr, addr_len) < 0) {
        LOG_PRINT("bind socket failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    if (listen(fd, 1) < 0) {
        LOG_PRINT("listen socket failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    return fd;

CLOSE_LISTEN_FD:
    (void)close(fd);

    return -1;
}

int perftest_create_client_socket(perftest_config_t *cfg)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int fd = perftest_create_socket(cfg, &addr, &addr_len, false);
    if (!perftest_get_remote_sockaddr(cfg, &addr, &addr_len)) {
        LOG_PRINT("get remote socket failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }
    if (connect(fd, (struct sockaddr *)&addr, addr_len) < 0) {
        LOG_PRINT("connect to server failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    return fd;

CLOSE_FD:
    (void)close(fd);

    return -1;
}

int perftest_server_do_accept(perftest_config_t *cfg, int fd, volatile bool *force_quit)
{
    struct sockaddr_in addr;
    socklen_t len = (socklen_t)sizeof(addr);
    int accept_fd = -1;

    do {
        accept_fd = accept(fd, (struct sockaddr *)(void *)&addr, &len);
        if (accept_fd >= 0) {
            break;
        }

        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            LOG_PRINT("accept socket failed, %s\n", strerror(errno));
            break;
        }

        usleep(URPC_PERFTEST_ACCEPT_WAIT_US);
    } while (!*force_quit);

    return accept_fd;
}

// client send "sync" and wait for "ack"
int perftest_client_sync(int fd)
{
    char msg[PERFTEST_SYNC_MSG_SIZE] = {0};
    int msg_len = send(fd, PERFTEST_SYN, strlen(PERFTEST_SYN), MSG_NOSIGNAL);
    if (msg_len != (int)strlen(PERFTEST_SYN)) {
        LOG_PRINT("send syn failed, %s\n", strerror(errno));
        return -1;
    }

    msg_len = recv_data(fd, (uint8_t *)msg, strlen(PERFTEST_ACK));
    if (msg_len != (int)strlen(PERFTEST_ACK) || memcmp(msg, PERFTEST_ACK, (size_t)msg_len) != 0) {
        LOG_PRINT("recv ack failed, msg %s, %s\n", msg, strerror(errno));
        return -1;
    }

    LOG_PRINT("client sync success\n");
    return 0;
}

// server wait for "sync" and send "ack"
int perftest_server_sync(int fd)
{
    char msg[PERFTEST_SYNC_MSG_SIZE] = {0};
    int msg_len = recv_data(fd, (uint8_t *)msg, strlen(PERFTEST_SYN));
    if (msg_len != (int)strlen(PERFTEST_SYN) || memcmp(msg, PERFTEST_SYN, (size_t)msg_len) != 0) {
        LOG_PRINT("recv syn failed, %s\n", strerror(errno));
        return -1;
    }

    msg_len = send(fd, PERFTEST_ACK, strlen(PERFTEST_ACK), MSG_NOSIGNAL);
    if (msg_len != (int)strlen(PERFTEST_ACK)) {
        LOG_PRINT("send ack failed, %s\n", strerror(errno));
        return -1;
    } else {
        LOG_PRINT("server sync success\n");
    }

    return 0;
}