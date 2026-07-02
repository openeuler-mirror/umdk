/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: communication for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "perftest_parameters.h"

#include "perftest_communication.h"

typedef struct comm_tcp_ctx {
    int listen_fd;
    int *sock_fd;
    uint32_t sock_num;
} comm_tcp_ctx_t;

static comm_tcp_ctx_t comm_ctx = {
    .listen_fd = -1,
    .sock_fd = NULL,
    .sock_num = 0,
};

static int get_sock_fd(const perftest_config_t *cfg, uint32_t index)
{
    if (cfg == NULL || comm_ctx.sock_fd == NULL || index >= comm_ctx.sock_num) {
        errno = EINVAL;
        return -1;
    }
    return comm_ctx.sock_fd[index];
}

static int send_all(int sock_fd, const char *buf, int size)
{
    ssize_t send_bytes;
    int total_send_bytes = 0;

    while (total_send_bytes < size) {
        send_bytes = send(sock_fd, buf + total_send_bytes, (size_t)(size - total_send_bytes), MSG_NOSIGNAL);
        if (send_bytes <= 0) {
            if (send_bytes < 0 && errno == EINTR) {
                continue;
            }
            LOG_ERROR("Failed to send data, errno: [%d]%s, total_size:%d, expect_size:%d.\n",
                      errno, strerror(errno), total_send_bytes, size);
            return -1;
        }
        total_send_bytes += (int)send_bytes;
    }

    return 0;
}

static int recv_all(int sock_fd, char *buf, int size)
{
    ssize_t recv_bytes;
    int total_recv_bytes = 0;

    while (total_recv_bytes < size) {
        recv_bytes = recv(sock_fd, buf + total_recv_bytes, (size_t)(size - total_recv_bytes), 0);
        if (recv_bytes == 0) {
            LOG_ERROR("Peer closed connection, total_size:%d, expect_size:%d.\n", total_recv_bytes, size);
            return -1;
        }
        if (recv_bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("Failed to recv data, errno: [%d]%s, total_size:%d, expect_size:%d.\n",
                      errno, strerror(errno), total_recv_bytes, size);
            return -1;
        }
        total_recv_bytes += (int)recv_bytes;
    }

    return 0;
}

static int alloc_comm_sock(uint32_t sock_num)
{
    if (comm_ctx.listen_fd >= 0 || comm_ctx.sock_fd != NULL) {
        errno = EBUSY;
        return -1;
    }

    comm_ctx.listen_fd = -1;
    comm_ctx.sock_fd = (int *)calloc(sock_num, sizeof(int));
    if (comm_ctx.sock_fd == NULL) {
        comm_ctx.sock_num = 0;
        return -1;
    }

    comm_ctx.sock_num = sock_num;
    for (uint32_t i = 0; i < sock_num; i++) {
        comm_ctx.sock_fd[i] = -1;
    }
    return 0;
}

static void cleanup_comm_ctx(void)
{
    if (comm_ctx.listen_fd >= 0) {
        (void)close(comm_ctx.listen_fd);
        comm_ctx.listen_fd = -1;
    }
    if (comm_ctx.sock_fd != NULL) {
        for (uint32_t i = 0; i < comm_ctx.sock_num; i++) {
            if (comm_ctx.sock_fd[i] >= 0) {
                (void)close(comm_ctx.sock_fd[i]);
                comm_ctx.sock_fd[i] = -1;
            }
        }
        free(comm_ctx.sock_fd);
    }
    comm_ctx.listen_fd = -1;
    comm_ctx.sock_fd = NULL;
    comm_ctx.sock_num = 0;
}

static int ip_set_sockopts(int sockfd)
{
    int ret;
    int enable_reuse = 1;
    int enable_nodelay = 1;

    /* Set socket reuse. When the server is restarted,
     * the problem of the connection failure of the client is solved */
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
    if (ret < 0) {
        LOG_ERROR("socket set_opt failed. enable_reuse:%d, ret: %d, err: [%d]%s.\n",
                  SO_REUSEPORT, ret, errno, strerror(errno));
        return ret;
    }

    // Close Nagle algorithm, and fix 42ms delay problem.
    ret = setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &enable_nodelay, sizeof(enable_nodelay));
    if (ret < 0) {
        LOG_ERROR("socket set_opt failed. opt:%d, ret: %d, err: [%d]%s.\n",
                  TCP_NODELAY, ret, errno, strerror(errno));
        return ret;
    }

    return 0;
}

#define PERFTEST_PORT_LEN_MAX 32
static int check_add_port(int port, const char *server_ip, struct addrinfo *hints, struct addrinfo **res)
{
    int num;
    char service[PERFTEST_PORT_LEN_MAX] = {0};

    if (port < 0 || port > UINT16_MAX) {
        LOG_ERROR("Invalid port: %d.\n", port);
        return -1;
    }

    if (snprintf(service, sizeof(service), "%d", port) <= 0) {
        return -1;
    }

    num = getaddrinfo(server_ip, service, hints, res);
    if (num < 0) {
        LOG_ERROR("%s for %s:%d\n", gai_strerror(num), server_ip, port);
        return -1;
    }

    return 0;
}

static int connect_retry(int sockfd, struct sockaddr *addr, uint32_t size)
{
    uint32_t times = 0;
    for (int i = 1; i <= PERFTEST_CONNECT_COUNT; i++) {
        if (connect(sockfd, addr, size) != 0) {
            times += i * (uint32_t)ERFTEST_SLEEP_TIME;
            (void)usleep(times);
            continue;
        }
        return 0;
    }
    return -1;
}

static int client_connect(perftest_config_t *cfg)
{
    struct addrinfo *res = NULL, *tmp = NULL, *client_res = NULL, *client_tmp = NULL;
    struct addrinfo hints = {0}, client_hints = {0};
    uint32_t i = 0;

    perftest_comm_t *comm = &cfg->comm;
    if (alloc_comm_sock(cfg->pair_num) != 0) {
        return -1;
    }
    hints.ai_family = comm->enable_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (comm->bind_ip != NULL) {
        int err, bound = 0;
        client_hints.ai_family = hints.ai_family;
        client_hints.ai_socktype = SOCK_STREAM;
        err = getaddrinfo(comm->bind_ip, NULL, &client_hints, &client_res);
        if (err != 0) {
            LOG_ERROR("Problem in resolving bind IP '%s': %s\n",
                      comm->bind_ip, gai_strerror(err));
            goto bind_client_error;
        }
        for (client_tmp = client_res; client_tmp != NULL; client_tmp = client_tmp->ai_next) {
            if (client_tmp->ai_family == hints.ai_family) {
                bound = 1;
                break;
            }
        }
        if (!bound) {
            LOG_ERROR("Bind IP not found : %s\n", comm->bind_ip);
            goto create_client_error;
        }
    }

    for (i = 0; i < cfg->pair_num; i++) {
        if (check_add_port((comm->port + i), comm->server_ip, &hints, &res)) {
            LOG_ERROR("Problem in resolving basic address and port\n");
            goto create_client_error;
        }

        for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
            bool try_connect = true;
            comm_ctx.sock_fd[i] = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
            if (comm_ctx.sock_fd[i] < 0) {
                continue;
            }
            if (comm->bind_ip != NULL) {
                if (bind(comm_ctx.sock_fd[i], client_tmp->ai_addr, client_tmp->ai_addrlen) != 0) {
                    try_connect = false;
                    LOG_ERROR("Failed to bind ip: %s\n", comm->bind_ip);
                }
            }
            if (try_connect && connect_retry(comm_ctx.sock_fd[i], tmp->ai_addr, tmp->ai_addrlen) == 0) {
                break;
            }
            close(comm_ctx.sock_fd[i]);
            comm_ctx.sock_fd[i] = -1;
        }

        if (res != NULL) {
            freeaddrinfo(res);
            res = NULL;
        }

        if (comm_ctx.sock_fd[i] < 0) {
            LOG_ERROR("Failed to connect %s:%d\n\n", comm->server_ip, (comm->port + i));
            goto create_client_error;
        }

        if (ip_set_sockopts(comm_ctx.sock_fd[i]) != 0) {
            LOG_ERROR("Failed to set_sockopts, sockfd:%d, errno: %s\n", comm_ctx.sock_fd[i], strerror(errno));
            (void)close(comm_ctx.sock_fd[i]);
            comm_ctx.sock_fd[i] = -1;
            goto create_client_error;
        }
    }

    if (comm->bind_ip != NULL) {
        if (client_res != NULL) {
            freeaddrinfo(client_res);
        }
    }

    return 0;
create_client_error:
    cleanup_comm_ctx();
    if (client_res != NULL) {
        freeaddrinfo(client_res);
    }
    return -1;
bind_client_error:
    cleanup_comm_ctx();
    return -1;
}

static int server_connect(perftest_config_t *cfg)
{
    struct addrinfo *res = NULL, *tmp = NULL;
    struct addrinfo hints = {0};
    uint32_t accept_num = 0;

    perftest_comm_t *comm = &cfg->comm;
    comm->server_ip = NULL;
    if (alloc_comm_sock(cfg->pair_num) != 0) {
        return -1;
    }
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = comm->enable_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (check_add_port(comm->port, comm->bind_ip, &hints, &res)) {
        LOG_ERROR("Problem in resolving basic address and port\n");
        goto free_sock;
    }

    for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
        if (tmp->ai_family != hints.ai_family) {
            continue;
        }

        comm_ctx.listen_fd = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
        if (comm_ctx.listen_fd >= 0) {
            if (ip_set_sockopts(comm_ctx.listen_fd) != 0) {
                LOG_ERROR("Failed to set_sockopts, sockfd:%d, errno: %s\n",
                          comm_ctx.listen_fd, strerror(errno));
                goto free_res;
            }
            if (bind(comm_ctx.listen_fd, tmp->ai_addr, tmp->ai_addrlen) == 0) {
                break;
            }
            (void)close(comm_ctx.listen_fd);
            comm_ctx.listen_fd = -1;
        }
    }

    if (comm_ctx.listen_fd < 0) {
        LOG_ERROR("Failed to bind, port:%d.\n", comm->port);
        goto free_res;
    }

    if (listen(comm_ctx.listen_fd, PERFTEST_MAX_CONNECTIONS) != 0) {
        LOG_ERROR("Failed to listen, listenfd:%d, errno: [%d]%s\n",
                  comm_ctx.listen_fd, errno, strerror(errno));
        goto free_res;
    }

    while (accept_num < cfg->pair_num) {
        comm_ctx.sock_fd[accept_num] = accept(comm_ctx.listen_fd, NULL, 0);
        if (comm_ctx.sock_fd[accept_num] < 0) {
            LOG_ERROR("Failed to accept, listenfd:%d, errno: [%d]%s\n",
                      comm_ctx.listen_fd, errno, strerror(errno));
            goto free_res;
        }

        if (ip_set_sockopts(comm_ctx.sock_fd[accept_num]) != 0) {
            LOG_ERROR("Failed to set_sockopts, sockfd:%d, errno: [%d]%s\n",
                      comm_ctx.sock_fd[accept_num], errno, strerror(errno));
            (void)close(comm_ctx.sock_fd[accept_num]);
            comm_ctx.sock_fd[accept_num] = -1;
            goto free_res;
        }
        accept_num++;
    }

    freeaddrinfo(res);
    (void)close(comm_ctx.listen_fd); // No other connections need to be accepted.
    comm_ctx.listen_fd = -1;
    return 0;

free_res:
    if (res != NULL) {
        freeaddrinfo(res);
    }
free_sock:
    cleanup_comm_ctx();
    return -1;
}

int establish_connection(perftest_config_t *cfg)
{
    int ret;

    if (cfg->comm.server_ip != NULL) {
        /* client side */
        ret = client_connect(cfg);
    } else {
        /* server side */
        LOG_INFO(PERFTEST_RESULT_LINE);
        LOG_INFO("                           Waiting for client to connect...\n");
        ret = server_connect(cfg);
    }

    return ret;
}

void close_connection(perftest_config_t *cfg)
{
    perftest_comm_t *comm = &cfg->comm;

    cleanup_comm_ctx();
    free(comm->server_ip);
    comm->server_ip = NULL;
    if (comm->bind_ip) {
        free(comm->bind_ip);
        comm->bind_ip = NULL;
    }
}

int sync_data(const perftest_config_t *cfg, uint32_t index, int size, char *local_data, char *remote_data)
{
    int sock_fd = get_sock_fd(cfg, index);
    if (sock_fd < 0) {
        return -1;
    }

    if (send_all(sock_fd, local_data, size) != 0) {
        LOG_ERROR("Failed to send data during sync_data.\n");
        return -1;
    }

    if (recv_all(sock_fd, remote_data, size) != 0) {
        LOG_ERROR("Failed to recv data during sync_data.\n");
        return -1;
    }

    return 0;
}

int sync_time(const perftest_config_t *cfg, uint32_t index, const char *a)
{
    if (a == NULL) {
        LOG_ERROR("Invalid parameter with a nullptr.\n");
        return -1;
    }
    int len = (int)strlen(a);
    char *b = calloc(1, (unsigned long)len + 1);
    int ret = 0;
    if (b == NULL) {
        return -ENOMEM;
    }
    ret = sync_data(cfg, index, len, (char *)a, b);
    if (ret != 0) {
        LOG_ERROR("sync time error, %s, ret: %d.\n", a, ret);
        goto sync_ret;
    }
    ret = memcmp(a, b, (unsigned long)len);
    if (ret != 0) {
        b[len] = '\0';
        LOG_ERROR("sync time error, %s != %s.\n", a, b);
        goto sync_ret;
    }

sync_ret:
    free(b);
    return ret;
}

ssize_t comm_send(const perftest_config_t *cfg, uint32_t index, const void *buf, size_t size)
{
    int sock_fd = get_sock_fd(cfg, index);
    if (sock_fd < 0) {
        return -1;
    }
    return send(sock_fd, buf, size, MSG_NOSIGNAL);
}

ssize_t comm_recv(const perftest_config_t *cfg, uint32_t index, void *buf, size_t size)
{
    int sock_fd = get_sock_fd(cfg, index);
    if (sock_fd < 0) {
        return -1;
    }
    return recv(sock_fd, buf, size, 0);
}

int comm_poll(const perftest_config_t *cfg, uint32_t index, int timeout_ms)
{
    int sock_fd = get_sock_fd(cfg, index);
    if (sock_fd < 0) {
        return -1;
    }

    struct pollfd pfd = {
        .fd = sock_fd,
        .events = POLLIN,
        .revents = 0,
    };
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
        errno = EIO;
        return -1;
    }
    return ret;
}
