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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "perftest_parameters.h"

#include "perftest_communication.h"

static int ip_set_sockopts(int sockfd)
{
    int ret;
    int enable_reuse = 1;
    int enable_nodelay = 1;

    /* Set socket reuse. When the server is restarted,
     * the problem of the connection failure of the client is solved */
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
    if (ret < 0) {
        (void)fprintf(stderr, "server socket set_opt failed. enable_reuse:%d, ret: %d, err: [%d]%s.\n",
                      SO_REUSEPORT, ret, errno, strerror(errno));
        return ret;
    }

    // Close Nagle algorithm, and fix 42ms delay problem.
    ret = setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &enable_nodelay, sizeof(enable_nodelay));
    if (ret < 0) {
        (void)fprintf(stderr, "server socket set_opt failed. opt:%d, ret: %d, err: [%d]%s.\n",
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

    if (sprintf(service, "%d", port) <= 0) {
        return -1;
    }

    num = getaddrinfo(server_ip, service, hints, res);
    if (num < 0) {
        (void)fprintf(stderr, "%s for %s:%d\n", gai_strerror(num), server_ip, port);
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
    comm->listen_fd = -1;
    comm->sock_fd = (int *)calloc(1, sizeof(int) * cfg->pair_num);
    if (comm->sock_fd == NULL) {
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
            (void)fprintf(stderr, "Problem in resolving bind IP '%s': %s\n",
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
            (void)fprintf(stderr, "Bind IP not found : %s\n", comm->bind_ip);
            goto create_client_error;
        }
    }

    for (i = 0; i < cfg->pair_num; i++) {
        if (check_add_port((comm->port + i), comm->server_ip, &hints, &res)) {
            (void)fprintf(stderr, "Problem in resolving basic address and port\n");
            free(comm->sock_fd);
            return -1;
        }

        for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
            bool try_connect = true;
            comm->sock_fd[i] = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
            if (comm->sock_fd[i] < 0) {
                continue;
            }
            if (comm->bind_ip != NULL) {
                if (bind(comm->sock_fd[i], client_tmp->ai_addr, client_tmp->ai_addrlen) != 0) {
                    try_connect = false;
                    (void)fprintf(stderr, "Failed to bind ip: %s\n", comm->bind_ip);
                }
            }
            if (try_connect && connect_retry(comm->sock_fd[i], tmp->ai_addr, tmp->ai_addrlen) == 0) {
                break;
            }
            close(comm->sock_fd[i]);
            comm->sock_fd[i] = -1;
        }

        if (res != NULL) {
            freeaddrinfo(res);
            res = NULL;
        }

        if (comm->sock_fd[i] < 0) {
            (void)fprintf(stderr, "Failed to connect %s:%d\n\n", comm->server_ip, (comm->port + i));
            goto create_client_error;
        }

        if (ip_set_sockopts(comm->sock_fd[i]) != 0) {
            (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: %s\n", comm->sock_fd[i], strerror(errno));
            (void)close(comm->sock_fd[i]);
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
    for (uint32_t j = 0; j < i; j++) {
        (void)close(comm->sock_fd[j]);
    }
    free(comm->sock_fd);
    if (client_res != NULL) {
        freeaddrinfo(client_res);
    }
bind_client_error:
    return -1;
}

static int server_connect(perftest_config_t *cfg)
{
    struct addrinfo *res, *tmp;
    struct addrinfo hints = {0};
    uint32_t accept_num = 0;

    perftest_comm_t *comm = &cfg->comm;
    comm->listen_fd = -1;
    comm->server_ip = NULL;
    comm->sock_fd = (int *)calloc(1, sizeof(int) * cfg->pair_num);
    if (comm->sock_fd == NULL) {
        return -1;
    }
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = comm->enable_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (check_add_port(comm->port, comm->bind_ip, &hints, &res)) {
        (void)fprintf(stderr, "Problem in resolving basic address and port\n");
        free(comm->sock_fd);
        return -1;
    }

    for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
        if (tmp->ai_family != hints.ai_family) {
            continue;
        }

        comm->listen_fd = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
        if (comm->listen_fd >= 0) {
            if (ip_set_sockopts(comm->listen_fd) != 0) {
                (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: %s\n",
                              comm->listen_fd, strerror(errno));
                goto close_listen_fd;
            }
            if (bind(comm->listen_fd, tmp->ai_addr, tmp->ai_addrlen) == 0) {
                break;
            }
            close(comm->listen_fd);
            comm->listen_fd = -1;
        }
    }

    if (comm->listen_fd < 0) {
        (void)fprintf(stderr, "Failed to bind, port:%d.\n", comm->port);
        goto close_listen_fd;
    }

    if (listen(comm->listen_fd, PERFTEST_MAX_CONNECTIONS) != 0) {
        (void)fprintf(stderr, "Failed to listen, listenfd:%d, errno: [%d]%s\n",
                      comm->listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    while (accept_num < cfg->pair_num) {
        comm->sock_fd[accept_num] = accept(comm->listen_fd, NULL, 0);
        if (comm->sock_fd[accept_num] < 0) {
            (void)fprintf(stderr, "Failed to accept, listenfd:%d, errno: [%d]%s\n",
                          comm->listen_fd, errno, strerror(errno));
            goto create_server_error;
        }

        if (ip_set_sockopts(comm->sock_fd[accept_num]) != 0) {
            (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: [%d]%s\n",
                          comm->sock_fd[accept_num], errno, strerror(errno));
            (void)close(comm->sock_fd[accept_num]);
            goto create_server_error;
        }
        accept_num++;
    }

    freeaddrinfo(res);
    (void)close(comm->listen_fd); // No other connections need to be accepted.
    comm->listen_fd = -1;
    return 0;

create_server_error:
    for (uint32_t j = 0; j < accept_num; j++) {
        (void)close(comm->sock_fd[j]);
    }
    free(comm->sock_fd);
close_listen_fd:
    freeaddrinfo(res);
    (void)close(comm->listen_fd);
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
        (void)printf(PERFTEST_RESULT_LINE);
        (void)printf("                           Waiting for client to connect...\n");
        ret = server_connect(cfg);
    }

    return ret;
}

void close_connection(perftest_config_t *cfg)
{
    uint32_t i = 0;
    perftest_comm_t *comm = &cfg->comm;

    for (i = 0; i < cfg->pair_num; i++) {
        (void)close(comm->sock_fd[i]);
        comm->sock_fd[i] = -1;
    }
    free(comm->sock_fd);
    comm->sock_fd = NULL;
    free(comm->server_ip);
    comm->server_ip = NULL;
    if (comm->bind_ip) {
        free(comm->bind_ip);
        comm->bind_ip = NULL;
    }
}

int sock_sync_data(int sock_fd, int size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;

    rc = write(sock_fd, local_data, (size_t)size);
    if (rc < size) {
        (void)fprintf(stderr, "Failed writing data during sock_sync_data, errno: %s.\n", strerror(errno));
    } else {
        rc = 0;
    }

    while (total_read_bytes < size) {
        read_bytes = read(sock_fd, remote_data + total_read_bytes, (size_t)size - total_read_bytes);
        if (read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            break;
        }
    }

    if (total_read_bytes == size) {
        return 0;
    }

    (void)fprintf(stderr, "Failed to read data during sock_sync_data, errno: %s total_size:%d, expect_size:%d.\n",
                  strerror(errno), total_read_bytes, size);
    return -1;
}

int sync_time(int sock_fd, char *a)
{
    if (a == NULL) {
        (void)fprintf(stderr, "Invalid parameter with a nullptr.\n");
        return -1;
    }
    int len = (int)strlen(a);
    char *b = calloc(1, (unsigned long)len + 1);
    int ret = 0;
    if (b == NULL) {
        return -ENOMEM;
    }
    ret = sock_sync_data(sock_fd, len, a, b);
    if (ret != 0) {
        (void)fprintf(stderr, "sync time error, %s, ret: %d.\n", a, ret);
        goto sync_ret;
    }
    ret = memcmp(a, b, (unsigned long)len);
    if (ret != 0) {
        b[len] = '\0';
        (void)fprintf(stderr, "sync time error, %s != %s.\n", a, b);
        goto sync_ret;
    }
sync_ret:
    free(b);
    return ret;
}
