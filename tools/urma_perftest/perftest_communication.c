/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: communication for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

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

static int client_connect(perftest_comm_t *comm)
{
    struct sockaddr_in addr;

    comm->listen_fd = -1;
    comm->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (comm->sock_fd < 0) {
        (void)fprintf(stderr, "Failed to create socket in client: %s, sock_fd: %d.\n", strerror(errno), comm->sock_fd);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = (uint16_t)htons(comm->port);
    addr.sin_addr.s_addr = inet_addr(comm->server_ip);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        (void)fprintf(stderr, "Failed to inet_addr server ip: %s, errno: %s\n", comm->server_ip, strerror(errno));
        goto close_fd;
    }

    if (connect_retry(comm->sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        (void)fprintf(stderr, "Failed to connect, sockfd:%d, errno: [%d]%s\n", comm->sock_fd, errno, strerror(errno));
        goto close_fd;
    }

    if (ip_set_sockopts(comm->sock_fd) !=  0) {
        (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: %s\n", comm->sock_fd, strerror(errno));
        goto close_fd;
    }
    return 0;

close_fd:
    (void)close(comm->sock_fd);
    return -1;
}

static int server_connect(perftest_comm_t *comm)
{
    struct sockaddr_in addr;

    comm->server_ip = NULL;
    comm->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (comm->listen_fd < 0) {
        (void)fprintf(stderr, "Failed to create socket in server: %s, listen_fd: %d.\n",
            strerror(errno), comm->listen_fd);
        return -1;
    }
    if (ip_set_sockopts(comm->listen_fd) !=  0) {
        (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: %s\n", comm->listen_fd, strerror(errno));
        goto close_listen_fd;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = (uint16_t)htons(comm->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(comm->listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        (void)fprintf(stderr, "Failed to bind, listenfd:%d, errno: [%d]%s\n", comm->listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    if (listen(comm->listen_fd, PERFTEST_MAX_CONNECTIONS) != 0) {
        (void)fprintf(stderr, "Failed to listen, listenfd:%d, errno: [%d]%s\n",
            comm->listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    comm->sock_fd = accept(comm->listen_fd, NULL, 0);
    if (comm->sock_fd < 0) {
        (void)fprintf(stderr, "Failed to accept, listenfd:%d, errno: [%d]%s\n",
            comm->listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    if (ip_set_sockopts(comm->sock_fd) !=  0) {
        (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: [%d]%s\n",
            comm->sock_fd, errno, strerror(errno));
        goto close_sockfd;
    }
    (void)close(comm->listen_fd);  // No other connections need to be accepted.
    comm->listen_fd = -1;
    return 0;

close_sockfd:
    (void)close(comm->sock_fd);
close_listen_fd:
    (void)close(comm->listen_fd);
    return -1;
}

int establish_connection(perftest_comm_t *comm)
{
    int ret;
    if (comm->server_ip != NULL) {
        /* client side */
        ret = client_connect(comm);
    } else {
        /* server side */
        (void)printf(PERFTEST_RESULT_LINE);
        (void)printf("                           Waiting for client to connect...\n");
        ret = server_connect(comm);
    }

    return ret;
}

void close_connection(perftest_comm_t *comm)
{
    (void)close(comm->sock_fd);
    comm->sock_fd = -1;
    free(comm->server_ip);
    comm->server_ip = NULL;
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

    while (rc == 0 && total_read_bytes < size) {
        read_bytes = read(sock_fd, remote_data, (size_t)size);
        if (read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            rc = read_bytes;
        }
    }

    return rc;
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