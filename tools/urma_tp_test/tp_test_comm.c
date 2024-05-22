/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: communication for urma_tp_test
 * Author: Qian Guoxin
 * Create: 2024-02-02
 * Note:
 * History: 2024-02-02   create file
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

#include "tp_test_para.h"
#include "tp_test_comm.h"

#define TP_TEST_MAX_CONNECTIONS    (100)
#define TP_TEST_CONNECT_COUNT      (5)
#define TP_TEST_SLEEP_TIME (100 * 1000) /* Sleep for 100 ms */

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
    for (int i = 1; i <= TP_TEST_CONNECT_COUNT; i++) {
        if (connect(sockfd, addr, size) != 0) {
            times += i * (uint32_t)TP_TEST_SLEEP_TIME;
            (void)usleep(times);
            continue;
        }
        return 0;
    }
    return -1;
}

static int client_connect(tp_test_config_t *cfg)
{
    struct sockaddr_in addr;

    cfg->server.listen_fd = -1;
    cfg->client.sock_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (cfg->client.sock_fd < 0) {
        (void)fprintf(stderr, "Failed to create socket in client: %s, sock_fd: %d.\n",
            strerror(errno), cfg->client.sock_fd);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = (uint16_t)htons(cfg->port);
    addr.sin_addr.s_addr = inet_addr(cfg->server_ip);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        (void)fprintf(stderr, "Failed to inet_addr server ip: %s, errno: %s\n",
            cfg->server_ip, strerror(errno));
        goto close_fd;
    }

    if (connect_retry(cfg->client.sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        (void)fprintf(stderr, "Failed to connect, sockfd:%d, errno: [%d]%s\n",
            cfg->client.sock_fd, errno, strerror(errno));
        goto close_fd;
    }

    if (ip_set_sockopts(cfg->client.sock_fd) !=  0) {
        (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: %s\n",
            cfg->client.sock_fd, strerror(errno));
        goto close_fd;
    }
    return 0;

close_fd:
    (void)close(cfg->client.sock_fd);
    return -1;
}

static int server_accept(tp_test_config_t *cfg, int listen_fd)
{
    uint32_t i;
    int sock_fd;
    struct sockaddr_in peer_addr;
    socklen_t len = (socklen_t)sizeof(peer_addr);
    char ip_addr[INET_ADDRSTRLEN];
    tp_test_client_node_t *rm_client;

    for (i = 0 ; i < cfg->client_num; i++) {
        sock_fd = accept(listen_fd, NULL, 0);
        if (sock_fd < 0) {
            (void)fprintf(stderr, "Failed to accept, listenfd:%d, errno: [%d]%s\n",
                listen_fd, errno, strerror(errno));
            goto free_client;
        }

        if (ip_set_sockopts(sock_fd) !=  0) {
            (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: [%d]%s\n",
                sock_fd, errno, strerror(errno));
            goto close_fd;
        }
        tp_test_client_node_t *client = (tp_test_client_node_t *)calloc(1, sizeof(tp_test_client_node_t));
        if (client == NULL) {
            goto close_fd;
        }
        client->sock_fd = sock_fd;
        ub_list_insert_after(&cfg->server.client_list, &client->node);

        (void)getpeername(sock_fd, (struct sockaddr *)&peer_addr, &len);
        (void)printf("New Connection: %s:%d.\n",
            inet_ntop(AF_INET, &peer_addr.sin_addr, ip_addr, sizeof(ip_addr)), ntohs(peer_addr.sin_port));
    }
    return 0;
close_fd:
    (void)close(sock_fd);
free_client:
    UB_LIST_FOR_EACH(rm_client, node, &cfg->server.client_list) {
        ub_list_remove(&rm_client->node);
        (void)close(rm_client->sock_fd);
        rm_client->sock_fd = -1;
        free(rm_client);
    }
    return -1;
}

static int server_connect(tp_test_config_t *cfg)
{
    struct sockaddr_in addr;

    cfg->server.listen_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (cfg->server.listen_fd < 0) {
        (void)fprintf(stderr, "Failed to create socket in server: %s, listen_fd: %d.\n",
            strerror(errno), cfg->server.listen_fd);
        return -1;
    }
    if (ip_set_sockopts(cfg->server.listen_fd) !=  0) {
        (void)fprintf(stderr, "Failed to set_sockopts, sockfd:%d, errno: %s\n",
            cfg->server.listen_fd, strerror(errno));
        goto close_listen_fd;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = (uint16_t)htons(cfg->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(cfg->server.listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        (void)fprintf(stderr, "Failed to bind, listenfd:%d, errno: [%d]%s\n",
            cfg->server.listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    if (listen(cfg->server.listen_fd, TP_TEST_MAX_CONNECTIONS) != 0) {
        (void)fprintf(stderr, "Failed to listen, listenfd:%d, errno: [%d]%s\n",
            cfg->server.listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    if (server_accept(cfg, cfg->server.listen_fd) != 0) {
        (void)fprintf(stderr, "Failed to accept, listenfd:%d, errno: [%d]%s\n",
            cfg->server.listen_fd, errno, strerror(errno));
        goto close_listen_fd;
    }

    (void)close(cfg->server.listen_fd);  // No other connections need to be accepted.
    cfg->server.listen_fd = -1;
    return 0;

close_listen_fd:
    (void)close(cfg->server.listen_fd);
    return -1;
}

int establish_connection(tp_test_config_t *cfg)
{
    int ret;
    if (cfg->is_server == false) {
        /* client side */
        ret = client_connect(cfg);
    } else {
        /* server side */
        (void)printf(TP_TEST_RESULT_LINE);
        (void)printf("                           Waiting for [%u] client to connect...\n",
            cfg->client_num);
        ret = server_connect(cfg);
    }

    return ret;
}

void close_connection(tp_test_config_t *cfg)
{
    if (cfg->is_server == false) {
        /* client side */
        (void)close(cfg->client.sock_fd);
        cfg->client.sock_fd = -1;
    } else {
        /* server side */
        tp_test_client_node_t *rm_client, *next;
        UB_LIST_FOR_EACH_SAFE(rm_client, next, node, &cfg->server.client_list) {
            ub_list_remove(&rm_client->node);
            (void)close(rm_client->sock_fd);
            rm_client->sock_fd = -1;
            free(rm_client);
        }
    }
    free(cfg->server_ip);
    cfg->server_ip = NULL;
}

int sock_send_data(int sock_fd, int size, char *local_data)
{
    int rc;

    rc = write(sock_fd, local_data, (size_t)size);
    if (rc < size) {
        (void)fprintf(stderr, "Failed writing data during sock_sync_data, errno: %s.\n", strerror(errno));
    } else {
        rc = 0;
    }

    return rc;
}

int sock_recv_data(int sock_fd, int size, char *remote_data)
{
    int rc = 0;
    int read_bytes = 0;
    int total_read_bytes = 0;

    while (rc == 0 && total_read_bytes < size) {
        read_bytes = read(sock_fd, remote_data + total_read_bytes, (size_t)size - total_read_bytes);
        if (read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            rc = read_bytes;
        }
    }

    return rc;
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