/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: communication header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef PERFTEST_COMMUNICATION_H
#define PERFTEST_COMMUNICATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PERFTEST_MAX_CONNECTIONS (10)
#define PERFTEST_CONNECT_COUNT   (5)
#define ERFTEST_SLEEP_TIME       (100 * 1000) /* Sleep for 100 ms */

typedef struct perftest_comm {
    char *server_ip;
    char *bind_ip;
    bool enable_ipv6;
    uint16_t port; /* Server port for bind or connect, default 21115. */
    int listen_fd;
    int *sock_fd;
} perftest_comm_t;

typedef struct perftest_config perftest_config_t;

int establish_connection(perftest_config_t *cfg);
void close_connection(perftest_config_t *cfg);

int sync_data(const perftest_config_t *cfg, uint32_t index, int size, char *local_data, char *remote_data);
int sync_time(const perftest_config_t *cfg, uint32_t index, const char *a);
ssize_t comm_send(const perftest_config_t *cfg, uint32_t index, const void *buf, size_t size);
ssize_t comm_recv(const perftest_config_t *cfg, uint32_t index, void *buf, size_t size);
int comm_poll(const perftest_config_t *cfg, uint32_t index, int timeout_ms);

#endif
