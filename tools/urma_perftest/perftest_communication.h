/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: communication header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef PERFTEST_COMMUNICATION_H
#define PERFTEST_COMMUNICATION_H

#define PERFTEST_MAX_CONNECTIONS    (10)
#define PERFTEST_CONNECT_COUNT      (5)
#define ERFTEST_SLEEP_TIME (100 * 1000) /* Sleep for 100 ms */

typedef struct perftest_comm {
    char *server_ip;
    uint16_t port;                          /* Server port for bind or connect, default 21115. */
    int listen_fd;
    int sock_fd;
} perftest_comm_t;

int establish_connection(perftest_comm_t *comm);
void close_connection(perftest_comm_t *comm);
int sock_sync_data(int sock_fd, int size, char *local_data, char *remote_data);
int sync_time(int sock_fd, char *a);

#endif