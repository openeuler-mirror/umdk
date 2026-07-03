/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: tcp management header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef PERFTEST_MGMT_TCP_H
#define PERFTEST_MGMT_TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct comm_tcp_cfg {
    char *server_ip;
    char *bind_ip;
    bool enable_ipv6;
    uint16_t port; /* Server port for bind or connect, default 21115. */
    uint32_t sock_num;
} comm_tcp_cfg_t;

int tcp_establish_connection(const comm_tcp_cfg_t *cfg);
void tcp_close_connection(void);

int tcp_sync_data(uint32_t index, int size, char *local_data, char *remote_data);
int tcp_sync_time(uint32_t index, const char *a);
ssize_t tcp_comm_send(uint32_t index, const void *buf, size_t size);
ssize_t tcp_comm_recv(uint32_t index, void *buf, size_t size);
int tcp_comm_poll(uint32_t index, int timeout_ms);

#endif
