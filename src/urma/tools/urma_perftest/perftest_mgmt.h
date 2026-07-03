/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: management header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef PERFTEST_MGMT_H
#define PERFTEST_MGMT_H

#include "perftest_mgmt_tcp.h"

typedef struct perftest_config perftest_config_t;

int establish_connection(const perftest_config_t *cfg);
void close_connection(perftest_config_t *cfg);

int sync_data(const perftest_config_t *cfg, uint32_t index, int size, char *local_data, char *remote_data);
int sync_time(const perftest_config_t *cfg, uint32_t index, const char *a);
ssize_t comm_send(const perftest_config_t *cfg, uint32_t index, const void *buf, size_t size);
ssize_t comm_recv(const perftest_config_t *cfg, uint32_t index, void *buf, size_t size);
int comm_poll(const perftest_config_t *cfg, uint32_t index, int timeout_ms);

#endif
