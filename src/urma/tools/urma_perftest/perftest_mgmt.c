/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: management for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <stdlib.h>

#include "perftest_parameters.h"

#include "perftest_mgmt.h"

int establish_connection(const perftest_config_t *cfg)
{
    comm_tcp_cfg_t tcp_cfg = {
        .server_ip = cfg->comm.server_ip,
        .bind_ip = cfg->comm.bind_ip,
        .enable_ipv6 = cfg->comm.enable_ipv6,
        .port = cfg->comm.port,
        .sock_num = cfg->pair_num,
    };

    return tcp_establish_connection(&tcp_cfg);
}

void close_connection(perftest_config_t *cfg)
{
    perftest_comm_t *comm = &cfg->comm;

    tcp_close_connection();
    free(comm->server_ip);
    comm->server_ip = NULL;
    if (comm->bind_ip != NULL) {
        free(comm->bind_ip);
        comm->bind_ip = NULL;
    }
}

int sync_data(const perftest_config_t *cfg, uint32_t index, int size, char *local_data, char *remote_data)
{
    (void)cfg;
    return tcp_sync_data(index, size, local_data, remote_data);
}

int sync_time(const perftest_config_t *cfg, uint32_t index, const char *a)
{
    (void)cfg;
    return tcp_sync_time(index, a);
}

ssize_t comm_send(const perftest_config_t *cfg, uint32_t index, const void *buf, size_t size)
{
    (void)cfg;
    return tcp_comm_send(index, buf, size);
}

ssize_t comm_recv(const perftest_config_t *cfg, uint32_t index, void *buf, size_t size)
{
    (void)cfg;
    return tcp_comm_recv(index, buf, size);
}

int comm_poll(const perftest_config_t *cfg, uint32_t index, int timeout_ms)
{
    (void)cfg;
    return tcp_comm_poll(index, timeout_ms);
}
