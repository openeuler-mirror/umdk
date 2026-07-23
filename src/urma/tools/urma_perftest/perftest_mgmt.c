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

#include "perftest_mgmt_tcp.h"
#include "perftest_mgmt_ub.h"
#include "perftest_parameters.h"

#include "perftest_mgmt.h"

int establish_connection(const perftest_config_t *cfg)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP: {
            comm_tcp_cfg_t tcp_cfg = {
                .server_ip = cfg->server_ip,
                .bind_ip = cfg->bind_ip,
                .enable_ipv6 = cfg->enable_ipv6,
                .port = cfg->port,
                .sock_num = cfg->pair_num,
            };
            return tcp_establish_connection(&tcp_cfg);
        }
        case PERFTEST_MGMT_UB: {
            const bool port_specified = cfg->port != PERFTEST_DEF_PORT;
            comm_ub_cfg_t ub_cfg = {
                .src_eid = NULL,
                .dst_eid = cfg->server_ip,
                .dst_jetty_id = port_specified ? cfg->port : 0,
            };
            return ub_establish_connection(&ub_cfg);
        }
        default:
            LOG_ERROR("Invalid management channel type: %d.\n", (int)cfg->mgmt_type);
            return -1;
    }
}

void close_connection(perftest_config_t *cfg)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP:
            tcp_close_connection();
            break;
        case PERFTEST_MGMT_UB:
            ub_close_connection();
            break;
        default:
            break;
    }
    free(cfg->server_ip);
    cfg->server_ip = NULL;
    if (cfg->bind_ip != NULL) {
        free(cfg->bind_ip);
        cfg->bind_ip = NULL;
    }
}

int sync_data(const perftest_config_t *cfg, uint32_t index, int size, char *local_data, char *remote_data)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP:
            return tcp_sync_data(index, size, local_data, remote_data);
        case PERFTEST_MGMT_UB:
            return ub_sync_data(index, size, local_data, remote_data);
        default:
            return -1;
    }
}

int sync_time(const perftest_config_t *cfg, uint32_t index, const char *a)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP:
            return tcp_sync_time(index, a);
        case PERFTEST_MGMT_UB:
            return ub_sync_time(index, a);
        default:
            return -1;
    }
}

ssize_t comm_send(const perftest_config_t *cfg, uint32_t index, const void *buf, size_t size)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP:
            return tcp_comm_send(index, buf, size);
        case PERFTEST_MGMT_UB:
            return ub_comm_send(index, buf, size);
        default:
            return -1;
    }
}

ssize_t comm_recv(const perftest_config_t *cfg, uint32_t index, void *buf, size_t size)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP:
            return tcp_comm_recv(index, buf, size);
        case PERFTEST_MGMT_UB:
            return ub_comm_recv(index, buf, size);
        default:
            return -1;
    }
}

int comm_poll(const perftest_config_t *cfg, uint32_t index, int timeout_ms)
{
    switch (cfg->mgmt_type) {
        case PERFTEST_MGMT_TCP:
            return tcp_comm_poll(index, timeout_ms);
        case PERFTEST_MGMT_UB:
            return ub_comm_poll(index, timeout_ms);
        default:
            return -1;
    }
}
