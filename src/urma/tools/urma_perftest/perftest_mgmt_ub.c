/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: ub management stub for urma_perftest
 * Author: Qian Guoxin
 * Create: 2026-07-03
 * Note:
 * History: 2026-07-03   create file
 */

#include <errno.h>

#include "perftest_log.h"
#include "perftest_parameters.h"

#include "perftest_mgmt_ub.h"

static int ub_not_implemented(void)
{
    LOG_ERROR("UB management channel is not implemented yet.\n");
    return -EOPNOTSUPP;
}

int ub_establish_connection(const comm_ub_cfg_t *cfg)
{
    if (cfg == NULL) {
        return -EINVAL;
    }

    return ub_not_implemented();
}

void ub_close_connection(void)
{
    return;
}

int ub_sync_data(uint32_t index, int size, char *local_data, char *remote_data)
{
    (void)index;
    (void)size;
    (void)local_data;
    (void)remote_data;
    return ub_not_implemented();
}

int ub_sync_time(uint32_t index, const char *tag)
{
    (void)index;
    (void)tag;
    return ub_not_implemented();
}

ssize_t ub_comm_send(uint32_t index, const void *buf, size_t size)
{
    (void)index;
    (void)buf;
    (void)size;
    return ub_not_implemented();
}

ssize_t ub_comm_recv(uint32_t index, void *buf, size_t size)
{
    (void)index;
    (void)buf;
    (void)size;
    return ub_not_implemented();
}

int ub_comm_poll(uint32_t index, int timeout_ms)
{
    (void)index;
    (void)timeout_ms;
    return ub_not_implemented();
}
