/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: ub management header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2026-07-03
 * Note:
 * History: 2026-07-03   create file
 */

#ifndef PERFTEST_MGMT_UB_H
#define PERFTEST_MGMT_UB_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define UB_MGMT_JFC_DEPTH               (64)
#define UB_MGMT_JFS_DEPTH               (8)
#define UB_MGMT_JFR_DEPTH               (8)
#define UB_MGMT_MSG_MAX_SIZE            (4096)

typedef struct comm_ub_cfg {
    char     *src_eid;      /* Local mgmt EID. Required. */
    char     *dst_eid;      /* Server mgmt EID, NULL on server side. */
    uint32_t  dst_jetty_id; /* Server mgmt jetty id, 0 on client (driver auto-assigns). */
} comm_ub_cfg_t;

int ub_establish_connection(const comm_ub_cfg_t *cfg);
void ub_close_connection(void);

int ub_sync_data(uint32_t index, int size, char *local_data, char *remote_data);
int ub_sync_time(uint32_t index, const char *tag);
ssize_t ub_comm_send(uint32_t index, const void *buf, size_t size);
ssize_t ub_comm_recv(uint32_t index, void *buf, size_t size);
int ub_comm_poll(uint32_t index, int timeout_ms);

#endif
