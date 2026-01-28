/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq example
 * Create: 2026-1-27
 * Note:
 * History: 2026-1-27
 */

#ifndef CONNECTION_SETUP_TOOL_H
#define CONNECTION_SETUP_TOOL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct exchange_info {
    uint32_t msg_len;
    uint8_t data[0];
} exchange_info_t;

typedef enum fd_ctx_type {
    FD_CTX_TYPE_INTERRUPT_TX = 0x123,
    FD_CTX_TYPE_INTERRUPT_RX,
    FD_CTX_TYPE_MAX,
} fd_ctx_type_t;

typedef struct fd_ctx {
    uint32_t type;
    uint64_t umqh;
    int fd;
    bool processing;
} fd_ctx_t;

typedef struct umq_ctx {
    uint64_t umqh;
    uint32_t main_umq_idx;
} umq_ctx_t;

typedef struct umq_info {
    uint64_t umqh;
    uint32_t send_req_cnt;
    uint32_t recv_req_cnt;
    uint32_t send_rsp_cnt;
    uint32_t recv_rsp_cnt;
    uint32_t fc_update;
    uint32_t eagain_cnt;
    fd_ctx_t *tx_fd_ctx;
    fd_ctx_t *rx_fd_ctx;
    umq_ctx_t *umq_ctx;
    bool enable;
    bool is_main_umq;
} umq_info_t;

typedef struct ip_info {
    char *ip;
    uint16_t port;
} ip_info_t;

typedef struct connection_bind_info {
    char dev_name[UMQ_DEV_NAME_SIZE];
    uint32_t eid_idx;
    uint32_t bind_info_size;
    uint8_t umq_bind_info[0];
} connection_bind_info_t;

struct urpc_example_config;
int connection_setup_tool(struct urpc_example_config *cfg);

#ifdef __cplusplus
}
#endif

#endif

