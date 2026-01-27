/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc unix domain server for inter-process communication
 * Create: 2024-4-22
 */

#ifndef URPC_UNIX_SERVER_H
#define URPC_UNIX_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNIX_SERVER_RECV_IMTEOUT_S 8

typedef enum urpc_ipc_module {
    URPC_IPC_MODULE_VERSION = 0,
    URPC_IPC_MODULE_STAT,
    URPC_IPC_MODULE_QUEUE,
    URPC_IPC_MODULE_PERF,
    URPC_IPC_MODULE_DBUF,
    URPC_IPC_MODULE_CHANNEL,
    URPC_IPC_MODULE_HANDSHAKER,
    URPC_IPC_MODULE_MAX,
} urpc_ipc_module_t;

// host byte order
typedef struct urpc_ipc_ctl_head {
    uint16_t module_id;
    uint16_t cmd_id;
    int error_code;
    uint32_t data_size;
} __attribute__((packed)) urpc_ipc_ctl_head_t;

typedef void (*ipc_func)(urpc_ipc_ctl_head_t *req_ctl, char *request, urpc_ipc_ctl_head_t *rsp_ctl, char **reply);

typedef struct urpc_ipc_cmd {
    uint16_t module_id;
    uint16_t cmd_id;
    ipc_func func;
    bool reply_malloced;
} urpc_ipc_cmd_t;

int unix_server_cmds_register(urpc_ipc_cmd_t *cmd, int num);
void unix_server_cmds_unregister(urpc_ipc_cmd_t *cmd, int num);
int unix_server_cmd_get(uint16_t module_id, uint16_t cmd_id, urpc_ipc_cmd_t *cmd);

int unix_server_init(const char *unix_domain_file_path);
void unix_server_uninit(void);

int unix_ipc_ctl_recv(int fd, urpc_ipc_ctl_head_t *ipc_ctl, char **out_data);
int unix_ipc_ctl_send(int fd, urpc_ipc_ctl_head_t *ipc_ctl, char *in_data);

int file_path_get(char *buf, size_t len, const char *unix_domain_file_path);

#ifdef __cplusplus
}
#endif

#endif
