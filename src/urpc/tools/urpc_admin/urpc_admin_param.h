/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc admin param process
 * Create: 2024-4-23
 */

#ifndef URPC_ADMIN_PARAM_H
#define URPC_ADMIN_PARAM_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include "perf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_ADMIN_MODULE_ID_INIT_VAL       UINT16_MAX
#define URPC_ADMIN_CMD_ID_INIT_VAL          UINT16_MAX

typedef enum urpc_cmd_bits {
    URPC_CMD_BITS_VERSION = 0,
    URPC_CMD_BITS_DBUF,
    URPC_CMD_BITS_CHANNEL,

    URPC_CMD_BITS_PERF,
    URPC_CMD_BITS_THRESH,

    URPC_CMD_BITS_STATS,
    URPC_CMD_BITS_QUEUE_ID,

    URPC_CMD_BITS_QUEUE_INFO,
    URPC_CMD_BITS_CLIENT_CHANNEL,
    URPC_CMD_BITS_SERVER_CHANNEL,

    URPC_CMD_BITS_HANDSHAKER,
    URPC_CMD_BITS_HANDSHAKER_ID,

    URPC_CMD_BITS_MAX,
} urpc_cmd_bits_e;

typedef struct urpc_admin_config {
    char path[PATH_MAX + 1];  // unix domain socket file path
    uint32_t pid;             // pid of remote process
    uint16_t module_id;
    uint16_t cmd_id;
    bool no_request;
    uint64_t channel_id;
    uint8_t server_flag;
    uint64_t req_id;
    uint16_t queue_id;
    int task_id;
    struct {
        uint64_t count_thresh[URPC_PERF_QUANTILE_MAX_NUM];
        uint8_t count_thresh_num;
    } perf;
    uint64_t bitmap;
} urpc_admin_config_t;

int urpc_admin_args_parse(int argc, char **argv, urpc_admin_config_t *cfg);
int admin_cfg_check(urpc_admin_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif