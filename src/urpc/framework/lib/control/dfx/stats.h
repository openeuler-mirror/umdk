/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc statistics cmd
 * Create: 2024-5-29
 */

#ifndef URPC_STATISTICS_H
#define URPC_STATISTICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_stats_cmd_id {
    URPC_STATS_CMD_ID_GET,
    URPC_STATS_CMD_ID_GET_BY_QID,
    URPC_STATS_CMD_ID_MAX,
} urpc_stats_cmd_id_t;

typedef struct urpc_stats_cmd_input {
    uint16_t queue_id;
} urpc_stats_cmd_input_t;

int stats_cmd_init(void);
void stats_cmd_uninit(void);

#ifdef __cplusplus
}
#endif

#endif