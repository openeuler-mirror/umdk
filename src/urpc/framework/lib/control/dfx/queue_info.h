/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc queue information cmd
 * Create: 2024-11-18
 */

#ifndef QUEUE_INFO_H
#define QUEUE_INFO_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_queue_cmd_id {
    URPC_QUEUE_CMD_ID_LOCAL_ALL,
    URPC_QUEUE_CMD_ID_BY_CLIENT_CHID,
    URPC_QUEUE_CMD_ID_BY_SERVER_CHID,
    URPC_QUEUE_CMD_ID_BY_QID,
    URPC_QUEUE_CMD_ID_MAX,
} urpc_queue_cmd_id_t;

typedef struct urpc_queue_cmd_input {
    uint32_t channel_id;
    uint16_t queue_id;
} urpc_queue_cmd_input_t;

int queue_info_cmd_init(void);
void queue_info_cmd_uninit(void);

#ifdef __cplusplus
}
#endif

#endif