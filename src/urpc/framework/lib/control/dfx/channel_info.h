/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc channel information cmd
 * Create: 2025-05-28
 */

#ifndef CHANNEL_INFO_H
#define CHANNEL_INFO_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_channel_cmd_id {
    URPC_CHANNEL_CMD_ID_ALL_CHANNEL,
    URPC_CHANNEL_CMD_ID_BY_CHID,
    URPC_CHANNEL_CMD_ID_MAX,
} urpc_channel_cmd_id_t;

typedef struct urpc_channel_cmd_input {
    uint32_t channel_id;
} urpc_channel_cmd_input_t;

int channel_info_cmd_init(void);
void channel_info_cmd_uninit(void);

#ifdef __cplusplus
}
#endif

#endif