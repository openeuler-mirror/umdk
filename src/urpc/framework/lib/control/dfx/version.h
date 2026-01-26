/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc version cmd
 * Create: 2024-4-24
 */

#ifndef URPC_VERSION_H
#define URPC_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_version_cmd_id {
    URPC_VERSION_CMD_ID_GET,
} urpc_version_cmd_id_t;

int version_cmd_init(void);
void version_cmd_uninit(void);

#ifdef __cplusplus
}
#endif

#endif