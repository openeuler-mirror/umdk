/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc dynamic buffer cmd
 * Create: 2024-11-27
 */

#ifndef URPC_DBUF_H
#define URPC_DBUF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_dbuf_cmd_id {
    URPC_DBUF_CMD_ID_GET,
} urpc_dbuf_cmd_id_t;

int dbuf_cmd_init(void);
void dbuf_cmd_uninit(void);

#ifdef __cplusplus
}
#endif

#endif