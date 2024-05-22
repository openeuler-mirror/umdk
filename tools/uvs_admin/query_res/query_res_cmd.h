/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: 'uvs_admin query_res and list_res' command definition
 * Author: Zhou Yuhao
 * Create: 2024-03-09
 * Note:
 * History: 2024-03-09 Zhou Yuhao Initial version
 */

#ifndef QUERYRES_CMD_H
#define QUERYRES_CMD_H

#include "uvs_admin_types.h"
#include "urma_types_str.h"
#include "uvs_admin_cmd.h"

int query_res_cmd_exec(int argc, char *argv[]);
void uvs_query_res_usage(void);

#endif /* QUERYRES_CMD_H */
