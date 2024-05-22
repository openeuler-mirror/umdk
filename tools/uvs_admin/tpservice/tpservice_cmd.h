/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of 'uvs_admin tpservice/show' command
 * Author: Ji Lei
 * Create: 2023-06-14
 * Note:
 * History: 2023-06-14 Ji Lei Initial version
 */

#ifndef TPSERVICE_CMD_H
#define TPSERVICE_CMD_H

#include "uvs_admin_types.h"
#include "uvs_admin_cmd.h"

typedef struct uvs_admin_service_show_rsp {
    uvs_admin_net_addr_t service_ip;
    uint16_t port_id;
} uvs_admin_service_show_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_tpservice_cmd;

#endif /* TPSERVICE_CMD_H */
