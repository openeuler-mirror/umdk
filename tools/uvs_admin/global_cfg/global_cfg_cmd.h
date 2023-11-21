/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of 'uvs_admin global_cfg' command
 * Author: Ji Lei
 * Create: 2023-06-14
 * Note:
 * History: 2023-06-14 Ji Lei Initial version
 */

#ifndef GLOBAL_CFG_CMD_H
#define GLOBAL_CFG_CMD_H

#include <netinet/in.h>
#include "uvs_admin_cmd.h"
#include "uvs_admin_types.h"

typedef union uvs_admin_global_cfg_mask {
    struct {
        uint32_t mtu            : 1;
        uint32_t slice          : 1;
        uint32_t suspend_period : 1;
        uint32_t suspend_cnt    : 1;
        uint32_t sus2err_period : 1;
        uint32_t reserved       : 27;
    } bs;
    uint32_t value;
} uvs_admin_global_cfg_mask_t;

typedef struct uvs_admin_global_cfg_args {
    uvs_admin_global_cfg_mask_t mask;
    uvs_admin_mtu_t mtu;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
} uvs_admin_global_cfg_args_t;

typedef struct uvs_admin_global_cfg_show_rsp {
    uvs_admin_mtu_t mtu_show;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
} uvs_admin_global_cfg_show_rsp_t;

// must be the same as that of uvs_admin_global_cfg_args.
typedef struct uvs_admin_global_cfg_set_req {
    uvs_admin_global_cfg_mask_t mask;
    uvs_admin_mtu_t mtu;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
} uvs_admin_global_cfg_set_req_t;

typedef struct uvs_admin_global_cfg_set_rsp {
    int ret;
} uvs_admin_global_cfg_set_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_global_cfg_cmd;

#endif /* GLOBAL_CFG_CMD_H */
