/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: ioctl command source file for urma_admin
 * Author: Chen Yutao
 * Create: 2023-03-14
 * Note:
 * History: 2023-03-14   create file
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include "ub_util.h"
#include "urma_cmd.h"
#include "urma_types.h"

#include "admin_file_ops.h"
#include "admin_netlink.h"
#include "admin_parameters.h"

#include "admin_cmd.h"

static int admin_set_reserved_jetty_id_range(admin_config_t *cfg)
{
    char jetty_id_range[VALUE_LEN_MAX] = {0};

    if (cfg->min_rsvd_jetty_id > cfg->max_rsvd_jetty_id) {
        (void)printf("set reserved jetty id range failed, min jetty id should not be larger than max jetty id.\n");
        return -1;
    }

    int len = sprintf(jetty_id_range, "%u-%u", cfg->min_rsvd_jetty_id, cfg->max_rsvd_jetty_id);
    if (len <= 0 || len >= VALUE_LEN_MAX) {
        (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
        return -1;
    }

    return admin_write_dev_file(cfg->dev_name, "reserved_jetty_id", jetty_id_range, len + 1);
}

int admin_cmd_main(admin_config_t *cfg)
{
    static const admin_cmd_t cmds[] = {
        {NULL, admin_cmd_show},
        {"add_eid", admin_cmd_add_eid_legacy},
        {"del_eid", admin_cmd_del_eid_legacy},
        {"set_eid_mode", admin_cmd_set_eid_mode_legacy},
        {"show_stats", admin_cmd_show_stats_legacy},
        {"show_res", admin_cmd_show_res_legacy},
        {"list_res", admin_cmd_list_res_legacy},
        {"set_ns_mode", admin_cmd_set_ns_mode_legacy},
        {"set_dev_ns", admin_cmd_set_dev_ns_legacy},
        {"set_reserved_jetty", admin_set_reserved_jetty_id_range},
        //
        {"show", admin_cmd_show},
        {"agg", admin_cmd_agg},
        {"dev", admin_cmd_dev},
        {"eid", admin_cmd_eid},
        {0},
    };
    return exec_cmd(cfg, cmds);
}
