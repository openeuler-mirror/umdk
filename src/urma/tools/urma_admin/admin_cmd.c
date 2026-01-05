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

static int cmd_main_usage(admin_config_t *cfg)
{
    (void)printf("Usage: %s command [command options]\n", cfg->filename);
    (void)printf(" %s URMA configuration tool, chips do not support some values, which might be invalid.\n",
                 cfg->filename);
    (void)printf("\n");
    (void)printf("Command syntax:\n");
    (void)printf("  show [--dev] [--whole]                                 show all UB devices info.\n");
    (void)printf("  add_eid <--dev> <--idx> [--ns /proc/$pid/ns/net]       add eid of UB device, only for uvs,\n");
    (void)printf("                                                           control plane not support.\n");
    (void)printf("  del_eid <--dev> <--idx>                                del eid of UB device, only for uvs,\n");
    (void)printf("                                                           control plane not support.\n");
    (void)printf("  set_eid_mode <--dev> [--eid_mode]                      change eid mode of MUE device, only for\n");
    (void)printf("                                                           uvs, control plane not support.\n");
    (void)printf("  set_reserved_jetty <--dev> <--min_id> <--max_id>       set reserved jetty id range.\n");
    (void)printf("  show_stats <--dev> <--resource_type> <--key>           show run stats of UB device, \n");
    (void)printf("                                                           control plane not support.\n");
    (void)printf("  show_topo                                              show topo_info of bonding device.\n");
    (void)printf("  show_res <--dev> <--resource_type> <--key> [--key_ext]                                  \n");
    (void)printf("           <--key_cnt>                                   show resources of UB device.\n");
    (void)printf("  list_res <--dev> <--resource_type> [--key] [--key_ext]                               \n");
    (void)printf("           [--key_cnt]                                   list resources of UB device.\n");
    (void)printf("  set_ns_mode <--ns_mode (exclusive: 0) | (shared: 1) >  set ns mode for UB devices.\n");
    (void)printf("  set_dev_ns <--dev> <--ns /proc/$pid/ns/net>            set net namespace of UB device.\n");
    (void)printf("Options:\n");
    (void)printf("  -h, --help                                  show help info.\n");
    (void)printf("  -d, --dev <dev_name>                        the name of UB device.\n");
    (void)printf("  -e, --eid <eid>                             the eid of UB device.\n");
    (void)printf("  -m, --eid_mode <eid_mode>                   the eid mode of UB device,/\n");
    (void)printf("                                              (change to dynamic_mode: cmd with -m,\n");
    (void)printf("                                              change to static_mode: cmd without -m).\n");
    (void)printf("  -v, --ue_idx <ue_idx>                       the ue_idx of ubep device.\n"
                 "                                              when ue_idx == 0xffff or empty, it refers to MUE.\n");
    (void)printf("  -i, --idx <idx>                             idx defaults to 0.\n");
    (void)printf("  -w, --whole                                 show whole information.\n");
    (void)printf("  -R, --resource_type <type>                  config stats type with 1(tp_id/vtp, not support)/\n");
    (void)printf("                                                2(tp, not support)/3(tpg, not support)/4(jfs)/\n");
    (void)printf("                                                5(jfr)/6(jetty)/\n");
    (void)printf("                                                7(jetty group, not support)/8(dev).\n");
    (void)printf("                                              config res type with 1(tp_id/vtp, not support)/\n");
    (void)printf("                                                2(tp, not support)/3(tpg, not support)/\n");
    (void)printf("                                                4(utp, not support)/5(jfs)/6(jfr)/7(jetty)/\n");
    (void)printf("                                                8(jetty group)/9(jfc)/10(rc)/11(seg)/\n");
    (void)printf("                                                12(dev ta, not support)/13(dev tp, not support).\n");
    (void)printf("  -k, --key <key>                             config stats/res key, config stats key with: .\n");
    (void)printf("                                                1(tp_id/vtpn, not support)/2(tpn, not support)/\n");
    (void)printf("                                                3(tpgn, not support)/4(jfs_id)/5(jfr_id)/\n");
    (void)printf("                                                6(jetty_id)/7(jetty group id, not support)/\n");
    (void)printf("                                                8(dev, no key)\n");
    (void)printf("                                              config res key with: \n");
    (void)printf("                                                1(tp_id/vtpn, not support)/2(tpn, not support)/\n");
    (void)printf("                                                3(tpgn, not support)/4(utpn, not support)/\n");
    (void)printf("                                                5(jfs_id)/6(jfr_id)/7(jetty_id)/\n");
    (void)printf("                                                8(jetty group id)/9(jfc_id)/\n");
    (void)printf("                                                10(rc_id, not support)/11(token_id)/\n");
    (void)printf("                                                12(eid, not support)/13(eid, not support).\n");
    (void)printf("  -K, --key_ext <key_ext>                     config key_ext for tp_id/vtp res.\n");
    (void)printf("  -C, --key_cnt <key>                         config key_cnt for rc res.\n");
    (void)printf("  -n, --ns </proc/$pid/ns/net>                ns path.\n");
    (void)printf("  -M, --ns_mode <0 or 1>                      ns_mode with (exclusive: 0) | (shared: 1).\n");
    (void)printf("  -l, --min_id  <0 - U32_MAX>                 min reserved jetty id, U32_MAX means invalid.\n");
    (void)printf("  -u, --max_id  <0 - U32_MAX>                 max reserved jetty id, U32_MAX means invalid.\n");
    return 0;
}

static bool is_cmd_legacy(admin_config_t *cfg)
{
    if (cfg->argc == 0) {
        return false;
    }

    const char *legacy_cmds[] = {
        "add_eid",  "del_eid",     "set_eid_mode", "show_stats",         "show_res",
        "list_res", "set_ns_mode", "set_dev_ns",   "set_reserved_jetty",
    };
    const size_t legacy_cmds_count = sizeof(legacy_cmds) / sizeof(legacy_cmds[0]);

    for (size_t i = 0; i < legacy_cmds_count; ++i) {
        if (strncmp(legacy_cmds[i], cfg->argv[0], strlen(legacy_cmds[i]) + 1) == 0) {
            return true;
        }
    }
    return false;
}

int exec_cmd(admin_config_t *cfg, const admin_cmd_t *cmds)
{
    const char *cmd_name = pop_arg(cfg);
    if (cmd_name == NULL) {
        return cmds[0].func(cfg);
    }

    const admin_cmd_t *cmd = cmds + 1;
    while (cmd->name) {
        if (strncmp(cmd->name, cmd_name, strlen(cmd->name) + 1) == 0) {
            return cmd->func(cfg);
        }
        cmd++;
    }

    printf("Unknown cmd '%s'.\n", cmd_name);
    return 0;
}

bool is_ubc(const char *dev_name)
{
    char *device_path = calloc(1, DEV_PATH_MAX);
    if (device_path == NULL) {
        return false;
    }

    if (snprintf(device_path, DEV_PATH_MAX - 1, "%s/%s/device", SYS_CLASS_PATH, dev_name) <= 0) {
        (void)printf("snprintf failed, dev:%s.\n", dev_name);
        free(device_path);
        return false;
    }

    const uint32_t device_id_ubc = 0xa001;
    uint32_t device_id;
    (void)admin_parse_file_value_u32(device_path, "device", &device_id);

    free(device_path);
    return device_id == device_id_ubc;
}

int admin_cmd_main(admin_config_t *cfg)
{
    if (is_cmd_legacy(cfg)) {
        printf("Warning: This command is deprecated and may be removed in future versions.\n");

        if (cfg->help) {
            cmd_main_usage(cfg);
            return 0;
        }

        static const admin_cmd_t cmds_legacy[] = {
            {NULL, cmd_main_usage},
            {"add_eid", admin_cmd_add_eid_legacy},
            {"del_eid", admin_cmd_del_eid_legacy},
            {"set_eid_mode", admin_cmd_set_eid_mode_legacy},
            {"show_stats", admin_cmd_show_stats_legacy},
            {"show_res", admin_cmd_show_res_legacy},
            {"list_res", admin_cmd_list_res_legacy},
            {"set_ns_mode", admin_cmd_set_ns_mode_legacy},
            {"set_dev_ns", admin_cmd_set_dev_ns_legacy},
            {0},
        };
        return exec_cmd(cfg, cmds_legacy);
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_main_usage},   //
        {"show", admin_cmd_show}, //
        {"agg", admin_cmd_agg},   //
        {"dev", admin_cmd_dev},   //
        {"eid", admin_cmd_eid},   //
        {0},                      //
    };
    return exec_cmd(cfg, cmds);
}
