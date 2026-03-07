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
#include <getopt.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "admin_log.h"
#include "admin_netlink.h"
#include "admin_parameters.h"

#include "admin_cmd.h"

static void version(void)
{
    printf("Version: 0.0.1\n");
}

static int usage(admin_config_t *cfg)
{
    printf("Usage: %s <command> [options]\n"
           "\n"
           "Commands:\n"
           "  show  Show information\n"
           "  dev   Device management operations\n"
           "  eid   EID management operations\n"
           "Run '%s <command> --help' for more information on a specific command.\n"
           "\n"
           "Options:\n"
           "  -h --help        Show this help and exit\n"
           "  -V --version     Show version and exit\n",
           cfg->filename,
           cfg->filename);

    printf("\n"
           "Legacy commands (deprecated):\n"
           "  add_eid <--dev> <--idx> [--ns /proc/$pid/ns/net]       add eid of UB device, only for uvs,\n"
           "                                                           control plane not support.\n"
           "  del_eid <--dev> <--idx>                                del eid of UB device, only for uvs,\n"
           "                                                           control plane not support.\n"
           "  set_eid_mode <--dev> [--eid_mode]                      change eid mode of MUE device, only for\n"
           "                                                           uvs, control plane not support.\n"
           "  show_stats <--dev> <--resource_type> <--key>           show run stats of UB device, \n"
           "                                                           control plane not support.\n"
           "  show_res <--dev> <--resource_type> <--key> [--key_ext]                                  \n"
           "           <--key_cnt>                                   show resources of UB device.\n"
           "  list_res <--dev> <--resource_type> [--key] [--key_ext]                               \n"
           "           [--key_cnt]                                   list resources of UB device.\n"
           "  set_ns_mode <--ns_mode (exclusive: 0) | (shared: 1) >  set ns mode for UB devices.\n"
           "  set_dev_ns <--dev> <--ns /proc/$pid/ns/net>            set net namespace of UB device.\n"
           "\n"
           "Legacy Options (deprecated):\n"
           "  -d, --dev <dev_name>                        the name of UB device.\n"
           "  -e, --eid <eid>                             the eid of UB device.\n"
           "  -m, --eid_mode <eid_mode>                   the eid mode of UB device,/\n"
           "                                              (change to dynamic_mode: cmd with -m,\n"
           "                                              change to static_mode: cmd without -m).\n"
           "  -v, --ue_idx <ue_idx>                       the ue_idx of ubep device.\n"
           "                                              when ue_idx == 0xffff or empty, it refers to MUE.\n"
           "  -i, --idx <idx>                             idx defaults to 0.\n"
           "  -w, --whole                                 show whole information.\n"
           "  -R, --resource_type <type>                  config stats type with 1(tp_id/vtp, not support)/\n"
           "                                                2(tp, not support)/3(tpg, not support)/4(jfs)/\n"
           "                                                5(jfr)/6(jetty)/\n"
           "                                                7(jetty group, not support)/8(dev).\n"
           "                                              config res type with 1(tp_id/vtp, not support)/\n"
           "                                                2(tp, not support)/3(tpg, not support)/\n"
           "                                                4(utp, not support)/5(jfs)/6(jfr)/7(jetty)/\n"
           "                                                8(jetty group)/9(jfc)/10(rc)/11(seg)/\n"
           "                                                12(dev ta, not support)/13(dev tp, not support).\n"
           "  -k, --key <key>                             config stats/res key, config stats key with: .\n"
           "                                                1(tp_id/vtpn, not support)/2(tpn, not support)/\n"
           "                                                3(tpgn, not support)/4(jfs_id)/5(jfr_id)/\n"
           "                                                6(jetty_id)/7(jetty group id, not support)/\n"
           "                                                8(dev, no key)\n"
           "                                              config res key with: \n"
           "                                                1(tp_id/vtpn, not support)/2(tpn, not support)/\n"
           "                                                3(tpgn, not support)/4(utpn, not support)/\n"
           "                                                5(jfs_id)/6(jfr_id)/7(jetty_id)/\n"
           "                                                8(jetty group id)/9(jfc_id)/\n"
           "                                                10(rc_id, not support)/11(token_id)/\n"
           "                                                12(eid, not support)/13(eid, not support).\n"
           "  -K, --key_ext <key_ext>                     config key_ext for tp_id/vtp res.\n"
           "  -C, --key_cnt <key>                         config key_cnt for rc res.\n"
           "  -n, --ns </proc/$pid/ns/net>                ns path.\n"
           "  -M, --ns_mode <0 or 1>                      ns_mode with (exclusive: 0) | (shared: 1).\n"
           "  -p, --priority  <0 - 15>                    the serial number of priority.\n"
           "  -u, --max_id  <0 - 15>                      the serial number of SL.\n");
    return 0;
}

static int parse_args(admin_config_t *cfg)
{
    static const struct option long_options[] = {
        {"dev", required_argument, NULL, 'd'},
        {"eid", required_argument, NULL, 'e'},
        {"eid_mode", no_argument, NULL, 'm'},
        {"ue_idx", required_argument, NULL, 'v'},
        {"idx", required_argument, NULL, 'i'},
        {"whole", no_argument, NULL, 'w'},
        {"resource_type", required_argument, NULL, 'R'},
        {"key", required_argument, NULL, 'k'},
        {"key_ext", required_argument, NULL, 'K'},
        {"key_cnt", required_argument, NULL, 'C'},
        {"ns", required_argument, NULL, 'n'},
        {"ns_mode", required_argument, NULL, 'M'},
        {"priority", required_argument, NULL, 'p'},
        {"sl", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, no_argument, NULL, '\0'},
    };

    int opt, ret = 0;
    while ((opt = getopt_long(cfg->argc, cfg->argv, "C:d:e:mv:i:wR:k:K:n:M:p:s:hV", long_options, NULL)) != -1) {
        switch (opt) {
            case 'C':
                ret = admin_str_to_u32(optarg, &cfg->key.key_cnt);
                break;
            case 'd':
                ret = admin_parse_dev_name(optarg, cfg);
                break;
            case 'e':
                (void)admin_str_to_eid(optarg, &cfg->eid);
                break;
            case 'm':
                cfg->dynamic_eid_mode = true;
                break;
            case 'v':
                ret = admin_str_to_u16(optarg, &cfg->ue_idx);
                break;
            case 'i':
                ret = admin_str_to_u16(optarg, &cfg->idx);
                break;
            case 'w':
                cfg->whole_info = true;
                break;
            case 'R':
                ret = admin_str_to_u32(optarg, &cfg->key.type);
                break;
            case 'k':
                ret = admin_str_to_u32(optarg, &cfg->key.key);
                break;
            case 'K':
                ret = admin_str_to_u32(optarg, &cfg->key.key_ext);
                break;
            case 'n':
                ret = admin_parse_ns(optarg, cfg);
                break;
            case 'M':
                ret = admin_str_to_u8(optarg, &cfg->ns_mode);
                break;
            case 'p':
                ret = admin_str_to_u8(optarg, &cfg->priority);
                break;
            case 's':
                ret = admin_str_to_u8(optarg, &cfg->SL);
                break;
            case 'h':
                cfg->help = true;
                break;
            case 'V':
                version();
                exit(EXIT_SUCCESS);
            case ':':
                printf("Option -%c requires an argument\n", optopt);
                URMA_ADMIN_LOG("Option -%c requires an argument\n", optopt);
                return -EINVAL;
            default:
                printf("Unknown option\n");
                URMA_ADMIN_LOG("Unknown option\n");
                return -EINVAL;
        }
        if (ret != 0) {
            const int option_offset = 2;
            printf("Invalid option %s\n", cfg->argv[optind - option_offset]);
            return -EINVAL;
        }
    }

    cfg->argc -= optind;
    cfg->argv += optind;
    return 0;
}

static bool is_cmd_legacy(admin_config_t *cfg)
{
    if (cfg->argc == 0) {
        return false;
    }

    const char *legacy_cmds[] = {
        "add_eid",
        "del_eid",
        "set_eid_mode",
        "show_stats",
        "show_res",
        "list_res",
        "set_ns_mode",
        "set_dev_ns",
    };
    const size_t legacy_cmds_count = sizeof(legacy_cmds) / sizeof(legacy_cmds[0]);

    for (size_t i = 0; i < legacy_cmds_count; ++i) {
        if (strncmp(legacy_cmds[i], cfg->argv[0], strlen(legacy_cmds[i]) + 1) == 0) {
            return true;
        }
    }
    return false;
}

int admin_cmd_main(admin_config_t *cfg)
{
    int ret = parse_args(cfg);
    if (ret != 0) {
        return ret;
    }

    if (is_cmd_legacy(cfg)) {
        printf("Warning: This command is deprecated and may be removed in future versions.\n");
        if (cfg->help) {
            return usage(cfg);
        }

        static const admin_cmd_t cmds_legacy[] = {
            {NULL, usage},
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
        {NULL, usage},
        {"show", admin_cmd_show},
        {"agg", admin_cmd_agg},
        {"dev", admin_cmd_dev},
        {"eid", admin_cmd_eid},
        {0},
    };
    return exec_cmd(cfg, cmds);
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

int exec_cmd(admin_config_t *cfg, const admin_cmd_t *cmds)
{
    const char *cmd_name = pop_arg(cfg);
    if (cmd_name == NULL) {
        return cmds[0].func(cfg);
    }

    const admin_cmd_t *cmd = cmds + 1;
    while (cmd->name) {
        if (strncmp(cmd->name, cmd_name, strnlen(cmd->name, MAX_CMDLINE_LEN) + 1) == 0) {
            return cmd->func(cfg);
        }
        cmd++;
    }

    printf("Unknown cmd '%s'.\n", cmd_name);
    return -EINVAL;
}
