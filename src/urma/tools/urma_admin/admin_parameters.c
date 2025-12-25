/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: parse parameters for urma_admin
 * Author: Qian Guoxin
 * Create: 2023-01-04
 * Note:
 * History: 2023-01-04   create file
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "admin_file_ops.h"
#include "admin_log.h"

#include "admin_parameters.h"

int admin_str_to_u8(const char *buf, uint8_t *u8)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > UCHAR_MAX) {
        return -ERANGE;
    }
    *u8 = (uint8_t)ret;
    return 0;
}

int admin_str_to_u16(const char *buf, uint16_t *u16)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > USHRT_MAX) {
        return -ERANGE;
    }
    *u16 = (uint16_t)ret;
    return 0;
}

int admin_str_to_u32(const char *buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > UINT_MAX) {
        return -ERANGE;
    }
    *u32 = (uint32_t)ret;
    return 0;
}

int admin_str_to_u64(const char *buf, uint64_t *u64)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }

    *u64 = ret;
    return 0;
}

static void usage(const char *argv0)
{
    (void)printf("Usage: %s command [command options]\n", argv0);
    (void)printf(" %s URMA configuration tool, chips do not support some values, which might be invalid.\n", argv0);
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
}

static tool_cmd_type_t parse_command(const char *argv1)
{
    int i;

    tool_cmd_t cmd[] = {{"show", TOOL_CMD_SHOW},
                        {"add_eid", TOOL_CMD_ADD_EID},
                        {"del_eid", TOOL_CMD_DEL_EID},
                        {"set_eid_mode", TOOL_CMD_SET_EID_MODE},
                        {"show_stats", TOOL_CMD_SHOW_STATS},
                        {"show_res", TOOL_CMD_SHOW_RES},
                        {"set_ns_mode", TOOL_CMD_SET_NS_MODE},
                        {"set_dev_ns", TOOL_CMD_SET_DEV_NS},
                        {"set_reserved_jetty", TOOL_CMD_SET_RESERVED_JETTY},
                        {"list_res", TOOL_CMD_LIST_RES},
                        {"show_topo", TOOL_CMD_SHOW_TOPO_INFO}};

    for (i = 0; i < (int)TOOL_CMD_NUM; i++) {
        if (strlen(argv1) != strlen(cmd[i].cmd)) {
            continue;
        }
        if (strcmp(argv1, cmd[i].cmd) == 0) {
            return cmd[i].type;
        }
    }

    return TOOL_CMD_NUM;
}

#define IPV4_MAP_IPV6_PREFIX 0x0000ffff
#define EID_STR_MIN_LEN      3
static inline void ipv4_map_to_eid(uint32_t ipv4, urma_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int admin_str_to_eid(const char *buf, urma_eid_t *eid)
{
    int ret;
    uint32_t ipv4;
    if (buf == NULL || strlen(buf) <= EID_STR_MIN_LEN || eid == NULL) {
        (void)printf("Invalid argument.\n");
        return -EINVAL;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return 0;
    }
    int err_ipv6 = errno;

    // ipv4 addr: xx.xx.xx.xx
    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        ipv4_map_to_eid(be32toh(ipv4), eid);
        return 0;
    }
    int err_ipv4 = errno;

    // ipv4 value: 0x12345  or abcdef or 12345
    ret = admin_str_to_u32(buf, &ipv4);
    if (ret == 0) {
        ipv4_map_to_eid(ipv4, eid);
        return 0;
    }

    (void)printf("format error, ipv6: %d, ipv4:%d, errno:%d.\n", err_ipv6, err_ipv4, errno);
    return -EINVAL;
}

static void init_tool_cfg(tool_config_t *cfg)
{
    (void)memset(cfg, 0, sizeof(tool_config_t));
    cfg->specify_device = false;
    cfg->whole_info = false;
    cfg->ue_idx = OWN_UE_IDX;
}

static int check_query_type(const tool_config_t *cfg)
{
    if (cfg->cmd == TOOL_CMD_SHOW_STATS) {
        if (cfg->key.type < TOOL_STATS_KEY_VTP || cfg->key.type > TOOL_STATS_KEY_URMA_DEV) {
            (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
            return -1;
        }
        if (cfg->key.type == TOOL_STATS_KEY_TPG || cfg->key.type == TOOL_STATS_KEY_JETTY_GROUP) {
            (void)printf("Type: %d currently not supported.\n", (int)cfg->key.type);
            return -1;
        }
    }
    if (cfg->cmd == TOOL_CMD_SHOW_RES) {
        if (cfg->key.type < TOOL_RES_KEY_VTP || cfg->key.type > TOOL_RES_KEY_DEV_TA) {
            (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
            return -1;
        }
    }
    return 0;
}

static bool check_dev_name(char *dev_name)
{
    bool ret = false;
    DIR *cdev_dir;
    struct dirent *dent;

    cdev_dir = opendir(CDEV_PATH);
    if (cdev_dir == NULL) {
        (void)printf("%s open failed, errno: %d.\n", CDEV_PATH, errno);
        return false;
    }

    while ((dent = readdir(cdev_dir)) != NULL) {
        if (strcmp(dent->d_name, dev_name) == 0) {
            ret = true;
            break;
        }
    }

    if (closedir(cdev_dir) < 0) {
        (void)printf("Failed to close dir: %s, errno: %d.\n", CDEV_PATH, errno);
    }
    return ret;
}

static const struct option g_urma_admin_long_options[] = {
    {"help", no_argument, NULL, 'h'},                //
    {"dev", required_argument, NULL, 'd'},           //
    {"eid", required_argument, NULL, 'e'},           //
    {"eid_mode", no_argument, NULL, 'm'},            //
    {"ue_idx", required_argument, NULL, 'v'},        //
    {"idx", required_argument, NULL, 'i'},           //
    {"whole", no_argument, NULL, 'w'},               //
    {"resource_type", required_argument, NULL, 'R'}, //
    {"key", required_argument, NULL, 'k'},           //
    {"key_ext", required_argument, NULL, 'K'},       //
    {"key_cnt", required_argument, NULL, 'C'},       //
    {"ns", required_argument, NULL, 'n'},            //
    {"ns_mode", required_argument, NULL, 'M'},       //
    {"min_id", required_argument, NULL, 'l'},        //
    {"max_id", required_argument, NULL, 'u'},        //
    {NULL, no_argument, NULL, '\0'},                 //
};

static int admin_parse_dev_name(char *buf, tool_config_t *cfg)
{
    if (strnlen(buf, URMA_ADMIN_MAX_DEV_NAME) + 1 > URMA_ADMIN_MAX_DEV_NAME || check_dev_name(buf) == false) {
        (void)printf("dev_name:%s out of range(%d) or invalid.\n", buf, URMA_ADMIN_MAX_DEV_NAME);
        URMA_ADMIN_LOG("dev_name:%s out of range(%d) or invalid.\n", buf, URMA_ADMIN_MAX_DEV_NAME);
        return -1;
    }
    cfg->specify_device = true;
    (void)memcpy(cfg->dev_name, buf, strlen(buf));
    return 0;
}

static int admin_parse_resource_type(char *buf, tool_config_t *cfg)
{
    if (admin_str_to_u32(buf, &cfg->key.type) != 0) {
        return -1;
    }
    if (check_query_type(cfg) != 0) {
        (void)printf("Failed to check query type: %u.\n", cfg->key.type);
        URMA_ADMIN_LOG("Failed to check query type: %u.\n", cfg->key.type);
        return -1;
    }
    return 0;
}

static int admin_parse_ns(char *buf, tool_config_t *cfg)
{
    if (strnlen(buf, URMA_ADMIN_MAX_NS_PATH) + 1 > URMA_ADMIN_MAX_NS_PATH) {
        (void)printf("ns path:%s out of range(%d) or invalid.\n", buf, URMA_ADMIN_MAX_NS_PATH);
        URMA_ADMIN_LOG("ns path:%s out of range(%d) or invalid.\n", buf, URMA_ADMIN_MAX_NS_PATH);
        return -1;
    }
    if (snprintf(cfg->ns, URMA_ADMIN_MAX_NS_PATH, "%s", buf) <= 0) {
        URMA_ADMIN_LOG("Failed to prepare buf.\n");
        return -1;
    }
    return 0;
}

static int admin_inner_parse_args(int argc, char *argv[], tool_config_t *cfg)
{
    int ret = 0;
    while (1) {
        int c;
        c = getopt_long(argc, argv, "C:hd:e:mv:i:wR:k:K:n:M:u:l:", g_urma_admin_long_options, NULL);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'C':
                ret = admin_str_to_u32(optarg, &cfg->key.key_cnt);
                break;
            case 'h':
                cfg->help = true;
                usage(argv[0]);
                return 0;
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
                ret = admin_parse_resource_type(optarg, cfg);
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
            case 'u':
                ret = admin_str_to_u32(optarg, &cfg->max_rsvd_jetty_id);
                break;
            case 'l':
                ret = admin_str_to_u32(optarg, &cfg->min_rsvd_jetty_id);
                break;
            default:
                usage(argv[0]);
                return -1;
        }
        if (ret != 0) {
            (void)printf("Please check the legality of parameters\n");
            URMA_ADMIN_LOG("Please check the legality of parameters\n");
            return -1;
        }
    }
    if (optind < argc - 1) {
        URMA_ADMIN_LOG("optind < argc - 1\n");
        usage(argv[0]);
        return -1;
    }
    return 0;
}

int admin_parse_args(int argc, char *argv[], tool_config_t *cfg)
{
    int ret = 0;

    if (argc == 1 || cfg == NULL) {
        URMA_ADMIN_LOG("Invalid parameter\n.");
        usage(argv[0]);
        return -1;
    }

    init_tool_cfg(cfg);
    /* First parse the command */
    cfg->cmd = parse_command(argv[1]);

    /* Second parse the options */
    ret = admin_inner_parse_args(argc, argv, cfg);
    if (ret != 0) {
        return -1;
    }

    /* Increase illegal cmd return error */
    if (cfg->cmd == TOOL_CMD_NUM && cfg->help == false) {
        URMA_ADMIN_LOG("cfg->cmd == TOOL_CMD_NUM\n");
        usage(argv[0]);
        return -1;
    }
    return 0;
}
