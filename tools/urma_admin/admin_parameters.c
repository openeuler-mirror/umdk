/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: parse parameters for urma_admin
 * Author: Qian Guoxin
 * Create: 2023-01-04
 * Note:
 * History: 2023-01-04   create file
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>

#include "admin_file_ops.h"
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
    (void)printf("  %s   URMA configuration tool\n", argv0);
    (void)printf("\n");
    (void)printf("Command syntax:\n");
    (void)printf("  show [--dev] [--whole]                                 show all ubep devices info.\n");
    (void)printf("  add_eid <--dev> <--idx> [--ns /proc/$pid/ns/net]       add the eid of UB function entity\n");
    (void)printf("  del_eid <--dev> <--idx>                                del the eid of UB function entity.\n");
    (void)printf("  set_eid_mode <--dev> [--eid_mode]                      change the eid mode of pf ubep device.\n");
    (void)printf("  show_stats <--dev> <--type> <--key>                    show run stats of ubep device.\n");
    (void)printf("  show_res <--dev> <--type> <--key> [--key_ext]                                        \n");
    (void)printf("           [--key_cnt]                                   show resources of ubep device.\n");
    (void)printf("  list_res <--dev> <--type> [--key] [--key_ext]                                        \n");
    (void)printf("           [--key_cnt]                                   list resources of ubep device.\n");
    (void)printf("  set_ns_mode <--ns_mode (exclusive: 0) | (shared: 1) >  set ns mode for UB devices, \n");
    (void)printf("                                                         not support IB and IP currently.\n");
    (void)printf("  set_dev_ns <--dev> <--ns /proc/$pid/ns/net>            set net namespace of UB device.\n");
    (void)printf("Options:\n");
    (void)printf("  -h, --help                                  show help info.\n");
    (void)printf("  -d, --dev <dev_name>                        the name of ubep device.\n");
    (void)printf("  -e, --eid <eid>                             the eid of ubep device.\n");
    (void)printf("  -m, --eid_mode <eid_mode>                   the eid mode of ubep device,/\n");
    (void)printf("                                              (change to dynamic_mode: cmd with -m,\n");
    (void)printf("                                              change to static_mode: cmd without -m).\n");
    (void)printf("  -v, --fe_idx <fe_idx>                       the fe_idx of ubep device.\n" \
                 "                                              when fe_idx == 0xffff or empty, it refers to PF.\n");
    (void)printf("  -i, --idx <idx>                             idx defaults to 0.\n");
    (void)printf("  -w, --whole                                 show whole information.\n");
    (void)printf("  -R, --resource_type <type>                  config stats type with 4(jfs)/5(jfr)/ \n");
    (void)printf("                                              6(jetty)/7(jetty group, not support)/8(dev).\n");
    (void)printf("                                              config res type with \n");
    (void)printf("                                              5(jfs)/6(jfr)/\n");
    (void)printf("                                              7(jetty)/8(jetty_grp)/9(jfc)\n");
    (void)printf("                                              10(rc)/11(seg)/12(dev_ta_ctx).\n");
    (void)printf("  -k, --key <key>                             config stats/res key.\n");
    (void)printf("  -K, --key_ext <key_ext>                     config key_ext for vtp res.\n");
    (void)printf("  -C, --key_cnt <key>                         config key_cnt for rc res.\n");
    (void)printf("  -n, --ns </proc/$pid/ns/net>                ns path.\n");
    (void)printf("  -M, --ns_mode <0 or 1>                      ns_mode with (shared: 0) | (exclusive: 1).\n");
}

static tool_cmd_type_t parse_command(const char *argv1)
{
    int i;

    tool_cmd_t cmd[] = {
        {"show",            TOOL_CMD_SHOW},
        {"add_eid",         TOOL_CMD_ADD_EID},
        {"del_eid",         TOOL_CMD_DEL_EID},
        {"set_eid_mode",    TOOL_CMD_SET_EID_MODE},
        {"show_stats",      TOOL_CMD_SHOW_STATS},
        {"show_res",        TOOL_CMD_SHOW_RES},
        {"set_ns_mode",     TOOL_CMD_SET_NS_MODE},
        {"set_dev_ns",      TOOL_CMD_SET_DEV_NS},
        {"set_rsvd_jetty",  TOOL_CMD_SET_RSVD_JID_RANGE},
        {"list_res",        TOOL_CMD_LIST_RES}
    };

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
#define EID_STR_MIN_LEN 3
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

    (void)printf("%s format error, ipv6: %d, ipv4:%d, errno:%d.\n",
        buf, err_ipv6, err_ipv4, errno);
    return -EINVAL;
}

static void init_tool_cfg(tool_config_t *cfg)
{
    (void)memset(cfg, 0, sizeof(tool_config_t));
    cfg->specify_device = false;
    cfg->whole_info = false;
    cfg->fe_idx = OWN_FE_IDX;
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

int admin_parse_args(int argc, char *argv[], tool_config_t *cfg)
{
    int ret = 0;

    if (argc == 1 || cfg == NULL) {
        usage(argv[0]);
        return -1;
    }

    init_tool_cfg(cfg);
    /* First parse the command */
    cfg->cmd = parse_command(argv[1]);

    static const struct option long_options[] = {
        {"help",              no_argument,       NULL, 'h'},
        {"dev",               required_argument, NULL, 'd'},
        {"eid",               required_argument, NULL, 'e'},
        {"eid_mode",          no_argument,       NULL, 'm'},
        {"fe_idx",            required_argument, NULL, 'v'},
        {"idx",               required_argument, NULL, 'i'},
        {"whole",             no_argument,       NULL, 'w'},
        {"resource_type",     required_argument, NULL, 'R'},
        {"key",               required_argument, NULL, 'k'},
        {"key_ext",           required_argument, NULL, 'K'},
        {"key_cnt",           required_argument, NULL, 'C'},
        {"ns",                required_argument, NULL, 'n'},
        {"ns_mode",           required_argument, NULL, 'M'},
        {"rjid_max",          required_argument, NULL, 'u'},
        {"rjid_min",          required_argument, NULL, 'l'},
        {NULL,                no_argument,       NULL, '\0'}
    };

    /* Second parse the options */
    while (1) {
        int c;
        c = getopt_long(argc, argv, "C:hd:e:mv:i:wR:k:K:n:M:u:l:", long_options, NULL);
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
                if (strnlen(optarg, URMA_ADMIN_MAX_DEV_NAME) + 1 > URMA_ADMIN_MAX_DEV_NAME ||
                    check_dev_name(optarg) == false) {
                    (void)printf("dev_name:%s out of range(%d) or invalid.\n", optarg, URMA_ADMIN_MAX_DEV_NAME);
                    return -1;
                }
                cfg->specify_device = true;
                (void)memcpy(cfg->dev_name, optarg, strlen(optarg));
                break;
            case 'e':
                (void)admin_str_to_eid(optarg, &cfg->eid);
                break;
            case 'm':
                cfg->dynamic_eid_mode = true;
                break;
            case 'v':
                ret = admin_str_to_u16(optarg, &cfg->fe_idx);
                break;
            case 'i':
                ret = admin_str_to_u16(optarg, &cfg->idx);
                break;
            case 'w':
                cfg->whole_info = true;
                break;
            case 'R':
                ret = admin_str_to_u32(optarg, &cfg->key.type);
                if (check_query_type(cfg) != 0) {
                    (void)printf("Failed to check query type: %u.\n", cfg->key.type);
                    return -1;
                }
                break;
            case 'k':
                ret = admin_str_to_u32(optarg, &cfg->key.key);
                break;
            case 'K':
                (void)admin_str_to_u32(optarg, &cfg->key.key_ext);
                break;
            case 'n':
                if (strnlen(optarg, URMA_ADMIN_MAX_NS_PATH) + 1 > URMA_ADMIN_MAX_NS_PATH) {
                    (void)printf("ns path:%s out of range(%d) or invalid.\n", optarg, URMA_ADMIN_MAX_NS_PATH);
                    return -1;
                }
                (void)strncpy(cfg->ns, optarg, URMA_ADMIN_MAX_NS_PATH - 1);
                break;
            case 'M':
                ret = admin_str_to_u8(optarg, &cfg->ns_mode);
                break;
            case 'u':
                ret = admin_str_to_u32(optarg, &cfg->reserved_jetty_id_max);
                break;
            case 'l':
                ret = admin_str_to_u32(optarg, &cfg->reserved_jetty_id_min);
                break;
            default:
                usage(argv[0]);
                return -1;
        }
        if (ret != 0) {
            (void)printf("Please check the legality of parameters\n");
            return -1;
        }
    }

    if (optind < argc - 1) {
        usage(argv[0]);
        return -1;
    }
    /* Increase illegal cmd return error */
    if (cfg->cmd == TOOL_CMD_NUM) {
        return -1;
    }
    return 0;
}