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
    (void)printf("  set_eid_mode <--dev> <--eid_mode>                      change the eid mode of pf ubep device.\n");
    (void)printf("  set_cc_alg <--dev> <--cc_alg>                          set one or more congestion control/\n");
    (void)printf("                                                         algorithms for ubep device.\n");
    (void)printf("  set_upi <--dev> [--fe_idx] <--idx> <--upi>             set the upi of ubep device.\n");
    (void)printf("  show_upi <--dev> [--fe_idx]                            show the upi of ubep device.\n");
    (void)printf("  show_stats <--type> <--key>                            show run stats of ubep device.\n");
    (void)printf("  show_res <--type> <--key> [--key_ext] [--key_cnt]      show resources of ubep device.\n");
    (void)printf("Options:\n");
    (void)printf("  -c, --cc_alg                                algorithmic value: ((CC_PFC: 1) | (CC_DCQCN: 2) |/\n");
    (void)printf("                                              (CC_DCQCN_AND_NETWORK_CC: 4) | (CC_LDCP: 8) |/\n");
    (void)printf("                                              (CC_LDCP_AND_CAQM: 16) | (CC_LDCP_AND_OPEN_CC: 32)/\n");
    (void)printf("                                              | (CC_HC3: 64) | (CC_DIP: 128)).\n");
    (void)printf("  -h, --help                                  show help info.\n");
    (void)printf("  -d, --dev <dev_name>                        the name of ubep device.\n");
    (void)printf("  -e, --eid <eid>                             the eid of ubep device.\n");
    (void)printf("  -m, --eid_mode <eid_mode>                   the eid mode of ubep device,/\n");
    (void)printf("                                              (dynamic_mode: 1, static_mode: 0).\n");
    (void)printf("  -v, --fe_idx <fe_idx>                       the fe_idx of ubep device.\n" \
                 "                                              when fe_idx == 0xffff or empty, it refers to PF.\n");
    (void)printf("  -i, --idx <idx>                             idx defaults to 0.\n");
    (void)printf("  -u, --upi <upi>                             upi value.\n");
    (void)printf("  -w, --whole                                 show whole information.\n");
    (void)printf("  -E, --spray_en                              end-side port number hashing enabled.\n");
    (void)printf("  -s, --src_port <port_id>                    udp data port start.\n");
    (void)printf("  -r, --range_port <range>                    udp range port.\n");
    (void)printf("  -R, --resource_type <type>                  config stats type with 1(tp)/2(tpg, not support)/\n");
    (void)printf("                                              3(jfs)/4(jfr)/5(jetty)/6(jetty group, not support).\n");
    (void)printf("                                              config res type with 1(upi)/2(vtp)/\n");
    (void)printf("                                              3(tp)/4(tpg)/5(utp)/6(jfs)/7(jfr)/\n");
    (void)printf("                                              8(jetty)/9(jetty_grp)/10(jfc)\n");
    (void)printf("                                              11(rc)/12(seg)/13(dev_ctx).\n");
    (void)printf("  -k, --key <key>                             config stats/res key.\n");
    (void)printf("  -K, --key_ext <key_ext>                     config key_ext for vtp res.\n");
    (void)printf("  -C, --key_cnt <key>                         config key_cnt for rc res.\n");
}

static tool_cmd_type_t parse_command(const char *argv1)
{
    int i;

    tool_cmd_t cmd[] = {
        {"show",            TOOL_CMD_SHOW},
        {"add_eid",         TOOL_CMD_ADD_EID},
        {"del_eid",         TOOL_CMD_DEL_EID},
        {"set_eid_mode",    TOOL_CMD_SET_EID_MODE},
        {"set_cc_alg",      TOOL_CMD_SET_CC_ALG},
        {"set_upi",         TOOL_CMD_SET_UPI},
        {"show_upi",        TOOL_CMD_SHOW_UPI},
        {"show_utp",        TOOL_CMD_SHOW_UTP},
        {"show_stats",      TOOL_CMD_SHOW_STATS},
        {"show_res",        TOOL_CMD_SHOW_RES}
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
    cfg->utp_port.spray_en = false;
    cfg->whole_info = false;
    cfg->fe_idx = OWN_FE_IDX;
}

static int check_query_type(const tool_config_t *cfg)
{
    if (cfg->cmd == TOOL_CMD_SHOW_STATS) {
        if (cfg->key.type < TOOL_STATS_KEY_TP || cfg->key.type > TOOL_STATS_KEY_JETTY_GROUP) {
            (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
            return -1;
        }
        if (cfg->key.type == TOOL_STATS_KEY_TPG || cfg->key.type == TOOL_STATS_KEY_JETTY_GROUP) {
            (void)printf("Type: %d currently not supported.\n", (int)cfg->key.type);
            return -1;
        }
    }
    if (cfg->cmd == TOOL_CMD_SHOW_RES) {
        if (cfg->key.type < TOOL_RES_KEY_UPI || cfg->key.type > TOOL_RES_KEY_DEV_CTX) {
            (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
            return -1;
        }
    }
    return 0;
}

static bool check_dev_name(char *dev_name)
{
    bool ret = false;
    DIR *class_dir;
    struct dirent *dent;

    class_dir = opendir(SYS_CLASS_PATH);
    if (class_dir == NULL) {
        (void)printf("%s open failed, errno: %d.\n", SYS_CLASS_PATH, errno);
        return false;
    }

    while ((dent = readdir(class_dir)) != NULL) {
        if (strcmp(dent->d_name, dev_name) == 0) {
            ret = true;
            break;
        }
    }

    if (closedir(class_dir) < 0) {
        (void)printf("Failed to close dir: %s, errno: %d.\n", SYS_CLASS_PATH, errno);
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
        {"cc_alg",            required_argument, NULL, 'c'},
        {"help",              no_argument,       NULL, 'h'},
        {"dev",               required_argument, NULL, 'd'},
        {"eid",               required_argument, NULL, 'e'},
        {"eid_mode",          no_argument,       NULL, 'm'},
        {"fe_idx",            required_argument, NULL, 'v'},
        {"idx",               required_argument, NULL, 'i'},
        {"upi",               required_argument, NULL, 'u'},
        {"whole",             no_argument,       NULL, 'w'},
        {"spray_en",          no_argument,       NULL, 'E'},
        {"src_port",          required_argument, NULL, 's'},
        {"range_port",        required_argument, NULL, 'r'},
        {"resource_type",     required_argument, NULL, 'R'},
        {"utp_id",            required_argument, NULL, 'p'},
        {"key",               required_argument, NULL, 'k'},
        {"key_ext",           required_argument, NULL, 'K'},
        {"key_cnt",           required_argument, NULL, 'C'},
        {"ns",                required_argument, NULL, 'n'},
        {NULL,                no_argument,       NULL, '\0'}
    };

    /* Second parse the options */
    while (1) {
        int c;
        c = getopt_long(argc, argv, "c:C:hd:e:Emv:i:u:ws:r:R:p:k:K:n:", long_options, NULL);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'c':
                ret = admin_str_to_u16(optarg, &cfg->cc_alg);
                break;
            case 'C':
                ret = admin_str_to_u32(optarg, &cfg->key.key_cnt);
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            case 'd':
                if (strlen(optarg) + 1 > URMA_ADMIN_MAX_DEV_NAME || check_dev_name(optarg) == false) {
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
            case 'u':
                ret = admin_str_to_u32(optarg, &cfg->upi);
                break;
            case 'w':
                cfg->whole_info = true;
                break;
            case 'E':
                cfg->utp_port.spray_en = true;
                break;
            case 's':
                ret = admin_str_to_u16(optarg, &cfg->utp_port.src_port_start);
                break;
            case 'r':
                ret = admin_str_to_u8(optarg, &cfg->utp_port.range_port);
                break;
            case 'p':
                ret = admin_str_to_u32(optarg, &cfg->utp_port.utpn);
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
                if (strlen(optarg) + 1 > URMA_ADMIN_MAX_NS_PATH) {
                    (void)printf("ns path:%s out of range(%d) or invalid.\n", optarg, URMA_ADMIN_MAX_NS_PATH);
                    return -1;
                }
                strncpy(cfg->ns, optarg, URMA_ADMIN_MAX_NS_PATH - 1);
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