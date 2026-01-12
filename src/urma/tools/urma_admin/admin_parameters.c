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
#include <fcntl.h>
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

void usage(const char *argv0)
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

int admin_parse_args(int argc, char *argv[], tool_config_t *cfg)
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
    return 0;
}

char *pop_arg(admin_config_t *cfg)
{
    if (cfg->argc <= 0) {
        return NULL;
    }

    char *arg = *cfg->argv;
    cfg->argc--;
    cfg->argv++;

    return arg;
}

int pop_arg_dev(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    if (arg == NULL) {
        printf("No device name specified.\n");
        return -EINVAL;
    }
    return admin_parse_dev_name(arg, cfg);
}

int pop_arg_ns(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    if (arg == NULL) {
        printf("No namespace specified.\n");
        return -EINVAL;
    }
    int ret = admin_parse_ns(arg, cfg);
    return ret;
}

int pop_arg_eid(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    int ret = admin_str_to_eid(arg, &cfg->eid);
    if (ret != 0) {
        printf("No eid specified.\n");
        return -EINVAL;
    }
    return ret;
}

int pop_arg_eid_idx(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    int ret = admin_str_to_u16(arg, &cfg->idx);
    if (ret != 0) {
        printf("No eid idx specified.\n");
        return -EINVAL;
    }
    return ret;
}

#define ADMIN_NET_NS_PATH_MAX_LEN  256
/* Path1 format: /var/run/netns/$ns_name */
#define ADMIN_NET_NS_PATH1_PREFIX  "/var/run/netns/"
#define ADMIN_NET_NS_PATH1_MIN_LEN strlen(ADMIN_NET_NS_PATH1_PREFIX)
/* Path2 format: /proc/$pid/ns/net */
#define ADMIN_NET_NS_PATH2_PREFIX  "/proc/"
#define ADMIN_NET_NS_PATH2_SUFFIX  "/ns/net"
/* The minimum length of path2: $pid occupies at least 1 character */
#define ADMIN_NET_NS_PATH2_MIN_LEN 14

static bool urma_validate_ns_path(const char *path)
{
    /* ns path is a special symbolic link, cannot be checked by realpath */
    /* check path format1: /var/run/netns/$ns_name->/proc/$pid/ns/net */
    size_t path_len = strnlen(path, ADMIN_NET_NS_PATH_MAX_LEN);
    if (path_len > ADMIN_NET_NS_PATH1_MIN_LEN && path_len < ADMIN_NET_NS_PATH_MAX_LEN &&
        (strncmp(path, ADMIN_NET_NS_PATH1_PREFIX, ADMIN_NET_NS_PATH1_MIN_LEN) == 0)) {
        /* check if there is still "/./" or "/../" after "ns/"-> check if there is any sub_str can be
           splitted by "/" */
        char ns_name[ADMIN_NET_NS_PATH_MAX_LEN + 1] = {0};
        /* check ns_name not containing "/" */
        int ret = sscanf(path + ADMIN_NET_NS_PATH1_MIN_LEN, "%[^/]", ns_name);
        if (ret < 0 || strlen(ns_name) + ADMIN_NET_NS_PATH1_MIN_LEN != path_len) {
            (void)printf("path 1 is invalid, ns_name: %s, ret: %d, errno: %d.\n", ns_name, ret, errno);
            return false;
        }
        return true;
    }

    /* check path format2: /proc/$pid/ns/net */
    if (path_len < ADMIN_NET_NS_PATH2_MIN_LEN || path_len >= ADMIN_NET_NS_PATH_MAX_LEN) {
        (void)printf("The len of ns realpath:%s is invalid, len: %lu.\n", path, path_len);
        return false;
    }

    /* /proc/ */
    size_t sub_str_len = strlen(ADMIN_NET_NS_PATH2_PREFIX);
    uint64_t offset = sub_str_len;
    if (offset >= path_len || strncmp(path, ADMIN_NET_NS_PATH2_PREFIX, sub_str_len) != 0) {
        (void)printf("path 2 is invalid, should start with '/proc/', path: %s.\n", path);
        return false;
    }

    /* pid */
    char num_str[ADMIN_NET_NS_PATH_MAX_LEN + 1] = {0};
    /* check sub_str only containing number */
    int success_len = sscanf(path + offset, "%[0-9]", num_str);
    /* The return value of sscanf_s is the number of string successfully matched */
    if (success_len != 1) {
        (void)printf("failed to get pid.\n");
        return false;
    }
    sub_str_len = strnlen(num_str, ADMIN_NET_NS_PATH_MAX_LEN);
    offset += sub_str_len;

    /* /ns/net */
    if (strcmp(path + offset, ADMIN_NET_NS_PATH2_SUFFIX) != 0) {
        (void)printf("path is not valid: should be /proc/pid/ns/net.\n");
        return false;
    }
    return true;
}

int admin_get_ns_fd(const char *ns)
{
    int ns_fd;
    /* validate input */
    if (urma_validate_ns_path(ns) == false) {
        return -1;
    }

    ns_fd = open(ns, O_RDONLY | O_CLOEXEC);
    if (ns_fd == -1) {
        (void)printf("failed to open ns file %s, errno:%d", ns, errno);
        return ns_fd;
    }
    return ns_fd;
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

bool is_1650(const char *dev_name)
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

    const uint32_t device_id_1650 = 0xa001;
    uint32_t device_id;
    (void)admin_parse_file_value_u32(device_path, "device", &device_id);

    free(device_path);
    return device_id == device_id_1650;
}
