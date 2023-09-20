/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: ioctl command source file for urma_admin
 * Author: Chen Yutao
 * Create: 2023-03-14
 * Note:
 * History: 2023-03-14   create file
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "urma_types.h"
#include "admin_parameters.h"
#include "admin_file_ops.h"
#include "ub_util.h"
#include "urma_cmd.h"
#include "admin_cmd.h"

#define UBCORE_DEV_PATH "/dev/ubcore"

static int urma_admin_cmd_set_utp(int ubcore_fd, const tool_config_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_set_utp_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_SET_UTP;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_set_utp_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    (void)memcpy(arg.in.eid, cfg->eid.raw, URMA_EID_SIZE);
    arg.in.transport_type = admin_read_dev_file_value_u32(cfg->dev_name, "transport_type");
    arg.in.spray_en = cfg->utp_port.spray_en;
    arg.in.data_udp_start = cfg->utp_port.src_port_start;
    arg.in.udp_range = cfg->utp_port.range_port;
    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

int admin_set_utp(const tool_config_t *cfg)
{
    int dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd == -1) {
        (void)printf("Failed to open %s, errno:%d\n", UBCORE_DEV_PATH, errno);
        return -1;
    }
    if (urma_admin_cmd_set_utp(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin set utp, errno:%d\n", errno);
        (void)close(dev_fd);
        return -1;
    }
    (void)close(dev_fd);
    return 0;
}

static int urma_admin_cmd_show_utp(int ubcore_fd, const tool_config_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_show_utp_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_SHOW_UTP;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_show_utp_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    (void)memcpy(arg.in.eid, cfg->eid.raw, URMA_EID_SIZE);
    arg.in.transport_type = admin_read_dev_file_value_u32(cfg->dev_name, "transport_type");
    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

int admin_show_udp(const tool_config_t *cfg)
{
    int dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd == -1) {
        (void)printf("Failed to open %s, errno:%d\n", UBCORE_DEV_PATH, errno);
        return -1;
    }
    if (urma_admin_cmd_show_utp(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin show utp, errno:%d\n", errno);
        (void)close(dev_fd);
        return -1;
    }
    (void)close(dev_fd);
    return 0;
}

static inline void admin_print_stats(const admin_cmd_query_stats_t *arg)
{
    (void)printf("tx_pkt              : %lu\n", arg->out.tx_pkt);
    (void)printf("rx_pkt              : %lu\n", arg->out.rx_pkt);
    (void)printf("tx_bytes            : %lu\n", arg->out.tx_bytes);
    (void)printf("rx_bytes            : %lu\n", arg->out.rx_bytes);
    (void)printf("tx_pkt_err          : %lu\n", arg->out.tx_pkt_err);
    (void)printf("rx_pkt_err          : %lu\n", arg->out.rx_pkt_err);
}

static int admin_cmd_query_stats(int dev_fd, const tool_config_t *cfg)
{
    urma_cmd_hdr_t hdr;
    admin_cmd_query_stats_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_STATS;
    hdr.args_len = sizeof(admin_cmd_query_stats_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    (void)memcpy(arg.in.eid, cfg->eid.raw, URMA_EID_SIZE);
    arg.in.tp_type = admin_read_dev_file_value_u32(cfg->dev_name, "transport_type");
    arg.in.key = cfg->key.key;
    arg.in.type = (uint32_t)cfg->key.type;

    int ret = ioctl(dev_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("Failed to ioctl, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        return ret;
    }
    admin_print_stats(&arg);
    return 0;
}

int admin_show_stats(const tool_config_t *cfg)
{
    char dev_path[FILE_PATH_MAX] = {0};
    int dev_fd;

    dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd < 0) {
        (void)printf("Failed to open dev_path: %s, errno: %d.\n", dev_path, errno);
        return -1;
    }
    if (admin_cmd_query_stats(dev_fd, cfg) != 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        (void)close(dev_fd);
        return -1;
    }

    (void)close(dev_fd);
    return 0;
}

static const size_t g_query_res_size[] = {
    [0]                        = 0,
    [TOOL_RES_KEY_UPI]         = sizeof(tool_res_upi_val_t),
    [TOOL_RES_KEY_TP]          = sizeof(tool_res_tp_val_t),
    [TOOL_RES_KEY_TPG]         = 0,
    [TOOL_RES_KEY_UTP]         = sizeof(tool_res_utp_val_t),
    [TOOL_RES_KEY_JFS]         = sizeof(tool_res_jfs_val_t),
    [TOOL_RES_KEY_JFR]         = sizeof(tool_res_jfr_val_t),
    [TOOL_RES_KEY_JETTY]       = sizeof(tool_res_jetty_val_t),
    [TOOL_RES_KEY_JETTY_GROUP] = 0,
    [TOOL_RES_KEY_JFC]         = sizeof(tool_res_jfc_val_t),
    [TOOL_RES_KEY_SEG]         = sizeof(tool_res_seg_val_t),
    [TOOL_RES_KEY_DEV_CTX]     = sizeof(tool_res_dev_val_t)
};

static const char *g_query_res_type[] = {
    [0]                        = NULL,
    [TOOL_RES_KEY_UPI]         = "RES_UPI",
    [TOOL_RES_KEY_TP]          = "RES_TP",
    [TOOL_RES_KEY_TPG]         = NULL,
    [TOOL_RES_KEY_UTP]         = "RES_UTP",
    [TOOL_RES_KEY_JFS]         = "RES_JFS",
    [TOOL_RES_KEY_JFR]         = "RES_JFR",
    [TOOL_RES_KEY_JETTY]       = "RES_JETTY",
    [TOOL_RES_KEY_JETTY_GROUP] = NULL,
    [TOOL_RES_KEY_JFC]         = "RES_JFC",
    [TOOL_RES_KEY_SEG]         = "RES_SEG",
    [TOOL_RES_KEY_DEV_CTX]     = "RES_DEV_CTX"
};

static const char *g_admin_tp_state[] = {
    "RESET",
    "RTR",
    "RTS",
    "SUSPENDED",
    "ERR"
};

static inline void admin_print_res_upi(const admin_cmd_query_res_t *arg)
{
    tool_res_upi_val_t *val = (tool_res_upi_val_t *)arg->out.addr;
    (void)printf("upi                 : %u\n", val->upi);
}

static void admin_print_res_tp(const admin_cmd_query_res_t *arg)
{
    tool_res_tp_val_t *val = (tool_res_tp_val_t *)arg->out.addr;
    (void)printf("tpn                 : %u\n", val->tpn);
    (void)printf("psn                 : %u\n", val->psn);
    (void)printf("pri                 : %u\n", (uint32_t)val->pri);
    (void)printf("oor                 : %u\n", (uint32_t)val->oor);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, g_admin_tp_state[val->state]);
    (void)printf("data_udp_start      : %u\n", (uint32_t)val->data_udp_start);
    (void)printf("ack_udp_start       : %u\n", (uint32_t)val->ack_udp_start);
    (void)printf("udp_range           : %u\n", (uint32_t)val->udp_range);
    (void)printf("spray_en            : %u\n", val->spray_en);
}

static void admin_print_res_utp(const admin_cmd_query_res_t *arg)
{
    tool_res_utp_val_t *val = (tool_res_utp_val_t *)arg->out.addr;
    (void)printf("utp                 : %u\n", (uint32_t)val->utp);
    (void)printf("data_udp_start      : %u\n", (uint32_t)val->data_udp_start);
    (void)printf("udp_range           : %u\n", (uint32_t)val->udp_range);
}

static void admin_print_res_jfs(const admin_cmd_query_res_t *arg)
{
    tool_res_jfs_val_t *val = (tool_res_jfs_val_t *)arg->out.addr;
    (void)printf("jfs_id              : %u\n", val->jfs_id);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jetty_state_to_string(val->state));
    (void)printf("depth               : %u\n", val->depth);
    (void)printf("pri                 : %u\n", (uint32_t)val->pri);
    (void)printf("jfc_id              : %u\n", val->jfc_id);
}

static void admin_print_res_jfr(const admin_cmd_query_res_t *arg)
{
    tool_res_jfr_val_t *val = (tool_res_jfr_val_t *)arg->out.addr;
    (void)printf("jfr_id              : %u\n", val->jfr_id);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jfr_state_to_string(val->state));
    (void)printf("depth               : %u\n", val->depth);
    (void)printf("pri                 : %u\n", (uint32_t)val->pri);
    (void)printf("jfc_id              : %u\n", val->jfc_id);
}

static void admin_print_res_jetty(const admin_cmd_query_res_t *arg)
{
    tool_res_jetty_val_t *val = (tool_res_jetty_val_t *)arg->out.addr;
    (void)printf("jetty_id            : %u\n", val->jetty_id);
    (void)printf("send_jfc_id         : %u\n", val->send_jfc_id);
    (void)printf("recv_jfc_id         : %u\n", val->recv_jfc_id);
    (void)printf("jfr_id              : %u\n", val->jfr_id);
    (void)printf("jfs_depth           : %u\n", val->jfs_depth);
    (void)printf("jfr_depth           : %u\n", val->jfr_depth);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jetty_state_to_string(val->state));
    (void)printf("pri                 : %u\n", (uint32_t)val->pri);
}

static void admin_print_res_jfc(const admin_cmd_query_res_t *arg)
{
    tool_res_jfc_val_t *val = (tool_res_jfc_val_t *)arg->out.addr;
    (void)printf("jfc_id              : %u\n", val->jfc_id);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jfc_state_to_string(val->state));
    (void)printf("depth               : %u\n", val->depth);
}

static void admin_print_res_seg(const admin_cmd_query_res_t *arg)
{
    tool_res_seg_val_t *val = (tool_res_seg_val_t *)arg->out.addr;
    (void)printf("eid                 :"EID_FMT" \n", EID_ARGS(val->ubva.eid));
    (void)printf("uasid               : %u\n", val->ubva.uasid);
    (void)printf("va                  : %lu\n", val->ubva.va);
    (void)printf("len                 : %lu\n", val->len);
    (void)printf("key_id              : %u\n", val->key_id);
    (void)printf("key                 : %u\n", val->key.key);
}

static void admin_print_res_dev(const admin_cmd_query_res_t *arg)
{
    uint32_t i;
    tool_res_dev_val_t *val = (tool_res_dev_val_t *)arg->out.addr;

    (void)printf("----------SEG----------\n");
    (void)printf("seg_cnt             :%u \n", val->seg_cnt);
    for (i = 0; i < val->seg_cnt; i++) {
        (void)printf("seg[%u].ubva.eid    \t:"EID_FMT"\n", i, EID_ARGS(val->seg_list[i].ubva.eid));
        (void)printf("seg[%u].ubva.uasid  \t:%u\n", i, val->seg_list[i].ubva.uasid);
        (void)printf("seg[%u].ubva.va     \t:%lu\n", i, val->seg_list[i].ubva.va);
        (void)printf("seg[%u].len         \t:%lu\n", i, val->seg_list[i].len);
        (void)printf("seg[%u].key_id      \t:%u\n", i, val->seg_list[i].key_id);
    }
    (void)printf("\n----------JFS----------\n");
    (void)printf("jfs_cnt             :%u \n", val->jfs_cnt);
    for (i = 0; i < val->jfs_cnt; i++) {
        (void)printf("jfs_id[%u]          \t:%u\n", i, val->jfs_list[i]);
    }
    (void)printf("\n----------JFR----------\n");
    (void)printf("jfr_cnt             :%u \n", val->jfr_cnt);
    for (i = 0; i < val->jfr_cnt; i++) {
        (void)printf("jfr_id[%u]           \t:%u\n", i, val->jfr_list[i]);
    }
    (void)printf("\n----------JFC----------\n");
    (void)printf("jfc_cnt             :%u \n", val->jfc_cnt);
    for (i = 0; i < val->jfc_cnt; i++) {
        (void)printf("jfc_id[%u]           \t:%u\n", i, val->jfc_list[i]);
    }
    (void)printf("\n---------JETTY---------\n");
    (void)printf("jetty_cnt           :%u \n", val->jetty_cnt);
    for (i = 0; i < val->jetty_cnt; i++) {
        (void)printf("jetty_id[%u]         \t:%u\n", i, val->jetty_list[i]);
    }
    (void)printf("\n------JETTY_GROUP------\n");
    (void)printf("jetty_group_cnt     :%u \n", val->jetty_group_cnt);
    for (i = 0; i < val->jetty_group_cnt; i++) {
        (void)printf("jetty_group_id[%u]   \t:%u\n", i, val->jetty_group_list[i]);
    }
    (void)printf("\n----------TP-----------\n");
    (void)printf("tp_cnt              :%u \n", val->tp_cnt);
    for (i = 0; i < val->tp_cnt; i++) {
        (void)printf("tp_id[%u]           \t:%u\n", i, val->tp_list[i]);
    }
    (void)printf("\n----------TPG----------\n");
    (void)printf("tpg_cnt             :%u \n", val->tpg_cnt);
    for (i = 0; i < val->tpg_cnt; i++) {
        (void)printf("tpg_id[%u]          \t:%u\n", i, val->tpg_list[i]);
    }
    (void)printf("\n----------UTP----------\n");
    (void)printf("utp_cnt             :%u \n", val->utp_cnt);
    for (i = 0; i < val->utp_cnt; i++) {
        (void)printf("utp_id[%u]          \t:%u\n", i, val->utp_list[i]);
    }
    (void)printf("\n");
}

static void admin_print_res(admin_cmd_query_res_t *arg)
{
    (void)printf("**********%s**********\n", g_query_res_type[arg->in.type]);
    switch (arg->in.type) {
        case TOOL_RES_KEY_UPI:
            admin_print_res_upi(arg);
            break;
        case TOOL_RES_KEY_TP:
            admin_print_res_tp(arg);
            break;
        case TOOL_RES_KEY_UTP:
            admin_print_res_utp(arg);
            break;
        case TOOL_RES_KEY_JFS:
            admin_print_res_jfs(arg);
            break;
        case TOOL_RES_KEY_JFR:
            admin_print_res_jfr(arg);
            break;
        case TOOL_RES_KEY_JETTY:
            admin_print_res_jetty(arg);
            break;
        case TOOL_RES_KEY_JFC:
            admin_print_res_jfc(arg);
            break;
        case TOOL_RES_KEY_SEG:
            admin_print_res_seg(arg);
            break;
        case TOOL_RES_KEY_DEV_CTX:
            admin_print_res_dev(arg);
            break;
        default:
            break;
    }
}

static void admin_dealloc_res_dev(const tool_config_t *cfg, uint64_t addr)
{
    tool_res_dev_val_t *dev = (tool_res_dev_val_t *)addr;
    if (dev->seg_list != NULL) {
        free(dev->seg_list);
        dev->seg_list = NULL;
    }
    if (dev->jfs_list != NULL) {
        free(dev->jfs_list);
        dev->jfs_list = NULL;
    }
    if (dev->jfr_list != NULL) {
        free(dev->jfr_list);
        dev->jfr_list = NULL;
    }
    if (dev->jfc_list != NULL) {
        free(dev->jfc_list);
        dev->jfc_list = NULL;
    }
    if (dev->jetty_list != NULL) {
        free(dev->jetty_list);
        dev->jetty_list = NULL;
    }
    if (dev->jetty_group_list != NULL) {
        free(dev->jetty_group_list);
        dev->jetty_group_list = NULL;
    }
    if (dev->tp_list != NULL) {
        free(dev->tp_list);
        dev->tp_list = NULL;
    }
    if (dev->tpg_list != NULL) {
        free(dev->tpg_list);
        dev->tpg_list = NULL;
    }
    if (dev->utp_list != NULL) {
        free(dev->utp_list);
        dev->utp_list = NULL;
    }
}

static int admin_alloc_res_dev(const tool_config_t *cfg, uint64_t addr)
{
    tool_res_dev_val_t *dev = (tool_res_dev_val_t *)addr;
    uint32_t max_jfs = admin_read_dev_file_value_u32(cfg->dev_name, "max_jfs");
    uint32_t max_jfr = admin_read_dev_file_value_u32(cfg->dev_name, "max_jfr");
    uint32_t max_jfc = admin_read_dev_file_value_u32(cfg->dev_name, "max_jfc");
    uint32_t max_len = max_jfs > max_jfr ? max_jfs : max_jfr;

    dev->seg_cnt = max_len;
    dev->seg_list = (tool_seg_info_t *)calloc(1, sizeof(tool_seg_info_t) * max_len);
    if (dev->seg_list == NULL) {
        return -1;
    }
    dev->jfs_cnt = max_jfs;
    dev->jfs_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_jfs);
    if (dev->jfs_list == NULL) {
        goto free_seg_list;
    }
    dev->jfr_cnt = max_jfr;
    dev->jfr_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_jfr);
    if (dev->jfr_list == NULL) {
        goto free_jfs_list;
    }
    dev->jfc_cnt = max_jfc;
    dev->jfc_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_jfc);
    if (dev->jfc_list == NULL) {
        goto free_jfr_list;
    }
    dev->jetty_cnt = max_len;
    dev->jetty_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->jetty_list == NULL) {
        goto free_jfc_list;
    }
    dev->jetty_group_cnt = max_len;
    dev->jetty_group_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->jetty_group_list == NULL) {
        goto free_jetty_list;
    }
    dev->tp_cnt = max_len;
    dev->tp_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->tp_list == NULL) {
        goto free_jetty_group_list;
    }
    dev->tpg_cnt = max_len;
    dev->tpg_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->tpg_list == NULL) {
        goto free_tp_list;
    }
    dev->utp_cnt = max_len;
    dev->utp_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->utp_list == NULL) {
        goto free_tpg_list;
    }

    return 0;
free_tpg_list:
    free(dev->tpg_list);
free_tp_list:
    free(dev->tp_list);
free_jetty_group_list:
    free(dev->jetty_group_list);
free_jetty_list:
    free(dev->jetty_list);
free_jfc_list:
    free(dev->jfc_list);
free_jfr_list:
    free(dev->jfr_list);
free_jfs_list:
    free(dev->jfs_list);
free_seg_list:
    free(dev->seg_list);
    return -1;
}

static int admin_cmd_ioctl_res(int dev_fd, const tool_config_t *cfg, uint64_t addr)
{
    urma_cmd_hdr_t hdr;
    admin_cmd_query_res_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_RES;
    hdr.args_len = (uint32_t)sizeof(admin_cmd_query_res_t);
    hdr.args_addr = (uint64_t)&arg;

    if (cfg->key.type == TOOL_RES_KEY_DEV_CTX && admin_alloc_res_dev(cfg, addr) != 0) {
        return -1;
    }
    arg.in.key = cfg->key.key;
    /* type cannot be 0/TOOL_RES_KEY_TPG/TOOL_RES_KEY_JETTY_GROUP here */
    arg.in.type = cfg->key.type;
    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    (void)memcpy(arg.in.eid, cfg->eid.raw, URMA_EID_SIZE);
    arg.in.tp_type = admin_read_dev_file_value_u32(cfg->dev_name, "transport_type");
    arg.out.addr = addr;
    arg.out.len = (uint32_t)g_query_res_size[cfg->key.type];

    int ret = ioctl(dev_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("Failed to ioctl, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        admin_dealloc_res_dev(cfg, addr);
        return ret;
    }
    admin_print_res(&arg);
    if (cfg->key.type == TOOL_RES_KEY_DEV_CTX) {
        admin_dealloc_res_dev(cfg, addr);
    }
    return 0;
}

static int admin_cmd_query_res(int dev_fd, const tool_config_t *cfg)
{
    void *addr = calloc(1, g_query_res_size[cfg->key.type]);
    if (addr == NULL) {
        (void)printf("Failed to alloc res addr, type: %u.\n", cfg->key.type);
        return -1;
    }

    if (admin_cmd_ioctl_res(dev_fd, cfg, (uint64_t)addr) != 0) {
        (void)printf("Failed to query res by ioctl, type: %u.\n", cfg->key.type);
        free(addr);
        return -1;
    }
    free(addr);
    return 0;
}

int admin_show_res(const tool_config_t *cfg)
{
    char dev_path[FILE_PATH_MAX] = {0};
    int dev_fd;

    if (cfg->specify_device == false || (cfg->eid.in6.interface_id == 0 && cfg->eid.in6.subnet_prefix == 0)) {
        (void)printf("The device and eid must be specified in the show res command.\n");
        return -1;
    }

    dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd < 0) {
        (void)printf("Failed to open ubcore dev: %s, errno: %d.\n", dev_path, errno);
        return -1;
    }
    if (admin_cmd_query_res(dev_fd, cfg) != 0) {
        (void)printf("Failed to query res by ioctl.\n");
        (void)close(dev_fd);
        return -1;
    }

    (void)close(dev_fd);
    return 0;
}