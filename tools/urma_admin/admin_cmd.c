/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: ioctl command source file for urma_admin
 * Author: Chen Yutao
 * Create: 2023-03-14
 * Note:
 * History: 2023-03-14   create file
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sched.h>

#include "urma_types.h"
#include "admin_parameters.h"
#include "admin_file_ops.h"
#include "ub_util.h"
#include "urma_cmd.h"
#include "admin_cmd.h"

#define UBCORE_DEV_PATH "/dev/ubcore"

static int urma_admin_set_ns(const char *ns)
{
    /* todo: validate input */
    int ns_fd = open(ns, O_RDONLY | O_CLOEXEC);
    if (ns_fd == -1) {
        (void)printf("failed to open ns file %s, errno:%d", ns,  errno);
        return ns_fd;
    }
    if (setns(ns_fd, CLONE_NEWNET) == -1) {
        (void)close(ns_fd);
        (void)printf("failed to setns");
        return -1;
    }
    return ns_fd;
}

static int urma_admin_cmd_add_eid(int ubcore_fd, const tool_config_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_update_eid_t arg = {0};
    int ns_fd = -1;

    hdr.command = (uint32_t)URMA_CORE_CMD_ADD_EID;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_update_eid_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_index = cfg->idx;
    if (strlen(cfg->ns) > 0 && (ns_fd = urma_admin_set_ns(cfg->ns)) < 0) {
        (void)printf("set ns failed, cmd:%u, ns %s.\n", hdr.command, cfg->ns);
        return -1;
    }
    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)close(ns_fd);
        (void)printf("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    (void)close(ns_fd);
    return 0;
}

static int urma_admin_cmd_del_eid(int ubcore_fd, const tool_config_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_update_eid_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_DEL_EID;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_update_eid_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_index = cfg->idx;
    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

static int urma_admin_cmd_set_eid_mode(int ubcore_fd, const tool_config_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_set_eid_mode_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_SET_EID_MODE;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_set_eid_mode_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_mode = cfg->dynamic_eid_mode;
    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

int admin_add_eid(const tool_config_t *cfg)
{
    int dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd == -1) {
        (void)printf("Failed to open %s, errno:%d\n", UBCORE_DEV_PATH, errno);
        return -1;
    }
    /* Automatically switch to static mode */
    if (urma_admin_cmd_set_eid_mode(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin del eid, errno:%d\n", errno);
        (void)close(dev_fd);
        return -1;
    }
    if (urma_admin_cmd_add_eid(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin add eid, errno:%d\n", errno);
        (void)close(dev_fd);
        return -1;
    }
    (void)close(dev_fd);
    return 0;
}

int admin_del_eid(const tool_config_t *cfg)
{
    int dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd == -1) {
        (void)printf("Failed to open %s, errno:%d\n", UBCORE_DEV_PATH, errno);
        return -1;
    }
    /* Automatically switch to static mode */
    if (urma_admin_cmd_set_eid_mode(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin del eid, errno:%d\n", errno);
        (void)close(dev_fd);
        return -1;
    }
    if (urma_admin_cmd_del_eid(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin del eid, errno:%d\n", errno);
        (void)close(dev_fd);
        return -1;
    }
    (void)close(dev_fd);
    return 0;
}

int admin_set_eid_mode(const tool_config_t *cfg)
{
    int dev_fd = open(UBCORE_DEV_PATH, O_RDWR);
    if (dev_fd == -1) {
        (void)printf("Failed to open %s, errno:%d\n", UBCORE_DEV_PATH, errno);
        return -1;
    }
    if (urma_admin_cmd_set_eid_mode(dev_fd, cfg) != 0) {
        (void)printf("Failed to urma admin del eid, errno:%d\n", errno);
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
    tool_res_utp_val_t utp_info = {0};
    admin_core_cmd_show_utp_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_SHOW_UTP;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_show_utp_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    arg.out.addr = (uint64_t)&utp_info;
    arg.out.len = (uint32_t)sizeof(tool_res_utp_val_t);

    ret = ioctl(ubcore_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    (void)printf("*************utp info**************\n");
    (void)printf("tpn                 : %u\n", (uint32_t)utp_info.utpn);
    (void)printf("spray_en            : %d\n", utp_info.spray_en);
    (void)printf("data_udp_start      : %hu\n", utp_info.data_udp_start);
    (void)printf("udp_range           : %u\n", (uint32_t)utp_info.udp_range);
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
    hdr.args_len = (uint32_t)sizeof(admin_cmd_query_stats_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
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
    [TOOL_RES_KEY_VTP]         = sizeof(tool_res_vtp_val_t),
    [TOOL_RES_KEY_TP]          = sizeof(tool_res_tp_val_t),
    [TOOL_RES_KEY_TPG]         = sizeof(tool_res_tpg_val_t),
    [TOOL_RES_KEY_UTP]         = sizeof(tool_res_utp_val_t),
    [TOOL_RES_KEY_JFS]         = sizeof(tool_res_jfs_val_t),
    [TOOL_RES_KEY_JFR]         = sizeof(tool_res_jfr_val_t),
    [TOOL_RES_KEY_JETTY]       = sizeof(tool_res_jetty_val_t),
    [TOOL_RES_KEY_JETTY_GROUP] = sizeof(tool_res_jetty_grp_val_t),
    [TOOL_RES_KEY_JFC]         = sizeof(tool_res_jfc_val_t),
    [TOOL_RES_KEY_RC]          = sizeof(tool_res_rc_val_t),
    [TOOL_RES_KEY_SEG]         = sizeof(tool_res_seg_val_t),
    [TOOL_RES_KEY_DEV_CTX]     = sizeof(tool_res_dev_val_t)
};

static const char *g_query_res_type[] = {
    [0]                        = NULL,
    [TOOL_RES_KEY_UPI]         = "RES_UPI",
    [TOOL_RES_KEY_VTP]         = "RES_VTP",
    [TOOL_RES_KEY_TP]          = "RES_TP",
    [TOOL_RES_KEY_TPG]         = "RES_TPG",
    [TOOL_RES_KEY_UTP]         = "RES_UTP",
    [TOOL_RES_KEY_JFS]         = "RES_JFS",
    [TOOL_RES_KEY_JFR]         = "RES_JFR",
    [TOOL_RES_KEY_JETTY]       = "RES_JETTY",
    [TOOL_RES_KEY_JETTY_GROUP] = "RES_JETTY_GRP",
    [TOOL_RES_KEY_JFC]         = "RES_JFC",
    [TOOL_RES_KEY_RC]          = "RES_RC",
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

static void admin_print_res_vtp(const admin_cmd_query_res_t *arg)
{
    tool_res_vtp_val_t *val = (tool_res_vtp_val_t *)arg->out.addr;
    (void)printf("fe_idx              : %hu\n", val->fe_idx);
    (void)printf("vtpn                : %u\n", val->vtpn);
    (void)printf("local_eid           : "EID_FMT"\n", EID_ARGS(val->local_eid));
    (void)printf("local_jetty         : %u\n", val->local_jetty);
    (void)printf("peer_eid            : "EID_FMT"\n", EID_ARGS(val->peer_eid));
    (void)printf("per_jetty           : %u\n", val->peer_jetty);
    (void)printf("clan                : %s\n", val->flag.bs.clan_tp == 1 ? "TRUE" : "FALSE");
    (void)printf("migrate             : %s\n", val->flag.bs.migrate == 1 ? "TRUE" : "FALSE");
    (void)printf("trans_mode          : %u [%s]\n", (uint32_t)val->trans_mode,
        urma_trans_mode_to_string(val->trans_mode));

    if (val->flag.bs.clan_tp == 1) {
        (void)printf("ctpn                : %u\n", val->ctpn);
        return;
    }

    if (val->trans_mode == URMA_TM_RM || val->trans_mode == URMA_TM_RC) {
        (void)printf("tpgn                : %u\n", val->tpgn);
        return;
    }

    if (val->trans_mode == URMA_TM_UM) {
        (void)printf("utpn                : %u\n", val->utpn);
        return;
    }
}

static void admin_print_res_tp(const admin_cmd_query_res_t *arg)
{
    tool_res_tp_val_t *val = (tool_res_tp_val_t *)arg->out.addr;
    (void)printf("tpn                 : %u\n", val->tpn);
    (void)printf("tx_psn              : %u\n", val->tx_psn);
    (void)printf("rx_psn              : %u\n", val->rx_psn);
    (void)printf("dscp                : %u\n", (uint32_t)val->dscp);
    (void)printf("oor_en              : %u\n", (uint32_t)val->oor_en);
    (void)printf("selective_retrans_en: %u\n", (uint32_t)val->selective_retrans_en);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, g_admin_tp_state[val->state]);
    (void)printf("data_udp_start      : %hu\n", val->data_udp_start);
    (void)printf("ack_udp_start       : %hu\n", val->ack_udp_start);
    (void)printf("udp_range           : %u\n", (uint32_t)val->udp_range);
    (void)printf("spray_en            : %u\n", val->spray_en);
}

static void admin_print_res_tpg(const admin_cmd_query_res_t *arg)
{
    tool_res_tpg_val_t *val = (tool_res_tpg_val_t *)arg->out.addr;
    (void)printf("tp_cnt              : %u\n", val->tp_cnt);
    (void)printf("dscp                : %u\n", (uint32_t)val->dscp);

    (void)printf("tp_list             : ");
    for (uint32_t i = 0; i < val->tp_cnt; i++) {
        (void)printf("%u ", val->tp_list[i]);
    }
    (void)printf("\n");
}

static void admin_print_res_utp(const admin_cmd_query_res_t *arg)
{
    tool_res_utp_val_t *val = (tool_res_utp_val_t *)arg->out.addr;
    (void)printf("utp                 : %u\n", (uint32_t)val->utpn);
    (void)printf("spray_en            : %s\n", val->spray_en ? "true" : "false");
    (void)printf("data_udp_start      : %hu\n", val->data_udp_start);
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
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jetty_state_to_string(val->state));
    (void)printf("pri                 : %u\n", (uint32_t)val->pri);
}

static void admin_print_res_jetty_grp(const admin_cmd_query_res_t *arg)
{
    tool_res_jetty_grp_val_t *val = (tool_res_jetty_grp_val_t *)arg->out.addr;
    (void)printf("jetty_cnt           : %hu\n", val->jetty_cnt);
    (void)printf("jetty_list             : ");
    for (uint32_t i = 0; i < val->jetty_cnt; i++) {
        (void)printf("%u ", val->jetty_list[i]);
    }
    (void)printf("\n");
}

static void admin_print_res_jfc(const admin_cmd_query_res_t *arg)
{
    tool_res_jfc_val_t *val = (tool_res_jfc_val_t *)arg->out.addr;
    (void)printf("jfc_id              : %u\n", val->jfc_id);
    (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jfc_state_to_string(val->state));
    (void)printf("depth               : %u\n", val->depth);
}

static void admin_print_res_rc(const admin_cmd_query_res_t *arg)
{
    tool_res_rc_val_t *val = (tool_res_rc_val_t *)arg->out.addr;
    (void)printf("type                : %u\n", val->type);
    (void)printf("rc_id               : %u\n", val->rc_id);
    (void)printf("depth               : %hu\n", val->depth);
    (void)printf("state               : %u\n", (uint32_t)val->state);
}

static void admin_print_res_seg(const admin_cmd_query_res_t *arg)
{
    tool_res_seg_val_t *val = (tool_res_seg_val_t *)arg->out.addr;
    (void)printf("eid                 :"EID_FMT" \n", EID_ARGS(val->ubva.eid));
    (void)printf("va                  : %lu\n", val->ubva.va);
    (void)printf("len                 : %lu\n", val->len);
    (void)printf("token_id            : %u\n", val->token_id);
    (void)printf("token_value         : %u\n", val->token_value.token);
}

static void admin_print_res_dev(const admin_cmd_query_res_t *arg)
{
    uint32_t i;
    tool_res_dev_val_t *val = (tool_res_dev_val_t *)arg->out.addr;

    (void)printf("----------SEG----------\n");
    (void)printf("seg_cnt             :%u \n", val->seg_cnt);
    for (i = 0; i < val->seg_cnt; i++) {
        (void)printf("seg[%u].ubva.eid    \t:"EID_FMT"\n", i, EID_ARGS(val->seg_list[i].ubva.eid));
        (void)printf("seg[%u].ubva.va     \t:%lu\n", i, val->seg_list[i].ubva.va);
        (void)printf("seg[%u].len         \t:%lu\n", i, val->seg_list[i].len);
        (void)printf("seg[%u].token_id      \t:%u\n", i, val->seg_list[i].token_id);
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
    (void)printf("\n----------RC-----------\n");
    (void)printf("rc_cnt              :%u \n", val->rc_cnt);
    for (i = 0; i < val->rc_cnt; i++) {
        (void)printf("rc_id[%u]           \t:%u\n", i, val->rc_list[i]);
    }
    (void)printf("\n----------VTP----------\n");
    (void)printf("vtp_cnt             :%u \n", val->vtp_cnt);
    for (i = 0; i < val->vtp_cnt; i++) {
        (void)printf("vtp_id[%u]          \t:%u\n", i, val->vtp_list[i]);
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
        case TOOL_RES_KEY_VTP:
            admin_print_res_vtp(arg);
            break;
        case TOOL_RES_KEY_TP:
            admin_print_res_tp(arg);
            break;
        case TOOL_RES_KEY_TPG:
            admin_print_res_tpg(arg);
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
        case TOOL_RES_KEY_JETTY_GROUP:
            admin_print_res_jetty_grp(arg);
            break;
        case TOOL_RES_KEY_JFC:
            admin_print_res_jfc(arg);
            break;
        case TOOL_RES_KEY_RC:
            admin_print_res_rc(arg);
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

static inline void admin_dealloc_res_tp_list(const tool_config_t *cfg, uint64_t addr)
{
    tool_res_tpg_val_t *tpg = (tool_res_tpg_val_t *)addr;
    if (tpg == NULL || tpg->tp_list == NULL) {
        (void)printf("Invalid argument: tp_list.\n");
        return;
    }
    free(tpg->tp_list);
}

static inline int admin_alloc_res_tp_list(const tool_config_t *cfg, uint64_t addr)
{
#define ADMIN_MAX_TP_CNT_IN_GRP 32
    tool_res_tpg_val_t *tpg = (tool_res_tpg_val_t *)addr;
    tpg->tp_list = calloc(1, sizeof(uint32_t) * ADMIN_MAX_TP_CNT_IN_GRP);
    if (tpg->tp_list == NULL) {
        (void)printf("Failed to alloc tp_list.\n");
        return -1;
    }

    return 0;
}

static inline void admin_dealloc_res_jetty_list(const tool_config_t *cfg, uint64_t addr)
{
    tool_res_jetty_grp_val_t *jetty_grp = (tool_res_jetty_grp_val_t *)addr;
    if (jetty_grp == NULL || jetty_grp->jetty_list == NULL) {
        (void)printf("Invalid argument: jetty_list.\n");
        return;
    }
    free(jetty_grp->jetty_list);
}

static inline int admin_alloc_res_jetty_list(const tool_config_t *cfg, uint64_t addr)
{
    tool_res_jetty_grp_val_t *jetty_grp = (tool_res_jetty_grp_val_t *)addr;
    uint32_t max_jetty_in_grp = admin_read_dev_file_value_u32(cfg->dev_name, "max_jetty_in_jetty_grp");

    jetty_grp->jetty_list = calloc(1, sizeof(uint32_t) * max_jetty_in_grp);
    if (jetty_grp->jetty_list == NULL) {
        (void)printf("Failed to alloc jetty_list.\n");
        return -1;
    }

    return 0;
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
    if (dev->rc_list != NULL) {
        free(dev->rc_list);
        dev->rc_list = NULL;
    }
    if (dev->vtp_list != NULL) {
        free(dev->vtp_list);
        dev->vtp_list = NULL;
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
    dev->rc_cnt = max_len;
    dev->rc_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->rc_list == NULL) {
        goto free_jetty_group_list;
    }
    dev->vtp_cnt = max_len;
    dev->vtp_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->vtp_list == NULL) {
        goto free_rc_list;
    }
    dev->tp_cnt = max_len;
    dev->tp_list = (uint32_t *)calloc(1, sizeof(uint32_t) * max_len);
    if (dev->tp_list == NULL) {
        goto free_vtp_list;
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
free_vtp_list:
    free(dev->vtp_list);
free_rc_list:
    free(dev->rc_list);
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

    if (cfg->key.type == TOOL_RES_KEY_TPG && admin_alloc_res_tp_list(cfg, addr) != 0) {
        return -1;
    }
    if (cfg->key.type == TOOL_RES_KEY_JETTY_GROUP && admin_alloc_res_jetty_list(cfg, addr) != 0) {
        return -1;
    }
    if (cfg->key.type == TOOL_RES_KEY_DEV_CTX && admin_alloc_res_dev(cfg, addr) != 0) {
        return -1;
    }

    arg.in.key = cfg->key.key;
    arg.in.type = cfg->key.type;
    arg.in.key_ext = cfg->key.key_ext;
    arg.in.key_cnt = cfg->key.key_cnt;
    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    arg.out.addr = addr;
    arg.out.len = (uint32_t)g_query_res_size[cfg->key.type];

    int ret = ioctl(dev_fd, URMA_CORE_CMD, &hdr);
    if (ret != 0) {
        (void)printf("Failed to ioctl, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        goto deaalloc;
    }

    admin_print_res(&arg);
deaalloc:
    if (cfg->key.type == TOOL_RES_KEY_TPG) {
        admin_dealloc_res_tp_list(cfg, addr);
    }
    if (cfg->key.type == TOOL_RES_KEY_JETTY_GROUP) {
        admin_dealloc_res_jetty_list(cfg, addr);
    }
    if (cfg->key.type == TOOL_RES_KEY_DEV_CTX) {
        admin_dealloc_res_dev(cfg, addr);
    }
    return ret;
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

    if (cfg->specify_device == false) {
        (void)printf("The device must be specified in the show res command.\n");
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