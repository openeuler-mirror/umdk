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

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "urma_types.h"
#include "admin_parameters.h"
#include "admin_file_ops.h"
#include "ub_util.h"
#include "urma_cmd.h"
#include "admin_netlink.h"
#include "admin_cmd.h"
typedef struct netlink_cb_par {
    uint32_t type;
} netlink_cb_par;


static int urma_admin_get_ns_fd(const char *ns)
{
    int ns_fd;

    /* todo: validate input */
    ns_fd = open(ns, O_RDONLY | O_CLOEXEC);
    if (ns_fd == -1) {
        (void)printf("failed to open ns file %s, errno:%d", ns,  errno);
        return ns_fd;
    }
    return ns_fd;
}

static int cmd_nlsend(struct nl_sock *sock, int genl_id, urma_cmd_hdr_t *hdr)
{
    void *msg_hdr;
    struct nl_msg *msg;
    int ret = 0, nlmsg_flags = 0;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        (void)printf("Unable to allocate netlink message\n");
        return -1;
    }

    if (hdr->command == URMA_CORE_CMD_QUERY_RES) {
        nlmsg_flags = NLM_F_DUMP;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, nlmsg_flags, (uint8_t)hdr->command,
        UBCORE_GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        (void)printf("Unable to write genl header\n");
        nlmsg_free(msg);
        return -1;
    }

    ret = nla_put_u32(msg, UBCORE_HDR_ARGS_LEN, hdr->args_len);
    if (ret < 0) {
        (void)printf("Unable to add args_len: %d\n", ret);
        nlmsg_free(msg);
        return ret;
    }

    ret = nla_put_u64(msg, UBCORE_HDR_ARGS_ADDR, hdr->args_addr);
    if (ret < 0) {
        (void)printf("Unable to add args_addr: %d\n", ret);
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        (void)printf("Netlink send failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr->command);
        nlmsg_free(msg);
        return ret;
    }

    nlmsg_free(msg);
    return ret;
}

static struct nl_sock *alloc_and_connect_nl(int *genl_id)
{
    int ret;
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        (void)printf("Failed to nl_socket_alloc\n");
        return NULL;
    }
    ret = genl_connect(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_connect, ret:%d, errno:%d\n", ret, errno);
        nl_socket_free(sock);
        return NULL;
    }
    *genl_id = genl_ctrl_resolve(sock, UBCORE_GENL_FAMILY_NAME);
    if (*genl_id < 0) {
        (void)printf("Resolving of \"%s\" failed, ret:%d\n", UBCORE_GENL_FAMILY_NAME, *genl_id);
        nl_close(sock);
        nl_socket_free(sock);
        return NULL;
    }
    return sock;
}

static int urma_admin_cmd_add_eid(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
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
    if (strlen(cfg->ns) > 0 && (ns_fd = urma_admin_get_ns_fd(cfg->ns)) < 0) {
        (void)printf("set ns failed, cmd:%u, ns %s.\n", hdr.command, cfg->ns);
        return -1;
    }
    arg.in.ns_fd = ns_fd;
    ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)close(ns_fd);
        (void)printf("cmd_nlsend failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    (void)close(ns_fd);
    return 0;
}

static int urma_admin_cmd_del_eid(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_update_eid_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_DEL_EID;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_update_eid_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_index = cfg->idx;
    arg.in.ns_fd = -1;
    ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("cmd_nlsend failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

static int urma_admin_cmd_set_eid_mode(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
{
    int ret;
    urma_cmd_hdr_t hdr;
    admin_core_cmd_set_eid_mode_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_SET_EID_MODE;
    hdr.args_len = (uint32_t)sizeof(admin_core_cmd_set_eid_mode_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_mode = cfg->dynamic_eid_mode;
    ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("cmd_nlsend failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    return 0;
}

int admin_add_eid(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    /* Automatically switch to static mode */
    if (urma_admin_cmd_set_eid_mode(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to urma admin set eid mode, errno:%d\n", errno);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }
    if (urma_admin_cmd_add_eid(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to urma admin add eid, errno:%d\n", errno);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }
    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

int admin_del_eid(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    /* Automatically switch to static mode */
    if (urma_admin_cmd_set_eid_mode(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to urma admin set eid mode, errno:%d\n", errno);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }
    if (urma_admin_cmd_del_eid(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to urma admin del eid, errno:%d\n", errno);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }
    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

int admin_set_eid_mode(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    if (urma_admin_cmd_set_eid_mode(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to urma admin del eid, errno:%d\n", errno);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }
    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

static int urma_admin_cmd_show_utp(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
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

    ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("cmd_nlsend failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    (void)printf("*************utp info**************\n");
    (void)printf("tpn                 : %u\n", (uint32_t)utp_info.utpn);
    (void)printf("flag                : %u\n", utp_info.flag.value);
    (void)printf("data_udp_start      : %hu\n", utp_info.data_udp_start);
    (void)printf("udp_range           : %u\n", (uint32_t)utp_info.udp_range);
    return 0;
}

int admin_show_utp(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }

    if (urma_admin_cmd_show_utp(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to urma admin show utp, errno:%d\n", errno);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
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

static int admin_cmd_query_stats(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
{
    urma_cmd_hdr_t hdr;
    admin_cmd_query_stats_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_STATS;
    hdr.args_len = (uint32_t)sizeof(admin_cmd_query_stats_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    arg.in.key = cfg->key.key;
    arg.in.type = (uint32_t)cfg->key.type;

    int ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("Failed to cmd_nlsend, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        return ret;
    }
    admin_print_stats(&arg);
    return 0;
}

int admin_show_stats(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    if (admin_cmd_query_stats(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

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

static inline void admin_print_res_upi(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_UPI_VAL) {
        tool_res_upi_val_t *val = (tool_res_upi_val_t *)nla_data(head);
        (void)printf("upi                 : %u\n", val->upi);
    }
}

static void admin_print_res_vtp(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_VTP_VAL) {
        tool_res_vtp_val_t *val = (tool_res_vtp_val_t *)nla_data(head);
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
}

static void admin_print_res_tp(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_TP_VAL) {
        tool_res_tp_val_t *val = (tool_res_tp_val_t *)nla_data(head);
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
}

static void admin_print_res_tpg(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_TPG_TP_CNT) {
            (void)printf("tp_cnt              : %u\n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_TPG_DSCP) {
            (void)printf("dscp                : %u\n", (uint32_t)nla_get_u8(nla));
            (void)printf("tp_list             : ");
        }

        if (type == UBCORE_RES_TPG_TP_VAL) {
            (void)printf("%u ", nla_get_u32(nla));
        }
    }
    (void)printf("\n");
}

static void admin_print_res_utp(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_UTP_VAL) {
        tool_res_utp_val_t *val = (tool_res_utp_val_t *)nla_data(head);
        (void)printf("utp                 : %u\n", (uint32_t)val->utpn);
        (void)printf("flag                : %u\n", val->flag.value);
        (void)printf("data_udp_start      : %hu\n", val->data_udp_start);
        (void)printf("udp_range           : %u\n", (uint32_t)val->udp_range);
    }
}

static void admin_print_res_jfs(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_JFS_VAL) {
        tool_res_jfs_val_t *val = (tool_res_jfs_val_t *)nla_data(head);
        (void)printf("jfs_id              : %u\n", val->jfs_id);
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state,
            urma_jetty_state_to_string(val->state));
        (void)printf("depth               : %u\n", val->depth);
        (void)printf("pri                 : %u\n", (uint32_t)val->pri);
        (void)printf("jfc_id              : %u\n", val->jfc_id);
    }
}

static void admin_print_res_jfr(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_JFR_VAL) {
        tool_res_jfr_val_t *val = (tool_res_jfr_val_t *)nla_data(head);
        (void)printf("jfr_id              : %u\n", val->jfr_id);
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jfr_state_to_string(val->state));
        (void)printf("depth               : %u\n", val->depth);
        (void)printf("jfc_id              : %u\n", val->jfc_id);
    }
}

static void admin_print_res_jetty(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_JETTY_VAL) {
        tool_res_jetty_val_t *val = (tool_res_jetty_val_t *)nla_data(head);
        (void)printf("jetty_id            : %u\n", val->jetty_id);
        (void)printf("send_jfc_id         : %u\n", val->send_jfc_id);
        (void)printf("recv_jfc_id         : %u\n", val->recv_jfc_id);
        (void)printf("jfr_id              : %u\n", val->jfr_id);
        (void)printf("jfs_depth           : %u\n", val->jfs_depth);
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state,
            urma_jetty_state_to_string(val->state));
        (void)printf("pri                 : %u\n", (uint32_t)val->pri);
    }
}

static void admin_print_res_jetty_grp(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_JTGRP_JETTY_CNT) {
            (void)printf("jetty_cnt           : %u\n", nla_get_u32(nla));
            (void)printf("jetty_list             : ");
        }

        if (type == UBCORE_RES_JTGRP_JETTY_VAL) {
            (void)printf("%u ", nla_get_u32(nla));
        }
    }
    (void)printf("\n");
}

static void admin_print_res_jfc(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_JFC_VAL) {
        tool_res_jfc_val_t *val = (tool_res_jfc_val_t *)nla_data(head);
        (void)printf("jfc_id              : %u\n", val->jfc_id);
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jfc_state_to_string(val->state));
        (void)printf("depth               : %u\n", val->depth);
    }
}

static void admin_print_res_rc(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_RC_VAL) {
        tool_res_rc_val_t *val = (tool_res_rc_val_t *)nla_data(head);
        (void)printf("type                : %u\n", val->type);
        (void)printf("rc_id               : %u\n", val->rc_id);
        (void)printf("depth               : %hu\n", val->depth);
        (void)printf("state               : %u\n", (uint32_t)val->state);
    }
}

static void admin_print_res_seg(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_SEGVAL_SEG_CNT) {
            (void)printf("seg_cnt             : %u\n", nla_get_u32(nla));
            (void)printf("seg_list            : \n");
        }

        if (type == UBCORE_RES_SEGVAL_SEG_VAL) {
            tool_seg_info_t *val = (tool_seg_info_t *)nla_data(nla);
            (void)printf("seg_list idx: %u\n", i);
            (void)printf("eid                 :"EID_FMT" \n", EID_ARGS(val->ubva.eid));
            (void)printf("va                  : %lu\n", val->ubva.va);
            (void)printf("len                 : %lu\n", val->len);
            (void)printf("token_id            : %u\n", val->token_id);
            (void)printf("\n");
            i++;
        }
    }
    (void)printf("\n");
}

static void admin_print_res_dev(struct nlattr *head, int len)
{
    int rem;
    uint32_t i = 0;
    struct nlattr *nla;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        switch (type) {
            case UBCORE_RES_DEV_SEG_CNT: {
                (void)printf("----------SEG----------\n");
                (void)printf("seg_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_SEG_VAL: {
                tool_seg_info_t *val = (tool_seg_info_t *)nla_data(nla);
                (void)printf("seg[%u].ubva.eid    \t:" EID_FMT "\n", i, EID_ARGS(val->ubva.eid));
                (void)printf("seg[%u].ubva.va     \t:%lu\n", i, val->ubva.va);
                (void)printf("seg[%u].len         \t:%lu\n", i, val->len);
                (void)printf("seg[%u].token_id      \t:%u\n", i, val->token_id);
                i++;
                break;
            }
            case UBCORE_RES_DEV_JFS_CNT: {
                (void)printf("\n----------JFS----------\n");
                (void)printf("jfs_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_JFS_VAL: {
                (void)printf("jfs_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_JFR_CNT: {
                (void)printf("\n----------JFR----------\n");
                (void)printf("jfr_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_JFR_VAL: {
                (void)printf("jfr_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_JFC_CNT: {
                (void)printf("\n----------JFR----------\n");
                (void)printf("jfc_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_JFC_VAL: {
                (void)printf("jfc_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_JETTY_CNT: {
                (void)printf("\n---------JETTY---------\n");
                (void)printf("jetty_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_JETTY_VAL: {
                (void)printf("jetty_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_JTGRP_CNT: {
                (void)printf("\n------JETTY_GROUP------\n");
                (void)printf("jetty_group_cnt     :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_JTGRP_VAL: {
                (void)printf("jetty_group_id[%u]   \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_RC_CNT: {
                (void)printf("\n----------RC-----------\n");
                (void)printf("rc_cnt              :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_RC_VAL: {
                (void)printf("rc_id[%u]           \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_VTP_CNT: {
                (void)printf("\n----------VTP----------\n");
                (void)printf("vtp_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_VTP_VAL: {
                (void)printf("vtp_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_TP_CNT: {
                (void)printf("\n----------TP-----------\n");
                (void)printf("tp_cnt              :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_TP_VAL: {
                (void)printf("tp_id[%u]           \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_TPG_CNT: {
                (void)printf("\n----------TPG----------\n");
                (void)printf("tpg_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_TPG_VAL: {
                (void)printf("tpg_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            case UBCORE_RES_DEV_UTP_CNT: {
                (void)printf("\n----------UTP----------\n");
                (void)printf("utp_cnt             :%u \n", nla_get_u32(nla));
                i = 0;
                break;
            }
            case UBCORE_RES_DEV_UTP_VAL: {
                (void)printf("utp_id[%u]          \t:%u\n", i, nla_get_u32(nla));
                i++;
                break;
            }
            default:
                break;
        }
    }
    (void)printf("\n");
}

static void print_query_res(struct nlattr *attr_ptr, netlink_cb_par *cb_par, int len)
{
    (void)printf("**********%s**********\n", g_query_res_type[cb_par->type]);
    switch (cb_par->type) {
        case TOOL_RES_KEY_TPG:
            admin_print_res_tpg(attr_ptr, len);
            break;
        case TOOL_RES_KEY_JETTY_GROUP:
            admin_print_res_jetty_grp(attr_ptr, len);
            break;
        case TOOL_RES_KEY_SEG:
            admin_print_res_seg(attr_ptr, len);
            break;
        case TOOL_RES_KEY_DEV_CTX:
            admin_print_res_dev(attr_ptr, len);
            break;
        case TOOL_RES_KEY_UPI:
            admin_print_res_upi(attr_ptr);
            break;
        case TOOL_RES_KEY_VTP:
            admin_print_res_vtp(attr_ptr);
            break;
        case TOOL_RES_KEY_TP:
            admin_print_res_tp(attr_ptr);
            break;
        case TOOL_RES_KEY_UTP:
            admin_print_res_utp(attr_ptr);
            break;
        case TOOL_RES_KEY_JFS:
            admin_print_res_jfs(attr_ptr);
            break;
        case TOOL_RES_KEY_JFR:
            admin_print_res_jfr(attr_ptr);
            break;
        case TOOL_RES_KEY_JETTY:
            admin_print_res_jetty(attr_ptr);
            break;
        case TOOL_RES_KEY_JFC:
            admin_print_res_jfc(attr_ptr);
            break;
        case TOOL_RES_KEY_RC:
            admin_print_res_rc(attr_ptr);
            break;
        default:
            break;
    }
}

static int cb_handler(struct nl_msg *msg, void *arg)
{
    (void)printf("enter cb\n");
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int len = genlmsg_attrlen(genlhdr, 0);

    netlink_cb_par *cb_par = (netlink_cb_par *)arg;
    print_query_res(attr_ptr, cb_par, len);

    return 0;
}

static int admin_cmd_query_res(struct nl_sock *sock, const tool_config_t *cfg, int genl_id, netlink_cb_par *cb_arg)
{
    admin_cmd_query_res_t *arg;
    urma_cmd_hdr_t hdr;
    arg = calloc(1, sizeof(admin_cmd_query_res_t));
    if (arg == NULL) {
        return -1;
    }

    arg->in.key = cfg->key.key;
    arg->in.type = cfg->key.type;
    arg->in.key_ext = cfg->key.key_ext;
    arg->in.key_cnt = cfg->key.key_cnt;
    (void)memcpy(arg->in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    cb_arg->type = arg->in.type;

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_RES;
    hdr.args_len = (uint32_t)sizeof(admin_cmd_query_res_t);
    hdr.args_addr = (uint64_t)arg;

    int ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("Failed to cmd_nlsend, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        free(arg);
        return ret;
    }

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_recvmsgs_default, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
    }
    free(arg);
    return 0;
}

int admin_show_res(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    netlink_cb_par nl_cb_agr;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    (void)nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, cb_handler, &nl_cb_agr);
    if (admin_cmd_query_res(sock, cfg, genl_id, &nl_cb_agr) < 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

static int ns_cb_handler(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static int admin_nl_send_recv(struct nl_sock *sock, struct nl_msg *msg)
{
    int ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        (void)printf("Netlink send failed, ret:%d, errno: %d..\n", ret, errno);
        return ret;
    }

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Netlink recv failed, ret:%d, errno:%d.\n", ret, errno);
    }
    return ret;
}

int admin_set_ns_mode(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, ns_cb_handler, NULL);

    void *msg_hdr;
    struct nl_msg *msg;
    int ret = 0, nlmsg_flags = 0;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        (void)printf("Unable to allocate netlink message\n");
        ret = -ENOMEM;
        goto close_sock;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, nlmsg_flags, URMA_CORE_SET_NS_MODE,
        UBCORE_GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        (void)printf("Unable to write genl header\n");
        ret = -ENOMEM;
        goto out;
    }

    ret = nla_put_u8(msg, UBCORE_ATTR_NS_MODE, cfg->ns_mode);
    if (ret < 0) {
        (void)printf("Unable to add ns mode: %d\n", ret);
        goto out;
    }

    ret = admin_nl_send_recv(sock, msg);

out:
    nlmsg_free(msg);
close_sock:
    nl_close(sock);
    nl_socket_free(sock);
    return ret;
}

int admin_set_dev_ns(const tool_config_t *cfg)
{
    int ret = 0;
    int ns_fd = -1;

    if (strlen(cfg->ns) == 0) {
        (void)printf("invalid ns path %s.\n", cfg->ns);
        return -1;
    }
    ns_fd = urma_admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("set ns failed, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        ret = -1;
        goto close_ns_fd;
    }

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, ns_cb_handler, NULL);

    void *msg_hdr;
    struct nl_msg *msg;
    int nlmsg_flags = 0;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        (void)printf("Unable to allocate netlink message\n");
        ret = -ENOMEM;
        goto close_sock;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, nlmsg_flags, URMA_CORE_SET_DEV_NS,
        UBCORE_GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        (void)printf("Unable to write genl header\n");
        ret = -ENOMEM;
        goto out;
    }

    ret = nla_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    if (ret < 0) {
        (void)printf("Unable to add device name: %d\n", ret);
        goto out;
    }

    ret = nla_put_u32(msg, UBCORE_ATTR_NS_FD, ns_fd);
    if (ret < 0) {
        (void)printf("Unable to add ns fd: %d\n", ret);
        goto out;
    }

    ret = admin_nl_send_recv(sock, msg);
out:
    nlmsg_free(msg);
close_sock:
    nl_close(sock);
    nl_socket_free(sock);
close_ns_fd:
    (void)close(ns_fd);
    return ret;
}
