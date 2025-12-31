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

typedef struct netlink_cb_par {
    uint32_t type;
    uint32_t key;
} netlink_cb_par;

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

    if (hdr->command == URMA_CORE_CMD_QUERY_RES || hdr->command == URMA_CORE_CMD_ADD_EID ||
        hdr->command == URMA_CORE_CMD_DEL_EID) {
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

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("query stats fail, please check input, ret:%d, errno:%d.\n", ret, errno);
        return ret;
    }

    admin_print_stats(&arg);
    return 0;
}

int admin_show_stats(tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    if (cfg->key.type < TOOL_STATS_KEY_VTP || cfg->key.type > TOOL_STATS_KEY_URMA_DEV) {
        (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
        return -1;
    }
    if (cfg->key.type == TOOL_STATS_KEY_TPG || cfg->key.type == TOOL_STATS_KEY_JETTY_GROUP) {
        (void)printf("Type: %d currently not supported.\n", (int)cfg->key.type);
        return -1;
    }
    if (cfg->key.type >= TOOL_STATS_KEY_VTP && cfg->key.type <= TOOL_STATS_KEY_TPG) {
        (void)printf("urma_admin do not support query tp stats.\n");
        return -1;
    }
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
    [0] = NULL,
    [TOOL_RES_KEY_VTP] = "RES_VTP",
    [TOOL_RES_KEY_TP] = "RES_TP",
    [TOOL_RES_KEY_TPG] = "RES_TPG",
    [TOOL_RES_KEY_UTP] = "RES_UTP",
    [TOOL_RES_KEY_JFS] = "RES_JFS",
    [TOOL_RES_KEY_JFR] = "RES_JFR",
    [TOOL_RES_KEY_JETTY] = "RES_JETTY",
    [TOOL_RES_KEY_JETTY_GROUP] = "RES_JETTY_GRP",
    [TOOL_RES_KEY_JFC] = "RES_JFC",
    [TOOL_RES_KEY_RC] = "RES_RC",
    [TOOL_RES_KEY_SEG] = "RES_SEG",
    [TOOL_RES_KEY_DEV_TA] = "RES_DEV_TA",
    [TOOL_RES_KEY_DEV_TP] = "RES_DEV_TP",
};

static void admin_print_res_jfs(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_JFS_VAL) {
        tool_res_jfs_val_t *val = (tool_res_jfs_val_t *)nla_data(head);
        (void)printf("jfs_id              : %u\n", val->jfs_id);
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jetty_state_to_string(val->state));
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
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state, urma_jetty_state_to_string(val->state));
        (void)printf("pri                 : %u\n", (uint32_t)val->pri);
    }
}

static void admin_print_res_jetty_grp(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_JTGRP_JETTY_CNT) {
            (void)printf("jetty_cnt           : %u\n", nla_get_u32(nla));
            (void)printf("jetty               : ");
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

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_SEGVAL_SEG_CNT) {
            (void)printf("seg_cnt             : %u\n", nla_get_u32(nla));
            (void)printf("seg                 : \n");
        }

        if (type == UBCORE_RES_SEGVAL_SEG_VAL) {
            tool_seg_info_t *val = (tool_seg_info_t *)nla_data(nla);
            (void)printf("seg_list idx: %u\n", i);
            (void)printf("eid                 :" EID_FMT " \n", EID_ARGS(val->ubva.eid));
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
            case UBCORE_RES_DEV_JFS_CNT: {
                (void)printf("\n----------JFS----------\n");
                (void)printf("jfs_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_JFR_CNT: {
                (void)printf("\n----------JFR----------\n");
                (void)printf("jfr_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_JFC_CNT: {
                (void)printf("\n----------JFC----------\n");
                (void)printf("jfc_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_JETTY_CNT: {
                (void)printf("\n---------JETTY---------\n");
                (void)printf("jetty_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_JTGRP_CNT: {
                (void)printf("\n------JETTY_GROUP------\n");
                (void)printf("jetty_group_cnt     :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_RC_CNT: {
                (void)printf("\n----------RC-----------\n");
                (void)printf("rc_cnt              :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_VTP_CNT: {
                (void)printf("\n----------VTP----------\n");
                (void)printf("vtp_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_TP_CNT: {
                (void)printf("\n----------TP-----------\n");
                (void)printf("tp_cnt              :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_TPG_CNT: {
                (void)printf("\n----------TPG----------\n");
                (void)printf("tpg_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_UTP_CNT: {
                (void)printf("\n----------UTP----------\n");
                (void)printf("utp_cnt             :%u \n", nla_get_u32(nla));
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
        case TOOL_RES_KEY_JETTY_GROUP:
            admin_print_res_jetty_grp(attr_ptr, len);
            break;
        case TOOL_RES_KEY_SEG:
            admin_print_res_seg(attr_ptr, len);
            break;
        case TOOL_RES_KEY_DEV_TA:
            admin_print_res_dev(attr_ptr, len);
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
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int len = genlmsg_attrlen(genlhdr, 0);

    netlink_cb_par *cb_par = (netlink_cb_par *)arg;
    print_query_res(attr_ptr, cb_par, len);

    return 0;
}

static void admin_list_res_jfs(struct nlattr *head, int len)
{
    int rem;
    struct nlattr *nla;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_JFS_CNT) {
            (void)printf("\n----------JFS----------\n");
            (void)printf("jfs_cnt             :%u \n", nla_get_u32(nla));
        }
        if (type == UBCORE_RES_DEV_JFS_VAL) {
            (void)printf("jfs_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void admin_list_res_jfr(struct nlattr *head, int len)
{
    int rem;
    struct nlattr *nla;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_JFR_CNT) {
            (void)printf("\n----------JFR----------\n");
            (void)printf("jfr_cnt             :%u \n", nla_get_u32(nla));
        }
        if (type == UBCORE_RES_DEV_JFR_VAL) {
            (void)printf("jfr_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void admin_list_res_jetty(struct nlattr *head, int len)
{
    int rem;
    struct nlattr *nla;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_JETTY_CNT) {
            (void)printf("\n---------JETTY---------\n");
            (void)printf("jetty_cnt             :%u \n", nla_get_u32(nla));
            i = 0;
        }
        if (type == UBCORE_RES_DEV_JETTY_VAL) {
            (void)printf("jetty_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void admin_list_res_jetty_grp(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_JTGRP_JETTY_CNT) {
            (void)printf("\n------JETTY_GROUP------\n");
            (void)printf("jetty_group_cnt     :%u \n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_JTGRP_JETTY_VAL) {
            (void)printf("jetty_group_id[%u]   \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void admin_list_res_jfc(struct nlattr *head, int len)
{
    int rem;
    struct nlattr *nla;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_JFC_CNT) {
            (void)printf("\n----------JFC----------\n");
            (void)printf("jfc_cnt             :%u \n", nla_get_u32(nla));
        }
        if (type == UBCORE_RES_DEV_JFC_VAL) {
            (void)printf("jfc_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void admin_list_res_rc(struct nlattr *head, int len)
{
    int rem;
    struct nlattr *nla;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_RC_CNT) {
            (void)printf("\n----------RC-----------\n");
            (void)printf("rc_cnt              :%u \n", nla_get_u32(nla));
        }
        if (type == UBCORE_RES_DEV_RC_VAL) {
            (void)printf("rc_id[%u]           \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void admin_list_res_seg(struct nlattr *head, int len)
{
    int rem;
    uint32_t i = 0;
    struct nlattr *nla;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        if (type == UBCORE_RES_SEGVAL_SEG_CNT) {
            (void)printf("seg_cnt             : %u\n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_SEGVAL_SEG_VAL) {
            tool_seg_info_t *val = (tool_seg_info_t *)nla_data(nla);
            (void)printf("seg_list idx: %u\n", i);
            (void)printf("eid                 :" EID_FMT " \n", EID_ARGS(val->ubva.eid));
            (void)printf("va                  : %lu\n", val->ubva.va);
            (void)printf("len                 : %lu\n", val->len);
            (void)printf("token_id            : %u\n", val->token_id);
            (void)printf("\n");
            i++;
        }
    }
}

static void print_list_res(struct nlattr *attr_ptr, netlink_cb_par *cb_par, int len)
{
    (void)printf("**********%s**********\n", g_query_res_type[cb_par->type]);
    switch (cb_par->type) {
        case TOOL_RES_KEY_JETTY_GROUP:
            admin_list_res_jetty_grp(attr_ptr, len);
            break;
        case TOOL_RES_KEY_SEG:
            admin_list_res_seg(attr_ptr, len);
            break;
        case TOOL_RES_KEY_JFS:
            admin_list_res_jfs(attr_ptr, len);
            break;
        case TOOL_RES_KEY_JFR:
            admin_list_res_jfr(attr_ptr, len);
            break;
        case TOOL_RES_KEY_JETTY:
            admin_list_res_jetty(attr_ptr, len);
            break;
        case TOOL_RES_KEY_JFC:
            admin_list_res_jfc(attr_ptr, len);
            break;
        case TOOL_RES_KEY_RC:
            admin_list_res_rc(attr_ptr, len);
            break;
        default:
            break;
    }
}

static int cb_handler_list(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int len = genlmsg_attrlen(genlhdr, 0);

    netlink_cb_par *cb_par = (netlink_cb_par *)arg;
    print_list_res(attr_ptr, cb_par, len);

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
    if (arg->in.type == TOOL_RES_KEY_DEV_TA && cfg->key.key_cnt == 0) {
        arg->in.key_cnt = 1;
    } else {
        arg->in.key_cnt = cfg->key.key_cnt;
    }
    (void)memcpy(arg->in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    cb_arg->type = arg->in.type;
    cb_arg->key = arg->in.key;

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
    return ret;
}

int admin_show_res(tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    netlink_cb_par nl_cb_agr;

    if (cfg->key.type < TOOL_RES_KEY_VTP || cfg->key.type > TOOL_RES_KEY_DEV_TA) {
        (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
        return -1;
    }
    if ((cfg->key.type >= TOOL_RES_KEY_VTP && cfg->key.type <= TOOL_RES_KEY_UTP) ||
        cfg->key.type == TOOL_RES_KEY_DEV_TP) {
        (void)printf("urma_admin do not support query tp stats.\n");
        return -1;
    }
    if (cfg->key.key_cnt == 0 && cfg->key.type != TOOL_RES_KEY_DEV_TA) {
        (void)printf("key_cnt in show_res cannot be 0 when type is not dev.\n");
        return -1;
    }
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

static int admin_cmd_list_res(struct nl_sock *sock, const tool_config_t *cfg, int genl_id, netlink_cb_par *cb_arg)
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
    cb_arg->key = arg->in.key;

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
    return ret;
}

int admin_list_res(tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    netlink_cb_par nl_cb_agr;

    if ((cfg->key.type >= TOOL_RES_KEY_VTP && cfg->key.type <= TOOL_RES_KEY_UTP) ||
        cfg->key.type >= TOOL_RES_KEY_DEV_TA) {
        (void)printf("urma_admin do not support query tp and dev stats.\n");
        return -1;
    }
    if (cfg->key.key_cnt != 0) {
        (void)printf("key_cnt in list_res should equal 0.\n");
        return -1;
    }
    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    (void)nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, cb_handler_list, &nl_cb_agr);
    if (admin_cmd_list_res(sock, cfg, genl_id, &nl_cb_agr) < 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

static int admin_set_reserved_jetty_id_range(tool_config_t *cfg)
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
        {"show_stats", admin_show_stats},
        {"show_res", admin_show_res},
        {"set_ns_mode", admin_cmd_set_ns_mode_legacy},
        {"set_dev_ns", admin_cmd_set_dev_ns_legacy},
        {"set_reserved_jetty", admin_set_reserved_jetty_id_range},
        {"list_res", admin_list_res},
        //
        {"show", admin_cmd_show},
        {"agg", admin_cmd_agg},
        {"dev", admin_cmd_dev},
        {"eid", admin_cmd_eid},
        {0},
    };
    return exec_cmd(cfg, cmds);
}
