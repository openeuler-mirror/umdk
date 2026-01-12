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

static int urma_admin_get_ns_fd(const char *ns)
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
    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_recvmsgs_default, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
    }
    (void)close(ns_fd);
    return ret;
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
    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_recvmsgs_default, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
    }
    return ret;
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
    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_recvmsgs_default, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
    }
    return ret;
}

static int cb_update_eid_handler(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int *ret = arg;

    if (arg == NULL) {
        return 0;
    }

    if (genlhdr->cmd != (int)URMA_CORE_CMD_ADD_EID && genlhdr->cmd != (int)URMA_CORE_CMD_DEL_EID) {
        return 0;
    }

    *ret = nla_get_s32(attr_ptr);
    if (*ret == 0) {
        return 0;
    } else if (*ret == 1) {
        (void)usleep(1); // ret == 1 means in progress, genl will try again.
    } else {
        (void)printf("Failed to %s, invalid parameter.\n",
                     (genlhdr->cmd == (int)URMA_CORE_CMD_ADD_EID) ? "add eid" : "del eid");
    }

    return 0;
}

int admin_add_eid(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    int ret = 0;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    (void)nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, cb_update_eid_handler, &ret);
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
    return ret;
}

int admin_del_eid(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    int ret = 0;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    (void)nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, cb_update_eid_handler, &ret);
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
    return ret;
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

int admin_show_stats(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

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

bool admin_is_eid_valid(const char *eid)
{
    int i;

    for (i = 0; i < EID_LEN; i++) {
        if (eid[i] != 0) {
            return true;
        }
    }
    return false;
}

void admin_print_topo_map(tool_topo_map_t *topo_map)
{
    uint32_t i, j, k;
    tool_topo_info_t *cur_node_info;

    (void)printf("========================== topo map start =============================\n");
    for (i = 0; i < topo_map->node_num; i++) {
        cur_node_info = topo_map->topo_infos + i;
        if (!admin_is_eid_valid(cur_node_info->bonding_eid)) {
            continue;
        }

        (void)printf("===================== node %d start =======================\n", i);
        (void)printf("bonding eid: " EID_FMT "\n", EID_ARGS(*(urma_eid_t *)cur_node_info->bonding_eid));
        for (j = 0; j < IODIE_NUM; j++) {
            (void)printf("**primary eid %d: " EID_FMT "\n", j,
                         EID_ARGS(*(urma_eid_t *)cur_node_info->io_die_info[j].primary_eid));
            for (k = 0; k < MAX_PORT_NUM; k++) {
                (void)printf("****port eid %d: " EID_FMT "\n", k,
                             EID_ARGS(*(urma_eid_t *)cur_node_info->io_die_info[j].port_eid[k]));
                (void)printf("****peer_port eid %d: " EID_FMT "\n", k,
                             EID_ARGS(*(urma_eid_t *)cur_node_info->io_die_info[j].peer_port_eid[k]));
            }
        }
        (void)printf("===================== node %d end =======================\n", i);
    }
    (void)printf("========================== topo map end =============================\n");
}

static int admin_cmd_query_topo_info(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
{
    urma_cmd_hdr_t hdr;
    tool_topo_map_t *topo_map = calloc(1, sizeof(tool_topo_map_t));
    int ret = 0;
    if (topo_map == NULL) {
        return -1;
    }
    int node_num = MAX_NODE_NUM;
    for (int i = 0; i < node_num; ++i) {
        admin_core_cmd_topo_info_t arg = {0};
        arg.in.node_idx = i;
        hdr.command = (uint32_t)URMA_CORE_GET_TOPO_INFO;
        hdr.args_len = (uint32_t)sizeof(admin_core_cmd_topo_info_t);
        hdr.args_addr = (uint64_t)(uintptr_t)&arg;

        ret = cmd_nlsend(sock, genl_id, &hdr);
        if (ret < 0) {
            (void)printf("Failed to cmd_nlsend, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
            goto free_topo;
        }

        ret = nl_recvmsgs_default(sock);
        if (ret < 0) {
            (void)printf("query topo_infos fail, please check input, ret:%d, errno:%d.\n", ret, errno);
            goto free_topo;
        }
        topo_map->topo_infos[i] = arg.out.topo_info;
        topo_map->node_num = arg.out.node_num;
        node_num = arg.out.node_num;
    }
    admin_print_topo_map(topo_map);
    free(topo_map);
    return 0;
free_topo:
    free(topo_map);
    return ret;
}

int admin_show_topo_info(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    if (admin_cmd_query_topo_info(sock, cfg, genl_id) < 0) {
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

int admin_show_res(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    netlink_cb_par nl_cb_agr;

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

int admin_list_res(const tool_config_t *cfg)
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
