/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: bondp support netlink msg
 * Author: Ruilang Lai
 * Create: 2026-04-24
 * Note:
 * History: 2026-04-24
 */

#include <errno.h>
#include <netlink/errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <stdbool.h>
#include <stdint.h>

#include "bondp_failback.h"
#include "bondp_worker.h"
#include "urma_log.h"

#include "bondp_netlink.h"

#define UBAGG_GENL_FAMILY_NAME    "UBAGG_GENL"
#define UBAGG_GENL_FAMILY_VERSION 1
#define UBAGG_GENL_MCGRP_NAME     "bonding"

typedef struct bondp_nl_ctx {
    struct nl_sock *sock;
} bondp_nl_ctx_t;

static bondp_nl_ctx_t g_nl_ctx = {
    .sock = NULL,
};

static int bondp_nl_parse_attrs(struct nl_msg *nlmsg, struct nlattr *attrs[], int max_attr)
{
    struct nlmsghdr *hdr = nlmsg_hdr(nlmsg);
    if (hdr == NULL) {
        return -EINVAL;
    }

    struct genlmsghdr *genl_hdr = (struct genlmsghdr *)nlmsg_data(hdr);
    if (genl_hdr == NULL) {
        return -EINVAL;
    }

    return nla_parse(attrs, max_attr, genlmsg_attrdata(genl_hdr, 0), genlmsg_attrlen(genl_hdr, 0), NULL);
}

static int bondp_nl_msg_cb(struct nl_msg *nlmsg, void *arg)
{
    (void)arg;

    struct nlattr *attrs[BONDP_NL_ATTR_MAX + 1] = {0};
    int ret = bondp_nl_parse_attrs(nlmsg, attrs, BONDP_NL_ATTR_MAX);
    if (ret != 0) {
        return NL_SKIP;
    }

    struct nlmsghdr *hdr = nlmsg_hdr(nlmsg);
    if (hdr == NULL) {
        return NL_SKIP;
    }

    struct genlmsghdr *genl_hdr = (struct genlmsghdr *)nlmsg_data(hdr);
    if (genl_hdr == NULL) {
        return NL_SKIP;
    }

    switch ((bondp_nl_cmd_t)genl_hdr->cmd) {
        case BONDP_NL_CMD_FAILBACK_NOTIFY:
            bondp_fb_handle_notify_nl_msg(attrs);
            break;
        case BONDP_NL_CMD_FAILBACK_DONE:
            bondp_fb_handle_done_nl_msg(attrs);
            break;
        default:
            break;
    }
    return NL_OK;
}

static void bondp_nl_handle_worker_event(void *arg)
{
    (void)arg;

    if (g_nl_ctx.sock == NULL) {
        return;
    }

    int ret = nl_recvmsgs_default(g_nl_ctx.sock);
    if (ret == -NLE_AGAIN || ret == -NLE_INTR) {
        return;
    }
    if (ret != 0) {
        URMA_LOG_WARN("Failed to recv bond netlink msg, ret=%d\n", ret);
    }
}

int bondp_nl_sock_init(void)
{
    if (g_nl_ctx.sock != NULL) {
        return 0;
    }

    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL) {
        URMA_LOG_ERR("Failed to allocate netlink socket.\n");
        return -ENOMEM;
    }

    int ret = genl_connect(sock);
    if (ret < 0) {
        URMA_LOG_ERR("Failed to connect generic netlink, ret=%d\n", ret);
        goto close_sock;
    }

    ret = genl_ctrl_resolve(sock, UBAGG_GENL_FAMILY_NAME);
    if (ret < 0) {
        URMA_LOG_ERR("Failed to resolve netlink family '%s', ret=%d\n", UBAGG_GENL_FAMILY_NAME, ret);
        goto close_sock;
    }
    int genl_id = ret;

    int mcgrp_id = genl_ctrl_resolve_grp(sock, UBAGG_GENL_FAMILY_NAME, UBAGG_GENL_MCGRP_NAME);
    if (mcgrp_id < 0) {
        URMA_LOG_ERR("Failed to resolve netlink multicast group '%s', ret=%d\n",
                     UBAGG_GENL_MCGRP_NAME, mcgrp_id);
        ret = mcgrp_id;
        goto close_sock;
    }

    ret = nl_socket_add_membership(sock, mcgrp_id);
    if (ret < 0) {
        URMA_LOG_ERR("Failed to subscribe bond netlink group '%s', ret=%d\n", UBAGG_GENL_MCGRP_NAME, ret);
        goto close_sock;
    }

    ret = nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, bondp_nl_msg_cb, NULL);
    if (ret < 0) {
        URMA_LOG_ERR("Failed to set bond netlink callback, ret=%d\n", ret);
        goto close_sock;
    }

    nl_socket_set_nonblocking(sock);
    g_nl_ctx.sock = sock;
    URMA_LOG_INFO("Bond netlink initialized, genl_id=%d mcgrp_id=%d\n", genl_id, mcgrp_id);
    return 0;

close_sock:
    nl_close(sock);
    nl_socket_free(sock);
    return ret;
}

void bondp_nl_sock_uninit(void)
{
    if (g_nl_ctx.sock == NULL) {
        return;
    }

    nl_close(g_nl_ctx.sock);
    nl_socket_free(g_nl_ctx.sock);
    g_nl_ctx.sock = NULL;
}

int bondp_nl_worker_init(void)
{
    if (g_nl_ctx.sock == NULL) {
        return -ENODEV;
    }

    int sock_fd = nl_socket_get_fd(g_nl_ctx.sock);
    if (sock_fd < 0) {
        return -EINVAL;
    }

    int ret = bondp_worker_add_fd(sock_fd, bondp_nl_handle_worker_event, NULL);
    if (ret != 0 && ret != -EEXIST) {
        URMA_LOG_ERR("Failed to register bond netlink fd=%d to worker, ret=%d\n", sock_fd, ret);
        return ret;
    }
    return 0;
}

void bondp_nl_worker_uninit(void)
{
    if (g_nl_ctx.sock == NULL) {
        return;
    }

    int sock_fd = nl_socket_get_fd(g_nl_ctx.sock);
    int ret = bondp_worker_del_fd(sock_fd);
    if (ret != 0 && ret != -ENOENT) {
        URMA_LOG_WARN("Failed to unregister bond netlink fd=%d from worker, ret=%d\n", sock_fd, ret);
    }
}
