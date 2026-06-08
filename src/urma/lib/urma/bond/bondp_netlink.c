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
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "urma_log.h"

#include "bondp_types.h"
#include "bondp_netlink.h"

#define UBCORE_GENL_FAMILY_NAME    "UBCORE_GENL"
#define UBCORE_GENL_FAMILY_VERSION 1

enum ubcore_nl_attr {
    UBCORE_ATTR_UNSPEC = 0,
    UBCORE_HDR_COMMAND,
    UBCORE_HDR_ARGS_LEN,
    UBCORE_HDR_ARGS_ADDR,
    UBCORE_ATTR_NS_MODE,
    UBCORE_ATTR_DEV_NAME,
    UBCORE_ATTR_NS_FD,
    UBCORE_ATTR_EID_IDX,
    UBCORE_ATTR_AFTER_LAST
};

typedef struct bondp_nl_ctx {
    struct nl_sock *sock;
    int genl_id;
    pthread_mutex_t lock;
} bondp_nl_ctx_t;

static bondp_nl_ctx_t g_bondp_nl_ctx = {
    .sock = NULL,
    .genl_id = -1,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};


int bondp_fallback_ctrl_send_default(bondp_context_t *bdp_ctx, uint32_t vjetty_id,
    int local_idx, int target_idx, uint8_t ctrl_type, uint8_t req_seq, uint32_t payload)
{
    if (bdp_ctx == NULL || local_idx < 0 || target_idx < 0) {
        return -EINVAL;
    }

    bondp_switchback_req_t req = {0};
    req.in.vjetty_id = vjetty_id;
    req.in.local_idx = (uint32_t)local_idx;
    req.in.target_idx = (uint32_t)target_idx;
    req.in.ctrl_type = ctrl_type;
    req.in.req_seq = req_seq;
    req.in.payload = payload;

    int ret = bondp_nl_send_switchback_req(&req);
    if (ret != 0) {
        URMA_LOG_WARN(
            "Failed to send switchback ctrl by netlink, ret=%d vjetty=%u lidx=%d tidx=%d type=%u seq=%u payload=%u\n",
            ret, vjetty_id, local_idx, target_idx, ctrl_type, req_seq, payload);
        return ret;
    }
    return 0;
}

static int bondp_nl_parse_cb(struct nl_msg *nlmsg, void *arg)
{
    bondp_switchback_msg_t *out = (bondp_switchback_msg_t *)arg;
    struct nlmsghdr *hdr = nlmsg_hdr(nlmsg);
    if (hdr == NULL || out == NULL) {
        return NL_SKIP;
    }

    struct genlmsghdr *genl_hdr = (struct genlmsghdr *)nlmsg_data(hdr);
    if (genl_hdr == NULL) {
        return NL_SKIP;
    }

    struct nlattr *attrs[UBCORE_ATTR_AFTER_LAST + 1] = {0};
    int ret = nla_parse(attrs, UBCORE_ATTR_AFTER_LAST, genlmsg_attrdata(genl_hdr, 0),
        genlmsg_attrlen(genl_hdr, 0), NULL);
    if (ret != 0) {
        return NL_SKIP;
    }

    if (attrs[UBCORE_HDR_ARGS_ADDR] == NULL) {
        return NL_SKIP;
    }

    void *payload = nla_data(attrs[UBCORE_HDR_ARGS_ADDR]);
    int payload_len = nla_len(attrs[UBCORE_HDR_ARGS_ADDR]);
    if (payload == NULL || payload_len < (int)sizeof(bondp_switchback_msg_t)) {
        return NL_SKIP;
    }

    (void)memcpy(out, payload, sizeof(*out));
    return NL_OK;
}

int bondp_nl_init(void)
{
    int ret = 0;

    pthread_mutex_lock(&g_bondp_nl_ctx.lock);
    if (g_bondp_nl_ctx.sock != NULL) {
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return 0;
    }

    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL) {
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        URMA_LOG_ERR("Failed to allocate netlink socket.\n");
        return -ENOMEM;
    }

    ret = genl_connect(sock);
    if (ret < 0) {
        nl_socket_free(sock);
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        URMA_LOG_ERR("Failed to connect generic netlink, ret=%d\n", ret);
        return ret;
    }

    ret = genl_ctrl_resolve(sock, UBCORE_GENL_FAMILY_NAME);
    if (ret < 0) {
        nl_close(sock);
        nl_socket_free(sock);
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        URMA_LOG_ERR("Failed to resolve netlink family '%s', ret=%d\n", UBCORE_GENL_FAMILY_NAME, ret);
        return ret;
    }

    nl_socket_set_nonblocking(sock);
    g_bondp_nl_ctx.sock = sock;
    g_bondp_nl_ctx.genl_id = ret;
    pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
    URMA_LOG_INFO("Bond netlink initialized, genl_id=%d\n", ret);
    return 0;
}

void bondp_nl_uninit(void)
{
    pthread_mutex_lock(&g_bondp_nl_ctx.lock);
    if (g_bondp_nl_ctx.sock != NULL) {
        nl_close(g_bondp_nl_ctx.sock);
        nl_socket_free(g_bondp_nl_ctx.sock);
        g_bondp_nl_ctx.sock = NULL;
        g_bondp_nl_ctx.genl_id = -1;
    }
    pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
}

int bondp_nl_get_fd(void)
{
    pthread_mutex_lock(&g_bondp_nl_ctx.lock);
    int fd = (g_bondp_nl_ctx.sock == NULL) ? -1 : nl_socket_get_fd(g_bondp_nl_ctx.sock);
    pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
    return fd;
}

int bondp_nl_send_switchback_req(const bondp_switchback_req_t *req)
{
    if (req == NULL) {
        return -EINVAL;
    }

    pthread_mutex_lock(&g_bondp_nl_ctx.lock);
    if (g_bondp_nl_ctx.sock == NULL || g_bondp_nl_ctx.genl_id < 0) {
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return -ENOTCONN;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) {
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return -ENOMEM;
    }

    if (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, g_bondp_nl_ctx.genl_id, 0, 0,
        SEND_SWITCHBACK_REQ, UBCORE_GENL_FAMILY_VERSION) == NULL) {
        nlmsg_free(msg);
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return -ENOMEM;
    }

    if (nla_put_u32(msg, UBCORE_HDR_COMMAND, SEND_SWITCHBACK_REQ) != 0 ||
        nla_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(*req)) != 0 ||
        nla_put(msg, UBCORE_HDR_ARGS_ADDR, (int)sizeof(*req), req) != 0) {
        nlmsg_free(msg);
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return -ENOMEM;
    }

    int ret = nl_send_auto(g_bondp_nl_ctx.sock, msg);
    nlmsg_free(msg);
    pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
    return (ret < 0) ? ret : 0;
}

int bondp_nl_recv_switchback_msg(bondp_switchback_msg_t *msg)
{
    if (msg == NULL) {
        return -EINVAL;
    }

    pthread_mutex_lock(&g_bondp_nl_ctx.lock);
    if (g_bondp_nl_ctx.sock == NULL) {
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return -ENOTCONN;
    }

    (void)memset(msg, 0, sizeof(*msg));
    int ret = nl_socket_modify_cb(g_bondp_nl_ctx.sock, NL_CB_MSG_IN, NL_CB_CUSTOM, bondp_nl_parse_cb, msg);
    if (ret < 0) {
        pthread_mutex_unlock(&g_bondp_nl_ctx.lock);
        return ret;
    }

    ret = nl_recvmsgs_default(g_bondp_nl_ctx.sock);
    (void)nl_socket_modify_cb(g_bondp_nl_ctx.sock, NL_CB_MSG_IN, NL_CB_CUSTOM, NULL, NULL);
    pthread_mutex_unlock(&g_bondp_nl_ctx.lock);

    if (ret == -NLE_AGAIN || ret == -NLE_INTR) {
        return -EAGAIN;
    }
    return (ret < 0) ? ret : 0;
}
