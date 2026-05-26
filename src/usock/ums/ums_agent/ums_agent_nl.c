/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Netlink communication layer implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13  Create File
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

#include "ums_agent_epoll.h"
#include "ums_agent_log.h"
#include "ums_agent_utils.h"
#include "ums_agent_nl.h"

#define UMS_AGENT_NLCTRL_MCAST_GROUP_NAME    "notify"
#define UMS_AGENT_NL_PROBE_INTERVAL_INIT_SEC 1
#define UMS_AGENT_NL_PROBE_INTERVAL_MAX_SEC  30
#define UMS_AGENT_NL_RECV_BUFSIZE            65536

struct ums_agent_nl {
    struct nl_sock *nlctrl_sock;
    int nlctrl_fd;
    int nlctrl_mcast_id;

    struct nl_sock *ums_sock;
    int ums_fd;
    int ums_family_id;

    bool ums_available;
    int probe_fd;
    int probe_interval_sec;

    ums_agent_nl_token_submit_cb token_submit_cb;
    bool initialized;
};

static struct ums_agent_nl g_ums_agent_nl = {
    .nlctrl_sock = NULL,
    .nlctrl_fd = -1,
    .nlctrl_mcast_id = -1,
    .ums_sock = NULL,
    .ums_fd = -1,
    .ums_family_id = 0,
    .ums_available = false,
    .probe_fd = -1,
    .probe_interval_sec = UMS_AGENT_NL_PROBE_INTERVAL_INIT_SEC,
    .token_submit_cb = NULL,
    .initialized = false,
};

static inline void ums_agent_nl_secure_zero_msg(struct nl_msg *msg)
{
    struct nlmsghdr *nh = nlmsg_hdr(msg);
    if (nh->nlmsg_len > NLMSG_HDRLEN) {
        ums_agent_secure_zero(NLMSG_DATA(nh), nh->nlmsg_len - NLMSG_HDRLEN);
    }
}

static int ums_agent_nl_send_role_cmd(uint8_t cmd)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        UMS_AGENT_LOG_ERR("nlmsg_alloc failed");
        return -1;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
        g_ums_agent_nl.ums_family_id, 0, 0, cmd, UMS_GENL_VERSION)) {
        UMS_AGENT_LOG_ERR("genlmsg_put failed for cmd=%d", cmd);
        nlmsg_free(msg);
        return -1;
    }

    int ret = nla_put_u32(msg, UMS_ATTR_ROLE, UMS_ROLE_AGENT);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put_u32 ROLE failed: %s", nl_geterror(ret));
        nlmsg_free(msg);
        return -1;
    }

    ret = nl_send_auto(g_ums_agent_nl.ums_sock, msg);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nl_send_auto cmd=%d failed: %s", cmd,
            nl_geterror(ret));
        nlmsg_free(msg);
        return -1;
    }

    UMS_AGENT_LOG_INFO("sent UMS_CMD_%s to kernel",
        cmd == UMS_CMD_READY ? "READY" : "DOWN");
    nlmsg_free(msg);
    return 0;
}

static inline int ums_agent_nl_send_ready(void)
{
    return ums_agent_nl_send_role_cmd(UMS_CMD_READY);
}

static inline int ums_agent_nl_send_down(void)
{
    return ums_agent_nl_send_role_cmd(UMS_CMD_DOWN);
}

static int ums_agent_nl_setup_probe_timer(void)
{
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) {
        UMS_AGENT_LOG_ERR("timerfd_create failed: %s (errno=%d)",
            strerror(errno), errno);
        return -1;
    }

    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_interval.tv_sec = g_ums_agent_nl.probe_interval_sec;
    its.it_value.tv_sec = g_ums_agent_nl.probe_interval_sec;

    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        UMS_AGENT_LOG_ERR("timerfd_settime failed: %s (errno=%d)",
            strerror(errno), errno);
        close(tfd);
        return -1;
    }

    if (ums_agent_epoll_add_fd(tfd, EPOLLIN) < 0) {
        UMS_AGENT_LOG_ERR("ums_agent_epoll_add_fd failed: %s (errno=%d)",
            strerror(errno), errno);
        close(tfd);
        return -1;
    }

    g_ums_agent_nl.probe_fd = tfd;

    UMS_AGENT_LOG_INFO("nl probe timer started for UMS_GENL availability, "
        "initial_interval=%ds, max_interval=%ds",
        g_ums_agent_nl.probe_interval_sec,
        UMS_AGENT_NL_PROBE_INTERVAL_MAX_SEC);
    return 0;
}

static void ums_agent_nl_teardown_probe_timer(void)
{
    if (g_ums_agent_nl.probe_fd < 0) {
        return;
    }

    (void)ums_agent_epoll_del_fd(g_ums_agent_nl.probe_fd);
    close(g_ums_agent_nl.probe_fd);
    g_ums_agent_nl.probe_fd = -1;
    g_ums_agent_nl.probe_interval_sec = UMS_AGENT_NL_PROBE_INTERVAL_INIT_SEC;
    UMS_AGENT_LOG_INFO("nl probe timer stopped");
}

static int ums_agent_nl_validate_token_submit(struct nlattr *attrs[])
{
    if (!attrs[UMS_ATTR_CLC_SESSION_ID]) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT missing UMS_ATTR_CLC_SESSION_ID");
        return -1;
    }

    if (!attrs[UMS_ATTR_INITIATOR_ID]) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT missing UMS_ATTR_INITIATOR_ID");
        return -1;
    }

    if (nla_len(attrs[UMS_ATTR_INITIATOR_ID]) != UMS_SYSTEMID_LEN) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT invalid INITIATOR_ID length=%d",
            nla_len(attrs[UMS_ATTR_INITIATOR_ID]));
        return -1;
    }

    if (!attrs[UMS_ATTR_FIRST_CONTACT]) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT missing UMS_ATTR_FIRST_CONTACT");
        return -1;
    }

    if (!attrs[UMS_ATTR_SEG_TOKEN]) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT missing UMS_ATTR_SEG_TOKEN");
        return -1;
    }

    if (!attrs[UMS_ATTR_DST_IP] && !attrs[UMS_ATTR_DST_IP6]) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT missing both DST_IP and DST_IP6");
        return -1;
    }

    if (attrs[UMS_ATTR_DST_IP6] &&
        nla_len(attrs[UMS_ATTR_DST_IP6]) != (int)sizeof(struct in6_addr)) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT invalid DST_IP6 length=%d",
            nla_len(attrs[UMS_ATTR_DST_IP6]));
        return -1;
    }

    uint8_t first_contact = nla_get_u8(attrs[UMS_ATTR_FIRST_CONTACT]);
    if (first_contact && !attrs[UMS_ATTR_JETTY_TOKEN]) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT first_contact=1 but missing JETTY_TOKEN");
        return -1;
    }

    return 0;
}

static int ums_agent_nl_process_token_submit(struct nlattr *attrs[])
{
    int ret = 0;
    struct ums_token_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.clc_session_id = nla_get_u32(attrs[UMS_ATTR_CLC_SESSION_ID]);
    entry.first_contact = nla_get_u8(attrs[UMS_ATTR_FIRST_CONTACT]);
    entry.seg_token_value = nla_get_u32(attrs[UMS_ATTR_SEG_TOKEN]);

    nla_memcpy(entry.initiator_id, attrs[UMS_ATTR_INITIATOR_ID],
        UMS_SYSTEMID_LEN);

    if (attrs[UMS_ATTR_DST_IP]) {
        entry.dst_addr.family = AF_INET;
        uint32_t ip4 = nla_get_u32(attrs[UMS_ATTR_DST_IP]);
        memcpy(&entry.dst_addr.ip.in4, &ip4, sizeof(ip4));
    } else if (attrs[UMS_ATTR_DST_IP6]) {
        entry.dst_addr.family = AF_INET6;
        nla_memcpy(&entry.dst_addr.ip.in6, attrs[UMS_ATTR_DST_IP6],
            sizeof(struct in6_addr));
    }

    if (attrs[UMS_ATTR_JETTY_TOKEN]) {
        entry.jetty_token_value = nla_get_u32(attrs[UMS_ATTR_JETTY_TOKEN]);
    }

    if (!g_ums_agent_nl.token_submit_cb) {
        UMS_AGENT_LOG_WARN("no handler registered for TOKEN_SUBMIT");
        ret = -ENOTSUP;
        goto cleanup;
    }

    ret = g_ums_agent_nl.token_submit_cb(&entry);
    if (ret != 0) {
        UMS_AGENT_LOG_ERR("token_submit_cb failed, clc_session_id=%u, ret=%d",
            entry.clc_session_id, ret);
        goto cleanup;
    }

cleanup:
    ums_agent_secure_zero(&entry.jetty_token_value, sizeof(entry.jetty_token_value));
    ums_agent_secure_zero(&entry.seg_token_value, sizeof(entry.seg_token_value));
    return ret;
}

static int ums_agent_nl_ums_cb(struct nl_msg *msg, void *arg)
{
    (void)arg;
    int cb_ret = NL_SKIP;

    struct nlmsghdr *nh = nlmsg_hdr(msg);
    struct genlmsghdr *gh = genlmsg_hdr(nh);

    if (gh->cmd != UMS_CMD_TOKEN_SUBMIT) {
        UMS_AGENT_LOG_WARN("received unexpected UMS cmd=%d, ignoring", gh->cmd);
        goto cleanup;
    }

    struct nlattr *attrs[UMS_ATTR_MAX + 1];
    memset(attrs, 0, sizeof(attrs));

    int ret = nla_parse(attrs, UMS_ATTR_MAX, genlmsg_attrdata(gh, 0),
        genlmsg_attrlen(gh, 0), NULL);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT nla_parse failed");
        goto cleanup;
    }

    ret = ums_agent_nl_validate_token_submit(attrs);
    if (ret < 0) {
        goto cleanup;
    }

    ret = ums_agent_nl_process_token_submit(attrs);
    if (ret < 0) {
        int err_code = -ret;
        uint32_t clc_session_id = nla_get_u32(attrs[UMS_ATTR_CLC_SESSION_ID]);
        uint8_t initiator_id[UMS_SYSTEMID_LEN];
        nla_memcpy(initiator_id, attrs[UMS_ATTR_INITIATOR_ID], UMS_SYSTEMID_LEN);
        ret = ums_agent_nl_send_token_submit_fail(clc_session_id, initiator_id, err_code);
        if (ret < 0) {
            UMS_AGENT_LOG_WARN("TOKEN_SUBMIT_FAIL send failed (result=%d), "
                "clc_session_id=%u, kernel will timeout", err_code, clc_session_id);
        }
        goto cleanup;
    }

    cb_ret = NL_OK;

cleanup:
    ums_agent_nl_secure_zero_msg(msg);
    return cb_ret;
}

static void ums_agent_nl_disconnect_ums(void)
{
    if (g_ums_agent_nl.ums_fd >= 0) {
        (void)ums_agent_epoll_del_fd(g_ums_agent_nl.ums_fd);
    }

    if (g_ums_agent_nl.ums_sock) {
        nl_socket_free(g_ums_agent_nl.ums_sock);
    }

    g_ums_agent_nl.ums_sock = NULL;
    g_ums_agent_nl.ums_fd = -1;
    g_ums_agent_nl.ums_family_id = 0;
    g_ums_agent_nl.ums_available = false;

    UMS_AGENT_LOG_INFO("UMS_GENL socket disconnected");
}

static void ums_agent_nl_disconnect_and_probe(void)
{
    if (g_ums_agent_nl.ums_available) {
        ums_agent_nl_disconnect_ums();
    }

    if (g_ums_agent_nl.probe_fd < 0) {
        (void)ums_agent_nl_setup_probe_timer();
    }
}

static int ums_agent_nl_try_connect_ums(void)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        UMS_AGENT_LOG_ERR("nl_socket_alloc failed for UMS_GENL");
        return -1;
    }

    nl_socket_disable_seq_check(sock);

    int ret = genl_connect(sock);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("genl_connect failed: %s", nl_geterror(ret));
        nl_socket_free(sock);
        return -1;
    }

    ret = nl_socket_set_buffer_size(sock, UMS_AGENT_NL_RECV_BUFSIZE, 0);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("nl_socket_set_buffer_size failed: %s",
            nl_geterror(ret));
    }

    int family_id = genl_ctrl_resolve(sock, UMS_GENL_NAME);
    if (family_id < 0) {
        UMS_AGENT_LOG_WARN("UMS_GENL family not found, ums.ko not loaded");
        nl_socket_free(sock);
        return -1;
    }

    ret = nl_socket_set_nonblocking(sock);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nl_socket_set_nonblocking failed: %s",
            nl_geterror(ret));
        nl_socket_free(sock);
        return -1;
    }

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
        ums_agent_nl_ums_cb, NULL);

    int fd = nl_socket_get_fd(sock);
    if (ums_agent_epoll_add_fd(fd, EPOLLIN) < 0) {
        UMS_AGENT_LOG_ERR("epoll_add_fd failed for UMS_GENL fd=%d", fd);
        nl_socket_free(sock);
        return -1;
    }

    g_ums_agent_nl.ums_sock = sock;
    g_ums_agent_nl.ums_fd = fd;
    g_ums_agent_nl.ums_family_id = family_id;

    ret = ums_agent_nl_send_ready();
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("send READY failed after connecting UMS_GENL");
        ums_agent_nl_disconnect_ums();
        return -1;
    }
    g_ums_agent_nl.ums_available = true;

    if (g_ums_agent_nl.probe_fd >= 0) {
        ums_agent_nl_teardown_probe_timer();
        UMS_AGENT_LOG_INFO("UMS_GENL connected via nl probe, family_id=%d, fd=%d",
            family_id, fd);
    } else {
        UMS_AGENT_LOG_INFO("UMS_GENL connected, family_id=%d, fd=%d",
            family_id, fd);
    }
    return 0;
}

static int ums_agent_nl_handle_family_new(void)
{
    UMS_AGENT_LOG_INFO("detected UMS_GENL family registration, ums.ko loaded");

    if (g_ums_agent_nl.ums_available) {
        UMS_AGENT_LOG_DEBUG("UMS_GENL already connected, skipping");
        return NL_SKIP;
    }

    (void)ums_agent_nl_try_connect_ums();
    return NL_OK;
}

static int ums_agent_nl_handle_family_del(void)
{
    UMS_AGENT_LOG_WARN("detected UMS_GENL family removal, ums.ko unloaded");

    ums_agent_nl_disconnect_and_probe();
    return NL_OK;
}

static int ums_agent_nlctrl_cb(struct nl_msg *msg, void *arg)
{
    (void)arg;

    struct nlmsghdr *nh = nlmsg_hdr(msg);
    struct genlmsghdr *gh = genlmsg_hdr(nh);

    if (gh->cmd != CTRL_CMD_NEWFAMILY && gh->cmd != CTRL_CMD_DELFAMILY) {
        return NL_SKIP;
    }

    struct nlattr *attrs[CTRL_ATTR_MAX + 1];
    memset(attrs, 0, sizeof(attrs));

    int ret = nla_parse(attrs, CTRL_ATTR_MAX, genlmsg_attrdata(gh, 0),
        genlmsg_attrlen(gh, 0), NULL);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("nlctrl nla_parse failed");
        return NL_SKIP;
    }

    if (!attrs[CTRL_ATTR_FAMILY_NAME]) {
        return NL_SKIP;
    }

    const char *family_name = nla_get_string(attrs[CTRL_ATTR_FAMILY_NAME]);
    if (strcmp(family_name, UMS_GENL_NAME) != 0) {
        return NL_SKIP;
    }

    if (gh->cmd == CTRL_CMD_NEWFAMILY) {
        return ums_agent_nl_handle_family_new();
    }

    return ums_agent_nl_handle_family_del();
}

static int ums_agent_nl_setup_nlctrl(void)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        UMS_AGENT_LOG_ERR("nl_socket_alloc failed for nlctrl");
        return -1;
    }

    nl_socket_disable_seq_check(sock);

    int ret = genl_connect(sock);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("genl_connect failed for nlctrl: %s",
            nl_geterror(ret));
        nl_socket_free(sock);
        return -1;
    }

    ret = nl_socket_set_buffer_size(sock, UMS_AGENT_NL_RECV_BUFSIZE, 0);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("nl_socket_set_buffer_size failed: %s",
            nl_geterror(ret));
    }

    int mcast_id = genl_ctrl_resolve_grp(sock, "nlctrl",
        UMS_AGENT_NLCTRL_MCAST_GROUP_NAME);
    if (mcast_id < 0) {
        UMS_AGENT_LOG_WARN("genl_ctrl_resolve_grp failed: %s, "
            "nlctrl events unavailable", nl_geterror(mcast_id));
        nl_socket_free(sock);
        return -1;
    }

    ret = nl_socket_add_membership(sock, mcast_id);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("nl_socket_add_membership failed: %s",
            nl_geterror(ret));
        nl_socket_free(sock);
        return -1;
    }

    ret = nl_socket_set_nonblocking(sock);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nl_socket_set_nonblocking failed: %s",
            nl_geterror(ret));
        nl_socket_free(sock);
        return -1;
    }

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
        ums_agent_nlctrl_cb, NULL);

    int fd = nl_socket_get_fd(sock);
    if (ums_agent_epoll_add_fd(fd, EPOLLIN) < 0) {
        UMS_AGENT_LOG_ERR("epoll_add_fd failed for nlctrl fd=%d", fd);
        nl_socket_free(sock);
        return -1;
    }

    g_ums_agent_nl.nlctrl_sock = sock;
    g_ums_agent_nl.nlctrl_fd = fd;
    g_ums_agent_nl.nlctrl_mcast_id = mcast_id;

    UMS_AGENT_LOG_DEBUG("nlctrl subscribed, mcast_id=%d, fd=%d", mcast_id, fd);
    return 0;
}

static void ums_agent_nl_teardown_nlctrl(void)
{
    if (g_ums_agent_nl.nlctrl_fd >= 0) {
        (void)ums_agent_epoll_del_fd(g_ums_agent_nl.nlctrl_fd);
    }

    if (g_ums_agent_nl.nlctrl_sock) {
        nl_socket_free(g_ums_agent_nl.nlctrl_sock);
    }

    g_ums_agent_nl.nlctrl_sock = NULL;
    g_ums_agent_nl.nlctrl_fd = -1;
    g_ums_agent_nl.nlctrl_mcast_id = -1;
}

int ums_agent_nl_init(void)
{
    if (g_ums_agent_nl.initialized) {
        UMS_AGENT_LOG_WARN("netlink already initialized");
        return 0;
    }

    if (ums_agent_nl_setup_nlctrl() < 0) {
        UMS_AGENT_LOG_WARN("nlctrl setup failed, nlctrl events unavailable");
    }

    if (ums_agent_nl_try_connect_ums() < 0) {
        UMS_AGENT_LOG_INFO("UMS_GENL not available, starting probe timer");
        if (ums_agent_nl_setup_probe_timer() < 0) {
            UMS_AGENT_LOG_ERR("probe timer setup failed");
            goto err_nlctrl;
        }
    }

    g_ums_agent_nl.initialized = true;
    return 0;

err_nlctrl:
    ums_agent_nl_teardown_nlctrl();
    return -1;
}

void ums_agent_nl_deinit(void)
{
    if (!g_ums_agent_nl.initialized) {
        return;
    }

    if (g_ums_agent_nl.ums_available) {
        int ret = ums_agent_nl_send_down();
        if (ret < 0) {
            UMS_AGENT_LOG_WARN("send DOWN failed");
        }
    }

    ums_agent_nl_disconnect_ums();
    ums_agent_nl_teardown_probe_timer();
    ums_agent_nl_teardown_nlctrl();

    g_ums_agent_nl.initialized = false;
}

bool ums_agent_nl_owns_fd(int fd)
{
    return fd == g_ums_agent_nl.nlctrl_fd ||
           fd == g_ums_agent_nl.ums_fd ||
           fd == g_ums_agent_nl.probe_fd;
}

static void ums_agent_nl_handle_ums_event(uint32_t events)
{
    if (!g_ums_agent_nl.ums_sock) {
        UMS_AGENT_LOG_WARN("ums event received but ums_sock is NULL");
        return;
    }

    if (events & (EPOLLIN | EPOLLERR)) {
        int ret = nl_recvmsgs_default(g_ums_agent_nl.ums_sock);
        if (ret < 0 && ret != -NLE_AGAIN) {
            UMS_AGENT_LOG_WARN("nl_recvmsgs_default ums failed: %s (%d)",
                nl_geterror(ret), ret);

            if (ret == -NLE_INTR) {
                return;
            }

            if (ret == -NLE_OBJ_NOTFOUND || ret == -NLE_FAILURE) {
                UMS_AGENT_LOG_INFO("ums.ko may have been unloaded, ret=%d", ret);
            }
            ums_agent_nl_disconnect_and_probe();
            return;
        }
    }

    if (events & EPOLLHUP) {
        UMS_AGENT_LOG_WARN("ums fd received EPOLLHUP, disconnecting");
        ums_agent_nl_disconnect_and_probe();
    }
}

static void ums_agent_nl_reconnect_nlctrl(const char *reason)
{
    ums_agent_nl_teardown_nlctrl();
    if (ums_agent_nl_setup_nlctrl() < 0) {
        UMS_AGENT_LOG_WARN("nlctrl re-setup failed after %s", reason);
    }
}

static void ums_agent_nl_handle_nlctrl_event(uint32_t events)
{
    if (!g_ums_agent_nl.nlctrl_sock) {
        UMS_AGENT_LOG_WARN("nlctrl event received but nlctrl_sock is NULL");
        return;
    }

    if (events & EPOLLIN) {
        int ret = nl_recvmsgs_default(g_ums_agent_nl.nlctrl_sock);
        if (ret < 0 && ret != -NLE_AGAIN) {
            UMS_AGENT_LOG_WARN(
                "nl_recvmsgs_default nlctrl failed: %s (%d), events=0x%x",
                nl_geterror(ret), ret, events);
            ums_agent_nl_reconnect_nlctrl("recv failed");
            return;
        }
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        UMS_AGENT_LOG_WARN("nlctrl fd received error/hangup event 0x%x", events);
        ums_agent_nl_reconnect_nlctrl("EPOLLERR/EPOLLHUP");
    }
}

static void ums_agent_nl_backoff_probe(void)
{
    int next = g_ums_agent_nl.probe_interval_sec * 2;
    if (next > UMS_AGENT_NL_PROBE_INTERVAL_MAX_SEC) {
        next = UMS_AGENT_NL_PROBE_INTERVAL_MAX_SEC;
    }
    if (next == g_ums_agent_nl.probe_interval_sec) {
        return;
    }

    g_ums_agent_nl.probe_interval_sec = next;

    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_interval.tv_sec = next;
    its.it_value.tv_sec = next;
    if (timerfd_settime(g_ums_agent_nl.probe_fd, 0, &its, NULL) < 0) {
        UMS_AGENT_LOG_ERR("timerfd_settime failed: %s (errno=%d)",
            strerror(errno), errno);
    }
}

static void ums_agent_nl_handle_probe_timer(uint32_t events)
{
    if (g_ums_agent_nl.probe_fd < 0) {
        UMS_AGENT_LOG_WARN("probe timer event received but probe_fd is invalid");
        return;
    }

    if (events & EPOLLIN) {
        uint64_t expirations;
        ssize_t n = read(g_ums_agent_nl.probe_fd, &expirations,
            sizeof(expirations));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return;
            }
            UMS_AGENT_LOG_ERR("read probe timerfd failed: %s (errno=%d)",
                strerror(errno), errno);
            return;
        }

        if (!g_ums_agent_nl.ums_available) {
            UMS_AGENT_LOG_DEBUG("probing UMS_GENL family availability");
            ums_agent_nl_try_connect_ums();
        }

        if (!g_ums_agent_nl.ums_available) {
            ums_agent_nl_backoff_probe();
            UMS_AGENT_LOG_DEBUG("probe failed, next probe in %ds",
                g_ums_agent_nl.probe_interval_sec);
        }
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        UMS_AGENT_LOG_WARN("probe timer fd received error event 0x%x", events);
        ums_agent_nl_teardown_probe_timer();
        if (ums_agent_nl_setup_probe_timer() < 0) {
            UMS_AGENT_LOG_ERR("probe timer re-setup failed after error event");
        }
    }
}

void ums_agent_nl_handle_event(int fd, uint32_t events)
{
    if (fd == g_ums_agent_nl.ums_fd) {
        ums_agent_nl_handle_ums_event(events);
        return;
    }

    if (fd == g_ums_agent_nl.nlctrl_fd) {
        ums_agent_nl_handle_nlctrl_event(events);
        return;
    }

    if (fd == g_ums_agent_nl.probe_fd) {
        ums_agent_nl_handle_probe_timer(events);
        return;
    }

    UMS_AGENT_LOG_WARN("unknown netlink fd=%d, events=0x%x", fd, events);
}

void ums_agent_nl_set_token_submit_cb(ums_agent_nl_token_submit_cb cb)
{
    if (!g_ums_agent_nl.initialized) {
        UMS_AGENT_LOG_WARN("netlink not initialized, cannot set token_submit_cb");
        return;
    }
    g_ums_agent_nl.token_submit_cb = cb;
}

int ums_agent_nl_send_token_submit_fail(uint32_t clc_session_id,
    const uint8_t *initiator_id, int result)
{
    if (!g_ums_agent_nl.ums_available) {
        UMS_AGENT_LOG_WARN("UMS_GENL not available, cannot send "
            "TOKEN_SUBMIT_FAIL, clc_session_id=%u", clc_session_id);
        return -1;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        UMS_AGENT_LOG_ERR("nlmsg_alloc failed for TOKEN_SUBMIT_FAIL");
        return -1;
    }

    int ret;

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
        g_ums_agent_nl.ums_family_id, 0, 0,
        UMS_CMD_TOKEN_SUBMIT_FAIL, UMS_GENL_VERSION)) {
        UMS_AGENT_LOG_ERR("genlmsg_put failed for TOKEN_SUBMIT_FAIL");
        goto err_free;
    }

    ret = nla_put_u32(msg, UMS_ATTR_CLC_SESSION_ID, clc_session_id);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put CLC_SESSION_ID failed: %s", nl_geterror(ret));
        goto err_free;
    }

    ret = nla_put(msg, UMS_ATTR_INITIATOR_ID, UMS_SYSTEMID_LEN, initiator_id);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put INITIATOR_ID failed: %s", nl_geterror(ret));
        goto err_free;
    }

    ret = nla_put_u32(msg, UMS_ATTR_RESULT, (uint32_t)result);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put RESULT failed: %s", nl_geterror(ret));
        goto err_free;
    }

    ret = nl_send_auto(g_ums_agent_nl.ums_sock, msg);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nl_send_auto TOKEN_SUBMIT_FAIL failed: %s, "
            "clc_session_id=%u, result=%d", nl_geterror(ret), clc_session_id, result);
        goto err_free;
    }

    UMS_AGENT_LOG_INFO("sent TOKEN_SUBMIT_FAIL, clc_session_id=%u, result=%d",
        clc_session_id, result);
    nlmsg_free(msg);
    return 0;

err_free:
    nlmsg_free(msg);
    return -1;
}

int ums_agent_nl_send_token_deliver(uint32_t clc_session_id,
    const uint8_t *initiator_id,
    uint32_t peer_jetty_token, uint32_t peer_seg_token,
    uint8_t first_contact)
{
    if (!g_ums_agent_nl.ums_available) {
        UMS_AGENT_LOG_WARN("UMS_GENL not available, cannot send TOKEN_DELIVER, "
            "clc_session_id=%u", clc_session_id);
        return -1;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        UMS_AGENT_LOG_ERR("nlmsg_alloc failed for TOKEN_DELIVER");
        return -1;
    }

    int ret;

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
        g_ums_agent_nl.ums_family_id, 0, 0,
        UMS_CMD_TOKEN_DELIVER, UMS_GENL_VERSION)) {
        UMS_AGENT_LOG_ERR("genlmsg_put failed for TOKEN_DELIVER");
        goto err_free;
    }

    ret = nla_put_u32(msg, UMS_ATTR_CLC_SESSION_ID, clc_session_id);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put CLC_SESSION_ID failed: %s", nl_geterror(ret));
        goto err_free;
    }

    ret = nla_put(msg, UMS_ATTR_INITIATOR_ID, UMS_SYSTEMID_LEN, initiator_id);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put INITIATOR_ID failed: %s", nl_geterror(ret));
        goto err_free;
    }

    ret = nla_put_u8(msg, UMS_ATTR_FIRST_CONTACT, first_contact);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put FIRST_CONTACT failed: %s",
            nl_geterror(ret));
        goto err_free;
    }

    if (first_contact) {
        ret = nla_put_u32(msg, UMS_ATTR_JETTY_TOKEN, peer_jetty_token);
        if (ret < 0) {
            UMS_AGENT_LOG_ERR("nla_put JETTY_TOKEN failed: %s",
                nl_geterror(ret));
            goto err_free;
        }
    }

    ret = nla_put_u32(msg, UMS_ATTR_SEG_TOKEN, peer_seg_token);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nla_put SEG_TOKEN failed: %s",
            nl_geterror(ret));
        goto err_free;
    }

    ret = nl_send_auto(g_ums_agent_nl.ums_sock, msg);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("nl_send_auto TOKEN_DELIVER failed: %s, "
            "clc_session_id=%u", nl_geterror(ret), clc_session_id);
        goto err_free;
    }

    UMS_AGENT_LOG_INFO("sent TOKEN_DELIVER, clc_session_id=%u", clc_session_id);
    ums_agent_nl_secure_zero_msg(msg);
    nlmsg_free(msg);
    return 0;

err_free:
    ums_agent_nl_secure_zero_msg(msg);
    nlmsg_free(msg);
    return -1;
}
