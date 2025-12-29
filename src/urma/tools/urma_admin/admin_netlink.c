/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: netlink header file for urma_admin
 * Author: Yan Fangfang
 * Create: 2023-12-07
 * Note:
 * History: 2023-12-07   create file
 */

#include <errno.h>
#include <fcntl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "urma_cmd.h"
#include "urma_types.h"

#include "admin_cmd.h"

#include "admin_netlink.h"

#define UBURMA_NL_TYPE 25

int admin_nl_talk(void *req, size_t len, enum admin_nlmsg_type type, admin_nl_resp *resp)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, UBURMA_NL_TYPE);
    if (fd == -1) {
        printf("create netlink socket err: %d\n", errno);
        return -1;
    }

    struct sockaddr_nl src_addr;
    (void)memset(&src_addr, 0, sizeof(struct sockaddr_nl));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = (uint32_t)getpid();
    src_addr.nl_groups = 0;

    if (bind(fd, (struct sockaddr *)&src_addr, sizeof(struct sockaddr_nl)) != 0) {
        printf("Failed to bind port, err: %d.\n", errno);
        (void)close(fd);
        return -1;
    }

    struct sockaddr_nl dst_addr;
    (void)memset(&dst_addr, 0, sizeof(struct sockaddr_nl));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0; // to kernel
    dst_addr.nl_groups = 0;

    struct nlmsghdr *nlh = calloc(1, NLMSG_SPACE(len));
    if (nlh == NULL) {
        (void)close(fd);
        return -1;
    }

    nlh->nlmsg_len = (uint32_t)NLMSG_SPACE(len);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq = src_addr.nl_pid;
    nlh->nlmsg_pid = src_addr.nl_pid; /* sender port ID */
    (void)memcpy(NLMSG_DATA(nlh), req, len);

    ssize_t ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_nl));
    if (ret == -1) {
        free(nlh);
        (void)close(fd);
        printf("sendto err: %d.\n", errno);
        return -1;
    }

    socklen_t src_addr_len = (socklen_t)sizeof(struct sockaddr_nl);
    ssize_t recv_len =
        recvfrom(fd, nlh, NLMSG_SPACE(sizeof(admin_nl_resp)), 0, (struct sockaddr *)&src_addr, &src_addr_len);
    if (recv_len <= 0) {
        free(nlh);
        (void)close(fd);
        printf("failed to recv nl resp");
        return -1;
    }

    (void)memcpy(resp, NLMSG_DATA(nlh), sizeof(admin_nl_resp));
    free(nlh);
    (void)close(fd);
    return 0;
}

static struct nl_sock *sock = NULL;
static int genl_id = 0;

static int init_sock_and_genl_id()
{
    if (sock != NULL) {
        return 0;
    }

    struct nl_sock *new_sock = nl_socket_alloc();
    if (new_sock == NULL) {
        printf("Failed to allocate netlink socket\n");
        return -ENOMEM;
    }

    int ret;

    ret = genl_connect(new_sock);
    if (ret < 0) {
        printf("Failed to connect netlink socket, ret:%d\n", ret);
        goto free_sock;
    }

    ret = genl_ctrl_resolve(new_sock, UBCORE_GENL_FAMILY_NAME);
    if (ret < 0) {
        printf("Resolving of \"%s\" failed, ret:%d\n", UBCORE_GENL_FAMILY_NAME, ret);
        goto close_sock;
    }
    genl_id = ret;
    sock = new_sock;
    return 0;

close_sock:
    nl_close(sock);
free_sock:
    nl_socket_free(sock);
    return ret;
}

int admin_nl_send_msg(struct nl_msg *msg)
{
    int ret;

    ret = init_sock_and_genl_id();
    if (ret != 0) {
        return ret;
    }

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        printf("Failed to send netlink msg, ret:%d\n", ret);
        return ret;
    }
    return 0;
}

int admin_nl_recv_msg(int (*cb)(struct nl_msg *msg, void *arg), void *arg)
{
    int ret;

    ret = init_sock_and_genl_id();
    if (ret != 0) {
        return ret;
    }

    ret = nl_socket_modify_cb(sock, NL_CB_MSG_IN, NL_CB_CUSTOM, cb, arg);
    if (ret < 0) {
        printf("Failed to set netlink callback, ret:%d\n", ret);
        return ret;
    }

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        printf("Netlink recv failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

int admin_nl_send_recv_msg(struct nl_msg *msg, int (*cb)(struct nl_msg *msg, void *arg), void *arg)
{
    int ret;

    ret = admin_nl_send_msg(msg);
    if (ret != 0) {
        return ret;
    }

    ret = admin_nl_recv_msg(cb, arg);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int nl_default_cb(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

int admin_nl_send_recv_msg_default(struct nl_msg *msg)
{
    return admin_nl_send_recv_msg(msg, nl_default_cb, NULL);
}

struct nl_msg *admin_nl_alloc_msg(uint8_t cmd, int flags)
{
    int ret;

    ret = init_sock_and_genl_id();
    if (ret != 0) {
        return NULL;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return NULL;
    }

    void *msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, flags, cmd, UBCORE_GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        printf("Failed to put genl header\n");
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
};

void admin_nl_free_msg(struct nl_msg *msg)
{
    nlmsg_free(msg);
};
