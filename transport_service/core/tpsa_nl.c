/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa netlink implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port netlink functions from tpsa_connect and daemon here
 */

#include <errno.h>
#include "tpsa_log.h"
#include "tpsa_sock.h"
#include "tpsa_nl.h"

int tpsa_nl_server_init(tpsa_nl_ctx_t *nl)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, TPSA_NETLINK_UBCORE_TYPE);
    if (fd == -1) {
        TPSA_LOG_ERR("create socket err: [%d]%s\n", errno, ub_strerror(errno));
        return -1;
    }

    (void)memset(&nl->src_addr, 0, sizeof(struct sockaddr_nl));
    nl->src_addr.nl_family = AF_NETLINK;
    nl->src_addr.nl_pid = (uint32_t)getpid();
    nl->src_addr.nl_groups = 0;
    nl->dst_addr.nl_family = AF_NETLINK;
    nl->dst_addr.nl_pid = 0; // to kernel
    nl->dst_addr.nl_groups = 0;

    if (tpsa_set_nonblock_opt(fd) != 0) {
        TPSA_LOG_ERR("Failed to set netlink opt, err: %s.\n", ub_strerror(errno));
        (void)close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&nl->src_addr, sizeof(struct sockaddr_nl)) != 0) {
        TPSA_LOG_ERR("Failed to bind port, err: [%d]%s.\n", errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }

    /* set nl agent pid */
    tpsa_nl_msg_t msg = {0};
    msg.hdr.nlmsg_type = TPSA_NL_SET_AGENT_PID;
    msg.hdr.nlmsg_pid = (uint32_t)getpid();
    msg.hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)&msg);
    ssize_t ret = sendto(fd, &msg.hdr, msg.hdr.nlmsg_len, 0,
        (struct sockaddr *)&nl->dst_addr, sizeof(struct sockaddr_nl));
    if (ret == -1) {
        (void)close(fd);
        TPSA_LOG_ERR("Failed to sendto err: %s.\n", ub_strerror(errno));
        return -1;
    }
    nl->fd = fd;
    return 0;
}

void tpsa_nl_server_uninit(tpsa_nl_ctx_t *nl)
{
    (void)close(nl->fd);
    nl->fd = -1;
}

int tpsa_nl_send_msg(tpsa_nl_ctx_t *nl, tpsa_nl_msg_t *msg)
{
   if (msg->hdr.nlmsg_len > sizeof(tpsa_nl_msg_t)) {
        TPSA_LOG_ERR("Maximum message length exceeded\n");
        return -1;
    }

    ssize_t ret = sendto(nl->fd, &msg->hdr, msg->hdr.nlmsg_len, 0,
        (struct sockaddr *)&nl->dst_addr, sizeof(struct sockaddr_nl));
    if (ret == -1) {
        TPSA_LOG_ERR("sendto err: %s.\n", ub_strerror(errno));
        return -1;
    }
    TPSA_LOG_INFO("[send_nl_msg:4]---msg_id: %d, msg_type: %d, transport_type: %d.\n",
        msg->nlmsg_seq, msg->msg_type, msg->transport_type);
    return 0;
}