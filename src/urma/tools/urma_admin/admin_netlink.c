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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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
