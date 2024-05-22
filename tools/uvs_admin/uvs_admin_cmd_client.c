/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of generic client ops of uvs_admin
 * Author: Ji Lei
 * Create: 2023-07-11
 * Note:
 * History: 2023-07-11 Ji Lei Initial version
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "uvs_admin_cmd_client.h"

static void client_ctx_uninit(int fd)
{
    (void)close(fd);
}

static int client_ctx_init(uvs_admin_cmd_ctx_t *ctx)
{
    int ret, fd;
    struct sockaddr_un addr = {0};
    struct timeval timeout = {ctx->timeout, 0};

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ctx->path, strlen(DEFAULT_UVSD_SOCK));

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        (void)printf("open socket failed, %s\n", ub_strerror(errno));
        return -errno;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        (void)printf("setsockopt timeout failed %s\n", ub_strerror(errno));
        (void)close(fd);
        return -errno;
    }

    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        (void)printf("connect to server failed, %s\n", ub_strerror(errno));
        (void)close(fd);
        return -errno;
    }

    return fd;
}

static int client_send_req(uvs_admin_request_t *req, int fd)
{
    if (send(fd, req, sizeof(uvs_admin_request_t) + req->req_len, MSG_NOSIGNAL) <= 0) {
        (void)printf("Failed send msg to rsp type %u, %s\n", req->cmd_type, ub_strerror(errno));
        return -errno;
    }

    return 0;
}

static uvs_admin_response_t *client_recv_rsp(int fd, char *buf)
{
    ssize_t read_len = recv(fd, buf, MAX_MSG_LEN, MSG_NOSIGNAL);
    if (read_len <= 0 || read_len >= MAX_MSG_LEN) {
        (void)printf("Failed to read rsp on socket %d, %s\n", fd,
            ub_strerror(errno));
        return NULL;
    }

    return (uvs_admin_response_t *)buf;
}

uvs_admin_response_t *client_get_rsp(uvs_admin_cmd_ctx_t *ctx,
    uvs_admin_request_t *req, char *buf)
{
    int fd;
    int ret;
    uvs_admin_response_t *rsp;

    fd = client_ctx_init(ctx);
    if (fd < 0) {
        return NULL;
    }

    ret = client_send_req(req, fd);
    if (ret < 0) {
        client_ctx_uninit(fd);
        return NULL;
    }

    rsp = client_recv_rsp(fd, buf);
    if (rsp == NULL) {
        client_ctx_uninit(fd);
        return NULL;
    }

    client_ctx_uninit(fd);
    return rsp;
}
