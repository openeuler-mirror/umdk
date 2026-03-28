/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc admin
 * Create: 2024-4-23
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "unix_server.h"
#include "urpc_framework_errno.h"
#include "urpc_socket.h"

#include "urpc_admin_cmd.h"
#include "urpc_admin_log.h"
#include "urpc_admin_param.h"

#define URPC_ADMIN_CONNECT_TIMEOUT_S 1
#define URPC_ADMIN_SEND_RECV_TIMEOUT_S 8

static struct {
    int fd;
    struct sockaddr_un addr;
} g_urpc_admin_ctx;

static int urpc_admin_connect(urpc_admin_config_t *cfg)
{
    g_urpc_admin_ctx.fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_urpc_admin_ctx.fd < 0) {
        LOG_PRINT("create socket failed\n");
        return -1;
    }

    int ret;
    g_urpc_admin_ctx.addr.sun_family = AF_UNIX;
    char buf[PATH_MAX + 1] = {0};
    if (file_path_get(buf, PATH_MAX + 1, cfg->path) != 0) {
        LOG_PRINT("check unix domain file path %s failed\n", cfg->path);
        goto ERROR;
    }

    ret = snprintf(g_urpc_admin_ctx.addr.sun_path, sizeof(g_urpc_admin_ctx.addr.sun_path),
        "%s/urpc.sock.%u", buf, cfg->pid);
    if (ret < 0 || ret >= (int)sizeof(g_urpc_admin_ctx.addr.sun_path)) {
        LOG_PRINT("copy socket name failed, error %d\n", ret);
        goto ERROR;
    }

    struct timeval tv = {.tv_sec = URPC_ADMIN_CONNECT_TIMEOUT_S};
    if (setsockopt(g_urpc_admin_ctx.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        LOG_PRINT("set socket connect timeout failed, %s\n", strerror(errno));
        goto ERROR;
    }

    ret = connect(g_urpc_admin_ctx.fd, (struct sockaddr *)&g_urpc_admin_ctx.addr, sizeof(struct sockaddr_un));
    if (ret < 0) {
        LOG_PRINT("connect %s failed, %s\n", g_urpc_admin_ctx.addr.sun_path, strerror(errno));
        goto ERROR;
    }

    tv.tv_sec = URPC_ADMIN_SEND_RECV_TIMEOUT_S;
    if (setsockopt(g_urpc_admin_ctx.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        LOG_PRINT("set socket recv timeout failed, %s\n", strerror(errno));
        goto ERROR;
    }

    return 0;

ERROR:
    (void)close(g_urpc_admin_ctx.fd);
    g_urpc_admin_ctx.fd = -1;
    return -1;
}

static void urpc_admin_close(void)
{
    (void)close(g_urpc_admin_ctx.fd);
    g_urpc_admin_ctx.fd = -1;
}

int main(int argc, char *argv[])
{
    int ret = -1;
    urpc_admin_config_t cfg = {0};
    urpc_ipc_ctl_head_t req_ctl, rsp_ctl;
    urpc_admin_cmd_t *cmd = NULL;
    char *request = NULL;
    char *reply = NULL;

    if (urpc_admin_args_parse(argc, argv, &cfg) != 0) {
        return -1;
    }

    if (cfg.no_request) {
        return 0;
    }

    if (urpc_admin_connect(&cfg) != 0) {
        return -1;
    }

    cmd = urpc_admin_cmd_get(cfg.module_id, cfg.cmd_id);
    if (cmd == NULL) {
        goto OUT;
    }

    if (cmd->create_request(&req_ctl, &request, &cfg) != 0) {
        goto OUT;
    }

    if (unix_ipc_ctl_send(g_urpc_admin_ctx.fd, &req_ctl, request) != URPC_SUCCESS) {
        LOG_PRINT("send ipc request failed, module_id %hu, cmd_id %hu, %s\n", rsp_ctl.module_id, rsp_ctl.cmd_id,
            strerror(errno));
        goto OUT;
    }

    if (unix_ipc_ctl_recv(g_urpc_admin_ctx.fd, &rsp_ctl, &reply) != URPC_SUCCESS) {
        LOG_PRINT("recv ipc reply failed, %s\n", strerror(errno));
        goto OUT;
    }

    if (cmd->process_response(&rsp_ctl, reply, &cfg) != 0) {
        goto OUT;
    }

    ret = 0;

OUT:
    free(request);
    free(reply);
    urpc_admin_close();

    return ret;
}
