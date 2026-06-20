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

#include "bondp_types.h"
#include "urma_log.h"

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
