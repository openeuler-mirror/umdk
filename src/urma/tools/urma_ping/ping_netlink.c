/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping netlink helper implementation file
 * Author: Wang Hang
 * Create: 2026-06-18
 * Note:
 * History: 2026-06-18 Create file
 */

#include <errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <stdint.h>
#include <stdlib.h>

#include "ping_log.h"
#include "ping_netlink.h"

#define UBAGG_GENL_FAMILY_NAME "UBAGG_GENL"
#define GENL_FAMILY_VERSION    1

enum {
    UBAGG_HDR_ARGS_ADDR = 4,
};

enum {
    UBAGG_NL_CMD_UNSPEC,
    UBAGG_NL_GET_TOPO,
};

typedef struct ping_core_cmd_topo_info {
    struct {
        int node_idx;
    } in;
    struct {
        uint32_t node_num;
        struct urma_ping_ubcore_topo_node topo_info;
    } out;
} ping_core_cmd_topo_info_t;

static struct nl_sock *g_ping_nl_sock = NULL;
static int g_ping_genl_id = 0;

static int ping_nl_init(void)
{
    if (g_ping_nl_sock != NULL) {
        return 0;
    }

    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL) {
        LOG_ERROR("Failed to allocate netlink socket\n");
        return -ENOMEM;
    }

    int ret = genl_connect(sock);
    if (ret < 0) {
        LOG_ERROR("Failed to connect netlink socket for \"%s\", ret=%d\n", UBAGG_GENL_FAMILY_NAME, ret);
        goto free_sock;
    }

    ret = genl_ctrl_resolve(sock, UBAGG_GENL_FAMILY_NAME);
    if (ret < 0) {
        LOG_ERROR("Resolving of \"%s\" failed, ret=%d\n", UBAGG_GENL_FAMILY_NAME, ret);
        goto close_sock;
    }

    g_ping_genl_id = ret;
    g_ping_nl_sock = sock;
    return 0;

close_sock:
    nl_close(sock);
free_sock:
    nl_socket_free(sock);
    return ret;
}

static struct nl_msg *ping_nl_alloc_msg(uint8_t cmd, int flags)
{
    if (ping_nl_init() != 0) {
        return NULL;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (msg == NULL) {
        LOG_ERROR("Failed to allocate netlink message\n");
        return NULL;
    }

    void *msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, g_ping_genl_id, 0, flags, cmd, GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        LOG_ERROR("Failed to put genl header\n");
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

static int ping_nl_send_recv_msg_default(struct nl_msg *msg)
{
    int ret = ping_nl_init();
    if (ret != 0) {
        return ret;
    }

    ret = nl_send_auto(g_ping_nl_sock, msg);
    if (ret < 0) {
        LOG_ERROR("Failed to send netlink msg, ret=%d\n", ret);
        return ret;
    }

    ret = nl_recvmsgs_default(g_ping_nl_sock);
    if (ret < 0) {
        LOG_ERROR("Failed to recv netlink msg, ret=%d\n", ret);
    }
    return ret;
}

int ping_get_topo_info(urma_ping_ubcore_topo_map_t *topo_map)
{
    int ret = 0;
    ping_core_cmd_topo_info_t *arg = NULL;
    uint32_t node_num = MAX_NODE_NUM;

    if (topo_map == NULL) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < node_num; ++i) {
        arg = calloc(1, sizeof(*arg));
        if (arg == NULL) {
            ret = -ENOMEM;
            goto free_topo;
        }
        arg->in.node_idx = i;

        struct nl_msg *msg = ping_nl_alloc_msg(UBAGG_NL_GET_TOPO, 0);
        if (msg == NULL) {
            ret = -ENOMEM;
            goto free_topo;
        }

        ret = nla_put_u64(msg, UBAGG_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)arg);
        if (ret != 0) {
            LOG_ERROR("Failed to put u64 attribute %d, ret=%d\n", UBAGG_HDR_ARGS_ADDR, ret);
            nlmsg_free(msg);
            goto free_topo;
        }

        ret = ping_nl_send_recv_msg_default(msg);
        nlmsg_free(msg);
        if (ret < 0) {
            goto free_topo;
        }

        if (arg->out.node_num == 0 || arg->out.node_num > MAX_NODE_NUM) {
            LOG_ERROR("Invalid topo node num from ubagg: %u\n", arg->out.node_num);
            ret = -EINVAL;
            goto free_topo;
        }
        topo_map->topo_infos[i] = arg->out.topo_info;
        topo_map->node_num = arg->out.node_num;
        node_num = arg->out.node_num;
        free(arg);
        arg = NULL;
    }
    return ret;

free_topo:
    free(arg);
    return ret;
}
