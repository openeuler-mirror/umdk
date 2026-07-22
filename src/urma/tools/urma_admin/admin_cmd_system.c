/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: system sub-command source file for urma_admin
 * Author: Wang Hang
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10   create file
 */

#include <errno.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <stdio.h>

#include "admin_netlink.h"

#include "admin_cmd.h"

typedef struct admin_show_system_ctx {
    uint8_t dev_ns_mode;
    uint8_t eid_ns_mode;
    bool has_dev_ns_mode;
    bool has_eid_ns_mode;
    bool found;
    int ret;
} admin_show_system_ctx_t;

static int admin_show_system_reply_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attrs[UBCORE_ATTR_AFTER_LAST] = {0};
    admin_show_system_ctx_t *ctx = arg;
    struct nlattr *attr;
    int ret;

    if (ctx == NULL) {
        return NL_OK;
    }

    ret = nla_parse(attrs, UBCORE_ATTR_AFTER_LAST - 1,
                    genlmsg_attrdata(genlhdr, 0),
                    genlmsg_attrlen(genlhdr, 0), NULL);
    if (ret != 0) {
        ctx->ret = ret;
        return NL_STOP;
    }

    attr = attrs[UBCORE_ATTR_DEV_NS_MODE];
    if (attr != NULL) {
        if (nla_len(attr) != sizeof(ctx->dev_ns_mode)) {
            ctx->ret = -EINVAL;
            return NL_STOP;
        }
        ctx->dev_ns_mode = nla_get_u8(attr);
        ctx->has_dev_ns_mode = true;
    }

    attr = attrs[UBCORE_ATTR_EID_NS_MODE];
    if (attr != NULL) {
        if (nla_len(attr) != sizeof(ctx->eid_ns_mode)) {
            ctx->ret = -EINVAL;
            return NL_STOP;
        }
        ctx->eid_ns_mode = nla_get_u8(attr);
        ctx->has_eid_ns_mode = true;
    }

    if (ctx->has_dev_ns_mode || ctx->has_eid_ns_mode) {
        ctx->found = true;
    }

    return NL_STOP;
}

static int admin_show_system_open_sock(struct nl_sock **sock, int *genl_id)
{
    struct nl_sock *new_sock = nl_socket_alloc();
    int ret;

    if (new_sock == NULL) {
        printf("Failed to allocate netlink socket\n");
        return -ENOMEM;
    }

    ret = genl_connect(new_sock);
    if (ret < 0) {
        printf("Failed to connect netlink socket for \"%s\", ret=%d\n",
               UBCORE_GENL_FAMILY_NAME, ret);
        nl_socket_free(new_sock);
        return ret;
    }

    ret = genl_ctrl_resolve(new_sock, UBCORE_GENL_FAMILY_NAME);
    if (ret < 0) {
        printf("Resolving of \"%s\" failed, ret=%d\n",
               UBCORE_GENL_FAMILY_NAME, ret);
        nl_close(new_sock);
        nl_socket_free(new_sock);
        return ret;
    }

    *sock = new_sock;
    *genl_id = ret;
    return 0;
}

static struct nl_msg *admin_show_system_alloc_genl_msg(int genl_id)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct genlmsghdr *msg_hdr;

    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return NULL;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, 0,
                          URMA_CORE_SHOW_SYSTEM, GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        printf("Failed to put genl header\n");
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

static int admin_show_system_recv_reply(struct nl_sock *sock,
                                        admin_show_system_ctx_t *ctx)
{
    int reset_ret;
    int ret;

    ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                              admin_show_system_reply_cb, ctx);
    if (ret < 0) {
        printf("Failed to set netlink valid callback, ret:%d\n", ret);
        return ret;
    }

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        printf("Failed to recv netlink msg, ret:%d\n", ret);
    }

    reset_ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                                    NULL, NULL);
    if (reset_ret < 0) {
        printf("Failed to reset netlink valid callback, ret:%d\n", reset_ret);
        if (ret == 0) {
            ret = reset_ret;
        }
    }

    return ret;
}

int admin_nl_set_dev_sharing(bool enabled)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_DEV_NS_MODE, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_u8(msg, UBCORE_ATTR_DEV_NS_MODE, (uint8_t)enabled);
    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    return ret;
}

static int admin_nl_set_eid_sharing(bool enabled)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_EID_NS_MODE, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_u8(msg, UBCORE_ATTR_EID_NS_MODE, (uint8_t)enabled);
    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    return ret;
}

static int cmd_system_usage(admin_config_t *cfg)
{
    (void)cfg;
    printf("Usage:\n"
           "  urma_admin system show\n"
           "  urma_admin system set dev_sharing {on|off}\n"
           "  urma_admin system set eid_sharing {on|off}\n"
           "\n"
           "Options:\n"
           "  dev_sharing  Device namespace sharing mode\n"
           "  eid_sharing  EID namespace sharing mode\n");
    return 0;
}

static int cmd_system_show(admin_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg;
    int genl_id = 0;
    int ret;

    (void)cfg;
    ret = admin_show_system_open_sock(&sock, &genl_id);
    if (ret != 0) {
        return ret;
    }

    msg = admin_show_system_alloc_genl_msg(genl_id);
    if (msg == NULL) {
        nl_close(sock);
        nl_socket_free(sock);
        return -ENOMEM;
    }

    admin_show_system_ctx_t ctx = {0};
    nl_socket_disable_auto_ack(sock);
    ret = nl_send_auto(sock, msg);
    nl_socket_enable_auto_ack(sock);
    if (ret < 0) {
        printf("Failed to send netlink msg, ret:%d\n", ret);
    } else {
        ret = admin_show_system_recv_reply(sock, &ctx);
    }

    nlmsg_free(msg);
    nl_close(sock);
    nl_socket_free(sock);

    if (ret != 0) {
        return ret;
    }
    if (ctx.ret != 0) {
        return ctx.ret;
    }
    if (!ctx.found) {
        printf("Failed to get system info, no valid reply\n");
        return -ENOENT;
    }

    if (ctx.has_dev_ns_mode) {
        printf("DEV_NS_SHARED: %s\n", ctx.dev_ns_mode ? "on" : "off");
    } else {
        printf("DEV_NS_SHARED: unknown\n");
    }

    if (ctx.has_eid_ns_mode) {
        printf("EID_NS_SHARED: %s\n", ctx.eid_ns_mode ? "on" : "off");
    } else {
        printf("EID_NS_SHARED: unknown\n");
    }

    return 0;
}

static int cmd_system_set_dev_sharing(admin_config_t *cfg)
{
    int ret;

    if ((ret = pop_arg_sharing(cfg)) != 0) {
        return ret;
    }

    return admin_nl_set_dev_sharing(cfg->sharing_on);
}

static int cmd_system_set_eid_sharing(admin_config_t *cfg)
{
    int ret;

    if ((ret = pop_arg_sharing(cfg)) != 0) {
        return ret;
    }

    return admin_nl_set_eid_sharing(cfg->sharing_on);
}

static int cmd_system_set(admin_config_t *cfg)
{
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_system_usage},
        {"dev_sharing", cmd_system_set_dev_sharing},
        {"eid_sharing", cmd_system_set_eid_sharing},
        {0},
    };
    return exec_cmd(cfg, cmds);
}

int admin_cmd_system(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_system_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_system_usage},
        {"show", cmd_system_show},
        {"set", cmd_system_set},
        {0},
    };
    return exec_cmd(cfg, cmds);
}
