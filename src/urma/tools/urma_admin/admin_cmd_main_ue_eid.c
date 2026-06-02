/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: main_ue_eid sub-command source file for urma_admin
 * Author: Weijie Li
 * Create: 2026-05-30
 * Note:
 * History: 2026-05-30   create file
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netlink/attr.h>
#include <netlink/errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include "admin_cmd.h"
#include "admin_netlink.h"

#define ADMIN_MAIN_UE_EID_BATCH_MAX 128U

typedef enum admin_main_ue_eid_reply_type {
    ADMIN_MAIN_UE_EID_REPLY_LOOKUP,
    ADMIN_MAIN_UE_EID_REPLY_STATUS,
} admin_main_ue_eid_reply_type_t;

typedef struct admin_main_ue_eid_reply_ctx {
    admin_main_ue_eid_reply_type_t type;
    urma_eid_t main_ue_eid;
    int status;
    bool found;
    int ret;
} admin_main_ue_eid_reply_ctx_t;

static bool admin_main_ue_eid_is_zero(const urma_eid_t *eid)
{
    for (uint32_t i = 0; i < sizeof(eid->raw); i++) {
        if (eid->raw[i] != 0) {
            return false;
        }
    }
    return true;
}

static int admin_main_ue_eid_pop_eid(admin_config_t *cfg, const char *name,
                                     urma_eid_t *eid)
{
    char *arg = pop_arg(cfg);
    int ret;

    if (arg == NULL) {
        printf("No %s specified.\n", name);
        return -EINVAL;
    }

    ret = admin_str_to_eid(arg, eid);
    if (ret != 0) {
        printf("Invalid %s: %s.\n", name, arg);
        return ret;
    }
    if (admin_main_ue_eid_is_zero(eid)) {
        printf("Invalid %s: zero EID is not allowed.\n", name);
        return -EINVAL;
    }
    return 0;
}

static bool admin_main_ue_eid_is_not_found(int ret)
{
    return ret == -ENOENT || ret == -NLE_OBJ_NOTFOUND;
}

static int admin_main_ue_eid_put_binary(struct nl_msg *msg, int attr,
                                        const uint8_t *data, size_t len)
{
    int ret;

    if (len > INT_MAX) {
        printf("Binary attribute %d is too long, len: %zu\n", attr, len);
        return -EINVAL;
    }

    ret = nla_put(msg, attr, (int)len, data);
    if (ret != 0) {
        printf("Failed to put binary attribute %d, ret: %d\n", attr, ret);
    }
    return ret;
}

static int admin_main_ue_eid_put_eid(struct nl_msg *msg, int attr,
                                     const urma_eid_t *eid)
{
    return admin_main_ue_eid_put_binary(msg, attr, eid->raw, sizeof(*eid));
}

static int admin_main_ue_eid_send_eid_cmd(uint8_t cmd, const urma_eid_t *eid)
{
    struct nl_msg *msg = admin_nl_alloc_msg(cmd, 0, UBCORE_GENL);
    int ret;

    if (msg == NULL) {
        return -ENOMEM;
    }

    ret = admin_main_ue_eid_put_eid(msg, UBCORE_ATTR_EID, eid);
    if (ret == 0) {
        ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    }

    admin_nl_free_msg(msg);
    return ret;
}

static int admin_main_ue_eid_insert(const urma_eid_t *eid,
                                    const urma_eid_t *main_ue_eid)
{
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_ADMIN_INSERT_MAIN_UE_EID, 0, UBCORE_GENL);
    int ret;

    if (msg == NULL) {
        return -ENOMEM;
    }

    ret = admin_main_ue_eid_put_eid(msg, UBCORE_ATTR_EID, eid);
    if (ret == 0) {
        ret = admin_main_ue_eid_put_eid(msg, UBCORE_ATTR_MAIN_UE_EID,
                                        main_ue_eid);
    }
    if (ret == 0) {
        ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    }

    admin_nl_free_msg(msg);
    return ret;
}

static int admin_main_ue_eid_reply_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attrs[UBCORE_ATTR_AFTER_LAST] = {0};
    admin_main_ue_eid_reply_ctx_t *ctx = arg;
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

    if (ctx->type == ADMIN_MAIN_UE_EID_REPLY_LOOKUP) {
        attr = attrs[UBCORE_ATTR_MAIN_UE_EID];
        if (attr == NULL || nla_len(attr) != sizeof(ctx->main_ue_eid)) {
            ctx->ret = -EINVAL;
            return NL_STOP;
        }
        (void)memcpy(&ctx->main_ue_eid, nla_data(attr),
                     sizeof(ctx->main_ue_eid));
    } else {
        attr = attrs[UBCORE_ATTR_STATUS];
        if (attr == NULL || nla_len(attr) != sizeof(int32_t)) {
            ctx->ret = -EINVAL;
            return NL_STOP;
        }
        ctx->status = nla_get_s32(attr);
    }

    ctx->found = true;
    return NL_STOP;
}

static int admin_main_ue_eid_open_sock(struct nl_sock **sock, int *genl_id)
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

static struct nl_msg *admin_main_ue_eid_alloc_genl_msg(int genl_id,
                                                       uint8_t cmd)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct genlmsghdr *msg_hdr;

    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return NULL;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, 0,
                          cmd, GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        printf("Failed to put genl header\n");
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

static int admin_main_ue_eid_recv_reply(struct nl_sock *sock,
                                        admin_main_ue_eid_reply_ctx_t *ctx)
{
    int reset_ret;
    int ret;

    ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
                              admin_main_ue_eid_reply_cb, ctx);
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

static int admin_main_ue_eid_send_recv(uint8_t cmd, const urma_eid_t *eid,
                                       admin_main_ue_eid_reply_ctx_t *ctx)
{
    struct nl_sock *sock = NULL;
    struct nl_msg *msg;
    int genl_id = 0;
    int ret = 0;

    ret = admin_main_ue_eid_open_sock(&sock, &genl_id);
    if (ret != 0) {
        return ret;
    }

    msg = admin_main_ue_eid_alloc_genl_msg(genl_id, cmd);
    if (msg == NULL) {
        nl_close(sock);
        nl_socket_free(sock);
        return -ENOMEM;
    }

    if (eid != NULL) {
        ret = admin_main_ue_eid_put_eid(msg, UBCORE_ATTR_EID, eid);
    }
    if (ret == 0) {
        nl_socket_disable_auto_ack(sock);
        ret = nl_send_auto(sock, msg);
        nl_socket_enable_auto_ack(sock);
        if (ret < 0) {
            printf("Failed to send netlink msg, ret:%d\n", ret);
        } else {
            ret = admin_main_ue_eid_recv_reply(sock, ctx);
        }
    }

    nlmsg_free(msg);
    nl_close(sock);
    nl_socket_free(sock);
    return ret;
}

static int admin_main_ue_eid_check_reply(const admin_main_ue_eid_reply_ctx_t *ctx,
                                         int not_found_ret)
{
    if (ctx->ret != 0) {
        return ctx->ret;
    }
    if (!ctx->found) {
        return not_found_ret;
    }
    return 0;
}

static int admin_main_ue_eid_lookup(const urma_eid_t *eid,
                                    urma_eid_t *main_ue_eid)
{
    admin_main_ue_eid_reply_ctx_t ctx = {
        .type = ADMIN_MAIN_UE_EID_REPLY_LOOKUP,
    };
    int ret;

    ret = admin_main_ue_eid_send_recv(URMA_CORE_ADMIN_LOOKUP_MAIN_UE_EID,
                                      eid, &ctx);
    if (ret != 0) {
        return ret;
    }

    ret = admin_main_ue_eid_check_reply(&ctx, -ENOENT);
    if (ret != 0) {
        return ret;
    }

    *main_ue_eid = ctx.main_ue_eid;
    return 0;
}

static int admin_main_ue_eid_flush(void)
{
    admin_main_ue_eid_reply_ctx_t ctx = {
        .type = ADMIN_MAIN_UE_EID_REPLY_STATUS,
    };
    int ret;

    ret = admin_main_ue_eid_send_recv(URMA_CORE_ADMIN_FLUSH_MAIN_UE_EID,
                                      NULL, &ctx);
    if (ret != 0) {
        return ret;
    }

    ret = admin_main_ue_eid_check_reply(&ctx, -EINVAL);
    if (ret != 0) {
        return ret;
    }
    return ctx.status;
}

static int admin_main_ue_eid_insert_batch(const urma_eid_t *main_ue_eid,
                                          const urma_eid_t *eids,
                                          uint32_t eid_num)
{
    struct nl_msg *msg;
    int ret;

    if (eid_num == 0 || eid_num > ADMIN_MAIN_UE_EID_BATCH_MAX) {
        return -EINVAL;
    }

    msg = admin_nl_alloc_msg(URMA_CORE_ADMIN_INSERT_MAIN_UE_EID_BATCH, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    ret = admin_main_ue_eid_put_eid(msg, UBCORE_ATTR_MAIN_UE_EID, main_ue_eid);
    if (ret == 0) {
        ret = admin_nl_put_u32(msg, UBCORE_ATTR_EID_NUM, eid_num);
    }
    if (ret == 0) {
        ret = admin_main_ue_eid_put_binary(msg, UBCORE_ATTR_EID_LIST,
                                           (const uint8_t *)eids,
                                           (size_t)eid_num * sizeof(*eids));
    }
    if (ret == 0) {
        ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    }

    admin_nl_free_msg(msg);
    return ret;
}

static int cmd_main_ue_eid_usage(admin_config_t *cfg)
{
    (void)cfg;
    printf("Usage:\n"
           "  urma_admin main_ue_eid insert <eid> <main_ue_eid>\n"
           "  urma_admin main_ue_eid insert_batch <main_ue_eid> <eid> [eid...]\n"
           "  urma_admin main_ue_eid delete <eid>\n"
           "  urma_admin main_ue_eid lookup <eid>\n"
           "  urma_admin main_ue_eid flush\n"
           "\n"
           "Options:\n"
           "  <eid>          EID key stored in the main UE EID table\n"
           "  <main_ue_eid>  Main UE EID mapped from one or more EIDs\n");
    return 0;
}

static int cmd_main_ue_eid_insert(admin_config_t *cfg)
{
    urma_eid_t eid = {0};
    urma_eid_t main_ue_eid = {0};
    int ret;

    ret = admin_main_ue_eid_pop_eid(cfg, "eid", &eid);
    if (ret != 0) {
        return ret;
    }
    ret = admin_main_ue_eid_pop_eid(cfg, "main_ue_eid", &main_ue_eid);
    if (ret != 0) {
        return ret;
    }

    ret = admin_main_ue_eid_insert(&eid, &main_ue_eid);
    if (ret != 0) {
        printf("Failed to insert main_ue_eid entry, ret:%d\n", ret);
    }
    return ret;
}

static int cmd_main_ue_eid_insert_batch(admin_config_t *cfg)
{
    urma_eid_t main_ue_eid = {0};
    urma_eid_t *eids;
    uint32_t eid_num;
    int ret;

    ret = admin_main_ue_eid_pop_eid(cfg, "main_ue_eid", &main_ue_eid);
    if (ret != 0) {
        return ret;
    }
    if (cfg->argc <= 0 || cfg->argc > ADMIN_MAIN_UE_EID_BATCH_MAX) {
        printf("Invalid eid num: %d, which is not belong to 1 - 128.\n", cfg->argc);
        return -EINVAL;
    }

    eid_num = (uint32_t)cfg->argc;
    eids = calloc(eid_num, sizeof(*eids));
    if (eids == NULL) {
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < eid_num; i++) {
        ret = admin_main_ue_eid_pop_eid(cfg, "eid", &eids[i]);
        if (ret != 0) {
            free(eids);
            return ret;
        }
    }

    ret = admin_main_ue_eid_insert_batch(&main_ue_eid, eids, eid_num);
    if (ret != 0) {
        printf("Failed to insert main_ue_eid batch, ret:%d\n", ret);
    }
    free(eids);
    return ret;
}

static int cmd_main_ue_eid_delete(admin_config_t *cfg)
{
    urma_eid_t eid = {0};
    int ret;

    ret = admin_main_ue_eid_pop_eid(cfg, "eid", &eid);
    if (ret != 0) {
        return ret;
    }

    ret = admin_main_ue_eid_send_eid_cmd(URMA_CORE_ADMIN_DELETE_MAIN_UE_EID,
                                         &eid);
    if (ret != 0) {
        if (admin_main_ue_eid_is_not_found(ret)) {
            printf("main_ue_eid entry not found for " EID_FMT "\n",
                   EID_ARGS(eid));
            return ret;
        }
        printf("Failed to delete main_ue_eid entry, ret:%d\n", ret);
    }
    return ret;
}

static int cmd_main_ue_eid_lookup(admin_config_t *cfg)
{
    urma_eid_t main_ue_eid = {0};
    urma_eid_t eid = {0};
    int ret;

    ret = admin_main_ue_eid_pop_eid(cfg, "eid", &eid);
    if (ret != 0) {
        return ret;
    }

    ret = admin_main_ue_eid_lookup(&eid, &main_ue_eid);
    if (ret != 0) {
        if (admin_main_ue_eid_is_not_found(ret)) {
            printf("main_ue_eid entry not found for " EID_FMT "\n",
                   EID_ARGS(eid));
            return ret;
        }
        printf("Failed to lookup main_ue_eid, ret:%d\n", ret);
        return ret;
    }

    printf(EID_FMT "\n", EID_ARGS(main_ue_eid));
    return 0;
}

static int cmd_main_ue_eid_flush(admin_config_t *cfg)
{
    int ret;

    (void)cfg;
    ret = admin_main_ue_eid_flush();
    if (ret != 0) {
        printf("Failed to flush main_ue_eid table, ret:%d\n", ret);
    }
    return ret;
}

int admin_cmd_main_ue_eid(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_main_ue_eid_usage(cfg);
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_main_ue_eid_usage},
        {"insert", cmd_main_ue_eid_insert},
        {"insert_batch", cmd_main_ue_eid_insert_batch},
        {"delete", cmd_main_ue_eid_delete},
        {"lookup", cmd_main_ue_eid_lookup},
        {"flush", cmd_main_ue_eid_flush},
        {0},
    };
    return exec_cmd(cfg, cmds);
}
