/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: eid sub-command source file for urma_admin
 * Author: Wang Hang
 * Create: 2025-12-26
 * Note:
 * History: 2025-12-26   create file
 */

#include <netlink/genl/genl.h>
#include <stdio.h>
#include <unistd.h>

#include "admin_netlink.h"

#include "admin_cmd.h"

static int nl_set_eid_mode(const admin_config_t *cfg)
{
    admin_core_cmd_set_eid_mode_t arg = {0};
    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_mode = cfg->dynamic_eid_mode;

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_CMD_SET_EID_MODE, 0);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(admin_core_cmd_set_eid_mode_t));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    int ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);
    return ret;
}

static int nl_set_eid_ns(const admin_config_t *cfg)
{
    int ns_fd = admin_get_ns_fd(cfg->ns);
    if (ns_fd < 0) {
        (void)printf("Failed to get ns fd, ns %s.\n", cfg->ns);
        return ns_fd;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_SET_DEV_EID_NS, 0);
    if (msg == NULL) {
        close(ns_fd);
        return -ENOMEM;
    }

    admin_nl_put_string(msg, UBCORE_ATTR_DEV_NAME, cfg->dev_name);
    admin_nl_put_u32(msg, UBCORE_ATTR_EID_IDX, cfg->idx);
    admin_nl_put_u32(msg, UBCORE_ATTR_NS_FD, ns_fd);

    int ret = admin_nl_send_recv_msg_default(msg);
    admin_nl_free_msg(msg);
    close(ns_fd);
    return ret;
}

static int cb_update_eid_handler(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int *ret = arg;

    if (arg == NULL) {
        return 0;
    }

    *ret = nla_get_s32(attr_ptr);
    if (*ret == 0) {
        return 0;
    } else if (*ret == 1) {
        (void)usleep(1); // ret == 1 means in progress, genl will try again.
    } else {
        (void)printf("Failed to %s, invalid parameter.\n",
                     (genlhdr->cmd == (int)URMA_CORE_CMD_ADD_EID) ? "add eid" : "del eid");
    }

    return 0;
}

static int nl_add_eid(const admin_config_t *cfg)
{
    admin_core_cmd_update_eid_t arg = {0};
    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_index = cfg->idx;
    if (strlen(cfg->ns) > 0 && (arg.in.ns_fd = admin_get_ns_fd(cfg->ns)) < 0) {
        (void)printf("set ns failed, ns %s.\n", cfg->ns);
        return -1;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_CMD_ADD_EID, 0);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(admin_core_cmd_update_eid_t));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    int cb_ret = 0;
    int ret = admin_nl_send_recv_msg(msg, cb_update_eid_handler, &cb_ret);
    admin_nl_free_msg(msg);
    return cb_ret | ret;
}

static int nl_del_eid(const admin_config_t *cfg)
{
    admin_core_cmd_update_eid_t arg = {0};
    (void)memcpy(arg.in.dev_name, cfg->dev_name, URMA_ADMIN_MAX_DEV_NAME);
    arg.in.eid_index = cfg->idx;
    arg.in.ns_fd = -1;

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_CMD_DEL_EID, 0);
    if (msg == NULL) {
        return -ENOMEM;
    }

    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(admin_core_cmd_update_eid_t));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    int cb_ret = 0;
    int ret = admin_nl_send_recv_msg(msg, cb_update_eid_handler, &cb_ret);
    admin_nl_free_msg(msg);
    return ret | cb_ret;
}

static int cmd_eid_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin eid add [ DEV ] [ EID_IDX ] [ EID ] --ns [ NETNS ] --mode [ EID_MODE ]\n"
           "       urma_admin eid del [ DEV ] [ EID_IDX ]\n"
           "       urma_admin eid set [ DEV ] [ EID_IDX ] ns [ NETNS ]\n"
           "       urma_admin eid set [ DEV ] [ EID_IDX ] mode { static | dynamic }\n"
           "where  NETNS := /proc/$pid/ns/net\n");
    return 0;
}

static int cmd_eid_add(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid_idx(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid(cfg)) != 0) {
        return ret;
    }

    /* Automatically switch to static mode */
    if ((ret = nl_set_eid_mode(cfg)) != 0) {
        printf("Failed to set eid mode, ret:%d\n", ret);
        return ret;
    }
    if ((ret = nl_add_eid(cfg)) != 0) {
        printf("Failed to add eid, ret:%d\n", ret);
        return ret;
    }
    return 0;
}

static int cmd_eid_del(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid_idx(cfg)) != 0) {
        return ret;
    }

    /* Automatically switch to static mode */
    if ((ret = nl_set_eid_mode(cfg)) < 0) {
        printf("Failed to set eid mode, ret:%d\n", ret);
        return ret;
    }
    if ((ret = nl_del_eid(cfg)) != 0) {
        printf("Failed to delete eid, ret:%d\n", ret);
        return ret;
    }
    return 0;
}

static int cmd_eid_set_mode(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_eid_mode(cfg)) != 0) {
        return ret;
    }
    if ((ret = nl_set_eid_mode(cfg)) != 0) {
        return ret;
    }
    return 0;
}

static int cmd_eid_set_ns(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_ns(cfg)) != 0) {
        return ret;
    }
    if ((ret = nl_set_eid_ns(cfg)) != 0) {
        return ret;
    }
    return 0;
}

static int cmd_eid_set(admin_config_t *cfg)
{
    int ret;
    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }
    if ((ret = pop_arg_eid_idx(cfg)) != 0) {
        return ret;
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_eid_usage},      //
        {"mode", cmd_eid_set_mode}, //
        {"ns", cmd_eid_set_ns},     //
        {0},                        //
    };
    return exec_cmd(cfg, cmds);
}

int admin_cmd_eid(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_eid_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_eid_usage}, //
        {"add", cmd_eid_add},  //
        {"del", cmd_eid_del},  //
        {"set", cmd_eid_set},  //
        {0},                   //
    };
    return exec_cmd(cfg, cmds);
}

// Legacy cmd
int admin_cmd_add_eid_legacy(admin_config_t *cfg)
{
    if (*cfg->dev_name && is_ubc(cfg->dev_name)) {
        (void)printf("This operation is not supported on ubc dev.\n");
        return -1;
    }

    int ret;

    /* Automatically switch to static mode */
    if ((ret = nl_set_eid_mode(cfg)) != 0) {
        printf("Failed to set eid mode, ret:%d\n", ret);
        return ret;
    }
    if ((ret = nl_add_eid(cfg)) != 0) {
        printf("Failed to add eid, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

int admin_cmd_del_eid_legacy(admin_config_t *cfg)
{
    if (*cfg->dev_name && is_ubc(cfg->dev_name)) {
        (void)printf("This operation is not supported on ubc dev.\n");
        return -1;
    }

    int ret;

    /* Automatically switch to static mode */
    if ((ret = nl_set_eid_mode(cfg)) < 0) {
        printf("Failed to set eid mode, ret:%d\n", ret);
        return ret;
    }
    if ((ret = nl_del_eid(cfg)) != 0) {
        printf("Failed to delete eid, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

int admin_cmd_set_eid_mode_legacy(admin_config_t *cfg)
{
    if (*cfg->dev_name && is_ubc(cfg->dev_name)) {
        (void)printf("This operation is not supported on ubc dev.\n");
        return -1;
    }
    return nl_set_eid_mode(cfg);
}
