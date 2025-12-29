/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: netlink header file for urma_admin
 * Author: Yan Fangfang
 * Create: 2023-12-07
 * Note:
 * History: 2023-12-07   create file
 */

#ifndef ADMIN_NETLINK
#define ADMIN_NETLINK

#include <netlink/msg.h>

#include "admin_parameters.h"

/* MUST be consistent with uburma netlink definitions */
typedef struct admin_nl_set_ns_mode {
    uint8_t ns_mode;
} admin_nl_set_ns_mode_t;

typedef struct admin_nl_set_dev_ns {
    char dev_name[URMA_MAX_NAME];
    int ns_fd;
} admin_nl_set_dev_ns_t;

typedef struct admin_nl_resp {
    int ret;
} admin_nl_resp;

enum admin_nlmsg_type {
    ADMIN_NL_SET_NS_MODE = NLMSG_MIN_TYPE, /* 0x10 */
    ADMIN_NL_SET_DEV_NS
};

int admin_nl_talk(void *req, size_t len, enum admin_nlmsg_type type, admin_nl_resp *resp);

int admin_nl_send_msg(struct nl_msg *msg);
int admin_nl_recv_msg(int (*cb)(struct nl_msg *msg, void *arg), void *arg);
int admin_nl_send_recv_msg(struct nl_msg *msg, int (*cb)(struct nl_msg *msg, void *arg), void *arg);
int admin_nl_send_recv_msg_default(struct nl_msg *msg);

struct nl_msg *admin_nl_alloc_msg(uint8_t cmd, int flags);
void admin_nl_free_msg(struct nl_msg *msg);

static inline int admin_nl_put_string(struct nl_msg *msg, int attr, const char *str)
{
    int ret = nla_put_string(msg, attr, str);
    if (ret != 0) {
        printf("Failed to put string attribute %d, ret: %d\n", attr, ret);
    }
    return ret;
}

static inline int admin_nl_put_u32(struct nl_msg *msg, int attr, uint32_t value)
{
    int ret = nla_put_u32(msg, attr, value);
    if (ret != 0) {
        printf("Failed to put u32 attribute %d, ret: %d\n", attr, ret);
    }
    return ret;
}

static inline int admin_nl_put_u8(struct nl_msg *msg, int attr, uint8_t value)
{
    int ret = nla_put_u8(msg, attr, value);
    if (ret != 0) {
        printf("Failed to put u8 attribute %d, ret: %d\n", attr, ret);
    }
    return ret;
}

static inline int admin_nl_put_u64(struct nl_msg *msg, int attr, uint64_t value)
{
    int ret = nla_put_u64(msg, attr, value);
    if (ret != 0) {
        printf("Failed to put string attribute %d, ret: %d\n", attr, ret);
    }
    return ret;
}

int cmd_nlsend_legacy(struct nl_msg *msg, urma_cmd_hdr_t *hdr);

#endif
