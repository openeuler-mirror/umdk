/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: netlink header file for urma_admin
 * Author: Yan Fangfang
 * Create: 2023-12-07
 * Note:
 * History: 2023-12-07   create file
 */

#ifndef ADMIN_NETLINK
#define ADMIN_NETLINK

#include <linux/netlink.h>
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

#endif