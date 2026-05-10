/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Shared type definitions for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#ifndef UMS_AGENT_TYPES_H
#define UMS_AGENT_TYPES_H

#include <netinet/in.h>
#include <sys/socket.h>

struct ums_agent_ip_addr {
    sa_family_t family;
    union {
        struct in_addr in4;
        struct in6_addr in6;
    } ip;
};

#endif /* UMS_AGENT_TYPES_H */
