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
#include <stdbool.h>
#include <sys/socket.h>

#define UMS_SYSTEMID_LEN 8

struct ums_agent_ip_addr {
    sa_family_t family;
    union {
        struct in_addr in4;
        struct in6_addr in6;
    } ip;
};

struct ums_token_entry {
    uint32_t clc_id;
    uint8_t  id_for_peer[UMS_SYSTEMID_LEN];
    uint8_t  first_contact;
    struct ums_agent_ip_addr dst_addr;
    uint32_t jetty_token_value;
    uint32_t seg_token_value;
};

#endif /* UMS_AGENT_TYPES_H */
