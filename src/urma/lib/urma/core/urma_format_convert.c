/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: urma format conversion
 * Author: Qianguoxin
 * Create: 2022-8-9
 * Note:
 * History: 2022-8-9 inital implementation
 */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ub_util.h"
#include "urma_log.h"
#include "urma_types.h"

#define URMA_EID_STR_MIN_LEN 3

void urma_u32_to_eid(uint32_t ipv4, urma_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(URMA_IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int urma_str_to_eid(const char *buf, urma_eid_t *eid)
{
    int ret;
    uint32_t ipv4;

    if (buf == NULL || strlen(buf) < URMA_EID_STR_MIN_LEN || eid == NULL) {
        URMA_LOG_ERR("Invalid argument.\n");
        return -EINVAL;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return 0;
    }

    // ipv4 addr: xx.xx.xx.xx
    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        urma_u32_to_eid(be32toh(ipv4), eid);
        return 0;
    }

    // ipv4 value: 0x12345  or abcdef or 12345
    ret = ub_str_to_u32(buf, &ipv4);
    if (ret == 0) {
        urma_u32_to_eid(ipv4, eid);
        return 0;
    }

    URMA_LOG_ERR("format error: %s.\n", buf);
    return -EINVAL;
}
