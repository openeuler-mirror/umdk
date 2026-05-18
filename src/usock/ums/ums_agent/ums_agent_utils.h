/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Utility functions for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#ifndef UMS_AGENT_UTILS_H
#define UMS_AGENT_UTILS_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/ssl.h>

#include "ums_agent_types.h"

void ums_agent_get_monotonic_time(struct timespec *ts);
int64_t ums_agent_timespec_diff_sec(const struct timespec *start,
    const struct timespec *end);

int ums_agent_ip_addr_from_str(struct ums_agent_ip_addr *addr, const char *str);
int ums_agent_ip_addr_to_str(const struct ums_agent_ip_addr *addr,
    char *buf, size_t buf_len);
bool ums_agent_ip_addr_equal(const struct ums_agent_ip_addr *a,
    const struct ums_agent_ip_addr *b);
void ums_agent_ip_addr_normalize(struct ums_agent_ip_addr *addr);
int ums_agent_ip_addr_to_sockaddr(const struct ums_agent_ip_addr *addr,
    uint16_t port, struct sockaddr *sa, socklen_t *sa_len);

static inline void ums_agent_secure_zero(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}

#endif /* UMS_AGENT_UTILS_H */
