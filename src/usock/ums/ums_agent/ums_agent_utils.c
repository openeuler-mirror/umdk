/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Utility functions implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "ums_agent_log.h"
#include "ums_agent_utils.h"

#define UMS_AGENT_IPV4_MAPPED_OFFSET    12
#define UMS_AGENT_IPV4_ADDR_LEN         4

void ums_agent_get_monotonic_time(struct timespec *ts)
{
    if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        UMS_AGENT_LOG_ERR("clock_gettime failed: %s (errno=%d)", strerror(errno), errno);
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    }
}

int64_t ums_agent_timespec_diff_sec(const struct timespec *start,
    const struct timespec *end)
{
    int64_t diff_sec = (int64_t)(end->tv_sec - start->tv_sec);
    long diff_nsec = end->tv_nsec - start->tv_nsec;
    if (diff_nsec < 0) {
        diff_sec--;
    }
    return diff_sec;
}

int ums_agent_ip_addr_from_str(struct ums_agent_ip_addr *addr, const char *str)
{
    if (!addr || !str) {
        return -1;
    }

    if (inet_pton(AF_INET, str, &addr->ip.in4) == 1) {
        addr->family = AF_INET;
        return 0;
    }

    if (inet_pton(AF_INET6, str, &addr->ip.in6) == 1) {
        addr->family = AF_INET6;
        ums_agent_ip_addr_normalize(addr);
        return 0;
    }

    return -1;
}

int ums_agent_ip_addr_to_str(const struct ums_agent_ip_addr *addr,
    char *buf, size_t buf_len)
{
    if (!addr || !buf || buf_len == 0) {
        return -1;
    }

    if (addr->family == AF_INET) {
        if (inet_ntop(AF_INET, &addr->ip.in4, buf, buf_len)) {
            return 0;
        }
        return -1;
    }

    if (addr->family == AF_INET6) {
        if (inet_ntop(AF_INET6, &addr->ip.in6, buf, buf_len)) {
            return 0;
        }
        return -1;
    }

    return -1;
}

bool ums_agent_ip_addr_equal(const struct ums_agent_ip_addr *a,
    const struct ums_agent_ip_addr *b)
{
    if (!a || !b) {
        return a == b;
    }

    if (a->family != b->family) {
        return false;
    }

    if (a->family == AF_INET) {
        return memcmp(&a->ip.in4, &b->ip.in4, sizeof(struct in_addr)) == 0;
    }

    if (a->family == AF_INET6) {
        return memcmp(&a->ip.in6, &b->ip.in6, sizeof(struct in6_addr)) == 0;
    }

    return false;
}

void ums_agent_ip_addr_normalize(struct ums_agent_ip_addr *addr)
{
    if (!addr || (addr->family != AF_INET && addr->family != AF_INET6)) {
        return;
    }

    if (addr->family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr->ip.in6)) {
        struct in_addr in4;
        (void)memcpy(&in4, &addr->ip.in6.s6_addr[UMS_AGENT_IPV4_MAPPED_OFFSET], UMS_AGENT_IPV4_ADDR_LEN);
        addr->family = AF_INET;
        addr->ip.in4 = in4;
    }
}

int ums_agent_ip_addr_to_sockaddr(const struct ums_agent_ip_addr *addr,
    uint16_t port, struct sockaddr *sa, socklen_t *sa_len)
{
    if (!addr || !sa || !sa_len) {
        return -1;
    }

    if (addr->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        (void)memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr = addr->ip.in4;
        *sa_len = sizeof(*sin);
        return 0;
    }

    if (addr->family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        (void)memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        sin6->sin6_addr = addr->ip.in6;
        *sa_len = sizeof(*sin6);
        return 0;
    }

    return -1;
}
