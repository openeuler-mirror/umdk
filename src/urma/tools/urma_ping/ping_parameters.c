/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping parameters implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ping_log.h"

#include "ping_parameters.h"

#define MAX_PING_SIZE 4096

int str_to_u32(const char *buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > UINT32_MAX) {
        return -ERANGE;
    }
    *u32 = (uint32_t)ret;
    return 0;
}

static inline void ipv4_map_to_eid(uint32_t ipv4, urma_eid_t *eid)
{
    const uint32_t ipv4_map_ipv6_prefix = 0x0000ffff;
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(ipv4_map_ipv6_prefix);
    eid->in4.addr = htobe32(ipv4);
}

int str_to_eid(const char *buf, urma_eid_t *eid)
{
    bool parsed = false;
    uint32_t ipv4;

    if (buf == NULL || eid == NULL) {
        return -EINVAL;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) > 0) {
        parsed = true;
    }

    // ipv4 addr: xx.xx.xx.xx
    if (!parsed && inet_pton(AF_INET, buf, &ipv4) > 0) {
        ipv4_map_to_eid(be32toh(ipv4), eid);
        parsed = true;
    }

    // ipv4 value: 0x12345  or abcdef or 12345
    if (!parsed && str_to_u32(buf, &ipv4) == 0) {
        ipv4_map_to_eid(ipv4, eid);
        parsed = true;
    }

    if (!parsed) {
        return -EINVAL;
    }

    const urma_eid_t zero_eid = {0};
    return memcmp(eid, &zero_eid, sizeof(zero_eid)) == 0 ? -EINVAL : 0;
}

void version()
{
    LOG_QUIET("Version: 0.0.1\n");
}

void usage(const char *filename)
{
    LOG_QUIET("Usage:\n"
              "  urma_ping [option] <destination>\n"
              "\n"
              "Options:\n"
              "  <destination>    Primary EID or bonding EID\n"
              "  -c <count>       Packet count (default: INT_MAX)\n"
              "  -I <eid>         Local primary EID used to ping\n"
              "  -i <interval>    Interval between packets in seconds (default: 1)\n"
              "  -s <size>        Send buffer size in bytes (default: 4)\n"
              "  -w <deadline>    Total execution time limit in seconds (default: unlimited)\n"
              "  -W <timeout>     Per-reply timeout in seconds (default: 1)\n"
              "  -q               Quiet output\n"
              "  -v --verbose     Verbose output\n"
              "  -h --help        Show this help and exit\n"
              "  -V --version     Show version and exit\n");
}

int parse_args(ping_cfg_t *cfg)
{
    static const struct option long_options[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt, ret = 0;
    while ((opt = getopt_long(cfg->argc, cfg->argv, ":c:I:i:s:qw:W:ShVv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                ret = str_to_u32(optarg, &cfg->count);
                break;
            case 'I':
                ret = str_to_eid(optarg, &cfg->src_eid);
                cfg->has_src_eid = (ret == 0);
                break;
            case 'i':
                ret = str_to_u32(optarg, &cfg->interval);
                break;
            case 's':
                ret = str_to_u32(optarg, &cfg->size);
                break;
            case 'w':
                ret = str_to_u32(optarg, &cfg->deadline);
                break;
            case 'W':
                ret = str_to_u32(optarg, &cfg->timeout);
                break;
            case 'q':
                cfg->verbose_level = VLOG_LEVEL_QUIET;
                break;
            case 'v':
                cfg->verbose_level++;
                break;
            case 'h':
                usage(cfg->filename);
                return -EINVAL;
            case 'V':
                version();
                return -EINVAL;
            case ':':
                LOG_ERROR("Missing argument for option -%c\n", optopt);
                return -EINVAL;
            default:
                LOG_ERROR("Unknown option %s\n", cfg->argv[optind - 1]);
                usage(cfg->filename);
                return -EINVAL;
        }
        if (ret != 0) {
            LOG_ERROR("Invalid value for -%c: %s\n", opt, optarg);
            return -EINVAL;
        }
    }

    if (optind >= cfg->argc) {
        LOG_ERROR("Destination EID is required\n");
        usage(cfg->filename);
        return -EINVAL;
    }

    ret = str_to_eid(cfg->argv[optind], &cfg->dst_eid);
    if (ret != 0) {
        LOG_ERROR("Invalid destination EID: %s\n", cfg->argv[optind]);
        return -EINVAL;
    }
    return 0;
}

int check_args(ping_cfg_t *cfg)
{
    if (cfg->count == 0) {
        LOG_ERROR("Count must be greater than 0\n");
        return -EINVAL;
    }

    if (cfg->size == 0) {
        LOG_ERROR("Size must be greater than 0\n");
        return -EINVAL;
    }

    if (cfg->size > MAX_PING_SIZE) {
        LOG_ERROR("Size must be less than or equal to 4096\n");
        return -EINVAL;
    }

    return 0;
}
