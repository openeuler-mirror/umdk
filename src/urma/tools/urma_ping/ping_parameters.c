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
    int ret;
    uint32_t ipv4;
    if (buf == NULL || eid == NULL) {
        return -EINVAL;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return 0;
    }

    // ipv4 addr: xx.xx.xx.xx
    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        ipv4_map_to_eid(be32toh(ipv4), eid);
        return 0;
    }

    // ipv4 value: 0x12345  or abcdef or 12345
    ret = str_to_u32(buf, &ipv4);
    if (ret == 0) {
        ipv4_map_to_eid(ipv4, eid);
        return 0;
    }

    return -EINVAL;
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
              "  <destination>    Primary eid or bonding eid\n"
              "  -c <count>       Packet count (default: INT_MAX)\n"
              "  -i <interval>    Interval between packets in seconds (default: 1)\n"
              "  -s <size>        Send buffer size in bytes (default: 4)\n"
              "  -w <deadline>    Total execution time limit in seconds (default: umlimited)\n"
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
    while ((opt = getopt_long(cfg->argc, cfg->argv, "c:i:s:qw:W:ShVv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                ret = str_to_u32(optarg, &cfg->count);
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
                LOG_ERROR("Option -%c requires an argument\n", optopt);
                return -EINVAL;
            default:
                LOG_ERROR("Unknown option\n");
                usage(cfg->filename);
                return -EINVAL;
        }
        if (ret != 0) {
            const int option_offset = 2;
            LOG_ERROR("Invalid option %s\n", cfg->argv[optind - option_offset]);
            return -EINVAL;
        }
    }

    if (optind >= cfg->argc) {
        LOG_ERROR("Destination is required\n");
        usage(cfg->filename);
        return -EINVAL;
    }

    ret = str_to_eid(cfg->argv[optind], &cfg->dest);
    if (ret != 0) {
        LOG_ERROR("Invalid dest eid %s\n", cfg->argv[optind]);
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

    if (cfg->size > 4096) {
        LOG_ERROR("Size must be less than or equal to 4096\n");
        return -EINVAL;
    }

    return 0;
}
