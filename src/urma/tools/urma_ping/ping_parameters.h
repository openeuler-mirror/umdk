/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping parameters head file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#ifndef URMA_PING_PARAMETERS_H
#define URMA_PING_PARAMETERS_H

#include <stdbool.h>
#include <stdint.h>

#include "urma_types.h"

typedef struct ping_cfg {
    int argc;
    char **argv;
    char *filename;
    urma_eid_t dst_eid;
    urma_eid_t src_eid;
    bool has_src_eid;
    uint32_t count;    /* UINT32_MAX means unlimited */
    uint32_t interval; /* seconds */
    uint32_t size;     /* bytes */
    uint32_t deadline; /* seconds, 0 means disabled */
    uint32_t timeout;  /* seconds, per-reply timeout */
    uint32_t verbose_level;
} ping_cfg_t;

int str_to_u32(const char *buf, uint32_t *u32);
int str_to_eid(const char *buf, urma_eid_t *eid);

void version();
void usage(const char *filename);
int parse_args(ping_cfg_t *cfg);
int check_args(ping_cfg_t *cfg);

#endif
