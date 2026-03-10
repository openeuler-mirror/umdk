/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping log implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include <stdarg.h>
#include <stdio.h>

#include "ping_log.h"

static int verbose_level = VLOG_LEVEL_NORMAL;

void verbose_set_level(ping_vlog_level_t level)
{
    verbose_level = level;
}

void verbose_print(FILE *stream, ping_vlog_level_t level, const char *fmt, ...)
{
    if (verbose_level < level) {
        return;
    }

    va_list va;
    va_start(va, fmt);
    (void)vfprintf(stream, fmt, va);
    va_end(va);
}
