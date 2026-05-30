/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_perftest log head file
 * Author: Wang Hang
 * Create: 2026-05-29
 * Note:
 * History: 2026-05-29 Create file
 */

#ifndef PERFTEST_LOG_H
#define PERFTEST_LOG_H

#include <stdarg.h>
#include <stdio.h>

typedef enum perftest_vlog_level {
    VLOG_LEVEL_QUIET = 0,
    VLOG_LEVEL_INFO = 1,
    VLOG_LEVEL_VERBOSE = 2,
    VLOG_LEVEL_VVERBOSE = 3,
} perftest_vlog_level_t;

extern perftest_vlog_level_t verbose_level;

static inline void verbose_set_level(perftest_vlog_level_t level)
{
    verbose_level = level;
}

static inline perftest_vlog_level_t verbose_get_level(void)
{
    return verbose_level;
}

static inline void verbose_print(FILE *stream, perftest_vlog_level_t level,
                                 const char *fmt, ...)
{
    if (verbose_level < level) {
        return;
    }

    va_list va;
    va_start(va, fmt);
    (void)vfprintf(stream, fmt, va);
    va_end(va);
}

#define LOG_QUIET(...)    verbose_print(stdout, VLOG_LEVEL_QUIET, __VA_ARGS__)
#define LOG_INFO(...)     verbose_print(stdout, VLOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_VERBOSE(...)  verbose_print(stdout, VLOG_LEVEL_VERBOSE, __VA_ARGS__)
#define LOG_VVERBOSE(...) verbose_print(stdout, VLOG_LEVEL_VVERBOSE, __VA_ARGS__)
#define LOG_ERROR(...)    verbose_print(stderr, VLOG_LEVEL_QUIET, __VA_ARGS__)

#endif
