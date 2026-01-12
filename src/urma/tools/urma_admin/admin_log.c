/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: urma_admin log implementation
 * Author: Qian Guoxin
 * Create: 2023-2-16
 * Note:
 * History: 2023-2-16 inital implementation of urma_admin log
 */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "admin_log.h"

#define MAX_LOG_LEN                1024
#define URMA_ADMIN_LOG_TAG         "URMA_ADMIN_LOGTAG"
#define URMA_ADMIN_VLOG_LEVEL_INFO 6

static int urma_admin_vlog(const char *function, int line, const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};

    /* add log head info, "URMA_LOG_TAG|function|[line]|format" */
    ret = snprintf(newformat, MAX_LOG_LEN, "%s|%s[%d]|%s", URMA_ADMIN_LOG_TAG, function, line, format);
    if (ret <= 0 || ret >= (int)sizeof(newformat)) {
        return ret;
    }
    ret = vsnprintf(logmsg, MAX_LOG_LEN, newformat, va);
    if (ret == -1) {
        (void)printf("logmsg size exceeds MAX_LOG_LEN size : %d\n", MAX_LOG_LEN);
        return ret;
    }
    syslog(URMA_ADMIN_VLOG_LEVEL_INFO, "%s", logmsg);

    return ret;
}

void urma_admin_log(const char *function, int line, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)urma_admin_vlog(function, line, format, va);
    va_end(va);
}
