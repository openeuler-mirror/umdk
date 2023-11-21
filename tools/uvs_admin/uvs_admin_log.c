/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs_admin log implementation
 * Author: Ji Lei
 * Create: 2023-6-13
 * Note:
 * History: 2023-6-13 inital implementation of uvs_admin log
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <syslog.h>

#include "uvs_admin_log.h"

#define MAX_LOG_LEN 1024
#define UVS_ADMIN_LOG_TAG "UVS_ADMIN_LOGTAG"

static int uvs_admin_vlog(const char *function, int line, uvs_admin_vlog_level_t level, const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};

    /* add log head info, "UVS_LOG_TAG|function|[line]|format" */
    ret = snprintf(newformat, sizeof(newformat), "%s|%s[%d]|%s",
                   UVS_ADMIN_LOG_TAG, function, line, format);
    if (ret <= 0 || ret >= (int)sizeof(newformat)) {
        return ret;
    }
    ret = vsnprintf(logmsg, sizeof(logmsg), newformat, va);
    if (ret == -1) {
        (void)printf("logmsg size exceeds MAX_LOG_LEN size : %d\n", MAX_LOG_LEN);
        return ret;
    }
    syslog((int)level, "%s", logmsg);

    return ret;
}

void uvs_admin_log(const char *function, int line, uvs_admin_vlog_level_t level, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)uvs_admin_vlog(function, line, level, format, va);
    va_end(va);
}
