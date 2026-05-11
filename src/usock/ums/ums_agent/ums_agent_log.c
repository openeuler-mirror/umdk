/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Syslog-based logging implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-04-20
 * Note:
 * History: 2026-04-20  Create File
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>

#include "ums_agent_log.h"

#define UMS_AGENT_LOG_MSG_MAX_LEN 1024

struct ums_agent_log_state {
    enum ums_agent_log_level level;
    bool initialized;
};

static struct ums_agent_log_state g_log_state = {
    .level = UMS_AGENT_LOG_LEVEL_INFO,
    .initialized = false
};

void ums_agent_log_init(enum ums_agent_log_level level)
{
    if (g_log_state.initialized) {
        return;
    }

    g_log_state.level = level;

    openlog("ums_agent", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

    g_log_state.initialized = true;
}

void ums_agent_log_deinit(void)
{
    if (!g_log_state.initialized) {
        return;
    }

    closelog();
    g_log_state.initialized = false;
}

void ums_agent_log_set_level(enum ums_agent_log_level level)
{
    if (!g_log_state.initialized) {
        return;
    }
    g_log_state.level = level;
}

void ums_agent_log_output(enum ums_agent_log_level level, const char *func,
    int line, const char *fmt, ...)
{
    if (!g_log_state.initialized) {
        return;
    }

    if (level > g_log_state.level) {
        return;
    }

    char msg[UMS_AGENT_LOG_MSG_MAX_LEN];
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (ret < 0) {
        syslog((int)level, "%s[%d]|log msg format error", func, line);
        return;
    }

    syslog((int)level, "%s[%d]|%s", func, line, msg);
}
