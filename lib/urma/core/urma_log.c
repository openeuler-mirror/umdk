/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: urma log implementation
 * Author: Yan Fangfang
 * Create: 2020-9-28
 * Note:
 * History: 2020-9-28 inital implementation of urma log
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <syslog.h>
#include <pthread.h>
#include "urma_opcode.h"
#include "urma_types.h"
#include "urma_log.h"

pthread_mutex_t g_urma_log_lock = PTHREAD_MUTEX_INITIALIZER;
urma_vlog_level_t g_urma_log_level = URMA_VLOG_LEVEL_INFO;
#define MAX_LOG_LEN 512
#define URMA_LOG_TAG "URMA_LOG_TAG"

static void urma_default_log_func(int level, char *message)
{
    syslog(level, "%s", message);
}

static urma_log_cb_t g_urma_log_func = urma_default_log_func;
urma_status_t urma_register_log_func(urma_log_cb_t func)
{
    if (func == NULL) {
        syslog((int)URMA_VLOG_LEVEL_ERR, "%s|%s|Invalid parameter.\n",
            URMA_LOG_TAG, __func__);
        return URMA_EINVAL;
    }
    syslog((int)URMA_VLOG_LEVEL_INFO, "%s|%s|register log succeed.\n",
        URMA_LOG_TAG, __func__);
    g_urma_log_func = func;
    return URMA_SUCCESS;
}

urma_status_t urma_unregister_log_func(void)
{
    char logmsg[MAX_LOG_LEN + 1] = {0};
    (void)snprintf(logmsg, MAX_LOG_LEN, "%s|%s|unregister log succeed.\n", URMA_LOG_TAG, __func__);
    (*g_urma_log_func)((int)URMA_VLOG_LEVEL_INFO, logmsg);
    g_urma_log_func = urma_default_log_func;
    return URMA_SUCCESS;
}

int urma_log_init(void)
{
    openlog("", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_USER);
    return setlogmask(LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_INFO) |
        LOG_MASK(LOG_DEBUG));
}

urma_vlog_level_t urma_log_get_level(void)
{
    urma_vlog_level_t level;

    pthread_mutex_lock(&g_urma_log_lock);
    level = g_urma_log_level;
    pthread_mutex_unlock(&g_urma_log_lock);
    return level;
}

void urma_log_set_level(urma_vlog_level_t level)
{
    if (level >= URMA_VLOG_LEVEL_MAX) {
        return;
    }
    pthread_mutex_lock(&g_urma_log_lock);
    g_urma_log_level = level;
    pthread_mutex_unlock(&g_urma_log_lock);
    return;
}

inline bool urma_log_drop(urma_vlog_level_t level)
{
    return ((level > g_urma_log_level) ? true : false);
}

const char *urma_get_level_print(urma_vlog_level_t level)
{
    switch (level) {
        case URMA_VLOG_LEVEL_CRIT: return "fatal";
        case URMA_VLOG_LEVEL_ERR: return "error";
        case URMA_VLOG_LEVEL_WARNING: return "warning";
        case URMA_VLOG_LEVEL_DEBUG: return "debug";
        case URMA_VLOG_LEVEL_INFO: return "info";
        case URMA_VLOG_LEVEL_EMERG:
        case URMA_VLOG_LEVEL_ALERT:
        case URMA_VLOG_LEVEL_NOTICE:
        case URMA_VLOG_LEVEL_MAX:
        default: return "Unknown";
    }
}

urma_vlog_level_t urma_log_get_level_from_string(const char* level_string)
{
    if (level_string == NULL) {
        return URMA_VLOG_LEVEL_MAX;
    }
    if (strcasecmp(level_string, "fatal") == 0) {
        return URMA_VLOG_LEVEL_CRIT;
    }
    if (strcasecmp(level_string, "error") == 0) {
        return URMA_VLOG_LEVEL_ERR;
    }
    if (strcasecmp(level_string, "warning") == 0) {
        return URMA_VLOG_LEVEL_WARNING;
    }
    if (strcasecmp(level_string, "info") == 0) {
        return URMA_VLOG_LEVEL_INFO;
    }
    if (strcasecmp(level_string, "debug") == 0) {
        return URMA_VLOG_LEVEL_DEBUG;
    }
    return URMA_VLOG_LEVEL_MAX;
}

static int urma_vlog(const char *function, int line, urma_vlog_level_t level, const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};

    /* add log head info, "URMA_LOG_TAG|function|[line]|format" */
    ret = snprintf(newformat, MAX_LOG_LEN, "%s|%s[%d]|%s", URMA_LOG_TAG, function, line, format);
    if (ret <= 0 || ret >= sizeof(newformat)) {
        return ret;
    }
    ret = vsnprintf(logmsg, MAX_LOG_LEN, newformat, va);
    if (ret == -1) {
        (void)printf("logmsg size exceeds MAX_LOG_LEN size :%d.\n", MAX_LOG_LEN);
        return ret;
    }
    (*g_urma_log_func)((int)level, logmsg);

    return ret;
}

void urma_log(const char *function, int line, urma_vlog_level_t level, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)urma_vlog(function, line, level, format, va);
    va_end(va);
}
