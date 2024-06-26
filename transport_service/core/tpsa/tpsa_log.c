/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa log module
 * Author: Chen Wen
 * Create: 2022-08-25
 * Note:
 * History:
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <pthread.h>
#include "tpsa_log.h"

#define MAX_LOG_LEN 1024
#define MAX_PROCESS_NAME_LEN 1024
#define TPSA_LOG_TAG "LogTag_TPSA"
#define TPSA_PROCESS_PATH "/proc/self/exe"

static pthread_mutex_t g_tpsa_log_lock = PTHREAD_MUTEX_INITIALIZER;
unsigned g_tpsa_log_level = TPSA_VLOG_LEVEL_INFO;
#define UVS_LOG_ENV_STR    "UVS_LOG_LEVEL"
#define UVS_LOG_LEVEL_ENV_MAX_BUF_LEN        32

char g_tpsa_process_path[MAX_PROCESS_NAME_LEN + 1] = {0};
char *g_tpsa_process_name = NULL;

void tpsa_log_init(void)
{
    openlog("tpsa", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_USER);
    (void)setlogmask(LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_INFO) | LOG_MASK(LOG_DEBUG));
}

void tpsa_log_uninit(void)
{
    closelog();
}

void tpsa_log_set_level(unsigned level)
{
    (void)pthread_mutex_lock(&g_tpsa_log_lock);
    g_tpsa_log_level = level;
    (void)pthread_mutex_unlock(&g_tpsa_log_lock);
    return;
}

inline bool tpsa_log_drop(unsigned int level)
{
    return ((level > g_tpsa_log_level) ? true : false);
}

static int tpsa_find_process_name(void)
{
    char *tpsa_process_name;

    ssize_t lenth = readlink(TPSA_PROCESS_PATH, g_tpsa_process_path, MAX_PROCESS_NAME_LEN);
    if (lenth <= 0 || lenth > MAX_PROCESS_NAME_LEN) {
        (void)printf("/proc/self/exe invalid, errno:%d.\n", errno);
        return -1;
    }

    g_tpsa_process_path[lenth] = '\0';
    tpsa_process_name = strrchr(g_tpsa_process_path, '/');
    if (tpsa_process_name == NULL) {
        (void)printf("tpsa_process_name strrchr failed, errno: %d.\n", errno);
        return -1;
    }

    tpsa_process_name++;
    g_tpsa_process_name = tpsa_process_name;
    return 0;
}

static enum tpsa_vlog_level tpsa_log_get_level_from_string(const char* level_string)
{
    if (level_string == NULL) {
        return TPSA_VLOG_LEVEL_MAX;
    }
    if (strcasecmp(level_string, "fatal") == 0) {
        return TPSA_VLOG_LEVEL_CRIT;
    }
    if (strcasecmp(level_string, "error") == 0) {
        return TPSA_VLOG_LEVEL_ERR;
    }
    if (strcasecmp(level_string, "warning") == 0) {
        return TPSA_VLOG_LEVEL_WARNING;
    }
    if (strcasecmp(level_string, "info") == 0) {
        return TPSA_VLOG_LEVEL_INFO;
    }
    if (strcasecmp(level_string, "debug") == 0) {
        return TPSA_VLOG_LEVEL_DEBUG;
    }
    return TPSA_VLOG_LEVEL_MAX;
}

void tpsa_getenv_log_level(void)
{
    char *level_str = getenv(UVS_LOG_ENV_STR);
    if (level_str == NULL) {
        return;
    }

    if (strnlen(level_str, UVS_LOG_LEVEL_ENV_MAX_BUF_LEN) >= UVS_LOG_LEVEL_ENV_MAX_BUF_LEN) {
        TPSA_LOG_ERR("Invalid parameter: log level str.");
        return;
    }

    enum tpsa_vlog_level log_level = tpsa_log_get_level_from_string(level_str);
    if (log_level != TPSA_VLOG_LEVEL_MAX) {
        pthread_mutex_lock(&g_tpsa_log_lock);
        g_tpsa_log_level = log_level;
        pthread_mutex_unlock(&g_tpsa_log_lock);
    }
}

static int tpsa_vlog(const char *function, int line, unsigned int level, const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};

    /* After the process starts, only need to get the process name once */
    if (g_tpsa_process_name == NULL) {
        ret = tpsa_find_process_name();
        if (ret != 0) {
            return ret;
        }
    }

    /* add log head info, "TPSA_LOG_TAG|*tpsaprocessname*|function|[line]|format" */
    ret = snprintf(newformat, sizeof(newformat), "%s|*%s*|%s[%d]|%s",
                     TPSA_LOG_TAG, g_tpsa_process_name, function, line, format);
    if (ret < 0 || ret >= (int)sizeof(newformat)) {
        return ret;
    }
    ret = vsnprintf(logmsg, sizeof(logmsg), newformat, va);
    if (ret < 0) {
        TPSA_LOG_ERR("logmsg size exceeds MAX_LOG_LEN size : %d\n", MAX_LOG_LEN);
        return ret;
    }
    syslog(level, "%s", logmsg);

    return ret;
}

void tpsa_log(const char *function, int line, uint32_t level, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)tpsa_vlog(function, line, level, format, va);
    va_end(va);
}