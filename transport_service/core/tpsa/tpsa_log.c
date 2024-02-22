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
    char *tpsa_process_path;
    char *tpsa_process_name;

    tpsa_process_path = (char*)calloc(MAX_PROCESS_NAME_LEN + 1, sizeof(char));
    if (tpsa_process_path == NULL) {
        /* TPSA_LOG cannot be used, otherwise, it will enter the dead cycle and burst the stack. */
        return -ENOMEM;
    }
    ssize_t lenth = readlink(TPSA_PROCESS_PATH, tpsa_process_path, MAX_PROCESS_NAME_LEN);
    if (lenth <= 0) {
        (void)printf("/proc/self/exe invalid, errno:%d.\n", errno);
        free(tpsa_process_path);
        return -1;
    }
    tpsa_process_path[lenth + 1] = '\0';
    tpsa_process_name = strrchr(tpsa_process_path, '/');
    if (tpsa_process_name == NULL) {
        (void)printf("tpsa_process_name strrchr failed, errno: %d.\n", errno);
        free(tpsa_process_path);
        return -1;
    }
    tpsa_process_name++;
    g_tpsa_process_name = tpsa_process_name;
    return 0;
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
        TPSA_LOG_ERR("logmsg size exceeds MAX_LOG_LEN size :\n");
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