/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-08-20
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include "snc_ping_log.h"

static FILE* g_logFile = NULL;
static pthread_mutex_t g_logMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_initMutex = PTHREAD_MUTEX_INITIALIZER;

static const char* LevelToStr(SncLogLevel level)
{
    switch (level) {
        case LOG_LEVEL_DEBUG:
            return "DEBUG";
        case LOG_LEVEL_INFO:
            return "INFO";
        case LOG_LEVEL_WARN:
            return "WARN";
        default:
            return "ERROR";
    }
}

void SncLogInit(void)
{
    pthread_mutex_lock(&g_initMutex);
    const char* logDir = getenv("SNC_LOG_DIR");
    if (logDir == NULL || strlen(logDir) == 0) {
        pthread_mutex_lock(&g_logMutex);
        FILE* oldFile = g_logFile;
        g_logFile = NULL;
        pthread_mutex_unlock(&g_logMutex);
        if (oldFile != NULL) {
            fclose(oldFile);
        }
        pthread_mutex_unlock(&g_initMutex);
        LOG_WARN("SncLogInit: SNC_LOG_DIR is not set or empty, logging to stdout");
        return;
    }
    size_t fullPathLen = strlen(logDir) + 32;
    char* logPath = (char*)malloc(fullPathLen);
    if (logPath == NULL) {
        pthread_mutex_unlock(&g_initMutex);
        LOG_ERROR("SncLogInit: failed to allocate memory for log path, logging to stdout");
        return;
    }
    int snprintfRet = snprintf(logPath, fullPathLen, "%s/snc.log", logDir);
    if (snprintfRet < 0 || (size_t)snprintfRet >= fullPathLen) {
        pthread_mutex_unlock(&g_initMutex);
        LOG_ERROR("SncLogInit: log path snprintf failed or truncated (ret=%d), logging to stdout",
                  snprintfRet);
        free(logPath);
        return;
    }
    FILE* newFile = fopen(logPath, "a");
    if (newFile == NULL) {
        pthread_mutex_unlock(&g_initMutex);
        LOG_ERROR("SncLogInit: failed to open log file (%s), logging to stdout", logPath);
        free(logPath);
        return;
    }
    free(logPath);
    pthread_mutex_lock(&g_logMutex);
    FILE* oldFile = g_logFile;
    g_logFile = newFile;
    pthread_mutex_unlock(&g_logMutex);
    if (oldFile != NULL) {
        fclose(oldFile);
    }
    pthread_mutex_unlock(&g_initMutex);
}

void SncLogDeinit(void)
{
    pthread_mutex_lock(&g_initMutex);
    pthread_mutex_lock(&g_logMutex);
    FILE* oldFile = g_logFile;
    g_logFile = NULL;
    pthread_mutex_unlock(&g_logMutex);
    if (oldFile != NULL) {
        fclose(oldFile);
    }
    pthread_mutex_unlock(&g_initMutex);
}

static void SncLogWriteInternal(SncLogLevel level, const char* fmt, va_list args)
{
    struct tm tmInfo;
    const int TIME_LEN = 32;
    time_t now = time(NULL);
    localtime_r(&now, &tmInfo);
    char timeStr[TIME_LEN];
    timeStr[0] = '\0';
    if (strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tmInfo) == 0) {
        if (snprintf(timeStr, sizeof(timeStr), "%s", "----") < 0) {
            timeStr[0] = '\0';
        }
    }
    pthread_mutex_lock(&g_logMutex);
    FILE* output = g_logFile != NULL ? g_logFile : stdout;
    int ret = fprintf(output, "[%s] [%s] ", timeStr, LevelToStr(level));
    if (ret >= 0) {
        ret = vfprintf(output, fmt, args);
    }
    if (ret >= 0) {
        ret = fprintf(output, "\n");
    }
    if (ret >= 0 && fflush(output) != 0) {
        ret = -1;
    }
    if (ret < 0 && output == g_logFile) {
        (void)fclose(g_logFile);
        g_logFile = NULL;
    }
    pthread_mutex_unlock(&g_logMutex);
}

void SncLogWrite(SncLogLevel level, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    SncLogWriteInternal(level, fmt, args);
    va_end(args);
}