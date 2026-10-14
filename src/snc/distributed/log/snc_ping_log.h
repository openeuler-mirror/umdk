/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-08-20
 */
#ifndef SNC_PING_LOG_H
#define SNC_PING_LOG_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
} SncLogLevel;

#define LOG_DEBUG(fmt, ...) SncLogWrite(LOG_LEVEL_DEBUG, "[SNC_PING] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  SncLogWrite(LOG_LEVEL_INFO,  "[SNC_PING] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  SncLogWrite(LOG_LEVEL_WARN,  "[SNC_PING] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) SncLogWrite(LOG_LEVEL_ERROR, "[SNC_PING] " fmt, ##__VA_ARGS__)

void SncLogInit(void);
void SncLogDeinit(void);
void SncLogWrite(SncLogLevel level, const char *fmt, ...);

#endif