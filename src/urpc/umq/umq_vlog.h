/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Provide the umq vlog module
 * Create: 2025-08-04
 */

#ifndef UMQ_VLOG_H
#define UMQ_VLOG_H

#include <pthread.h>

#include "util_vlog.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_vlog_config {
    uint32_t log_flag;
    util_vlog_ctx_t ctx;
    pthread_mutex_t log_lock;
} umq_vlog_config_t;

#define UMQ_VLOG_ERR(__format, ...)    \
    UTIL_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_ERR, __format, ##__VA_ARGS__)
#define UMQ_VLOG_WARN(__format, ...)   \
    UTIL_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_WARN, __format, ##__VA_ARGS__)
#define UMQ_VLOG_NOTICE(__format, ...) \
    UTIL_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_NOTICE, __format, ##__VA_ARGS__)
#define UMQ_VLOG_INFO(__format, ...)   \
    UTIL_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_INFO, __format, ##__VA_ARGS__)
#define UMQ_VLOG_DEBUG(__format, ...)  \
    UTIL_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_DEBUG, __format, ##__VA_ARGS__)

#define UMQ_LIMIT_VLOG_ERR(__format, ...)   \
    UTIL_LIMIT_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_ERR, __format, ##__VA_ARGS__)
#define UMQ_LIMIT_VLOG_WARN(__format, ...)  \
    UTIL_LIMIT_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_WARN, __format, ##__VA_ARGS__)
#define UMQ_LIMIT_VLOG_NOTICE(__format, ...)    \
    UTIL_LIMIT_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_NOTICE, __format, ##__VA_ARGS__)
#define UMQ_LIMIT_VLOG_INFO(__format, ...)  \
    UTIL_LIMIT_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_INFO, __format, ##__VA_ARGS__)
#define UMQ_LIMIT_VLOG_DEBUG(__format, ...)     \
    UTIL_LIMIT_VLOG(umq_get_log_ctx(), UTIL_VLOG_LEVEL_DEBUG, __format, ##__VA_ARGS__)

util_vlog_ctx_t *umq_get_log_ctx(void);
umq_vlog_config_t *umq_get_log_config(void);

#ifdef __cplusplus
}
#endif

#endif