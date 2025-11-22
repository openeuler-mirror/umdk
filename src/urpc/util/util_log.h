/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: util log
 * Create: 2025-11-18
 */

#ifndef UTIL_LOG_H
#define UTIL_LOG_H

#include "util_vlog.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UTIL_LOG_ERR(frm_, ...) \
    UTIL_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_ERR, frm_, ##__VA_ARGS__)
#define UTIL_LOG_WARN(frm_, ...)    \
    UTIL_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_WARN, frm_, ##__VA_ARGS__)
#define UTIL_LOG_NOTICE(frm_, ...)  \
    UTIL_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_NOTICE, frm_, ##__VA_ARGS__)
#define UTIL_LOG_INFO(frm_, ...)    \
    UTIL_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_INFO, frm_, ##__VA_ARGS__)
#define UTIL_LOG_DEBUG(frm_, ...)   \
    UTIL_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_DEBUG, frm_, ##__VA_ARGS__)

#define UTIL_LIMIT_LOG_ERR(frm_, ...)   \
    UTIL_LIMIT_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_ERR, frm_, ##__VA_ARGS__)
#define UTIL_LIMIT_LOG_WARN(frm_, ...)  \
    UTIL_LIMIT_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_WARN, frm_, ##__VA_ARGS__)
#define UTIL_LIMIT_LOG_NOTICE(frm_, ...)    \
    UTIL_LIMIT_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_NOTICE, frm_, ##__VA_ARGS__)
#define UTIL_LIMIT_LOG_INFO(frm_, ...)  \
    UTIL_LIMIT_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_INFO, frm_, ##__VA_ARGS__)
#define UTIL_LIMIT_LOG_DEBUG(frm_, ...)     \
    UTIL_LIMIT_VLOG(util_log_ctx_get(), UTIL_VLOG_LEVEL_DEBUG, frm_, ##__VA_ARGS__)

int util_log_ctx_set(util_vlog_ctx_t *ctx);
util_vlog_ctx_t *util_log_ctx_get(void);

#ifdef __cplusplus
}
#endif

#endif // UTIL_LOG_H