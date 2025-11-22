/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib log
 * Create: 2024-3-12
 */

#ifndef URPC_LIB_LOG_H
#define URPC_LIB_LOG_H

#include <stdio.h>
#include "util_vlog.h"
#include "urpc_framework_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_LIB_LOG_ERR(frm_, ...) \
    UTIL_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_ERR, frm_, ##__VA_ARGS__)
#define URPC_LIB_LOG_WARN(frm_, ...)    \
    UTIL_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_WARN, frm_, ##__VA_ARGS__)
#define URPC_LIB_LOG_NOTICE(frm_, ...)  \
    UTIL_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_NOTICE, frm_, ##__VA_ARGS__)
#define URPC_LIB_LOG_INFO(frm_, ...)    \
    UTIL_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_INFO, frm_, ##__VA_ARGS__)
#define URPC_LIB_LOG_DEBUG(frm_, ...)   \
    UTIL_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_DEBUG, frm_, ##__VA_ARGS__)

#define URPC_LIB_LIMIT_LOG_ERR(frm_, ...)   \
    UTIL_LIMIT_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_ERR, frm_, ##__VA_ARGS__)
#define URPC_LIB_LIMIT_LOG_WARN(frm_, ...)  \
    UTIL_LIMIT_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_WARN, frm_, ##__VA_ARGS__)
#define URPC_LIB_LIMIT_LOG_NOTICE(frm_, ...)    \
    UTIL_LIMIT_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_NOTICE, frm_, ##__VA_ARGS__)
#define URPC_LIB_LIMIT_LOG_INFO(frm_, ...)  \
    UTIL_LIMIT_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_INFO, frm_, ##__VA_ARGS__)
#define URPC_LIB_LIMIT_LOG_DEBUG(frm_, ...)     \
    UTIL_LIMIT_VLOG(urpc_lib_get_vlog_ctx(), UTIL_VLOG_LEVEL_DEBUG, frm_, ##__VA_ARGS__)

util_vlog_ctx_t *urpc_lib_get_vlog_ctx(void);

#ifdef __cplusplus
}
#endif

#endif // URPC_LIB_LOG_H
