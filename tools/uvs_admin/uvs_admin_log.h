/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs_admin log head file
 * Author: Ji Lei
 * Create: 2023-6-13
 * Note:
 * History: 2023-6-13 delare uvs_admin log API
 */


#ifndef UVS_ADMIN_LOG_H
#define UVS_ADMIN_LOG_H

typedef enum uvs_admin_vlog_level {
    UVS_ADMIN_VLOG_LEVEL_EMERG = 0,
    UVS_ADMIN_VLOG_LEVEL_ALERT = 1,
    UVS_ADMIN_VLOG_LEVEL_CRIT = 2,
    UVS_ADMIN_VLOG_LEVEL_ERR = 3,
    UVS_ADMIN_VLOG_LEVEL_WARNING = 4,
    UVS_ADMIN_VLOG_LEVEL_NOTICE = 5,
    UVS_ADMIN_VLOG_LEVEL_INFO = 6,
    UVS_ADMIN_VLOG_LEVEL_DEBUG = 7,
    UVS_ADMIN_VLOG_LEVEL_MAX = 8,
} uvs_admin_vlog_level_t;

void uvs_admin_log(const char *function, int line, uvs_admin_vlog_level_t level, const char *format, ...);

#define UVS_ADMIN_LOG(l, ...) uvs_admin_log(__func__, __LINE__, UVS_ADMIN_VLOG_LEVEL_##l, __VA_ARGS__)

#define UVS_ADMIN_LOG_INFO(...) UVS_ADMIN_LOG(INFO, __VA_ARGS__)

#define UVS_ADMIN_LOG_ERR(...) UVS_ADMIN_LOG(ERR, __VA_ARGS__)

#define UVS_ADMIN_LOG_WARN(...) UVS_ADMIN_LOG(WARNING, __VA_ARGS__)

#define UVS_ADMIN_LOG_DEBUG(...) UVS_ADMIN_LOG(DEBUG, __VA_ARGS__)


#endif
