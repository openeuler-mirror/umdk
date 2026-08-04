/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_log.h
 * Description   : dlock log module
 * History       : create file & add functions
 * 1.Date        : 2021-06-11
 * Author        : zhangjun
 * Modification  : Created file
 */

#ifndef __DLOCK_LOG_H__
#define __DLOCK_LOG_H__

#include <syslog.h>
#include "urma_log.h"

namespace dlock {
constexpr unsigned int DLOCK_LOG_FORMAT_LEN = 512;

void dlock_log(const char *func, int line, int priority, const char *format, ...) noexcept;
void dlock_set_log_level(int log_level);

#define DLOCK_LOG(dbg_level, fmt, args...)                         \
    do {                                                           \
        dlock_log(__FUNCTION__, __LINE__, dbg_level, fmt, ##args); \
        if (!urma_log_drop(static_cast<urma_vlog_level_t>(dbg_level))) { \
            urma_log(__FILE_NAME__, __FUNCTION__, __LINE__, static_cast<urma_vlog_level_t>(dbg_level), fmt, ##args); \
        } \
    } while (0)

#define DLOCK_LOG_DEBUG(format, ...) DLOCK_LOG(LOG_DEBUG, format, ##__VA_ARGS__)
#define DLOCK_LOG_INFO(format, ...) DLOCK_LOG(LOG_INFO, format, ##__VA_ARGS__)
#define DLOCK_LOG_WARN(format, ...) DLOCK_LOG(LOG_WARNING, format, ##__VA_ARGS__)
#define DLOCK_LOG_ERR(format, ...) DLOCK_LOG(LOG_ERR, format, ##__VA_ARGS__)
};

#endif
