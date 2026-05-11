/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Logging API and level definitions for the UMS agent
 * Author: Hu Ying
 * Create: 2026-04-20
 * Note:
 * History: 2026-04-20  Create File
 */

#ifndef UMS_AGENT_LOG_H
#define UMS_AGENT_LOG_H

enum ums_agent_log_level {
    UMS_AGENT_LOG_LEVEL_EMERG   = 0,
    UMS_AGENT_LOG_LEVEL_ALERT   = 1,
    UMS_AGENT_LOG_LEVEL_CRIT    = 2,
    UMS_AGENT_LOG_LEVEL_ERR     = 3,
    UMS_AGENT_LOG_LEVEL_WARNING = 4,
    UMS_AGENT_LOG_LEVEL_NOTICE  = 5,
    UMS_AGENT_LOG_LEVEL_INFO    = 6,
    UMS_AGENT_LOG_LEVEL_DEBUG   = 7,
    UMS_AGENT_LOG_LEVEL_MAX     = 8,
};

#define UMS_AGENT_LOG_EMERG(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_EMERG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_ALERT(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_ALERT, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_CRIT(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_CRIT, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_ERR(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_ERR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_WARN(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_WARNING, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_NOTICE(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_NOTICE, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_INFO(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define UMS_AGENT_LOG_DEBUG(fmt, ...) \
    ums_agent_log_output(UMS_AGENT_LOG_LEVEL_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)

#define UMS_AGENT_LOG_FMT_ARG_IDX   4
#define UMS_AGENT_LOG_VA_ARG_IDX    5

void ums_agent_log_init(enum ums_agent_log_level level);
void ums_agent_log_deinit(void);
void ums_agent_log_set_level(enum ums_agent_log_level level);
void ums_agent_log_output(enum ums_agent_log_level level, const char *func,
    int line, const char *fmt, ...)
    __attribute__((format(printf, UMS_AGENT_LOG_FMT_ARG_IDX, UMS_AGENT_LOG_VA_ARG_IDX)));

#endif /* UMS_AGENT_LOG_H */
