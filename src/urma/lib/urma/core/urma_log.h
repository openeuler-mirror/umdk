/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.
 * Description: urma log head file
 * Author: Yan Fangfang, Qian Guoxin
 * Create: 2020-9-28
 * Note:
 * History: 2020-9-28 delare urma log API
 */

#ifndef URMA_LOG_H
#define URMA_LOG_H

#include <stdbool.h>
#include <urma_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_FORMAT_IDX 4 /* index of 'format' of urma_log */
#define LOG_VA_ARG_IDX 5 /* index of variable argument of urma_log */

int urma_log_init(void);
void urma_getenv_log_level(void);
bool urma_log_drop(urma_vlog_level_t level);
void __attribute__((format(printf, LOG_FORMAT_IDX, LOG_VA_ARG_IDX)))
urma_log(const char *function, int line, urma_vlog_level_t level, const char *format, ...);
const char *urma_get_level_print(urma_vlog_level_t level);
urma_vlog_level_t urma_log_get_level_from_string(const char *level_string);

#define URMA_LOG(l, ...)                                                                                               \
    if (!urma_log_drop(URMA_VLOG_LEVEL_##l)) {                                                                         \
        urma_log(__func__, __LINE__, URMA_VLOG_LEVEL_##l, __VA_ARGS__);                                                \
    }

#define URMA_LOG_INFO(...) URMA_LOG(INFO, __VA_ARGS__)

#define URMA_LOG_ERR(...) URMA_LOG(ERR, __VA_ARGS__)

#define URMA_LOG_WARN(...) URMA_LOG(WARNING, __VA_ARGS__)

#define URMA_LOG_DEBUG(...) URMA_LOG(DEBUG, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
