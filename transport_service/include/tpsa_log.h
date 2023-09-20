/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa log head file
 * Author: Chen Wen
 * Create: 2022-08-24
 * Note:
 * History:
 */

#ifndef TPSA_LOG_H
#define TPSA_LOG_H

#include "ub_list.h"


#ifdef __cplusplus
extern "C"
{
#endif

enum tpsa_vlog_level {
    /* TPSA_VLOG_LEVEL_EMERG = 0, */
    /* TPSA_VLOG_LEVEL_ALERT = 1, */
    TPSA_VLOG_LEVEL_CRIT = 2,
    TPSA_VLOG_LEVEL_ERR = 3,
    TPSA_VLOG_LEVEL_WARNING = 4,
    /* TPSA_VLOG_LEVEL_NOTICE = 5, */
    TPSA_VLOG_LEVEL_INFO = 6,
    TPSA_VLOG_LEVEL_DEBUG = 7,
    TPSA_VLOG_LEVEL_MAX = 8,
};

void tpsa_log_init(void);
void tpsa_log_uninit(void);
void tpsa_log_set_level(unsigned level);
void tpsa_log(const char *function, int line, uint32_t level, const char *format, ...);
bool tpsa_log_drop(unsigned int level);

#define TPSA_LOG(l, ...) if (!tpsa_log_drop(TPSA_VLOG_LEVEL_##l)) {                          \
        tpsa_log(__func__, __LINE__, TPSA_VLOG_LEVEL_##l, __VA_ARGS__); \
    }

#define TPSA_LOG_INFO(...) TPSA_LOG(INFO, __VA_ARGS__)

#define TPSA_LOG_ERR(...) TPSA_LOG(ERR, __VA_ARGS__)

#define TPSA_LOG_WARN(...) TPSA_LOG(WARNING, __VA_ARGS__)

#define TPSA_LOG_DEBUG(...) TPSA_LOG(DEBUG, __VA_ARGS__)


#ifdef __cplusplus
}
#endif

#endif
