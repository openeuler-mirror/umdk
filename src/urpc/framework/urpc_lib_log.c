/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib log
 * Create: 2024-3-12
 */

#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <syslog.h>

#include "urma_api.h"
#include "urpc_framework_errno.h"
#include "urpc_util.h"
#include "util_log.h"
#include "urpc_lib_log.h"

typedef struct urpc_lib_log_config {
    uint32_t log_flag;
    util_vlog_ctx_t ctx;
} urpc_lib_log_config_t;

static urpc_lib_log_config_t g_urpc_log_config = {
    .ctx = {
        .vlog_name = "URPC_LOG",
        .vlog_output_func = default_vlog_output,
        .level = UTIL_VLOG_LEVEL_INFO,
        .rate_limited = {
            .interval_ms = UTIL_VLOG_PRINT_PERIOD_MS,
            .num = UTIL_VLOG_PRINT_TIMES,
        },
    },
};
static pthread_mutex_t g_urpc_log_lock = PTHREAD_MUTEX_INITIALIZER;

int urpc_log_config_set(urpc_log_config_t *config)
{
    if (config == NULL) {
        URPC_LIB_LOG_ERR("invalid configure\n");
        return -URPC_ERR_EINVAL;
    }

    if ((config->log_flag & URPC_LOG_FLAG_LEVEL) &&
        (config->level < URPC_LOG_LEVEL_ERR || config->level >= URPC_LOG_LEVEL_MAX)) {
        URPC_LIB_LOG_ERR("invalid log level %d\n", config->level);
        return URPC_FAIL;
    }

    (void)pthread_mutex_lock(&g_urpc_log_lock);
    if (config->log_flag & URPC_LOG_FLAG_FUNC) {
        if (config->func == NULL) {
            g_urpc_log_config.ctx.vlog_output_func = default_vlog_output;
            urma_unregister_log_func();
            URPC_LIB_LOG_INFO("set log configuration successful, log output function: default\n");
        } else {
            g_urpc_log_config.ctx.vlog_output_func = config->func;
            urma_register_log_func(config->func);
            URPC_LIB_LOG_INFO("set log configuration successful, log output function: user defined\n");
        }
    }

    if (config->log_flag & URPC_LOG_FLAG_LEVEL) {
        g_urpc_log_config.ctx.level = (util_vlog_level_t)config->level;
        urma_log_set_level((urma_vlog_level_t)config->level);
        URPC_LIB_LOG_INFO("set log configuration successful, log level: %d\n", config->level);
    }

    if ((config->log_flag & URPC_LOG_FLAG_RATE_LIMITED)) {
        g_urpc_log_config.ctx.rate_limited.interval_ms = config->rate_limited.interval_ms;
        g_urpc_log_config.ctx.rate_limited.num = config->rate_limited.num;
        URPC_LIB_LOG_INFO("set log configuration successful, limited interval(ms): %u, limited num: %u\n",
            config->rate_limited.interval_ms, config->rate_limited.num);
    }
    (void)pthread_mutex_unlock(&g_urpc_log_lock);

    return URPC_SUCCESS;
}

int urpc_log_config_get(urpc_log_config_t *config)
{
    if (config == NULL) {
        URPC_LIB_LOG_ERR("invalid parameter\n");
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_mutex_lock(&g_urpc_log_lock);
    config->log_flag = g_urpc_log_config.log_flag;
    config->level = (urpc_log_level_t)g_urpc_log_config.ctx.level;
    config->func = g_urpc_log_config.ctx.vlog_output_func;
    config->rate_limited.interval_ms = g_urpc_log_config.ctx.rate_limited.interval_ms;
    config->rate_limited.num = g_urpc_log_config.ctx.rate_limited.num;
    if (config->func == default_vlog_output) {
        config->func = NULL;
    }
    (void)pthread_mutex_unlock(&g_urpc_log_lock);

    return URPC_SUCCESS;
}

util_vlog_ctx_t *urpc_lib_get_vlog_ctx(void)
{
    return &g_urpc_log_config.ctx;
}

URPC_CONSTRUCTOR(urpc_log_register, CONSTRUCTOR_PRIORITY_LOG_URPC)
{
    util_log_ctx_set(urpc_lib_get_vlog_ctx());
}