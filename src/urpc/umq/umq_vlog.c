/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Provide the umq vlog module
 * Create: 2025-08-04
 */

#include <pthread.h>

#include "urpc_util.h"
#include "util_log.h"
#include "umq_errno.h"
#include "umq_types.h"
#include "umq_vlog.h"

static umq_vlog_config_t g_umq_log_config = {
    .ctx = {
        .level = UTIL_VLOG_LEVEL_INFO,
        .vlog_name = "UMQ",
        .vlog_output_func = default_vlog_output,
        .rate_limited = {
            .interval_ms = UTIL_VLOG_PRINT_PERIOD_MS,
            .num = UTIL_VLOG_PRINT_TIMES,
        },
    },
    .log_lock = PTHREAD_MUTEX_INITIALIZER,
};

umq_vlog_config_t *umq_get_log_config(void)
{
    return &g_umq_log_config;
}

util_vlog_ctx_t *umq_get_log_ctx(void)
{
    return (util_vlog_ctx_t *)&g_umq_log_config.ctx;
}

URPC_CONSTRUCTOR(umq_log_register, CONSTRUCTOR_PRIORITY_LOG_UMQ)
{
    util_log_ctx_set(umq_get_log_ctx());
}