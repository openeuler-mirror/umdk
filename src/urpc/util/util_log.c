/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: util log
 * Create: 2025-11-18
 */

#include <pthread.h>

#include "urpc_util.h"
#include "util_log.h"

static util_vlog_ctx_t *log_ctx = NULL;
int util_log_ctx_set(util_vlog_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -EINVAL;
    }
    log_ctx = ctx;
    return 0;
}

util_vlog_ctx_t *util_log_ctx_get(void)
{
    return log_ctx;
}