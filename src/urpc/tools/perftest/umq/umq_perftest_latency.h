/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perftest latency test case
 * Create: 2025-8-27
 */

#ifndef UMQ_PERFTEST_LATENCY_H
#define UMQ_PERFTEST_LATENCY_H

#include "umq_perftest_param.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_perftest_latency_arg {
    umq_perftest_config_t *cfg;
} umq_perftest_latency_arg_t;

void umq_perftest_run_latency(uint64_t umqh, umq_perftest_latency_arg_t *lat_arg);

#ifdef __cplusplus
}
#endif

#endif  // UMQ_PERFTEST_LATENCY_H