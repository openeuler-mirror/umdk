/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: perftest qps
 * Create: 2025-9-8
 */

#ifndef PERFTEST_QPS_H
#define PERFTEST_QPS_H

#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
#include <cstdint>
#include <atomic>
using namespace std;
#else
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#endif

#include "perftest_thread.h"

#ifdef __cplusplus

extern "C" {
#endif

typedef struct perftest_qps_ctx {
    atomic_ullong reqs[PERFTEST_THREAD_MAX_NUM];
    uint32_t thread_num;
    uint32_t size_total;    // record sum of all sizes
    bool show_thread;
} perftest_qps_ctx_t;

perftest_qps_ctx_t *get_perftest_qps_ctx(void);
void perftest_print_qps(perftest_qps_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif  // PERFTEST_QPS_H