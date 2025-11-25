/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perftest param process
 * Create: 2025-8-29
 */

#ifndef UMQ_PERFTEST_PARAM_H
#define UMQ_PERFTEST_PARAM_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

#include "perftest_util.h"
#include "umq_types.h"
#include "umq_pro_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_ENABLE_INLINE_LIMIT_SIZE 32
#define UMQ_INLINE_ENABLE 1

typedef struct umq_perftest_config {
    perftest_config_t config;

    uint32_t trans_mode;
    uint32_t feature;
    uint32_t test_round;
    umq_buf_mode_t buf_mode;
    uint16_t cna;
    uint32_t deid;
    uint16_t eid_idx;
    bool buf_multiplex;
    bool use_atomic_window;
    uint64_t thresh_array[UMQ_PERF_QUANTILE_MAX_NUM];
    uint16_t thresh_num;
} umq_perftest_config_t;

int umq_perftest_parse_arguments(int argc, char **argv, umq_perftest_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif  // UMQ_LIB_PERFTEST_PARAM_H
