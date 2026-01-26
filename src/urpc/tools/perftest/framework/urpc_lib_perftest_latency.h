/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest latency test case
 * Create: 2024-3-29
 */

#ifndef URPC_LIB_PERFTEST_LATENCY_H
#define URPC_LIB_PERFTEST_LATENCY_H

#include "urpc_lib_perftest_param.h"
#include "perftest_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    Q_FOR_SEND = 0,
    Q_FOR_RECV,

    LAT_Q_NUM,
};

typedef struct urpc_lib_perftest_latency_arg {
    perftest_framework_config_t *cfg;
    uint64_t r_qhs[LAT_Q_NUM];
    uint64_t l_qhs[LAT_Q_NUM];
    uint32_t chid;
} urpc_lib_perftest_latency_arg_t;

void urpc_perftest_run_latency(perftest_thread_arg_t *args, urpc_lib_perftest_latency_arg_t *lat_arg, uint64_t qh);
void urpc_perftest_print_latency(perftest_framework_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif  // URPC_LIB_PERFTEST_LATENCY_H