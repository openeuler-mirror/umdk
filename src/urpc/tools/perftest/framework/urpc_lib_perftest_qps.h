/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest qps test case
 * Create: 2024-3-6
 */

#ifndef URPC_LIB_PERFTEST_QPS_H
#define URPC_LIB_PERFTEST_QPS_H

#include "urpc_lib_perftest_param.h"
#include "perftest_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct urpc_lib_perftest_qps_arg {
    perftest_framework_config_t *cfg;
    uint32_t chid;
} urpc_lib_perftest_qps_arg_t;

void urpc_perftest_print_qps(perftest_framework_config_t *cfg);
void urpc_perftest_server_run_qps(perftest_thread_arg_t *args, urpc_lib_perftest_qps_arg_t *qps_arg, uint64_t qh);
void urpc_perftest_client_run_qps(perftest_thread_arg_t *args, urpc_lib_perftest_qps_arg_t *qps_arg, uint64_t qh);

#ifdef __cplusplus
}
#endif

#endif  // URPC_LIB_PERFTEST_QPS_H