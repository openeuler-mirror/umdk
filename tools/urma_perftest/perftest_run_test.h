/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: run test header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-07
 * Note:
 * History: 2022-04-07   create file
 */

#ifndef PERFTEST_RUN_TEST_H
#define PERFTEST_RUN_TEST_H

#include "perftest_parameters.h"
#include "perftest_resources.h"

int run_read_lat(perftest_context_t *ctx, perftest_config_t *cfg);
int run_write_lat(perftest_context_t *ctx, perftest_config_t *cfg);
int run_send_lat(perftest_context_t *ctx, perftest_config_t *cfg);
int run_atomic_lat(perftest_context_t *ctx, perftest_config_t *cfg);
int run_read_bw(perftest_context_t *ctx, perftest_config_t *cfg);
int run_write_bw(perftest_context_t *ctx, perftest_config_t *cfg);
int run_send_bw(perftest_context_t *ctx, perftest_config_t *cfg);
int run_atomic_bw(perftest_context_t *ctx, perftest_config_t *cfg);

#endif