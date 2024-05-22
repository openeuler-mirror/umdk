/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: resource operation header file for urma_tp_test
 * Author: Qian Guoxin
 * Create: 2024-01-31
 * Note:
 * History: 2024-01-31   create file
 */

#ifndef TP_TEST_RES_H
#define TP_TEST_RES_H

#include "urma_types.h"

#include "ub_util.h"

#include "tp_test_para.h"
#include "ub_get_clock.h"
extern urma_token_t g_tp_test_token;

typedef struct tp_test_context {
    urma_transport_type_t tp_type;
    uint32_t ctx_num;
    urma_context_t **urma_ctx;
    urma_device_attr_t dev_attr;
    urma_token_id_t **token_id;

    // jetty
    urma_jfc_t **jfc;
    urma_jfr_t **jfr;
    urma_jetty_t **jetty;
    uint32_t jetty_num;

    // remote info
    urma_jetty_t remote_jetty;

    // import jetty
    urma_target_jetty_t **tjetty;

    pthread_t *thread;
    struct tp_thread_arg *thread_arg;

    uint64_t **before;  // cycles
    uint64_t **middle;  // cycles
    uint64_t **after;   // cycles
} tp_test_context_t;

typedef struct tp_thread_arg {
    tp_test_config_t *cfg;
    tp_test_context_t *ctx;
    uint32_t thread_idx;
    bool stop;
} tp_thread_arg_t;

int create_ctx(tp_test_context_t *ctx, tp_test_config_t *cfg);
void destroy_ctx(tp_test_context_t *ctx, tp_test_config_t *cfg);
#endif