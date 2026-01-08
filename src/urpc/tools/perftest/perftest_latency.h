/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: perftest latency
 * Create: 2025-9-8
 */

#ifndef PERFTEST_LATENCY_H
#define PERFTEST_LATENCY_H

#include <stdlib.h>
#include <unistd.h>

#define SEND_LATENCY_MODE 0

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct perftest_latency_ctx {
    uint64_t *cycles;
    uint64_t *first_cycles;
    uint32_t iters;
} perftest_latency_ctx_t;

perftest_latency_ctx_t *get_perftest_latency_ctx(void);

void perftest_calculate_latency(uint64_t *cycles, uint32_t iters, uint32_t msg_size, int mode);
void perftest_print_latency(perftest_latency_ctx_t *ctx);

uint64_t get_total_cycle(uint32_t con_num, uint64_t *cycles);

#ifdef __cplusplus
}
#endif

#endif  // URPC_LIB_PERFTEST_LATENCY_H