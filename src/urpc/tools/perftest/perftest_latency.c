/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: perftest latency
 * Create: 2025-9-8
 */

#include <math.h>
#include <stdlib.h>
#include <stdio.h>

#include "ub_get_clock.h"
#include "perftest_util.h"

#include "perftest_latency.h"

#define LATENCY_MEASURE_TAIL 2

#define SERVER_USE_SGE_SIZE 256
#define UNIDIRECTIONAL_LATENCY_FACTOR 1
#define BIDIRECTIONAL_LATENCY_FACTOR 2

static int urpc_perftest_latency_compare(const void *src, const void *dst)
{
    const uint64_t *a = (const uint64_t *)src;
    const uint64_t *b = (const uint64_t *)dst;

    if (*a < *b) {
        return -1;
    } else if (*a > *b) {
        return 1;
    }

    return 0;
}

static inline uint32_t urpc_perftest_get_latency_percentile(uint32_t measure_cnt, double percent)
{
    uint32_t percentile = (uint32_t)ceil((measure_cnt) * percent);
    return percentile > measure_cnt - 1 ? measure_cnt - 1 : percentile;
}

static int perftest_calculate_rtt_factor(int cmd)
{
    if (cmd == SEND_LATENCY_MODE) {
        return BIDIRECTIONAL_LATENCY_FACTOR;
    }
    return UNIDIRECTIONAL_LATENCY_FACTOR;
}

void perftest_calculate_latency(uint64_t *cycles, uint32_t iters, uint32_t msg_size, int mode)
{
    if (iters <= LATENCY_MEASURE_TAIL) {
        return;
    }

    int rtt_factor = perftest_calculate_rtt_factor(mode);
    double cycles_to_units = get_cpu_mhz(false);
    double cycles_rtt_quotient = cycles_to_units * rtt_factor;

    uint32_t measure_cnt = iters;
    qsort(cycles, (size_t)measure_cnt, sizeof(uint64_t), urpc_perftest_latency_compare);
    measure_cnt = measure_cnt - LATENCY_MEASURE_TAIL;  // Remove two largest values

    double average_sum = 0.0, average = 0.0;
    for (uint32_t i = 0; i < measure_cnt; i++) {
        average_sum += (cycles[i] / cycles_rtt_quotient);
    }
    average = average_sum / measure_cnt;

    double stdev, temp_var, stdev_sum = 0;
    for (uint32_t i = 0; i < measure_cnt; i++) {
        temp_var = average - (cycles[i] / cycles_rtt_quotient);
        stdev_sum += temp_var * temp_var;
    }
    stdev = sqrt(stdev_sum / measure_cnt);

    uint32_t iters_50 = urpc_perftest_get_latency_percentile(measure_cnt, 0.5);
    uint32_t iters_99 = urpc_perftest_get_latency_percentile(measure_cnt, 0.99);
    uint32_t iters_99_9 = urpc_perftest_get_latency_percentile(measure_cnt, 0.999);
    uint32_t iters_99_99 = urpc_perftest_get_latency_percentile(measure_cnt, 0.9999);
    uint32_t iters_99_99_9 = urpc_perftest_get_latency_percentile(measure_cnt, 0.99999);

    (void)printf(" bytes   iterations  t_min[us]  t_max[us]  t_median[us]  t_avg[us]  t_stdev[us]  "
                 "99%%[us]  99.9%%[us]  99.99%%[us]  99.999%%[us]\n");
    (void)printf(" %-7u %-10u  %-7.2lf    %-7.2lf    %-7.2lf       %-7.2lf    %-7.2lf      "
                 "%-7.2lf  %-7.2lf    %-7.2lf     %-7.2lf\n",
        msg_size, iters, cycles[0] / cycles_rtt_quotient, cycles[measure_cnt - 1] / cycles_rtt_quotient,
        cycles[iters_50] / cycles_rtt_quotient, average, stdev, cycles[iters_99] / cycles_rtt_quotient,
        cycles[iters_99_9] / cycles_rtt_quotient, cycles[iters_99_99] / cycles_rtt_quotient,
        cycles[iters_99_99_9] / cycles_rtt_quotient);
}

uint64_t get_total_cycle(uint32_t con_num, uint64_t *cycles)
{
    uint64_t res = 0;
    if (con_num > 1) {
        for (uint32_t i = 1; i < con_num; i++) {
            res += cycles[i];
        }
    }
    return res;
}

void perftest_print_latency(perftest_latency_ctx_t *ctx)
{
    // fake print func
    while (!is_perftest_force_quit()) {
        (void)sleep(1);
    }
}
