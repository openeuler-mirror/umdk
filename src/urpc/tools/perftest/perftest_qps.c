/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc lib perftest qps test case
 * Create: 2025-9-8
 */

#include <stdatomic.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include "ub_get_clock.h"
#include "urpc_util.h"
#include "perftest_util.h"
#include "perftest_qps.h"

#define QPS_MESSAGE_SIZE 4096
#define PERCENT_NUM 100

#define QPS_THREAD_FORMAT "       %-7.3lf"
#define QPS_FIRST_THREAD_FORMAT "     %-7.3lf"

static inline void perftest_reqs_get(uint64_t *reqs, perftest_qps_ctx_t *ctx, uint64_t length)
{
    for (uint32_t i = 1; i < ctx->thread_num + 1 && i < length; i++) {
        reqs[i] = atomic_load(&ctx->reqs[i]);
    }
}

static inline uint64_t urpc_perftest_reqs_sum_get(uint64_t *reqs, uint32_t worker_num)
{
    uint64_t total = 0;
    for (uint32_t i = 1; i < worker_num + 1 && i < PERFTEST_THREAD_MAX_NUM; i++) {
        total += reqs[i];
    }

    return total;
}

static void urpc_perftest_print_qps_title(perftest_qps_ctx_t *ctx)
{
    int s = 0;
    int ret;
    char title[QPS_MESSAGE_SIZE];

    if (!ctx->show_thread) {
        (void)printf("  qps[Mpps]    BW[MB/Sec]     cpu-utilization[%%]\n");
        return;
    }

    ret = sprintf(title, "  qps[Mpps]    BW[MB/Sec]");
    if (ret < 0) {
        LOG_PRINT("fail to get qps title string\n");
        ret = 0;
    }

    s += ret;
    for (uint32_t i = 1; i < ctx->thread_num + 1; i++) {
        ret = sprintf(title + s, "  %02u-qps[Mpps]", i);
        if (ret < 0) {
            LOG_PRINT("fail to get qps title string\n");
            ret = 0;
        }

        s += ret;
    }

    (void)printf("%s\n", title);
}

// use cycle to calculate the precise time for QPS; sleep is only used for timed output of results.
void perftest_print_qps(perftest_qps_ctx_t *ctx)
{
    char result[QPS_MESSAGE_SIZE];
    uint64_t reqs[PERFTEST_THREAD_MAX_NUM] = {0};
    uint64_t reqs_old[PERFTEST_THREAD_MAX_NUM] = {0};
    uint64_t cur_sum, end;
    double cycles_to_units = get_cpu_mhz(true);
    double qps;
    int ret;

    perftest_reqs_get(reqs_old, ctx, PERFTEST_THREAD_MAX_NUM);
    uint64_t reqs_num = urpc_perftest_reqs_sum_get(reqs_old, ctx->thread_num);
    uint64_t begin = get_cycles();

    struct rusage ru;
    double end_cpu_time;
    getrusage(RUSAGE_SELF, &ru);
    double begin_cpu_time =
        ru.ru_utime.tv_sec + ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec + ru.ru_utime.tv_usec) / (double)PERFTEST_1M;

    urpc_perftest_print_qps_title(ctx);
    uint64_t start_cycle = get_cycles();
    while (!is_perftest_force_quit() && (get_cycles() - start_cycle) / cycles_to_units < ITER_MAX_WAIT_TIME_US) {
        (void)sleep(1);

        perftest_reqs_get(reqs, ctx, PERFTEST_THREAD_MAX_NUM);
        cur_sum = urpc_perftest_reqs_sum_get(reqs, ctx->thread_num);
        end = get_cycles();
        getrusage(RUSAGE_SELF, &ru);
        end_cpu_time = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec +
                       (ru.ru_stime.tv_usec + ru.ru_utime.tv_usec) / (double)PERFTEST_1M;
        double real_time_diff = (double)(end - begin) / (cycles_to_units);
        // show cpu_usage

        // show qps
        qps = (double)(cur_sum - reqs_num) / real_time_diff;

        int s = 0;
        ret = sprintf(result, "  %-7.6lf     %-7.3lf           %-7.2lf", qps,
                      qps * PERFTEST_1M * ctx->size_total / PERFTEST_1MB,
                      (end_cpu_time - begin_cpu_time) * PERCENT_NUM * PERFTEST_1M / real_time_diff);
        if (ret < 0) {
            LOG_PRINT("fail to get qps string\n");
            ret = 0;
        }

        s += ret;
        if (!ctx->show_thread) {
            goto OUTPUT;
        }

        for (uint32_t i = 1; i < ctx->thread_num + 1; i++) {
            ret = sprintf(result + s, i == 1 ? QPS_FIRST_THREAD_FORMAT : QPS_THREAD_FORMAT,
                (double)(reqs[i] - reqs_old[i]) * cycles_to_units / (double)(end - begin));
            if (ret < 0) {
                LOG_PRINT("fail to get worker thread qps string\n");
                ret = 0;
            }

            s += ret;
            reqs_old[i] = reqs[i];
        }

OUTPUT:
        (void)fflush(stdout);
        (void)printf("%s\n", result);
        reqs_num = cur_sum;
        begin = end;
        begin_cpu_time = end_cpu_time;
    }
    perftest_force_quit();
}
