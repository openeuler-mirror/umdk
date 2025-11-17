/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: UB perf cycle source file
 * Author: Chen Yutao
 * Create: 2022-10-25
 * Note:
 * History: 2022-10-25   Create File
 *                       Rename to ub_perf_cycle.c
 */

#include <stdlib.h>
#include <syslog.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "ub_get_clock.h"
#include "ub_perf_cycle.h"

#define UB_PERF_CYCLE_NUM_MIN 5
#define UB_PERF_MEASURE_TAIL 2

#define UB_PERF_PERCENT_25 (0.25)
#define UB_PERF_PERCENT_50 (0.50)
#define UB_PERF_PERCENT_75 (0.75)
#define UB_PERF_PERCENT_99 (0.99)
#define UB_PERF_PERCENT_99_99 (0.9999)

#define RESULT_LAT_FMT " point_idx\t t_min[us]\t t_max[us]\t t_avg[us]\t " \
    "25%%[us]\t 50%%[us]\t 75%%[us]\t 99%%[us]\t 99.99%%[us]"
#define REPORT_LAT_FMT " %-7u\t %-7.2lf\t %-7.2lf\t %-7.2lf\t %-7.2lf\t %-7.2lf\t %-7.2lf\t " \
                        "%-7.2lf\t %-7.2lf"

ub_perf_context_t *g_perf_context = NULL;

static int ub_init_perf_proc(ub_perf_proc_context_t *perf_proc, uint64_t cycles_num)
{
    perf_proc->cycle_cnt = 0;
    perf_proc->cycles_num = cycles_num;
    perf_proc->start = calloc(1, cycles_num * sizeof(uint64_t));
    if (perf_proc->start == NULL) {
        return -ENOMEM;
    }
    perf_proc->end = calloc(1, cycles_num * sizeof(uint64_t));
    if (perf_proc->end == NULL) {
        free(perf_proc->start);
        perf_proc->start = NULL;
        return -ENOMEM;
    }
    return 0;
}

static void ub_free_perf_proc(ub_perf_proc_context_t *perf_proc)
{
    free(perf_proc->start);
    perf_proc->start = NULL;
    free(perf_proc->end);
    perf_proc->end = NULL;
}

int ub_perf_context_init(uint32_t perf_num, uint64_t cycles_num)
{
    if (cycles_num == 0 || cycles_num < UB_PERF_CYCLE_NUM_MIN ||
        cycles_num > SIZE_MAX / sizeof(uint64_t)) {
        syslog(LOG_ERR, "Invalid parameter.\n");
        return -EINVAL;
    }

    ub_perf_context_t *perf_context = calloc(1, sizeof(ub_perf_context_t));
    if (perf_context == NULL) {
        return -ENOMEM;
    }
    perf_context->perf_num = perf_num;
    perf_context->perf_proc = calloc(1, perf_num * sizeof(ub_perf_proc_context_t));
    if (perf_context->perf_proc == NULL) {
        goto free_perf_ctx;
    }
    int i, j;
    for (i = 0; i < perf_num; i++) {
        if (ub_init_perf_proc(&perf_context->perf_proc[i], cycles_num) != 0) {
            syslog(LOG_ERR, "Failed to init perf proc.\n");
            goto free_perf_proc;
        }
    }
    g_perf_context = perf_context;
    return 0;

free_perf_proc:
    for (j = 0; j < i; j++) {
        ub_free_perf_proc(&perf_context->perf_proc[j]);
    }
    free(perf_context->perf_proc);
free_perf_ctx:
    free(perf_context);
    return -1;
}

void ub_perf_context_uninit(void)
{
    ub_perf_context_t *perf_context = g_perf_context;
    g_perf_context = NULL;
    if (perf_context == NULL) {
        syslog(LOG_ERR, "Invalid parameter with perf_context null ptr.\n");
        return;
    }
    for (int i = 0; i < perf_context->perf_num; i++) {
        ub_free_perf_proc(&perf_context->perf_proc[i]);
    }

    free(perf_context->perf_proc);
    perf_context->perf_proc = NULL;

    free(perf_context);
}

ub_perf_context_t *ub_get_perf_context(void)
{
    return g_perf_context;
}

static int data_compare(const void *a, const void *b)
{
    return *((uint64_t *)a) - *((uint64_t *)b);
}

static void ub_print_result_us(uint64_t *cycles, uint64_t cycles_num, uint32_t index)
{
    double sum = 0;
    double cpu_mhz = get_cpu_mhz(true);

    qsort(cycles, cycles_num, sizeof(uint64_t), data_compare);

    if (cycles_num <= UB_PERF_MEASURE_TAIL) {
        (void)fprintf(stderr, "Invalid cycles_num: too small after tail removal.\n");
        return;
    }
    uint64_t cal_num = cycles_num - UB_PERF_MEASURE_TAIL;       /* Remove the two largest values */

    if (cal_num > SIZE_MAX / sizeof(double)) {
        (void)fprintf(stderr, "Requested buffer size too large.\n");
        return;
    }
    double *delta_us = (double *)calloc(cal_num, sizeof(double));
    if (delta_us == NULL) {
        (void)fprintf(stderr, "Failed to alloc delta_us buffer.\n");
        return;
    }

    for (uint64_t i = 0; i < cal_num; i++) {
        delta_us[i] = cycles[i] * 1.0 / cpu_mhz;
        sum += delta_us[i];
    }

    uint64_t percent_25 = (uint64_t)(cal_num * UB_PERF_PERCENT_25);
    uint64_t percent_50 = (uint64_t)(cal_num * UB_PERF_PERCENT_50);
    uint64_t percent_75 = (uint64_t)(cal_num * UB_PERF_PERCENT_75);
    uint64_t percent_99 = (uint64_t)(cal_num * UB_PERF_PERCENT_99);
    uint64_t percent_99_99 = (uint64_t)(cal_num * UB_PERF_PERCENT_99_99);
    (void)printf(REPORT_LAT_FMT, index, delta_us[0], delta_us[cal_num - 1], sum / (cal_num - 1),
        delta_us[percent_25], delta_us[percent_50], delta_us[percent_75], delta_us[percent_99],
        delta_us[percent_99_99]);
    (void)printf("\n");
    free(delta_us);
}

static void ub_print_perf_result_by_index(ub_perf_proc_context_t *perf_proc, uint32_t index)
{
    uint64_t cycles_num = perf_proc->cycles_num;
    uint64_t *cycles = (uint64_t *)calloc(cycles_num, sizeof(uint64_t));
    if (cycles == NULL) {
        (void)fprintf(stderr, "Failed to alloc cycles buffer.\n");
        return;
    }
    for (uint64_t i = 0; i < cycles_num; i++) {
        if (perf_proc->end[i] < perf_proc->start[i]) {
            (void)fprintf(stderr, "Invalid parameter, end: %lu, start: %lu.\n", perf_proc->end[i],
                perf_proc->start[i]);
            free(cycles);
            return;
        }
        cycles[i] = perf_proc->end[i] - perf_proc->start[i];
    }

    ub_print_result_us(cycles, cycles_num, index);
    free(cycles);
}

void ub_print_perf_result(ub_perf_context_t *perf_ctx)
{
    if (perf_ctx == NULL || perf_ctx->perf_num == 0 || perf_ctx->perf_proc == NULL) {
        (void)fprintf(stderr, "Invalid parameter.\n");
        return;
    }
    (void)printf(RESULT_LAT_FMT);
    (void)printf("\n");
    for (uint32_t i = 0; i < perf_ctx->perf_num; i++) {
        ub_print_perf_result_by_index(&perf_ctx->perf_proc[i], i);
    }
}