/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
#include "ub_perf_cycle.h"

ub_perf_context_t *g_perf_context = NULL;

static int ub_init_perf_proc(ub_perf_proc_context_t *perf_proc, uint64_t cycles_num)
{
    perf_proc->cycle_cnt = 0;
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
    if (cycles_num == 0) {
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
