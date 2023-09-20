/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: UB perf cycle header file
 * Author: Chen Yutao
 * Create: 2022-10-25
 * Note:
 * History: 2022-10-25   Create File
 *          2022-12-28   Rename File to ub_perf_cycle.h
 */

#ifndef UB_PERF_CYCLE_H
#define UB_PERF_CYCLE_H

/* API with compile macro PERF_CYCLE_FLAG only for perftest cycle record. */
/* this file is only compiled with -DPERF_CYCLE="enable" */

#include <stdint.h>

typedef struct ub_perf_proc_context {
    uint64_t cycles_num;                 /* number of one procedure iterations */
    uint64_t cycle_cnt;                  /* cycle counter */
    uint64_t *start;
    uint64_t *end;
} ub_perf_proc_context_t;

typedef struct ub_perf_context {
    uint32_t perf_num;                    /* number of perftest procedures */
    ub_perf_proc_context_t *perf_proc;
} ub_perf_context_t;

int ub_perf_context_init(uint32_t perf_num, uint64_t cycles_num);
void ub_perf_context_uninit(void);
ub_perf_context_t *ub_get_perf_context(void);

#endif // UB_PERF_CYCLE_H