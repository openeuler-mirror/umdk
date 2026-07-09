/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq perf
 * Create: 2025-10-29
 */

#ifndef UMQ_PERF_H
#define UMQ_PERF_H

#include <stdint.h>
#include <stdbool.h>

#include "umq_dfx_types.h"
#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_PERF_RECORD_TRANSPORT_POLL_EMPTY_OFFSET (2)

#define UMQ_DFX_PERF_EQUALS "=========================================================================================\
================================================================================"
#define UMQ_DFX_PERF_UNDERLINE "--------------------------------------------------------------------------------------\
-----------------------------------------------------------------------------------"

uint64_t umq_perf_get_start_timestamp(void);
void umq_perf_record_write(umq_perf_record_type_t type, uint64_t start);
void umq_perf_record_write_with_direction(umq_perf_record_type_t type, uint64_t start, umq_io_direction_t direction);
void umq_perf_record_write_interrupt_with_direction(
    umq_perf_record_type_t type, uint64_t start, umq_io_direction_t direction);
int umq_perf_init(void);
void umq_perf_uninit(void);
void umq_trace_uninit(void);
void umq_trace_timer_delete(void);
int umq_trace_stop(void);
int umq_trace_start(umq_trace_cfg_t *cfg);
void umq_trace_start_record(umq_trace_type_t type, uint64_t time, uint64_t tag_timestamp, uint32_t umq_id);
void umq_trace_sub_record(umq_trace_type_t type, umq_urma_func_type_t func_type,
                          uint64_t start_time, uint64_t exec_time);
void umq_trace_item_record(uint32_t msn, uint32_t size, uint32_t sub_umq_id);
void umq_trace_end_record(umq_trace_type_t type, uint64_t time);
void umq_trace_remain_output(void);
uint64_t umq_trace_start_timestamp_get(void);
uint64_t umq_trace_timestamp_get(void);
uint64_t umq_trace_write_delta(uint64_t start);

static inline uint64_t umq_perf_get_start_timestamp_with_feature(uint32_t feature)
{
    if ((feature & UMQ_FEATURE_ENABLE_PERF) == 0) {
        return 0;
    }
    return umq_perf_get_start_timestamp();
}

static inline void umq_perf_record_write_with_feature(umq_perf_record_type_t type, uint64_t start, uint32_t feature)
{
    if ((feature & UMQ_FEATURE_ENABLE_PERF) == 0) {
        return;
    }
    umq_perf_record_write(type, start);
}

int umq_perf_start(void);
int umq_perf_reset(umq_perf_stats_cfg_t *perf_stats_cfg);
int umq_perf_stop(void);
int umq_perf_info_get(umq_perf_stats_t *perf_info);
int umq_perf_info_to_string(umq_perf_stats_t *perf_stats, char *umq_perf_stats_buf, int max_buf_size);

#ifdef __cplusplus
}
#endif

#endif
