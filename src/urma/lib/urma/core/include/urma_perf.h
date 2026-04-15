/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: Performance monitoring and profiling for URMA
 * Author: Tang Zhedong
 * Create: 2026-04-08
 * Note:
 * History: 2026-04-08 create file
 */

#ifndef URMA_PERF_H
#define URMA_PERF_H

#include <stdint.h>
#include <stdbool.h>
#include <threads.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urma_perf_type {
    UB_JETTY_POST_SEND,
    BOND_JETTY_POST_SEND,
    UB_JFS_POST_SEND,
    BOND_JFS_POST_SEND,
    UB_JETTY_POST_RECV,
    BOND_JETTY_POST_RECV,
    UB_POST_JFR_RECV,
    BOND_POST_JFR_RECV,
    UB_POLL_JFC,
    BOND_POLL_JFC,
    UB_WAIT_JFC,
    BOND_WAIT_JFC,
    UB_ACK_JFC,
    UB_REARM_JFC,
    BOND_REARM_JFC,
    URMA_PERF_RECORD_TYPE_MAX,
} urma_perf_record_type_t;

typedef struct urma_perf_stats {
    uint64_t retry_count;
    struct {
        urma_perf_record_type_t type;
        uint64_t sample_num;
        uint64_t average;
        uint64_t mininum;
        uint64_t maxinum;
        uint64_t p50;
        uint64_t p90;
        uint64_t p99;
    } type_record[URMA_PERF_RECORD_TYPE_MAX];
} urma_perf_stats_t;

typedef struct {
    int64_t lowest_trackable_value;
    int64_t highest_trackable_value;
    int32_t significant_figures;
    int32_t unit_magnitude;
    int32_t sub_bucket_magnitude;
    int32_t sub_bucket_half_count;
    int32_t sub_bucket_mask;
    int32_t sub_bucket_count;
    int32_t bucket_count;
    int64_t total_count;
    int64_t min_value;
    int64_t max_value;
    int64_t *counts;
} hdr_histogram_data;

typedef struct {
    hdr_histogram_data* histograms[URMA_PERF_RECORD_TYPE_MAX];
    urma_perf_stats_t stats;
    int32_t is_running;
} urma_perf_context;

extern thread_local urma_perf_context* g_perf_ctx;

#define PERF_PROFILING_START(type) \
    struct timespec __perf_start_##type; \
    do { \
        if (g_perf_ctx != NULL && g_perf_ctx->is_running == 1) { \
            clock_gettime(CLOCK_MONOTONIC, &__perf_start_##type); \
        } \
    } while (0)

#define PERF_PROFILING_END(type) \
    do { \
        if (g_perf_ctx != NULL && g_perf_ctx->is_running == 1) { \
            struct timespec _perf_end; \
            clock_gettime(CLOCK_MONOTONIC, &_perf_end); \
            uint64_t _perf_elapsed_ns = (_perf_end.tv_sec - __perf_start_##type.tv_sec) * 1000000000UL + \
                (_perf_end.tv_nsec - __perf_start_##type.tv_nsec); \
            urma_step_perf(type, _perf_elapsed_ns); \
        } \
    } while (0)

/**
 * Start performance monitoring for urma devices.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_start_perf(void);

/**
 * Stop performance monitoring for urma devices.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_stop_perf(void);

void urma_step_perf(urma_perf_record_type_t type, uint64_t latency);

/**
 * Get performance statistics information.
 * @param[in] perf_buf: Buffer to store performance information, user needs to allocate the memory;
 * @param[in] length: Pointer to buffer length, input as buffer size, output as actual data length;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_get_perf_info(char *perf_buf, uint32_t *length);

#ifdef __cplusplus
}
#endif

#endif
