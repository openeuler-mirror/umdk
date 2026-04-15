/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: Performance monitoring and profiling for URMA
 * Author: Tang Zhedong
 * Create: 2026-04-08
 * Note:
 * History: 2026-04-08 create file
 */

#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <threads.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "urma_api.h"
#include "urma_perf.h"
#include "urma_types.h"
#include "urma_private.h"

#define URMA_PERF_MIN_VALUE 32
#define URMA_PERF_MAX_VALUE 1000000000L
#define URMA_PERF_SIGNIFICANT_FIGURES 5

#define URMA_SUCCESS 0
#define URMA_ERROR -1

static const char* perf_type_names[] = {
    "UB_JETTY_POST_SEND",
    "BOND_JETTY_POST_SEND",
    "UB_JFS_POST_SEND",
    "BOND_JFS_POST_SEND",
    "UB_JETTY_POST_RECV",
    "BOND_JETTY_POST_RECV",
    "UB_POST_JFR_RECV",
    "BOND_POST_JFR_RECV",
    "UB_POLL_JFC",
    "BOND_POLL_JFC",
    "UB_WAIT_JFC",
    "BOND_WAIT_JFC",
    "UB_ACK_JFC",
    "UB_REARM_JFC",
    "BOND_REARM_JFC"
};

thread_local urma_perf_context* g_perf_ctx;

static int32_t get_bucket_index(int64_t value, int32_t unit_magnitude)
{
    int32_t leading_zero_count = __builtin_clzll(value);
    // Count the number of leading zeros. 64 is the upper limit for the int64_t type.
    int32_t pow2_ceiling = 64 - leading_zero_count;
    return pow2_ceiling - unit_magnitude - 1;
}

static int32_t get_sub_bucket_index(int64_t value, int32_t bucket_index, int32_t unit_magnitude, int32_t sub_bucket_count)
{
    int64_t bucket_base = (int64_t)1 << (bucket_index + unit_magnitude);
    int64_t sub_bucket_size = bucket_base / sub_bucket_count;
    int64_t offset = value - bucket_base;
    int32_t sub_bucket_index = (int32_t)(offset / sub_bucket_size);

    if (sub_bucket_index < 0) {
        sub_bucket_index = 0;
    }
    if (sub_bucket_index >= sub_bucket_count) {
        sub_bucket_index = sub_bucket_count - 1;
    }
    return sub_bucket_index;
}

static int32_t counts_index(int32_t bucket_index, int32_t sub_bucket_index, int32_t sub_bucket_count)
{
    return bucket_index * sub_bucket_count + sub_bucket_index;
}

static hdr_histogram_data* hdr_init(int64_t lowest_trackable_value, int64_t highest_trackable_value, int32_t significant_figures)
{
    int32_t unit_magnitude = (int32_t)floor(log(lowest_trackable_value) / log(2));
    int32_t sub_bucket_magnitude = (int32_t)ceil(log(significant_figures * 2.0) / log(2));
    int32_t sub_bucket_half_count = 1 << sub_bucket_magnitude;
    int32_t sub_bucket_count = sub_bucket_half_count * 2;
    int32_t sub_bucket_mask = sub_bucket_count - 1;
    
    int32_t bucket_count = get_bucket_index(highest_trackable_value, unit_magnitude) + 1;
    
    size_t counts_len = (bucket_count + 1) * sub_bucket_count;
    size_t size = sizeof(hdr_histogram_data) + sizeof(int64_t) * counts_len;
    
    hdr_histogram_data* data = (hdr_histogram_data*)calloc(1, size);
    if (data == NULL) {
        printf("Failed to allocate memory for hdr_histogram_data\n");
        return NULL;
    }
    data->lowest_trackable_value = lowest_trackable_value;
    data->highest_trackable_value = highest_trackable_value;
    data->significant_figures = significant_figures;
    data->unit_magnitude = unit_magnitude;
    data->sub_bucket_magnitude = sub_bucket_magnitude;
    data->sub_bucket_half_count = sub_bucket_half_count;
    data->sub_bucket_mask = sub_bucket_mask;
    data->sub_bucket_count = sub_bucket_count;
    data->bucket_count = bucket_count;
    data->min_value = INT64_MAX;
    data->max_value = 0;
    data->counts = (int64_t*)(data + 1);
    
    return data;
}

static void hdr_record_value(hdr_histogram_data* data, int64_t value)
{
    if (value < data->lowest_trackable_value) {
        value = data->lowest_trackable_value;
    }
    if (value > data->highest_trackable_value) {
        value = data->highest_trackable_value;
    }

    int32_t bucket_index = get_bucket_index(value, data->unit_magnitude);
    int32_t sub_bucket_index = get_sub_bucket_index(value, bucket_index, data->unit_magnitude, data->sub_bucket_count);
    int32_t index = counts_index(bucket_index, sub_bucket_index, data->sub_bucket_count);

    if (index < 0 || index >= (data->bucket_count + 1) * data->sub_bucket_count) {
        printf("Index out of bounds: %d\n", index);
        return;
    }

    data->counts[index]++;
    data->total_count++;

    if (value < data->min_value) {
        data->min_value = value;
    }
    if (value > data->max_value) {
        data->max_value = value;
    }
}

static int64_t hdr_get_value_at_percentile(hdr_histogram_data* data, double percentile)
{
    if (data->total_count == 0) {
        return 0;
    }

    int64_t threshold = (int64_t)ceil(percentile * data->total_count / 100.0);
    int64_t count_to_prev = 0;
    
    for (int32_t i = 0; i < data->bucket_count; i++) {
        int64_t bucket_base = (int64_t)1 << (i + data->unit_magnitude);
        int64_t sub_bucket_size = bucket_base / data->sub_bucket_count;
        for (int32_t j = 0; j < data->sub_bucket_count; j++) {
            int32_t index = counts_index(i, j, data->sub_bucket_count);
            int64_t count_at_index = data->counts[index];
            
            if (count_at_index > 0) {
                count_to_prev += count_at_index;
                if (count_to_prev >= threshold) {
                    return bucket_base + j * sub_bucket_size;
                }
            }
        }
    }
    return data->max_value;
}

static int64_t hdr_get_mean(hdr_histogram_data* data)
{
    if (data->total_count == 0) {
        return 0;
    }

    int64_t total = 0;
    for (int32_t i = 0; i < data->bucket_count; i++) {
        int64_t bucket_base = (int64_t)1 << (i + data->unit_magnitude);
        int64_t sub_bucket_size = bucket_base / data->sub_bucket_count;
        for (int32_t j = 0; j < data->sub_bucket_count; j++) {
            int32_t index = counts_index(i, j, data->sub_bucket_count);
            int64_t count = data->counts[index];
            if (count > 0) {
                int64_t value = bucket_base + j * sub_bucket_size + sub_bucket_size / 2;
                total += value * count;
            }
        }
    }
    return total / data->total_count;
}

static void hdr_free(hdr_histogram_data* data)
{
    free(data);
}

static void update_stats(urma_perf_context* ctx, urma_perf_record_type_t type)
{
    hdr_histogram_data* hist = ctx->histograms[type];
    ctx->stats.type_record[type].sample_num = hist->total_count;
    ctx->stats.type_record[type].average = hdr_get_mean(hist);
    ctx->stats.type_record[type].mininum = hist->total_count > 0 ? hist->min_value : 0;
    ctx->stats.type_record[type].maxinum = hist->max_value;
    ctx->stats.type_record[type].p50 = hdr_get_value_at_percentile(hist, 50.0);
    ctx->stats.type_record[type].p90 = hdr_get_value_at_percentile(hist, 90.0);
    ctx->stats.type_record[type].p99 = hdr_get_value_at_percentile(hist, 99.0);
}

urma_status_t urma_start_perf(void)
{
    if (g_perf_ctx != NULL) {
        printf("g_perf_ctx != NULL");
        return URMA_ERROR;
    }
    
    g_perf_ctx = (urma_perf_context*)calloc(1, sizeof(urma_perf_context));
    if (g_perf_ctx == NULL) {
        printf("g_perf_ctx == NULL");
        return URMA_ERROR;
    }
    
    g_perf_ctx->stats.retry_count = 0;
    
    for (int i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        g_perf_ctx->histograms[i] = hdr_init(URMA_PERF_MIN_VALUE, URMA_PERF_MAX_VALUE, URMA_PERF_SIGNIFICANT_FIGURES);
        if (g_perf_ctx->histograms[i] == NULL) {
            printf("Failed to initialize histogram for type %d\n", i);
            return URMA_ERROR;
        }
        g_perf_ctx->stats.type_record[i].type = (urma_perf_record_type_t)i;
    }
    
    g_perf_ctx->is_running = 1;
    return URMA_SUCCESS;
}

urma_status_t urma_stop_perf(void)
{
    if (g_perf_ctx == NULL) {
        return URMA_ERROR;
    }
    
    if (!g_perf_ctx->is_running) {
        return URMA_ERROR;
    }
    
    g_perf_ctx->is_running = 0;
    return URMA_SUCCESS;
}

void urma_step_perf(urma_perf_record_type_t type, uint64_t latency)
{
    if (g_perf_ctx == NULL || !g_perf_ctx->is_running) return;
    if (type >= URMA_PERF_RECORD_TYPE_MAX) return;

    uint32_t current_retry = urma_ubagg_switch_get();
    if (current_retry > g_perf_ctx->stats.retry_count) {
        g_perf_ctx->stats.retry_count = current_retry;
    }
    hdr_record_value(g_perf_ctx->histograms[type], latency);
}

void urma_perf_cleanup(void)
{
    if (g_perf_ctx == NULL) return;
    
    for (int i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        hdr_free(g_perf_ctx->histograms[i]);
    }
    free(g_perf_ctx);
    g_perf_ctx = NULL;
}

urma_status_t urma_get_perf_info(char *perf_buf, uint32_t *length)
{
    if (g_perf_ctx == NULL || perf_buf == NULL || length == NULL) {
        return URMA_ERROR;
    }

    for (int i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        update_stats(g_perf_ctx, i);
    }
    
    char* ptr = perf_buf;
    uint32_t remaining = *length;
    int written;
    
    written = snprintf(ptr, remaining, "retry_count: %lu\n", g_perf_ctx->stats.retry_count);
    if (written < 0 || written >= remaining) {
        return URMA_ERROR;
    }
    ptr += written;
    remaining -= written;
    
    written = snprintf(ptr, remaining, 
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n"
        "| Type                 | samples  | avg      | min      | max      | p50      | p90      | p99      |\n"
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    if (written < 0 || written >= remaining) {
        return URMA_ERROR;
    }
    ptr += written;
    remaining -= written;
    
    for (int i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        written = snprintf(ptr, remaining, 
            "| %-20s | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu |\n",
            perf_type_names[i],
            g_perf_ctx->stats.type_record[i].sample_num,
            g_perf_ctx->stats.type_record[i].average,
            g_perf_ctx->stats.type_record[i].mininum,
            g_perf_ctx->stats.type_record[i].maxinum,
            g_perf_ctx->stats.type_record[i].p50,
            g_perf_ctx->stats.type_record[i].p90,
            g_perf_ctx->stats.type_record[i].p99);
        
        if (written < 0 || written >= remaining) {
            return URMA_ERROR;
        }
        
        ptr += written;
        remaining -= written;
    }
    
    written = snprintf(ptr, remaining, 
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    if (written < 0 || written >= remaining) {
        return URMA_ERROR;
    }
    ptr += written;
    remaining -= written;
    
    *length = ptr - perf_buf;
    urma_perf_cleanup();
    return URMA_SUCCESS;
}