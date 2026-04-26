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
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "urma_log.h"
#include "ub_get_clock.h"
#include "urma_perf.h"
#include "urma_private.h"

typedef struct urma_perf_record {
    struct {
        uint64_t accumulation;
        uint64_t min;
        uint64_t max;
        uint64_t cnt;
        uint64_t bucket[URMA_PERF_BUCKET_MAX_NUM + 1];
    } type_record[URMA_PERF_RECORD_TYPE_MAX];
    // record context data validity control
    bool is_used;
} urma_perf_record_t;

typedef struct urma_perf_record_ctx {
    urma_perf_record_t record_table[URMA_PERF_THREAD_MAX_NUM];
    // record context thread validity control
    pthread_once_t *thread_run_once[URMA_PERF_THREAD_MAX_NUM];
    uint64_t thresh_cycle[URMA_PERF_BUCKET_MAX_NUM];
    uint64_t thresh_ns[URMA_PERF_BUCKET_MAX_NUM];
    uint32_t thresh_num;
} urma_perf_record_ctx_t;

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

#define MHZ_TO_HZ 1000000UL
#define NS_PER_SEC 1000000000UL

static uint64_t g_cpu_hz = 0;
static bool g_urma_perf_record_enable = false;
static urma_perf_record_ctx_t g_urma_perf_record_ctx = {0};
static pthread_spinlock_t g_urma_perf_record_lock;

static pthread_key_t perf_record_clean_key;
static pthread_once_t g_perf_start_once = PTHREAD_ONCE_INIT;
static pthread_once_t g_perf_stop_once = PTHREAD_ONCE_INIT;
static __thread uint32_t g_perf_record_index = UINT32_MAX;
static __thread pthread_once_t g_thread_run_once = PTHREAD_ONCE_INIT;

static inline uint64_t get_cpu_hz_cached(void)
{
    if (g_cpu_hz == 0) {
        g_cpu_hz = get_cpu_mhz(false) * MHZ_TO_HZ;
    }
    return g_cpu_hz;
}

static inline uint64_t ns_to_cycles(uint64_t ns)
{
    return ns * get_cpu_hz_cached() / NS_PER_SEC;
}

static inline uint64_t cycles_to_ns(uint64_t cycles)
{
    if ((cycles != 0) && (UINT64_MAX / cycles <= NS_PER_SEC)) {
        return cycles / get_cpu_hz_cached() * NS_PER_SEC;
    } else {
        return cycles * NS_PER_SEC / get_cpu_hz_cached();
    }
}

static void urma_perf_reset_record_item(bool reset_all_thread, uint32_t thread_idx) {
    uint32_t thread_num = reset_all_thread ? URMA_PERF_THREAD_MAX_NUM : 1;
    uint32_t thread_start = reset_all_thread ? 0 : thread_idx;
    
    for (int i = thread_start; i < (thread_start + thread_num); ++i) {
        g_urma_perf_record_ctx.record_table[i].is_used = false;
        for (int j = 0; j < URMA_PERF_RECORD_TYPE_MAX; ++j) {
            g_urma_perf_record_ctx.record_table[i].type_record[j].min = UINT64_MAX;
            g_urma_perf_record_ctx.record_table[i].type_record[j].accumulation = 0;
            g_urma_perf_record_ctx.record_table[i].type_record[j].max = 0;
            g_urma_perf_record_ctx.record_table[i].type_record[j].cnt = 0;
            for (int k = 0; k < URMA_PERF_BUCKET_MAX_NUM + 1; ++k) {
                g_urma_perf_record_ctx.record_table[i].type_record[j].bucket[k] = 0;
            }
        }
    }
}

static void urma_perf_reset_record_context() {
    const uint64_t context_threshold[URMA_PERF_BUCKET_MAX_NUM] = {
        20, 30, 40, 50, 60, 70, 80, 90, 100,
        150, 200, 250, 300, 350, 400, 450, 500, 600, 650, 700, 750, 800, 850, 900, 950, 1000,
        2000, 3000, 4000, 8000, 16000, 32000};

    g_urma_perf_record_ctx.thresh_num = URMA_PERF_BUCKET_MAX_NUM;
    for (int i = 0; i < URMA_PERF_BUCKET_MAX_NUM; ++i) {
        g_urma_perf_record_ctx.thresh_ns[i] = context_threshold[i];
        g_urma_perf_record_ctx.thresh_cycle[i] = ns_to_cycles(context_threshold[i]);
    }
    urma_perf_reset_record_item(true, 0);
}

static void urma_perf_global_context_init()
{
    (void)pthread_spin_init(&g_urma_perf_record_lock, PTHREAD_PROCESS_PRIVATE);
}
static void urma_perf_global_context_uninit()
{
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);
    (void)pthread_spin_destroy(&g_urma_perf_record_lock);
}

static void urma_perf_thread_exit_cleanup(void *arg)
{
    if (g_perf_record_index >= URMA_PERF_THREAD_MAX_NUM) {
        URMA_LOG_ERR("Urma perf thread cleanup, thread index %d is invalid.\n", g_perf_record_index);
        return;
    }
    // only reset thread_run_once, not reset is_used
    g_urma_perf_record_ctx.thread_run_once[g_perf_record_index] = NULL;
}
static int urma_perf_allocate_record_slot(void)
{
    int thread_idx;

    for (thread_idx = 0; thread_idx < URMA_PERF_THREAD_MAX_NUM; ++thread_idx) {
        if (!g_urma_perf_record_ctx.record_table[thread_idx].is_used) {
            return thread_idx;
        }
    }
    // reuse the thread index from a thread that has already exited
    for (int i = 0; i < URMA_PERF_THREAD_MAX_NUM; ++i) {
        if (g_urma_perf_record_ctx.thread_run_once[i] == NULL) {
            g_urma_perf_record_ctx.record_table[i].is_used = false;
        }
        if (thread_idx == URMA_PERF_THREAD_MAX_NUM) {
            thread_idx = i;
        }
    }
    return thread_idx;
}

static void urma_perf_thread_context_init(void)
{
    uint32_t thread_idx;

    (void)pthread_spin_lock(&g_urma_perf_record_lock);
    thread_idx = urma_perf_allocate_record_slot();
    if (thread_idx == URMA_PERF_THREAD_MAX_NUM) {
        (void)pthread_spin_unlock(&g_urma_perf_record_lock);
        return;
    }
    urma_perf_reset_record_item(false, thread_idx);
    g_perf_record_index = thread_idx;
    g_urma_perf_record_ctx.thread_run_once[thread_idx] = &g_thread_run_once;

    // execute when thread exit
    pthread_key_create(&perf_record_clean_key, urma_perf_thread_exit_cleanup);
    pthread_setspecific(perf_record_clean_key, &g_perf_record_index);
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);
}

static uint64_t urma_perf_cal_quantile(urma_perf_record_t *record, urma_perf_record_type_t type,
    uint64_t quantile_count)
{
    uint32_t bucket_idx = 0;
    uint64_t base;
    uint64_t cur_count = quantile_count;
    uint64_t *thresh_arr = g_urma_perf_record_ctx.thresh_ns;
    uint32_t thresh_num = g_urma_perf_record_ctx.thresh_num;
    uint64_t p90 = 0;

    if ((thresh_num == 0) || (thresh_arr == NULL)) {
        return 0;
    }

    for (bucket_idx = 0; bucket_idx < thresh_num; ++bucket_idx) {
        if (record->type_record[type].bucket[bucket_idx] >= cur_count) {
            break;
        }
        cur_count -= record->type_record[type].bucket[bucket_idx];
    }
    // correct the discrepancy in extreme edge cases
    if (bucket_idx >= thresh_num) {
        return thresh_arr[thresh_num - 1];
    }
    base = (bucket_idx == 0) ? 0 : thresh_arr[bucket_idx - 1];
    p90 = ((double)cur_count / record->type_record[type].bucket[bucket_idx]) * (thresh_arr[bucket_idx] - base) + base;
    if (p90 > record->type_record[type].max) {
        p90 = record->type_record[type].max;
    }
    return p90;
}

static void urma_perf_record_merge(urma_perf_record_t *total_perf_record, urma_perf_record_t *perf_record)
{
    for (uint32_t i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        if (perf_record->type_record[i].cnt == 0) {
            continue;
        }
        total_perf_record->type_record[i].accumulation += perf_record->type_record[i].accumulation;
        total_perf_record->type_record[i].min =
            (total_perf_record->type_record[i].min != 0 &&
            total_perf_record->type_record[i].min < perf_record->type_record[i].min) ?
            total_perf_record->type_record[i].min : perf_record->type_record[i].min;
        total_perf_record->type_record[i].max =
            total_perf_record->type_record[i].max > perf_record->type_record[i].max ?
            total_perf_record->type_record[i].max : perf_record->type_record[i].max;
        total_perf_record->type_record[i].cnt += perf_record->type_record[i].cnt;
        for (uint32_t j = 0; j <= URMA_PERF_BUCKET_MAX_NUM; j++) {
            total_perf_record->type_record[i].bucket[j] += perf_record->type_record[i].bucket[j];
        }
    }
}

static void urma_perf_convert_cycles_to_ns(urma_perf_record_t *perf_record)
{
    for (uint32_t i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        perf_record->type_record[i].accumulation = cycles_to_ns(perf_record->type_record[i].accumulation);
        perf_record->type_record[i].min =
            perf_record->type_record[i].min == UINT64_MAX ? 0 : cycles_to_ns(perf_record->type_record[i].min);
        perf_record->type_record[i].max = cycles_to_ns(perf_record->type_record[i].max);
    }
}
static int urma_perf_info_get_internal(urma_perf_stats_t *perf_info)
{
    urma_perf_record_t total_perf_record = {0};

    for (uint32_t i = 0; i < URMA_PERF_THREAD_MAX_NUM; ++i) {
        if (!g_urma_perf_record_ctx.record_table[i].is_used) {
            continue;
        }
        urma_perf_record_merge(&total_perf_record, &g_urma_perf_record_ctx.record_table[i]);
    }
    urma_perf_convert_cycles_to_ns(&total_perf_record);

    for (uint32_t i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        perf_info->type_record[i].type = (urma_perf_record_type_t)i;
        perf_info->type_record[i].sample_num = total_perf_record.type_record[i].cnt;
        perf_info->type_record[i].average = total_perf_record.type_record[i].cnt != 0 ?
            (total_perf_record.type_record[i].accumulation / total_perf_record.type_record[i].cnt) : 0;
        perf_info->type_record[i].maxinum = total_perf_record.type_record[i].max;
        perf_info->type_record[i].mininum = total_perf_record.type_record[i].min;
        perf_info->type_record[i].p50 = urma_perf_cal_quantile(&total_perf_record, i,
            (uint64_t)(0.5 * total_perf_record.type_record[i].cnt));
        perf_info->type_record[i].p90 = urma_perf_cal_quantile(&total_perf_record, i,
            (uint64_t)(0.9 * total_perf_record.type_record[i].cnt));
        perf_info->type_record[i].p99 = urma_perf_cal_quantile(&total_perf_record, i,
            (uint64_t)(0.99 * total_perf_record.type_record[i].cnt));
    }
    perf_info->retry_count = urma_ubagg_switch_get();

    return 0;
}

bool urma_perf_is_enabled()
{
    return g_urma_perf_record_enable;
}

urma_status_t urma_start_perf(void)
{
    // singleton
    if (pthread_once(&g_perf_start_once, urma_perf_global_context_init) != 0) {
        URMA_LOG_ERR("Urma perf failed to initialize performance record context\n");
        return URMA_FAIL;
    }
    // reset context
    urma_perf_reset_record_context();
    g_urma_perf_record_enable = true;
    return URMA_SUCCESS;
}

urma_status_t urma_stop_perf(void)
{
    if (pthread_once(&g_perf_stop_once, urma_perf_global_context_uninit) != 0) {
        URMA_LOG_ERR("Urma perf failed to uninitialize performance record context\n");
        return URMA_FAIL;
    }
    g_urma_perf_record_enable = false;
    return URMA_SUCCESS;
}
uint64_t urma_get_perf_timestamp(void)
{
    if (urma_perf_is_enabled()) {
        pthread_once(&g_thread_run_once, urma_perf_thread_context_init);
        g_urma_perf_record_ctx.record_table[g_perf_record_index].is_used = true;
    }
    return get_cycles();
}

urma_status_t urma_config_perf_attr(urma_perf_attr_t *perf_attr)
{
    uint32_t thresh_num;
    uint64_t *thresh_array;
    uint32_t bucket_idx = 0;

    if (!urma_perf_is_enabled()) {
        URMA_LOG_ERR("Urma perf config failed. perf record is not started. \n");
        return URMA_ENOPERM;
    }
    if ((perf_attr == NULL) || perf_attr->thresh_num > URMA_PERF_BUCKET_MAX_NUM) {
        URMA_LOG_ERR("Urma perf config failed. perf_attr is invalid. \n");
        return URMA_EINVAL;
    }
    thresh_num = perf_attr->thresh_num;
    thresh_array = perf_attr->thresh_array;

    (void)pthread_spin_lock(&g_urma_perf_record_lock);
    // reset global record context
    for (int i = 0; i < URMA_PERF_BUCKET_MAX_NUM; ++i) {
        g_urma_perf_record_ctx.thresh_ns[i] = 0;
        g_urma_perf_record_ctx.thresh_cycle[i] = 0;
    }
    urma_perf_reset_record_item(true, 0);
    // set thresh
    for (uint32_t i = 0; i < thresh_num; ++i) {
        if ((thresh_array[i] > URMA_PERF_MAX_THRESH_NS) || (thresh_array[i] == 0)) {
            URMA_LOG_WARN("Urma perf config failed. thresh: %lu is invalid.\n", thresh_array[i]);
            continue;
        }
        if ((bucket_idx == 0) || (thresh_array[i] > g_urma_perf_record_ctx.thresh_ns[bucket_idx - 1])) {
            g_urma_perf_record_ctx.thresh_ns[bucket_idx] = thresh_array[i];
            g_urma_perf_record_ctx.thresh_cycle[bucket_idx] = ns_to_cycles(thresh_array[i]);
            bucket_idx++;
        }
    }
    g_urma_perf_record_ctx.thresh_num = bucket_idx;
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);
    return URMA_SUCCESS;
}

urma_status_t urma_step_perf(urma_perf_record_type_t type, uint64_t delta)
{
    uint32_t bucket_idx;
    urma_perf_record_t *cur_record = &g_urma_perf_record_ctx.record_table[g_perf_record_index];

    if (!urma_perf_is_enabled()){
        return URMA_ENOPERM;
    }
    if (type >= URMA_PERF_RECORD_TYPE_MAX) {
        URMA_LOG_ERR("Urma perf type %d is invalid. \n", type);
        return URMA_EINVAL;
    }
    if (delta < g_urma_perf_record_ctx.thresh_cycle[0]) {
        URMA_LOG_WARN("Urma perf type %d delta is %lu, less than threshold %lu.\n",
            type, delta, g_urma_perf_record_ctx.thresh_cycle[0]);
        return URMA_EINVAL;
    }

    for (bucket_idx = 0; bucket_idx < URMA_PERF_BUCKET_MAX_NUM; ++bucket_idx) {
        if (delta <= g_urma_perf_record_ctx.thresh_cycle[bucket_idx]) {
            break;
        }
    }
    cur_record->type_record[type].bucket[bucket_idx]++;
    cur_record->type_record[type].cnt++;
    cur_record->type_record[type].accumulation += delta;
    cur_record->type_record[type].min = (delta < cur_record->type_record[type].min) ? delta : cur_record->type_record[type].min;
    cur_record->type_record[type].max = (delta > cur_record->type_record[type].max) ? delta : cur_record->type_record[type].max;
    return URMA_SUCCESS;
}

urma_status_t urma_get_perf_info(char *perf_buf, uint32_t *length)
{
    urma_perf_stats_t perf_info = {0};
    char temp_buf[8192];
    int buffer_used = 0;
    int ret;

    if (perf_buf == NULL || length == NULL) {
        URMA_LOG_ERR("Urma perf info get failed, perf_buf or length is invalid\n");
        return URMA_EINVAL;
    }

    (void)pthread_spin_lock(&g_urma_perf_record_lock);
    ret = urma_perf_info_get_internal(&perf_info);
    if (ret != URMA_SUCCESS) {
        (void)pthread_spin_unlock(&g_urma_perf_record_lock);
        return ret;
    }
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "  retry_count: %-20lu\n", perf_info.retry_count);
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "  Type                 | samples  | avg      | min      | max      | p50      | p90      | p99       \n");
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    for (uint32_t i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        if (perf_info.type_record[i].sample_num == 0) {
            continue;
        }
        buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
            "  %-20s | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu  \n",
            perf_type_names[i],
            perf_info.type_record[i].sample_num,
            perf_info.type_record[i].average,
            perf_info.type_record[i].mininum,
            perf_info.type_record[i].maxinum,
            perf_info.type_record[i].p50,
            perf_info.type_record[i].p90,
            perf_info.type_record[i].p99);
    }
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);

    if (*length < (uint32_t)buffer_used + 1) {
        URMA_LOG_ERR("Urma perf get info failed, need %d bytes buffer, but only %u provided\n",
            buffer_used + 1, *length);
        return URMA_EINVAL;
    }
    (void)memcpy(perf_buf, temp_buf, (size_t)(buffer_used + 1));
    *length = buffer_used + 1;
    return URMA_SUCCESS;
}