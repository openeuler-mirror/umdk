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
#include <stdatomic.h>
#include <time.h>

#include "urma_log.h"
#include "urma_perf.h"
#include "urma_private.h"

#ifdef URMA_PERF_USE_CNTVCT
#ifndef __aarch64__
#error "URMA_PERF_USE_CNTVCT is only supported on AArch64"
#endif

#define URMA_NS_PER_SEC 1000000000ULL
/* Maximum seconds of uptime the mult/shift conversion handles without overflow */
#define URMA_CNTVCT_MAX_SEC 600
/* Width of mult (uint32_t) */
#define URMA_CNTVCT_MULT_BITS 32
/* Divisor for round-to-nearest when computing the mult value */
#define URMA_CNTVCT_ROUND_DIVISOR 2

static inline uint64_t urma_read_cntvct_el0(void)
{
    uint64_t val;
    /*
     * Read CNTVCT_EL0 without isb; Isb serializes the pipeline and costs
     * ~15-20ns, which increases the profiling overhead;
     * Without isb, the measured result may have 10~20ns jitter
     */
    __asm__ __volatile__("mrs %0, cntvct_el0"
                         : "=r" (val)
                         :
                         : "memory");
    return val;
}

static inline uint64_t urma_read_cntfrq_el0(void)
{
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r" (val));
    return val;
}

/*
 * mult/shift use atomic types to guarantee cross-core visibility in
 * high-concurrency scenarios.
 */
static atomic_uint g_cntvct_mult;
static atomic_uint g_cntvct_shift;
static atomic_bool g_cntvct_mult_shift_inited = ATOMIC_VAR_INIT(false);

/*
 * Calculate mult/shift for tick-to-ns conversion, following the same
 * algorithm as the Linux kernel's clocks_calc_mult_shift().
 */
static void urma_cntvct_calc_mult_shift(void)
{
    uint64_t freq = urma_read_cntfrq_el0();
    uint64_t tmp;
    uint32_t sftacc = URMA_CNTVCT_MULT_BITS;
    uint32_t sft;

    if (freq == 0) {
        atomic_store_explicit(&g_cntvct_mult, 0, memory_order_relaxed);
        atomic_store_explicit(&g_cntvct_shift, 0, memory_order_relaxed);
        return;
    }

    /* Determine the maximum safe mult value to avoid overflow */
    tmp = ((uint64_t)URMA_CNTVCT_MAX_SEC * freq) >> URMA_CNTVCT_MULT_BITS;
    while (tmp > 0) {
        tmp >>= 1;
        sftacc--;
    }

    /* Find the best mult/shift pair for the conversion */
    for (sft = URMA_CNTVCT_MULT_BITS; sft > 0; sft--) {
        tmp = (uint64_t)URMA_NS_PER_SEC << sft;
        tmp += freq / URMA_CNTVCT_ROUND_DIVISOR;
        tmp /= freq;
        if ((tmp >> sftacc) == 0)
            break;
    }
    atomic_store_explicit(&g_cntvct_mult, (uint32_t)tmp, memory_order_relaxed);
    atomic_store_explicit(&g_cntvct_shift, sft, memory_order_relaxed);
}


static inline uint64_t urma_cntvct_to_ns(uint64_t cntvct)
{
    uint32_t mult = atomic_load_explicit(&g_cntvct_mult, memory_order_relaxed);
    uint32_t shift = atomic_load_explicit(&g_cntvct_shift, memory_order_relaxed);
    return (cntvct * (uint64_t)mult) >> shift;
}

static inline uint64_t urma_cntvct_avg_to_ns(uint64_t cntvct_sum, uint64_t cnt)
{
    uint32_t mult = atomic_load_explicit(&g_cntvct_mult, memory_order_relaxed);
    uint32_t shift = atomic_load_explicit(&g_cntvct_shift, memory_order_relaxed);

    return (uint64_t)(((__uint128_t)cntvct_sum * mult) >> shift) / cnt;
}

#endif /* URMA_PERF_USE_CNTVCT */

// Control sampling range（1ns ~ 4s）
#define UBCORE_PERF_BUCKET_SHIFT        32
// Control sampling precision（1/2^4）
#define UBCORE_PERF_SUB_BUCKET_SHIFT        1
#define UBCORE_PERF_SUB_BUCKETS  (1 << UBCORE_PERF_SUB_BUCKET_SHIFT)
#define UBCORE_PERF_BUCKETS          (UBCORE_PERF_BUCKET_SHIFT * UBCORE_PERF_SUB_BUCKETS)

typedef struct urma_perf_record {
    struct {
        uint64_t accumulation;
        uint64_t min;
        uint64_t max;
        uint64_t cnt;
        uint64_t bucket[UBCORE_PERF_BUCKETS];
    } type_record[URMA_PERF_RECORD_TYPE_MAX];
    // record context data validity control
    bool is_used;
} urma_perf_record_t;

typedef struct urma_perf_record_ctx {
    urma_perf_record_t record_table[URMA_PERF_THREAD_MAX_NUM];
    // record context thread validity control
    bool thread_initialized[URMA_PERF_THREAD_MAX_NUM];
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

static atomic_bool g_urma_perf_context_inited = ATOMIC_VAR_INIT(false);
static pthread_mutex_t g_urma_perf_init_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool g_urma_perf_record_enable = ATOMIC_VAR_INIT(false);
static urma_perf_record_ctx_t g_urma_perf_record_ctx = {0};
static pthread_spinlock_t g_urma_perf_record_lock;
static pthread_key_t perf_record_clean_key;
static __thread uint32_t g_perf_record_index = URMA_PERF_THREAD_MAX_NUM;
static __thread bool g_thread_initialized = false;

static void urma_perf_reset_record_item(bool reset_all_thread, uint32_t thread_idx)
{
    uint32_t thread_num = reset_all_thread ? URMA_PERF_THREAD_MAX_NUM : 1;
    uint32_t thread_start = reset_all_thread ? 0 : thread_idx;

    (void)pthread_spin_lock(&g_urma_perf_record_lock);
    for (int i = thread_start; i < (thread_start + thread_num); ++i) {
        g_urma_perf_record_ctx.record_table[i].is_used = false;
        for (int j = 0; j < URMA_PERF_RECORD_TYPE_MAX; ++j) {
            g_urma_perf_record_ctx.record_table[i].type_record[j].min = UINT64_MAX;
            g_urma_perf_record_ctx.record_table[i].type_record[j].accumulation = 0;
            g_urma_perf_record_ctx.record_table[i].type_record[j].max = 0;
            g_urma_perf_record_ctx.record_table[i].type_record[j].cnt = 0;
            for (int k = 0; k < UBCORE_PERF_BUCKETS; ++k) {
                g_urma_perf_record_ctx.record_table[i].type_record[j].bucket[k] = 0;
            }
        }
    }
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);
}

static void urma_perf_thread_exit_cleanup(void *arg)
{
    if (g_perf_record_index >= URMA_PERF_THREAD_MAX_NUM) {
        URMA_LOG_ERR("Urma perf thread cleanup, thread index %d is invalid\n", g_perf_record_index);
        return;
    }
    // only reset thread_initialized, not reset is_used
    (void)pthread_spin_lock(&g_urma_perf_record_lock);
    g_urma_perf_record_ctx.thread_initialized[g_perf_record_index] = false;
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);
}

static inline void urma_perf_global_context_init()
{
    (void)pthread_spin_init(&g_urma_perf_record_lock, PTHREAD_PROCESS_PRIVATE);
    (void)pthread_key_create(&perf_record_clean_key, urma_perf_thread_exit_cleanup);
}

static int urma_perf_allocate_record_slot(void)
{
    (void)pthread_spin_lock(&g_urma_perf_record_lock);
    for (int i = 0; i < URMA_PERF_THREAD_MAX_NUM; ++i) {
        if (!g_urma_perf_record_ctx.record_table[i].is_used) {
            g_urma_perf_record_ctx.record_table[i].is_used = true;
            g_urma_perf_record_ctx.thread_initialized[i] = true;
            (void)pthread_spin_unlock(&g_urma_perf_record_lock);
            return i;
        }
    }

    for (int i = 0; i < URMA_PERF_THREAD_MAX_NUM; ++i) {
        if (!g_urma_perf_record_ctx.thread_initialized[i]) {
            g_urma_perf_record_ctx.record_table[i].is_used = true;
            g_urma_perf_record_ctx.thread_initialized[i] = true;
            (void)pthread_spin_unlock(&g_urma_perf_record_lock);
            return i;
        }
    }
    (void)pthread_spin_unlock(&g_urma_perf_record_lock);
    return URMA_PERF_THREAD_MAX_NUM;
}

static void urma_perf_thread_context_init(void)
{
    g_perf_record_index = urma_perf_allocate_record_slot();
    if (g_perf_record_index >= URMA_PERF_THREAD_MAX_NUM) {
        URMA_LOG_ERR("Urma perf thread context init failed, no available thread slot. pid=%d\n", getpid());
        return;
    }

    g_thread_initialized = true;
    // execute when thread exit
    pthread_setspecific(perf_record_clean_key, &g_perf_record_index);
}

static uint64_t bucket_low_bound(uint32_t bucket)
{
    uint32_t exp;
    uint32_t sub;
    uint64_t base;

    if (bucket == 0) {
        return 0;
    }

    exp = bucket >> UBCORE_PERF_SUB_BUCKET_SHIFT;
    sub = bucket & (UBCORE_PERF_SUB_BUCKETS - 1);
    base = 1ULL << exp;

    return base + ((base * sub) >> UBCORE_PERF_SUB_BUCKET_SHIFT);
}

static uint64_t urma_perf_cal_quantile(urma_perf_record_t *record, uint32_t type, uint64_t quantile_count)
{
    uint64_t cur_bucket_sample = 0;
    uint64_t last_bucket_sample = 0;
    uint64_t low;
    uint64_t high;
    uint32_t bucket_idx;

    for (bucket_idx = 0; bucket_idx < UBCORE_PERF_BUCKETS; bucket_idx++) {
        last_bucket_sample = cur_bucket_sample;
        cur_bucket_sample += record->type_record[type].bucket[bucket_idx];
        if (cur_bucket_sample >= quantile_count) {
            break;
        }
    }
    low = bucket_low_bound(bucket_idx);
    high = bucket_low_bound(bucket_idx + 1);

    if (bucket_idx >= UBCORE_PERF_BUCKETS) {
        return bucket_low_bound(UBCORE_PERF_BUCKETS - 1);
    }
    if (record->type_record[type].bucket[bucket_idx] == 0) {
        return low;
    }

    return low + (quantile_count - last_bucket_sample) * (high - low) / record->type_record[type].bucket[bucket_idx];
}

static void urma_perf_fill_type_stats(urma_perf_stats_t *perf_info, urma_perf_record_t *record, uint32_t type)
{
    uint64_t cnt = record->type_record[type].cnt;
#ifdef URMA_PERF_USE_CNTVCT
    uint64_t maxinum = urma_cntvct_to_ns(record->type_record[type].max);
    uint64_t mininum = urma_cntvct_to_ns(record->type_record[type].min);
    uint64_t p90 = urma_cntvct_to_ns(urma_perf_cal_quantile(record, type, (uint64_t)(0.9 * cnt + 0.99)));
    uint64_t p99 = urma_cntvct_to_ns(urma_perf_cal_quantile(record, type, (uint64_t)(0.99 * cnt + 0.999)));
    uint64_t p9999 = urma_cntvct_to_ns(urma_perf_cal_quantile(record, type, (uint64_t)(0.9999 * cnt + 0.99999)));
#else
    uint64_t maxinum = record->type_record[type].max;
    uint64_t mininum = record->type_record[type].min;
    uint64_t p90 = urma_perf_cal_quantile(record, type, (uint64_t)(0.9 * cnt + 0.99));
    uint64_t p99 = urma_perf_cal_quantile(record, type, (uint64_t)(0.99 * cnt + 0.999));
    uint64_t p9999 = urma_perf_cal_quantile(record, type, (uint64_t)(0.9999 * cnt + 0.99999));
#endif

    perf_info->type_record[type].type = type;
    perf_info->type_record[type].sample_num = cnt;
#ifdef URMA_PERF_USE_CNTVCT
    perf_info->type_record[type].average = cnt != 0 ?
        urma_cntvct_avg_to_ns(record->type_record[type].accumulation, cnt) : 0;
#else
    perf_info->type_record[type].average = cnt != 0 ? (record->type_record[type].accumulation / cnt) : 0;
#endif
    perf_info->type_record[type].maxinum = maxinum;
    perf_info->type_record[type].mininum = mininum;
    // Ignore the impact of excessive interpolation errors
    perf_info->type_record[type].p90 = maxinum > p90 ? p90 : maxinum;
    perf_info->type_record[type].p99 = maxinum > p99 ? p99 : maxinum;
    perf_info->type_record[type].p9999 = maxinum > p9999 ? p9999 : maxinum;
}

static void urma_perf_record_agg(urma_perf_record_t *total_perf_record, urma_perf_record_t *perf_record)
{
    for (uint32_t i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        if (perf_record->type_record[i].cnt == 0) {
            continue;
        }
        total_perf_record->type_record[i].accumulation += perf_record->type_record[i].accumulation;
        if (total_perf_record->type_record[i].cnt == 0 ||
            perf_record->type_record[i].min < total_perf_record->type_record[i].min) {
            total_perf_record->type_record[i].min = perf_record->type_record[i].min;
        }
        if (perf_record->type_record[i].max > total_perf_record->type_record[i].max) {
            total_perf_record->type_record[i].max = perf_record->type_record[i].max;
        }
        total_perf_record->type_record[i].cnt += perf_record->type_record[i].cnt;
        for (uint32_t j = 0; j < UBCORE_PERF_BUCKETS; j++) {
            total_perf_record->type_record[i].bucket[j] += perf_record->type_record[i].bucket[j];
        }
    }
}

static void urma_perf_dump_info(urma_perf_stats_t *perf_info)
{
    urma_perf_record_t total_perf_record = {0};

    for (uint32_t i = 0; i < URMA_PERF_THREAD_MAX_NUM; ++i) {
        if (!g_urma_perf_record_ctx.record_table[i].is_used) {
            continue;
        }
        urma_perf_record_agg(&total_perf_record, &g_urma_perf_record_ctx.record_table[i]);
    }

    for (uint32_t i = 0; i < URMA_PERF_RECORD_TYPE_MAX; i++) {
        if (total_perf_record.type_record[i].cnt == 0) {
            continue;
        }
        urma_perf_fill_type_stats(perf_info, &total_perf_record, i);
    }

    perf_info->retry_count = urma_ubagg_switch_get();
}

bool urma_perf_is_enabled()
{
    return atomic_load_explicit(&g_urma_perf_record_enable, memory_order_relaxed);
}

urma_status_t urma_start_perf(void)
{
    atomic_store_explicit(&g_urma_perf_record_enable, false, memory_order_relaxed);
    if (!atomic_load(&g_urma_perf_context_inited)) {
        (void)pthread_mutex_lock(&g_urma_perf_init_lock);
        if (!atomic_load(&g_urma_perf_context_inited)) {
            urma_perf_global_context_init();
            atomic_store(&g_urma_perf_context_inited, true);
        }
        (void)pthread_mutex_unlock(&g_urma_perf_init_lock);
    }
#ifdef URMA_PERF_USE_CNTVCT
    if (!atomic_load_explicit(&g_cntvct_mult_shift_inited, memory_order_acquire)) {
        urma_cntvct_calc_mult_shift();
        atomic_store_explicit(&g_cntvct_mult_shift_inited, true, memory_order_release);
    }
#endif
    // reset context
    urma_perf_reset_record_item(true, 0);
    atomic_store_explicit(&g_urma_perf_record_enable, true, memory_order_relaxed);
    return URMA_SUCCESS;
}

urma_status_t urma_stop_perf(void)
{
    atomic_store_explicit(&g_urma_perf_record_enable, false, memory_order_relaxed);
    return URMA_SUCCESS;
}

uint64_t urma_get_perf_timestamp(void)
{
#ifdef URMA_PERF_USE_CNTVCT
    /*
     * Return raw CNTVCT ticks directly. The tick-to-ns conversion is
     * deferred to urma_step_perf() where it is done once per measurement
     * (on the delta), instead of twice per measurement (on each timestamp).
     */
    if (urma_perf_is_enabled()) {
        if (g_perf_record_index == URMA_PERF_THREAD_MAX_NUM) {
            urma_perf_thread_context_init();
        } else {
            g_urma_perf_record_ctx.record_table[g_perf_record_index].is_used = true;
        }
    }

    return urma_read_cntvct_el0();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    if (urma_perf_is_enabled()) {
        if (g_perf_record_index == URMA_PERF_THREAD_MAX_NUM) {
            urma_perf_thread_context_init();
        } else {
            g_urma_perf_record_ctx.record_table[g_perf_record_index].is_used = true;
        }
    }

    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

#define MAX_BIT_POS 63
static uint32_t urma_perf_get_bucket_idx(uint64_t latency)
{
    uint32_t latency_idx;
    uint32_t sub_bucket_idx;
    uint32_t bucket_base_idx;
    uint32_t bucket_shift;
    uint64_t latency_offset;

    if (latency == 0) {
        return 0;
    }
    bucket_shift = (uint32_t)(MAX_BIT_POS - __builtin_clzll(latency));
    bucket_base_idx = bucket_shift * UBCORE_PERF_SUB_BUCKETS;
    latency_offset = latency - (1ULL << bucket_shift);
    if (bucket_base_idx >= UBCORE_PERF_BUCKETS) {
        return UBCORE_PERF_BUCKETS - 1;
    }
    if (bucket_shift >= UBCORE_PERF_SUB_BUCKET_SHIFT) {
        sub_bucket_idx = (uint32_t)(latency_offset >> (bucket_shift - UBCORE_PERF_SUB_BUCKET_SHIFT));
    } else {
        sub_bucket_idx = (uint32_t)(latency_offset << (UBCORE_PERF_SUB_BUCKET_SHIFT - bucket_shift));
    }
    sub_bucket_idx &= (UBCORE_PERF_SUB_BUCKETS - 1);
    latency_idx = bucket_base_idx + sub_bucket_idx;

    return (latency_idx >= UBCORE_PERF_BUCKETS) ? (UBCORE_PERF_BUCKETS - 1) : latency_idx;
}

urma_status_t urma_step_perf(urma_perf_record_type_t type, uint64_t delta)
{
    uint32_t bucket_idx;
    urma_perf_record_t *cur_record;

    if ((!urma_perf_is_enabled()) || (g_perf_record_index >= URMA_PERF_THREAD_MAX_NUM)) {
        return URMA_ENOPERM;
    }
    if (type >= URMA_PERF_RECORD_TYPE_MAX) {
        URMA_LOG_ERR("Urma perf step invalid param\n");
        return URMA_EINVAL;
    }
    if (delta == 0) {
        return URMA_SUCCESS;
    }

    cur_record = &g_urma_perf_record_ctx.record_table[g_perf_record_index];
    bucket_idx = urma_perf_get_bucket_idx(delta);

    cur_record->type_record[type].bucket[bucket_idx]++;
    cur_record->type_record[type].cnt++;
    cur_record->type_record[type].accumulation += delta;
    cur_record->type_record[type].min = (delta < cur_record->type_record[type].min) ?
                                         delta : cur_record->type_record[type].min;
    cur_record->type_record[type].max = (delta > cur_record->type_record[type].max) ?
                                         delta : cur_record->type_record[type].max;
    return URMA_SUCCESS;
}

urma_status_t urma_get_perf_info(char *perf_buf, uint32_t *length)
{
    urma_perf_stats_t perf_info = {0};
    char temp_buf[16384] = {0};
    int buffer_used = 0;

    if (perf_buf == NULL || length == NULL) {
        URMA_LOG_ERR("Urma perf info get failed, perf_buf or length is invalid\n");
        return URMA_EINVAL;
    }

    urma_perf_dump_info(&perf_info);

    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "  retry_count: %-20lu\n", perf_info.retry_count);
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "  Type                 | samples  | avg[ns]  | min[ns]  | max[ns]  | p90[ns]  | p99[ns]  | p9999[ns]\n");
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
            perf_info.type_record[i].p90,
            perf_info.type_record[i].p99,
            perf_info.type_record[i].p9999);
    }
    buffer_used += snprintf(temp_buf + buffer_used, sizeof(temp_buf) - buffer_used,
        "+----------------------+----------+----------+----------+----------+----------+----------+----------+\n");
    if (*length < (uint32_t)buffer_used + 1) {
        URMA_LOG_ERR("Urma perf get info failed, need %d bytes buffer, but only %u provided\n",
            buffer_used + 1, *length);
        return URMA_EINVAL;
    }
    (void)memcpy(perf_buf, temp_buf, (size_t)(buffer_used + 1));
    *length = buffer_used + 1;
    return URMA_SUCCESS;
}
