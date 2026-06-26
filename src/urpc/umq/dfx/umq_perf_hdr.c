/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq perf hdr histogram
 * Create: 2026-06-24
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "umq_perf_hdr.h"

/* map a value to its counts-array index (O(1), branch-light hot path) */
static inline uint32_t umq_perf_hdr_counts_index(const umq_perf_hdr_t *h, uint64_t v)
{
    if (v < h->sub_bucket_half_count) {
        return (uint32_t)v;
    }
    if (v >= h->highest_trackable) {
        return h->counts_array_size - 1;
    }
    int bit_len = (int)(sizeof(uint64_t) * CHAR_BIT) - __builtin_clzll(v);
    int bucket_index = bit_len - (int)(h->sub_bucket_half_mag) - 1;
    uint32_t sub_index = (uint32_t)(v >> bucket_index);
    return (uint32_t)bucket_index * h->sub_bucket_half_count + sub_index;
}

/* recover the lower-bound value represented by a counts-array index */
static inline uint64_t umq_perf_hdr_value_from_index(const umq_perf_hdr_t *h, uint32_t index)
{
    if (index < h->sub_bucket_count) {
        return (uint64_t)index;
    }
    int bucket_index = (int)(index >> h->sub_bucket_half_mag) - 1;
    int sub_index = (int)(index & (h->sub_bucket_half_count - 1)) + (int)h->sub_bucket_half_count;
    return ((uint64_t)sub_index) << bucket_index;
}

umq_perf_hdr_t *umq_perf_hdr_create(uint64_t max_value)
{
    if (max_value == 0) {
        return NULL;
    }
    /* sig_figures -> sub_bucket_half_mag: ceil(sig * log2(10)) without libm */
    int sf = UMQ_PERF_HDR_DEFAULT_SIG_FIGURES;
    uint32_t sub_bucket_half_mag = (uint32_t)
        ((sf * UMQ_PERF_HDR_LOG2_10_NUM + UMQ_PERF_HDR_LOG2_10_CEIL_BIAS) / UMQ_PERF_HDR_LOG2_10_DEN);
    uint32_t sub_bucket_half_count = 1u << sub_bucket_half_mag;
    uint32_t sub_bucket_count = sub_bucket_half_count * 2u;
    int bit_len = (int)(sizeof(uint64_t) * CHAR_BIT) - __builtin_clzll(max_value);
    int bucket_count = bit_len - (int)sub_bucket_half_mag - 1;
    if (bucket_count < 0) {
        bucket_count = 0;
    }
    uint32_t counts_array_size = sub_bucket_count + (uint32_t)bucket_count * sub_bucket_half_count;

    umq_perf_hdr_t *h = (umq_perf_hdr_t *)calloc(1, sizeof(umq_perf_hdr_t) + counts_array_size * sizeof(uint64_t));
    if (h == NULL) {
        return NULL;
    }
    h->sub_bucket_half_mag = sub_bucket_half_mag;
    h->sub_bucket_half_count = sub_bucket_half_count;
    h->sub_bucket_count = sub_bucket_count;
    h->bucket_count = (uint32_t)bucket_count;
    h->counts_array_size = counts_array_size;
    h->highest_trackable = (uint64_t)sub_bucket_count << bucket_count;
    h->min_value = UINT64_MAX;
    return h;
}

void umq_perf_hdr_destroy(umq_perf_hdr_t *h)
{
    free(h);
}

void umq_perf_hdr_reset(umq_perf_hdr_t *h)
{
    if (h == NULL) {
        return;
    }
    memset(h->counts, 0, h->counts_array_size * sizeof(uint64_t));
    h->total_count = 0;
    h->min_value = UINT64_MAX;
    h->max_value = 0;
    h->sum = 0;
}

void umq_perf_hdr_record(umq_perf_hdr_t *h, uint64_t value)
{
    if (h == NULL) {
        return;
    }
    uint32_t idx = umq_perf_hdr_counts_index(h, value);
    h->counts[idx]++;
    h->total_count++;
    h->sum += value;
    if (value < h->min_value) {
        h->min_value = value;
    }
    if (value > h->max_value) {
        h->max_value = value;
    }
}

uint64_t umq_perf_hdr_value_at_quantile(const umq_perf_hdr_t *h, double percentile)
{
    /* !(percentile > 0.0) also rejects NaN (NaN > 0.0 is false), avoiding UB in
     * the later (uint64_t)target cast; no <math.h> needed. */
    if (h == NULL || h->total_count == 0 || !(percentile > 0.0)) {
        return 0;
    }
    if (percentile >= UMQ_PERF_HDR_MAX_PERCENTILE) {
        return h->max_value;
    }
    /* ceil((percentile/100) * total_count) without libm */
    double target = (percentile / UMQ_PERF_HDR_MAX_PERCENTILE) * (double)h->total_count;
    uint64_t need = (uint64_t)target;
    if ((double)need < target) {
        need++;
    }
    if (need < 1) {
        need = 1;
    }
    if (need > h->total_count) {
        need = h->total_count;
    }
    uint64_t cumulative = 0;
    for (uint32_t i = 0; i < h->counts_array_size; i++) {
        cumulative += h->counts[i];
        if (cumulative >= need) {
            return umq_perf_hdr_value_from_index(h, i);
        }
    }
    return h->max_value;
}

void umq_perf_hdr_merge(umq_perf_hdr_t *dst, const umq_perf_hdr_t *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }
    uint32_t n = dst->counts_array_size < src->counts_array_size ? dst->counts_array_size : src->counts_array_size;
    for (uint32_t i = 0; i < n; i++) {
        dst->counts[i] += src->counts[i];
    }
    dst->total_count += src->total_count;
    dst->sum += src->sum;
    if (src->min_value < dst->min_value) {
        dst->min_value = src->min_value;
    }
    if (src->max_value > dst->max_value) {
        dst->max_value = src->max_value;
    }
}

size_t umq_perf_hdr_counts_size(const umq_perf_hdr_t *h)
{
    if (h == NULL) {
        return 0;
    }
    return (size_t)h->counts_array_size;
}
