/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq perf hdr histogram
 * Create: 2026-06-24
 */

#ifndef UMQ_PERF_HDR_H
#define UMQ_PERF_HDR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UMQ_PERF_HDR_MAX_PERCENTILE      (100.0)
#define UMQ_PERF_HDR_DEFAULT_SIG_FIGURES (2)
#define UMQ_PERF_HDR_DEFAULT_MAX_MS      (1000)
/* ceil(sig * log2(10)) ≈ (sig * 10 + 2) / 3, without libm */
#define UMQ_PERF_HDR_LOG2_10_NUM         (10)
#define UMQ_PERF_HDR_LOG2_10_CEIL_BIAS   (2)
#define UMQ_PERF_HDR_LOG2_10_DEN         (3)

typedef struct umq_perf_hdr {
    uint64_t total_count;
    uint64_t min_value;
    uint64_t max_value;
    uint64_t sum;
    /* layout parameters (computed from sig_figures and max_value) */
    uint32_t sub_bucket_half_mag;
    uint32_t sub_bucket_half_count;
    uint32_t sub_bucket_count;
    uint32_t bucket_count;
    uint32_t counts_array_size;
    uint64_t highest_trackable;
    uint64_t counts[0];
} umq_perf_hdr_t;

/* sig_figures is hardcoded to 2 (~0.78% relative error).
 * max_value: highest trackable value in the same unit as record values.
 * Returns NULL on invalid params or OOM. */
umq_perf_hdr_t *umq_perf_hdr_create(uint64_t max_value);
void umq_perf_hdr_destroy(umq_perf_hdr_t *h);
void umq_perf_hdr_reset(umq_perf_hdr_t *h);
void umq_perf_hdr_record(umq_perf_hdr_t *h, uint64_t value);
uint64_t umq_perf_hdr_value_at_quantile(const umq_perf_hdr_t *h, double percentile);
void umq_perf_hdr_merge(umq_perf_hdr_t *dst, const umq_perf_hdr_t *src);
size_t umq_perf_hdr_counts_size(const umq_perf_hdr_t *h);

#ifdef __cplusplus
}
#endif

#endif
