/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq perf hdr histogram test
 * Create: 2026-06-24
 */

#include <gtest/gtest.h>
#include <vector>
#include <thread>
#include <cstdint>

#include "umq_perf_hdr.h"

#define TEST_MAX_VALUE     (2000000000ULL) // ~1s at 2GHz

class HdrTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// basic create / record / min / max / sum
TEST_F(HdrTest, CreateRecordBasic)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(h->total_count, 0u);

    umq_perf_hdr_record(h, 100);
    umq_perf_hdr_record(h, 200);
    umq_perf_hdr_record(h, 300);
    EXPECT_EQ(h->total_count, 3u);
    EXPECT_EQ(h->min_value, 100u);
    EXPECT_EQ(h->max_value, 300u);
    EXPECT_EQ(h->sum, 600u);
    umq_perf_hdr_destroy(h);
}

// empty histogram quantile returns 0
TEST_F(HdrTest, EmptyQuantileZero)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    EXPECT_EQ(umq_perf_hdr_value_at_quantile(h, 50.0), 0u);
    EXPECT_EQ(umq_perf_hdr_value_at_quantile(h, 99.0), 0u);
    EXPECT_EQ(umq_perf_hdr_value_at_quantile(h, 99.99), 0u);
    umq_perf_hdr_destroy(h);
}

// null pointers must not crash
TEST_F(HdrTest, NullSafe)
{
    umq_perf_hdr_destroy(nullptr);
    umq_perf_hdr_reset(nullptr);
    umq_perf_hdr_record(nullptr, 100);
    EXPECT_EQ(umq_perf_hdr_value_at_quantile(nullptr, 50.0), 0u);
    umq_perf_hdr_merge(nullptr, nullptr);
}

// reset clears all state
TEST_F(HdrTest, ResetClears)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    umq_perf_hdr_record(h, 100);
    umq_perf_hdr_record(h, 200);
    umq_perf_hdr_reset(h);
    EXPECT_EQ(h->total_count, 0u);
    EXPECT_EQ(umq_perf_hdr_value_at_quantile(h, 50.0), 0u);

    umq_perf_hdr_record(h, 50);
    EXPECT_EQ(h->total_count, 1u);
    EXPECT_EQ(h->min_value, 50u);
    EXPECT_EQ(h->max_value, 50u);
    umq_perf_hdr_destroy(h);
}

// boundary values map to valid indices without corruption
TEST_F(HdrTest, BoundaryValuesRecorded)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    uint64_t ht = h->highest_trackable;
    std::vector<uint64_t> vals = {0, 1, 127, 128, 255, 256, 511, 512, 1023, 1024, 4095, 4096,
                                  65535, 65536, 1000000, ht - 1, ht, ht + 1000, ht * 4};
    // clamp ht*4 to avoid uint64 overflow in test data
    if (vals.back() < ht) {
        vals.back() = ht;
    }
    for (uint64_t v : vals) {
        umq_perf_hdr_record(h, v);
    }
    EXPECT_EQ(h->total_count, vals.size());
    EXPECT_EQ(h->max_value, ht * 4 > ht ? ht * 4 : ht);
    // p100 returns the real max
    EXPECT_EQ(umq_perf_hdr_value_at_quantile(h, 100.0), h->max_value);
    umq_perf_hdr_destroy(h);
}

// out-of-range values are clamped into the last bucket
TEST_F(HdrTest, ClampOutOfRange)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    uint64_t ht = h->highest_trackable;
    umq_perf_hdr_record(h, ht * 2);
    umq_perf_hdr_record(h, ht * 3);
    EXPECT_EQ(h->total_count, 2u);
    uint64_t q = umq_perf_hdr_value_at_quantile(h, 50.0);
    EXPECT_GT(q, 0u);
    umq_perf_hdr_destroy(h);
}

// precision: uniform 1..N, each quantile within 1% of nearest-rank
TEST_F(HdrTest, PrecisionWithinOnePercent)
{
    const uint64_t N = 10000;
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    for (uint64_t v = 1; v <= N; v++) {
        umq_perf_hdr_record(h, v);
    }
    double pcts[] = {50.0, 90.0, 99.0, 99.99};
    for (double pct : pcts) {
        double target = (pct / 100.0) * (double)N;
        uint64_t expected = (uint64_t)target;
        if ((double)expected < target) {
            expected++;
        }
        if (expected < 1) {
            expected = 1;
        }
        if (expected > N) {
            expected = N;
        }
        uint64_t got = umq_perf_hdr_value_at_quantile(h, pct);
        int64_t diff = (int64_t)got - (int64_t)expected;
        if (diff < 0) {
            diff = -diff;
        }
        double rel = (double)diff / (double)expected;
        EXPECT_LT(rel, 0.01) << "pct=" << pct << " got=" << got << " exp=" << expected;
    }
    umq_perf_hdr_destroy(h);
}

// monotonicity: p50 <= p90 <= p99 <= p9999 <= max
TEST_F(HdrTest, QuantileMonotonic)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    for (uint64_t v = 1; v <= 5000; v++) {
        umq_perf_hdr_record(h, v * 3);
    }
    uint64_t p50 = umq_perf_hdr_value_at_quantile(h, 50.0);
    uint64_t p90 = umq_perf_hdr_value_at_quantile(h, 90.0);
    uint64_t p99 = umq_perf_hdr_value_at_quantile(h, 99.0);
    uint64_t p9999 = umq_perf_hdr_value_at_quantile(h, 99.99);
    EXPECT_LE(p50, p90);
    EXPECT_LE(p90, p99);
    EXPECT_LE(p99, p9999);
    EXPECT_LE(p9999, h->max_value);
    umq_perf_hdr_destroy(h);
}

// memory budget: counts array <= 25KB for default config (sig=2, max=1s@2GHz)
TEST_F(HdrTest, MemoryBudget)
{
    umq_perf_hdr_t *h = umq_perf_hdr_create(TEST_MAX_VALUE);
    ASSERT_NE(h, nullptr);
    size_t buckets = umq_perf_hdr_counts_size(h);
    size_t counts_bytes = buckets * sizeof(uint64_t);
    EXPECT_LE(counts_bytes, 25600u); // 25KB
    EXPECT_LE(sizeof(umq_perf_hdr_t), 128u);
    umq_perf_hdr_destroy(h);
}

// merge combines counts and extremes
TEST_F(HdrTest, MergeCombines)
{
    umq_perf_hdr_t *a = umq_perf_hdr_create(TEST_MAX_VALUE);
    umq_perf_hdr_t *b = umq_perf_hdr_create(TEST_MAX_VALUE);
    for (uint64_t v = 1; v <= 1000; v++) {
        umq_perf_hdr_record(a, v);
    }
    for (uint64_t v = 1001; v <= 2000; v++) {
        umq_perf_hdr_record(b, v);
    }
    umq_perf_hdr_merge(a, b);
    EXPECT_EQ(a->total_count, 2000u);
    EXPECT_EQ(a->min_value, 1u);
    EXPECT_EQ(a->max_value, 2000u);
    uint64_t p50 = umq_perf_hdr_value_at_quantile(a, 50.0);
    EXPECT_GE(p50, 990u);
    EXPECT_LE(p50, 1010u);
    umq_perf_hdr_destroy(a);
    umq_perf_hdr_destroy(b);
}

// thread safety: per-thread histograms recorded concurrently, then merged (perf.c model)
TEST_F(HdrTest, ThreadSafetyPerThreadMerge)
{
    const int T = 8;
    const uint64_t M = 10000;
    std::vector<umq_perf_hdr_t *> hs(T);
    for (auto &h : hs) {
        h = umq_perf_hdr_create(TEST_MAX_VALUE);
        ASSERT_NE(h, nullptr);
    }
    std::vector<std::thread> threads;
    for (int t = 0; t < T; t++) {
        threads.emplace_back([&hs, M, t]() {
            for (uint64_t v = 1; v <= M; v++) {
                umq_perf_hdr_record(hs[t], v);
            }
        });
    }
    for (auto &th : threads) {
        th.join();
    }
    umq_perf_hdr_t *total = umq_perf_hdr_create(TEST_MAX_VALUE);
    for (auto h : hs) {
        umq_perf_hdr_merge(total, h);
    }
    EXPECT_EQ(total->total_count, (uint64_t)T * M);
    EXPECT_EQ(total->min_value, 1u);
    EXPECT_EQ(total->max_value, M);
    uint64_t p50 = umq_perf_hdr_value_at_quantile(total, 50.0);
    EXPECT_GE(p50, M / 2 - M / 100);
    EXPECT_LE(p50, M / 2 + M / 100);
    for (auto h : hs) {
        umq_perf_hdr_destroy(h);
    }
    umq_perf_hdr_destroy(total);
}
