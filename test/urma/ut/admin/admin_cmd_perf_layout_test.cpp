/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_admin perf netlink payload layout tests.
 */

#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

#include "admin_cmd_perf_layout.h"

namespace {

constexpr size_t PERF_RECORD_TYPE_COUNT = 82;
constexpr size_t COMPACT_RECORD_SIZE = 64;
constexpr size_t KABI_RECORD_SIZE = 80;
constexpr size_t COMPACT_STAT_SIZE = 5256;
constexpr size_t KABI_STAT_SIZE = 6568;

static_assert(ADMIN_PERF_RECORD_TYPE_MAX == PERF_RECORD_TYPE_COUNT,
              "unexpected perf record type count");
static_assert(PERF_URMA_CMD_CREATE_JETTY == 0,
              "unexpected first perf record type");
static_assert(PERF_UB_DESTROY_JFC == PERF_RECORD_TYPE_COUNT - 1,
              "unexpected last perf record type");
static_assert(sizeof(admin_perf_record_stat_t) == COMPACT_RECORD_SIZE,
              "unexpected compact perf record size");
static_assert(sizeof(admin_perf_record_stat_kabi_t) == KABI_RECORD_SIZE,
              "unexpected KABI perf record size");
static_assert(sizeof(admin_core_latency_stat_t) == COMPACT_STAT_SIZE,
              "unexpected compact perf stat size");
static_assert(offsetof(admin_core_latency_stat_t, perf_stat_table) +
              ADMIN_PERF_RECORD_TYPE_MAX * sizeof(admin_perf_record_stat_kabi_t) ==
              KABI_STAT_SIZE,
              "unexpected KABI perf stat size");

TEST(UrmaAdminPerfLayoutTest, RecordFieldOffsetsMatchProtocol)
{
    EXPECT_EQ(offsetof(admin_perf_record_stat_t, record_type), 0U);
    EXPECT_EQ(offsetof(admin_perf_record_stat_t, count), 8U);
    EXPECT_EQ(sizeof(admin_perf_record_stat_t), COMPACT_RECORD_SIZE);
    EXPECT_EQ(sizeof(admin_perf_record_stat_kabi_t), KABI_RECORD_SIZE);
}

TEST(UrmaAdminPerfLayoutTest, StatPayloadSizesMatchSupportedKernels)
{
    EXPECT_EQ(sizeof(admin_core_latency_stat_t), COMPACT_STAT_SIZE);
    EXPECT_EQ(offsetof(admin_core_latency_stat_t, perf_stat_table) +
              ADMIN_PERF_RECORD_TYPE_MAX * sizeof(admin_perf_record_stat_kabi_t),
              KABI_STAT_SIZE);
}

} // namespace
