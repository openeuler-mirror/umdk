/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA util and clock unit tests.
 */

#include "common_fixture.h"

using namespace urma_test_common;

TEST(UrmaCommonTest, UtilBitSearchCoversSetAndZeroPaths)
{
    unsigned long bits[3] = {};

    EXPECT_EQ(0U, ub_find_first_bit(bits, 0));
    EXPECT_EQ(130U, ub_find_first_bit(bits, 130));
    EXPECT_EQ(0U, ub_find_first_zero_bit(bits, 130));
    EXPECT_EQ(130U, ub_find_next_bit(bits, 130, 130));

    bits[0] = ~0UL;
    bits[1] = 0;
    bits[2] = 1UL << 1;
    EXPECT_EQ(64U, ub_find_first_zero_bit(bits, 130));
    EXPECT_EQ(0U, ub_find_first_bit(bits, 130));
    EXPECT_EQ(129U, ub_find_next_bit(bits, 130, 64));
    EXPECT_EQ(65U, ub_find_next_zero_bit(bits, 130, 65));

    bits[1] = ~0UL;
    bits[2] = ~0UL;
    EXPECT_EQ(130U, ub_find_first_zero_bit(bits, 130));
    EXPECT_EQ(130U, ub_find_next_zero_bit(bits, 130, 130));
}

TEST(UrmaCommonTest, UtilLargeMemAndHugePageBoundaries)
{
    uint8_t dst[8] = {};
    uint8_t src[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

    EXPECT_EQ(0, memset_s_large_buf(dst, sizeof(dst), 0xab, 4));
    EXPECT_EQ(0xab, dst[0]);
    EXPECT_EQ(0xab, dst[3]);
    EXPECT_EQ(0, memset_s_large_buf(dst, sizeof(dst), 0, 0));
    EXPECT_EQ(0, memcpy_s_large_buf(dst, sizeof(dst), src, sizeof(src)));
    EXPECT_EQ(0, std::memcmp(dst, src, sizeof(src)));
    EXPECT_EQ(0, memcpy_s_large_buf(dst, sizeof(dst), src, 0));

    EXPECT_EQ(nullptr, ub_hugemalloc(0, UB_HUGE_PAGE_SIZE_ANY, nullptr));
    EXPECT_EQ(-EINVAL, ub_hugefree(nullptr, 4096));
}

TEST(UrmaCommonTest, UtilStringConversionsAcceptValidAndRejectInvalid)
{
    bool boolValue = false;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;
    int intValue = 0;

    EXPECT_EQ(0, ub_str_to_bool("true", &boolValue));
    EXPECT_TRUE(boolValue);
    EXPECT_EQ(0, ub_str_to_bool("false", &boolValue));
    EXPECT_FALSE(boolValue);
    EXPECT_EQ(-EINVAL, ub_str_to_bool(nullptr, &boolValue));
    EXPECT_EQ(-EINVAL, ub_str_to_bool("", &boolValue));
    EXPECT_EQ(-EINVAL, ub_str_to_bool("yes", &boolValue));

    EXPECT_EQ(0, ub_str_to_u8("255", &u8));
    EXPECT_EQ(255U, u8);
    EXPECT_EQ(-EINVAL, ub_str_to_u8(nullptr, &u8));
    EXPECT_EQ(-EINVAL, ub_str_to_u8("-1", &u8));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u8("12x", &u8));
    EXPECT_EQ(-ERANGE, ub_str_to_u8("256", &u8));

    EXPECT_EQ(0, ub_str_to_u16("65535", &u16));
    EXPECT_EQ(65535U, u16);
    EXPECT_EQ(-ERANGE, ub_str_to_u16("65536", &u16));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u16("x", &u16));

    EXPECT_EQ(0, ub_str_to_u32("4294967295", &u32));
    EXPECT_EQ(UINT_MAX, u32);
    EXPECT_EQ(-ERANGE, ub_str_to_u32("4294967296", &u32));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u32("x", &u32));

    EXPECT_EQ(0, ub_str_to_u64("18446744073709551615", &u64));
    EXPECT_EQ(UINT64_MAX, u64);
    EXPECT_EQ(-EINVAL, ub_str_to_u64("-1", &u64));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u64("x", &u64));

    EXPECT_EQ(0, ub_str_to_int("-12", &intValue));
    EXPECT_EQ(-12, intValue);
    EXPECT_EQ(-EINVAL, ub_str_to_int(nullptr, &intValue));
    EXPECT_EQ(-ENOEXEC, ub_str_to_int("1x", &intValue));
    EXPECT_EQ(-ERANGE, ub_str_to_int("2147483648", &intValue));
}

TEST(UrmaCommonTest, ClockAndErrorHelpersReturnStableValues)
{
    ResetCommonWrap();
    g_commonWrap.failCalloc = true;
    /* Force the clock helper away from heap allocation while keeping /proc data deterministic. */
    g_commonWrap.cpuInfo = "cpu MHz : 2400.000\n";
    uint64_t firstCycles = get_cycles();
    uint64_t secondCycles = get_cycles();
    const char *knownError = ub_strerror(EINVAL);
    double cpuMhz = get_cpu_mhz(false);

    EXPECT_GE(secondCycles, firstCycles);
    ASSERT_NE(nullptr, knownError);
    EXPECT_GT(std::strlen(knownError), 0U);
    EXPECT_DOUBLE_EQ(2400.000, cpuMhz);
}

TEST(UrmaCommonTest, ClockFallsBackToProcWhenSamplingFails)
{
    ResetCommonWrap();
    /* A failed allocation makes get_cpu_mhz read the mocked cpuinfo stream. */
    g_commonWrap.failCalloc = true;
    g_commonWrap.cpuInfo = "processor : 0\ncpu MHz : 2100.500\n";

    EXPECT_DOUBLE_EQ(2100.500, get_cpu_mhz(false));
}

TEST(UrmaCommonTest, ClockUsesSampleWhenProcInfoIsUnavailable)
{
    ResetCommonWrap();
    g_commonWrap.cpuInfo = nullptr;

    EXPECT_GT(get_cpu_mhz(false), 0.0);
}

TEST(UrmaCommonTest, ClockReturnsZeroWhenSamplingAndProcAreUnavailable)
{
    ResetCommonWrap();
    g_commonWrap.failFirstGettimeofday = true;
    g_commonWrap.cpuInfo = nullptr;

    EXPECT_DOUBLE_EQ(0.0, get_cpu_mhz(false));
}

TEST(UrmaCommonTest, ClockHandlesGettimeofdayAndCpuFrequencyMismatch)
{
    ResetCommonWrap();
    g_commonWrap.failSecondGettimeofday = true;
    g_commonWrap.cpuInfo = "cpu MHz : 2000.000\ncpu MHz : 2500.000\n";

    EXPECT_DOUBLE_EQ(2000.000, get_cpu_mhz(true));
}
