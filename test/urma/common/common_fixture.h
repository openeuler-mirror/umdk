/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA common unit test helpers.
 */

#ifndef TEST_URMA_COMMON_COMMON_FIXTURE_H
#define TEST_URMA_COMMON_COMMON_FIXTURE_H

#include <cerrno>
#include <climits>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/time.h>

#include <gtest/gtest.h>

#include "ub_bitmap.h"
#include "ub_dstring.h"
#include "ub_get_clock.h"
#include "ub_hash.h"
#include "ub_hmap.h"
#include "ub_util.h"

namespace urma_test_common {
struct CommonWrapState {
    bool failCalloc;
    bool failFirstGettimeofday;
    bool failSecondGettimeofday;
    int gettimeofdayCalls;
    const char *cpuInfo;
};

extern CommonWrapState g_commonWrap;

void ResetCommonWrap();
} // namespace urma_test_common

#endif // TEST_URMA_COMMON_COMMON_FIXTURE_H
