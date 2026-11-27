/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA common unit test wrap mocks.
 */

#include "common_fixture.h"

namespace urma_test_common {
CommonWrapState g_commonWrap = {};

void ResetCommonWrap()
{
    g_commonWrap = {};
}
} // namespace urma_test_common

using namespace urma_test_common;

extern "C" {
void *__real_calloc(size_t nmemb, size_t size);
int __real_gettimeofday(struct timeval *tv, void *tz);
int __real_clock_gettime(clockid_t clk, struct timespec *ts);
FILE *__real_fopen(const char *path, const char *mode);
char *__real_fgets(char *s, int size, FILE *stream);
int __real_fclose(FILE *stream);

void *__wrap_calloc(size_t nmemb, size_t size)
{
    if (g_commonWrap.failCalloc) {
        return nullptr;
    }
    return __real_calloc(nmemb, size);
}

int __wrap_gettimeofday(struct timeval *tv, void *tz)
{
    ++g_commonWrap.gettimeofdayCalls;
    if (g_commonWrap.failFirstGettimeofday && g_commonWrap.gettimeofdayCalls == 1) {
        return -1;
    }
    if (g_commonWrap.failSecondGettimeofday && g_commonWrap.gettimeofdayCalls == 2) {
        return -1;
    }
    return __real_gettimeofday(tv, tz);
}

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts)
{
    ++g_commonWrap.clockGettimeCalls;
    if (g_commonWrap.failFirstClockGettime && g_commonWrap.clockGettimeCalls == 1) {
        return -1;
    }
    if (g_commonWrap.failSecondClockGettime && g_commonWrap.clockGettimeCalls == 2) {
        return -1;
    }
    int rc = __real_clock_gettime(clk, ts);
    if (g_commonWrap.injectTimeJump && g_commonWrap.clockGettimeCalls >= 2) {
        ts->tv_sec += 5;
    }
    return rc;
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (g_commonWrap.cpuInfo == nullptr) {
        return nullptr;
    }
    (void)path;
    (void)mode;
    return fmemopen(const_cast<char *>(g_commonWrap.cpuInfo), std::strlen(g_commonWrap.cpuInfo), "r");
}

char *__wrap_fgets(char *s, int size, FILE *stream)
{
    return __real_fgets(s, size, stream);
}

int __wrap_fclose(FILE *stream)
{
    return __real_fclose(stream);
}
}
