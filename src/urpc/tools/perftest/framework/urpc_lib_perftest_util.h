/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest utils
 * Create: 2024-3-6
 */

#ifndef URPC_LIB_PERFTEST_UTIL_H
#define URPC_LIB_PERFTEST_UTIL_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_PERFTEST_1M (1000000)
#define URPC_PERFTEST_1MB (0x100000)

#define LOG_PRINT(fmt, ...) \
    (void)printf("%s|%s|%s|%d:" fmt "", __DATE__, __TIME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif  // URPC_LIB_PERFTEST_UTIL_H