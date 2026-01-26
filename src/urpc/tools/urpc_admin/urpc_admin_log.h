/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc admin log
 * Create: 2024-4-23
 */

#ifndef URPC_ADMIN_LOG_H
#define URPC_ADMIN_LOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_PRINT(fmt, ...) \
    (void)printf("%s|%s|%s|%d:" fmt "", __DATE__, __TIME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif