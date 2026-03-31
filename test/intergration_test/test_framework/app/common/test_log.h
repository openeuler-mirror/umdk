/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: log function
*/

#ifndef TEST_LOG_H
#define TEST_LOG_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

enum test_log_level {
    TEST_LOG_LEVEL_ERROR = 3,
    TEST_LOG_LEVEL_WARN,
    TEST_LOG_LEVEL_INFO = 6,
    TEST_LOG_LEVEL_DEBUG,
    TEST_LOG_LEVEL_MAX,
};

#define TEST_LOG_LEVEL "TEST_LOG_LEVEL"

void test_log_init(void);
void test_log(const char *function, int line, uint32_t level, const char *format, ...);
bool test_log_drop(uint32_t level);
int test_log_create_dir(char *dir_name);

// set log level
int test_log_set_level(enum test_log_level level);

#define TEST_LOG(l, ...) \
    if (!test_log_drop(TEST_LOG_LEVEL_##l)) { \
        test_log(__func__, __LINE__, TEST_LOG_LEVEL_##l, __VA_ARGS__); \
    }
#define TEST_LOG_DEBUG(...) TEST_LOG(DEBUG, __VA_ARGS__)
#define TEST_LOG_INFO(...) TEST_LOG(INFO, __VA_ARGS__)
#define TEST_LOG_WARN(...) TEST_LOG(WARN, __VA_ARGS__)
#define TEST_LOG_ERROR(...) TEST_LOG(ERROR, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* TEST_LOG_H */