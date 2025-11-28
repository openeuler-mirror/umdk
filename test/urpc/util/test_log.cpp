/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc util test
 */
#include "gtest/gtest.h"
#include "urpc_lib_log.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"

TEST(UrpcLogTest, TestLevel) {
    urpc_log_level_t level = URPC_LOG_LEVEL_DEBUG;
    bool res = util_vlog_drop(urpc_lib_get_vlog_ctx(), (util_vlog_level_t)level);
    ASSERT_EQ(res, true);

    urpc_log_config_t log_cfg;
    memset(&log_cfg, 0, sizeof(log_cfg));
    log_cfg.log_flag = URPC_LOG_FLAG_LEVEL;
    log_cfg.level = level;
    int ret = urpc_log_config_set(&log_cfg);
    ASSERT_EQ(ret, URPC_SUCCESS);
    res = util_vlog_drop(urpc_lib_get_vlog_ctx(), (util_vlog_level_t)level);
    ASSERT_EQ(res, false);

    level = URPC_LOG_LEVEL_MAX;
    log_cfg.level = level;
    ret = urpc_log_config_set(&log_cfg);
    ASSERT_EQ(ret, URPC_FAIL);
}

void default_output(int level, char *log_msg) {
    (void) fprintf(stdout, "%s\n", log_msg);
}

TEST(UrpcLogTest, TestRegister) {
    urpc_log_config_t log_cfg;
    memset(&log_cfg, 0, sizeof(log_cfg));
    log_cfg.log_flag = URPC_LOG_FLAG_FUNC;
    log_cfg.func = default_output;
    int ret = urpc_log_config_set(&log_cfg);
    ASSERT_EQ(ret, URPC_SUCCESS);

    log_cfg.func = NULL;
    ret = urpc_log_config_set(&log_cfg);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST(UrpcLogTest, TestSetLogLimitConfig)
{
    // test using NULL to set configure
    uint32_t count_call = 0;
    uint64_t last_time = 0;
    // test default configure
    for (uint32_t i = 0; i < UTIL_VLOG_PRINT_TIMES; i++) {
        ASSERT_EQ(util_vlog_limit(urpc_lib_get_vlog_ctx(), &count_call, &last_time), true);
    }
    ASSERT_EQ(util_vlog_limit(urpc_lib_get_vlog_ctx(), &count_call, &last_time), false);

    // test specified configure
    count_call = 0;
    last_time = 0;
    urpc_log_config_t config;
    config.log_flag = URPC_LOG_FLAG_RATE_LIMITED;
    config.rate_limited.interval_ms = 2000;
    config.rate_limited.num = 3;
    ASSERT_EQ(urpc_log_config_set(&config), URPC_SUCCESS);
    for (uint32_t i = 0; i < config.rate_limited.num; i++) {
        ASSERT_EQ(util_vlog_limit(urpc_lib_get_vlog_ctx(), &count_call, &last_time), true);
    }
    ASSERT_EQ(util_vlog_limit(urpc_lib_get_vlog_ctx(), &count_call, &last_time), false);

    // test disable rate-limited log
    count_call = 0;
    last_time = 0;
    config.rate_limited.interval_ms = 0;
    config.rate_limited.num = 0;
    ASSERT_EQ(urpc_log_config_set(&config), URPC_SUCCESS);
    ASSERT_EQ(util_vlog_limit(urpc_lib_get_vlog_ctx(), &count_call, &last_time), true);
}

static void urpc_log_test_print(int level, char *log_msg)
{
    return;
}

TEST(UrpcLogTest, TestSetGetLogConfig)
{
    ASSERT_EQ(urpc_log_config_set(NULL), -URPC_ERR_EINVAL);

    urpc_log_config_t config_input;
    urpc_log_config_t config_output;
    config_input.log_flag = URPC_LOG_FLAG_RATE_LIMITED;
    config_input.rate_limited.interval_ms = 2000;
    config_input.rate_limited.num = 3;
    ASSERT_EQ(urpc_log_config_set(&config_input), URPC_SUCCESS);
    ASSERT_EQ(urpc_log_config_get(&config_output), URPC_SUCCESS);
    ASSERT_EQ(config_output.log_flag, 0);
    ASSERT_EQ((uint64_t)config_output.func, 0);
    ASSERT_EQ(config_output.rate_limited.interval_ms, config_input.rate_limited.interval_ms);
    ASSERT_EQ(config_output.rate_limited.num, config_input.rate_limited.num);

    config_input.log_flag = URPC_LOG_FLAG_RATE_LIMITED | URPC_LOG_FLAG_LEVEL;
    config_input.level = URPC_LOG_LEVEL_DEBUG;
    config_input.rate_limited.interval_ms = 3000;
    config_input.rate_limited.num = 4;
    ASSERT_EQ(urpc_log_config_set(&config_input), URPC_SUCCESS);
    ASSERT_EQ(urpc_log_config_get(&config_output), URPC_SUCCESS);
    ASSERT_EQ(config_output.log_flag, 0);
    ASSERT_EQ((uint64_t)config_output.func, 0);
    ASSERT_EQ(config_output.level, URPC_LOG_LEVEL_DEBUG);
    ASSERT_EQ(config_output.rate_limited.interval_ms, config_input.rate_limited.interval_ms);
    ASSERT_EQ(config_output.rate_limited.num, config_input.rate_limited.num);

    config_input.log_flag = URPC_LOG_FLAG_RATE_LIMITED | URPC_LOG_FLAG_LEVEL | URPC_LOG_FLAG_FUNC;
    config_input.func = urpc_log_test_print;
    config_input.level = URPC_LOG_LEVEL_WARN;
    config_input.rate_limited.interval_ms = 4000;
    config_input.rate_limited.num = 5;
    ASSERT_EQ(urpc_log_config_set(&config_input), URPC_SUCCESS);
    ASSERT_EQ(urpc_log_config_get(&config_output), URPC_SUCCESS);
    ASSERT_EQ(config_output.log_flag, 0);
    ASSERT_EQ(config_output.func, urpc_log_test_print);
    ASSERT_EQ(config_output.level, URPC_LOG_LEVEL_WARN);
    ASSERT_EQ(config_output.rate_limited.interval_ms, config_input.rate_limited.interval_ms);
    ASSERT_EQ(config_output.rate_limited.num, config_input.rate_limited.num);

    config_input.func = NULL;
    ASSERT_EQ(urpc_log_config_set(&config_input), URPC_SUCCESS);
    ASSERT_EQ(urpc_log_config_get(&config_output), URPC_SUCCESS);
    ASSERT_EQ(config_output.log_flag, 0);
    ASSERT_EQ((uint64_t)config_output.func, 0);
    ASSERT_EQ(config_output.level, URPC_LOG_LEVEL_WARN);
    ASSERT_EQ(config_output.rate_limited.interval_ms, config_input.rate_limited.interval_ms);
    ASSERT_EQ(config_output.rate_limited.num, config_input.rate_limited.num);

    config_input.func = urpc_log_test_print;
    config_input.level = URPC_LOG_LEVEL_MAX;
    ASSERT_EQ(urpc_log_config_set(&config_input), URPC_FAIL);
}