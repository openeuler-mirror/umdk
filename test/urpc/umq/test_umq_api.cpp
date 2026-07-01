/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq api test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "umq_api.h"
#include "umq_inner.h"

class UmqAPITest : public ::testing::Test {
  public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {
    }

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {
    }
};

TEST_F(UmqAPITest, test_umq_log_config_get_failure)
{
    ASSERT_NE(umq_log_config_get(nullptr), 0);
}

TEST_F(UmqAPITest, test_umq_log_config_set_failure)
{
    umq_log_config_t cfg;
    memset(&cfg, 0, sizeof(umq_log_config_t));

    ASSERT_NE(umq_log_config_set(nullptr), 0);

    cfg.log_flag |= UMQ_LOG_FLAG_LEVEL;
    cfg.level = UMQ_LOG_LEVEL_MAX;
    ASSERT_NE(umq_log_config_set(&cfg), 0);
    cfg.level = UMQ_LOG_LEVEL_INFO;
}

TEST_F(UmqAPITest, test_umq_log_config_set_and_get_success)
{
    umq_log_config_t cfg0, cfg;
    memset(&cfg0, 0, sizeof(umq_log_config_t));
    memset(&cfg, 0, sizeof(umq_log_config_t));

    ASSERT_EQ(umq_log_config_get(&cfg0), 0);
    ASSERT_EQ(cfg0.log_flag, 0);

    cfg.log_flag |= UMQ_LOG_FLAG_LEVEL | UMQ_LOG_FLAG_RATE_LIMITED | UMQ_LOG_FLAG_FUNC;
    cfg.level = UMQ_LOG_LEVEL_EMERG;
    ASSERT_EQ(umq_log_config_set(&cfg), 0);

    ASSERT_EQ(umq_log_config_get(&cfg), 0);
    ASSERT_EQ(cfg.level, UMQ_LOG_LEVEL_EMERG);
    ASSERT_EQ(cfg.rate_limited.interval_ms, 0);
    ASSERT_EQ(cfg.rate_limited.num, 0);

    // restore log config
    ASSERT_EQ(umq_log_config_set(&cfg0), 0);
}

TEST_F(UmqAPITest, test_is_timeout)
{
    struct timespec start;
    (void)clock_gettime(CLOCK_MONOTONIC, &start);

    start.tv_sec -= 1;
    ASSERT_EQ(is_timeout(&start, 1000), true);

    start.tv_sec += 100;
    ASSERT_EQ(is_timeout(&start, 1000), false);
}
