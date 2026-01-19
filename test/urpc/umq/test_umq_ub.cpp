/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq ub test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include "umq_api.h"

class UmqUBTest : public ::testing::Test {
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

TEST_F(UmqUBTest, test_umq_ub)
{
    umq_init_cfg_t cfg;
    memset(&cfg, 0, sizeof(umq_init_cfg_t));
    int ret;

    cfg.trans_info_num = 1;
    cfg.trans_info[0].trans_mode = UMQ_TRANS_MODE_UB;

    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
}

