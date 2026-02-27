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

#include "umq_ub_flow_control.h"

#define TEST_QUEUE_RX_DEPTH 128

class UmqFlowControlTest : public ::testing::Test {
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

TEST_F(UmqFlowControlTest, test_umq_ub_flow_control_init_non_atomic)
{
    ub_queue_t queue = {0};
    queue.create_flag = 0;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    umq_ub_flow_control_uninit(&queue.flow_control);
}

TEST_F(UmqFlowControlTest, test_umq_ub_flow_control_init_atomic)
{
    ub_queue_t queue = {0};
    queue.create_flag = 0;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    cfg.use_atomic_window = true;
    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    umq_ub_flow_control_uninit(&queue.flow_control);
}

TEST_F(UmqFlowControlTest, test_umq_ub_shared_credit_recharge)
{
    ub_queue_t queue = {0};
    queue.create_flag = 0;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    cfg.use_atomic_window = true;
    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    umq_ub_shared_credit_recharge(&queue, 1);
    ASSERT_EQ(io_jfr_ctx.credit.stats_u16[CREDIT_POOL_IDLE], 1);
    umq_ub_flow_control_uninit(&queue.flow_control);
}

TEST_F(UmqFlowControlTest, test_umq_ub_idle_credit_flush)
{
    ub_queue_t queue = {0};
    queue.create_flag = 0;
    umq_ub_ctx_t dev_ctx;
    queue.dev_ctx = &dev_ctx;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    cfg.use_atomic_window = true;
    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    io_jfr_ctx.credit.stats_u16[CREDIT_POOL_IDLE] = 1;
    umq_ub_idle_credit_flush(&queue, 1);
    ASSERT_EQ(io_jfr_ctx.credit.stats_u16[CREDIT_POOL_IDLE], 0);
    umq_ub_flow_control_uninit(&queue.flow_control);
}

TEST_F(UmqFlowControlTest, test_umq_ub_idle_credit_flush_non_atomic)
{
    ub_queue_t queue = {0};
    queue.create_flag = 0;
    umq_ub_ctx_t dev_ctx;
    queue.dev_ctx = &dev_ctx;
    dev_ctx.flow_control.use_atomic_window = true;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    cfg.use_atomic_window = false;
    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    io_jfr_ctx.credit.stats_u16[CREDIT_POOL_IDLE] = 1;
    umq_ub_idle_credit_flush(&queue, 1);
    ASSERT_EQ(io_jfr_ctx.credit.stats_u16[CREDIT_POOL_IDLE], 0);
    umq_ub_flow_control_uninit(&queue.flow_control);
}

TEST_F(UmqFlowControlTest, test_umq_ub_rx_consumed_inc_atomic)
{
    volatile uint64_t var = 0;
    (void)umq_ub_rx_consumed_inc(true, &var, 1);
    ASSERT_EQ(var, 1);
}

TEST_F(UmqFlowControlTest, test_umq_ub_rx_consumed_inc_non_atomic)
{
    volatile uint64_t var = 0;
    (void)umq_ub_rx_consumed_inc(false, &var, 1);
    ASSERT_EQ(var, 1);
}