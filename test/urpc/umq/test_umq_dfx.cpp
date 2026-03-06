#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <cstring>

#include "umq_api.h"
#include "umq_errno.h"
#include "umq_vlog.h"
#include "urpc_util.h"
#include "umq_inner.h"
#include "umq_dfx_api.h"
#include "umq_ub_private.h"
#include "umq_ub_flow_control.h"
#include "umq_ub_api.h"

#define TEST_QUEUE_RX_DEPTH 128
// Test DFX functionality
class DfxTest : public ::testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

TEST_F(DfxTest, UmqStatsFlowControlGetTestWithInvalidParam)
{
    umq_dfx_ops_t dfx_tp_ops = {
        .umq_tp_stats_flow_control_get = NULL,
    };
    umq_t umq = {
        .mode = UMQ_TRANS_MODE_UB,
        .dfx_tp_ops = &dfx_tp_ops,
    };
    umq_flow_control_stats_t flow_control_stats = {0};
    int ret = umq_stats_flow_control_get((uint64_t)(uintptr_t)(&umq), &flow_control_stats);
    EXPECT_EQ(ret, -UMQ_ERR_EINVAL);
}

TEST_F(DfxTest, UmqStatsFlowControlGetTestWithDisableFc)
{
    ub_queue_t umqh = {0};
    umq_t umq = {
        .mode = UMQ_TRANS_MODE_UB,
        .dfx_tp_ops = umq_ub_dfx_ops_get(),
        .umqh_tp = (uint64_t)(uintptr_t)&umqh
    };
    umq_flow_control_stats_t flow_control_stats = {0};
    int ret = umq_stats_flow_control_get((uint64_t)(uintptr_t)(&umq), &flow_control_stats);
    EXPECT_EQ(ret, -UMQ_ERR_EINVAL);
}

TEST_F(DfxTest, UmqStatsFlowControlGetTestWithEnableFcAtomic)
{
    ub_queue_t queue = {0};
    queue.flow_control.enabled = true;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    urma_jetty_t jetty;
    jetty.jetty_id.id = 0;
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    cfg.use_atomic_window = true;
    umq_ub_ctx_t dev_ctx;
    uint64_t rx_consumed_jetty_table;
    dev_ctx.rx_consumed_jetty_table = &rx_consumed_jetty_table;
    dev_ctx.flow_control.use_atomic_window = true;
    queue.jetty[UB_QUEUE_JETTY_IO] = &jetty;
    queue.dev_ctx = &dev_ctx;

    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    umq_t umq = {
        .mode = UMQ_TRANS_MODE_UB,
        .dfx_tp_ops = umq_ub_dfx_ops_get(),
        .umqh_tp = (uint64_t)(uintptr_t)&queue
    };
    umq_flow_control_stats_t flow_control_stats = {0};
    ret = umq_stats_flow_control_get((uint64_t)(uintptr_t)(&umq), &flow_control_stats);
    EXPECT_EQ(ret, UMQ_SUCCESS);
    umq_ub_flow_control_uninit(&queue.flow_control);
}

TEST_F(DfxTest, UmqStatsFlowControlGetTestWithEnableFcNonAtomic)
{
    ub_queue_t queue = {0};
    queue.flow_control.enabled = true;
    queue.flow_control.local_rx_depth = TEST_QUEUE_RX_DEPTH;
    jfr_ctx_t io_jfr_ctx =  {0};
    urma_jetty_t jetty;
    jetty.jetty_id.id = 0;
    queue.jfr_ctx[UB_QUEUE_JETTY_IO] = &io_jfr_ctx;
    umq_flow_control_cfg_t cfg = {0};
    cfg.use_atomic_window = false;
    umq_ub_ctx_t dev_ctx;
    uint64_t rx_consumed_jetty_table;
    dev_ctx.rx_consumed_jetty_table = &rx_consumed_jetty_table;
    dev_ctx.flow_control.use_atomic_window = true;
    queue.jetty[UB_QUEUE_JETTY_IO] = &jetty;
    queue.dev_ctx = &dev_ctx;

    int ret = umq_ub_flow_control_init(&queue.flow_control, &queue, UMQ_FEATURE_ENABLE_FLOW_CONTROL, &cfg);
    ASSERT_EQ(ret, 0);
    umq_t umq = {
        .mode = UMQ_TRANS_MODE_UB,
        .dfx_tp_ops = umq_ub_dfx_ops_get(),
        .umqh_tp = (uint64_t)(uintptr_t)&queue
    };
    umq_flow_control_stats_t flow_control_stats = {0};
    ret = umq_stats_flow_control_get((uint64_t)(uintptr_t)(&umq), &flow_control_stats);
    EXPECT_EQ(ret, UMQ_SUCCESS);
    umq_ub_flow_control_uninit(&queue.flow_control);
}
