/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib test
 */

#include "gtest/gtest.h"
#include "mockcpp/mockcpp.hpp"
#include "urpc_id_generator.h"
#include "channel.h"
#include "cp.h"
#include "dp.h"
#include "func.h"
#include "protocol.h"
#include "queue.h"
#include "jetty_public_func.h"
#include "queue_send_recv.h"
#include "state.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"

#define MAX_MSG_SIZE (1UL << 20)
#define FISRT_SGE_LENGTH            (256)
#define URPC_UT_FUNC_ID             (111U)

static urma_status_t urma_query_device_mock(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    dev_attr->dev_cap.max_msg_size = MAX_MSG_SIZE;
    return URMA_SUCCESS;
}

static uint64_t g_test_dp_rx_ctx;
static urpc_sge_t g_test_dp_rx_sge;
static urma_status_t urma_post_jetty_mock(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    g_test_dp_rx_ctx = wr->user_ctx;
    g_test_dp_rx_sge.addr = wr->src.sge[0].addr;
    g_test_dp_rx_sge.length = wr->src.sge[0].len;
    return URMA_SUCCESS;
}

static urma_status_t urma_query_jetty_mock(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr)
{
    attr->state = URMA_JETTY_STATE_READY;
    return URMA_SUCCESS;
}

static urma_status_t urma_query_jfr_mock(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr)
{
    attr->state = URMA_JFR_STATE_READY;
    return URMA_SUCCESS;
}

class DatapathTest : public :: testing::Test {
public:
    void SetUp() override {
        static urma_device_t dev = {0};
        dev.type = URMA_TRANSPORT_UB;
        static urma_eid_info_t eid_info = {0};
        (void)urma_str_to_eid("127.0.0.1", &eid_info.eid);
        static uint32_t eid_num = 1;
        static urma_context_t urma_ctx = {0};
        urma_ctx.dev = &dev;
        MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
        MOCKER(urma_get_device_by_name).stubs().will(returnValue(&dev));
        MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
        MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
        MOCKER(urma_get_eid_list)
        .stubs()
        .with(any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
        .will(returnValue(&eid_info));

        static urma_jfr_t jfr = {0};
        static urma_jfc_t jfc = {0};
        static urma_jetty_t jetty = {0};
        static urma_target_jetty target_jetty = {0};
        MOCKER(urma_create_jfr).stubs().will(returnValue(&jfr));
        MOCKER(urma_delete_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfc).stubs().will(returnValue(&jfc));
        MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jetty).stubs().will(returnValue(&jetty));
        MOCKER(urma_delete_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_import_jetty).stubs().will(returnValue(&target_jetty));
        MOCKER(urma_unimport_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jetty).stubs().will(invoke(urma_query_jetty_mock));
        MOCKER(urma_modify_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jfr).stubs().will(invoke(urma_query_jfr_mock));

        urma_target_seg_t seg = {0};
        MOCKER(urma_register_seg).stubs().will(returnValue(&seg));
        MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_post_jetty_recv_wr).stubs().will(invoke(urma_post_jetty_mock));

        urpc_config_t urpc_config = { .role = URPC_ROLE_CLIENT };
        urpc_config.feature = URPC_FEATURE_TIMEOUT;
        urpc_config.trans_info_num = 1;
        urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
        urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
        (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "lo");
        urpc_state_set(URPC_STATE_UNINIT);

        int ret = urpc_init(&urpc_config);
        EXPECT_EQ(ret, URPC_SUCCESS);

        default_allocator_cfg_t cfg = {
            .need_large_sge = true,
            .large_sge_size = DEFAULT_LARGE_SGE_SIZE,
        };
        EXPECT_EQ(urpc_default_allocator_init(&cfg), URPC_SUCCESS);
        urpc_allocator_t *default_alloc = default_allocator_get();
        EXPECT_NE(default_alloc, nullptr);
    }

    void TearDown() override {
        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
        urpc_uninit();
        urpc_default_allocator_uninit();
        GlobalMockObject::verify();
    }
};

TEST_F(DatapathTest, UrpcFuncCallTestWithNullLQueue) {
    uint32_t chid = urpc_channel_create();

    char buf[FISRT_SGE_LENGTH];
    struct urpc_sge sge = {.addr = (uint64_t)buf, .length = FISRT_SGE_LENGTH};
    urpc_call_wr_t wr = {.func_id = 0, .args = &sge, .args_num = 1};

    struct urpc_call_option option = {0};
    option.option_flag = FUNC_CALL_FLAG_L_QH;
    option.l_qh = 0;

    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_LOCAL_QUEUE_ERR);
    urpc_channel_destroy(chid);
}

TEST_F(DatapathTest, UrpcFuncCallTestWithNullRQueue) {
    uint32_t chid = urpc_channel_create();
    urpc_qcfg_create_t cfg = {0};
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &cfg);
    ASSERT_NE(qh, (uint64_t)URPC_INVALID_HANDLE);
    urpc_channel_info_t *channel = channel_get(chid);
    queue_node_t node = {
        .urpc_qh = qh,
    };
    node.node.next = NULL;
    node.ref_cnt = 1;
    URPC_SLIST_INSERT_HEAD(&channel->l_queue_nodes_head, &node, node);
    channel->l_qnum++;
    queue_t *queue = (queue_t *)(uintptr_t)qh;
    (void)__sync_fetch_and_add(&queue->ref_cnt, 1);

    char buf[FISRT_SGE_LENGTH];
    struct urpc_sge sge = {.addr = (uint64_t)buf, .length = FISRT_SGE_LENGTH};
    urpc_call_wr_t wr = {.func_id = 0, .args = &sge, .args_num = 1};

    struct urpc_call_option option = {0};
    option.option_flag = FUNC_CALL_FLAG_R_QH;
    option.r_qh = 0;
    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_REMOTE_QUEUE_ERR);
    URPC_SLIST_REMOVE(&channel->l_queue_nodes_head, &node, queue_node, node);
    channel->l_qnum = 0;
    (void)__sync_fetch_and_sub(&queue->ref_cnt, 1);
    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, 0);

    urpc_channel_destroy(chid);
}

TEST_F(DatapathTest, UrpcFuncCallTestWithNullChannelQueue) {
    uint32_t chid = urpc_channel_create();

    char buf[FISRT_SGE_LENGTH];
    struct urpc_sge sge = {.addr = (uint64_t)buf, .length = FISRT_SGE_LENGTH};
    urpc_call_wr_t wr = {.func_id = 0, .args = &sge, .args_num = 1};

    struct urpc_call_option option = {0};
    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_LOCAL_QUEUE_ERR);
    urpc_channel_destroy(chid);
}

static uint64_t g_test_dp_tx_ctx;

static urma_status_t test_dp_send_mock(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    g_test_dp_tx_ctx = wr->user_ctx;
    return URMA_SUCCESS;
}

static int test_dp_poll_mock(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
    static int cnt = 0;
    if (cnt == 0) {
        cr[0].status = URMA_CR_SUCCESS;
        cr[0].user_ctx = g_test_dp_tx_ctx;
        cr[0].completion_len = 512;

        cnt++;
        return 1;
    }

    if (cnt == 1) {
        cr[0].status = URMA_CR_SUCCESS;
        cr[0].user_ctx = g_test_dp_rx_ctx;
        cr[0].completion_len = 512;
        // construct ack header
        urpc_ack_head_t *ack_hdr = (urpc_ack_head_t *)(uintptr_t)g_test_dp_rx_sge.addr;
        urpc_ack_fill_one_req_head(ack_hdr, 0, 0);
        cnt = 0;
        return 1;
    }

    return 0;
}

// func_call and get ack
TEST_F(DatapathTest, TestServerPoll)
{
    MOCKER(urma_poll_jfc).stubs().will(invoke(test_dp_poll_mock));
    MOCKER(urma_post_jetty_send_wr).stubs().will(invoke(test_dp_send_mock));
    urma_target_jetty_t tjetty = {0};
    send_recv_queue_remote_t r_q = {0};
    r_q.tjetty = &tjetty;
    MOCKER(urpc_get_remote_queue).stubs().will(returnValue(&r_q.remote_q.queue));

    struct urpc_poll_option poll_option = {0};
    struct urpc_poll_msg msg[2];
    urpc_qcfg_create_t cfg = {0};
    cfg.create_flag = QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    cfg.rx_depth = 1;
    cfg.tx_depth = 1;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &cfg);
    ASSERT_NE(qh, (uint64_t)URPC_INVALID_HANDLE);
    poll_option.urpc_qh = qh;

    uint32_t chid = urpc_channel_create();
    ASSERT_NE(chid, URPC_U32_FAIL);
    urpc_channel_info_t *channel = channel_get(chid);
    queue_node_t node = {
        .urpc_qh = qh,
    };
    node.node.next = NULL;
    node.ref_cnt = 1;
    URPC_SLIST_INSERT_HEAD(&channel->l_queue_nodes_head, &node, node);
    channel->l_qnum++;
    queue_t *queue = (queue_t *)(uintptr_t)qh;
    (void)__sync_fetch_and_add(&queue->ref_cnt, 1);

    // 1. req call with ack
    urpc_call_option_t call_option = {0};
    call_option.option_flag = FUNC_CALL_FLAG_CALL_MODE;
    call_option.call_mode = FUNC_CALL_MODE_EARLY_RSP;
    urpc_call_wr_t call_wr = {0};
    char *buf = (char *)malloc(512);
    ASSERT_NE(buf, nullptr);
    uint64_t mem_h = urpc_mem_seg_register((uint64_t)(uintptr_t)buf, 512);
    ASSERT_NE(mem_h, (uint64_t)URPC_INVALID_HANDLE);
    urpc_sge_t sge = {0};
    sge.addr = (uint64_t)(uintptr_t)buf;
    sge.length = 512;
    sge.mem_h = mem_h;
    call_wr.args = &sge;
    call_wr.args_num = 1;
    uint64_t id = urpc_func_call(chid, &call_wr, &call_option);
    ASSERT_NE(id, URPC_U64_FAIL);

    urpc_queue_rx_post(qh, &sge, 1);
    // 2. mock poll one tx cqe and one ack rx cqe
    int ret = urpc_func_poll(URPC_INVALID_ID_U32, &poll_option, msg, 2);
    ASSERT_EQ(ret, 2);
    ASSERT_EQ(msg[0].event, POLL_EVENT_REQ_RSPED);
    URPC_SLIST_REMOVE(&channel->l_queue_nodes_head, &node, queue_node, node);
    channel->l_qnum = 0;
    (void)__sync_fetch_and_sub(&queue->ref_cnt, 1);
    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, 0);

    ret = urpc_channel_destroy(chid);
    ASSERT_EQ(ret, 0);

    ret = urpc_mem_seg_unregister(mem_h);
    ASSERT_EQ(ret, 0);

    free(buf);
}

// func_call and get ack
TEST_F(DatapathTest, TestPollChannel)
{
    MOCKER(urma_poll_jfc).stubs().will(invoke(test_dp_poll_mock));
    MOCKER(urma_post_jetty_send_wr).stubs().will(invoke(test_dp_send_mock));
    urma_target_jetty_t tjetty = {0};
    send_recv_queue_remote_t r_q = {0};
    r_q.tjetty = &tjetty;
    MOCKER(urpc_get_remote_queue).stubs().will(returnValue(&r_q.remote_q.queue));

    struct urpc_poll_option poll_option = {0};
    struct urpc_poll_msg msg[2];
    urpc_qcfg_create_t cfg = {0};
    cfg.create_flag = QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    cfg.rx_depth = 1;
    cfg.tx_depth = 1;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &cfg);
    ASSERT_NE(qh, (uint64_t)URPC_INVALID_HANDLE);

    uint32_t chid = urpc_channel_create();
    ASSERT_NE(chid, URPC_U32_FAIL);

    // 1. req call with ack
    urpc_call_option_t call_option = {0};
    call_option.option_flag = FUNC_CALL_FLAG_CALL_MODE;
    call_option.call_mode = FUNC_CALL_MODE_EARLY_RSP;
    urpc_call_wr_t call_wr = {0};
    char *buf = (char *)malloc(512);
    ASSERT_NE(buf, nullptr);
    uint64_t mem_h = urpc_mem_seg_register((uint64_t)(uintptr_t)buf, 512);
    ASSERT_NE(mem_h, (uint64_t)URPC_INVALID_HANDLE);
    urpc_sge_t sge = {0};
    sge.addr = (uint64_t)(uintptr_t)buf;
    sge.length = 512;
    sge.mem_h = mem_h;
    call_wr.args = &sge;
    call_wr.args_num = 1;

    // 2. local queue is null
    poll_option.urpc_qh = URPC_INVALID_HANDLE;
    int ret = urpc_func_poll(chid, &poll_option, msg, 2);
    ASSERT_EQ(ret, 0);

    urpc_channel_info_t *channel = channel_get(chid);
    queue_node_t node = {
        .urpc_qh = qh,
    };
    node.node.next = NULL;
    node.ref_cnt = 1;
    URPC_SLIST_INSERT_HEAD(&channel->l_queue_nodes_head, &node, node);
    channel->l_qnum++;
    queue_t *queue = (queue_t *)(uintptr_t)qh;
    (void)__sync_fetch_and_add(&queue->ref_cnt, 1);

    uint64_t id = urpc_func_call(chid, &call_wr, &call_option);
    ASSERT_NE(id, URPC_U64_FAIL);

    urpc_queue_rx_post(qh, &sge, 1);
    // 2. mock poll one tx cqe and one ack rx cqe
    poll_option.urpc_qh = qh;
    ret = urpc_func_poll(chid, &poll_option, msg, 2);
    ASSERT_EQ(ret, 2);
    ASSERT_EQ(msg[0].event, POLL_EVENT_REQ_RSPED);

    URPC_SLIST_REMOVE(&channel->l_queue_nodes_head, &node, queue_node, node);
    channel->l_qnum = 0;
    (void)__sync_fetch_and_sub(&queue->ref_cnt, 1);
    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, 0);

    ret = urpc_channel_destroy(chid);
    ASSERT_EQ(ret, 0);

    ret = urpc_mem_seg_unregister(mem_h);
    ASSERT_EQ(ret, 0);

    free(buf);
}

TEST_F(DatapathTest, TestWrNull)
{
    urpc_qcfg_create_t cfg = {0};
    cfg.create_flag = QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    cfg.rx_depth = 1;
    cfg.tx_depth = 1;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &cfg);
    ASSERT_NE(qh, (uint64_t)URPC_INVALID_HANDLE);

    queue_t *l_queue = (queue_t *)(uintptr_t)qh;
    void *req_ctx = queue_ctx_get(l_queue, QUEUE_CTX_TYPE_REQ);
    ASSERT_NE(req_ctx, nullptr);
    memset(req_ctx, 0, queue_ctx_size_get(QUEUE_CTX_TYPE_REQ));

    int ret = urpc_func_return(qh, req_ctx, nullptr, nullptr);
    ASSERT_EQ(ret, URPC_SUCCESS);

    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, 0);
}

TEST_F(DatapathTest, TestRsp)
{
    MOCKER(is_server_support_quick_reply).stubs().will(returnValue(true));

    urpc_qcfg_create_t cfg = {0};
    cfg.create_flag = QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    cfg.rx_depth = 1;
    cfg.tx_depth = 1;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &cfg);
    ASSERT_NE(qh, (uint64_t)URPC_INVALID_HANDLE);

    urpc_return_wr_t wr = {0};
    urpc_sge_t sge = {0};
    char buf[512];
    sge.addr = (uint64_t)(uintptr_t)buf;
    sge.length = 512;
    wr.rsps = &sge;
    wr.rsps_sge_num = 1;

    req_ctx_t *req_ctx = (req_ctx_t *)queue_ctx_get((queue_t *)(uintptr_t)qh, QUEUE_CTX_TYPE_REQ);
    ASSERT_NE(req_ctx, nullptr);
    memset(req_ctx, 0, sizeof(req_ctx_t));
    int ret = urpc_func_return(qh, req_ctx, &wr, nullptr);
    EXPECT_EQ(ret, -URPC_ERR_REMOTE_QUEUE_ERR);

    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, 0);
}

urma_cr_status_t g_cr_status_mock;
void *g_user_ctx_mock;
ext_ops_t g_ext_ops = {0};

static int urma_poll_jfc_mock(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
    cr[0].status = g_cr_status_mock;
    cr[0].user_ctx = (uint64_t)(uintptr_t)g_user_ctx_mock;
    cr[0].completion_len = 1;
    return 1;
}

static urma_status_t urma_modify_jetty_mock(urma_jetty_t *jetty, urma_jetty_attr_t *attr)
{
    return URMA_SUCCESS;
}

TEST_F(DatapathTest, ProcReadErrMsg) {
    urpc_state_set(URPC_STATE_INIT);
    urpc_poll_msg_t msg[1];
    uint32_t max_msg_num = 1;
    urpc_poll_option_t option = {0};
    option.poll_direction = POLL_DIRECTION_TX;
    urpc_qcfg_create_t qcfg = {0};
    qcfg.create_flag |= QCREATE_FLAG_SKIP_POST_RX;
    qcfg.skip_post_rx = true;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &qcfg);
    ASSERT_NE(qh, URPC_INVALID_HANDLE);
    option.urpc_qh = qh;
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)qh;
    local_queue->local_q.tx_wr_cnt = 1;

    g_ext_ops.func_defined = URPC_UT_FUNC_ID;
    ext_process_register_ops(&g_ext_ops);

    g_cr_status_mock = URMA_CR_WR_UNHANDLED;
    queue_ctx_head_t *ctx_head =
        (queue_ctx_head_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE, 1, sizeof(queue_ctx_head_t) + sizeof(tx_ctx_t));
    tx_ctx_t *tx_ctx = (tx_ctx_t *)(ctx_head + 1);
    tx_ctx->msg_type = URPC_MSG_READ;
    tx_ctx->func_defined = URPC_UT_FUNC_ID;
    tx_ctx->l_qh = qh;
    g_user_ctx_mock = (void *)tx_ctx;
    MOCKER(urma_poll_jfc).stubs().will(invoke(urma_poll_jfc_mock));
    MOCKER(urma_modify_jetty).stubs().will(invoke(urma_modify_jetty_mock));
    ASSERT_EQ(urpc_func_poll(URPC_INVALID_ID_U32, &option, msg, max_msg_num), max_msg_num);

    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST_F(DatapathTest, ProcReadCqe) {
    urpc_state_set(URPC_STATE_INIT);
    urpc_poll_msg_t msg[1];
    uint32_t max_msg_num = 1;
    urpc_poll_option_t option = {0};
    option.poll_direction = POLL_DIRECTION_TX;
    urpc_qcfg_create_t qcfg = {0};
    qcfg.create_flag |= QCREATE_FLAG_SKIP_POST_RX;
    qcfg.skip_post_rx = true;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &qcfg);
    ASSERT_NE(qh, URPC_INVALID_HANDLE);
    option.urpc_qh = qh;
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)qh;
    local_queue->local_q.tx_wr_cnt = 1;
    g_ext_ops.func_defined = URPC_UT_FUNC_ID;
    ext_process_register_ops(&g_ext_ops);

    g_cr_status_mock = URMA_CR_SUCCESS;
    tx_ctx_t tx_ctx = {0};
    tx_ctx.msg_type = URPC_MSG_READ;
    tx_ctx.func_defined = URPC_UT_FUNC_ID;
    tx_ctx.l_qh = qh;
    g_user_ctx_mock = (void *)&tx_ctx;
    MOCKER(urma_poll_jfc).stubs().will(invoke(urma_poll_jfc_mock));
    MOCKER(urma_modify_jetty).stubs().will(invoke(urma_modify_jetty_mock));
    ASSERT_EQ(urpc_func_poll(URPC_INVALID_ID_U32, &option, msg, max_msg_num), max_msg_num);

    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

req_entry_t *g_req_entry;

static req_entry_t *req_entry_query_mock(uint32_t urpc_chid, uint32_t req_id, bool need_lock)
{
    return g_req_entry;
}

void req_entry_put_mock(req_entry_t *req_entry)
{
    return;
}

TEST_F(DatapathTest, ProcAckRspMsg) {
    urpc_state_set(URPC_STATE_INIT);
    urpc_poll_msg_t msg[1];
    uint32_t max_msg_num = 1;
    urpc_poll_option_t option = {0};
    option.poll_direction = POLL_DIRECTION_RX;
    urpc_qcfg_create_t qcfg = {0};
    qcfg.create_flag |= QCREATE_FLAG_SKIP_POST_RX;
    qcfg.skip_post_rx = true;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &qcfg);
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)qh;
    local_q->rq_ctx->rx_wr_cnt = 1;
    ASSERT_NE(qh, URPC_INVALID_HANDLE);
    option.urpc_qh = qh;

    g_ext_ops.func_defined = URPC_UT_FUNC_ID;
    ext_process_register_ops(&g_ext_ops);

    g_cr_status_mock = URMA_CR_SUCCESS;

    rx_user_ctx_head_t *rx_user_ctx_head =
        (rx_user_ctx_head_t *)calloc(1, sizeof(rx_user_ctx_head_t) + sizeof(rx_user_ctx_t));
    rq_ctx_t *rq_ctx = (rq_ctx_t *)calloc(1, sizeof(rq_ctx_t));
    rx_user_ctx_head->rq_ctx = rq_ctx;
    rq_ctx->lock_free = true;
    rx_user_ctx_head->rq_ctx->rx_user_ctx_slab.obj_size = 1;
    rx_user_ctx_t *rx_ctx = (rx_user_ctx_t *)(rx_user_ctx_head + 1);
    char buf[256] = {0};
    urpc_sge_t sges = {.addr = (uint64_t)(uintptr_t)buf, .length = 256};
    rx_ctx->sges = &sges;
    rx_ctx->sge_num = 1;
    rx_ctx->rq_ctx = rq_ctx;
    g_user_ctx_mock = (void *)rx_ctx;

    urpc_req_head_t *head = (urpc_req_head_t *)(uintptr_t)rx_ctx->sges[0].addr;
    head->type = URPC_MSG_ACK_AND_RSP;
    urpc_rsp_head_t *rsp_hdr = (urpc_rsp_head_t *)(uintptr_t)rx_ctx->sges[0].addr;
    rsp_hdr->response_total_size = proto_filed32_put(256);
    rsp_hdr->function_defined = URPC_UT_FUNC_ID;
    rsp_hdr->status = URPC_SUCCESS;

    req_entry_t req_entry = {0};
    (void)pthread_mutex_init(&req_entry.lock, NULL);
    (void)pthread_mutex_lock(&req_entry.lock);
    g_req_entry = &req_entry;

    tx_ctx_t tx_ctx = {0};
    tx_ctx.func_defined = URPC_UT_FUNC_ID;
    req_entry.ctx = (void *)(uintptr_t)&tx_ctx;

    MOCKER(req_entry_put).stubs().will(invoke(req_entry_put_mock));
    MOCKER(urma_poll_jfc).stubs().will(invoke(urma_poll_jfc_mock));
    MOCKER(urma_modify_jetty).stubs().will(invoke(urma_modify_jetty_mock));
    MOCKER(req_entry_query).stubs().will(invoke(req_entry_query_mock));
    ASSERT_EQ(urpc_func_poll(URPC_INVALID_ID_U32, &option, msg, max_msg_num), max_msg_num);

    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);

    free(rq_ctx);
    free(rx_user_ctx_head);
}

TEST(UrpcFuncCallTest, TestWithNullWr) {
    uint32_t chid = 1;
    struct urpc_call_option option = {0};
    uint64_t result = urpc_func_call(chid, NULL, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_EINVAL);
}

TEST(UrpcFuncCallTest, TestWithNullWrArgs)
{
    uint32_t chid = 1;
    urpc_call_wr_t wr = {0};
    struct urpc_call_option option = {0};
    wr.args = NULL;
    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_EINVAL);
}

TEST(UrpcFuncCallTest, TestWithZeroWrArgsNum) {
    uint32_t chid = 1;
    urpc_call_wr_t wr = {0};
    struct urpc_call_option option = {0};
    struct urpc_sge sge = {0};
    wr.args = &sge;
    wr.args_num = 0;
    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_EINVAL);
}

TEST(UrpcFuncCallTest, TestWithLargeWrArgsNum) {
    uint32_t chid = 1;
    urpc_call_wr_t wr = {0};
    struct urpc_call_option option = {0};
    struct urpc_sge sge = {0};
    wr.args = &sge;
    wr.args_num = 33;
    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_EINVAL);
}

TEST(UrpcFuncCallTest, TestWithNotEnoughBuffer) {
    uint32_t chid = 1;
    struct urpc_call_option option = {0};

    char buf[19];
    struct urpc_sge sge = {.addr = (uint64_t)buf, .length = 19};
    struct urpc_call_wr wr = {.func_id = 0, .args = &sge, .args_num = 1};

    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_EINVAL);
}

TEST(UrpcFuncCallTest, TestWithNullOption) {
    uint32_t chid = 1;

    char buf[FISRT_SGE_LENGTH];
    struct urpc_sge sge = {.addr = (uint64_t)buf, .length = FISRT_SGE_LENGTH};
    urpc_call_wr_t wr = {.func_id = 0, .args = &sge, .args_num = 1};

    uint64_t result = urpc_func_call(chid, &wr, NULL);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_EINVAL);
}

TEST(UrpcFuncCallTest, TestWithNullChannel) {
    uint32_t chid = 1;

    char buf[FISRT_SGE_LENGTH];
    struct urpc_sge sge = {.addr = (uint64_t)buf, .length = FISRT_SGE_LENGTH};
    urpc_call_wr_t wr = {.func_id = 0, .args = &sge, .args_num = 1};

    struct urpc_call_option option;
    uint64_t result = urpc_func_call(chid, &wr, &option);
    ASSERT_EQ(result, URPC_U64_FAIL);
    ASSERT_EQ(errno, URPC_ERR_SESSION_CLOSE);
}

TEST(UrpcFuncPollTest, NullMsgTest) {
    urpc_poll_option_t option;
    uint32_t max_msg_num = 10;
    int result = urpc_func_poll(URPC_INVALID_ID_U32, &option, NULL, max_msg_num);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(UrpcFuncPollTest, ZeroMaxMsgNumTest) {
    urpc_poll_option_t option;
    urpc_poll_msg_t msg[10];
    int result = urpc_func_poll(URPC_INVALID_ID_U32, &option, msg, 0);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(UrpcFuncPollTest, NullOptionTest) {
    urpc_poll_msg_t msg[10];
    uint32_t max_msg_num = 10;
    int result = urpc_func_poll(URPC_INVALID_ID_U32, NULL, msg, max_msg_num);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(UrpcFuncPollTest, ChannelIsNull) {
    urpc_poll_msg_t msg[10];
    uint32_t max_msg_num = 10;
    urpc_poll_option_t option;
    option.urpc_qh = URPC_INVALID_HANDLE;
    int result = urpc_func_poll(0, &option, msg, max_msg_num);
    ASSERT_EQ(result, -URPC_ERR_SESSION_CLOSE);
}

TEST(UrpcFuncTest, TestFuncInit) {
    int ret = urpc_func_init(0, 100);
    ASSERT_EQ(0, ret);
    urpc_func_uninit();
}

static void func_test(struct urpc_sge *args, uint32_t args_sge_num, void *ctx, struct urpc_sge **rsps,
    uint32_t *rsps_sge_num)
{
}

#define DEVICE_CLASS 0x001
#define SUB_CLASS 0x001

TEST(UrpcFuncTest, TestFuncRegister) {
    urpc_handler_info_t info;
    uint64_t func_id;
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    // invalid info
    ret = urpc_func_register(NULL, &func_id);
    ASSERT_EQ(-URPC_ERR_EINVAL, ret);

    // invalid func_id
    ret = urpc_func_register(&info, NULL);
    ASSERT_EQ(-URPC_ERR_EINVAL, ret);

    urpc_handler_info_t info1 = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test"};
    ret = urpc_func_register(&info1, &func_id);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    urpc_func_uninit();
}

TEST(UrpcFuncTest, TestFuncExec) {
    uint64_t func_id = UINT64_MAX;
    struct urpc_sge args;
    uint32_t args_sge_num = 0;
    struct urpc_sge *rsps;
    uint32_t rsps_sge_num;
    int ret;

    ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    EXPECT_EQ(ret, 0);

    urpc_handler_info_t info = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test"};
    ret = urpc_func_register(&info, &func_id);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(func_id, (uint64_t)0x001001800004);

    // invalid class
    ret = urpc_func_exec(0x000000800004, &args, args_sge_num, &rsps, &rsps_sge_num);
    EXPECT_EQ(ret, -URPC_ERR_EINVAL);

    // not private
    ret = urpc_func_exec(0x001001000004, &args, args_sge_num, &rsps, &rsps_sge_num);
    EXPECT_EQ(ret, -URPC_ERR_EINVAL);

    // invalid args
    ret = urpc_func_exec(func_id, NULL, args_sge_num, &rsps, &rsps_sge_num);
    EXPECT_EQ(ret, -URPC_ERR_EINVAL);

    // exec func
    char buf[64];
    args.addr = (uint64_t)buf;
    args.length = 64;
    ret = urpc_func_exec(func_id, &args, 1, &rsps, &rsps_sge_num);
    EXPECT_EQ(ret, 0);

    urpc_func_uninit();
}

TEST(UrpcFuncTest, TestFuncIdByteOrder) {
    urpc_handler_info_t info = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test"};
    uint64_t func_id;
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    ret = urpc_func_register(&info, &func_id);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    urpc_req_head_t *req_head = (urpc_req_head_t *)calloc(1, sizeof(urpc_req_head_t));
    ASSERT_NE(req_head, nullptr);
    urpc_req_fill_req_info_without_dma(req_head, func_id, 0, 0, 0);
    ASSERT_EQ(req_head->function, (uint64_t)0x001001800004);

    urpc_func_uninit();
    free(req_head);
}

TEST(UrpcFuncTest, TestFuncUnregister) {
    urpc_handler_info_t info = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test"};
    uint64_t func_id;
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    ret = urpc_func_register(&info, &func_id);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    // invalid class
    ret = urpc_func_unregister(0x000000800004);
    ASSERT_EQ(-URPC_ERR_EINVAL, ret);

    // not private
    ret = urpc_func_unregister(0x001001000004);
    ASSERT_EQ(-URPC_ERR_EINVAL, ret);

    ret = urpc_func_unregister(func_id);
    ASSERT_EQ(0, ret);

    urpc_func_uninit();
}

TEST(UrpcFuncReturnTest, TestFuncReturn)
{
    queue_t queue;
    int ret = urpc_func_return((uint64_t)&queue, nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
}

TEST(UrpcFuncReturnTest, TestInvalidQueueHandle)
{
    urpc_sge_t sge = {0};
    urpc_return_wr_t wr;
    wr.rsps = &sge;
    wr.rsps_sge_num = 1;
    int ret = urpc_func_return(URPC_INVALID_HANDLE, nullptr, &wr, nullptr);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
}

TEST(UrpcFuncIdGetTest, TestFound) {
    urpc_handler_info_t info = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test"};
    uint64_t func_id;
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    ret = urpc_func_register(&info, &func_id);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    func_id = urpc_func_id_get(URPC_INVALID_ID_U32, info.name);
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    ret = urpc_func_unregister(func_id);
    ASSERT_EQ(0, ret);

    urpc_func_uninit();

    func_id = urpc_func_id_get(URPC_INVALID_ID_U32, info.name);
    ASSERT_EQ(func_id, (uint64_t)URPC_INVALID_FUNC_ID);
}

TEST(UrpcFuncIdGetTest, TestInvalidName) {
    uint64_t func_id;
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    func_id = urpc_func_id_get(URPC_INVALID_ID_U32, NULL);
    ASSERT_EQ(func_id, (uint64_t)URPC_INVALID_FUNC_ID);

    urpc_func_uninit();
}

TEST(UrpcFuncIdGetTest, TestNotFound) {
    uint64_t func_id;
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    func_id = urpc_func_id_get(URPC_INVALID_ID_U32, "test");
    ASSERT_EQ(func_id, (uint64_t)URPC_INVALID_FUNC_ID);

    urpc_func_uninit();
}

TEST(UrpcFuncIdGetTest, TestFuncInitFail) {
    // hmap init failed
    MOCKER(urpc_hmap_init).expects(exactly(1)).will(returnValue(-1));
    int ret = urpc_func_init(0, 100);
    ASSERT_EQ(-1, ret);

    // generator init failed
    MOCKER(urpc_id_generator_init).expects(exactly(1)).will(returnValue(-1));
    ret = urpc_func_init(0, 100);
    ASSERT_EQ(-1, ret);

    urpc_func_uninit();
    GlobalMockObject::verify();
}

TEST(UrpcFuncQueryTest, TestFuncTableSuccess) {
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    uint64_t func_id;
    urpc_handler_info_t info = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test"};
    ret = urpc_func_register(&info, &func_id);
    ASSERT_EQ(0, ret);

    // server func id
    func_id = urpc_func_id_get(URPC_INVALID_ID_U32, "func_test");
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    void *addr;
    uint32_t len;
    ret = urpc_func_info_get(&addr, &len);
    ASSERT_EQ(0, ret);
    ASSERT_NE(addr, nullptr);

    struct urpc_hmap table = {0};
    ret = urpc_func_info_set(&table, (uint64_t)addr, len);
    ASSERT_EQ(0, ret);

    // mock set client func_tbl
    MOCKER(urpc_role_get).expects(exactly(1)).will(returnValue(URPC_ROLE_CLIENT));
    uint32_t chid = urpc_channel_create();
    ASSERT_NE(chid, URPC_U32_FAIL);
    urpc_channel_info_t *channel = channel_get(chid);
    channel->func_tbl = table;

    // client func id
    func_id = urpc_func_id_get(chid, "func_test");
    ASSERT_EQ(func_id, (uint64_t)0x001001800004);

    urpc_dbuf_free(addr);
    urpc_func_uninit();
    urpc_channel_destroy(chid);
}

TEST(UrpcFuncQueryTest, TestFuncTableMultiSuccess) {
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    uint64_t func_id1;
    uint64_t func_id2;
    uint64_t func_id3;
    urpc_handler_info_t info1 = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test1"};
    urpc_handler_info_t info2 = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test2"};
    urpc_handler_info_t info3 = {URPC_HANDLER_SYNC, {func_test}, NULL, "func_test3"};
    ret = urpc_func_register(&info1, &func_id1);
    ASSERT_EQ(0, ret);
    ret = urpc_func_register(&info2, &func_id2);
    ASSERT_EQ(0, ret);
    ret = urpc_func_register(&info3, &func_id3);
    ASSERT_EQ(0, ret);

    // server func id
    func_id1 = urpc_func_id_get(URPC_INVALID_ID_U32, "func_test1");
    func_id2 = urpc_func_id_get(URPC_INVALID_ID_U32, "func_test2");
    func_id3 = urpc_func_id_get(URPC_INVALID_ID_U32, "func_test3");
    ASSERT_EQ(func_id1, (uint64_t)0x001001800004);
    ASSERT_EQ(func_id2, (uint64_t)0x001001800005);
    ASSERT_EQ(func_id3, (uint64_t)0x001001800006);

    void *addr;
    uint32_t len;
    ret = urpc_func_info_get(&addr, &len);
    ASSERT_EQ(0, ret);
    ASSERT_NE(addr, nullptr);

    struct urpc_hmap table = {0};
    ret = urpc_func_info_set(&table, (uint64_t)addr, len);
    ASSERT_EQ(0, ret);

    // mock set client func_tbl
    MOCKER(urpc_role_get).expects(exactly(1)).will(returnValue(URPC_ROLE_CLIENT));
    uint32_t chid = urpc_channel_create();
    ASSERT_NE(chid, URPC_U32_FAIL);
    urpc_channel_info_t *channel = channel_get(chid);
    channel->func_tbl = table;

    // client func id
    func_id1 = urpc_func_id_get(chid, "func_test1");
    func_id2 = urpc_func_id_get(chid, "func_test2");
    func_id3 = urpc_func_id_get(chid, "func_test3");
    uint64_t func_id4 = urpc_func_id_get(chid, "func_test4");
    ASSERT_EQ(func_id1, (uint64_t)0x001001800004);
    ASSERT_EQ(func_id2, (uint64_t)0x001001800005);
    ASSERT_EQ(func_id3, (uint64_t)0x001001800006);
    ASSERT_EQ(func_id4, URPC_INVALID_FUNC_ID);

    urpc_dbuf_free(addr);
    urpc_func_uninit();
    urpc_func_tbl_release(&table);
}

TEST(UrpcFuncQueryTest, TestServerNoFunc) {
    int ret = urpc_func_init(DEVICE_CLASS, SUB_CLASS);
    ASSERT_EQ(0, ret);

    void *addr;
    uint32_t len;
    ret = urpc_func_info_get(&addr, &len);
    ASSERT_EQ(0, ret);
    ASSERT_NE(addr, nullptr);

    struct urpc_hmap table = {0};
    ret = urpc_func_info_set(&table, (uint64_t)addr, len);
    ASSERT_EQ(0, ret);

    urpc_dbuf_free(addr);
    urpc_func_uninit();
}
