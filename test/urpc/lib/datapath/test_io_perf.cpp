/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib test
 */

#include <stdio.h>
#include <time.h>
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

typedef struct perf_record {
    struct {
        uint64_t begin;
        uint64_t end;
        uint64_t latency;
    } time_record[PERF_RECORD_POINT_MAX];
} perf_record_t;

perf_record_t g_perf_record = {0};

static void perf_func(urpc_perf_record_type_t type, urpc_perf_record_point_t point)
{
    if (type == PERF_RECORD_TYPE_BEGIN) {
        g_perf_record.time_record[point].begin = get_timestamp_ns();
    } if (type == PERF_RECORD_TYPE_END) {
        uint64_t latency = get_timestamp_ns() - g_perf_record.time_record[point].begin;
        g_perf_record.time_record[point].begin = 0;
        g_perf_record.time_record[point].end = 0;
        printf("urpc perf record type[%u], latency:%lu\n", point, latency);
    }
}

static urma_status_t urma_query_device_mock(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    dev_attr->dev_cap.max_msg_size = (1UL << 20);
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

class IOPerfTest : public :: testing::Test {
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
        EXPECT_EQ(urpc_perf_recorder_register(perf_func), URPC_SUCCESS);
    }

    void TearDown() override {
        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
        EXPECT_EQ(urpc_perf_recorder_unregister(), URPC_SUCCESS);
        urpc_allocator_unregister();
        urpc_uninit();
        urpc_default_allocator_uninit();
    }
};

TEST_F(IOPerfTest, TestCallAndPoll)
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

    // 2. mock poll one tx cqe and one ack rx cqe
    urpc_queue_rx_post(qh, &sge, 1);
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