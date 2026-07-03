/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq ub test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include "umq_api.h"
#include "umq_qbuf_pool.h"
#include "umq_ub_flow_control.h"
#include "umq_ub_private.h"
#include "umq_ub_impl.h"
#include "urma_api.h"
#include "util_id_generator.h"

#define TEST_DEV_NUM 1
static const uint32_t EXAMPLE_BUFFER_SIZE = 8192;
static const uint32_t EXAMPLE_DEPTH = 128;
static urma_device_t dev = {0};
static urma_device_t g_dev_list[TEST_DEV_NUM];
static urma_device_t *g_dev_ptr_list[TEST_DEV_NUM];

urma_device_t **urma_get_device_list_mock(int *num_devices)
{
    *num_devices = 1;
    (void)snprintf(g_dev_list[0].name, URMA_MAX_NAME, "%s", "bonding_dev_0");
    g_dev_list[0].type = URMA_TRANSPORT_UB;
    g_dev_ptr_list[0] = &g_dev_list[0];
    return (urma_device_t **)&g_dev_ptr_list;
}

class UmqUBTest : public ::testing::Test {
  public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
        dev.type = URMA_TRANSPORT_UB;
        static urma_eid_info_t eid_info = {0};
        (void)urma_str_to_eid("127.0.0.1", &eid_info.eid);
        static uint32_t eid_num = 1;
        static urma_context_t urma_ctx = {0};
        urma_ctx.dev = &dev;
        static urma_target_seg_t tseg;
        static urma_device_attr_t dev_attr = {0};
        dev_attr.dev_cap.priority_info[0].tp_type.bs.rtp = 1;
        dev_attr.dev_cap.max_jetty = 65536;
        dev_attr.dev_cap.max_msg_size = 65536;
        dev_attr.dev_cap.max_jfc_depth = 8192;
        dev_attr.dev_cap.max_jfs_depth = 8192;
        dev_attr.dev_cap.max_jfr_depth = 8192;
        dev_attr.dev_cap.max_jfr_sge = 6;
        dev_attr.dev_cap.max_jfs_sge = 6;
        MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_device).stubs()
            .with(mockcpp::any(), outBoundP((urma_device_attr_t *)&dev_attr))
            .will(returnValue(URMA_SUCCESS));
        MOCKER(urma_get_device_by_name).stubs().will(returnValue(&dev));
        MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
        MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
        MOCKER(urma_get_eid_list).stubs()
            .with(mockcpp::any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
            .will(returnValue(&eid_info));
        MOCKER(urma_get_device_list).stubs().will(invoke(urma_get_device_list_mock));
        MOCKER(urma_register_seg).stubs().will(returnValue(&tseg));
        MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());

        static urma_jfr_t jfr = {0};
        static urma_jfc_t jfc = {0};
        static urma_jfce_t jfce = {0};
        static urma_jetty_t jetty = {0};
        static urma_jfr_cfg_t jfr_cfg = {0};
        jetty.jetty_cfg.jfr_cfg = &jfr_cfg;
        static urma_target_jetty target_jetty = {0};
        MOCKER(urma_create_jfr).stubs().will(returnValue(&jfr));
        MOCKER(urma_delete_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfc).stubs().will(returnValue(&jfc));
        MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jetty).stubs().will(returnValue(&jetty));
        MOCKER(urma_delete_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfce).stubs().will(returnValue(&jfce));
        MOCKER(urma_delete_jfce).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_poll_jfc).stubs().will(returnValue(0));
        MOCKER(urma_import_jetty).stubs().will(returnValue(&target_jetty));
        MOCKER(urma_import_seg).stubs().will(returnValue(&tseg));
        MOCKER(urma_bind_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_post_jetty_recv_wr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
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
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
}

TEST_F(UmqUBTest, test_ub_control_plane_success)
{
    umq_init_cfg_t cfg;
    memset(&cfg, 0, sizeof(umq_init_cfg_t));
    int ret;
    uint8_t local_bind_info[512] = {0};
    uint32_t bind_info_size = 512;

    cfg.trans_info_num = 1;
    cfg.feature = UMQ_FEATURE_ENABLE_FLOW_CONTROL;
    cfg.trans_info[0].trans_mode = UMQ_TRANS_MODE_UB;
    cfg.trans_info[0].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
    strcpy(cfg.trans_info[0].dev_info.dev.dev_name, "bonding_dev_0");
    cfg.trans_info[0].dev_info.dev.eid_idx = 0;
    umq_create_option_t option = {
        .trans_mode = cfg.trans_info[0].trans_mode,
        .create_flag = UMQ_CREATE_FLAG_MAIN_UMQ | UMQ_CREATE_FLAG_RX_BUF_SIZE | UMQ_CREATE_FLAG_TX_BUF_SIZE |
                       UMQ_CREATE_FLAG_RX_DEPTH | UMQ_CREATE_FLAG_TX_DEPTH | UMQ_CREATE_FLAG_QUEUE_MODE |\
                       UMQ_CREATE_FLAG_UMQ_CTX,
        .rx_buf_size = EXAMPLE_BUFFER_SIZE,
        .tx_buf_size = EXAMPLE_BUFFER_SIZE,
        .rx_depth = EXAMPLE_DEPTH,
        .tx_depth = EXAMPLE_DEPTH,
        .mode = (umq_queue_mode_t)1};

    ret = umq_init(&cfg);
    ASSERT_EQ(ret, 0);
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);

    sprintf(option.name, "%s", "server");
    (void)memcpy(&option.dev_info, &cfg.trans_info[0].dev_info, sizeof(umq_dev_assign_t));
    uint64_t umqh = umq_create(&option);
    ASSERT_NE(umqh, 0);
    bind_info_size = umq_bind_info_get(umqh, local_bind_info, bind_info_size);

    option.create_flag &= ~UMQ_CREATE_FLAG_MAIN_UMQ;
    option.create_flag |= UMQ_CREATE_FLAG_SHARE_RQ;
    option.create_flag |= UMQ_CREATE_FLAG_SUB_UMQ;
    option.share_rq_umqh = umqh;
    urma_jetty_t jetty1 = {0};
    jetty1.jetty_id.id = 1;
    MOCKER(umq_create_jetty).stubs().will(returnValue(&jetty1));
    uint64_t umqh1 = umq_create(&option);
    ASSERT_NE(umqh1, 0);

    MOCKER(umq_ub_post_rx_inner_impl).stubs().will(returnValue(0));
    MOCKER(umq_ub_shared_credit_req_send).stubs().will(returnValue(0));
    ret = umq_bind(umqh1, local_bind_info, bind_info_size);
    ASSERT_EQ(ret, 0);

    ret = umq_unbind(umqh1);
    ASSERT_EQ(ret, 0);
    umq_destroy(umqh1);
    ASSERT_EQ(ret, 0);
    umq_destroy(umqh);
    ASSERT_EQ(ret, 0);
    umq_uninit();
}

TEST_F(UmqUBTest, test_ub_init_failure)
{
    umq_init_cfg_t cfg;
    memset(&cfg, 0, sizeof(umq_init_cfg_t));
    int ret;

    cfg.trans_info_num = 1;
    cfg.feature = 0;
    cfg.trans_info[0].trans_mode = UMQ_TRANS_MODE_UB;
    cfg.trans_info[0].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
    strcpy(cfg.trans_info[0].dev_info.dev.dev_name, "bonding_dev_0");
    cfg.trans_info[0].dev_info.dev.eid_idx = 0;

    MOCKER(umq_qbuf_pool_init).stubs().will(returnValue(-1));
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);

    MOCKER(umq_io_buf_malloc).stubs().will(returnValue((void *)NULL));
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);

    cfg.trans_info[0].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.trans_info[0].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;

    MOCKER(umq_ub_ctx_imported_info_create).stubs().will(returnValue((remote_imported_tseg_info_t *)NULL));
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);

    MOCKER(urma_init).stubs().will(returnValue(-1));
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);

    MOCKER(umq_ub_id_allocator_init).stubs().will(returnValue(-1));
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);

    MOCKER(calloc).stubs().will(returnValue((void *)NULL));
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
}

TEST_F(UmqUBTest, test_umq_ub_bind_info_check)
{
    ub_queue_t queue;
    memset(&queue, 0, sizeof(queue));
    umq_ub_bind_info_t info;
    memset(&info, 0, sizeof(info));
    umq_ub_bind_version_info_t version;
    memset(&version, 0, sizeof(version));
    umq_ub_bind_dev_info_t dev;
    memset(&dev, 0, sizeof(dev));
    umq_ub_bind_queue_info_t queue_info;
    memset(&queue_info, 0, sizeof(queue_info));
    queue_info.rjetty->trans_mode = URMA_TM_RM;
    umq_ub_bind_fc_info_t fc_info;
    memset(&fc_info, 0, sizeof(fc_info));
    umq_ub_ctx_t dev_ctx;
    memset(&dev_ctx, 0, sizeof(dev_ctx));
    queue.dev_ctx = &dev_ctx;
    urma_jetty_t jetty;
    memset(&jetty, 0, sizeof(jetty));
    queue.jetty[0] = &jetty;

    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);

    info.version_info = &version;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);

    info.dev_info = &dev;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);

    queue.flow_control.enabled = true;
    info.queue_info = &queue_info;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);

    info.fc_info = &fc_info;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);

    dev.umq_trans_mode = UMQ_TRANS_MODE_UB;

    queue.state = QUEUE_STATE_ERR;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);
    queue.state = QUEUE_STATE_READY;

    dev_ctx.trans_info.trans_mode = UMQ_TRANS_MODE_UB;

    queue.tp_mode = URMA_TM_UM;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);
    queue.tp_mode = URMA_TM_RM;

    queue.tp_type = URMA_UTP;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);
    queue.tp_type = URMA_RTP;

    info.dev_info->feature = UMQ_FEATURE_ENABLE_TOKEN_POLICY;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);
    info.dev_info->feature = 0;

    info.dev_info->buf_pool_mode = UMQ_BUF_COMBINE;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);
    info.dev_info->buf_pool_mode = UMQ_BUF_SPLIT;

    info.queue_info->is_binded = true;
    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);
    info.queue_info->is_binded = false;

    ASSERT_NE(umq_ub_bind_info_check(&queue, &info), 0);

    queue.jetty[0]->jetty_id.id++;
    ASSERT_EQ(umq_ub_bind_info_check(&queue, &info), 0);
}

TEST_F(UmqUBTest, test_share_rq_param_check_tx_buf_size_match)
{
    ub_queue_t queue;
    ub_queue_t share_rq;
    memset(&queue, 0, sizeof(queue));
    memset(&share_rq, 0, sizeof(share_rq));

    share_rq.create_flag = UMQ_CREATE_FLAG_MAIN_UMQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    share_rq.state = QUEUE_STATE_READY;
    share_rq.dev_ctx = (umq_ub_ctx_t *)1;
    share_rq.tx_buf_size = EXAMPLE_BUFFER_SIZE;

    queue.create_flag = UMQ_CREATE_FLAG_SHARE_RQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    queue.dev_ctx = (umq_ub_ctx_t *)1;

    ASSERT_EQ(share_rq_param_check(&queue, &share_rq), 0);
    ASSERT_EQ(queue.tx_buf_size, share_rq.tx_buf_size);
}

TEST_F(UmqUBTest, test_share_rq_param_check_tx_buf_size_mismatch)
{
    ub_queue_t queue;
    ub_queue_t share_rq;
    memset(&queue, 0, sizeof(queue));
    memset(&share_rq, 0, sizeof(share_rq));

    share_rq.create_flag = UMQ_CREATE_FLAG_MAIN_UMQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    share_rq.state = QUEUE_STATE_READY;
    share_rq.dev_ctx = (umq_ub_ctx_t *)1;
    share_rq.tx_buf_size = EXAMPLE_BUFFER_SIZE;

    queue.create_flag = UMQ_CREATE_FLAG_SHARE_RQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT |
                        UMQ_CREATE_FLAG_TX_BUF_SIZE;
    queue.dev_ctx = (umq_ub_ctx_t *)1;
    queue.tx_buf_size = EXAMPLE_BUFFER_SIZE * 2;

    ASSERT_NE(share_rq_param_check(&queue, &share_rq), 0);
}

TEST_F(UmqUBTest, test_share_rq_param_check_tx_depth_mismatch)
{
    ub_queue_t queue;
    ub_queue_t share_rq;
    memset(&queue, 0, sizeof(queue));
    memset(&share_rq, 0, sizeof(share_rq));

    share_rq.create_flag = UMQ_CREATE_FLAG_MAIN_UMQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    share_rq.state = QUEUE_STATE_READY;
    share_rq.dev_ctx = (umq_ub_ctx_t *)1;
    share_rq.tx_depth = EXAMPLE_DEPTH;

    queue.create_flag = UMQ_CREATE_FLAG_SHARE_RQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT |
                        UMQ_CREATE_FLAG_TX_DEPTH;
    queue.dev_ctx = (umq_ub_ctx_t *)1;
    queue.tx_depth = EXAMPLE_DEPTH * 2;

    ASSERT_NE(share_rq_param_check(&queue, &share_rq), 0);
}

TEST_F(UmqUBTest, test_share_rq_param_check_share_transport_creating_has_share_rq_no)
{
    ub_queue_t queue;
    ub_queue_t share_rq;
    memset(&queue, 0, sizeof(queue));
    memset(&share_rq, 0, sizeof(share_rq));

    share_rq.create_flag = UMQ_CREATE_FLAG_MAIN_UMQ;
    share_rq.state = QUEUE_STATE_READY;
    share_rq.dev_ctx = (umq_ub_ctx_t *)1;

    queue.create_flag = UMQ_CREATE_FLAG_SHARE_RQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    queue.dev_ctx = (umq_ub_ctx_t *)1;

    ASSERT_NE(share_rq_param_check(&queue, &share_rq), 0);
}

TEST_F(UmqUBTest, test_share_rq_param_check_share_transport_share_rq_has_creating_no)
{
    ub_queue_t queue;
    ub_queue_t share_rq;
    memset(&queue, 0, sizeof(queue));
    memset(&share_rq, 0, sizeof(share_rq));

    share_rq.create_flag = UMQ_CREATE_FLAG_MAIN_UMQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    share_rq.state = QUEUE_STATE_READY;
    share_rq.dev_ctx = (umq_ub_ctx_t *)1;

    queue.create_flag = UMQ_CREATE_FLAG_SHARE_RQ;
    queue.dev_ctx = (umq_ub_ctx_t *)1;

    ASSERT_NE(share_rq_param_check(&queue, &share_rq), 0);
}

TEST_F(UmqUBTest, test_interrupt_fd_get_polling_mode_null_jfce)
{
    ub_queue_t queue;
    memset(&queue, 0, sizeof(queue));

    queue.create_flag = UMQ_CREATE_FLAG_MAIN_UMQ | UMQ_CREATE_FLAG_SHARE_TRANSPORT;
    queue.jetty_node_list = (umq_ub_jetty_node_list_t *)calloc(1, sizeof(umq_ub_jetty_node_list_t));
    ASSERT_NE(queue.jetty_node_list, nullptr);

    queue.jetty_node_list->list_len = 4;
    queue.jetty_node_list->node_list = (jetty_pool_node_t **)calloc(4, sizeof(jetty_pool_node_t *));
    ASSERT_NE(queue.jetty_node_list->node_list, nullptr);

    queue.jetty_node_list->bitmap = urpc_bitmap_alloc(4);
    ASSERT_NE(queue.jetty_node_list->bitmap, nullptr);
    urpc_bitmap_set1(queue.jetty_node_list->bitmap, 0);

    jetty_pool_node_t *node = (jetty_pool_node_t *)calloc(1, sizeof(jetty_pool_node_t));
    ASSERT_NE(node, nullptr);
    node->jfs_jfce = NULL;
    queue.jetty_node_list->node_list[0] = node;

    umq_interrupt_option_t option;
    memset(&option, 0, sizeof(option));
    option.flag = UMQ_INTERRUPT_FLAG_TP_HANDLE_IDX | UMQ_INTERRUPT_FLAG_IO_DIRECTION;
    option.direction = UMQ_IO_TX;
    option.tp_handle_idx = 0;

    int fd = umq_ub_interrupt_fd_get_impl((uint64_t)(uintptr_t)&queue, &option);
    ASSERT_EQ(fd, UMQ_INVALID_FD);

    urpc_bitmap_free(queue.jetty_node_list->bitmap);
    free(node);
    free(queue.jetty_node_list->node_list);
    free(queue.jetty_node_list);
}
