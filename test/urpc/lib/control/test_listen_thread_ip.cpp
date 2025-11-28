/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc listen thread ip test
 */

#include "gtest/gtest.h"
#include "mockcpp/mockcpp.hpp"

#include "cp.h"
#include "dp.h"
#include "ip_handshaker.h"
#include "urpc_framework_api.h"
#include "urma_api.h"
#include "state.h"
#include "urpc_framework_errno.h"

#define DEFAULT_PORT        19875
#define IP_ADDR_LEN         20
#define DEV_NAME_LEN        15
#define MAX_MSG_SIZE        (1UL << 20)

static urma_status_t urma_query_device_mock(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    dev_attr->dev_cap.max_msg_size = MAX_MSG_SIZE;
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

class listen_thread_test : public ::testing::Test {
public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
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
        static urma_jfr_cfg_t jfr_cfg = {0};
        jetty.jetty_cfg.jfr_cfg = &jfr_cfg;
        static urma_target_jetty target_jetty = {0};
        MOCKER(urma_create_jfr).stubs().will(returnValue(&jfr));
        MOCKER(urma_delete_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfc).stubs().will(returnValue(&jfc));
        MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jetty).stubs().will(returnValue(&jetty));
        MOCKER(urma_delete_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_import_jetty).stubs().will(returnValue(&target_jetty));
        MOCKER(urma_advise_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jetty).stubs().will(invoke(urma_query_jetty_mock));
        MOCKER(urma_modify_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jfr).stubs().will(invoke(urma_query_jfr_mock));

        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));

        urma_target_seg_t seg = {0};
        MOCKER(urma_register_seg).stubs().will(returnValue(&seg));
        MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {}

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {}
};

void handshake_sync_callback(void *ctx, int result)
{
    handshaker_callback_ctx_t *notifier = (handshaker_callback_ctx_t *)ctx;
    notifier->result = result;
    (void)sem_post(&notifier->sem);
}

TEST_F(listen_thread_test, TestListenThreadByUrpcFrameworkDefinedCallBack) {
    urpc_log_config_t log_cfg;
    memset(&log_cfg, 0, sizeof(log_cfg));
    log_cfg.log_flag = URPC_LOG_FLAG_LEVEL;
    log_cfg.level = URPC_LOG_LEVEL_DEBUG;
    (void)urpc_log_config_set(&log_cfg);
    // g_send_recv_queue_list, 避免listen线程访问时coredump
    urpc_state_update(URPC_STATE_UNINIT);
    char dev_name[DEV_NAME_LEN] = "xxxx";
    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config_t));
    urpc_config.role = URPC_ROLE_SERVER_CLIENT;
    urpc_config.feature |= URPC_FEATURE_TIMEOUT;
    urpc_config.trans_info_num = 1;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", dev_name);
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);

    urpc_state_update(URPC_STATE_INIT);

    // 创建一个listen_thread
    char ip_addr[URPC_IPV4_SIZE] = "127.0.0.1";
    urpc_host_info_t server;
    memset(&server, 0, sizeof(urpc_host_info_t));
    server.host_type = HOST_TYPE_IPV4;
    memcpy(server.ipv4.ip_addr, ip_addr, strlen(ip_addr));
    server.ipv4.port = DEFAULT_PORT;

    // urpc server start
    EXPECT_EQ(ip_handshaker_init(&server, NULL), URPC_SUCCESS);
    uint32_t id = urpc_channel_create();
    urpc_channel_info_t *channel = channel_get(id);
    ASSERT_NE(channel, nullptr);
    channel->manage_chid = URPC_INVALID_ID_U32;

    urpc_qcfg_create_t q_cfg = {0};
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &q_cfg);
    ASSERT_NE(qh, (uint64_t)URPC_INVALID_HANDLE);
    EXPECT_EQ(urpc_queue_destroy(qh), URPC_SUCCESS);
    EXPECT_EQ(urpc_channel_destroy(channel->id), URPC_SUCCESS);

    urpc_uninit();
}
