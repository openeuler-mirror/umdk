/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc keepalive test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include "cp.h"
#include "dp.h"
#include "state.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "urpc_manage.h"
#include "urpc_thread.h"
#include "urpc_framework_types.h"

#include "keepalive.h"

#define TEST_KEEPALIVE_CYCLE_TIME 6
#define TEST_KEEPALIVE_CHECK_TIME 18
#define TEST_KEEPALIVE_RELEASE_TIME 1

static urma_device_t dev;

static void test_keepalive_callback(urpc_keepalive_event_type_t type, urpc_keepalive_event_info_t info)
{}

static void test_keepalive_cfg_fill(urpc_keepalive_config_t *cfg)
{
    cfg->user_ctx = 0;
    cfg->keepalive_callback = test_keepalive_callback;
    cfg->keepalive_cycle_time = TEST_KEEPALIVE_CYCLE_TIME;
    cfg->keepalive_check_time = TEST_KEEPALIVE_CHECK_TIME;
    cfg->delay_release_time = TEST_KEEPALIVE_RELEASE_TIME;
    cfg->max_msg_size = 0;
    cfg->q_depth = 0;
}

static bool is_feature_enable_mock(uint32_t feature)
{
    return true;
}

class keepalive_test : public ::testing::Test {
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
        static urma_device_attr_t dev_attr = {0};
        dev_attr.dev_cap.max_msg_size = 65536;
        MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_device)
            .stubs()
            .with(any(), outBoundP((urma_device_attr_t *)&dev_attr))
            .will(returnValue(URMA_SUCCESS));
        MOCKER(urma_get_device_by_name).stubs().will(returnValue(&dev));
        MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
        MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
        MOCKER(urma_get_eid_list)
            .stubs()
            .with(any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
            .will(returnValue(&eid_info));

        static urma_jfr_t jfr = {0};
        static urma_jfc_t jfc = {0};
        static urma_jfce_t jfce = {0};
        static urma_jetty_t jetty = {0};
        static urma_jfr_cfg_t jfr_cfg = {0};
        jetty.jetty_cfg.jfr_cfg = &jfr_cfg;
        MOCKER(urma_create_jfr).stubs().will(returnValue(&jfr));
        MOCKER(urma_delete_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfc).stubs().will(returnValue(&jfc));
        MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jetty).stubs().will(returnValue(&jetty));
        MOCKER(urma_delete_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfce).stubs().will(returnValue(&jfce));
        MOCKER(urma_delete_jfce).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_poll_jfc).stubs().will(returnValue(0));
        MOCKER(urma_modify_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_rearm_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_wait_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_post_jetty_send_wr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_SERVER_CLIENT));
        MOCKER(is_feature_enable).stubs().will(invoke(is_feature_enable_mock));

        MOCKER(queue_id_allocator_free).stubs().will(ignoreReturnValue());
        urpc_trans_info_t cfg = {.trans_mode = URPC_TRANS_MODE_UB, .assign_mode = DEV_ASSIGN_MODE_DEV,};
        (void)snprintf(cfg.dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "lo");
        provider_flag_t flag = {0};
        int ret = provider_init(1, &cfg, flag);
        ASSERT_EQ(ret, URPC_SUCCESS);
        urpc_state_set(URPC_STATE_INIT);

        ret = urpc_timing_wheel_init();
        ASSERT_EQ(ret, 0);

        ASSERT_EQ(urpc_thread_ctx_init(), URPC_SUCCESS);
        urpc_manage_uninit();
        ASSERT_EQ(urpc_manage_init(), URPC_SUCCESS);
        ASSERT_EQ(queue_id_allocator_init(), URPC_SUCCESS);

        urpc_keepalive_config_t keepalive_cfg;
        test_keepalive_cfg_fill(&keepalive_cfg);
        ret = urpc_keepalive_init(&keepalive_cfg);
        ASSERT_EQ(ret, URPC_SUCCESS);
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        urpc_manage_uninit();
        urpc_thread_ctx_uninit();

        urpc_keepalive_uninit();
        urpc_timing_wheel_uninit();
        queue_id_allocator_uninit();
        provider_uninit();

        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {}

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {}
};

TEST_F(keepalive_test, keepalive_init_uninit_test)
{
    uint64_t qh = urpc_keepalive_queue_handle_get();
    EXPECT_NE(qh, (uint64_t)0);
    uint32_t cycle = urpc_keepalive_cycle_time_get();
    EXPECT_EQ(cycle, (uint32_t)TEST_KEEPALIVE_CYCLE_TIME);
    uint32_t check_time = urpc_keepalive_check_time_get();
    EXPECT_EQ(check_time, (uint32_t)TEST_KEEPALIVE_CHECK_TIME);
    uint32_t release_time = urpc_keepalive_release_time_get();
    EXPECT_EQ(release_time, (uint32_t)TEST_KEEPALIVE_RELEASE_TIME);
    keepalive_callback_t cb = urpc_keepalive_callback_get();
    EXPECT_EQ(cb, test_keepalive_callback);
}

TEST_F(keepalive_test, client_keepalive_task_create_and_delete_test)
{
    urpc_server_info_t server;
    urpc_host_info_t host;
    memset(&server, 0, sizeof(server));
    server.server_type = SERVER_TYPE_IPV4;
    (void)snprintf(server.ipv4.ip_addr, URPC_IPV4_SIZE, "127.0.0.1");

    parse_server_to_host(&server, &host, NULL);
    urpc_keepalive_task_info_t info = {0};
    info.server = &host;
    info.remote_version = 1;
    info.is_server = URPC_FALSE;
    info.remote_primary_is_server = URPC_TRUE;

    int ret;
    urpc_instance_key_t instance = {0};
    // 2. create keepalive task
    ret = urpc_keepalive_task_create(&instance, &info);
    ASSERT_EQ(ret, URPC_SUCCESS);

    urpc_keepalive_id_t id = {0};
    urpc_keepalive_event_info_t event_info = {0};
    event_info.user_ctx = 1;
    ret = urpc_keepalive_task_entry_info_get(&id, false, &event_info);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(event_info.user_ctx, (uint64_t)0);

    ret = keepalive_task_stop(&instance, &info);
    EXPECT_EQ(ret, URPC_SUCCESS);

    ret = keepalive_task_restart(&instance, &info);
    EXPECT_EQ(ret, URPC_SUCCESS);

    EXPECT_EQ(urpc_keepalive_task_primary_is_client(&instance), true);

    urpc_keepalive_task_delete(&instance, &info);
}

TEST_F(keepalive_test, server_keepalive_task_create_and_delete_test)
{
    int ret;
    urpc_keepalive_task_info_t info = {0};
    info.remote_version = 1;
    info.is_server = URPC_TRUE;

    urpc_instance_key_t instance = {0};
    ret = urpc_keepalive_task_create(&instance, &info);
    ASSERT_EQ(ret, URPC_SUCCESS);

    info.server_chid = 1;
    ret = urpc_keepalive_task_server_chid_add(&instance, &info);
    EXPECT_EQ(ret, 0);

    urpc_keepalive_id_t id = {0};
    urpc_keepalive_task_timestamp_update(&id, true);

    urpc_keepalive_event_info_t event_info = {0};
    event_info.user_ctx = 1;
    ret = urpc_keepalive_task_entry_info_get(&id, true, &event_info);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(event_info.user_ctx, (uint64_t)0);

    info.server_chid = 0;
    urpc_keepalive_task_delete(&instance, &info);
}

TEST_F(keepalive_test, urpc_keepalive_task_add_logic_client)
{
    urpc_host_info_t server;
    memset(&server, 0, sizeof(server));
    server.host_type = HOST_TYPE_IPV4;
    (void)snprintf(server.ipv4.ip_addr, URPC_IPV4_SIZE, "127.0.0.1");
 
    urpc_keepalive_task_info_t info = {0};
    info.server = &server;
    info.remote_version = 1;
    info.is_server = URPC_FALSE;
    info.remote_primary_is_server = URPC_TRUE;
 
    urpc_instance_key_t instance = {0};
    // 1. create keepalive task
    int ret = urpc_keepalive_task_create(&instance, &info);
    ASSERT_EQ(ret, URPC_SUCCESS);
 
    ret = urpc_keepalive_task_create(&instance, &info);
    ASSERT_EQ(ret, URPC_SUCCESS);
 
    urpc_keepalive_task_delete(&instance, &info);
}
 
TEST_F(keepalive_test, urpc_keepalive_task_add_logic_server)
{
    urpc_host_info_t server;
    memset(&server, 0, sizeof(server));
    server.host_type = HOST_TYPE_IPV4;
    (void)snprintf(server.ipv4.ip_addr, URPC_IPV4_SIZE, "127.0.0.1");
 
    urpc_keepalive_task_info_t info = {0};
    info.server = &server;
    info.remote_version = 1;
    info.is_server = URPC_TRUE;
    info.remote_primary_is_server = URPC_TRUE;
 
    urpc_instance_key_t instance = {0};
    // 1. create keepalive task
    int ret = urpc_keepalive_task_create(&instance, &info);
    ASSERT_EQ(ret, URPC_SUCCESS);
 
    ret = urpc_keepalive_task_create(&instance, &info);
    ASSERT_EQ(ret, URPC_SUCCESS);
 
    urpc_keepalive_task_delete(&instance, &info);
}

char g_keepalive_buffer[URPC_KEEPALIVE_HDR_SIZE] = {0};
urpc_sge_t g_keepalive_sge = {.addr = (uint64_t)(uintptr_t)&g_keepalive_buffer, .length = URPC_KEEPALIVE_HDR_SIZE};

static int get_func_mock(urpc_sge_t **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option)
{
    *sge = &g_keepalive_sge;
    *num = 1;
    return URPC_SUCCESS;
}

static int put_func_mock(urpc_sge_t *sge, uint32_t num, urpc_allocator_option_t *option)
{
    return URPC_SUCCESS;
}

urpc_allocator_t g_allocator_mock = {0};

urpc_allocator_t *allocator_get_mock()
{
    return &g_allocator_mock;
}

static uint32_t crypto_security_field_size_get_mock(void)
{
    return 0;
}

TEST_F(keepalive_test, test_keepalive_probe_process_default_msg)
{
    g_allocator_mock.put = put_func_mock;
    char buf[256] = {0};
    urpc_sge_t sge = {.addr = (uint64_t)(uintptr_t)&buf, .length = 0};

    urpc_poll_msg_t msgs;
    msgs.event = POLL_EVENT_REQ_ERR;
    msgs.req_err.args = &sge;
    msgs.req_err.args_sge_num = 1;

    int poll_num = 1;
    urpc_poll_option_t poll_opt = {0};

    MOCKER(default_allocator_get).stubs().will(invoke(allocator_get_mock));
    urpc_keepalive_process_msg(&msgs, poll_num, &poll_opt);
    ASSERT_EQ(msgs.event, POLL_EVENT_REQ_ERR);

    msgs.event = POLL_EVENT_ERR;
    sge.length = 256;
    urpc_keepalive_process_msg(&msgs, poll_num, &poll_opt);
    ASSERT_EQ(msgs.event, POLL_EVENT_ERR);

    msgs.event = POLL_EVENT_REQ_ACKED;
    urpc_keepalive_process_msg(&msgs, poll_num, &poll_opt);
    ASSERT_EQ(msgs.event, POLL_EVENT_REQ_ACKED);
}

TEST_F(keepalive_test, test_keepalive_sge_put)
{
    urpc_keepalive_task_entry_t entry = {0};
    urpc_channel_info_t channel = {0};
    queue_t remote_q = {0};
    MOCKER(channel_get).stubs().will(returnValue(&channel));
    MOCKER(channel_get_remote_queue_by_flag).stubs().will(returnValue(&remote_q));

    g_allocator_mock.put = put_func_mock;
    g_allocator_mock.get = get_func_mock;
    MOCKER(default_allocator_get).stubs().will(invoke(allocator_get_mock));
    MOCKER(crypto_security_field_size_get).stubs().will(invoke(crypto_security_field_size_get_mock));

    MOCKER(urpc_func_call).stubs().will(returnValue(URPC_U64_FAIL));
    ASSERT_EQ(urpc_keepalive_request_send(&entry), URPC_FAIL);
}

TEST_F(keepalive_test, test_keepalive_sge_construct_v0_func)
{
    urpc_keepalive_task_entry_t entry = {0};
    urpc_channel_info_t channel = {0};
    queue_t remote_q = {0};
    MOCKER(channel_get).stubs().will(returnValue(&channel));
    MOCKER(channel_get_remote_queue_by_flag).stubs().will(returnValue(&remote_q));

    g_allocator_mock.put = put_func_mock;
    g_allocator_mock.get = get_func_mock;
    MOCKER(default_allocator_get).stubs().will(invoke(allocator_get_mock));
    MOCKER(crypto_security_field_size_get).stubs().will(invoke(crypto_security_field_size_get_mock));
    MOCKER(urpc_func_call).stubs().will(returnValue(1));
    ASSERT_EQ(urpc_keepalive_request_send(&entry), URPC_SUCCESS);
}

class KeepaliveTestNoThing : public :: testing::Test {
public:
    void SetUp() override {
    }

    void TearDown() override {
        GlobalMockObject::verify();
    }
};


#define TEST_KEEPALIVE_TASK_INITFALG_SIZE 4
int urpc_keepalive_task_init_flag[TEST_KEEPALIVE_TASK_INITFALG_SIZE] = {0, 0, 0, -1};
uint32_t urpc_keepalive_task_init_flag_idx = 0;
int urpc_hmap_init_stud(struct urpc_hmap *hmap, uint32_t count)
{
    return urpc_keepalive_task_init_flag[urpc_keepalive_task_init_flag_idx++ % TEST_KEEPALIVE_TASK_INITFALG_SIZE];
}
void urpc_hmap_uninit_stud(struct urpc_hmap *hmap)
{
}

TEST_F(KeepaliveTestNoThing, urpc_keepalive_task_init_err)
{
    MOCKER(urpc_hmap_init).stubs().will(invoke(urpc_hmap_init_stud));
    MOCKER(urpc_hmap_uninit).stubs().will(invoke(urpc_hmap_uninit_stud));

    // server info map 初始化失败
    urpc_keepalive_task_init_flag_idx = 0;
    urpc_keepalive_task_init_flag[3] = -1;
    ASSERT_EQ(urpc_keepalive_task_init(), URPC_FAIL);

    // task map 初始化失败
    urpc_keepalive_task_init_flag_idx = 0;
    urpc_keepalive_task_init_flag[2] = -1;
    ASSERT_EQ(urpc_keepalive_task_init(), URPC_FAIL);

    // server id map 初始化失败
    urpc_keepalive_task_init_flag_idx = 0;
    urpc_keepalive_task_init_flag[1] = -1;
    ASSERT_EQ(urpc_keepalive_task_init(), URPC_FAIL);

    // client id map 初始化失败
    urpc_keepalive_task_init_flag_idx = 0;
    urpc_keepalive_task_init_flag[0] = -1;
    ASSERT_EQ(urpc_keepalive_task_init(), URPC_FAIL);
    // 覆盖无效参数
    urpc_keepalive_id_t id;
    urpc_instance_key_t key;
    urpc_keepalive_task_info_t info;
    memset(&id, 1, sizeof(urpc_keepalive_id_t));
    memset(&key, 1, sizeof(urpc_instance_key_t));
    memset(&info, 1, sizeof(urpc_keepalive_task_info_t));

    // entry 不存在的场景
    ASSERT_EQ(urpc_keepalive_task_server_chid_add(&key, &info), URPC_FAIL);
    urpc_keepalive_task_server_chid_delete(&key, &info);
    ASSERT_EQ(urpc_keepalive_msg_send(&id), URPC_FAIL);
    MOCKER(urpc_dbuf_calloc).stubs().will(returnValue((void *)NULL));
    urpc_keepalive_task_create(&key, &info);
    info.is_server = true;
    keepalive_task_restart(&key, &info);
    keepalive_task_stop(&key, &info);
    GlobalMockObject::verify();
}

TEST_F(KeepaliveTestNoThing, urpc_keepalive_task_timeout)
{
    MOCKER(urpc_keepalive_cycle_time_get).stubs().will(returnValue(1));
    MOCKER(is_feature_enable).stubs().will(returnValue(true));
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_SERVER_CLIENT));
    MOCKER(urpc_hmap_init).stubs().will(returnValue(URPC_FAIL));
    uint64_t cpu_cycle_start = 0;
    urpc_state_set(URPC_STATE_INIT);
    ASSERT_EQ(urpc_keepalive_task_init(), URPC_FAIL);

    urpc_keepalive_check((void *)&cpu_cycle_start);
    GlobalMockObject::verify();
}