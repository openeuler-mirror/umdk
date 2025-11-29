/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc control path test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include <future>
#include "channel.h"
#include "cp.h"
#include "ip_handshaker.h"
#include "cp_vers_compat.h"
#include "queue.h"
#include "state.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "urpc_manage.h"
#include "urpc_thread.h"

class ControlTest : public ::testing::Test {
public:
    void SetUp() override {
        urpc_client_channel_id_allocator_init();
    }

    void TearDown() override {
        urpc_client_channel_id_allocator_uninit();
        GlobalMockObject::verify();
    }
};

TEST(urpc_channel_cfg_get, InvalidChannelId)
{
    uint32_t chid = 0xFFFFFFFF;
    urpc_ccfg_get_t cfg;
    int ret = urpc_channel_cfg_get(chid, &cfg);
    EXPECT_NE(ret, 0);
}

TEST(urpc_channel_cfg_get, NullCfg)
{
    uint32_t chid = 1;
    int ret = urpc_channel_cfg_get(chid, NULL);
    EXPECT_NE(ret, 0);
}

TEST(UrpcChannelQueueQueryTest, TestWithValidChannelId)
{
    // 创建一个有效的通道ID
    uint32_t valid_chid = 1;
    urpc_channel_qinfos_t info;

    // 调用待测试的方法
    int result = urpc_channel_queue_query(valid_chid, &info);

    // 验证结果
    ASSERT_EQ(URPC_FAIL, result);
}

TEST(UrpcChannelQueueQueryTest, TestWithInvalidChannelId)
{
    // 创建一个无效的通道ID
    uint32_t invalid_chid = 0xFFFFFFFF;
    urpc_channel_qinfos_t info;

    // 调用待测试的方法
    int result = urpc_channel_queue_query(invalid_chid, &info);

    // 验证结果
    ASSERT_NE(URPC_SUCCESS, result);
    // 其他验证可以根据实际情况添加
}

TEST(UrpcChannelQueueQueryTest, TestWithNullInfo)
{
    // 创建一个有效的通道ID
    uint32_t valid_chid = 1;
    urpc_channel_qinfos_t *info = NULL;

    // 调用待测试的方法
    int result = urpc_channel_queue_query(valid_chid, info);

    // 验证结果
    ASSERT_NE(URPC_SUCCESS, result);
    // 其他验证可以根据实际情况添加
}

TEST(UrpcChannelQueueAddTest, TestAddWithInvalidChid)
{
    uint32_t chid = 0;
    queue_local_t queue;
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_LOCAL};
    int ret = urpc_channel_queue_add(chid, (uint64_t)(uintptr_t)&queue, attr, &queue_option);
    ASSERT_NE(ret, URPC_SUCCESS);
    // 解释：这个测试用例是为了测试当尝试使用无效的chid添加元素时，是否会返回错误。
}

TEST(UrpcChannelQueueRmTest, TestRmWithInvalidChid)
{
    queue_local_t queue;
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_LOCAL};
    int ret = urpc_channel_queue_rm(0, (uint64_t)(uintptr_t)&queue, attr, &queue_option);
    ASSERT_NE(ret, URPC_SUCCESS);
    // 解释：这个测试用例是为了测试当尝试使用无效的chid添加元素时，是否会返回错误。
}

TEST(UrpcChannelQueueRmTest, TestRmWithInvalidType)
{
    uint64_t qh = 100;
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = (urpc_channel_queue_type_t)3};
    int ret = urpc_channel_queue_rm(0, qh, attr, &queue_option);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
    attr.type = CHANNEL_QUEUE_TYPE_REMOTE;
    ret = urpc_channel_queue_rm(0, 0, attr, &queue_option);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
}

TEST(UrpcChannelQueueAddTest, TestAddWithInvalidType)
{
    uint64_t qh = 100;
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = (urpc_channel_queue_type_t)3};
    int ret = urpc_channel_queue_add(0, qh, attr, &queue_option);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
    attr.type = CHANNEL_QUEUE_TYPE_REMOTE;
    ret = urpc_channel_queue_add(0, 0, attr, &queue_option);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
}

TEST(UrpcChannelQueueErrorStatesGetTest, TestErrorStatesGetWithInvalidQueue)
{
    queue_local_t queue;
    uint64_t stats[ERR_STATS_TYPE_MAX] = {0};
    int ret = urpc_queue_error_stats_get((uint64_t)(uintptr_t)&queue, stats, ERR_STATS_TYPE_MAX);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
}

TEST(UrpcChannelQueueErrorStatesGetTest, TestErrorStatesGetWithValidQueue)
{
    queue_local_t queue;
    uint64_t stats[ERR_STATS_TYPE_MAX] = {0};
    queue.queue.flag.is_remote = false;
    queue.cfg.type = QUEUE_TYPE_NORMAL;
    int ret = urpc_queue_error_stats_get((uint64_t)(uintptr_t)&queue, stats, ERR_STATS_TYPE_MAX);
    ASSERT_EQ(ret, 0);
}

TEST(UrpcQueueGetSetTest, UrpcQueueGetSetTest_1)
{
    // 创建一个urpc通道和队列
    int ret = urpc_queue_cfg_set(0, NULL);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);

    ret = urpc_queue_cfg_get(0, NULL);
    ASSERT_EQ(ret, -URPC_ERR_EINVAL);
}

TEST_F(ControlTest, UrpcQueueGetSetTest_all)
{
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_CLIENT));
    uint32_t channel_id = urpc_channel_create();
    ASSERT_EQ(channel_id, 0u);
    urpc_ccfg_set_t cfg = {.set_flag = CHANNEL_CFG_SET_FLAG_REQ_ENTRY_SIZE};

    // 测试req entry size不是2的幂的情况
    cfg.req_entry_size = 15;
    int ret = urpc_channel_cfg_set(channel_id, &cfg);
    ASSERT_EQ(ret, URPC_FAIL);

    // 测试成功设置req entry size的情况
    cfg.req_entry_size = 16;
    ret = urpc_channel_cfg_set(channel_id, &cfg);
    ASSERT_EQ(ret, URPC_SUCCESS);

    // 查询req entry size设置成功
    urpc_ccfg_get_t ccfg_get;
    ret = urpc_channel_cfg_get(channel_id, &ccfg_get);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ASSERT_EQ(ccfg_get.req_entry_size, cfg.req_entry_size);

    ASSERT_EQ(urpc_channel_destroy(channel_id), URPC_SUCCESS);
}

TEST_F(ControlTest, UrpcChannelCreateTestReturnsZero)
{
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_CLIENT));
    uint32_t channel_id = urpc_channel_create();
    ASSERT_EQ(channel_id, 0u);
    ASSERT_EQ(urpc_channel_destroy(channel_id), URPC_SUCCESS);
}

TEST_F(ControlTest, UrpcChannelDestroyTestDestroyInvalidChannel)
{
    uint32_t channel_id = 0xFFFFFFFF;
    ASSERT_EQ(urpc_channel_destroy(channel_id), -URPC_ERR_EINVAL);
}

TEST_F(ControlTest, UrpcChannelDestroyTestDestroyChannelTwice)
{
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_CLIENT));
    uint32_t channel_id = urpc_channel_create();
    ASSERT_EQ(channel_id, 0u);
    ASSERT_EQ(urpc_channel_destroy(channel_id), URPC_SUCCESS);
    ASSERT_EQ(urpc_channel_destroy(channel_id), -URPC_ERR_EINVAL);
}

TEST_F(ControlTest, UrpcServerStartTest)
{
    urpc_state_set(URPC_STATE_INIT);
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_SERVER));

    ASSERT_EQ(urpc_thread_ctx_init(), URPC_SUCCESS);
    ASSERT_EQ(urpc_manage_init(), URPC_SUCCESS);

    urpc_control_plane_config_t cfg;
    cfg.server.server_type = SERVER_TYPE_IPV4;
    strncpy(cfg.server.ipv4.ip_addr, "127.0.0.1", URPC_IPV4_SIZE);
    cfg.server.ipv4.port = 19875;
    EXPECT_EQ(urpc_server_start(&cfg), URPC_SUCCESS);

    urpc_manage_uninit();
    urpc_thread_ctx_uninit();

    ip_handshaker_uninit();
}

typedef struct manage_test_args {
    uint32_t loop_job_cnt;
    std::promise<bool> cmd_process_promise;
    std::promise<bool> cmd_exception_promise;
} manage_test_args_t;

manage_test_args_t g_manage_test_args[URPC_MANAGE_JOB_TYPE_NUM];

static void loop_job_func(void *args)
{
    manage_test_args_t *test_args = (manage_test_args_t *)(uintptr_t)args;
    test_args->loop_job_cnt++;
}

static void cmd_process_job_func(void *args)
{
    manage_test_args_t *test_args = (manage_test_args_t *)(uintptr_t)args;
    test_args->cmd_process_promise.set_value(true);
}

static void cmd_exception_job_func(void *args)
{
    manage_test_args_t *test_args = (manage_test_args_t *)(uintptr_t)args;
    test_args->cmd_exception_promise.set_value(true);
}

static void test_and_uninit(void)
{
    urpc_manage_uninit();
    urpc_thread_ctx_uninit();

    for (uint32_t i = 0; i < URPC_MANAGE_JOB_TYPE_NUM; i++) {
        EXPECT_EQ(g_manage_test_args[i].loop_job_cnt > 0, true);
    }
}

TEST_F(ControlTest, UrpcServerManageCmdQueue)
{
    urpc_state_set(URPC_STATE_INIT);
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_SERVER));
    std::future<bool> cmd_process_future[URPC_MANAGE_JOB_TYPE_NUM];
    std::future<bool> cmd_exception_future[URPC_MANAGE_JOB_TYPE_NUM];
    for (uint32_t i = 0; i < URPC_MANAGE_JOB_TYPE_NUM; i++) {
        urpc_manage_cmd_queue_enable((urpc_manage_job_type_t)i);
        cmd_process_future[i] = g_manage_test_args[i].cmd_process_promise.get_future();
        cmd_exception_future[i] = g_manage_test_args[i].cmd_exception_promise.get_future();
        urpc_manage_job_register((urpc_manage_job_type_t)i, loop_job_func, &g_manage_test_args[i], 0);
    }

    ASSERT_EQ(urpc_thread_ctx_init(), URPC_SUCCESS);
    ASSERT_EQ(urpc_manage_init(), URPC_SUCCESS);

    for (uint32_t i = 0; i < URPC_MANAGE_JOB_TYPE_NUM; i++) {
        urpc_cmd_queue_t *cmd_queue = urpc_manage_get_cmd_queue((urpc_manage_job_type_t)i);
        ASSERT_NE(cmd_queue, nullptr);
        urpc_cmd_queue_insert(cmd_queue, cmd_process_job_func, cmd_exception_job_func, &g_manage_test_args[i]);
        ASSERT_EQ(cmd_process_future[i].get(), true);
    }
    test_and_uninit();
}

TEST_F(ControlTest, CoverageUrpcServerStartFaile)
{
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_CLIENT));
    urpc_state_set(URPC_STATE_INIT);
    ASSERT_EQ(urpc_server_start(NULL), -URPC_ERR_EPERM);

    urpc_state_set(URPC_STATE_UNINIT);
    ASSERT_EQ(urpc_server_start(NULL), -URPC_ERR_EPERM);
    urpc_state_set(URPC_STATE_INIT);
}

TEST_F(ControlTest, UrpcChannelCfgSetCgfNull)
{
    ASSERT_EQ(urpc_channel_cfg_set(0, NULL), -URPC_ERR_EINVAL);
}

TEST_F(ControlTest, UrpcChannelCfgSetCahnnelNull)
{
    ASSERT_EQ(urpc_channel_cfg_set(0, (urpc_ccfg_set_t *)(void *)1), -URPC_ERR_EINVAL);
}

TEST_F(ControlTest, UrpcChannelCfgSetReqEntrySizeIvalid)
{
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_CLIENT));
    uint32_t channel_id = urpc_channel_create();
    ASSERT_EQ(channel_id, 0u);
    urpc_ccfg_set_t cfg = {.set_flag = CHANNEL_CFG_SET_FLAG_REQ_ENTRY_SIZE};

    // 测试成功设置req entry size的情况
    cfg.req_entry_size = 16;
    urpc_channel_info_t *channel = channel_get(channel_id);
    channel->req_entry_size = 1;
    int ret = urpc_channel_cfg_set(channel_id, &cfg);
    ASSERT_EQ(ret, URPC_FAIL);

    ASSERT_EQ(urpc_channel_destroy(channel_id), URPC_SUCCESS);
}

TEST_F(ControlTest, UrpcChannelCfgSetReqEntryTableNull)
{
    MOCKER(urpc_role_get).stubs().will(returnValue(URPC_ROLE_CLIENT));
    uint32_t channel_id = urpc_channel_create();
    ASSERT_EQ(channel_id, 0u);
    urpc_ccfg_set_t cfg = {.set_flag = CHANNEL_CFG_SET_FLAG_REQ_ENTRY_SIZE};

    // 测试成功设置req entry size的情况
    cfg.req_entry_size = 16;
    req_entry_t req_entry_table;
    urpc_channel_info_t *channel = channel_get(channel_id);
    channel->req_entry_table = &req_entry_table;
    int ret = urpc_channel_cfg_set(channel_id, &cfg);
    ASSERT_EQ(ret, URPC_FAIL);

    channel->req_entry_table = NULL;
    ASSERT_EQ(urpc_channel_destroy(channel_id), URPC_SUCCESS);
}

TEST_F(ControlTest, TestUrpcChannelQueuePair)
{
    urpc_state_t old_state = urpc_state_get();
    urpc_state_set(URPC_STATE_UNINIT);
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    // urpc channel queue pair urpc not ready
    ASSERT_EQ(urpc_channel_queue_pair(URPC_INVALID_ID_U32,
        URPC_INVALID_HANDLE, URPC_INVALID_HANDLE, &queue_option), -URPC_ERR_EPERM);

    // urpc channel queue unpair urpc not ready
    ASSERT_EQ(urpc_channel_queue_unpair(URPC_INVALID_ID_U32, URPC_INVALID_HANDLE, URPC_INVALID_HANDLE, &queue_option),
        -URPC_ERR_EPERM);
    urpc_state_set(old_state);
}

crypto_key_t g_crypto_key = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

int crypto_ssl_gen_crypto_key_mock(crypto_key_t *crypto_key)
{
    *crypto_key = g_crypto_key;
    return URPC_SUCCESS;
}

// 测试neg_msg_v1_serialize函数
TEST(TLV, TestNegMsgV1Serialize)
{
    urpc_neg_msg_v1_t data;
    memset(&data, 0, sizeof(data));
    MOCKER(crypto_ssl_gen_crypto_key).stubs().will(invoke(crypto_ssl_gen_crypto_key_mock));

    int ret = urpc_neg_msg_v1_serialize(&data);
    ASSERT_EQ(URPC_SUCCESS, ret);
    ASSERT_NE(data.data.buffer, nullptr);
    ASSERT_EQ(data.data.len > sizeof(urpc_tlv_head_t), true);

    urpc_neg_msg_v1_buffer_release(&data);
}

// 测试neg_msg_v1_deserialize函数
TEST(TLV, TestNegMsgV1Deserialize)
{
    urpc_neg_msg_v1_t data_input;
    memset(&data_input, 0, sizeof(data_input));
    MOCKER(crypto_ssl_gen_crypto_key).stubs().will(invoke(crypto_ssl_gen_crypto_key_mock));

    int ret = urpc_neg_msg_v1_serialize(&data_input);
    ASSERT_EQ(URPC_SUCCESS, ret);
    ASSERT_NE(data_input.data.buffer, nullptr);
    ASSERT_EQ(data_input.data.len > sizeof(urpc_tlv_head_t), true);

    urpc_neg_msg_v1_t data_output;
    memset(&data_output, 0, sizeof(data_output));
    data_output.data = data_input.data;
    ret = urpc_neg_msg_v1_deserialize(&data_output);
    ASSERT_EQ(URPC_SUCCESS, ret);
    ASSERT_EQ(memcmp(&g_crypto_key, data_output.crypto_key, sizeof(crypto_key_t)), 0);

    urpc_neg_msg_v1_buffer_release(&data_input);
}

static urpc_eid_t g_eid = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe };

void get_eid_mock(provider_t *provider, urpc_eid_t *eid)
{
    *eid = g_eid;
}

TEST(TLV, TestDetachMsgV1SerializeDeserializeWithInValidChannel)
{
    uint32_t server_chid = 1;
    urpc_detach_msg_v1_t data;
    memset(&data, 0, sizeof(data));

    // 测试channel为NULL的情况
    int result = urpc_detach_msg_v1_serialize(NULL, server_chid, &data);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(TLV, TestDetachMsgV1SerializeWithInValidServerChannelId)
{
    provider_ops_t provider_ops;
    provider_ops.get_eid = get_eid_mock;
    provider_t provider;
    provider.ops = &provider_ops;
    urpc_channel_info_t channel;
    channel.provider = &provider;
    urpc_detach_msg_v1_t data;
    memset(&data, 0, sizeof(data));

    // 测试server_chid为URPC_INVALID_ID_U32的情况
    int result = urpc_detach_msg_v1_serialize(&channel, URPC_INVALID_ID_U32, &data);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(TLV, TestDetachMsgV1SerializeWithInValidData)
{
    provider_ops_t provider_ops;
    provider_ops.get_eid = get_eid_mock;
    provider_t provider;
    provider.ops = &provider_ops;
    urpc_channel_info_t channel;
    channel.provider = &provider;
    uint32_t server_chid = 1;
    urpc_detach_msg_v1_t data;
    memset(&data, 0, sizeof(data));

    // 测试data为NULL的情况
    int result = urpc_detach_msg_v1_serialize(&channel, server_chid, NULL);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}


TEST(TLV, TestDetachMsgV1SerializeDeserializeNormal)
{
    provider_ops_t provider_ops;
    provider_ops.get_eid = get_eid_mock;
    provider_t provider;
    provider.ops = &provider_ops;
    urpc_channel_info_t channel;
    channel.provider = &provider;
    uint32_t server_chid = 1;
    urpc_detach_msg_v1_t data;
    memset(&data, 0, sizeof(data));

    // 测试正常情况
    int result = urpc_detach_msg_v1_serialize(&channel, server_chid, &data);
    ASSERT_EQ(result, URPC_SUCCESS);
    ASSERT_NE(data.data.buffer, nullptr);
    ASSERT_EQ(data.data.len > sizeof(urpc_tlv_head_t), true);
    ASSERT_EQ(memcmp(&data.detach_info->key.eid, &g_eid, sizeof(urpc_eid_t)), 0);
    ASSERT_EQ(data.detach_info->key.pid, getpid());
    ASSERT_EQ(data.detach_info->server_chid, server_chid);

    urpc_detach_msg_v1_buffer_release(&data);
}

TEST(TLV, TestDetachMsgV1DeserializeWithInValidDate)
{
    urpc_detach_msg_v1_t output;
    memset(&output, 0, sizeof(output));
    // 测试data的buffer为NULL的情况
    int result = urpc_detach_msg_v1_deserialize(&output);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(TLV, TestDetachMsgV1DeserializeWithNull)
{
    urpc_detach_msg_v1_t output;
    memset(&output, 0, sizeof(output));
    // 测试data为NULL的情况
    int result = urpc_detach_msg_v1_deserialize(NULL);
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST(TLV, TestDetachMsgV1DeserializeWithNormal)
{
    provider_ops_t provider_ops;
    provider_ops.get_eid = get_eid_mock;
    provider_t provider;
    provider.ops = &provider_ops;
    urpc_channel_info_t channel;
    channel.provider = &provider;
    uint32_t server_chid = 1;
    urpc_detach_msg_v1_t data;
    memset(&data, 0, sizeof(data));

    // 测试正常情况
    int result = urpc_detach_msg_v1_serialize(&channel, server_chid, &data);
    urpc_detach_msg_v1_t output;
    memset(&output, 0, sizeof(output));
    output.data = data.data;
    result = urpc_detach_msg_v1_deserialize(&output);
    ASSERT_EQ(result, URPC_SUCCESS);
    ASSERT_EQ(memcmp(&output.detach_info->key.eid, &g_eid, sizeof(urpc_eid_t)), 0);
    ASSERT_EQ(output.detach_info->key.pid, getpid());
    ASSERT_EQ(output.detach_info->server_chid, server_chid);
    urpc_detach_msg_v1_buffer_release(&data);
}

static queue_info_t g_user_queue_info;
static queue_info_t g_manage_queue_info;

void init_user_queue_info(void)
{
    g_user_queue_info.type = QUEUE_TYPE_NORMAL;
    g_user_queue_info.trans_mode = QUEUE_TRANS_MODE_JETTY;
    g_user_queue_info.priority = 2;
    g_user_queue_info.queue_flag = 3;
    g_user_queue_info.qid = 4;
    g_user_queue_info.rx_buf_size = 6;
    g_user_queue_info.timestamp = 7;
    g_user_queue_info.custom_flag = 8;
}

void init_manage_queue_info(void)
{
    g_manage_queue_info.type = QUEUE_TYPE_MAX;
    g_manage_queue_info.trans_mode = QUEUE_TRANS_MODE_MAX;
    g_manage_queue_info.priority = 6;
    g_manage_queue_info.queue_flag = 5;
    g_manage_queue_info.qid = 4;
    g_manage_queue_info.rx_buf_size = 2;
    g_manage_queue_info.timestamp = 1;
    g_manage_queue_info.custom_flag = 0;
}

int user_queue_query_local_queue(queue_t *l_queue, void *ptr)
{
    memcpy(ptr, &g_user_queue_info, sizeof(g_user_queue_info));

    return URPC_SUCCESS;
}

int manage_queue_query_local_queue(queue_t *l_queue, void *ptr)
{
    memcpy(ptr, &g_manage_queue_info, sizeof(g_manage_queue_info));

    return URPC_SUCCESS;
}

static void check_manage_message(urpc_attach_msg_v1_t *data, urpc_attach_msg_input_t *input, uint32_t attr, uint32_t id)
{
    EXPECT_EQ(data->chmsg_arr.chmsgs[0].qinfo_arr.arr_num, input->manage.q_num);
    EXPECT_EQ(memcmp(data->chmsg_arr.chmsgs[0].qinfo_arr.qinfos[0], &g_manage_queue_info, sizeof(queue_info_t)), 0);
    EXPECT_EQ(memcmp(&data->chmsg_arr.chmsgs[0].chinfo->key.eid, &g_eid, sizeof(urpc_eid_t)), 0);
    EXPECT_EQ(data->chmsg_arr.chmsgs[0].chinfo->key.pid, getpid());
    EXPECT_EQ(data->chmsg_arr.chmsgs[0].chinfo->attr, attr);
    EXPECT_EQ(data->chmsg_arr.chmsgs[0].chinfo->chid, id);
    EXPECT_EQ(data->chmsg_arr.chmsgs[0].chinfo->cap.is_support_quik_reply, 1);
}

static void check_user_message(urpc_attach_msg_v1_t *data, urpc_attach_msg_input_t *input, uint32_t attr, uint32_t id)
{
    EXPECT_EQ(data->chmsg_arr.chmsgs[1].qinfo_arr.arr_num, input->user.q_num);
    EXPECT_EQ(memcmp(data->chmsg_arr.chmsgs[1].qinfo_arr.qinfos[0], &g_user_queue_info, sizeof(queue_info_t)), 0);
    EXPECT_EQ(memcmp(&data->chmsg_arr.chmsgs[1].chinfo->key.eid, &g_eid, sizeof(urpc_eid_t)), 0);
    EXPECT_EQ(data->chmsg_arr.chmsgs[1].chinfo->key.pid, getpid());
    EXPECT_EQ(data->chmsg_arr.chmsgs[1].chinfo->attr, attr);
    EXPECT_EQ(data->chmsg_arr.chmsgs[1].chinfo->chid, id);
    EXPECT_EQ(data->chmsg_arr.chmsgs[1].chinfo->cap.is_support_quik_reply, 1);
}

static void check_client_message(urpc_attach_msg_v1_t *data, urpc_attach_msg_input_t *input)
{
    EXPECT_EQ(data->chmsg_arr.arr_num, 2);
    check_manage_message(data, input, input->manage.client_channel->attr, input->manage.client_channel->id);
    check_user_message(data, input, input->user.client_channel->attr,  input->user.client_channel->id);
    EXPECT_EQ(data->attach_info->keepalive_attr, input->attach_info.keepalive_attr);
    EXPECT_EQ(data->attach_info->server_chid, input->attach_info.server_chid);
}

static void check_server_message(urpc_attach_msg_v1_t *data, urpc_attach_msg_input_t *input)
{
    ASSERT_EQ(data->chmsg_arr.arr_num, 2);
    check_manage_message(data, input, URPC_ATTR_MANAGE, input->manage.server_channel_id);
    check_user_message(data, input, 0,  input->user.server_channel_id);
    ASSERT_EQ(data->attach_info->keepalive_attr, input->attach_info.keepalive_attr);
    ASSERT_EQ(data->attach_info->server_chid, input->attach_info.server_chid);
}

static int urpc_instance_key_fill_mock(urpc_instance_key_t *key)
{
    get_eid_mock(NULL, &key->eid);
    key->pid = (uint32_t)getpid();

    return URPC_SUCCESS;
}

// 测试attach_msg_v1_serialize函数
TEST(TLV, TestAttachMsgV1SerializeDeserialize)
{
    urpc_log_config_t log_cfg;
    memset(&log_cfg, 0, sizeof(log_cfg));
    log_cfg.log_flag = URPC_LOG_FLAG_LEVEL;
    log_cfg.level = URPC_LOG_LEVEL_DEBUG;
    (void)urpc_log_config_set(&log_cfg);
    init_user_queue_info();
    init_manage_queue_info();
    provider_ops_t provider_ops;
    provider_ops.get_eid = get_eid_mock;
    provider_t provider;
    provider.ops = &provider_ops;
    urpc_channel_info_t client_user_channel;
    client_user_channel.provider = &provider;
    queue_ops_t user_queue_ops;
    user_queue_ops.query_local_queue = user_queue_query_local_queue;
    queue_t user_queue;
    user_queue.ops = &user_queue_ops;

    urpc_channel_info_t client_manage_channel;
    client_manage_channel.provider = &provider;
    queue_ops_t manage_queue_ops;
    manage_queue_ops.query_local_queue = manage_queue_query_local_queue;
    queue_t manage_queue;
    manage_queue.ops = &manage_queue_ops;

    urpc_attach_msg_input_t input;
    memset(&input, 0, sizeof(input));
    input.is_server = false;
    input.attach_info.keepalive_attr = 123456789;
    input.attach_info.server_chid = 987654321;
    input.user.client_channel = &client_user_channel;
    input.user.q_num = 1;
    input.user.qh[0] = (uint64_t)(uintptr_t)&user_queue;
    input.manage.client_channel = &client_manage_channel;
    input.manage.q_num = 1;
    input.manage.qh[0] = (uint64_t)(uintptr_t)&manage_queue;

    MOCKER(is_feature_enable).stubs().will(returnValue(true));
    MOCKER(urpc_instance_key_fill).stubs().will(invoke(urpc_instance_key_fill_mock));

    urpc_attach_msg_v1_t serialize_data;
    urpc_attach_msg_v1_t deserialize_data;
    memset(&serialize_data, 0, sizeof(serialize_data));
    memset(&deserialize_data, 0, sizeof(deserialize_data));

    // 1. 测试client侧serialize attach msg
    int ret = urpc_attach_msg_v1_serialize(&input, &serialize_data);
    ASSERT_EQ(URPC_SUCCESS, ret);
    ASSERT_EQ(serialize_data.data.len > sizeof(urpc_tlv_head_t), true);
    check_client_message(&serialize_data, &input);

    // 2. 测试client侧deserialize attach msg
    deserialize_data.data = serialize_data.data;
    ret = urpc_attach_msg_v1_deserialize(&deserialize_data);
    ASSERT_EQ(URPC_SUCCESS, ret);
    check_client_message(&deserialize_data, &input);

    urpc_attach_msg_v1_buffer_release(&serialize_data);

    // 3. 测试server侧serialize attach msg
    input.is_server = true;
    input.manage.server_channel_id = 10;
    input.user.server_channel_id = 20;

    ret = urpc_attach_msg_v1_serialize(&input, &serialize_data);
    ASSERT_EQ(URPC_SUCCESS, ret);
    ASSERT_EQ(serialize_data.data.len > sizeof(urpc_tlv_head_t), true);
    check_server_message(&serialize_data, &input);

    // 4. 测试server侧deserialize attach msg
    deserialize_data.data = serialize_data.data;
    ret = urpc_attach_msg_v1_deserialize(&deserialize_data);
    check_server_message(&deserialize_data, &input);

    urpc_attach_msg_v1_buffer_release(&serialize_data);
}

TEST(urpc_channel_server_attach, TestAttachWithNotReady)
{
    urpc_channel_connect_option_t channel_option = {0};
    channel_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    channel_option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    urpc_host_info_t server;
    urpc_state_set(URPC_STATE_UNINIT);
    int ret = urpc_channel_server_attach(0, &server, &channel_option);
    ASSERT_EQ(-URPC_ERR_EPERM, ret);
}

TEST(urpc_channel_server_detach, TestDetachWithNotReady)
{
    urpc_channel_connect_option_t channel_option = {0};
    channel_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    channel_option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    urpc_host_info_t server;
    urpc_state_set(URPC_STATE_UNINIT);
    int ret = urpc_channel_server_detach(0, &server, &channel_option);
    ASSERT_EQ(-URPC_ERR_EPERM, ret);
}

TEST(urpc_channel_server_refresh, TestRefreshWithNotReady)
{
    urpc_channel_connect_option_t channel_option = {0};
    channel_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    channel_option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    urpc_state_set(URPC_STATE_UNINIT);
    int ret = urpc_channel_server_refresh(0, &channel_option);
    ASSERT_EQ(-URPC_ERR_EPERM, ret);
}