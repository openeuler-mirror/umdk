/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc channel test
 */
 
#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"
#include "mockcpp/mockcpp.hpp"
#include <sys/eventfd.h>
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_framework_types.h"
#include "urpc_framework_errno.h"

#include "state.h"
#include "channel.h"
#include "client_manage_channel.h"
#include "queue.h"
#include "dp.h"
#include "cp.h"
#include "cp_vers_compat.h"
#include "urpc_dbuf_stat.h"
#include "urpc_list.h"

#define MAX_MSG_SIZE (1UL << 20)

static urma_device_t g_test_dev = {0};
static int g_notifier_fd = -1;
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

class ChannelTest : public ::testing::Test {
public:
    void SetUp() override {
    }

    void TearDown() override {
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {
        g_test_dev.type = URMA_TRANSPORT_UB;
        static urma_eid_info_t eid_info = {0};
        (void)urma_str_to_eid("127.0.0.1", &eid_info.eid);
        static uint32_t eid_num = 1;
        static urma_context_t urma_ctx = {0};
        urma_ctx.dev = &g_test_dev;
        MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
        MOCKER(urma_get_device_by_name).stubs().will(returnValue(&g_test_dev));
        MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
        MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
        urma_notifier_t notifier;
        g_notifier_fd = eventfd(0, EFD_NONBLOCK);
        notifier.fd = g_notifier_fd;
        MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
        MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_get_eid_list)
        .stubs()
        .with(any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
        .will(returnValue(&eid_info));

        static urma_jfr_t jfr = {0};
        static urma_jfc_t jfc = {0};
        static urma_jetty_t jetty = {0};
        static urma_target_jetty target_jetty = {0};
        static urma_target_seg_t tseg;
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
        MOCKER(urma_query_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_poll_jfc).stubs().will(returnValue(0));
        MOCKER(urma_register_seg).stubs().will(returnValue(&tseg));
        MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jetty).stubs().will(invoke(urma_query_jetty_mock));
        MOCKER(urma_modify_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jfr).stubs().will(invoke(urma_query_jfr_mock));

        urpc_config_t urpc_config = { .role = URPC_ROLE_CLIENT };
        urpc_config.feature |= URPC_FEATURE_TIMEOUT;
        urpc_config.trans_info_num = 1;
        urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
        urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
        (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "lo");
        urpc_state_set(URPC_STATE_UNINIT);

        int ret = urpc_init(&urpc_config);

        ASSERT_EQ(ret, URPC_SUCCESS);
    }

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {
        urpc_uninit();
        GlobalMockObject::verify();
    }
};

TEST_F(ChannelTest, channel_alloc_test) {
    // 测试channel_alloc是否返回非空指针
    urpc_channel_info_t *channel_1 = channel_alloc();
    ASSERT_NE(channel_1, nullptr);
    ASSERT_EQ(channel_1->id, 0u);
    ASSERT_EQ(channel_1->status, URPC_CHANNEL_IDLE);

    urpc_channel_info_t *channel_2 = channel_alloc();
    ASSERT_NE(channel_2, nullptr);
    ASSERT_EQ(channel_2->id, 1u);
    ASSERT_EQ(channel_2->status, URPC_CHANNEL_IDLE);

    // 调用channel_free函数
    int result = channel_free(channel_1->id);
    // 验证channel_free函数返回0，表示成功释放通道
    ASSERT_EQ(result, URPC_SUCCESS);
    // 调用channel_free函数
    result = channel_free(channel_2->id);
    // 验证channel_free函数返回0，表示成功释放通道
    ASSERT_EQ(result, URPC_SUCCESS);

    urpc_channel_info_t *channel_3 = channel_alloc();
    ASSERT_NE(channel_3, nullptr);
    ASSERT_EQ(channel_3->id, 1u);
    ASSERT_EQ(channel_3->status, URPC_CHANNEL_IDLE);

    // 调用channel_free函数
    result = channel_free(channel_3->id);
    // 验证channel_free函数返回0，表示成功释放通道
    ASSERT_EQ(result, URPC_SUCCESS);
}

TEST_F(ChannelTest, channel_free_test_with_invalid_channel_id) {
    // 创建一个无效的通道ID
    uint32_t chid = 1;

    // 调用channel_free函数
    int result = channel_free(chid);

    // 验证channel_free函数返回-EINVAL，表示无法释放无效的通道
    ASSERT_EQ(result, -URPC_ERR_EINVAL);
}

TEST_F(ChannelTest, channel_free_test_with_already_freed_channel_id) {
    // 创建一个已经被释放的通道ID
    urpc_channel_info_t *channel = channel_alloc();
    ASSERT_NE(channel, nullptr);

    int id = channel->id;
    // 调用channel_free函数两次
    int result1 = channel_free(id);
    int result2 = channel_free(id);

    // 验证第一次调用channel_free函数返回0，表示成功释放通道
    ASSERT_EQ(result1, URPC_SUCCESS);
    // 验证第二次调用channel_free函数返回-URPC_ERR_EINVAL，表示无法释放已经被释放的通道
    ASSERT_EQ(result2, -URPC_ERR_EINVAL);
}

TEST(channel_queue_query, test_with_local_queue) {
    urpc_channel_info_t channel;
    urpc_channel_qinfos_t info;
    queue_node_t node1, node2;
    queue_t queue1, queue2;
    server_node_t server_node;

    // 初始化数据
    pthread_spin_init(&channel.lock, 0);
    (void)pthread_rwlock_init(&channel.rw_lock, NULL);
    channel.l_qnum = 2;
    URPC_SLIST_INIT(&channel.l_queue_nodes_head);
    URPC_SLIST_INSERT_HEAD(&channel.l_queue_nodes_head, &node1, node);
    URPC_SLIST_INSERT_HEAD(&channel.l_queue_nodes_head, &node2, node);
    node1.urpc_qh = (uint64_t)(uintptr_t)&queue1;
    node2.urpc_qh = (uint64_t)(uintptr_t)&queue2;
    queue1.ref_cnt = 1;
    queue2.ref_cnt = 2;

    urpc_list_init(&channel.server_nodes_list);
    urpc_list_push_back(&channel.server_nodes_list, &server_node.node);
    server_node.urpc_qh_count = 0;

    // 调用函数
    channel_queue_query(&channel, &info);

    // 验证结果
    ASSERT_EQ(info.l_qnum, 2);
    EXPECT_EQ(info.l_qinfo[0].ref_cnt, (uint32_t)2);
    EXPECT_EQ(info.l_qinfo[1].ref_cnt, (uint32_t)1);
    ASSERT_EQ(info.r_qnum, 0);
}

TEST(channel_queue_query, test_with_remote_queue) {
    urpc_channel_info_t channel;
    urpc_channel_qinfos_t info;
    queue_t queue1, queue2;
    server_node_t server_node;

    // 初始化数据
    pthread_spin_init(&channel.lock, 0);
    (void)pthread_rwlock_init(&channel.rw_lock, NULL);
    channel.l_qnum = 0;
    URPC_SLIST_INIT(&channel.l_queue_nodes_head);
    urpc_list_init(&channel.server_nodes_list);
    urpc_list_push_back(&channel.server_nodes_list, &server_node.node);
    server_node.urpc_qh_count = 2;
    server_node.urpc_qh = (uint64_t *)malloc(sizeof(uint64_t) * 2);
    server_node.urpc_qh[0] = (uint64_t)(uintptr_t)&queue1;
    server_node.urpc_qh[1] = (uint64_t)(uintptr_t)&queue2;
    queue1.ref_cnt = 1;
    queue2.ref_cnt = 2;

    // 调用函数
    channel_queue_query(&channel, &info);

    // 验证结果
    ASSERT_EQ(info.l_qnum, 0);
    ASSERT_EQ(info.r_qnum, 2);
    ASSERT_EQ(info.r_qinfo[0].ref_cnt, (uint32_t)1);
    ASSERT_EQ(info.r_qinfo[1].ref_cnt, (uint32_t)2);

    free(server_node.urpc_qh);
}

TEST_F(ChannelTest, ChannelRemoveServerTypeIP)
{
    urpc_channel_info_t *channel = channel_alloc();
    ASSERT_NE(channel, nullptr);
    urpc_endpoints_t server[3];
    server[0].server.host_type = HOST_TYPE_IPV4;
    server[0].server.ipv4.port = 0;
    strncpy(server[0].server.ipv4.ip_addr, "192.168.0.10", URPC_IPV4_SIZE);

    server[1].server.host_type = HOST_TYPE_IPV6;
    server[1].server.ipv6.port = 0;
    strncpy(server[1].server.ipv6.ip_addr, "1234:abcd::101:175", URPC_IPV6_SIZE);

    server[2].server.host_type = HOST_TYPE_IPV6;
    server[2].server.ipv6.port = 0;
    strncpy(server[2].server.ipv6.ip_addr, "1234:abcd::0101:0175", URPC_IPV6_SIZE);

    queue_info_t qinfo;
    memset(&qinfo, 0, sizeof(queue_info_t));
    qinfo.trans_mode = QUEUE_TRANS_MODE_JETTY;
    urpc_chinfo_t chinfo;
    memset(&chinfo, 0, sizeof(urpc_chinfo_t));
    urpc_chmsg_v1_t chmsg;
    memset(&chmsg, 0, sizeof(urpc_chmsg_v1_t));
    chmsg.chinfo = &chinfo;
    chmsg.chinfo->cap.is_support_quik_reply = true;
    chmsg.qinfo_arr.arr_num = 1;
    chmsg.qinfo_arr.qinfos[0] = &qinfo;

    bool put = channel_put_remote_queue_infos(channel, 0, &server[0], (void *)&chmsg);
    EXPECT_TRUE(put);
    put = channel_put_remote_queue_infos(channel, 0, &server[1], (void *)&chmsg);
    EXPECT_TRUE(put);

    size_t num = urpc_list_size(&channel->server_nodes_list);
    EXPECT_EQ(num, (size_t)2);

    (void)channel_remove_server(channel, &server[0].server);
    (void)channel_remove_server(channel, &server[2].server);

    //server[1] and server[2] is same, should be removed successfully
    num = urpc_list_size(&channel->server_nodes_list);
    EXPECT_EQ(num, (size_t)0);

    int ret = channel_free(channel->id);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST_F(ChannelTest, test_channel_get_server_node_by_chid) {
    // 创建一个urpc_channel_info_t实例
    urpc_channel_info_t channel;
    memset(&channel, 0, sizeof(urpc_channel_info_t));
    urpc_list_init(&channel.server_nodes_list);

    // 创建一些server_node_t实例
    server_node_t node1, node2, node3;
    node1.server_chid = 1;
    node2.server_chid = 2;
    node3.server_chid = 3;

    // 将这些实例添加到channel的server_nodes_list中
    urpc_list_push_back(&channel.server_nodes_list, &node1.node);
    urpc_list_push_back(&channel.server_nodes_list, &node2.node);
    urpc_list_push_back(&channel.server_nodes_list, &node3.node);

    // 测试server_chid为1的情况
    ASSERT_EQ(&node1, channel_get_server_node_by_chid(&channel, 1));

    // 测试server_chid为2的情况
    ASSERT_EQ(&node2, channel_get_server_node_by_chid(&channel, 2));

    // 测试server_chid为3的情况
    ASSERT_EQ(&node3, channel_get_server_node_by_chid(&channel, 3));

    // 测试server_chid为4的情况，应该返回NULL
    ASSERT_EQ(NULL, channel_get_server_node_by_chid(&channel, 4));
}

TEST(ChannelAllocTest, channel_alloc_test_with_invalid_channel_id) {
    MOCKER(channel_id_allocator_get).stubs().will(returnValue(URPC_MAX_CHANNELS));
    urpc_channel_info_t *channel_1 = channel_alloc();
    ASSERT_EQ(channel_1, nullptr);
    GlobalMockObject::verify();
}

TEST(req_entry_query_test, test_with_invalid_channel_id) {
    req_entry_t *entry = req_entry_query(URPC_MAX_CHANNELS, 0, false);
    ASSERT_EQ(entry, nullptr);

    entry = req_entry_query(0, 0, false);
    ASSERT_EQ(entry, nullptr);
}

TEST(channel_get_cur_poll_queue_test, test_with_cur_poll_queue_is_null) {
    urpc_channel_info_t channel;
    (void)pthread_rwlock_init(&channel.rw_lock, NULL);
    pthread_spin_init(&channel.lock, 0);
    channel.cur_poll_queue = NULL;
    URPC_SLIST_INIT(&channel.l_queue_nodes_head);

    queue_t *queue = channel_get_cur_poll_queue(&channel);
    ASSERT_EQ(queue, nullptr);
}

class ChannelGetQueueTest : public ::testing::Test {
public:
    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase() {
        urpc_client_channel_id_allocator_init();
    }

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase() {
        urpc_client_channel_id_allocator_uninit();
        GlobalMockObject::verify();
    }
};

TEST_F(ChannelGetQueueTest, test_with_invalid_channel) {
    // channel is NULL
    uint32_t urpc_chid = 0;
    char *output = NULL;
    uint32_t output_size = 0;
    ASSERT_EQ(channel_get_queue_trans_info(urpc_chid, &output, &output_size), URPC_FAIL);

    // queue num is 0
    urpc_channel_info_t *channel = channel_alloc();
    ASSERT_EQ(channel_get_queue_trans_info(channel->id, &output, &output_size), URPC_SUCCESS);

    // 队列数量不一致
    channel->l_qnum = 1;
    channel->r_qnum = 1;
    ASSERT_EQ(channel_get_queue_trans_info(channel->id, &output, &output_size), URPC_FAIL);

    int ret = channel_free(channel->id);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST_F(ChannelGetQueueTest, test_with_invalid_malloc) {
    char *output = NULL;
    uint32_t output_size = 0;
    // queue num is 0
    urpc_channel_info_t *channel = channel_alloc();
    // malloc failed
    channel->l_qnum = 1;
    channel->r_qnum = 1;
    MOCKER(urpc_dbuf_malloc).stubs().will(returnValue(NULL));
    int ret = channel_get_queue_trans_info(channel->id, &output, &output_size);
    ASSERT_EQ(ret, URPC_FAIL);

    ret = channel_free(channel->id);
    ASSERT_EQ(ret, URPC_SUCCESS);
}
