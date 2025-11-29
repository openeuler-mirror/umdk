/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc server channel test
 */

#include "gtest/gtest.h"
#include "mockcpp/mockcpp.hpp"
#include <sys/eventfd.h>

#include "channel.h"
#include "cp.h"
#include "cp_vers_compat.h"
#include "dp.h"
#include "jetty_public_func.h"
#include "queue_send_recv.h"
#include "server_manage_channel.h"
#include "state.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_dbuf_stat.h"
#include "urpc_framework_errno.h"

#define DEV_NAME_LEN        15
#define MAX_MSG_SIZE (1UL << 20)

extern queue_ops_t g_urpc_send_recv_ops;

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

class ServerChannelTest : public ::testing::Test {
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
        static urma_jfr_cfg_t jfr_cfg = {0};
        jetty.jetty_cfg.jfr_cfg = &jfr_cfg;
        MOCKER(urma_create_jfr).stubs().will(returnValue(&jfr));
        MOCKER(urma_delete_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfc).stubs().will(returnValue(&jfc));
        MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jetty).stubs().will(returnValue(&jetty));
        MOCKER(urma_delete_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jetty).stubs().will(invoke(urma_query_jetty_mock));
        MOCKER(urma_modify_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_jfr).stubs().will(invoke(urma_query_jfr_mock));
        static uint32_t qid = 0;
        MOCKER(queue_id_allocator_alloc)
            .stubs()
            .with(outBoundP((uint32_t *)&qid, sizeof(qid)))
            .will(returnValue(URPC_SUCCESS));
        MOCKER(queue_id_allocator_free).stubs().will(ignoreReturnValue());

        urpc_trans_info_t cfg = {.trans_mode = URPC_TRANS_MODE_UB, .assign_mode = DEV_ASSIGN_MODE_DEV,};
        (void)snprintf(cfg.dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "lo");
        provider_flag_t flag = {0};
        int ret = provider_init(1, &cfg, flag);
        ASSERT_EQ(ret, URPC_SUCCESS);
        urpc_state_set(URPC_STATE_INIT);
        urpc_timing_wheel_init();
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        urpc_timing_wheel_uninit();
        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
        provider_uninit();
        close(g_notifier_fd);
        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {
        urpc_server_channel_id_allocator_init();
    }

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {
        urpc_server_channel_id_allocator_uninit();
    }
};

void delete_remote_queue_mock(queue_t *r_queue)
{
    return;
}

int unimport_remote_queue_mock(queue_t *r_queue)
{
    return URPC_SUCCESS;
}

int import_remote_queue_mock(queue_t *r_queue)
{
    return URPC_SUCCESS;
}

TEST_F(ServerChannelTest, ServerChannelAlloc) {
    urpc_instance_key_t key  = {0};
    urpc_server_channel_info_t *info = server_channel_alloc(&key , 0);
    ASSERT_NE(info, nullptr);
    server_channel_unlock(info->id);
    ASSERT_EQ(server_channel_free(info->id, false), URPC_SUCCESS);
}

TEST_F(ServerChannelTest, ServerChannelGet) {
    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info = server_channel_alloc(&key, 0);
    ASSERT_NE(info, nullptr);
    urpc_server_channel_info_t *get_info = server_channel_get(info->id);
    ASSERT_EQ(info, get_info);
    server_channel_unlock(info->id);
    ASSERT_EQ(server_channel_free(info->id, false), URPC_SUCCESS);
}

TEST_F(ServerChannelTest, ServerChannelMaxConnPerClient) {
    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info[URPC_MAX_CHANNEL_PER_CLIENT + 1];
    uint32_t i;
    for (i= 0; i < URPC_MAX_CHANNEL_PER_CLIENT; i++) {
        info[i] = server_channel_alloc(&key, 0);
        ASSERT_NE(info[i], nullptr);
    }
    info[i] = server_channel_alloc(&key, 0);
    ASSERT_EQ(info[i], nullptr);
    for (i = 0; i < URPC_MAX_CHANNEL_PER_CLIENT; i++) {
        server_channel_unlock(info[i]->id);
        ASSERT_EQ(server_channel_free(info[i]->id, false), URPC_SUCCESS);
    }
}

TEST_F(ServerChannelTest, ServerChannelBaseIdKeep) {
    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info[4];
    uint32_t i;
    for (i= 0; i < 4; i++) {
        info[i] = server_channel_alloc(&key, 0);
        ASSERT_NE(info[i], nullptr);
    }
    uint32_t base_id1 = info[0]->id >> URPC_BASE_ID_OFFSETS;
    uint32_t base_id2 = info[1]->id >> URPC_BASE_ID_OFFSETS;
    for (i = 0; i < 4; i++) {
        server_channel_unlock(info[i]->id);
        ASSERT_EQ(server_channel_free(info[i]->id, false), URPC_SUCCESS);
    }
    ASSERT_EQ(base_id1, base_id2);
}

TEST_F(ServerChannelTest, ServerChannelBaseIdReuse) {
    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info[4];
    uint32_t i;
    for (i= 0; i < 4; i++) {
        info[i] = server_channel_alloc(&key, 0);
        ASSERT_NE(info[i], nullptr);
    }
    uint32_t base_id1 = info[0]->id >> URPC_BASE_ID_OFFSETS;
    for (i = 0; i < 4; i++) {
        server_channel_unlock(info[i]->id);
        ASSERT_EQ(server_channel_free(info[i]->id, false), URPC_SUCCESS);
    }
    info[0] = server_channel_alloc(&key, 0);
    ASSERT_NE(info[0], nullptr);
    uint32_t base_id2 = info[0]->id >> URPC_BASE_ID_OFFSETS;
    server_channel_unlock(info[0]->id);
    ASSERT_EQ(server_channel_free(info[0]->id, false), URPC_SUCCESS);
    ASSERT_EQ(base_id1, base_id2);
}

TEST_F(ServerChannelTest, test_list_queue_by_server_channel_id) {
    urma_target_jetty_t jetty1 = {0};
    jetty1.id.id = 0;
    urma_target_jetty_t jetty2 = {0};
    jetty2.id.id = 1;
    MOCKER(urma_import_jetty).stubs().will(returnObjectList(&jetty1, &jetty2));
    MOCKER(urma_unimport_jetty).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_advise_jetty).stubs().will(returnValue(URMA_SUCCESS));

    urpc_qcfg_create_t q_cfg = {0};
    uint64_t qh1 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &q_cfg);
    EXPECT_NE(qh1, (uint64_t)URPC_INVALID_HANDLE);

    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info = server_channel_alloc(&key, 0);
    EXPECT_NE(info, nullptr);
    server_channel_unlock(info->id);

    queue_info_t queue1_info = {0};
    queue1_info.mode_jetty.jetty_id.id = 0;
    queue1_info.trans_mode = QUEUE_TRANS_MODE_JETTY;
    queue_t *queue1 = g_urpc_send_recv_ops.create_remote_queue(&queue1_info, info->id, 0);
    queue_t *l_queue = (queue_t *)(uintptr_t)qh1;
    g_urpc_send_recv_ops.import_remote_queue(queue1, l_queue->provider);
    queue_node_t *node1 = (queue_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(queue_node_t));
    ASSERT_NE(node1, nullptr);
    node1->urpc_qh = (uint64_t)(uintptr_t)queue1;
    node1->node.next = NULL;
    URPC_SLIST_INSERT_HEAD(&info->r_queue_nodes_head, node1, node);

    char *output = NULL;
    uint32_t output_size = 0;
    ASSERT_EQ(server_channel_get_queue_trans_info(info->id, &output, &output_size), 0);
    ASSERT_NE(output_size, (uint32_t)0);
    ASSERT_EQ(output != NULL, true);

    queue_trans_info_t *trans_info = (queue_trans_info_t *)output;

    EXPECT_EQ(trans_info->flag.is_remote, 1);
    EXPECT_EQ(trans_info->trans_spec_cnt, (uint32_t)1);
    urpc_dbuf_free(output);

    server_channel_free(info->id, false);

    int ret = urpc_queue_destroy(qh1);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

static void *urpc_dbuf_malloc_stud(urpc_dbuf_type_t type, uint32_t size)
{
    return NULL;
}

TEST_F(ServerChannelTest, test_server_channel_get_queue_trans_info_malloc_fail)
{
    urma_target_jetty_t jetty1 = {0};
    jetty1.id.id = 0;
    urma_target_jetty_t jetty2 = {0};
    jetty2.id.id = 1;
    MOCKER(urma_import_jetty).stubs().will(returnObjectList(&jetty1, &jetty2));
    MOCKER(urma_unimport_jetty).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_advise_jetty).stubs().will(returnValue(URMA_SUCCESS));

    urpc_qcfg_create_t q_cfg = {0};
    uint64_t qh1 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &q_cfg);
    EXPECT_NE(qh1, URPC_INVALID_HANDLE);

    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info = server_channel_alloc(&key, 0);
    EXPECT_NE(info, nullptr);
    server_channel_unlock(info->id);

    queue_info_t queue1_info = {0};
    queue1_info.mode_jetty.jetty_id.id = 0;
    queue1_info.trans_mode = QUEUE_TRANS_MODE_JETTY;
    queue_t *queue1 = g_urpc_send_recv_ops.create_remote_queue(&queue1_info, info->id, 0);
    queue_t *l_queue = (queue_t *)(uintptr_t)qh1;
    g_urpc_send_recv_ops.import_remote_queue(queue1, l_queue->provider);
    queue_node_t *node1 = (queue_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(queue_node_t));
    ASSERT_NE(node1, nullptr);
    node1->urpc_qh = (uint64_t)(uintptr_t)queue1;
    node1->node.next = NULL;
    URPC_SLIST_INSERT_HEAD(&info->r_queue_nodes_head, node1, node);

    char *output = NULL;
    uint32_t output_size = 0;
    MOCKER(urpc_dbuf_malloc).stubs().will(invoke(urpc_dbuf_malloc_stud));
    ASSERT_EQ(server_channel_get_queue_trans_info(info->id, &output, &output_size), -URPC_ERR_ENOMEM);
    urpc_dbuf_free(output);

    server_channel_free(info->id, false);

    int ret = urpc_queue_destroy(qh1);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST_F(ServerChannelTest, TestServerRefreshRemoteQueueInfos) {
    urma_target_jetty_t jetty1 = {0};
    jetty1.id.id = 0;
    urma_target_jetty_t jetty2 = {0};
    jetty2.id.id = 1;
    MOCKER(urma_import_jetty).stubs().will(returnObjectList(&jetty1, &jetty2));
    MOCKER(urma_unimport_jetty).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_advise_jetty).stubs().will(returnValue(URMA_SUCCESS));

    urpc_qcfg_create_t q_cfg = {0};
    uint64_t qh1 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &q_cfg);
    ASSERT_NE(qh1, (uint64_t)URPC_INVALID_HANDLE);

    urpc_instance_key_t key = {0};
    urpc_server_channel_info_t *info = server_channel_alloc(&key, 0);
    ASSERT_NE(info, nullptr);

    queue_info_t queue1_info = {0};
    queue1_info.mode_jetty.jetty_id.id = 0;
    queue1_info.trans_mode = QUEUE_TRANS_MODE_JETTY;
    queue_t *queue1 = g_urpc_send_recv_ops.create_remote_queue(&queue1_info, info->id, 0);
    queue_t *l_queue = (queue_t *)(uintptr_t)qh1;
    g_urpc_send_recv_ops.import_remote_queue(queue1, l_queue->provider);
    queue_node_t *node1 = (queue_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_CHANNEL, sizeof(queue_node_t));
    ASSERT_NE(node1, nullptr);
    node1->urpc_qh = (uint64_t)(uintptr_t)queue1;
    node1->node.next = NULL;
    URPC_SLIST_INSERT_HEAD(&info->r_queue_nodes_head, node1, node);

    queue_info_t *xchg_info = (queue_info_t *)calloc(1, sizeof(queue_info_t));
    ASSERT_NE(xchg_info, nullptr);

    xchg_info->trans_mode = QUEUE_TRANS_MODE_JETTY;
    xchg_info->mode_jetty.jetty_id.id = 1;

    queue_node_t *l_node;
    URPC_SLIST_FOR_EACH(l_node, &info->r_queue_nodes_head, node) {
        /* only queue3 exists */
        ASSERT_EQ(g_urpc_send_recv_ops.is_same_queue((queue_t *)(uintptr_t)l_node->urpc_qh, xchg_info,
                                                QUEUE_AUTHN_BY_QUEUE_INFO) ||
                  g_urpc_send_recv_ops.is_same_queue((queue_t *)(uintptr_t)l_node->urpc_qh, &queue1_info,
                                                QUEUE_AUTHN_BY_QUEUE_INFO), true);
    }

    server_channel_unlock(info->id);
    server_channel_free(info->id, false);

    int ret = urpc_queue_destroy(qh1);
    ASSERT_EQ(ret, URPC_SUCCESS);

    free(xchg_info);
}

class ServerChannelTestNoThing : public :: testing::Test {
public:
    void SetUp() override {
    }

    void TearDown() override {
        GlobalMockObject::verify();
    }
};

void *server_channel_alloc_urpc_dbuf_calloc_stud_return = NULL;

void *server_channel_alloc_urpc_dbuf_calloc_stud(urpc_dbuf_type_t type, uint32_t nitems, uint32_t size)
{
    if (type == URPC_DBUF_TYPE_CHANNEL) {
        return server_channel_alloc_urpc_dbuf_calloc_stud_return;
    }
    return NULL;
}

void server_channel_alloc_urpc_dbuf_free_stud(void *ptr)
{
}

TEST_F(ServerChannelTestNoThing, TestServerChannelAlloc)
{
    void *ptr = malloc(4096);
    server_channel_alloc_urpc_dbuf_calloc_stud_return = ptr;
    MOCKER(urpc_dbuf_calloc).stubs().will(invoke(server_channel_alloc_urpc_dbuf_calloc_stud));
    MOCKER(urpc_dbuf_free).stubs().will(invoke(server_channel_alloc_urpc_dbuf_free_stud));
    MOCKER(crypto_is_dp_ssl_enabled).stubs().will(returnValue(true));

    // 覆盖urpc dbuf calloc失败
    ASSERT_EQ(server_channel_alloc(NULL, 0), (urpc_server_channel_info_t *)NULL);
    free(ptr);
    GlobalMockObject::verify();
}
