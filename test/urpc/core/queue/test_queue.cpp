/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc queue test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"
#include <deque>
#include <future>
#include <iostream>
#include <random>

#include "notify.h"
#include "async_event.h"
#include "cp.h"
#include "dp.h"
#include "jetty_public_func.h"

#include "protocol.h"
#include "provider_ops_jetty.h"
#include "queue.h"
#include "queue_send_recv.h"
#include "state.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_dbuf_stat.h"
#include "urpc_framework_errno.h"

#include "urpc_manage.h"
#include "urpc_timer.h"

#define DEFAULT_PRIORITY 5
#define DEFAULT_RX_DEPTH 128
#define DEFAULT_TX_DEPTH 128
#define DEFAULT_MSG_SIZE 64

#define SHARED_JFR_Q1_MAX_RX_SGE 16
#define SHARED_JFR_Q1_RX_DEPTH 32
#define SHARED_JFR_Q1_RX_BUF_SIZE 128

#define SHARED_JFR_Q2_MAX_RX_SGE 15
#define SHARED_JFR_Q2_RX_DEPTH 31
#define SHARED_JFR_Q2_RX_BUF_SIZE 127

#define SHARED_JFC_MAX_RX_SGE 15
#define SHARED_JFC_RX_BUF_SIZE 127

#define MAX_MSG_SIZE (1UL << 20)
#define READ_CACHE_LIST_TEST_CONCURRENT_CNT 4
#define DEFAULT_POLL_NUM 32
#define SGE_SIZE 4096
#define SGE_CUR 3
#define PLOG_SGE_SIZE_ARRAY_SIZE 32
#define URPC_EXT_HEADER_SIZE 256
#define SIMULATE_PLOG_CMD_SIZE 128
#define FAKE_MEM_HANDLE 0x123
#define PLOG_READ_HEADER_ROOM_SIZE 64
#define PLOG_READ_HEADER_TOTAL_SIZE 256
#define URPC_TIMER_MAGIC_NUM 0x33445577u
#define QUEUE_ID_FREE_NUM 8

#define DMA_CNT 5

static urma_device_t dev = {0};

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

class queue_test : public ::testing::Test {
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
        urma_notifier_t notifier;
        MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
        MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));
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
        MOCKER(urma_query_jetty).stubs().will(invoke(urma_query_jetty_mock));
        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_poll_jfc).stubs().will(returnValue(0));

        MOCKER(urma_modify_jetty).stubs().will(returnValue(URMA_SUCCESS));
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
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
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

TEST(queue_not_init_test, send_recv_create_local_queue_without_init)
{
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    queue_cfg.rx_buf_size = DEFAULT_MSG_SIZE;
    queue_cfg.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    // 底下没有urma初始化，预期为空
    ASSERT_EQ(qh, (uint64_t)0);
}

TEST(queue_not_init_test, send_recv_init_dev_by_ip_addr)
{
    urma_device_t dev = {0};
    dev.type = URMA_TRANSPORT_UB;
    urma_device_t *device_list = &dev;
    int device_num = 1;
    urma_eid_info_t eid_info = {0};
    uint32_t eid_num = 1;
    urma_context_t urma_ctx = {0};
    urma_ctx.dev = &dev;
    MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
    MOCKER(urma_get_device_by_name).stubs().will(returnValue(&dev));
    MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
    MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_get_eid_list)
        .stubs()
        .with(any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
        .will(returnValue(&eid_info));
    MOCKER(urma_get_device_list)
        .stubs()
        .with(outBoundP((int *)&device_num, sizeof(device_num)))
        .will(returnValue(&device_list));

    EXPECT_EQ(urma_str_to_eid("127.0.0.1", &eid_info.eid), 0);
    provider_flag_t flag = {0};

    urpc_trans_info_t dp_cfg = {.trans_mode = URPC_TRANS_MODE_UB, .assign_mode = DEV_ASSIGN_MODE_IPV4,};
    (void)snprintf(dp_cfg.ipv4.ip_addr, URPC_IPV4_SIZE, "%s", "127.0.0.1");
    dp_cfg.trans_mode = (enum urpc_trans_mode)10;
    EXPECT_EQ(provider_init(1, &dp_cfg, flag), URPC_FAIL);

    dp_cfg.trans_mode = URPC_TRANS_MODE_UB;
    EXPECT_EQ(provider_init(1, &dp_cfg, flag), URPC_SUCCESS);

    provider_uninit();

    GlobalMockObject::verify();
}

TEST_F(queue_test, send_recv_create_local_queue_real)
{
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag =
        QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_PRIORITY;
    queue_cfg.rx_buf_size = DEFAULT_MSG_SIZE;
    queue_cfg.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg.priority = DEFAULT_PRIORITY;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    ASSERT_NE(qh, (uint64_t)0);

    urpc_qcfg_get_t get_cfg;
    (void)urpc_queue_cfg_get(qh, &get_cfg);
    ASSERT_EQ(get_cfg.priority, DEFAULT_PRIORITY);

    urpc_qcfg_set_t set_cfg;
    set_cfg.set_flag = QCFG_SET_FLAG_PRIORITY;
    int ret = urpc_queue_cfg_set(qh, &set_cfg);
    ASSERT_NE(ret, URPC_SUCCESS);

    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST_F(queue_test, send_recv_shared_rq_and_cq)
{
    dev.type = URMA_TRANSPORT_UB;
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH |
                            QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_MAX_RX_SGE;
    queue_cfg.rx_buf_size = SHARED_JFR_Q1_RX_BUF_SIZE;
    queue_cfg.rx_depth = SHARED_JFR_Q1_RX_DEPTH;
    queue_cfg.max_rx_sge = SHARED_JFR_Q1_MAX_RX_SGE;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    ASSERT_NE(qh, (uint64_t)0);

    urpc_qcfg_create_t queue_cfg1 = {0};
    queue_cfg1.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH |
                             QCREATE_FLAG_QH_SHARE_RQ;
    queue_cfg1.rx_buf_size = SHARED_JFR_Q2_RX_BUF_SIZE;
    queue_cfg1.rx_depth = SHARED_JFR_Q2_RX_DEPTH;
    queue_cfg.max_rx_sge = SHARED_JFR_Q2_MAX_RX_SGE;
    queue_cfg1.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg1.urpc_qh_share_rq = qh;
    uint64_t qh1 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg1);
    ASSERT_NE(qh1, (uint64_t)0);

    urpc_qcfg_get_t get_cfg;
    (void)urpc_queue_cfg_get(qh, &get_cfg);
    ASSERT_EQ(get_cfg.rx_buf_size, (uint32_t)SHARED_JFR_Q1_RX_BUF_SIZE);
    ASSERT_EQ(get_cfg.rx_depth, (uint32_t)SHARED_JFR_Q1_RX_DEPTH);
    ASSERT_EQ(get_cfg.max_rx_sge, SHARED_JFR_Q1_MAX_RX_SGE);

    urpc_qcfg_get_t get_cfg1;
    (void)urpc_queue_cfg_get(qh1, &get_cfg1);
    ASSERT_EQ(get_cfg1.rx_buf_size, (uint32_t)SHARED_JFR_Q1_RX_BUF_SIZE);
    ASSERT_EQ(get_cfg1.rx_depth, (uint32_t)SHARED_JFR_Q1_RX_DEPTH);
    ASSERT_EQ(get_cfg1.max_rx_sge, SHARED_JFR_Q1_MAX_RX_SGE);

    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ret = urpc_queue_destroy(qh1);
    ASSERT_EQ(ret, URPC_SUCCESS);
    dev.type = URMA_TRANSPORT_UB;
}

TEST_F(queue_test, send_recv_create_shared_txrx_cq)
{
    dev.type = URMA_TRANSPORT_UB;
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH |
                            QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_MAX_RX_SGE | QCREATE_FLAG_TX_CQ_DEPTH;
    queue_cfg.rx_buf_size = SHARED_JFR_Q1_RX_BUF_SIZE;
    queue_cfg.rx_depth = SHARED_JFR_Q1_RX_DEPTH;
    queue_cfg.max_rx_sge = SHARED_JFR_Q1_MAX_RX_SGE;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg.tx_cq_depth = 2 * (DEFAULT_TX_DEPTH + 1);
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    ASSERT_NE(qh, (uint64_t)0);

    urpc_qcfg_get_t get_cfg;
    (void)urpc_queue_cfg_get(qh, &get_cfg);
    ASSERT_EQ(get_cfg.rx_buf_size, (uint32_t)SHARED_JFR_Q1_RX_BUF_SIZE);
    ASSERT_EQ(get_cfg.rx_depth, (uint32_t)SHARED_JFR_Q1_RX_DEPTH);
    ASSERT_EQ(get_cfg.max_rx_sge, SHARED_JFR_Q1_MAX_RX_SGE);
    ASSERT_EQ(get_cfg.tx_cq_depth, 2 * (DEFAULT_TX_DEPTH + 1));
    ASSERT_EQ(get_cfg.rx_cq_depth, queue_cfg.rx_depth);

    urpc_qcfg_create_t queue_cfg1 = {0};
    queue_cfg1.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH |
                             QCREATE_FLAG_MAX_RX_SGE | QCREATE_FLAG_QH_SHARE_TX_CQ;
    queue_cfg1.rx_buf_size = SHARED_JFC_RX_BUF_SIZE;
    queue_cfg1.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg1.max_rx_sge = SHARED_JFC_MAX_RX_SGE;
    queue_cfg1.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg1.urpc_qh_share_tx_cq = qh;
    uint64_t qh1 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg1);
    ASSERT_NE(qh1, (uint64_t)0);

    urpc_qcfg_get_t get_cfg1;
    (void)urpc_queue_cfg_get(qh1, &get_cfg1);
    ASSERT_EQ(get_cfg1.rx_buf_size, (uint32_t)SHARED_JFC_RX_BUF_SIZE);
    ASSERT_EQ(get_cfg1.rx_depth, (uint32_t)DEFAULT_RX_DEPTH);
    ASSERT_EQ(get_cfg1.max_rx_sge, SHARED_JFC_MAX_RX_SGE);
    ASSERT_EQ(get_cfg1.tx_cq_depth, 2 * (DEFAULT_TX_DEPTH + 1));
    ASSERT_EQ(get_cfg1.rx_cq_depth, queue_cfg1.rx_depth);

    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ret = urpc_queue_destroy(qh1);
    ASSERT_EQ(ret, URPC_SUCCESS);
    dev.type = URMA_TRANSPORT_UB;
}

TEST_F(queue_test, send_recv_create_shared_txrx_cq_fail)
{
    dev.type = URMA_TRANSPORT_UB;
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_MODE|
                            QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_MAX_RX_SGE | QCREATE_FLAG_TX_CQ_DEPTH;
    queue_cfg.rx_buf_size = SHARED_JFR_Q1_RX_BUF_SIZE;
    queue_cfg.rx_depth = SHARED_JFR_Q1_RX_DEPTH;
    queue_cfg.max_rx_sge = SHARED_JFR_Q1_MAX_RX_SGE;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg.tx_cq_depth = 3 * (DEFAULT_TX_DEPTH + 1);
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    uint64_t qh1 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    ASSERT_NE(qh, (uint64_t)0);
    ASSERT_NE(qh1, (uint64_t)0);

    urpc_qcfg_create_t queue_cfg1 = {0};
    queue_cfg1.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH |
                             QCREATE_FLAG_MAX_RX_SGE | QCREATE_FLAG_QH_SHARE_TX_CQ |
                             QCREATE_FLAG_QH_SHARE_RQ | QCREATE_FLAG_MODE;
    queue_cfg1.rx_buf_size = SHARED_JFC_RX_BUF_SIZE;
    queue_cfg1.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg1.max_rx_sge = SHARED_JFC_MAX_RX_SGE;
    queue_cfg1.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg1.urpc_qh_share_tx_cq = qh;
    uint64_t qh2 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg1);
    ASSERT_EQ(qh2, (uint64_t)0);
    queue_cfg.mode = QUEUE_MODE_INTERRUPT;
    queue_cfg1.urpc_qh_share_rq = qh;
    qh2 = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg1);
    ASSERT_NE(qh2, (uint64_t)0);

    int ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ret = urpc_queue_destroy(qh1);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ret = urpc_queue_destroy(qh2);
    ASSERT_EQ(ret, URPC_SUCCESS);
    dev.type = URMA_TRANSPORT_UB;
}

TEST_F(queue_test, test_list_queue_local)
{
    int ret = 0;
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag =
        QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_PRIORITY;
    queue_cfg.rx_buf_size = DEFAULT_MSG_SIZE;
    queue_cfg.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg.priority = DEFAULT_PRIORITY;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    ASSERT_NE(qh, (uint64_t)0);

    char *output = NULL;
    uint32_t output_size = 0;
    ASSERT_EQ(get_queue_trans_info(&output, &output_size), 0);
    ASSERT_NE(output_size, (uint32_t)0);
    ASSERT_EQ(output != NULL, true);

    queue_trans_info_t *trans_info = (queue_trans_info_t *)output;

    ASSERT_EQ(trans_info->flag.is_remote, 0);
    ASSERT_EQ(trans_info->trans_spec_cnt, (uint32_t)1);

    urpc_dbuf_free(output);

    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

TEST_F(queue_test, test_queue_info_get)
{
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH |
        QCREATE_FLAG_CUSTOM_FLAG;
    queue_cfg.rx_buf_size = 4096;
    queue_cfg.rx_depth = 16;
    queue_cfg.tx_depth = 16;
    queue_cfg.custom_flag = QALLOCA_NORMAL_SIZE_FLAG;
    uint64_t qh = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
    queue_local_t *lq = (queue_local_t *)qh;
    uint16_t qid = lq->qid;
    char *output = NULL;
    uint32_t output_size = 0;
    int ret = queue_info_get(qid, &output, &output_size);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ASSERT_EQ(output != NULL, true);
    ASSERT_EQ(output_size, sizeof(queue_trans_info_t) + sizeof(queue_trans_resource_spec_t));

    queue_trans_info_t *qti = (queue_trans_info_t *)output;
    ASSERT_EQ(qti->trans_spec_cnt, 1);
    ASSERT_EQ(qti->custom_flag, QALLOCA_NORMAL_SIZE_FLAG);

    urpc_dbuf_free(output);
    ret = urpc_queue_destroy(qh);
    ASSERT_EQ(ret, URPC_SUCCESS);
}

typedef struct test_read_cache_args {
    uint32_t list_size;
    uint32_t concurrent_cnt;
    read_cache_list_t *rcache_list;
    std::atomic<int> ready_cnt;
} test_read_cache_args_t;

void sync_multi_thread(std::atomic<int> &ready_cnt, uint32_t concurrent_cnt)
{
    ready_cnt.fetch_add(1);
    while (ready_cnt.load() != (int)concurrent_cnt) {
    }
}

void *test_read_cache_concurrent_push_back_callback(void *args)
{
    test_read_cache_args_t *cache_args = (test_read_cache_args_t *)args;
    uint32_t push_back_cnt = cache_args->list_size / cache_args->concurrent_cnt;
    sync_multi_thread(cache_args->ready_cnt, cache_args->concurrent_cnt);
    for (uint32_t i = 0; i < push_back_cnt; i++) {
        read_cache_t *read_cache = (read_cache_t *)calloc(1, sizeof(read_cache_t));
        EXPECT_TRUE(read_cache != nullptr);
        int ret = queue_read_cache_list_push_back(cache_args->rcache_list, read_cache);
        EXPECT_EQ(ret, URPC_SUCCESS);
    }
    return nullptr;
}

void *test_read_cache_list_upper_limit_callback(void *args)
{
    test_read_cache_args_t *cache_args = (test_read_cache_args_t *)args;
    read_cache_t *read_cache = (read_cache_t *)calloc(1, sizeof(read_cache_t));
    EXPECT_TRUE(read_cache != nullptr);
    sync_multi_thread(cache_args->ready_cnt, cache_args->concurrent_cnt);
    int ret = queue_read_cache_list_push_back(cache_args->rcache_list, read_cache);
    EXPECT_EQ(ret, URPC_FAIL);
    queue_read_cache_list_push_front(cache_args->rcache_list, read_cache);
    return nullptr;
}

void *test_read_cache_concurrent_pop_front_callback(void *args)
{
    test_read_cache_args_t *cache_args = (test_read_cache_args_t *)args;
    uint32_t pop_front_cnt = (cache_args->list_size / cache_args->concurrent_cnt) + 1;
    sync_multi_thread(cache_args->ready_cnt, cache_args->concurrent_cnt);
    for (uint32_t i = 0; i < pop_front_cnt; i++) {
        read_cache_t *read_cache = queue_read_cache_list_pop_front(cache_args->rcache_list);
        EXPECT_TRUE(read_cache != nullptr);
        free(read_cache);
    }
    return nullptr;
}

void test_read_cache_concurrent_push_back(test_read_cache_args_t *cache_args)
{
    pthread_t thd[cache_args->concurrent_cnt];
    cache_args->ready_cnt.store(0);
    for (uint32_t i = 0; i < cache_args->concurrent_cnt; i++) {
        (void)pthread_create(&thd[i], nullptr, test_read_cache_concurrent_push_back_callback, cache_args);
    }

    for (uint32_t i = 0; i < cache_args->concurrent_cnt; i++) {
        (void)pthread_join(thd[i], nullptr);
    }

    ASSERT_EQ(queue_read_cache_list_size(cache_args->rcache_list), cache_args->list_size);
}

void test_read_cache_list_upper_limit(test_read_cache_args_t *cache_args)
{
    pthread_t thd[cache_args->concurrent_cnt];
    cache_args->ready_cnt.store(0);
    for (uint32_t i = 0; i < cache_args->concurrent_cnt; i++) {
        (void)pthread_create(&thd[i], nullptr, test_read_cache_list_upper_limit_callback, cache_args);
    }

    for (uint32_t i = 0; i < cache_args->concurrent_cnt; i++) {
        (void)pthread_join(thd[i], nullptr);
    }

    ASSERT_EQ(queue_read_cache_list_size(cache_args->rcache_list), cache_args->list_size + cache_args->concurrent_cnt);
}

void test_read_cache_concurrent_pop_front(test_read_cache_args_t *cache_args)
{
    pthread_t thd[cache_args->concurrent_cnt];
    cache_args->ready_cnt.store(0);
    for (uint32_t i = 0; i < cache_args->concurrent_cnt; i++) {
        (void)pthread_create(&thd[i], nullptr, test_read_cache_concurrent_pop_front_callback, cache_args);
    }

    for (uint32_t i = 0; i < cache_args->concurrent_cnt; i++) {
        (void)pthread_join(thd[i], nullptr);
    }

    ASSERT_EQ(queue_read_cache_list_size(cache_args->rcache_list), (uint32_t)0);
}

TEST_F(queue_test, test_read_cache_list)
{
    read_cache_list_t rcache_list;

    queue_read_cache_list_init(&rcache_list, 0);

    test_read_cache_args_t cache_args = {0};
    cache_args.concurrent_cnt = READ_CACHE_LIST_TEST_CONCURRENT_CNT;
    cache_args.list_size = DEFAULT_READ_CACHE_LIST_DEPTH;
    cache_args.rcache_list = &rcache_list;
    cache_args.ready_cnt.store(0);

    test_read_cache_concurrent_push_back(&cache_args);

    test_read_cache_list_upper_limit(&cache_args);

    test_read_cache_concurrent_pop_front(&cache_args);

    queue_read_cache_list_uninit(&rcache_list);
}