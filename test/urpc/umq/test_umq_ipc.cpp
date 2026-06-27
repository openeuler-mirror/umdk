/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq ipc test
 */

#include <sys/mman.h>

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include "perf.h"
#include "umq_api.h"
#include "umq_pro_api.h"
#include "umq_qbuf_pool.h"
#include "umq_huge_qbuf_pool.h"
#include "urpc_util.h"

#define TEST_IPC_BIND_INFO_SIZE 2048

static uint64_t g_ipc_umqh;

static int test_umq_ipc_init(void)
{
    umq_init_cfg_t cfg;
    memset(&cfg, 0, sizeof(umq_init_cfg_t));

    cfg.trans_info_num = 1;
    cfg.trans_info[0].trans_mode = UMQ_TRANS_MODE_IPC;

    return umq_init(&cfg);
}

static uint64_t test_umq_create_ipc_qh(bool interrupt, int index)
{
    umq_create_option_t option;
    memset(&option, 0, sizeof(umq_create_option_t));
    (void)snprintf(option.name, UMQ_NAME_MAX_LEN, "%s_%d", "test_umq_ipc", index);

    // clean up leftover files
    shm_unlink(option.name);

    option.create_flag = UMQ_CREATE_FLAG_QUEUE_MODE;
    option.trans_mode = UMQ_TRANS_MODE_IPC;
    option.mode = interrupt ? UMQ_MODE_INTERRUPT : UMQ_MODE_POLLING;
    return umq_create(&option);
};

static inline uint64_t test_ipc_umqh(void)
{
    return g_ipc_umqh;
}

class UmqIPCTest : public ::testing::Test {
  public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
        ASSERT_EQ(test_umq_ipc_init(), 0);
        g_ipc_umqh = test_umq_create_ipc_qh(false, 0);
        ASSERT_NE(g_ipc_umqh, UMQ_INVALID_HANDLE);
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        ASSERT_EQ(umq_destroy(g_ipc_umqh), 0);
        g_ipc_umqh = 0;
        umq_uninit();
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

TEST_F(UmqIPCTest, test_umq_init_failure)
{
    umq_init_cfg_t cfg;
    memset(&cfg, 0, sizeof(umq_init_cfg_t));
    int ret;

    ret = umq_init(nullptr);
    ASSERT_NE(ret, 0);

    cfg.trans_info_num = MAX_UMQ_TRANS_INFO_NUM + 1;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.trans_info_num = 0;

    cfg.headroom_size = UMQ_HEADROOM_SIZE_LIMIT + 1;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.headroom_size = 0;

    MOCKER(urpc_rand_seed_init).stubs().will(returnValue(-1));
    cfg.feature = UMQ_FEATURE_ENABLE_TOKEN_POLICY;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.feature = 0;
    GlobalMockObject::verify();

    cfg.buf_pool_cfg.small_block_size = BLOCK_SIZE_MAX;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.buf_pool_cfg.small_block_size = BLOCK_SIZE_8K;

    cfg.trans_info_num = 32;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.trans_info_num = 0;

    MOCKER(umq_perf_init).stubs().will(returnValue(-1));
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    ret = umq_init(&cfg);
    ASSERT_NE(ret, 0);
    cfg.feature = 0;
    GlobalMockObject::verify();
}

TEST_F(UmqIPCTest, test_umq_bind_failure)
{
    int ret;
    uint8_t bind_info[TEST_IPC_BIND_INFO_SIZE];
    uint32_t bind_info_size;

    ASSERT_EQ(umq_bind_info_get(0, bind_info, TEST_IPC_BIND_INFO_SIZE), 0);
    ASSERT_EQ(umq_bind_info_get(test_ipc_umqh(), bind_info, 0), 0);

    bind_info_size = umq_bind_info_get(test_ipc_umqh(), bind_info, TEST_IPC_BIND_INFO_SIZE);
    EXPECT_GT(bind_info_size, 0);

    ret = umq_bind(0, bind_info, TEST_IPC_BIND_INFO_SIZE);
    ASSERT_NE(ret, 0);

    ret = umq_bind(test_ipc_umqh(), bind_info, 0);
    ASSERT_NE(ret, 0);
}

TEST_F(UmqIPCTest, test_umq_bind_success)
{
    int ret;
    uint64_t umqh1;

    umqh1 = test_umq_create_ipc_qh(false, 1);
    ASSERT_NE(umqh1, UMQ_INVALID_HANDLE);

    uint8_t bind_info[TEST_IPC_BIND_INFO_SIZE];
    uint32_t bind_info_size;

    bind_info_size = umq_bind_info_get(test_ipc_umqh(), bind_info, TEST_IPC_BIND_INFO_SIZE);
    EXPECT_GT(bind_info_size, 0);

    ret = umq_bind(umqh1, bind_info, bind_info_size);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(umq_unbind(umqh1), 0);

    ASSERT_EQ(umq_destroy(umqh1), 0);
}

TEST_F(UmqIPCTest, test_umq_enqueue_dequeue)
{
    int ret;
    uint64_t umqh1;
    umq_buf_t *qbuf, *dequeue_buf, *bad = nullptr;

    umqh1 = test_umq_create_ipc_qh(false, 1);
    ASSERT_NE(umqh1, UMQ_INVALID_HANDLE);

    uint8_t bind_info[TEST_IPC_BIND_INFO_SIZE];
    uint8_t bind_info1[TEST_IPC_BIND_INFO_SIZE];
    uint32_t bind_info_size, bind_info_size1;

    bind_info_size = umq_bind_info_get(test_ipc_umqh(), bind_info, TEST_IPC_BIND_INFO_SIZE);
    EXPECT_GT(bind_info_size, 0);
    bind_info_size1 = umq_bind_info_get(umqh1, bind_info1, TEST_IPC_BIND_INFO_SIZE);
    EXPECT_GT(bind_info_size1, 0);
    ret = umq_bind(umqh1, bind_info, bind_info_size);
    ASSERT_EQ(ret, 0);
    ret = umq_bind(test_ipc_umqh(), bind_info, bind_info_size);
    ASSERT_EQ(ret, 0);

    qbuf = umq_buf_alloc(4096, 1, test_ipc_umqh(), nullptr);
    ASSERT_NE(qbuf, nullptr);

    // umqh enqueue, umqh2 dequeue
    ASSERT_EQ(umq_enqueue(test_ipc_umqh(), qbuf, &bad), 0);
    ASSERT_EQ(bad, nullptr);
    dequeue_buf = umq_dequeue(umqh1);
    ASSERT_NE(dequeue_buf, nullptr);

    // qbuf no need to free explicitly
    umq_buf_free(dequeue_buf);

    ASSERT_EQ(umq_unbind(test_ipc_umqh()), 0);
    ASSERT_EQ(umq_unbind(umqh1), 0);
    ASSERT_EQ(umq_destroy(umqh1), 0);
}

TEST_F(UmqIPCTest, test_umq_interrupt_failure)
{
    umq_interrupt_option_t opt;
    memset(&opt, 0, sizeof(umq_interrupt_option_t));

    ASSERT_LT(umq_wait_interrupt(test_ipc_umqh(), -1, nullptr), 0);
    ASSERT_LT(umq_wait_interrupt(test_ipc_umqh(), -1, &opt), 0);
    umq_notify(test_ipc_umqh());
    umq_ack_interrupt(test_ipc_umqh(), 1, nullptr);
    umq_ack_interrupt(test_ipc_umqh(), 1, &opt);
    umq_rearm_interrupt(test_ipc_umqh(), true, nullptr);
    umq_rearm_interrupt(test_ipc_umqh(), true, &opt);

    opt.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION;
    opt.direction = UMQ_IO_TX;
    ASSERT_LT(umq_wait_interrupt(test_ipc_umqh(), -1, &opt), 0);
    umq_notify(test_ipc_umqh());
    umq_ack_interrupt(test_ipc_umqh(), 1, &opt);
    umq_rearm_interrupt(test_ipc_umqh(), true, &opt);
}

static void *test_umq_notify_func(void *arg)
{
    usleep(10000);

    printf("notify ipc interrupt\n");

    uint64_t umqh = (uint64_t)(uintptr_t)arg;
    umq_notify(umqh);

    return NULL;
}

TEST_F(UmqIPCTest, test_umq_interrupt_success)
{
    uint64_t umqh1;
    pthread_t thread;
    umq_interrupt_option_t opt;
    memset(&opt, 0, sizeof(umq_interrupt_option_t));

    umqh1 = test_umq_create_ipc_qh(true, 1);
    ASSERT_NE(umqh1, UMQ_INVALID_HANDLE);

    ASSERT_EQ(pthread_create(&thread, NULL, test_umq_notify_func, (void *)(uintptr_t)umqh1), 0);
    printf("wait ipc interrupt...\n");

    opt.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION;
    opt.direction = UMQ_IO_TX;
    ASSERT_GE(umq_wait_interrupt(umqh1, 500, &opt), 0);

    umq_ack_interrupt(umqh1, 1, &opt);
    umq_rearm_interrupt(umqh1, true, &opt);

    (void)pthread_join(thread, NULL);
    ASSERT_EQ(umq_destroy(umqh1), 0);
}

TEST_F(UmqIPCTest, test_umq_ipc_log_cfg_set_success)
{
    umq_log_config_t cfg0, cfg;
    memset(&cfg0, 0, sizeof(umq_log_config_t));
    memset(&cfg, 0, sizeof(umq_log_config_t));

    ASSERT_EQ(umq_log_config_get(&cfg0), 0);

    cfg.log_flag |= UMQ_LOG_FLAG_LEVEL | UMQ_LOG_FLAG_RATE_LIMITED | UMQ_LOG_FLAG_FUNC;
    cfg.level = UMQ_LOG_LEVEL_EMERG;
    ASSERT_EQ(umq_log_config_set(&cfg), 0);

    // restore log config
    ASSERT_EQ(umq_log_config_set(&cfg0), 0);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_umq_state_set_failure)
{
    ASSERT_NE(umq_state_set(0, QUEUE_STATE_IDLE), 0);
    ASSERT_NE(umq_state_set(test_ipc_umqh(), QUEUE_STATE_IDLE), 0);
}

// IPC umq only support get umq state
TEST_F(UmqIPCTest, test_umq_state_get_success)
{
    ASSERT_EQ(umq_state_get(test_ipc_umqh()), QUEUE_STATE_READY);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_umq_cfg_get_failure)
{
    umq_cfg_get_t cfg;

    ASSERT_NE(umq_cfg_get(0, nullptr), 0);
    ASSERT_NE(umq_cfg_get(0, &cfg), 0);
    ASSERT_NE(umq_cfg_get(test_ipc_umqh(), &cfg), 0);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_umq_mempool_state_get_failure)
{
    umq_mempool_state_t state;

    ASSERT_NE(umq_mempool_state_get(0, 0, nullptr), 0);
    ASSERT_NE(umq_mempool_state_get(test_ipc_umqh(), 0, nullptr), 0);
    ASSERT_NE(umq_mempool_state_get(test_ipc_umqh(), 0, &state), 0);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_umq_mempool_state_refresh_failure)
{
    ASSERT_NE(umq_mempool_state_refresh(0, 0), 0);
    ASSERT_NE(umq_mempool_state_refresh(test_ipc_umqh(), 0), 0);
}

TEST_F(UmqIPCTest, test_umq_buf_alloc_success)
{
    umq_alloc_option_t option;
    memset(&option, 0, sizeof(umq_alloc_option_t));
    umq_buf_t *qbuf;

    qbuf = umq_buf_alloc(4096, 1, test_ipc_umqh(), &option);
    ASSERT_NE(qbuf, nullptr);

    umq_buf_free(qbuf);
}

TEST_F(UmqIPCTest, test_umq_buf_headroom_reset)
{
    umq_buf_t *qbuf;

    ASSERT_NE(umq_buf_headroom_reset(nullptr, 0), 0);

    qbuf = umq_buf_alloc(4096, 1, test_ipc_umqh(), nullptr);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_NE(umq_buf_headroom_reset(qbuf, UMQ_HEADROOM_SIZE_LIMIT + 1), 0);

    ASSERT_EQ(umq_buf_headroom_reset(qbuf, UMQ_HEADROOM_SIZE_LIMIT), 0);
    ASSERT_EQ(umq_buf_headroom_reset(qbuf, 0), 0);

    umq_buf_free(qbuf);
}

TEST_F(UmqIPCTest, test_umq_buf_reset)
{
    int cnt = 0;
    umq_buf_t *qbuf, *head;

    ASSERT_NE(umq_buf_reset(nullptr), 0);

    qbuf = umq_buf_alloc(4096, 1, test_ipc_umqh(), nullptr);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_EQ(qbuf->total_data_size, 4096);

    ASSERT_EQ(umq_buf_reset(qbuf), 0);
    ASSERT_GT(qbuf->total_data_size, 4096);

    umq_buf_free(qbuf);

    qbuf = umq_buf_alloc(10240, 2, test_ipc_umqh(), nullptr);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_EQ(qbuf->total_data_size, 10240);
    head = qbuf;
    while (head) {
        cnt++;
        printf("head total size %u data size %u buf size %u\n", head->total_data_size, head->data_size, head->buf_size);
        head = head->qbuf_next;
    }
    ASSERT_EQ(cnt, 4);

    ASSERT_EQ(umq_buf_reset(qbuf), 0);
    head = qbuf;
    while (head) {
        cnt++;
        printf("head total size %u data size %u buf size %u\n", head->total_data_size, head->data_size, head->buf_size);
        head = head->qbuf_next;
    }

    ASSERT_EQ(qbuf->total_data_size, 8192 * 2);
    head = qbuf->qbuf_next->qbuf_next;
    ASSERT_EQ(head->total_data_size, 8192 * 2);

    umq_buf_free(qbuf);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_umq_data_to_head_failure)
{
    umq_buf_t *qbuf;

    ASSERT_EQ(umq_data_to_head(nullptr), nullptr);

    qbuf = umq_buf_alloc(4096, 1, test_ipc_umqh(), nullptr);
    ASSERT_NE(qbuf, nullptr);

    ASSERT_EQ(umq_data_to_head(qbuf->buf_data), nullptr);

    umq_buf_free(qbuf);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_pro_umq_post_failure)
{
    umq_buf_t *qbuf, *bad;

    qbuf = umq_buf_alloc(4096, 1, test_ipc_umqh(), nullptr);
    ASSERT_NE(qbuf, nullptr);

    umq_io_option_t opt = {
        .flag = UMQ_IO_OPTION_FLAG_DIRECTION,
        .io_direction = UMQ_IO_MAX,
    };

    ASSERT_LT(umq_post(0, nullptr, &opt, nullptr), 0);
    opt.io_direction = UMQ_IO_ALL;
    ASSERT_LT(umq_post(test_ipc_umqh(), qbuf, &opt, &bad), 0);
    opt.io_direction = UMQ_IO_TX;
    ASSERT_LT(umq_post(test_ipc_umqh(), qbuf, &opt, &bad), 0);
    opt.io_direction = UMQ_IO_RX;
    ASSERT_LT(umq_post(test_ipc_umqh(), qbuf, &opt, &bad), 0);

    umq_buf_free(qbuf);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_pro_umq_poll_failure)
{
    umq_buf_t *buf[2];
    umq_io_option_t opt = {
        .flag = UMQ_IO_OPTION_FLAG_DIRECTION,
        .io_direction = UMQ_IO_MAX,
    };
    ASSERT_LT(umq_poll(0, &opt, nullptr, 0), 0);
    opt.io_direction = UMQ_IO_ALL;
    ASSERT_LT(umq_poll(test_ipc_umqh(), &opt, buf, 1), 0);
    ASSERT_LT(umq_poll(test_ipc_umqh(), &opt, buf, 2), 0);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_pro_umq_interrupt_fd_get_failure)
{
    umq_interrupt_option_t opt;
    ASSERT_NE(umq_interrupt_fd_get(0, nullptr), 0);
    ASSERT_NE(umq_interrupt_fd_get(test_ipc_umqh(), nullptr), 0);
    ASSERT_NE(umq_interrupt_fd_get(test_ipc_umqh(), &opt), 0);
}

// IPC umq not support
TEST_F(UmqIPCTest, test_pro_umq_get_cq_event_failure)
{
    umq_interrupt_option_t opt;
    ASSERT_NE(umq_get_cq_event(0, nullptr), 0);
    ASSERT_NE(umq_get_cq_event(test_ipc_umqh(), nullptr), 0);
    ASSERT_NE(umq_get_cq_event(test_ipc_umqh(), &opt), 0);
}

TEST(UmqIPCRawTest, test_umq_buf_split)
{
    int cnt;
    umq_buf_t *qbuf, *head, *node;
    uint64_t umqh;

    ASSERT_NE(umq_buf_split(nullptr, nullptr), 0);

    ASSERT_EQ(test_umq_ipc_init(), 0);
    umqh = test_umq_create_ipc_qh(false, 0);
    ASSERT_NE(umqh, UMQ_INVALID_HANDLE);

    ASSERT_NE(umq_buf_split(nullptr, nullptr), 0);

    qbuf = umq_buf_alloc(4096, 10, umqh, nullptr);
    ASSERT_NE(qbuf, nullptr);
    cnt = 0;
    head = qbuf;
    while (head) {
        head = head->qbuf_next;
        cnt++;
        if (cnt == 5) {
            node = head;
        }
    }
    ASSERT_EQ(cnt, 10);

    head = (umq_buf_t *)100;
    ASSERT_NE(umq_buf_split(qbuf, head), 0);

    ASSERT_EQ(umq_buf_split(qbuf, node), 0);
    head = qbuf;
    cnt = 0;
    while (head) {
        cnt++;
        head = head->qbuf_next;
    }
    ASSERT_EQ(cnt, 5);

    umq_buf_free(qbuf);
    umq_buf_free(node);

    ASSERT_EQ(umq_destroy(umqh), 0);
    umq_uninit();
}

TEST(UmqIPCRawTest, test_umq_create_failure)
{
    umq_create_option_t option;
    memset(&option, 0, sizeof(umq_create_option_t));
    (void)snprintf(option.name, UMQ_NAME_MAX_LEN, "%s", "test_umq_ipc");
    uint64_t umqh;

    umqh = umq_create(nullptr);
    ASSERT_EQ(umqh, UMQ_INVALID_HANDLE);

    option.trans_mode = UMQ_TRANS_MODE_MAX;
    umqh = umq_create(&option);
    ASSERT_EQ(umqh, UMQ_INVALID_HANDLE);

    option.trans_mode = UMQ_TRANS_MODE_UCP;
    umqh = umq_create(&option);
    ASSERT_EQ(umqh, UMQ_INVALID_HANDLE);
    option.trans_mode = UMQ_TRANS_MODE_UB;
}

// IPC umq not support
TEST(UmqIPCRawTest, test_umq_async_event_fd_get_failure)
{
    umq_trans_info_t trans_info;
    memset(&trans_info, 0, sizeof(umq_trans_info_t));
    trans_info.trans_mode = UMQ_TRANS_MODE_IPC;

    ASSERT_EQ(umq_async_event_fd_get(&trans_info), UMQ_INVALID_FD);

    ASSERT_EQ(test_umq_ipc_init(), 0);

    ASSERT_EQ(umq_async_event_fd_get(nullptr), UMQ_INVALID_FD);
    ASSERT_EQ(umq_async_event_fd_get(&trans_info), UMQ_INVALID_FD);

    umq_uninit();
}

// IPC umq not support
TEST(UmqIPCRawTest, test_umq_get_async_event_failure)
{
    umq_trans_info_t trans_info;
    memset(&trans_info, 0, sizeof(umq_trans_info_t));
    trans_info.trans_mode = UMQ_TRANS_MODE_IPC;
    umq_async_event_t event;

    ASSERT_NE(umq_get_async_event(&trans_info, &event), 0);

    ASSERT_EQ(test_umq_ipc_init(), 0);

    ASSERT_NE(umq_get_async_event(&trans_info, nullptr), 0);
    ASSERT_NE(umq_get_async_event(&trans_info, &event), 0);

    umq_uninit();
}

// IPC umq not support
TEST(UmqIPCRawTest, test_umq_ack_async_event_failure)
{
    umq_async_event_t event;
    event.trans_info.trans_mode = UMQ_TRANS_MODE_IPC;

    umq_ack_async_event(&event);

    ASSERT_EQ(test_umq_ipc_init(), 0);

    umq_ack_async_event(nullptr);
    event.trans_info.trans_mode = UMQ_TRANS_MODE_MAX;
    umq_ack_async_event(&event);
    event.trans_info.trans_mode = UMQ_TRANS_MODE_IPC;
    umq_ack_async_event(&event);

    umq_uninit();
}

// IPC umq not support
TEST(UmqIPCRawTest, test_umq_get_route_list_failure)
{
    umq_route_key_t route_key;
    umq_route_list_t route_list;
    memset(&route_key, 0, sizeof(umq_route_key_t));
    memset(&route_list, 0, sizeof(umq_route_list_t));

    ASSERT_NE(umq_get_route_list(&route_key, UMQ_TRANS_MODE_IPC, &route_list), 0);

    ASSERT_EQ(test_umq_ipc_init(), 0);

    ASSERT_NE(umq_get_route_list(nullptr, UMQ_TRANS_MODE_IPC, nullptr), 0);
    ASSERT_NE(umq_get_route_list(&route_key, UMQ_TRANS_MODE_IPC, nullptr), 0);
    ASSERT_NE(umq_get_route_list(&route_key, UMQ_TRANS_MODE_MAX, &route_list), 0);
    ASSERT_NE(umq_get_route_list(&route_key, UMQ_TRANS_MODE_IPC, &route_list), 0);

    umq_uninit();
}

// IPC umq not support
TEST(UmqIPCRawTest, test_umq_dev_add_failure)
{
    umq_trans_info_t trans_info;
    memset(&trans_info, 0, sizeof(umq_trans_info_t));
    trans_info.trans_mode = UMQ_TRANS_MODE_IPC;

    ASSERT_NE(umq_dev_add(nullptr), 0);
    ASSERT_NE(umq_dev_add(&trans_info), 0);

    ASSERT_EQ(test_umq_ipc_init(), 0);
    ASSERT_NE(umq_dev_add(nullptr), 0);
    ASSERT_NE(umq_dev_add(&trans_info), 0);

    umq_uninit();
}

// IPC umq not support
TEST(UmqIPCRawTest, test_umq_tp_dev_info_get_failure)
{
    umq_dev_info_t dev_info;
    char name[] = "";

    ASSERT_NE(umq_dev_info_get(nullptr, UMQ_TRANS_MODE_MAX, nullptr), 0);
    ASSERT_NE(umq_dev_info_get(nullptr, UMQ_TRANS_MODE_IPC, &dev_info), 0);
    ASSERT_NE(umq_dev_info_get(name, UMQ_TRANS_MODE_IPC, &dev_info), 0);

    ASSERT_EQ(test_umq_ipc_init(), 0);

    ASSERT_NE(umq_dev_info_get(nullptr, UMQ_TRANS_MODE_MAX, nullptr), 0);
    ASSERT_NE(umq_dev_info_get(nullptr, UMQ_TRANS_MODE_IPC, &dev_info), 0);
    ASSERT_NE(umq_dev_info_get(name, UMQ_TRANS_MODE_IPC, &dev_info), 0);

    umq_uninit();
}

TEST(UmqIPCRawTest, test_umq_buf_alloc_failure)
{
    uint64_t umqh;
    umq_alloc_option_t option;
    memset(&option, 0, sizeof(umq_alloc_option_t));
    umq_buf_t *qbuf;

    qbuf = umq_buf_alloc(4096, 0, 0, nullptr);
    ASSERT_EQ(qbuf, nullptr);

    ASSERT_EQ(test_umq_ipc_init(), 0);
    umqh = test_umq_create_ipc_qh(false, 0);
    ASSERT_NE(umqh, UMQ_INVALID_HANDLE);

    option.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    option.headroom_size = UMQ_HEADROOM_SIZE_LIMIT + 1;
    qbuf = umq_buf_alloc(4096, 1, 0, &option);
    ASSERT_EQ(qbuf, nullptr);
    option.flag = 0;
    option.headroom_size = 0;

    // alloc without umqh not support
    qbuf = umq_buf_alloc(4096, 1, 0, &option);
    ASSERT_EQ(qbuf, nullptr);

    qbuf = umq_buf_alloc(umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_MID), 1, 0, &option);
    ASSERT_EQ(qbuf, nullptr);
    umq_buf_free(qbuf);

    ASSERT_EQ(umq_destroy(umqh), 0);
    umq_uninit();
}

TEST(UmqIPCRawTest, test_umq_buf_break_and_free)
{
    uint64_t umqh;
    umq_alloc_option_t option;
    memset(&option, 0, sizeof(umq_alloc_option_t));
    umq_buf_t *qbuf;

    ASSERT_EQ(umq_buf_break_and_free(nullptr), nullptr);

    ASSERT_EQ(test_umq_ipc_init(), 0);
    umqh = test_umq_create_ipc_qh(false, 0);
    ASSERT_NE(umqh, UMQ_INVALID_HANDLE);

    qbuf = umq_buf_alloc(4096, 1, umqh, &option);
    ASSERT_NE(qbuf, nullptr);

    ASSERT_EQ(umq_buf_break_and_free(qbuf), nullptr);

    qbuf = umq_buf_alloc(4096, 2, umqh, &option);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_NE(qbuf->qbuf_next, nullptr);
    qbuf = umq_buf_break_and_free(qbuf);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_EQ(qbuf->qbuf_next, nullptr);
    umq_buf_free(qbuf);

    qbuf = umq_buf_alloc(10240, 2, umqh, &option);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_NE(qbuf->qbuf_next, nullptr);
    qbuf = umq_buf_break_and_free(qbuf);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_NE(qbuf->qbuf_next, nullptr);
    ASSERT_EQ(qbuf->qbuf_next->qbuf_next, nullptr);
    umq_buf_free(qbuf);

    ASSERT_EQ(umq_destroy(umqh), 0);
    umq_uninit();
}
