/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: umq api test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "msg_ring.h"
#include "umq_api.h"
#include "umq_inner.h"

class UmqAPITest : public ::testing::Test {
  public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
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

TEST_F(UmqAPITest, test_umq_log_config_get_failure)
{
    ASSERT_NE(umq_log_config_get(nullptr), 0);
}

TEST_F(UmqAPITest, test_umq_log_config_set_failure)
{
    umq_log_config_t cfg;
    memset(&cfg, 0, sizeof(umq_log_config_t));

    ASSERT_NE(umq_log_config_set(nullptr), 0);

    cfg.log_flag |= UMQ_LOG_FLAG_LEVEL;
    cfg.level = UMQ_LOG_LEVEL_MAX;
    ASSERT_NE(umq_log_config_set(&cfg), 0);
    cfg.level = UMQ_LOG_LEVEL_INFO;
}

TEST_F(UmqAPITest, test_umq_log_config_set_and_get_success)
{
    umq_log_config_t cfg0, cfg;
    memset(&cfg0, 0, sizeof(umq_log_config_t));
    memset(&cfg, 0, sizeof(umq_log_config_t));

    ASSERT_EQ(umq_log_config_get(&cfg0), 0);
    ASSERT_EQ(cfg0.log_flag, 0);

    cfg.log_flag |= UMQ_LOG_FLAG_LEVEL | UMQ_LOG_FLAG_RATE_LIMITED | UMQ_LOG_FLAG_FUNC;
    cfg.level = UMQ_LOG_LEVEL_EMERG;
    ASSERT_EQ(umq_log_config_set(&cfg), 0);

    ASSERT_EQ(umq_log_config_get(&cfg), 0);
    ASSERT_EQ(cfg.level, UMQ_LOG_LEVEL_EMERG);
    ASSERT_EQ(cfg.rate_limited.interval_ms, 0);
    ASSERT_EQ(cfg.rate_limited.num, 0);

    // restore log config
    ASSERT_EQ(umq_log_config_set(&cfg0), 0);
}

TEST_F(UmqAPITest, test_is_timeout)
{
    struct timespec start;
    (void)clock_gettime(CLOCK_MONOTONIC, &start);

    start.tv_sec -= 1;
    ASSERT_EQ(is_timeout(&start, 1000), true);

    start.tv_sec += 100;
    ASSERT_EQ(is_timeout(&start, 1000), false);
}

TEST_F(UmqAPITest, test_umq_msg_ring_create_failure)
{
    char name[MAX_MSG_RING_NAME + 1];
    msg_ring_option_t cfg;
    memset(&cfg, 0, sizeof(msg_ring_option_t));

    cfg.owner = true;
    cfg.tx_max_buf_size = 32;
    cfg.tx_depth = 32;
    cfg.rx_max_buf_size = 32;
    cfg.rx_depth = 32;

    ASSERT_EQ(msg_ring_create(name, sizeof(name), &cfg), nullptr);

    MOCKER(shm_open).stubs().will(returnValue(-1));
    ASSERT_EQ(msg_ring_create(name, MAX_MSG_RING_NAME, &cfg), nullptr);
    cfg.owner = false;
    ASSERT_EQ(msg_ring_create(name, MAX_MSG_RING_NAME, &cfg), nullptr);
}

TEST_F(UmqAPITest, test_umq_msg_ring_create_success)
{
    msg_ring_t *r;
    char name[MAX_MSG_RING_NAME];
    (void)snprintf(name, MAX_MSG_RING_NAME, "%s", "umq_test_ring");
    msg_ring_option_t cfg;
    memset(&cfg, 0, sizeof(msg_ring_option_t));

    cfg.owner = true;
    cfg.tx_max_buf_size = 32;
    cfg.tx_depth = 32;
    cfg.rx_max_buf_size = 32;
    cfg.rx_depth = 32;

    r = msg_ring_create(name, sizeof(name), &cfg);
    ASSERT_NE(r, nullptr);

    msg_ring_destroy(r);
}

TEST_F(UmqAPITest, test_umq_msg_ring_post_poll)
{
    int ret;
    uint32_t recv_len = 0;
    msg_ring_t *r_t, *r_r;
    char msg[] = "test_umq_msg_ring_post_poll";
    uint32_t msg_len = static_cast<uint32_t>(strlen(msg));
    char recv_msg[32];
    char name[MAX_MSG_RING_NAME];
    (void)snprintf(name, MAX_MSG_RING_NAME, "%s", "umq_test_ring");
    msg_ring_option_t cfg;
    memset(&cfg, 0, sizeof(msg_ring_option_t));

    cfg.owner = true;
    cfg.tx_max_buf_size = 32;
    cfg.tx_depth = 32;
    cfg.rx_max_buf_size = 32;
    cfg.rx_depth = 32;

    shm_unlink(name);
    r_t = msg_ring_create(name, sizeof(name), &cfg);
    ASSERT_NE(r_t, nullptr);

    cfg.owner = false;
    r_r = msg_ring_create(name, sizeof(name), &cfg);
    ASSERT_NE(r_r, nullptr);

    ret = msg_ring_post_tx(r_t, msg, msg_len);
    ASSERT_EQ(ret, 0);

    ret = msg_ring_poll_tx(r_r, recv_msg, 32, &recv_len);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(recv_len, msg_len);
    ret = memcmp(recv_msg, msg, recv_len);
    ASSERT_EQ(ret, 0);

    ret = msg_ring_post_rx(r_r, msg, msg_len);
    ASSERT_EQ(ret, 0);

    recv_len = 0;
    memset(recv_msg, 0, 32);
    ret = msg_ring_poll_rx(r_t, recv_msg, 32, &recv_len);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(recv_len, msg_len);
    ret = memcmp(recv_msg, msg, recv_len);
    ASSERT_EQ(ret, 0);

    ret = msg_ring_post_rx(r_r, msg, msg_len);
    ASSERT_EQ(ret, 0);
    ret = msg_ring_post_rx(r_r, msg, msg_len);
    ASSERT_EQ(ret, 0);

    char *recv_batch[2];
    char recv1[32];
    char recv2[32];
    recv_batch[0] = recv1;
    recv_batch[1] = recv2;
    uint32_t recv_batch_len[2];
    ret = msg_ring_poll_rx_batch(r_t, recv_batch, 32, recv_batch_len, 2);
    ASSERT_EQ(ret, 2);
    for (int i = 0; i < ret; i++) {
        ASSERT_EQ(recv_batch_len[i], msg_len);
        ret = memcmp(recv_batch[i], msg, recv_batch_len[i]);
        ASSERT_EQ(ret, 0);
    }

    msg_ring_destroy(r_t);
    msg_ring_destroy(r_r);
}
