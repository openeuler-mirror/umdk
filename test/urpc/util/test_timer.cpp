/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc timer test
 */
#include <stdlib.h>

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include "urpc_framework_api.h"
#include "urpc_manage.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_util.h"
#include "urpc_hmap.h"
#include "urpc_thread.h"

#include "urpc_timer.h"

static urpc_log_config_t g_log_cfg;

class timer_test : public ::testing::Test {
public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
        g_log_cfg.log_flag = URPC_LOG_FLAG_LEVEL;
        g_log_cfg.level = URPC_LOG_LEVEL_DEBUG;
        ASSERT_EQ(urpc_log_config_set(&g_log_cfg), URPC_SUCCESS);
        int ret = urpc_thread_ctx_init();
        ASSERT_EQ(ret, 0);
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        urpc_thread_ctx_uninit();

        g_log_cfg.level = URPC_LOG_LEVEL_INFO;
        ASSERT_EQ(urpc_log_config_set(&g_log_cfg), URPC_SUCCESS);
        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {}

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {}
};

static inline void test_timer_cb(void *arg)
{
    uint64_t *time = (uint64_t *)arg;
    *time = get_timestamp_ns();

    printf("timer callback %lu\n", *time);
}

TEST_F(timer_test, TestTimingWheel)
{
    // run get_cpu_mhz to init
    (void)urpc_get_cpu_hz();

    int ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, 0);

    ret = urpc_manage_init();
    ASSERT_EQ(ret, 0);

    // test 750ms timer
    uint32_t timeout_ms = 750;
    urpc_timer_t *timer = urpc_timer_create(URPC_INVALID_ID_U32, false);
    ASSERT_NE(timer, nullptr);

    uint64_t begin = get_timestamp_ns();
    uint64_t end = 0;

    ret = urpc_timer_start(timer, timeout_ms, test_timer_cb, (void *)&end, true);
    ASSERT_EQ(ret, 0);

    urpc_timer_restart(timer);

    sleep(1);

    urpc_timer_destroy(timer);

    uint64_t delta = end > begin ? end - begin : begin;
    delta = delta / NS_PER_MS > timeout_ms ? delta / NS_PER_MS - timeout_ms : timeout_ms - delta / NS_PER_MS;

    // expect error less than 10ms (1 tick)
    EXPECT_LE(delta, (uint64_t)10);

    urpc_manage_uninit();
    urpc_timing_wheel_uninit();
}

static inline void test_timer_massive_cb(void *arg)
{
    uint64_t *time = (uint64_t *)arg;
    *time = urpc_get_cpu_cycles();
}

TEST_F(timer_test, TestTimerMassive)
{
    g_log_cfg.level = URPC_LOG_LEVEL_INFO;
    ASSERT_EQ(urpc_log_config_set(&g_log_cfg), URPC_SUCCESS);

    int ret;
    int default_timer_num = 8000;
    int chid_num = 45;
    int timer_num = (default_timer_num + chid_num * 2048);
    uint32_t timeout_ms;
    uint64_t cycles = 0;
    urpc_timer_t **t = (urpc_timer_t **)malloc(sizeof(urpc_timer_t *) * timer_num);
    ASSERT_NE(t, nullptr);

    ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, 0);
    ret = urpc_manage_init();
    ASSERT_EQ(ret, 0);

    // 1. start 10w rand timers
    for (int i = 0; i < default_timer_num; i++) {
        t[i] = urpc_timer_create(URPC_INVALID_ID_U32, false);
        ASSERT_NE(t[i], nullptr);

        timeout_ms = rand() % 1000 + 10;  // 10ms ~ 1.01s

        ret = urpc_timer_start(t[i], timeout_ms, test_timer_massive_cb, (void *)&cycles, true);
        ASSERT_EQ(ret, 0);
    }

    for (int i = 0; i < chid_num; i++) {
        ret = urpc_timer_pool_add(i, 2048, false);
        ASSERT_EQ(ret, 0);

        for (int j = 0; j < 2048; j++) {
            int idx = default_timer_num + i * 2048 + j;
            t[idx] = urpc_timer_create(i, false);
            ASSERT_NE(t[idx], nullptr);

            timeout_ms = rand() % 1000 + 10;  // 10ms ~ 1.01s

            ret = urpc_timer_start(t[idx], timeout_ms, test_timer_massive_cb, (void *)&cycles, true);
            ASSERT_EQ(ret, 0);
        }
    }

    // 2. start test timer to test accuracy
    uint64_t cost = urpc_get_cpu_cycles();
    urpc_timer_t *timer = urpc_timer_create(URPC_INVALID_ID_U32, false);
    cost = urpc_get_cpu_cycles() - cost;
    cost = cost * NS_PER_SEC / urpc_get_cpu_hz();
    ASSERT_NE(timer, nullptr);

    // 2.1 expect create cost less than 100us
    printf("create timer cost %lu ns\n", cost);
    EXPECT_LE(cost, (uint64_t)100 * NS_PER_MS);

    timeout_ms = 1000;
    uint64_t begin = get_timestamp_ns();
    uint64_t end = 0;
    cost = urpc_get_cpu_cycles();
    ret = urpc_timer_start(timer, timeout_ms, test_timer_cb, (void *)&end, true);
    cost = urpc_get_cpu_cycles() - cost;
    cost = cost * NS_PER_SEC / urpc_get_cpu_hz();
    ASSERT_EQ(ret, 0);

    // 2.2 expect start timer cost less than 100us
    printf("start timer cost %lu ns\n", cost);
    EXPECT_LE(cost, (uint64_t)100 * NS_PER_MS);

    usleep(1500 * 1000);

    uint64_t delta = end > begin ? end - begin : begin;
    delta = delta / NS_PER_MS > timeout_ms ? delta / NS_PER_MS - timeout_ms : timeout_ms - delta / NS_PER_MS;
    // 2.3 expect error less than 10ms (1 tick), if end is 0 means timer cb not executed
    printf("timer error is %lu ms, begin %lu ns, end %lu ns\n", delta, begin, end);
    EXPECT_LE(delta, (uint64_t)10);

    cost = urpc_get_cpu_cycles();
    urpc_timer_destroy(timer);
    cost = urpc_get_cpu_cycles() - cost;
    cost = cost * NS_PER_SEC / urpc_get_cpu_hz();

    // 2.4 expect destroy cost less than 100us
    printf("destroy timer cost %lu ns\n", cost);
    EXPECT_LE(cost, (uint64_t)100 * NS_PER_US);

    // 3. release rand timers
    for (int i = 0; i < timer_num; i++) {
        urpc_timer_destroy(t[i]);
    }

    for (int i = 0; i < chid_num; i++) {
        urpc_timer_pool_delete(i, false);
    }

    free(t);

    urpc_manage_uninit();
    urpc_timing_wheel_uninit();
}

#define TEST_TIMER_START_TOMEOUTMS 100
#define URPC_TIMER_MAGIC_NUM 0x33445577u

TEST_F(timer_test, TestTimerStart)
{
    int ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, 0);
    ret = urpc_manage_init();
    ASSERT_EQ(ret, 0);

    urpc_timer_t *timer = urpc_timer_create(URPC_INVALID_ID_U32, false);

    // timer is NULL
    ASSERT_EQ(urpc_timer_start(NULL, 0, NULL, NULL, false), URPC_FAIL);

    // func is NULL
    ASSERT_EQ(urpc_timer_start(timer, 0, NULL, NULL, false), URPC_FAIL);

    // timeout less then 10ms
    ASSERT_EQ(urpc_timer_start(timer, 0, test_timer_cb, NULL, false), URPC_FAIL);

    // start timer
    ASSERT_EQ(urpc_timer_start(timer, TEST_TIMER_START_TOMEOUTMS, test_timer_cb, NULL, false), URPC_SUCCESS);

    // restart timer
    ASSERT_EQ(urpc_timer_start(timer, TEST_TIMER_START_TOMEOUTMS, test_timer_cb, NULL, false), URPC_SUCCESS);

    urpc_timer_destroy(NULL);

    urpc_manage_uninit();
    urpc_timing_wheel_uninit();
}

TEST_F(timer_test, TestTimerReStart)
{
    int ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, 0);
    ret = urpc_manage_init();
    ASSERT_EQ(ret, 0);

    // timer is NULL
    ASSERT_EQ(urpc_timer_restart(NULL), URPC_FAIL);

    urpc_manage_uninit();
    urpc_timing_wheel_uninit();
}

TEST_F(timer_test, TestTimingTimerPoolInit)
{
    MOCKER(urpc_timer_pool_add).stubs().will(returnValue(URPC_FAIL));
    int ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, URPC_FAIL);

    MOCKER(urpc_hmap_init).stubs().will(returnValue(URPC_FAIL));
    ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, URPC_FAIL);

    ASSERT_EQ(urpc_timer_create(300001, false), (urpc_timer_t *)NULL);
}