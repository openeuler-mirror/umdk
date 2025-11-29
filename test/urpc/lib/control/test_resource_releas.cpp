/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc resource release test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include "resource_release.h"
#include "urpc_timer.h"
#include "urpc_framework_api.h"
#include "urpc_util.h"
#include "urpc_framework_errno.h"

static urpc_log_config_t g_log_cfg;

class resource_release_test : public ::testing::Test {
public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
        g_log_cfg.log_flag = URPC_LOG_FLAG_LEVEL;
        g_log_cfg.level = URPC_LOG_LEVEL_DEBUG;
        ASSERT_EQ(urpc_log_config_set(&g_log_cfg), URPC_SUCCESS);
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
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

static int test_release_callback(void *args, bool force)
{
    static int again_cnt = 0;
    if (force) {
        printf("force to release\n");
    }

    uint64_t now = get_timestamp();

    if (args == NULL) {
        printf("release NULL again %lu\n", now);
        return (again_cnt++ == 0) ? URPC_RESOURCE_RELEASE_AGAIN : URPC_RESOURCE_RELEASE_DONE;
    }

    free(args);
    printf("release test %lu\n", now);
    return URPC_RESOURCE_RELEASE_DONE;
}

uint32_t task_id = 0;
uint32_t expect_id = 1;

TEST_F(resource_release_test, TestReleaseStartTimer)
{
    int release_size = 100;
    int ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, 0);

    ret = urpc_resource_release_init();
    ASSERT_EQ(ret, 0);

    ret = urpc_resource_release_entry_add(test_release_callback, NULL, 0, &task_id);
    ASSERT_EQ(ret, -1);

    uint32_t now = get_timestamp();
    printf("start release test %u\n", now);

    void *args = malloc(release_size);
    ASSERT_NE(args, nullptr);
    ret = urpc_resource_release_entry_add(test_release_callback, args, 1, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);

    // test callback restart
    ret = urpc_resource_release_entry_add(test_release_callback, NULL, 1, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);

    // test resource list reset empty
    sleep(3);

    args = malloc(release_size);
    ASSERT_NE(args, nullptr);
    ret = urpc_resource_release_entry_add(test_release_callback, args, 2, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);

    args = malloc(release_size);
    ASSERT_NE(args, nullptr);
    ret = urpc_resource_release_entry_add(test_release_callback, args, 3, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);

    args = malloc(release_size);
    ASSERT_NE(args, nullptr);
    ret = urpc_resource_release_entry_add(test_release_callback, args, 1, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);

    sleep(2);

    printf("sleep stop %u\n", get_timestamp());

    urpc_resource_release_clear();

    urpc_resource_release_uninit();

    urpc_timing_wheel_uninit();
}

TEST_F(resource_release_test, TestStartTimerFailed)
{
    int ret = urpc_timing_wheel_init();
    ASSERT_EQ(ret, 0);

    ret = urpc_resource_release_init();
    ASSERT_EQ(ret, 0);

    uint32_t now = get_timestamp();
    printf("start release test %u\n", now);

    urpc_timer_t *mock_timer = NULL;
    MOCKER(urpc_timer_create).stubs().will(returnValue(mock_timer));
    ret = urpc_resource_release_entry_add(test_release_callback, NULL, 1, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);
    ASSERT_EQ(urpc_resource_release_entry_delete(task_id), true);

    MOCKER(urpc_timer_start).stubs().will(returnValue(URPC_FAIL));
    ret = urpc_resource_release_entry_add(test_release_callback, NULL, 1, &task_id);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(task_id, expect_id++);
    ASSERT_EQ(urpc_resource_release_entry_delete(task_id), true);

    urpc_resource_release_clear();

    urpc_resource_release_uninit();

    urpc_timing_wheel_uninit();
}
