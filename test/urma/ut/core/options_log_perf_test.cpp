/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core option, log and perf unit tests.
 */

#include "core_fixture.h"

using namespace urma_test_core;

TEST(UrmaCoreTest, CheckOptValidUpdatesOnlyOptionMask)
{
    uint64_t mask = 0;

    EXPECT_EQ(URMA_SUCCESS, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_DEPTH_OPT, sizeof(uint32_t)));
    EXPECT_EQ(0U, mask);

    EXPECT_EQ(URMA_SUCCESS, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_ID_OPT, sizeof(uint32_t)));
    EXPECT_EQ(URMA_TEST_ID_MASK, mask);
}

TEST(UrmaCoreTest, CheckOptValidRejectsWrongLengthAndIgnoresUnknownOpt)
{
    uint64_t mask = 0;

    EXPECT_EQ(URMA_EINVAL, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_ID_OPT, sizeof(uint64_t)));
    EXPECT_EQ(0U, mask);

    EXPECT_EQ(URMA_SUCCESS, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), 0xff, sizeof(uint32_t)));
    EXPECT_EQ(0U, mask);
}

TEST(UrmaCoreTest, SetOptionsCommonWritesTargetStruct)
{
    urma_test_cfg_t cfg = {};
    urma_test_opt_t opt = {};
    urma_test_cfg_t jfsCfg = {};
    uint32_t depth = 128;
    uint32_t id = 7;
    uint64_t userCtx = 0x12345678;

    EXPECT_EQ(URMA_SUCCESS, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_DEPTH_OPT, &depth, sizeof(depth), &cfg, &opt, &jfsCfg));
    EXPECT_EQ(depth, cfg.depth);

    EXPECT_EQ(URMA_SUCCESS, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_ID_OPT, &id, sizeof(id), &cfg, &opt, &jfsCfg));
    EXPECT_EQ(id, opt.id);

    EXPECT_EQ(URMA_SUCCESS, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_JFS_OPT, &userCtx, sizeof(userCtx), &cfg, &opt, &jfsCfg));
    EXPECT_EQ(userCtx, jfsCfg.userCtx);

    EXPECT_EQ(URMA_EINVAL, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), 0xff, &id, sizeof(id), &cfg, &opt, &jfsCfg));
}

TEST(UrmaCoreTest, UbaggSwitchCounter)
{
    urma_ubagg_switch_init();
    EXPECT_EQ(0U, urma_ubagg_switch_get());
    urma_ubagg_switch_inc();
    urma_ubagg_switch_inc();
    EXPECT_EQ(2U, urma_ubagg_switch_get());
}

TEST(UrmaCoreTest, LogApisHandleCallbacksLevelsTagsAndEnv)
{
    const char *oldLevelEnv = getenv("URMA_LOG_LEVEL");
    const char *oldSeparatorEnv = getenv("URMA_LOG_SEPARATOR");
    std::string oldLevel = oldLevelEnv == nullptr ? "" : oldLevelEnv;
    std::string oldSeparator = oldSeparatorEnv == nullptr ? "" : oldSeparatorEnv;

    g_logCallbackCount = 0;
    g_locLogCallbackCount = 0;
    EXPECT_EQ(URMA_EINVAL, urma_register_log_func(nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_register_log_func(MockLogCallback));
    urma_log("CoreLogTest", 1, URMA_VLOG_LEVEL_INFO, "plain %d", 1);
    EXPECT_EQ(1, g_logCallbackCount);
    EXPECT_EQ(static_cast<int>(URMA_VLOG_LEVEL_INFO), g_lastLogLevel);

    EXPECT_EQ(URMA_EINVAL, urma_register_loc_log_func(nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_register_loc_log_func(MockLocLogCallback));
    int locLogCountAfterRegister = g_locLogCallbackCount;
    urma_log_loc("core_test.cpp", "LogApis", 2, URMA_VLOG_LEVEL_ERR, "loc");
    EXPECT_GT(g_locLogCallbackCount, locLogCountAfterRegister);
    EXPECT_EQ(static_cast<int>(URMA_VLOG_LEVEL_ERR), g_lastLogLevel);

    urma_log_set_level(URMA_VLOG_LEVEL_WARNING);
    EXPECT_EQ(URMA_VLOG_LEVEL_WARNING, urma_log_get_level());
    EXPECT_TRUE(urma_log_drop(URMA_VLOG_LEVEL_DEBUG));
    EXPECT_FALSE(urma_log_drop(URMA_VLOG_LEVEL_ERR));
    urma_log_set_level(URMA_VLOG_LEVEL_MAX);
    EXPECT_EQ(URMA_VLOG_LEVEL_WARNING, urma_log_get_level());

    urma_log_set_thread_tag("core-ut");
    EXPECT_STREQ("core-ut", urma_log_get_thread_tag());
    urma_log_set_thread_tag(nullptr);
    EXPECT_STREQ("core-ut", urma_log_get_thread_tag());

    EXPECT_STREQ("fatal", urma_get_level_print(URMA_VLOG_LEVEL_CRIT));
    EXPECT_STREQ("error", urma_get_level_print(URMA_VLOG_LEVEL_ERR));
    EXPECT_STREQ("warning", urma_get_level_print(URMA_VLOG_LEVEL_WARNING));
    EXPECT_STREQ("info", urma_get_level_print(URMA_VLOG_LEVEL_INFO));
    EXPECT_STREQ("debug", urma_get_level_print(URMA_VLOG_LEVEL_DEBUG));
    EXPECT_STREQ("Unknown", urma_get_level_print(URMA_VLOG_LEVEL_MAX));
    EXPECT_EQ(URMA_VLOG_LEVEL_CRIT, urma_log_get_level_from_string("fatal"));
    EXPECT_EQ(URMA_VLOG_LEVEL_ERR, urma_log_get_level_from_string("ERROR"));
    EXPECT_EQ(URMA_VLOG_LEVEL_WARNING, urma_log_get_level_from_string("warning"));
    EXPECT_EQ(URMA_VLOG_LEVEL_INFO, urma_log_get_level_from_string("info"));
    EXPECT_EQ(URMA_VLOG_LEVEL_DEBUG, urma_log_get_level_from_string("debug"));
    EXPECT_EQ(URMA_VLOG_LEVEL_MAX, urma_log_get_level_from_string(nullptr));
    EXPECT_EQ(URMA_VLOG_LEVEL_MAX, urma_log_get_level_from_string("invalid"));

    setenv("URMA_LOG_LEVEL", "debug", 1);
    urma_getenv_log_level();
    EXPECT_EQ(URMA_VLOG_LEVEL_DEBUG, urma_log_get_level());
    setenv("URMA_LOG_LEVEL", "invalid", 1);
    urma_getenv_log_level();
    EXPECT_EQ(URMA_VLOG_LEVEL_DEBUG, urma_log_get_level());
    setenv("URMA_LOG_SEPARATOR", ":", 1);
    urma_getenv_log_separator();
    setenv("URMA_LOG_SEPARATOR", "bad@", 1);
    urma_getenv_log_separator();

    urma_log_rl_state_t rl = {};
    EXPECT_TRUE(urma_log_rl_check(&rl, "core_test.cpp", "LogApis", 3));
    for (uint32_t i = 0; i < URMA_LOG_RL_LIMIT + 1; i++) {
        (void)urma_log_rl_check(&rl, "core_test.cpp", "LogApis", 3);
    }

    EXPECT_EQ(URMA_SUCCESS, urma_unregister_log_func());
    if (oldLevelEnv == nullptr) {
        unsetenv("URMA_LOG_LEVEL");
    } else {
        setenv("URMA_LOG_LEVEL", oldLevel.c_str(), 1);
    }
    if (oldSeparatorEnv == nullptr) {
        unsetenv("URMA_LOG_SEPARATOR");
    } else {
        setenv("URMA_LOG_SEPARATOR", oldSeparator.c_str(), 1);
    }
}

TEST(UrmaCoreTest, PerfApisRecordAndFormatStats)
{
    char perfBuf[8192] = {};
    uint32_t len = sizeof(perfBuf);
    uint64_t start = 0;
    uint64_t end = 0;

    EXPECT_FALSE(urma_perf_is_enabled());
    EXPECT_EQ(URMA_ENOPERM, urma_step_perf(UB_JFS_POST_SEND, 100));
    EXPECT_EQ(URMA_SUCCESS, urma_start_perf());
    EXPECT_TRUE(urma_perf_is_enabled());

    start = urma_get_perf_timestamp();
    end = urma_get_perf_timestamp();
    EXPECT_GE(end, start);
    EXPECT_EQ(URMA_EINVAL, urma_step_perf(URMA_PERF_RECORD_TYPE_MAX, 1));
    EXPECT_EQ(URMA_SUCCESS, urma_step_perf(UB_JFS_POST_SEND, 0));
    EXPECT_EQ(URMA_SUCCESS, urma_step_perf(UB_JFS_POST_SEND, 1));
    EXPECT_EQ(URMA_SUCCESS, urma_step_perf(UB_JFS_POST_SEND, 1024));
    EXPECT_EQ(URMA_EINVAL, urma_get_perf_info(nullptr, &len));
    EXPECT_EQ(URMA_EINVAL, urma_get_perf_info(perfBuf, nullptr));
    len = 1;
    EXPECT_EQ(URMA_EINVAL, urma_get_perf_info(perfBuf, &len));
    len = sizeof(perfBuf);
    EXPECT_EQ(URMA_SUCCESS, urma_get_perf_info(perfBuf, &len));
    EXPECT_NE(nullptr, strstr(perfBuf, "UB_JFS_POST_SEND"));
    EXPECT_GT(len, 0U);

    EXPECT_EQ(URMA_SUCCESS, urma_stop_perf());
    EXPECT_FALSE(urma_perf_is_enabled());
}

TEST(UrmaCoreTest, PerfThreadCleanupRunsOnWorkerExit)
{
    pthread_t thread;

    EXPECT_EQ(URMA_SUCCESS, urma_start_perf());
    ASSERT_EQ(0, pthread_create(&thread, nullptr, CorePerfWorker, nullptr));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_stop_perf());
}
