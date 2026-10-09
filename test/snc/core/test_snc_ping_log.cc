/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Unit tests for snc_ping_log module
 */
#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include "snc_ping_log.h"
}

class SncPingLogTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        unsetenv("SNC_LOG_DIR");
        SncLogInit();
    }

    void TearDown() override
    {
        SncLogDeinit();
        unsetenv("SNC_LOG_DIR");
    }

    std::string CreateTempDir()
    {
        char tmpl[] = "/tmp/snc_ping_test_XXXXXX";
        char* dir = mkdtemp(tmpl);
        return std::string(dir);
    }

    void RemoveDir(const std::string& path)
    {
        std::string cmd = "rm -rf " + path;
        system(cmd.c_str());
    }
};

TEST_F(SncPingLogTest, InitWithoutLogDirLogsToStdout)
{
    SncLogInit();
    LOG_INFO("test message to stdout");
    SUCCEED();
}

TEST_F(SncPingLogTest, InitWithLogDirWritesToFile)
{
    std::string dir = CreateTempDir();
    setenv("SNC_LOG_DIR", dir.c_str(), 1);
    SncLogInit();
    LOG_INFO("test message to file");
    fflush(nullptr);

    std::string logPath = dir + "/snc.log";
    std::ifstream f(logPath);
    ASSERT_TRUE(f.good()) << "log file should exist at " << logPath;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    EXPECT_TRUE(content.find("test message to file") != std::string::npos)
        << "log file should contain the message";
    f.close();
    RemoveDir(dir);
}

TEST_F(SncPingLogTest, AllLogLevels)
{
    LOG_DEBUG("debug message %d", 1);
    LOG_INFO("info message %d", 2);
    LOG_WARN("warn message %d", 3);
    LOG_ERROR("error message %d", 4);
    SUCCEED();
}

TEST_F(SncPingLogTest, DeinitClosesLogFile)
{
    std::string dir = CreateTempDir();
    setenv("SNC_LOG_DIR", dir.c_str(), 1);
    SncLogInit();
    LOG_INFO("before deinit");
    SncLogDeinit();
    LOG_INFO("after deinit goes to stdout");
    SncLogInit();
    RemoveDir(dir);
}

TEST_F(SncPingLogTest, ReinitSwitchesLogFile)
{
    std::string dir1 = CreateTempDir();
    std::string dir2 = CreateTempDir();
    setenv("SNC_LOG_DIR", dir1.c_str(), 1);
    SncLogInit();
    LOG_INFO("first log");
    setenv("SNC_LOG_DIR", dir2.c_str(), 1);
    SncLogInit();
    LOG_INFO("second log");
    fflush(nullptr);

    std::string log2 = dir2 + "/snc.log";
    std::ifstream f(log2);
    ASSERT_TRUE(f.good());
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    EXPECT_TRUE(content.find("second log") != std::string::npos);
    f.close();
    RemoveDir(dir1);
    RemoveDir(dir2);
}

TEST_F(SncPingLogTest, ConcurrentWritesAreThreadSafe)
{
    const int threadCount = 8;
    const int writesPerThread = 100;
    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([i, writesPerThread]() {
            for (int j = 0; j < writesPerThread; j++) {
                LOG_INFO("thread %d write %d", i, j);
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }
    SUCCEED();
}

TEST_F(SncPingLogTest, LevelToStrDefaultIsError)
{
    SncLogLevel unknown = (SncLogLevel)99;
    const char* levelStr = nullptr;
    switch (unknown) {
        case LOG_LEVEL_DEBUG: levelStr = "DEBUG"; break;
        case LOG_LEVEL_INFO: levelStr = "INFO"; break;
        case LOG_LEVEL_WARN: levelStr = "WARN"; break;
        default: levelStr = "ERROR"; break;
    }
    EXPECT_STREQ("ERROR", levelStr);
}

TEST_F(SncPingLogTest, EmptyLogDirFallsBackToStdout)
{
    setenv("SNC_LOG_DIR", "", 1);
    SncLogInit();
    LOG_INFO("empty dir fallback to stdout");
    SUCCEED();
}
