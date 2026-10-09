/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Unit tests for snc_ping module (with stubbed HCCN/ACL)
 */
#include <gtest/gtest.h>

#include <cstring>
#include <thread>

extern "C" {
#include "snc_ping.h"
#include "snc_ping_log.h"
}

#include "stub_control.h"

class SncPingTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        unsetenv("SNC_LOG_DIR");
        SncLogInit();
        StubReset();
        StubSetRpingGetResultAlwaysAgain(0);
        StubSetRpingResult(10, 10, 0);
    }

    void TearDown() override
    {
        SncLogDeinit();
    }

    SncPingEntity MakeEntity(int devId, const char* eid)
    {
        SncPingEntity e;
        e.devId = devId;
        memset(e.eid, 0, sizeof(e.eid));
        strncpy(e.eid, eid, IP_LEN - 1);
        return e;
    }
};

TEST_F(SncPingTest, InitWithNullEntitiesReturnsError)
{
    EXPECT_EQ(-1, SncPingInit(nullptr, 5));
}

TEST_F(SncPingTest, InitWithZeroCountReturnsError)
{
    SncPingEntity e = MakeEntity(0, "AAAAAA01");
    EXPECT_EQ(-1, SncPingInit(&e, 0));
}

TEST_F(SncPingTest, InitWithNegativeCountReturnsError)
{
    SncPingEntity e = MakeEntity(0, "AAAAAA01");
    EXPECT_EQ(-1, SncPingInit(&e, -1));
}

TEST_F(SncPingTest, InitWithValidEntitiesSucceeds)
{
    SncPingEntity entities[] = {
        MakeEntity(0, "AAAAAA01000000000000000000000001"),
        MakeEntity(0, "AAAAAA01000000000000000000000002"),
        MakeEntity(1, "BBBBBB01000000000000000000000001"),
    };
    EXPECT_EQ(0, SncPingInit(entities, 3));
    EXPECT_EQ(3, StubGetRpingInitCallCount());
    EXPECT_EQ(2, StubGetAclSetDeviceCallCount());

    SncPingEntity cleanup[] = {
        MakeEntity(0, "AAAAAA01000000000000000000000001"),
        MakeEntity(1, "BBBBBB01000000000000000000000001"),
    };
    SncPingDeinit(cleanup, 2);
}

TEST_F(SncPingTest, InitDuplicateDevIdSkipsExisting)
{
    SncPingEntity e1[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e1, 1));
    EXPECT_EQ(1, StubGetRpingInitCallCount());

    SncPingEntity e2[] = { MakeEntity(0, "AAAAAA01000000000000000000000002") };
    ASSERT_EQ(0, SncPingInit(e2, 1));
    EXPECT_EQ(1, StubGetRpingInitCallCount());

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, OneWithUnknownDevIdReturnsError)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    EXPECT_EQ(-1, SncPingOne(999, "AAAAAA01000000000000000000000001",
                              "BBBBBB01000000000000000000000001", &result));

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, OneWithValidDevIdReturnsSuccess)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(0, SncPingOne(0, "AAAAAA01000000000000000000000001",
                             "BBBBBB01000000000000000000000001", &result));
    EXPECT_EQ(10u, result.txPkt);
    EXPECT_EQ(10u, result.rxPkt);
    EXPECT_EQ(0u, result.state);

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, OneFillsResultFields)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    StubSetRpingResult(5, 5, 1);

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(0, SncPingOne(0, "AAAAAA01000000000000000000000001",
                             "BBBBBB01000000000000000000000001", &result));
    EXPECT_EQ(5u, result.txPkt);
    EXPECT_EQ(5u, result.rxPkt);
    EXPECT_EQ(1u, result.state);
    EXPECT_EQ(100u, result.minRTT);
    EXPECT_EQ(200u, result.maxRTT);
    EXPECT_EQ(150u, result.avgRTT);

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, DeinitWithNullEntitiesReturnsError)
{
    EXPECT_EQ(-1, SncPingDeinit(nullptr, 5));
}

TEST_F(SncPingTest, DeinitWithZeroCountReturnsError)
{
    SncPingEntity e = MakeEntity(0, "AAAAAA01000000000000000000000001");
    EXPECT_EQ(-1, SncPingDeinit(&e, 0));
}

TEST_F(SncPingTest, DeinitWithValidEntitiesSucceeds)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    EXPECT_EQ(0, SncPingDeinit(e, 1));
    EXPECT_EQ(1, StubGetRpingDeinitCallCount());
}

TEST_F(SncPingTest, DeinitWithDuplicateDevIdHandlesCorrectly)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingEntity cleanup[] = {
        MakeEntity(0, "AAAAAA01000000000000000000000001"),
        MakeEntity(0, "AAAAAA01000000000000000000000001"),
    };
    EXPECT_EQ(0, SncPingDeinit(cleanup, 2));
    EXPECT_EQ(1, StubGetRpingDeinitCallCount());
}

TEST_F(SncPingTest, DeinitWithUnknownDevIdContinuesToNext)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingEntity cleanup[] = {
        MakeEntity(99, "UNKNOWN01000000000000000000000001"),
        MakeEntity(0, "AAAAAA01000000000000000000000001"),
    };
    EXPECT_EQ(0, SncPingDeinit(cleanup, 2));
    EXPECT_EQ(1, StubGetRpingDeinitCallCount());
}

TEST_F(SncPingTest, RpingInitFailureSkipsEidCtx)
{
    StubSetRpingInitFail(1);
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    EXPECT_EQ(0, SncPingInit(e, 1));
    EXPECT_EQ(1, StubGetRpingInitCallCount());

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(-1, SncPingOne(0, "AAAAAA01000000000000000000000001",
                              "BBBBBB01000000000000000000000001", &result));

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, RpingAddTargetFailureReturnsError)
{
    StubSetRpingAddTargetFail(1);
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(-1, SncPingOne(0, "AAAAAA01000000000000000000000001",
                              "BBBBBB01000000000000000000000001", &result));

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, RpingBatchStartFailureReturnsError)
{
    StubSetRpingBatchStartFail(1);
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(-1, SncPingOne(0, "AAAAAA01000000000000000000000001",
                              "BBBBBB01000000000000000000000001", &result));

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, RpingGetResultFailureReturnsError)
{
    StubSetRpingGetResultFail(1);
    StubSetRpingGetResultAlwaysAgain(0);
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(-1, SncPingOne(0, "AAAAAA01000000000000000000000001",
                              "BBBBBB01000000000000000000000001", &result));

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, RpingGetResultRetryThenSuccess)
{
    StubSetRpingGetResultAlwaysAgain(1);
    StubSetRpingResult(10, 10, 0);
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    EXPECT_EQ(0, SncPingOne(0, "AAAAAA01000000000000000000000001",
                             "BBBBBB01000000000000000000000001", &result));
    EXPECT_GE(StubGetRpingGetResultCallCount(), 2);

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, AclSetDeviceFailureDoesNotBlockInit)
{
    StubSetAclSetDeviceFail(1);
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    EXPECT_EQ(0, SncPingInit(e, 1));
    EXPECT_EQ(1, StubGetAclSetDeviceCallCount());
    EXPECT_EQ(1, StubGetRpingInitCallCount());

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, MultipleDevicesInitAndDeinit)
{
    SncPingEntity e[] = {
        MakeEntity(0, "AAAAAA01000000000000000000000001"),
        MakeEntity(1, "BBBBBB01000000000000000000000001"),
        MakeEntity(2, "CCCCCC01000000000000000000000001"),
    };
    ASSERT_EQ(0, SncPingInit(e, 3));
    EXPECT_EQ(3, StubGetRpingInitCallCount());

    EXPECT_EQ(0, SncPingDeinit(e, 3));
    EXPECT_EQ(3, StubGetRpingDeinitCallCount());
}

TEST_F(SncPingTest, InitAfterDeinitWorks)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));
    ASSERT_EQ(0, SncPingDeinit(e, 1));

    StubReset();
    EXPECT_EQ(0, SncPingInit(e, 1));
    EXPECT_EQ(1, StubGetRpingInitCallCount());

    EXPECT_EQ(0, SncPingDeinit(e, 1));
}

TEST_F(SncPingTest, OneWithNullClientEidHandledGracefully)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    int ret = SncPingOne(0, nullptr,
                          "BBBBBB01000000000000000000000001", &result);
    EXPECT_EQ(-1, ret);

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}

TEST_F(SncPingTest, OneWithNullServerEidHandledGracefully)
{
    SncPingEntity e[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    ASSERT_EQ(0, SncPingInit(e, 1));

    SncPingResult result;
    memset(&result, 0, sizeof(result));
    int ret = SncPingOne(0, "AAAAAA01000000000000000000000001",
                          nullptr, &result);
    EXPECT_EQ(-1, ret);

    SncPingEntity cleanup[] = { MakeEntity(0, "AAAAAA01000000000000000000000001") };
    SncPingDeinit(cleanup, 1);
}
