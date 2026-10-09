/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Stub implementation for ACL and HCCN rping APIs
 *              used in snc_ping unit tests
 */
#include <cstring>
#include "acl/acl.h"
#include "hccl/hccn_rping.h"
#include "stub_control.h"

static bool g_aclSetDeviceFail = false;
static bool g_rpingInitFail = false;
static bool g_rpingAddTargetFail = false;
static bool g_rpingBatchStartFail = false;
static bool g_rpingGetResultFail = false;
static bool g_rpingGetResultAgain = true;
static int g_rpingInitCallCount = 0;
static int g_rpingDeinitCallCount = 0;
static int g_rpingAddTargetCallCount = 0;
static int g_rpingRemoveTargetCallCount = 0;
static int g_rpingBatchStartCallCount = 0;
static int g_rpingBatchStopCallCount = 0;
static int g_rpingGetResultCallCount = 0;
static int g_aclSetDeviceCallCount = 0;
static HccnRpingResultInfo g_lastResult;

void StubReset()
{
    g_aclSetDeviceFail = false;
    g_rpingInitFail = false;
    g_rpingAddTargetFail = false;
    g_rpingBatchStartFail = false;
    g_rpingGetResultFail = false;
    g_rpingGetResultAgain = true;
    g_rpingInitCallCount = 0;
    g_rpingDeinitCallCount = 0;
    g_rpingAddTargetCallCount = 0;
    g_rpingRemoveTargetCallCount = 0;
    g_rpingBatchStartCallCount = 0;
    g_rpingBatchStopCallCount = 0;
    g_rpingGetResultCallCount = 0;
    g_aclSetDeviceCallCount = 0;
    memset(&g_lastResult, 0, sizeof(g_lastResult));
}

void StubSetAclSetDeviceFail(bool fail) { g_aclSetDeviceFail = fail; }
void StubSetRpingInitFail(bool fail) { g_rpingInitFail = fail; }
void StubSetRpingAddTargetFail(bool fail) { g_rpingAddTargetFail = fail; }
void StubSetRpingBatchStartFail(bool fail) { g_rpingBatchStartFail = fail; }
void StubSetRpingGetResultFail(bool fail) { g_rpingGetResultFail = fail; }
void StubSetRpingGetResultAlwaysAgain(bool again) { g_rpingGetResultAgain = again; }

void StubSetRpingResult(uint32_t txPkt, uint32_t rxPkt, uint32_t state)
{
    g_lastResult.txPkt = txPkt;
    g_lastResult.rxPkt = rxPkt;
    g_lastResult.state = state;
    g_lastResult.minRTT = 100;
    g_lastResult.maxRTT = 200;
    g_lastResult.avgRTT = 150;
}

int StubGetRpingInitCallCount() { return g_rpingInitCallCount; }
int StubGetRpingDeinitCallCount() { return g_rpingDeinitCallCount; }
int StubGetRpingAddTargetCallCount() { return g_rpingAddTargetCallCount; }
int StubGetRpingRemoveTargetCallCount() { return g_rpingRemoveTargetCallCount; }
int StubGetRpingBatchStartCallCount() { return g_rpingBatchStartCallCount; }
int StubGetRpingBatchStopCallCount() { return g_rpingBatchStopCallCount; }
int StubGetRpingGetResultCallCount() { return g_rpingGetResultCallCount; }
int StubGetAclSetDeviceCallCount() { return g_aclSetDeviceCallCount; }

aclError aclrtSetDevice(int32_t deviceId)
{
    (void)deviceId;
    g_aclSetDeviceCallCount++;
    return g_aclSetDeviceFail ? -1 : ACL_SUCCESS;
}

HccnResult HccnRpingInit(uint32_t devId, const HccnRpingInitAttr* attr, HccnRpingCtx* ctx)
{
    (void)devId;
    (void)attr;
    g_rpingInitCallCount++;
    if (g_rpingInitFail) {
        return -1;
    }
    *ctx = (HccnRpingCtx)(uintptr_t)(0x1000 + g_rpingInitCallCount);
    return HCCN_SUCCESS;
}

HccnResult HccnRpingDeinit(HccnRpingCtx ctx)
{
    (void)ctx;
    g_rpingDeinitCallCount++;
    return HCCN_SUCCESS;
}

HccnResult HccnRpingAddTarget(HccnRpingCtx ctx, uint32_t count, const HccnRpingTargetInfo* targets)
{
    (void)ctx;
    (void)count;
    (void)targets;
    g_rpingAddTargetCallCount++;
    return g_rpingAddTargetFail ? -1 : HCCN_SUCCESS;
}

HccnResult HccnRpingRemoveTarget(HccnRpingCtx ctx, uint32_t count, const HccnRpingTargetInfo* targets)
{
    (void)ctx;
    (void)count;
    (void)targets;
    g_rpingRemoveTargetCallCount++;
    return HCCN_SUCCESS;
}

HccnResult HccnRpingBatchPingStart(HccnRpingCtx ctx, uint32_t pktNum, uint32_t interval, uint32_t timeout)
{
    (void)ctx;
    (void)pktNum;
    (void)interval;
    (void)timeout;
    g_rpingBatchStartCallCount++;
    return g_rpingBatchStartFail ? -1 : HCCN_SUCCESS;
}

HccnResult HccnRpingBatchPingStop(HccnRpingCtx ctx)
{
    (void)ctx;
    g_rpingBatchStopCallCount++;
    return HCCN_SUCCESS;
}

HccnResult HccnRpingGetResult(HccnRpingCtx ctx, uint32_t count, const HccnRpingTargetInfo* targets, HccnRpingResultInfo* results)
{
    (void)ctx;
    (void)count;
    (void)targets;
    g_rpingGetResultCallCount++;
    if (g_rpingGetResultFail) {
        return -1;
    }
    if (g_rpingGetResultAgain && g_rpingGetResultCallCount < 2) {
        return HCCN_E_AGAIN;
    }
    *results = g_lastResult;
    return HCCN_SUCCESS;
}
