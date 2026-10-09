/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Stub control API for snc_ping unit tests
 */
#ifndef STUB_CONTROL_H_
#define STUB_CONTROL_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void StubReset(void);

void StubSetAclSetDeviceFail(bool fail);
void StubSetRpingInitFail(bool fail);
void StubSetRpingAddTargetFail(bool fail);
void StubSetRpingBatchStartFail(bool fail);
void StubSetRpingGetResultFail(bool fail);
void StubSetRpingGetResultAlwaysAgain(bool again);

void StubSetRpingResult(uint32_t txPkt, uint32_t rxPkt, uint32_t state);

int StubGetRpingInitCallCount(void);
int StubGetRpingDeinitCallCount(void);
int StubGetRpingAddTargetCallCount(void);
int StubGetRpingRemoveTargetCallCount(void);
int StubGetRpingBatchStartCallCount(void);
int StubGetRpingBatchStopCallCount(void);
int StubGetRpingGetResultCallCount(void);
int StubGetAclSetDeviceCallCount(void);

#ifdef __cplusplus
}
#endif

#endif
