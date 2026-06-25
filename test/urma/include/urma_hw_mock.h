/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Shared URMA hardware/provider mock return data for unit tests.
 */

#ifndef TEST_URMA_INCLUDE_URMA_HW_MOCK_H
#define TEST_URMA_INCLUDE_URMA_HW_MOCK_H

#include "urma_provider.h"

namespace urma_test {

struct HwMockState {
    urma_status_t status;
    urma_status_t jfsModifyStatus;
    urma_status_t jfrQueryStatus;
    int intReturn;
    int userCtlReturn;
    bool ioctlSucceed;
    uint32_t ioctlId;
    uint64_t ioctlHandle;
    int ioctlCount;
    void *badObject;
    void *badSendWr;
    void *badRecvWr;
    urma_async_event_t asyncEvent;
    int ackAsyncCount;
    int importSegCount;
    int importJettyCount;
    int importJfrCount;
    int postJfsCount;
    int postJfrCount;
    int bindJettyCount;
    int unbindJettyCount;
    int bindJettyFailAt;
};

inline HwMockState &GetHwMockState()
{
    static HwMockState state = {};

    return state;
}

inline void ResetHwMockState()
{
    HwMockState &state = GetHwMockState();

    state = {};
    state.status = URMA_SUCCESS;
    state.jfsModifyStatus = URMA_ENOPERM;
    state.jfrQueryStatus = URMA_EAGAIN;
    state.intReturn = 1;
    state.userCtlReturn = URMA_ENOPERM;
    state.ioctlId = 0x9000;
    state.ioctlHandle = 0x90000000ULL;
    state.bindJettyFailAt = -1;
}

inline void SetHwMockStatus(urma_status_t status)
{
    GetHwMockState().status = status;
}

inline void SetHwMockIntReturn(int value)
{
    GetHwMockState().intReturn = value;
}

inline void SetHwMockBadObject(void *badObject)
{
    GetHwMockState().badObject = badObject;
}

inline void SetHwMockBadWr(void *badSendWr, void *badRecvWr)
{
    HwMockState &state = GetHwMockState();

    state.badSendWr = badSendWr;
    state.badRecvWr = badRecvWr;
}

inline void SetHwMockIoctl(bool succeed, uint32_t id = 0x9000, uint64_t handle = 0x90000000ULL)
{
    HwMockState &state = GetHwMockState();

    state.ioctlSucceed = succeed;
    state.ioctlId = id;
    state.ioctlHandle = handle;
}

inline void SetHwMockBindJettyFailAt(int failAt)
{
    GetHwMockState().bindJettyFailAt = failAt;
}

} // namespace urma_test

#endif // TEST_URMA_INCLUDE_URMA_HW_MOCK_H
