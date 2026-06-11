/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: moe lowlatency zero-buffer base header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create moe lowlatency zero-buffer base header file
 */
#ifndef MOE_LOWLATENCY_ZERO_BUFFER_BASE_H
#define MOE_LOWLATENCY_ZERO_BUFFER_BASE_H

namespace MoeLowlatencyZeroBufferBase {
constexpr uint64_t OP_CNT_POSUL = 3UL;
constexpr uint32_t ZERONE_STATE_POS = 0U;
constexpr uint32_t OPOSITION_POS = 1U;
constexpr uint32_t TILING_EPRANKID_POS = 2U;
constexpr uint32_t MOE_NUM_POS = 3U;
constexpr uint32_t TILING_WORLDSIZE_POS = 4U;
constexpr uint32_t GLOBALBS_POS = 5U;
constexpr uint32_t UB_ALIGN = 32U;

enum Op : int { COPYONLY = -1, ADD = 0, MUL = 1, MAX = 2, MIN = 3 };

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

using namespace AscendC;

__aicore__ inline uint32_t ZeroBufferInitWinState(GlobalTensor<uint32_t> selfDataStatusGMTensor,
    uint32_t epRankIdOriginal, uint32_t moeExpertNum, uint32_t epWorldSizeOriginal, uint32_t globalBS,
    TBuf<> dataStateBuf)
{
    LocalTensor<uint64_t> dataStateLocalTensor64 = dataStateBuf.Get<uint64_t>();
    LocalTensor<uint32_t> dataStateLocalTensor = dataStateBuf.Get<uint32_t>();
    DataCopy(dataStateLocalTensor, selfDataStatusGMTensor, UB_ALIGN / sizeof(uint32_t));
    SyncFunc<AscendC::HardEvent::MTE2_S>();
    // uint32_t epRankIdHccl = winContext->localUsrRankId;
    // uint32_t epWorldSizeHccl = winContext->rankSize;
    uint32_t dataState = dataStateLocalTensor.GetValue(ZERONE_STATE_POS);
    dataStateLocalTensor.SetValue(ZERONE_STATE_POS, dataState == 0 ? 1 : 0);
    dataStateLocalTensor.SetValue(OPOSITION_POS, 1);
    dataStateLocalTensor.SetValue(TILING_EPRANKID_POS, epRankIdOriginal);
    dataStateLocalTensor.SetValue(MOE_NUM_POS, moeExpertNum);
    dataStateLocalTensor.SetValue(TILING_WORLDSIZE_POS, epWorldSizeOriginal);
    dataStateLocalTensor.SetValue(GLOBALBS_POS, globalBS);
    uint32_t opCnt = dataStateLocalTensor64.GetValue(OP_CNT_POSUL);
    opCnt = opCnt + 1;
    dataStateLocalTensor64.SetValue(OP_CNT_POSUL, opCnt);
    SyncFunc<AscendC::HardEvent::S_MTE3>();
    DataCopy(selfDataStatusGMTensor, dataStateLocalTensor, UB_ALIGN / sizeof(uint32_t));
    return dataState;
}

}  // namespace MoeLowlatencyZeroBufferBase
#endif  // MOE_LOWLATENCY_ZERO_BUFFER_BASE_H
