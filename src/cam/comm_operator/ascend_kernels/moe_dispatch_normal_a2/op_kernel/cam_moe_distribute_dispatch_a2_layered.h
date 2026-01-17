/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch normal A2 kernel part operator implement
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create dispatch normal A2 kernel part operator implement
 */

#ifndef CAM_MOE_DISTRIBUTE_DISPATCH_A2_LAYERED_H
#define CAM_MOE_DISTRIBUTE_DISPATCH_A2_LAYERED_H

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "cam_moe_distribute_dispatch_tiling.h"
#include "moe_distribute_base.h"
#include "comm_args.h"

namespace MoeDistributeDispatchA2Impl {
constexpr uint32_t STATE_OFFSET = 512;
constexpr uint32_t STATUS_SIZE_LAYERED = 1024 * 1024;  // 1M
constexpr uint32_t RDMA_BUFFER_ALIGN = 4 * 1024;
constexpr uint32_t SELF_STATE_OFFSET = 512 * 1024;  // local rank status offset
constexpr uint32_t SERVER_RANK_SIZE = 8;
constexpr uint32_t INFO_NUM_IN_TOKENSTRUCK = 4;  // three infos after token: expIds, weights, tokenIdx, scales
constexpr uint32_t B64_PER_BLOCK = 4;
constexpr uint32_t PER_MSG_RDMA_SEND_TIME = 2;
constexpr uint32_t B32_PER_BLOCK = 8;
constexpr uint32_t UB_32B_ALIGN = 32;
constexpr uint32_t EXP_TOKEN_COUNT_FLAG_CNT = UB_32B_ALIGN / sizeof(int32_t);  // 8
constexpr uint32_t DISPATCH_TOKEN_UB_SIZE = 176 * 1024;
constexpr uint32_t IPC_MAGIC_OFFSET = 2 * 1024 * 1024 - 64 * 32;
constexpr uint32_t IPC_TOKEN_CNT_OFFSET = 2 * 1024 * 1024;
constexpr uint32_t IPC_DATA_OFFSET = 4 * 1024 * 1024;
constexpr uint32_t NOTIFY_OFFSET = 0 * 1024 * 1024;
constexpr uint32_t IPC_BUFF_ALIGN = 512;
constexpr uint32_t TOKEN_COUNT_SIZE = 32;
constexpr uint32_t FLAG_U32_CNT = TOKEN_COUNT_SIZE / 4;
constexpr int32_t IPC_FLAG_STEP_1 = 1ULL;
constexpr int32_t IPC_FLAG_STEP_2 = 2ULL;
constexpr uint32_t TBUF_TEMP_OFFSET = 8 * 1024;
constexpr uint32_t TBUF_OFFSET_ALIGN_B32_CNT = 2 * 1024 / sizeof(int32_t);
constexpr uint32_t RDMA_DATA_SIZE = 100U * 1024U * 1024U;
constexpr uint32_t EXTRA_TOKEN_INFO_NUM = 4U;  // expert, weight, quantscale, arrival flag
constexpr uint32_t BITS32_PER_BLOCK = 8U;
constexpr static uint32_t BW_ITEM_SIZE = 32;
constexpr uint32_t FLAG_VALUE = 0xFFFFFFFF;
constexpr uint32_t BS_UPPER = 4096;

#define TemplateMC2TypeA2layeredClass \
    typename XType, typename ExpandXOutType, bool StaticQuant, bool DynamicQuant, bool IsSmoothScaleExist
#define TemplateMC2TypeA2layeredFunc XType, ExpandXOutType, StaticQuant, DynamicQuant, IsSmoothScaleExist

using namespace AscendC;
using namespace Cam;
template <TemplateMC2TypeA2layeredClass>
class CamMoeDistributeDispatchA2Layered {
    template <typename T>
    inline __aicore__ T RoundUp(const T val, const T align)
    {
        static_assert(std::is_arithmetic<T>::value, "T must be an arithmetic type");
        if (align == 0 || val + align - 1 < val) {
            return val;
        }
        return (val + align - 1) / align * align;
    }

public:
    __aicore__ inline CamMoeDistributeDispatchA2Layered(){};
    __aicore__ inline void Init(GM_ADDR x, GM_ADDR expertIds, GM_ADDR scales, GM_ADDR expertScales,
                                GM_ADDR tokenServerIdx, GM_ADDR tokenServerCnt, GM_ADDR epRankTokenCnt,
                                GM_ADDR srcOffsetRankTokenIdx, GM_ADDR dstOffsetRankTokenIdx, GM_ADDR expandXOut,
                                GM_ADDR dynamicScalesOut, GM_ADDR expandIdxOut, GM_ADDR expertTokenNumsOut,
                                GM_ADDR epRecvCountsOut, GM_ADDR expandScales, GM_ADDR workspaceGM, TPipe *pipe,
                                GM_ADDR tilingGM);
    __aicore__ inline void Process();
    template <AscendC::HardEvent event>
    __aicore__ inline void SyncFunc()
    {
        int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
        AscendC::SetFlag<event>(eventID);
        AscendC::WaitFlag<event>(eventID);
    }

private:
    __aicore__ inline void Input2Win();
    __aicore__ inline uint32_t GetExpRank(uint32_t expertId);
    __aicore__ inline bool IsInSameServer(uint32_t targetRankId);
    __aicore__ inline void SetTokenCnt(GlobalTensor<int32_t> globalSet);
    __aicore__ inline void CopyTokenToWinOut(uint32_t localTokenIdx, uint32_t tokenIdx, uint32_t dstServerId);
    __aicore__ inline void WaitWindow();

    __aicore__ inline void Ipc2Out();
    __aicore__ inline void DispatchBetweenServer();
    __aicore__ inline void ConstructDataAndFlagBatchWriteInfo();
    __aicore__ inline void WaitIpcFlag(uint64_t flagVal = 1ULL);
    __aicore__ inline void SetIpcFlag(uint64_t flagVal = 1ULL);
    __aicore__ inline void WriteRdmaCntInfo();
    __aicore__ inline void CleanUp();
    __aicore__ inline void QuantProcess(uint32_t sendTokenNum, LocalTensor<XType> xTokenLt,
                                        LocalTensor<float> tokenCastLt);
    __aicore__ inline uint64_t MergeMagicWithValue(uint64_t magic, uint64_t value);

    TPipe *tpipe_{nullptr};
    GlobalTensor<int32_t> expertIdsGMTensor_;
    GlobalTensor<ExpandXOutType> expandXOutGMTensor_;
    GlobalTensor<float> dynamicScalesOutGMTensor_;
    GlobalTensor<float> weightsOutGt;
    GlobalTensor<uint64_t> dataBatchWriteInfoTensor_;
    GlobalTensor<int32_t> sendStatusTensor_;
    GlobalTensor<uint8_t> readTokensU8Tensor_;
    GlobalTensor<uint8_t> sendTokensU8Tensor_;
    GlobalTensor<uint32_t> sendTokensU32Tensor_;
    GlobalTensor<uint32_t> bufferChosenGlobal_;
    GlobalTensor<uint32_t> expertToServerGlobalTensor_;
    GlobalTensor<int32_t> readStatusTensor_;
    GlobalTensor<int32_t> tokenServerIdxGMTensor_;
    GlobalTensor<int32_t> tokenServerCntGMTensor_;

    GlobalTensor<int32_t> epRankTokenCntGMTensor_;
    GlobalTensor<int32_t> srcOffsetRankTokenIdxGMTensor_;
    GlobalTensor<int32_t> dstOffsetRankTokenIdxGMTensor_;

    LocalTensor<int32_t> expertCountTensor_;
    LocalTensor<uint64_t> batchWriteU64Tensor_;
    LocalTensor<uint32_t> batchWriteU32Tensor_;
    LocalTensor<uint32_t> expertToServerCntTensor_;
    LocalTensor<uint32_t> expertToServerIdxTensor_;

    LocalTensor<int32_t> tokenServerIdxTensor_;
    LocalTensor<int32_t> serverCountTensor_;

    TBuf<> tokenServerIdxBuf_;
    TBuf<> serverCountBuf_;

    TBuf<> expertCountBuf_;
    TBuf<> statusBuf_;
    TBuf<> batchWriteInfoBuf_;
    TBuf<> expertToServerCntsBuf_;  // total table, type int but only 1 and 0
    TBuf<> expertToServerIdxBuf_;
    TBuf<QuePosition::VECCALC> tBuf;
    TBuf<> weightBuf_;

    GM_ADDR expandXGM_;
    GM_ADDR expandIdxGM_;
    GM_ADDR weightsGM_;
    GM_ADDR expertTokenNumsOutGM_;
    GM_ADDR epRecvCountsGM_;
    GM_ADDR statusSpaceGm_;
    GM_ADDR windowInGM_;
    GM_ADDR windowOutGM_;
    GM_ADDR dataBatchWriteInfo_;
    GM_ADDR expertToServerCntGM_;
    GM_ADDR shareAddrs[8];
    GM_ADDR shareAddrWins[8];

    // tiling asserted upper bound, safe for muplication. use uint32_t
    uint32_t axisBS_{0};
    uint32_t globalBs_{0};
    uint32_t axisH_{0};
    uint32_t axisK_{0};
    uint32_t kAlign_{0};
    uint32_t aivNum_{0};
    uint32_t expertIdsCnt_{0};
    uint32_t worldSize_{0};
    uint32_t rankId_{0};
    uint32_t aivId_{0};         // aiv id
    uint32_t moeExpertNum_{0};  //  equals worldSize_ - shared expert rank num
    uint32_t moeExpertNumInServer_{0};
    uint32_t localMoeExpertNum_{0};
    uint32_t SERVER_SIZE_ON_WIN{0};
    uint32_t RANK_SIZE_ON_IPC{0};
    uint32_t WIN_SIZE{0};
    uint32_t bufferId_{0};
    uint32_t totalSize_{0};
    uint32_t totalWinSize_{0};
    uint32_t halfWinSize_{0};
    uint32_t serverNum{0};
    uint32_t expertTokenNumsType_{0};
    uint32_t shareMemOffset_{0};
    // TokenStruck related
    uint32_t tokenGapInStruct_{0};
    uint32_t infoGapInStruct_{0};
    uint32_t tokenStructLen_{0};
    uint32_t tokenLenInStruct_{0};
    uint32_t expLenInStruct_{0};
    uint32_t weightLenInStruct_{0};
    uint32_t realLenInStruct_{0};
    uint32_t cntLenInStruct_{0};
    uint32_t expOffsetInStruct_{0};
    uint32_t weightOffsetInStruct_{0};
    uint32_t cntOffsetInStruct_{0};
    uint32_t scaleOffsetInStruct_{0};
    uint64_t magicVal_{0};

    uint32_t combineInnerCntOffset;
    uint32_t combineInnerCntIndexOffset;
    uint32_t combineOuterCntOffset;
    uint32_t combineOuterCntIndexOffset;

    Hccl<HCCL_SERVER_TYPE_AICPU> hccl_;
    __gm__ HcclOpResParam *winContext_{nullptr};
};

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::Init(
    GM_ADDR x, GM_ADDR expertIds, GM_ADDR scales, GM_ADDR expertScales, GM_ADDR tokenServerIdx, GM_ADDR tokenServerCnt,
    GM_ADDR epRankTokenCnt, GM_ADDR srcOffsetRankTokenIdx, GM_ADDR dstOffsetRankTokenIdx, GM_ADDR expandXOut,
    GM_ADDR dynamicScalesOut, GM_ADDR expandIdxOut, GM_ADDR expertTokenNumsOut, GM_ADDR epRecvCountsOut,
    GM_ADDR expandScales, GM_ADDR workspaceGM, TPipe *pipe, GM_ADDR tilingGM)
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::Input2Win()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::QuantProcess(
    uint32_t sendTokenNum, LocalTensor<XType> xTokenLt, LocalTensor<float> tokenCastLt)
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::WriteRdmaCntInfo()
{
    return;
}

// build data info sending to other servers
template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void
CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::ConstructDataAndFlagBatchWriteInfo()
{
    return;
}

// RDMA communication between servers
template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::DispatchBetweenServer()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline uint32_t
CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::GetExpRank(uint32_t expertId)
{
    return expertId / localMoeExpertNum_;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline bool
CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::IsInSameServer(uint32_t targetRankId)
{
    return targetRankId / SERVER_RANK_SIZE == rankId_ / SERVER_RANK_SIZE;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline uint64_t
CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::MergeMagicWithValue(uint64_t magic, uint64_t value)
{
    return (magic * 2ULL + value);
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::SetIpcFlag(uint64_t flagVal)
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::WaitIpcFlag(uint64_t flagVal)
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void
CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::SetTokenCnt(GlobalTensor<int32_t> globalSet)
{
    AscendC::SetAtomicAdd<int32_t>();
    LocalTensor<int32_t> localSet = tBuf.GetWithOffset<int32_t>(EXP_TOKEN_COUNT_FLAG_CNT, 0);
    localSet(0) = 1;  // AtomicAdd++ on each calling
    SyncFunc<AscendC::HardEvent::S_MTE3>();
    DataCopy(globalSet, localSet, EXP_TOKEN_COUNT_FLAG_CNT);
    SyncFunc<AscendC::HardEvent::MTE3_S>();
    AscendC::SetAtomicNone();
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::WaitWindow()
{
    // first ServerNum rank wait，keep the one waiting the local rank
    if (aivId_ >= serverNum || aivId_ == (rankId_ / SERVER_RANK_SIZE)) {
        return;  // skip waiting the local server
    }
    uint32_t waitFlagIdx = aivId_;
    PipeBarrier<PIPE_ALL>();
    LocalTensor<int32_t> statusTensor = statusBuf_.Get<int32_t>();
    while (true) {
        DataCopy(statusTensor, readStatusTensor_[(waitFlagIdx)*STATE_OFFSET / sizeof(int32_t)], FLAG_U32_CNT);
        SyncFunc<AscendC::HardEvent::MTE2_S>();
        int32_t sumOfFlag = statusTensor.GetValue(0);
        if (sumOfFlag == FLAG_VALUE) {
            break;
        }
    }
}

// each expert gather data from different servers
template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::Ipc2Out()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::CleanUp()  // clean status
{
    uint32_t cleanBuffSize = worldSize_ * localMoeExpertNum_ * TOKEN_COUNT_SIZE;
    if (cleanBuffSize < STATE_OFFSET * serverNum) {
        cleanBuffSize = STATE_OFFSET * serverNum;
    }
    LocalTensor<int32_t> cleanTempLt_ = tBuf.GetWithOffset<int32_t>(cleanBuffSize / sizeof(int32_t), TBUF_TEMP_OFFSET);
    GlobalTensor<int32_t> flagIpcGt;
    Duplicate<int32_t>(cleanTempLt_, 0, cleanBuffSize / sizeof(int32_t));
    PipeBarrier<PIPE_ALL>();
    flagIpcGt.SetGlobalBuffer((__gm__ int32_t *)(shareAddrs[rankId_ % SERVER_RANK_SIZE]));
    PipeBarrier<PIPE_ALL>();
    DataCopy(readStatusTensor_, cleanTempLt_, cleanBuffSize / sizeof(int32_t));
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void CamMoeDistributeDispatchA2Layered<TemplateMC2TypeA2layeredFunc>::Process()
{
    return;
}
}  // namespace MoeDistributeDispatchA2Impl
#endif  // MOE_DISTRIBUTE_DISPATCH_A2_LAYERED_H
