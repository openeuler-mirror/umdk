/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: combine normal A2 kernel part operator implementation
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create combine normal A2 kernel part operator implementation
 */

#ifndef MOE_DISTRIBUTE_COMBINE_A2_LAYERED_H
#define MOE_DISTRIBUTE_COMBINE_A2_LAYERED_H
#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "moe_distribute_combine_a2_tiling.h"
#include "moe_distribute_base.h"

namespace MoeDistributeCombineA2Impl {

#define COMBINE_2SERVER_VERSION

#define TemplateMC2TypeA2layeredClass typename ExpandXType, typename ExpandIdxType
#define TemplateMC2TypeA2layeredFunc ExpandXType, ExpandIdxType
using namespace AscendC;
template <TemplateMC2TypeA2layeredClass>
class MoeDistributeCombineA2Layered {
public:
    constexpr static uint32_t BUFFER_NUM = 2U;                   // multiple buf
    constexpr static uint32_t STATE_OFFSET = 512U;               // state offset address
    constexpr static uint32_t STATE_SPACE_SIZE = 1024U * 1024U;  // 1M
    constexpr static uint32_t UB_ALIGN = 32U;                    // UB align 32
    constexpr static uint32_t SELF_STATE_OFFSET = 512U * 1024U;  // local rank state offset
    constexpr static uint32_t BATCH_WRITE_ITEM_OFFSET =
        8U * 1024U;  // batchWriteInfo struct offset from the last 1M windowOut
    constexpr static uint32_t BATCH_WRITE_ITEM_SIZE = 32U;
    constexpr static uint32_t BLOCK_SIZE = 32U;
    constexpr static uint32_t B32_PER_BLOCK = 8U;
    constexpr static uint32_t B64_PER_BLOCK = 4U;
    constexpr static uint32_t SERVER_RANK_SIZE = 8U;
    constexpr static uint32_t IPC_DATA_OFFSET = 4U * 1024U * 1024U;
    constexpr static uint32_t IPC_DISPATCH_DATA_OFFSET = 2U * 1024U * 1024U;
    constexpr static uint32_t NOTIFY_DATA_SIZE = 400U * 1024U * 1024U;
    constexpr static uint32_t RDMA_DATA_SIZE = 300U * 1024U * 1024U;
    constexpr static uint32_t EXTRA_TOKEN_INFO_NUM = 4U;  // expert, weight, quantScale and arrival sign
    constexpr static uint64_t MB_SIZE = 1024UL * 1024UL;
    constexpr static uint32_t MAX_BS = 4096;  // max batchsize for each rank

    template <AscendC::HardEvent event>
    __aicore__ inline void SyncFunc()
    {
        int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
        AscendC::SetFlag<event>(eventID);
        AscendC::WaitFlag<event>(eventID);
    }
    template <typename T>
    inline __aicore__ T RoundUp(const T val, const T align)
    {
        static_assert(std::is_arithmetic<T>::value, "T must be an arithmetic type");
        if (align == 0 || val + align - 1 < val) {
            return val;
        }
        return (val + align - 1) / align * align;
    }

    __aicore__ inline MoeDistributeCombineA2Layered(){};
    __aicore__ inline void Init(GM_ADDR expandX, GM_ADDR expandIdx, GM_ADDR sendCount, GM_ADDR offsetInner,
                                GM_ADDR offsetOuter, GM_ADDR countOuter, GM_ADDR scales, GM_ADDR XOut,
                                GM_ADDR workspaceGM, TPipe *pipe, const MoeDistributeCombineA2TilingData *tilingData,
                                __gm__ void *mc2InitTiling, __gm__ void *mc2CcTiling);
    __aicore__ inline void Process();

private:
    __aicore__ inline void BuffInit();
    __aicore__ inline void SplitCoreCal();
    __aicore__ inline void AlltoAllDispatch();
    __aicore__ inline void SumToWindow();
    __aicore__ inline void SetStatus();
    __aicore__ inline void WaitDispatch();
    __aicore__ inline void AlltoAllServerDispatch();
    __aicore__ inline void SumToServer();
    __aicore__ inline void Preload();

    TPipe *tpipe_{nullptr};
    GlobalTensor<ExpandXType> expandXGlobal_;
    GlobalTensor<ExpandIdxType> expandIdxGlobal_;
    GlobalTensor<ExpandIdxType> sendCountGlobal_;
    GlobalTensor<ExpandIdxType> bkCountGlobal_;
    GlobalTensor<float> expandScalesGlobal_;
    GlobalTensor<ExpandXType> expandOutGlobal_;
    GlobalTensor<ExpandXType> rankWindow_;  // peer window parameters
    GlobalTensor<ExpandXType> localOutWindow_;
    GlobalTensor<ExpandXType> localInWindow_;
    GlobalTensor<uint32_t> bufferIdGlobal_;     // peer sttus window parameter
    GlobalTensor<int32_t> statusSpaceGlobal_;   // win status copy in parameter
    GlobalTensor<uint64_t> workspaceGlobal_;    // batchWriteInfo struct
    GlobalTensor<uint32_t> workspaceGlobal32_;  // batchWriteInfo struct
    GlobalTensor<int32_t> readStateGlobal_;
    GlobalTensor<int32_t> dstRankStateGlobal_;
    LocalTensor<uint64_t> batchWriteItemLocalB64;
    LocalTensor<uint32_t> batchWriteItemLocalB32;
    LocalTensor<uint32_t> recvCountLocal_;
    LocalTensor<uint32_t> expertWindowOffsetLocal_;
    LocalTensor<float> rowTmpFloatLocal_;
    LocalTensor<float> mulBufLocal_;
    LocalTensor<float> sumFloatLocal_;
    LocalTensor<ExpandIdxType> expertIdsLocal_;
    LocalTensor<float> expandScalesLocal_;
    LocalTensor<ExpandIdxType> indexCountsLocal_;
    LocalTensor<ExpandXType> tmpUb_;
    uint64_t shareAddreRank[8];
    GlobalTensor<ExpandXType> selfRankshareMemGlobal_;

    GM_ADDR windowInGM_;
    GM_ADDR windowOutGM_;
    GM_ADDR statusSpaceGm_;
    GM_ADDR expandXGM_;
    GM_ADDR expertIdsGM_;
    GM_ADDR expandIdxGM_;
    GM_ADDR sendCountGM_;
    GM_ADDR scalesGM_;
    GM_ADDR XOutGM_;

    // layered related parameters
    GM_ADDR shareAddrGM_;
    GM_ADDR offsetInnerGM_;
    GM_ADDR countInnerGM_;
    GM_ADDR offsetOuterGM_;
    GM_ADDR countOuterGM_;
    GM_ADDR recvCountInnerGM_;
    GlobalTensor<int32_t> shareAddrGlobal_;
    GlobalTensor<int64_t> shareFlagGlobal_;
    GlobalTensor<ExpandXType> shareMemGlobal_;
    GlobalTensor<ExpandXType> dstshareMemGlobal_;
    GlobalTensor<int32_t> offsetInnerGlobal_;
    GlobalTensor<int32_t> offsetOuterGlobal_;
    GlobalTensor<int32_t> countOuterGlobal_;
    GlobalTensor<int32_t> recvCountInnerGlobal_;
    TBuf<> offsetReduceBuf_;
    TBuf<> countReduceBuf_;
    // tiling part ensures the upper bound，safe to multicate, so use uint32_t
    uint32_t countReL{0};
    uint32_t axisBS_{0};
    uint32_t globalBs{0};
    uint32_t axisH_{0};
    uint32_t axisK_{0};  // topK
    uint32_t aivNum_{0};
    uint32_t worldSize_{0};
    uint32_t rankId_{0};
    uint32_t coreIdx_{0};              // aiv id
    uint32_t sharedExpertRankNum_{0};  // shared rank num
    __gm__ HcclOpResParam *winContext_{nullptr};
    uint32_t moeExpertNum_{0};       // moe expert num = worldSize_ - shared rank num
    uint32_t localMoeExpertNum_{0};
    uint32_t expandXRows_;
    uint64_t rankSizeOnWin_{0};
    Hccl<HCCL_SERVER_TYPE_AICPU> hccl_;
    uint64_t dataOffsetOnWin_{0};
    uint64_t stateOffsetOnWin_{0};
    uint32_t axisHFloatSize_{0};
    uint32_t axisHExpandXTypeSize_{0};
    uint32_t startRankId_{0};
    uint32_t endRankId_{0};
    uint32_t sendRankNum_{0};
    uint32_t halfWinSize_{0};
    uint32_t dataSpaceSize_{0};
    uint32_t bufferId_{0};
    uint32_t tokenNumPerCore_{0};
    uint32_t tokenIndex_{0};
    uint32_t serverNum{0};
    uint32_t ipcSliceSize{0};
    uint32_t ipcSliceNodeSize{0};
    uint64_t send_counts_inner_offset{0};
    uint64_t offset_inner_offset{0};
    uint64_t send_counts_outer_offset{0};
    uint64_t offset_outer_offset{0};
    uint64_t share_offset{0};
    uint32_t IPC_DATA_SIZE{0};
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, BUFFER_NUM> moeQueue_;
    TQue<QuePosition::VECIN, BUFFER_NUM> moeSumQueue_;
    TBuf<> rowTmpFloatBuf_;
    TBuf<> sumFloatBuf_;
    TBuf<> mulBuf_;
    TBuf<> sendCountBuf_;
    TBuf<> statusBuf_;
    TBuf<> statusSumOutBuf_;
    TBuf<> batchWriteItemBuf_;
    TBuf<> recvCountBuf_;
    TBuf<> scaleBuf_;
    TBuf<> expertWindowOffsetBuf_;
    TBuf<> innerOffsetBuf_;
    int32_t sumTarget_{0};
    int32_t stateValue_{0};
    uint32_t startBs{0};
    uint32_t endBs{0};
    uint32_t processNum{0};
    uint32_t resNum{0};
    uint32_t resLen{0};
    uint32_t offsetIndex{0};
    uint32_t maxLocalBs{0};
    LocalTensor<int32_t> offsetReduceLocal_;
    LocalTensor<int32_t> countReduceLocal_;
};

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::Init(
    GM_ADDR expandX, GM_ADDR expandIdx, GM_ADDR sendCount, GM_ADDR offsetInner, GM_ADDR offsetOuter, GM_ADDR countOuter,
    GM_ADDR scales, GM_ADDR XOut, GM_ADDR workspaceGM, TPipe *pipe, const MoeDistributeCombineA2TilingData *tilingData,
    __gm__ void *mc2InitTiling, __gm__ void *mc2CcTiling)
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::BuffInit()
{
    tpipe_->InitBuffer(moeQueue_, BUFFER_NUM, (axisHExpandXTypeSize_ + 32U));  // 7168 * 2 * 2 = 28672
    tpipe_->InitBuffer(statusBuf_, worldSize_ * UB_ALIGN);
    tpipe_->InitBuffer(rowTmpFloatBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(mulBuf_, axisHFloatSize_);       //  // 7168 * 4 = 28672
    tpipe_->InitBuffer(sumFloatBuf_, axisHFloatSize_);  //  // 7168 * 4 = 28672
    // global sendCount, everyexpert receive token num from each rank
    tpipe_->InitBuffer(sendCountBuf_, RoundUp(moeExpertNum_ * worldSize_, B32_PER_BLOCK) *
                                          sizeof(int32_t));
    tpipe_->InitBuffer(moeSumQueue_, BUFFER_NUM, (axisHExpandXTypeSize_ + 32U));
    tpipe_->InitBuffer(statusSumOutBuf_, sizeof(float));
    tpipe_->InitBuffer(batchWriteItemBuf_, BATCH_WRITE_ITEM_SIZE * worldSize_);
    tpipe_->InitBuffer(innerOffsetBuf_, localMoeExpertNum_ * SERVER_RANK_SIZE * sizeof(int32_t));
    batchWriteItemLocalB64 = batchWriteItemBuf_.Get<uint64_t>();
    batchWriteItemLocalB32 = batchWriteItemLocalB64.template ReinterpretCast<uint32_t>();
}
template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::SplitCoreCal()
{
    // split worldSize
    sendRankNum_ = worldSize_ / aivNum_;
    uint32_t remainderRankNum = worldSize_ % aivNum_;
    startRankId_ = sendRankNum_ * coreIdx_;
    if (coreIdx_ < remainderRankNum) {
        sendRankNum_++;
        startRankId_ += coreIdx_;
    } else {
        startRankId_ += remainderRankNum;
    }
    endRankId_ = startRankId_ + sendRankNum_;
}
template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::AlltoAllDispatch()
{
    rowTmpFloatLocal_ = rowTmpFloatBuf_.Get<float>();
    ipcSliceSize = IPC_DATA_SIZE / worldSize_;
    ipcSliceNodeSize = ipcSliceSize * SERVER_RANK_SIZE;
    LocalTensor<ExpandIdxType> sendCountLocal = sendCountBuf_.Get<int32_t>();
    DataCopy(sendCountLocal, sendCountGlobal_, RoundUp(moeExpertNum_ * worldSize_, B32_PER_BLOCK));
    SyncFunc<AscendC::HardEvent::MTE2_S>();
    for (uint32_t dstRankId = startRankId_; dstRankId < endRankId_; ++dstRankId) {
        // the same local rank id rank on local server with the dstRankId
        uint32_t targetRank = dstRankId % SERVER_RANK_SIZE;
        // calculate the target IPC address without flag offset
        uint64_t targetRankShareAddr = shareAddreRank[targetRank];
        uint64_t targetRankAddr =
            targetRankShareAddr +
            static_cast<uint64_t>(dstRankId / SERVER_RANK_SIZE * ipcSliceNodeSize + IPC_DATA_OFFSET);

        dstshareMemGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)(targetRankAddr));
        shareFlagGlobal_.SetGlobalBuffer((__gm__ int64_t *)(targetRankShareAddr + IPC_DISPATCH_DATA_OFFSET));
        // calculate the token send count
        uint32_t rankTokenNum = 0U;
        uint32_t serverStartExpId = rankId_ / SERVER_RANK_SIZE * SERVER_RANK_SIZE * localMoeExpertNum_;
        for (uint32_t expertId = 0U; expertId < localMoeExpertNum_; ++expertId) {
            uint32_t preCount = 0U;
            if (expertId != 0U || dstRankId != 0U) {
                for (int i = 0; i <= expertId; i++) {
                    for (int j = 0; j < worldSize_; j++) {
                        if ((i == expertId) && j >= dstRankId) {
                            break;
                        }
                        // sum up the [startExpId, expertId - 1] rows in epSendCount,
                        // and sum up expertId row first disRankId - 1 items.
                        preCount += sendCountLocal.GetValue((i + rankId_ * localMoeExpertNum_) * worldSize_ + j);
                    }
                }
            }

            uint32_t tokenNum =
                sendCountLocal.GetValue((expertId + rankId_ * localMoeExpertNum_) * worldSize_ + dstRankId);
            uint32_t startTokenAddr = preCount * axisH_;
            SyncFunc<AscendC::HardEvent::MTE2_S>();
            uint32_t tokenOffset = 0;
            // from self server expert start expertId to current expertId
            for (int i = serverStartExpId; i < rankId_ * localMoeExpertNum_ + expertId; i++) {
                tokenOffset += sendCountLocal.GetValue(i * worldSize_ + dstRankId);
            }
            for (uint32_t tokenId = 0U; tokenId < tokenNum; ++tokenId) {
                float scaleVal = expandScalesGlobal_[preCount].GetValue(tokenId);
                LocalTensor<ExpandXType> InUb = moeQueue_.AllocTensor<ExpandXType>();
                LocalTensor<float> InUbTemp = InUb[axisH_].template ReinterpretCast<float>();
                InUbTemp(0) = scaleVal;
                SyncFunc<AscendC::HardEvent::S_MTE2>();
                DataCopy(InUb, expandXGlobal_[startTokenAddr], axisH_);
                moeQueue_.EnQue(InUb);
                LocalTensor<ExpandXType> OutUb = moeQueue_.DeQue<ExpandXType>();
                DataCopy(dstshareMemGlobal_[(tokenOffset + tokenId) * (axisH_ + 16U)], OutUb, axisH_ + 16U);
                moeQueue_.FreeTensor<ExpandXType>(OutUb);
                startTokenAddr += axisH_;
                rankTokenNum++;
                PipeBarrier<PIPE_ALL>();
            }
        }
        PipeBarrier<PIPE_ALL>();
        LocalTensor<int64_t> InUb = statusBuf_.AllocTensor<int64_t>();
        InUb.SetValue(0, 12345);
        uint32_t flagOffset = rankId_ % SERVER_RANK_SIZE + dstRankId / SERVER_RANK_SIZE * SERVER_RANK_SIZE;
        DataCopy(shareFlagGlobal_[flagOffset * 4], InUb, 4);  // reason for 4: Single copy 256 bytes = 4 × int64.
        statusBuf_.FreeTensor<int64_t>(InUb);
    }
    SyncAll<true>();
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::SumToWindow()
{
    // Assumpt only one core handles one rank. only serverNum ranks with the same local rank id
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::AlltoAllServerDispatch()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::SetStatus()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::WaitDispatch()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::Preload()
{
    return;
}
template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::SumToServer()
{
    return;
}

template <TemplateMC2TypeA2layeredClass>
__aicore__ inline void MoeDistributeCombineA2Layered<TemplateMC2TypeA2layeredFunc>::Process()
{
    return;
}

}  // namespace MoeDistributeCombineA2Impl
#endif  // MOE_DISTRIBUTE_COMBINE_A2_LAYERED_H
