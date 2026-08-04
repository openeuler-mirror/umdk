/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add combine kernel implement
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04 add combine kernel implement
 */
#ifndef CAM_MOE_DISTRIBUTE_COMBINE_H
#define CAM_MOE_DISTRIBUTE_COMBINE_H
#define OPT_RANK_OFFSET 0

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "../../fused_deep_moe_base.h"
#include "../../fused_deep_moe_tiling.h"
#include "../fused_deep_moe_utils.h"

using namespace Cam;
namespace MoeDistributeCombineImpl {
constexpr uint8_t BUFFER_NUM = 2;  // multi-buf
constexpr uint32_t UB_ALIGN = 32;
constexpr uint8_t EP_DOMAIN = 0;
constexpr uint8_t TP_DOMAIN = 1;
constexpr uint16_t SEND_SYNC_EVENT_ID = 6;
constexpr uint16_t RECV_SYNC_EVENT_ID = 7;

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

using namespace AscendC;

struct CombineCalcInfo {
    uint64_t expertPerSizeOnWin_;
    uint32_t epRankId_;
    uint32_t epWorldSize_;
    uint32_t moeExpertPerRankNum_;
    uint32_t axisH_;
    uint32_t moeSendNum_;
    GM_ADDR epSendCount_;
    __gm__ Mc2Kernel::HcclOpParam *epWinContext_;
    uint64_t winDataSizeOffset_;
    uint32_t aivNum_;
    uint32_t moeExpertNum_;
    int64_t combineTokenOffset_;
    GM_ADDR gmEpTokenCount_; // Replaces epTokenCountOffset_
    GM_ADDR gmAllRankSendCount_; // Replaces allRankSendCountOffset_
    GM_ADDR metaInfoGm_;
    // (Before dispatch send) data in allExpertTokenNums is computed
    GM_ADDR allExpertTokenNums_;
    // (Before combine send) compute allEpRecvCount from allExpertTokenNums
    GM_ADDR allEpRecvCount_;
    GM_ADDR combineSend_;
};

template <TemplateMC2TypeClass>
class CamMoeDistributeCombine {
public:
    __aicore__ inline CamMoeDistributeCombine(){};
    __aicore__ inline void Init(GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount,
                                GM_ADDR tpSendCount, GM_ADDR scales, GM_ADDR xActiveMask, GM_ADDR XOut,
                                GM_ADDR workspaceGM, TPipe *pipe, GM_ADDR gmAllRankSendCount, GM_ADDR gmEpTokenCount,
                                    const FusedDeepMoeTilingData *tilingData);
    __aicore__ inline void Process();
    __aicore__ inline void AllToAllSend();
    __aicore__ inline void ReducePermute();
    __aicore__ inline void ProcessCombine();

    __aicore__ inline CombineCalcInfo &GetCalcInfo()
    {
        return calcInfo_;
    }

    __aicore__ inline void TPipeSet(AscendC::TPipe *pipe)
    {
        PipeBarrier<PIPE_ALL>();
        tpipe_ = pipe;
    }

private:
    __aicore__ inline void InitStatusTargetSum();
    __aicore__ inline void AlltoAllBuffInit();
    __aicore__ inline void LocalShmemCopy();
    __aicore__ inline void BuffInit();
    __aicore__ inline void SplitCoreCal();
    __aicore__ inline void SetStatus();
    __aicore__ inline void WaitDispatch();
    __aicore__ GM_ADDR GetWinAddrByRankId(const int32_t rankId, const uint8_t domain, const uint8_t expertLocalId = 0U)
    {
        if (domain == EP_DOMAIN) {
            return Mc2Kernel::GetBaseWindAddrByRankId(epWinContext_, rankId, epRankId_);
        } else {
            return Mc2Kernel::GetBaseWindAddrByRankId(tpWinContext_, rankId, tpRankId_);
        }
    }

    __aicore__ GM_ADDR GetWinStateAddrByRankId(const int32_t rankId, const uint8_t domain)
    {
        if (domain == EP_DOMAIN) {
            return Mc2Kernel::GetBaseWindStateAddrByRankId(epWinContext_, rankId, epRankId_);
        } else {
            return Mc2Kernel::GetBaseWindStateAddrByRankId(tpWinContext_, rankId, tpRankId_);
        }
    }

    __aicore__ inline uint32_t MIN(uint32_t x, uint32_t y)
    {
        return (x < y) ? x : y;
    }

    __aicore__ static void DoCombineRecv(void *ptr)
    {
        auto *combiner = (CamMoeDistributeCombine<TemplateMC2TypeFunc> *)ptr;
        combiner->ReducePermute();
    }

    TPipe *tpipe_{nullptr};
    GlobalTensor<ExpandXType> expandXGM_;
    GlobalTensor<ExpandIdxType> expertIdsGM_;
    GlobalTensor<ExpandIdxType> expandIdxGM_;
    GlobalTensor<ExpandIdxType> epSendCountGM_;
    GlobalTensor<ExpandIdxType> tpSendCountGM_;
    GlobalTensor<float> expandScalesGM_;
    GlobalTensor<bool> xActiveMaskGM_;
    GlobalTensor<ExpandXType> expandOutGlobal_;
    GlobalTensor<ExpandXType> rankWindow_;
    GlobalTensor<int32_t> rankStates_;
    GlobalTensor<float> epStatusSpaceGlobalTensor_;
    GlobalTensor<float> tpStatusSpaceGlobalTensor_;
    GlobalTensor<ExpandXType> tpRankWindow_;
    GlobalTensor<ExpandXType> rowTmpGlobal_;
    // Write: in BlockEpilogue before combine send
    // Read: in CamMoeDistributeCombine before reduce copy
    GlobalTensor<ExpandIdxType> allEpRecvCountGM_;
    GM_ADDR workspaceGM_;
    GM_ADDR epWindowGM_;
    GM_ADDR epStatusSpaceGm_;
    GM_ADDR tpWindowGM_;
    GM_ADDR tpStatusSpaceGm_;
    GM_ADDR stateGM_;
    // Read: local combine-send region during reduce copy; load into rowTmpGlobal_ when used
    GM_ADDR combineSendGM_;
    GM_ADDR metaInfoGm_;

    LocalTensor<ExpandXType> winTpSendCountTensor_;
    LocalTensor<ExpandXType> gmTpSendCountTensor_;
    LocalTensor<ExpandXType> outTensor_;
    LocalTensor<float> winTpSendCountFloatTensor_;
    LocalTensor<float> gmTpSendCountFloatTensor_;
    LocalTensor<ExpandIdxType> epSendCountLocal_;

    CombineCalcInfo calcInfo_;
    uint32_t axisBS_{0};
    uint32_t axisMaxBs_{0};
    uint32_t axisBsAlignSize_{0};
    uint64_t activeMaskBsCnt_{0};
    uint32_t axisH_{0};
    uint32_t axisK_{0};
    uint32_t aivNum_{0};
    uint32_t epWorldSize_{0};
    uint32_t tpWorldSize_{0};
    uint32_t epRankId_{0};
    uint32_t tpRankId_{0};
    uint32_t coreIdx_{0};  // aiv id
    uint32_t RankNum_{0};
    uint32_t moeExpertNum_{0};
    uint32_t moeExpertPerRankNum_{0};
    uint32_t moeSendNum_{0};  // moeExpertPerRankNum_ * epWorldSize_
    uint32_t tpScatterNum_{0};
    uint32_t firstTpTokenEndIdx_{0};
    uint32_t firstTpTokenEndOffset_{0};
    uint32_t endTok_{0};
    uint32_t beginIndex_{0};
    uint32_t endIndex_{0};
    __gm__ Mc2Kernel::HcclOpParam *epWinContext_{nullptr};
    __gm__ Mc2Kernel::HcclOpParam *tpWinContext_{nullptr};
    uint32_t epDataOffsetOnWin_{0};
    uint32_t tpDataOffsetOnWin_{0};
    uint32_t epStateOffsetOnWin_{0};
    uint32_t tpStateOffsetOnWin_{0};
    uint32_t axisHFloatSize_{0};
    uint32_t axisHExpandXTypeSize_{0};
    uint32_t bsKNum_{0};
    uint32_t startRankId_{0};
    uint32_t endRankId_{0};
    uint32_t sendRankNum_{0};
    uint32_t ubSize_{0};
    uint32_t dataState_{0};
    uint32_t stateOffset_{0};
    uint64_t winDataSizeOffset_{0};
    uint64_t expertPerSizeOnWin_{0};
    uint64_t totalWinSize_{0};
    // Offset of statusDataSpace in metaInfo
    uint64_t statusDataSpaceOffset_{0};
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> moeQueue_;
    TQue<QuePosition::VECIN, 1> moeSumQueue_;
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> gmTpSendCountQueue_;
    TQue<QuePosition::VECIN, 1> gmTpSendCountInQueue_;
    TQue<QuePosition::VECIN, 1> winTpSendCountInQueue_;
    TQue<QuePosition::VECOUT, 1> xOutQueue_;
    TBuf<> readStateBuf_;
    TBuf<> expertIdsBuf_;
    TBuf<> expandScalesBuf_;
    TBuf<> rowTmpFloatBuf_;
    TBuf<> sumFloatBuf_;
    TBuf<> mulBuf_;
    TBuf<> sendCountBuf_;
    TBuf<> indexCountsBuf_;
    TBuf<> winTpSendCountFloatBuf_;
    TBuf<> gmTpSendCountFloatBuf_;
    TBuf<> tokenBuf_;
    TBuf<> statusBuf_;
    TBuf<> gatherMaskOutBuf_;  // gather mask output buf
    TBuf<> gatherTmpBuf_;
    TBuf<> statusSumOutBuf_;
    TBuf<> xActMaskTBuf_;
    TBuf<> xActMaskCastTBuf_;
    TBuf<> xActMaskSumTBuf_;
    TBuf<> allEpRecvCountBuf_;
    TBuf<> cleanUpBuf_;
    float sumTarget_{0.0};
    int32_t epStateValue_;
};

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::Init(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount, GM_ADDR tpSendCount, GM_ADDR scales,
    GM_ADDR xActiveMask, GM_ADDR XOut, GM_ADDR workspaceGM, TPipe *pipe, GM_ADDR gmAllRankSendCount,
        GM_ADDR gmEpTokenCount, const FusedDeepMoeTilingData *tilingData)
{
    tpipe_ = pipe;
    coreIdx_ = GetBlockIdx();
    epRankId_ = tilingData->fusedDeepMoeInfo.epRankId;
    auto contextGM0 = AscendC::GetHcclContext<HCCL_GROUP_ID_0>();
    epWinContext_ = (__gm__ Mc2Kernel::HcclOpParam *)contextGM0;
    GlobalTensor<int32_t> selfDataStatusTensor;
    GM_ADDR statusDataSpaceGm = Mc2Kernel::GetStatusDataSpaceGm(epWinContext_);
    selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + IPCStateOffset::AI_CORE_STATE_OFFSET));
    dataState_ = FlushAndGetValue<int32_t>(selfDataStatusTensor, coreIdx_ * UB_ALIGN);
    pipe_barrier(PIPE_ALL);

    workspaceGM_ = workspaceGM;
    expandXGM_.SetGlobalBuffer((__gm__ ExpandXType *)expandX);
    expertIdsGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expertIds);
    expandIdxGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expandIdx);
    epSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)epSendCount);
    expandScalesGM_.SetGlobalBuffer((__gm__ float *)scales);
    xActiveMaskGM_.SetGlobalBuffer((__gm__ bool*)xActiveMask);
    expandOutGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)XOut);
    allEpRecvCountGM_.SetGlobalBuffer((__gm__ int32_t *)(gmEpTokenCount));
    combineSendGM_ = GetWinAddrByRankId(epRankId_, EP_DOMAIN) + tilingData->ipcDataOffset.y2TokenOffset;
    axisBS_ = tilingData->fusedDeepMoeInfo.bs;
    activeMaskBsCnt_ = axisBS_;
    axisH_ = tilingData->fusedDeepMoeInfo.h;
    axisK_ = tilingData->fusedDeepMoeInfo.k;
    if constexpr (EXEC_FLAG & (EXEC_FLAG_DEEP_FUSE | EXEC_FLAG_SHARED_EXPERT)) {
        aivNum_ = tilingData->fusedDeepMoeInfo.aicNum;
    } else {
        aivNum_ = tilingData->fusedDeepMoeInfo.aivNum;
    }
    ubSize_ = tilingData->fusedDeepMoeInfo.totalUbSize;
    moeExpertNum_ = tilingData->fusedDeepMoeInfo.moeExpertNum;
    moeExpertPerRankNum_ = tilingData->fusedDeepMoeInfo.moeExpertNumPerRank;
    epWorldSize_ = tilingData->fusedDeepMoeInfo.epRankSize;
    axisMaxBs_ = tilingData->fusedDeepMoeInfo.globalBs / epWorldSize_;
    moeSendNum_ = epWorldSize_ * moeExpertPerRankNum_;
    tpWorldSize_ = 1;
    tpRankId_ = 0;
    totalWinSize_ = tilingData->fusedDeepMoeInfo.totalWinSize;
    stateOffset_ = UB_ALIGN;
    epStatusSpaceGm_ = GetWinStateAddrByRankId(epRankId_, EP_DOMAIN);
    epStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)(GetWinStateAddrByRankId(epRankId_,
        EP_DOMAIN) + IPCStateOffset::Gmm2Combine::COMBINE_SEND_FLAG_OFFSET));
    epStateOffsetOnWin_ = epRankId_ * stateOffset_;
    axisHFloatSize_ = axisH_ * sizeof(float);
    axisHExpandXTypeSize_ = axisH_ * sizeof(ExpandXType);
    bsKNum_ = axisBS_ * axisK_;

    InitStatusTargetSum();
    if constexpr (EXEC_FLAG & (EXEC_FLAG_DEEP_FUSE | EXEC_FLAG_SHARED_EXPERT)) {
        coreIdx_ = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
    }
    SplitCoreCal();

    calcInfo_.epRankId_ = epRankId_;
    calcInfo_.epWorldSize_ = epWorldSize_;
    calcInfo_.expertPerSizeOnWin_ = expertPerSizeOnWin_;
    calcInfo_.moeExpertPerRankNum_ = moeExpertPerRankNum_;
    calcInfo_.axisH_ = axisH_;
    calcInfo_.moeSendNum_ = moeSendNum_;
    calcInfo_.epSendCount_ = epSendCount;
    calcInfo_.epWinContext_ = epWinContext_;
    calcInfo_.aivNum_ = aivNum_;
    calcInfo_.moeExpertNum_ = moeExpertNum_;
    calcInfo_.metaInfoGm_ = metaInfoGm_;
    calcInfo_.gmAllRankSendCount_ = gmAllRankSendCount;
    calcInfo_.combineTokenOffset_ = tilingData->ipcDataOffset.y2TokenOffset;
    calcInfo_.gmEpTokenCount_ = gmEpTokenCount;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::InitStatusTargetSum()
{
    // ep state
    sumTarget_ = dataState_ == 0 ? 0.0f : 1.0f; // Must start from a non-zero state on the first run
    epStateValue_ = dataState_ == 0 ? 0 : 0x3F800000;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::BuffInit()
{
    tpipe_->Reset();
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);
    uint32_t sendNumAlign = Ceil(moeSendNum_ * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(sendCountBuf_, sendNumAlign);
    tpipe_->InitBuffer(gmTpSendCountQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
    epSendCountLocal_ = sendCountBuf_.Get<int32_t>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::AlltoAllBuffInit()
{
    tpipe_->Reset();

    if (activeMaskBsCnt_ < aivNum_) {
        uint32_t aivNumPerToken = aivNum_ / activeMaskBsCnt_;
        if (coreIdx_ < (activeMaskBsCnt_ * aivNumPerToken)) {
            uint32_t tokenIndex = coreIdx_ / aivNumPerToken;
            beginIndex_ = tokenIndex;
            endIndex_ = beginIndex_ + 1U;
        }
    } else {
        uint32_t tokenPerAivNum = activeMaskBsCnt_ / aivNum_;
        uint32_t remainderToken = activeMaskBsCnt_ % aivNum_;
        beginIndex_ = tokenPerAivNum * coreIdx_;
        if (coreIdx_ < remainderToken) {
            tokenPerAivNum++;
            beginIndex_ = tokenPerAivNum * coreIdx_;
        } else {
            beginIndex_ += remainderToken;
        }
        endIndex_ = beginIndex_ + tokenPerAivNum;
    }

    uint32_t localTokenNum = endIndex_ - beginIndex_;
    uint32_t localBsKSize = localTokenNum * axisK_;
    uint32_t localBsKSizeAligned = Ceil(localBsKSize * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);
    tpipe_->InitBuffer(statusBuf_, sendRankNum_ * UB_ALIGN);
    tpipe_->InitBuffer(expertIdsBuf_, localBsKSizeAligned);
    tpipe_->InitBuffer(expandScalesBuf_, localBsKSizeAligned);
    tpipe_->InitBuffer(tokenBuf_, axisH_ * sizeof(ExpandXType));
    tpipe_->InitBuffer(rowTmpFloatBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(mulBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(sumFloatBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(indexCountsBuf_, localBsKSizeAligned);
    tpipe_->InitBuffer(moeSumQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
    tpipe_->InitBuffer(gatherMaskOutBuf_, epWorldSize_ * sizeof(float));
    tpipe_->InitBuffer(gatherTmpBuf_, sizeof(uint32_t));
    tpipe_->InitBuffer(statusSumOutBuf_, sizeof(float));
    tpipe_->InitBuffer(allEpRecvCountBuf_, epWorldSize_ * moeExpertNum_ * sizeof(uint32_t));
    tpipe_->InitBuffer(cleanUpBuf_, moeExpertNum_ * sizeof(int32_t));

    if constexpr (EXEC_FLAG & EXEC_FLAG_X_ACTIVE_MASK) {
        axisBsAlignSize_ = Ceil(axisBS_ * sizeof(bool), UB_ALIGN) * UB_ALIGN;
        tpipe_->InitBuffer(xActMaskTBuf_, axisBsAlignSize_);
        tpipe_->InitBuffer(xActMaskCastTBuf_, axisBsAlignSize_ * sizeof(half));
        tpipe_->InitBuffer(xActMaskSumTBuf_, axisBsAlignSize_ * sizeof(half));
        LocalTensor<bool> xActiveMaskTensor = xActMaskTBuf_.Get<bool>();
        LocalTensor<half> tempTensor = xActMaskCastTBuf_.Get<half>();
        LocalTensor<half> sumOutTensor = xActMaskSumTBuf_.Get<half>();
        DataCopyExtParams xActiveMaskParams{1U, static_cast<uint32_t>(axisBS_ * sizeof(bool)), 0U, 0U, 0U};
        DataCopyPadExtParams<bool> xActiveMaskCopyPadParams{false, 0U, 0U, 0U};
        DataCopyPad(xActiveMaskTensor, xActiveMaskGM_, xActiveMaskParams, xActiveMaskCopyPadParams);
        SyncFunc<AscendC::HardEvent::MTE2_V>();
        LocalTensor<int8_t> xActiveMaskInt8Tensor = xActiveMaskTensor.ReinterpretCast<int8_t>();
        Cast(tempTensor, xActiveMaskInt8Tensor, RoundMode::CAST_NONE, axisBS_);
        PipeBarrier<PIPE_V>();
        SumParams params{1, axisBsAlignSize_, axisBS_};
        Sum(sumOutTensor, tempTensor, params);
        SyncFunc<AscendC::HardEvent::V_S>();
        activeMaskBsCnt_ = static_cast<int32_t>(sumOutTensor.GetValue(0));
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::SplitCoreCal()
{
    sendRankNum_ = epWorldSize_ / aivNum_;
    uint32_t remainderRankNum = epWorldSize_ % aivNum_;
    startRankId_ = sendRankNum_ * coreIdx_;
    if (coreIdx_ < remainderRankNum) {
        sendRankNum_++;
        startRankId_ += coreIdx_;
    } else {
        startRankId_ += remainderRankNum;
    }
    endRankId_ = startRankId_ + sendRankNum_;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::SetStatus()
{
    pipe_barrier(PIPE_ALL);
    if (startRankId_ >= epWorldSize_) {
        return;
    }

    LocalTensor<int32_t> statusFlagUb = readStateBuf_.Get<int32_t>();
    statusFlagUb.SetValue(0, epStateValue_);
    SyncFunc<AscendC::HardEvent::S_MTE3>();

    for (uint32_t epIdx = startRankId_; epIdx < endRankId_; epIdx++) {
        stateGM_ = GetWinStateAddrByRankId(epIdx,
            EP_DOMAIN) + IPCStateOffset::Gmm2Combine::COMBINE_SEND_FLAG_OFFSET + epStateOffsetOnWin_;
        rankStates_.SetGlobalBuffer((__gm__ int32_t *)stateGM_);
        DataCopy(rankStates_, statusFlagUb, 8);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::WaitDispatch()
{
    if (startRankId_ < epWorldSize_) {
        LocalTensor<float> statusTensor = statusBuf_.Get<float>();
        LocalTensor<float> gatherMaskOutTensor = gatherMaskOutBuf_.Get<float>();
        LocalTensor<uint32_t> gatherTmpTensor = gatherTmpBuf_.Get<uint32_t>();
        LocalTensor<float> statusSumOutTensor = statusSumOutBuf_.Get<float>();
        PipeBarrier<PIPE_ALL>();

        gatherTmpTensor.SetValue(0, 1);
        uint32_t mask = 1;  // gatherMask + sum
        uint64_t rsvdCnt = 0;
        float sumOfFlag = static_cast<float>(-1.0);
        float minTarget = (sumTarget_ * sendRankNum_) - (float)0.5;
        float maxTarget = (sumTarget_ * sendRankNum_) + (float)0.5;
        SumParams sumParams{1, sendRankNum_, sendRankNum_};
        SyncFunc<AscendC::HardEvent::S_V>();
        while ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
            DataCopy<float>(statusTensor, epStatusSpaceGlobalTensor_[startRankId_ * stateOffset_ / sizeof(float)],
                            8 * sendRankNum_);
            SyncFunc<AscendC::HardEvent::MTE2_V>();
            GatherMask(gatherMaskOutTensor, statusTensor, gatherTmpTensor, true, mask,
                       {1, (uint16_t)sendRankNum_, 1, 0}, rsvdCnt);
            PipeBarrier<PIPE_V>();
            Sum(statusSumOutTensor, gatherMaskOutTensor, sumParams);
            SyncFunc<AscendC::HardEvent::V_S>();
            sumOfFlag = statusSumOutTensor.GetValue(0);
            if ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
                SPIN_WAIT_CYCLES();
            }
        }
    }

    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(RECV_SYNC_EVENT_ID);
    AscendC::CrossCoreWaitFlag(RECV_SYNC_EVENT_ID);
}
template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::Process()
{
    SyncAll<true>();
    AlltoAllBuffInit();
    SetStatus();
    WaitDispatch();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::LocalShmemCopy()
{
    if (activeMaskBsCnt_ == 0U) {
        return;
    }
    uint32_t processLen = 0;
    uint32_t tokenOffset = 0;
    if (activeMaskBsCnt_ < aivNum_) {
        uint32_t aivNumPerToken = aivNum_ / activeMaskBsCnt_;
        if (coreIdx_ >= (activeMaskBsCnt_ * aivNumPerToken)) {
            return;
        }
        processLen = ((axisH_ / UB_ALIGN) / aivNumPerToken) * UB_ALIGN;
        tokenOffset = processLen * (coreIdx_ % aivNumPerToken);
        if ((coreIdx_ % aivNumPerToken) == (aivNumPerToken - 1)) {
            processLen = axisH_ - ((aivNumPerToken - 1) * processLen);
        }
    } else {
        processLen = axisH_;
    }
    LocalTensor<ExpandIdxType> expertIdsLocal = expertIdsBuf_.Get<ExpandIdxType>();
    LocalTensor<float> expandScalesLocal = expandScalesBuf_.Get<float>();

    LocalTensor<float> rowTmpFloatLocal = rowTmpFloatBuf_.Get<float>();
    LocalTensor<float> mulBufLocal = mulBuf_.Get<float>();
    LocalTensor<float> sumFloatBufLocal = sumFloatBuf_.Get<float>();

    LocalTensor<ExpandIdxType> indexCountsLocal = indexCountsBuf_.Get<ExpandIdxType>();
    LocalTensor<ExpandIdxType> allEpRecvCountLocal = allEpRecvCountBuf_.Get<ExpandIdxType>();

    uint32_t localTokenNum = endIndex_ - beginIndex_;
    uint32_t localBsKSize = localTokenNum * axisK_;
    const DataCopyExtParams localBskParams = {1U, static_cast<uint32_t>(localBsKSize * sizeof(uint32_t)), 0U, 0U, 0U};
    const DataCopyPadExtParams<ExpandIdxType> copyPadParams{false, 0U, 0U, 0U};
    const DataCopyPadExtParams<float> copyPadFloatParams{false, 0U, 0U, 0U};
    uint32_t allEpRecvCountSize = epWorldSize_ * moeExpertNum_;
    const DataCopyExtParams allEpRecvCountParams = {1U, static_cast<uint32_t>(allEpRecvCountSize * sizeof(uint32_t)),
        0U, 0U, 0U};

    DataCopyPad(indexCountsLocal, expandIdxGM_[beginIndex_ * axisK_], localBskParams, copyPadParams);
    DataCopyPad(expertIdsLocal, expertIdsGM_[beginIndex_ * axisK_], localBskParams, copyPadParams);
    DataCopyPad(expandScalesLocal, expandScalesGM_[beginIndex_ * axisK_], localBskParams, copyPadFloatParams);
    DataCopyPad(allEpRecvCountLocal, allEpRecvCountGM_, allEpRecvCountParams, copyPadParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();

    for (uint32_t tokenIndex = beginIndex_; tokenIndex < endIndex_; tokenIndex++) {
        uint32_t index = (tokenIndex - beginIndex_) * axisK_;
        SyncFunc<AscendC::HardEvent::MTE3_V>();
        Duplicate(sumFloatBufLocal, (float)0, axisH_);
        for (uint32_t i = 0; i < axisK_; i++) {
            int32_t moeExpert = expertIdsLocal.GetValue(index);
            if (moeExpert < 0) {
                index++;
                continue;
            }
            float scaleVal = expandScalesLocal.GetValue(index);
            // Expert offset
            uint32_t expertOffset =
                moeExpert == 0 ? 0 : allEpRecvCountLocal.GetValue(epRankId_ * moeExpertNum_ + moeExpert - 1);
            GM_ADDR shmemAddr = (__gm__ uint8_t *)(combineSendGM_) +
                            expertOffset * axisHExpandXTypeSize_ +
                            indexCountsLocal.GetValue(index) * axisHExpandXTypeSize_ +
                            tokenOffset * sizeof(ExpandXType);
            rowTmpGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)shmemAddr);
            ExpandXType val = rowTmpGlobal_.GetValue(0);
            LocalTensor<ExpandXType> tmpUb = moeSumQueue_.AllocTensor<ExpandXType>();
            DataCopy(tmpUb, rowTmpGlobal_, processLen);
            moeSumQueue_.EnQue(tmpUb);
            tmpUb = moeSumQueue_.DeQue<ExpandXType>();
            Cast(rowTmpFloatLocal, tmpUb, AscendC::RoundMode::CAST_NONE, processLen);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Muls(mulBufLocal, rowTmpFloatLocal, scaleVal, processLen);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Add(sumFloatBufLocal, sumFloatBufLocal, mulBufLocal, processLen);
            index++;
            moeSumQueue_.FreeTensor<ExpandXType>(tmpUb);
        }
        LocalTensor<ExpandXType> rowTmpLocal = tokenBuf_.Get<ExpandXType>();

        AscendC::PipeBarrier<PIPE_V>();
        LocalTensor<ExpandXType> sumBufLocal = tokenBuf_.Get<ExpandXType>();
        Cast(sumBufLocal, sumFloatBufLocal, AscendC::RoundMode::CAST_RINT, processLen);
        SyncFunc<AscendC::HardEvent::V_MTE3>();
        DataCopy(expandOutGlobal_[tokenIndex * axisH_ + tokenOffset], sumBufLocal, processLen);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::AllToAllSend()
{
    BuffInit();
    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
        AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
    } else {
        SyncAll<true>();
    }
    SetStatus();
    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        AscendC::CrossCoreWaitFlag(RECV_SYNC_EVENT_ID);
    } else {
        SyncAll<true>();
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ReducePermute()
{
    AlltoAllBuffInit();
    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
    } else {
        SyncAll<true>();
    }

    WaitDispatch();
    LocalShmemCopy();

    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ProcessCombine()
{
    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
    AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
    AlltoAllBuffInit();
    SetStatus();
    WaitDispatch();
    LocalShmemCopy();
}
}  // namespace MoeDistributeCombineImpl

#endif  // CAM_MOE_DISTRIBUTE_COMBINE_IMPL_H
