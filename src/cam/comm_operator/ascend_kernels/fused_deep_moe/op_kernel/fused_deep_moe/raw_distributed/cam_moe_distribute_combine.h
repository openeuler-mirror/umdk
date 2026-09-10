/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add combine kernel implement
 * Create: 2025-07-21
 * Note:
 * History: 2025-07-21 add combine kernel implement
 */
#ifndef CAM_MOE_DISTRIBUTE_COMBINE_H
#define CAM_MOE_DISTRIBUTE_COMBINE_H
#define OPT_RANK_OFFSET 512

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "../../fused_deep_moe_base.h"
#include "../../fused_deep_moe_tiling.h"
#include "shmem.h"

using namespace Cam;
namespace MoeDistributeCombineImpl {
constexpr uint8_t BUFFER_NUM = 2;  // multi-buf
constexpr uint32_t STATE_OFFSET = 512;
constexpr uint32_t STATE_SIZE = 1024 * 1024;  // 1M
constexpr uint32_t RANK_SIZE_ON_WIN_512 = 512 * 1024;
constexpr uint32_t RANK_SIZE_ON_WIN_256 = 256 * 1024;
constexpr uint32_t TP_RANK_SIZE_ON_WIN = 0;
constexpr uint32_t UB_ALIGN = 32;
constexpr uint32_t SELF_STATE_OFFSET = 256 * 1024;
constexpr uint8_t EP_DOMAIN = 0;
constexpr uint8_t TP_DOMAIN = 1;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint16_t SEND_SYNC_EVENT_ID = 6;
constexpr uint16_t RECV_SYNC_EVENT_ID = 7;
constexpr uint32_t A3_AIV_NUM = 48;
constexpr uint32_t SHMEM_COMBINE_TOKEN_CHUNK = 512;

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

using namespace AscendC;

struct CombineCalcInfo {
    uint32_t epRankId_;
    uint32_t epWorldSize_;
    uint32_t moeExpertPerRankNum_;
    uint32_t axisH_;
    uint32_t moeSendNum_;
    GM_ADDR epSendCount_;
    uint32_t aivNum_;
    uint32_t moeExpertNum_;
    GM_ADDR metaInfoGm_;
    // (dispatch send前)allExpertTokenNums中的数据计算好
    GM_ADDR allExpertTokenNums_;
    // (combine send前)根据allExpertTokenNums计算allEpRecvCount
    GM_ADDR allEpRecvCount_;
    GM_ADDR combineSend_;
};

template <TemplateMC2TypeClass>
class CamMoeDistributeCombine {
public:
    __aicore__ inline CamMoeDistributeCombine(){};
    __aicore__ inline void Init(GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount,
                                GM_ADDR tpSendCount, GM_ADDR scales, GM_ADDR xActiveMask, GM_ADDR XOut,
                                GM_ADDR workspaceGM, TPipe *pipe, const FusedDeepMoeTilingData *tilingData,
                                GM_ADDR allExpertTokenNums, GM_ADDR allEpRecvCount, GM_ADDR combineSend,
                                uint64_t statusDataSpaceOffset);
    __aicore__ inline void AllToAllSend();
    __aicore__ inline void ReducePermute();
    __aicore__ inline void ProcessCombine();

    __aicore__ inline CombineCalcInfo &GetCalcInfo()
    {
        return calcInfo_;
    }

    __aicore__ inline void TPipeSet(AscendC::TPipe *pipe)
    {
        tpipe_ = pipe;
    }

private:
    __aicore__ inline void InitStatusTargetSum();
    __aicore__ inline void AlltoAllBuffInit();
    __aicore__ inline void ReduceScatterTrans();
    __aicore__ inline void LocalShmemCopy();
    __aicore__ inline void BuffInit();
    __aicore__ inline void SplitCoreCal();
    __aicore__ inline void SetStatus();
    __aicore__ inline void WaitDispatch();
    __aicore__ GM_ADDR GetWinAddrByRankId(const int32_t rankId, const uint8_t domain, const uint8_t expertLocalId = 0U)
    {
        if (domain == EP_DOMAIN) {
            return (GM_ADDR)((epRankId_ == rankId)
                                 ? epWinContext_->localWindowsIn
                                 : ((HcclRankRelationResV2 *)(epWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsIn) +
                   winDataSizeOffset_ + expertLocalId * expertPerSizeOnWin_ + rankId * OPT_RANK_OFFSET;
        } else {
            return (GM_ADDR)((tpRankId_ == rankId)
                                 ? tpWinContext_->localWindowsIn
                                 : ((HcclRankRelationResV2 *)(tpWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsIn) +
                   winDataSizeOffset_ + rankId * OPT_RANK_OFFSET;
        }
    }

    __aicore__ GM_ADDR GetWinStateAddrByRankId(const int32_t rankId, const uint8_t domain)
    {
        if (domain == EP_DOMAIN) {
            return (GM_ADDR)((epRankId_ == rankId)
                                 ? epWinContext_->localWindowsExp
                                 : ((HcclRankRelationResV2 *)(epWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsExp) +
                   dataState_ * WIN_STATE_OFFSET;
        } else {
            return (GM_ADDR)((tpRankId_ == rankId)
                                 ? tpWinContext_->localWindowsExp
                                 : ((HcclRankRelationResV2 *)(tpWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsExp) +
                   dataState_ * WIN_STATE_OFFSET;
        }
    }

    __aicore__ GM_ADDR GetShmemAddrByRankId(GM_ADDR baseAddr, int64_t rankId)
    {
        if (epRankId_ == rankId) {
            return baseAddr;
        }
        return (GM_ADDR)aclshmem_ptr(baseAddr, rankId);
    }

    __aicore__ GM_ADDR GetShmemStateAddrByRankId(int64_t rankId)
    {
        return GetShmemAddrByRankId(metaInfoGm_ + statusDataSpaceOffset_ + dataState_ * WIN_STATE_OFFSET, rankId);
    }

    __aicore__ inline GM_ADDR GetShmemLocalNotifyDataAddr(int64_t rankId)
    {
        uint64_t offset = A3_AIV_NUM * UB_ALIGN + epWorldSize_ * UB_ALIGN;
        return GetShmemAddrByRankId(metaInfoGm_ + offset, rankId);
    }

    CATLASS_DEVICE
    void ShmemCleanUp()
    {
        if (coreIdx_ != 0) {
            return;
        }

        AscendC::LocalTensor<int32_t> cleanTempLt = cleanUpBuf_.Get<int32_t>();
        AscendC::Duplicate(cleanTempLt, (int32_t)0, moeExpertNum_);
        AscendC::PipeBarrier<PIPE_ALL>();

        AscendC::GlobalTensor<int32_t> localNotifyDataTensor;
        GM_ADDR localNotifyDataAddr = GetShmemLocalNotifyDataAddr(epRankId_);
        localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)localNotifyDataAddr);
        AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum_ * sizeof(int32_t)),
            0U, 0U, 0U};
        AscendC::DataCopyPad(localNotifyDataTensor, cleanTempLt, dataCopyParams);
        AscendC::PipeBarrier<PIPE_ALL>();
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
    // 写：combine send前的BlockEpilogue中
    // 读：reduce copy前的CamMoeDistributeCombine中
    GlobalTensor<ExpandIdxType> allEpRecvCountGM_;
    GM_ADDR workspaceGM_;
    GM_ADDR epStatusSpaceGm_;
    GM_ADDR tpWindowGM_;
    GM_ADDR tpStatusSpaceGm_;
    GM_ADDR stateGM_;
    // 读：reduce copy时的本地的combinesend区域，使用时装载至rowTmpGlobal_数据容器中
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
    __gm__ HcclOpResParam *epWinContext_{nullptr};
    __gm__ HcclOpResParam *tpWinContext_{nullptr};
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
    // statusDataSpace在metaInfo中的偏移
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
    GM_ADDR xActiveMask, GM_ADDR XOut, GM_ADDR workspaceGM, TPipe *pipe, const FusedDeepMoeTilingData *tilingData,
    GM_ADDR allExpertTokenNums, GM_ADDR allEpRecvCount, GM_ADDR combineSend, uint64_t statusDataSpaceOffset)
{
    tpipe_ = pipe;
    coreIdx_ = GetBlockIdx();
    epRankId_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    GlobalTensor<int32_t> selfDataStatusTensor;
    GM_ADDR statusDataSpaceGm;
    metaInfoGm_ = (GM_ADDR)(tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.metaInfoPtr);
    statusDataSpaceGm = metaInfoGm_ + statusDataSpaceOffset;
    selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
    __asm__ __volatile__("");
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfDataStatusTensor[coreIdx_ * UB_ALIGN]);
    __asm__ __volatile__("");
    dataState_ = selfDataStatusTensor(coreIdx_ * UB_ALIGN);
    if (dataState_ == 0) {
        selfDataStatusTensor(coreIdx_ * UB_ALIGN) = 1;
    } else {
        selfDataStatusTensor(coreIdx_ * UB_ALIGN) = 0;
    }
    __asm__ __volatile__("");
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfDataStatusTensor[coreIdx_ * UB_ALIGN]);
    __asm__ __volatile__("");
    pipe_barrier(PIPE_ALL);

    workspaceGM_ = workspaceGM;
    expandXGM_.SetGlobalBuffer((__gm__ ExpandXType *)expandX);
    expertIdsGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expertIds);
    expandIdxGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expandIdx);
    epSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)epSendCount);
    expandScalesGM_.SetGlobalBuffer((__gm__ float *)scales);
    xActiveMaskGM_.SetGlobalBuffer((__gm__ bool*)xActiveMask);
    expandOutGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)XOut);
    allEpRecvCountGM_.SetGlobalBuffer((__gm__ int32_t *)allEpRecvCount);
    combineSendGM_ = combineSend;
    axisBS_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.bs;
    activeMaskBsCnt_ = axisBS_;
    axisH_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.h;
    axisK_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.k;
    aivNum_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.aicNum;
    ubSize_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.totalUbSize;
    moeExpertNum_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNum;
    moeExpertPerRankNum_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    epWorldSize_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.epRankSize;
    axisMaxBs_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.globalBs / epWorldSize_;
    moeSendNum_ = epWorldSize_ * moeExpertPerRankNum_;
    tpWorldSize_ = 1;
    tpRankId_ = 0;
    stateOffset_ = (moeSendNum_ > 512) ? (STATE_OFFSET / 2) : STATE_OFFSET;
    expertPerSizeOnWin_ =
        static_cast<uint64_t>(axisMaxBs_) * static_cast<uint64_t>(axisH_) * static_cast<uint64_t>(sizeof(ExpandXType));
    winDataSizeOffset_ = static_cast<uint64_t>(dataState_) * static_cast<uint64_t>(moeSendNum_) * expertPerSizeOnWin_;
    statusDataSpaceOffset_ = statusDataSpaceOffset;
    epStatusSpaceGm_ = GetShmemStateAddrByRankId(epRankId_);
    epStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)epStatusSpaceGm_);
    epStateOffsetOnWin_ = epRankId_ * stateOffset_;
    axisHFloatSize_ = axisH_ * sizeof(float);
    axisHExpandXTypeSize_ = axisH_ * sizeof(ExpandXType);
    bsKNum_ = axisBS_ * axisK_;

    if constexpr (IsNeedReduceScatter) {
        tpSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)tpSendCount);
        tpWindowGM_ = GetWinAddrByRankId(tpRankId_, TP_DOMAIN);
        tpStatusSpaceGm_ = GetWinStateAddrByRankId(tpRankId_, TP_DOMAIN);
        tpStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)tpStatusSpaceGm_);
        tpDataOffsetOnWin_ = tpRankId_ * TP_RANK_SIZE_ON_WIN;
        tpStateOffsetOnWin_ = tpRankId_ * stateOffset_;
        uint32_t tpScatterRankWinOffset = (tpRankId_ == 0) ? TP_RANK_SIZE_ON_WIN : 0;
        GM_ADDR rankGM = tpWindowGM_ + tpScatterRankWinOffset;
        tpRankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    }

    InitStatusTargetSum();
    coreIdx_ = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
    SplitCoreCal();

    calcInfo_.epRankId_ = epRankId_;
    calcInfo_.epWorldSize_ = epWorldSize_;
    calcInfo_.moeExpertPerRankNum_ = moeExpertPerRankNum_;
    calcInfo_.axisH_ = axisH_;
    calcInfo_.moeSendNum_ = moeSendNum_;
    calcInfo_.epSendCount_ = epSendCount;
    calcInfo_.aivNum_ = aivNum_;
    calcInfo_.moeExpertNum_ = moeExpertNum_;
    calcInfo_.metaInfoGm_ = metaInfoGm_;
    calcInfo_.allExpertTokenNums_ = allExpertTokenNums;
    calcInfo_.allEpRecvCount_ = allEpRecvCount;
    calcInfo_.combineSend_ = combineSend;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::InitStatusTargetSum()
{
    // ep state
    GlobalTensor<int32_t> selfStatusTensor;
    selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(epStatusSpaceGm_ + SELF_STATE_OFFSET));
    __asm__ __volatile__("");
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfStatusTensor[coreIdx_ * UB_ALIGN]);
    __asm__ __volatile__("");
    int32_t state = selfStatusTensor(coreIdx_ * UB_ALIGN);
    if (state == 0) {
        sumTarget_ = static_cast<float>(1.0);
        selfStatusTensor(coreIdx_ * UB_ALIGN) = 0x3F800000;  // 1.0f
        epStateValue_ = 0x3F800000;                          // 1.0f
    } else {
        sumTarget_ = static_cast<float>(0.0);
        selfStatusTensor(coreIdx_ * UB_ALIGN) = 0;
        epStateValue_ = 0;
    }
    __asm__ __volatile__("");
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfStatusTensor[coreIdx_ * UB_ALIGN]);
    __asm__ __volatile__("");
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::BuffInit()
{
    tpipe_->Reset();
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);
    uint32_t sendNumAlign = Ceil(moeSendNum_ * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(sendCountBuf_, sendNumAlign);
    if constexpr (IsNeedReduceScatter) {
        tpipe_->InitBuffer(winTpSendCountInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        tpipe_->InitBuffer(gmTpSendCountInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        tpipe_->InitBuffer(xOutQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        if constexpr (AscendC::IsSameType<ExpandXType, bfloat16_t>::value) {
            tpipe_->InitBuffer(winTpSendCountFloatBuf_, axisHFloatSize_);
            tpipe_->InitBuffer(gmTpSendCountFloatBuf_, axisHFloatSize_);
            winTpSendCountFloatTensor_ = winTpSendCountFloatBuf_.Get<float>();
            gmTpSendCountFloatTensor_ = gmTpSendCountFloatBuf_.Get<float>();
        }
    } else {
        tpipe_->InitBuffer(gmTpSendCountQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
    }
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
    uint32_t bufferTokenNum = MIN(localTokenNum, SHMEM_COMBINE_TOKEN_CHUNK);
    uint32_t localBsKSize = bufferTokenNum * axisK_;
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
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ReduceScatterTrans()
{
    __asm__ __volatile__("");
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
                                tpSendCountGM_[tpRankId_]);
    __asm__ __volatile__("");
    uint32_t offset = tpSendCountGM_.GetValue(tpRankId_) * axisH_;
    GlobalTensor<ExpandXType> dataCopyInGM = expandXGM_[offset];
    GM_ADDR rankGM = GetWinAddrByRankId(1 - tpRankId_, TP_DOMAIN) + tpDataOffsetOnWin_;
    rankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    uint32_t copyStartIdx = 0;
    if (startRankId_ > 0) {
        __asm__ __volatile__("");
        DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            epSendCountGM_[epWorldSize_ + startRankId_ - 1]);
        __asm__ __volatile__("");
        copyStartIdx = epSendCountGM_.GetValue(epWorldSize_ + startRankId_ - 1);
    }
    __asm__ __volatile__("");
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        epSendCountGM_[epWorldSize_ + endRankId_ - 1]);
    __asm__ __volatile__("");
    uint32_t copyEndIdx = epSendCountGM_.GetValue(epWorldSize_ + endRankId_ - 1);
    LocalTensor<ExpandXType> tmpUb;
    for (uint32_t tokenNumIdx = copyStartIdx; tokenNumIdx < copyEndIdx; tokenNumIdx++) {
        tmpUb = moeQueue_.AllocTensor<ExpandXType>();
        DataCopy(tmpUb, dataCopyInGM[tokenNumIdx * axisH_], axisH_);
        moeQueue_.EnQue(tmpUb);
        tmpUb = moeQueue_.DeQue<ExpandXType>();
        DataCopy(rankWindow_[tokenNumIdx * axisH_], tmpUb, axisH_);
        moeQueue_.FreeTensor<ExpandXType>(tmpUb);
    }
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
        stateGM_ = GetShmemStateAddrByRankId(epIdx) + epStateOffsetOnWin_;
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
        DataCopyParams intriParams{static_cast<uint16_t>(sendRankNum_), 1,
                                   static_cast<uint16_t>((moeSendNum_ > 512) ? 7 : 15), 0};  // srcStride is 15 blocks
        float sumOfFlag = static_cast<float>(-1.0);
        float minTarget = (sumTarget_ * sendRankNum_) - (float)0.5;
        float maxTarget = (sumTarget_ * sendRankNum_) + (float)0.5;
        SumParams sumParams{1, sendRankNum_, sendRankNum_};
        SyncFunc<AscendC::HardEvent::S_V>();
        while ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
            DataCopy<float>(statusTensor, epStatusSpaceGlobalTensor_[startRankId_ * stateOffset_ / sizeof(float)],
                            intriParams);
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

    const DataCopyPadExtParams<ExpandIdxType> copyPadParams{false, 0U, 0U, 0U};
    const DataCopyPadExtParams<float> copyPadFloatParams{false, 0U, 0U, 0U};
    uint32_t allEpRecvCountSize = epWorldSize_ * moeExpertNum_;
    const DataCopyExtParams allEpRecvCountParams = {1U, static_cast<uint32_t>(allEpRecvCountSize * sizeof(uint32_t)),
        0U, 0U, 0U};

    DataCopyPad(allEpRecvCountLocal, allEpRecvCountGM_, allEpRecvCountParams, copyPadParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();

    for (uint32_t chunkBegin = beginIndex_; chunkBegin < endIndex_; chunkBegin += SHMEM_COMBINE_TOKEN_CHUNK) {
        uint32_t chunkEnd = MIN(chunkBegin + SHMEM_COMBINE_TOKEN_CHUNK, endIndex_);
        uint32_t chunkTokenNum = chunkEnd - chunkBegin;
        uint32_t chunkBsKSize = chunkTokenNum * axisK_;
        const DataCopyExtParams chunkBskParams = {
            1U, static_cast<uint32_t>(chunkBsKSize * sizeof(uint32_t)), 0U, 0U, 0U};
        DataCopyPad(indexCountsLocal, expandIdxGM_[chunkBegin * axisK_], chunkBskParams, copyPadParams);
        DataCopyPad(expertIdsLocal, expertIdsGM_[chunkBegin * axisK_], chunkBskParams, copyPadParams);
        DataCopyPad(expandScalesLocal, expandScalesGM_[chunkBegin * axisK_], chunkBskParams, copyPadFloatParams);
        SyncFunc<AscendC::HardEvent::MTE2_S>();

        for (uint32_t tokenIndex = chunkBegin; tokenIndex < chunkEnd; tokenIndex++) {
            uint32_t index = (tokenIndex - chunkBegin) * axisK_;
            SyncFunc<AscendC::HardEvent::MTE3_V>();
            Duplicate(sumFloatBufLocal, (float)0, axisH_);
            for (uint32_t i = 0; i < axisK_; i++) {
                int32_t moeExpert = expertIdsLocal.GetValue(index);
                if (moeExpert < 0) {
                    index++;
                    continue;
                }
                float scaleVal = expandScalesLocal.GetValue(index);
                uint32_t expertOffset =
                    moeExpert == 0 ? 0 : allEpRecvCountLocal.GetValue(epRankId_ * moeExpertNum_ + moeExpert - 1);
                GM_ADDR shmemAddr = (__gm__ uint8_t *)(combineSendGM_) +
                                expertOffset * axisHExpandXTypeSize_ +
                                indexCountsLocal.GetValue(index) * axisHExpandXTypeSize_ +
                                tokenOffset * sizeof(ExpandXType);
                rowTmpGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)shmemAddr);
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

            AscendC::PipeBarrier<PIPE_V>();
            LocalTensor<ExpandXType> sumBufLocal = tokenBuf_.Get<ExpandXType>();
            Cast(sumBufLocal, sumFloatBufLocal, AscendC::RoundMode::CAST_RINT, processLen);
            SyncFunc<AscendC::HardEvent::V_MTE3>();
            DataCopy(expandOutGlobal_[tokenIndex * axisH_ + tokenOffset], sumBufLocal, processLen);
        }
        AscendC::PipeBarrier<PIPE_ALL>();
    }
}


template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::AllToAllSend()
{
    if constexpr (IsNeedReduceScatter) {
        tpipe_->InitBuffer(moeQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        ReduceScatterTrans();
    }
    BuffInit();
    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
    AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
    SetStatus();
    AscendC::CrossCoreWaitFlag(RECV_SYNC_EVENT_ID);
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ReducePermute()
{
    AlltoAllBuffInit();
    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);

    WaitDispatch();
    LocalShmemCopy();

    AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);

    ShmemCleanUp();
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

    ShmemCleanUp();
}
}  // namespace MoeDistributeCombineImpl

#endif  // CAM_MOE_DISTRIBUTE_COMBINE_IMPL_H
