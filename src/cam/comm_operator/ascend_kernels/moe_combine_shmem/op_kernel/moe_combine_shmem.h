/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shmem combine function device header file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create shmem combine header file in device part
 */

#ifndef MOE_COMBINE_SHMEM_H
#define MOE_COMBINE_SHMEM_H
#define OPT_RANK_OFFSET 512

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "moe_combine_shmem_tiling.h"
#include "shmem.h"

using namespace AscendC;
using namespace Moe;
#define SHMEM_PUT_BY_DTYPE(dtype, ...)                            \
    do {                                                          \
        if constexpr (std::is_same_v<dtype, half>) {              \
            aclshmem_half_put_nbi(__VA_ARGS__);                  \
        } else if constexpr (std::is_same_v<dtype, bfloat16_t>) { \
            aclshmem_bfloat16_put_nbi(__VA_ARGS__);              \
        }                                                         \
    } while (0)

#define SHMEM_GET_BY_DTYPE(dtype, ...)                            \
    do {                                                          \
        if constexpr (std::is_same_v<dtype, half>) {              \
            aclshmem_half_get_nbi(__VA_ARGS__);                  \
        } else if constexpr (std::is_same_v<dtype, bfloat16_t>) { \
            aclshmem_bfloat16_get_nbi(__VA_ARGS__);              \
        }                                                         \
    } while (0)

namespace MoeDistributeCombineImpl {
constexpr uint8_t BUFFER_NUM = 2;             // Multi-buffer
constexpr uint32_t STATE_OFFSET = 512;        // State space offset address
constexpr uint32_t STATE_SIZE = 1024 * 1024;  // 1M
constexpr uint32_t RANK_SIZE_ON_WIN_512 = 512 * 1024;
constexpr uint32_t RANK_SIZE_ON_WIN_256 = 256 * 1024;
constexpr uint32_t TP_RANK_SIZE_ON_WIN = 0;
constexpr uint32_t UB_ALIGN = 32;                   // UB aligned to 32 bytes
constexpr uint32_t SELF_STATE_OFFSET = 256 * 1024;  // Local card state space offset address
constexpr uint8_t EP_DOMAIN = 0;
constexpr uint8_t TP_DOMAIN = 1;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint32_t VEC_LEN = 256U;
constexpr float SCALE_PARAM = 127.0;
// BlockReduceMax 256-byte aligned, compute block count per 256 bytes
constexpr uint32_t BLOCK_NUM = 256U / UB_ALIGN;
constexpr int CAM_MAX_RANK_SIZE = 384;                // cam max rank size
constexpr int64_t IPC_DATA_OFFSET = 2 * 1024 * 1024;  // first 2MB for flag.

constexpr uint32_t TP_CONTEXT_OFFSET = 512 * 1024 * 1024;  // 512M

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

#define TemplateMC2TypeClass typename ExpandXType, typename ExpandIdxType, bool IsNeedReduceScatter, bool IsQuant
#define TemplateMC2TypeFunc ExpandXType, ExpandIdxType, IsNeedReduceScatter, IsQuant
template <TemplateMC2TypeClass>
class MoeCombineShmem
{
public:
    __aicore__ inline MoeCombineShmem(){};
    __aicore__ inline void Init(GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount,
                                GM_ADDR tpSendCount, GM_ADDR scales, GM_ADDR XOut, GM_ADDR workspaceGM, TPipe *pipe,
                                const MoeCombineShmemTilingData *tilingData);
    __aicore__ inline void Process();

private:
    __aicore__ inline void InitStatusTargetSum();
    __aicore__ inline void AlltoAllBuffInit();
    __aicore__ inline void ReduceScatterTrans();
    __aicore__ inline void SetWaitTpStatusAndDisPatch();
    __aicore__ inline void CustomAdd(LocalTensor<ExpandXType> &dst, LocalTensor<ExpandXType> &src0,
                                     LocalTensor<ExpandXType> &src1, uint32_t dataCnt);
    __aicore__ inline void ExpertAlltoAllDispatchInnerCopyAdd(uint32_t tokenNumLoop, uint32_t srcStartTokenIdx,
                                                              uint32_t ep, uint32_t expertIdx);
    __aicore__ inline void ExpertAlltoAllDispatchReduceScatterCopyAdd(uint32_t srcStartTokenIdx, uint32_t dataCnt,
                                                                      uint32_t loopIdx, uint32_t ep);
    __aicore__ inline void ExpertAlltoAllDispatchCopyAdd();
    __aicore__ inline void QuantProcess();
    __aicore__ inline void DequantProcess(LocalTensor<ExpandXType> &src);
    __aicore__ inline void LocalWindowCopy();
    __aicore__ inline void BuffInit();
    __aicore__ inline void SplitCoreCal();
    __aicore__ inline void SetStatus();
    __aicore__ inline void WaitDispatch();
    __aicore__ GM_ADDR GetWinAddrByRankId(const int32_t rankId, const uint8_t domain, const uint8_t expertLocalId = 0U)
    {
        return (GM_ADDR)(gva_gm) + IPC_DATA_OFFSET + winDataSizeOffset_ + expertLocalId * expertPerSizeOnWin_;
    }
    __aicore__ GM_ADDR GetWinStateAddrByRankId(const int32_t rankId, const uint8_t domain)
    {
        return (GM_ADDR)(gva_gm) + dataState_ * WIN_STATE_OFFSET;
    }

    __aicore__ inline uint32_t MIN(uint32_t x, uint32_t y)
    {
        return (x < y) ? x : y;
    }

    TPipe *tpipe_{nullptr};
    GlobalTensor<ExpandXType> expandXGM_;
    GlobalTensor<ExpandIdxType> expertIdsGM_;
    GlobalTensor<ExpandIdxType> expandIdxGM_;
    GlobalTensor<ExpandIdxType> epSendCountGM_;
    GlobalTensor<ExpandIdxType> tpSendCountGM_;
    GlobalTensor<float> expandScalesGM_;
    GlobalTensor<ExpandXType> expandOutGlobal_;
    GlobalTensor<ExpandXType> rankWindow_;           // Variable for storing peer window
    GlobalTensor<int32_t> rankStates_;               // Variable for storing peer state window
    GlobalTensor<float> epStatusSpaceGlobalTensor_;  // Parameters for copying into window state region
    GlobalTensor<float> tpStatusSpaceGlobalTensor_;
    GlobalTensor<ExpandXType> tpRankWindow_;
    GlobalTensor<ExpandXType> rowTmpGlobal_;
    GlobalTensor<GM_ADDR> peerMemsAddrGm_;
    GM_ADDR workspaceGM_;
    GM_ADDR epWindowGM_;
    GM_ADDR epStatusSpaceGm_;
    GM_ADDR tpWindowGM_;
    GM_ADDR tpStatusSpaceGm_;
    GM_ADDR stateGM_;

    LocalTensor<ExpandXType> winTpSendCountTensor_;
    LocalTensor<ExpandXType> gmTpSendCountTensor_;
    LocalTensor<ExpandXType> outTensor_;
    LocalTensor<float> winTpSendCountFloatTensor_;
    LocalTensor<float> gmTpSendCountFloatTensor_;
    LocalTensor<ExpandIdxType> epSendCountLocal_;

    // Tiling side ensures data upper bounds, multiplication won't overflow, so uint32_t is used uniformly
    uint32_t axisBS_{0};
    uint32_t axisMaxBS_{0};
    uint32_t axisH_{0};
    uint32_t axisK_{0};
    uint32_t aivNum_{0};
    uint32_t epWorldSize_{0};
    uint32_t tpWorldSize_{0};
    uint32_t epRankId_{0};
    uint32_t tpRankId_{0};
    uint32_t coreIdx_{0};              // aiv id
    uint32_t sharedExpertRankNum_{0};  // Shared expert card count
    uint32_t moeExpertNum_{0};         // MOE expert count
    uint32_t moeExpertPerRankNum_{0};  // MOE expert count per card
    uint32_t moeSendNum_{0};           // moeExpertPerRankNum_ * epWorldSize_
    uint32_t tpScatterNum_{0};
    uint32_t firstTpTokenEndIdx_{0};
    uint32_t firstTpTokenEndOffset_{0};
    uint32_t endTok_{0};
    GM_ADDR gva_gm;

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
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> moeQueue_;
    TQue<QuePosition::VECIN, 1> moeSumQueue_;
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> gmTpSendCountQueue_;
    TQue<QuePosition::VECIN, 1> gmTpSendCountInQueue_;
    TQue<QuePosition::VECIN, 1> winTpSendCountInQueue_;
    TQue<QuePosition::VECIN, 1> gmQuantInQueue_;
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
    TBuf<> gatherMaskOutBuf_;  // Gather mask output buffer
    TBuf<> gatherTmpBuf_;      // Auxiliary gather tensor definition
    TBuf<> statusSumOutBuf_;
    float sumTarget_{0.0};
    int32_t epStateValue_;
    bool isShardExpert_{false};

    // Int8 quantization
    TBuf<> xAbsBuf_;
    TBuf<> xInt8Buf_;
    TBuf<> xMaxBuf_;
    TBuf<> xScaleBuf_;
    TBuf<> xScaleMulBuf_;
    LocalTensor<ExpandXType> absTensor_;
    LocalTensor<int8_t> castLocal_;
    LocalTensor<ExpandXType> reduceMaxTensor_;
    LocalTensor<ExpandXType> scaleDivLocal_;
    LocalTensor<ExpandXType> scaleDup_;
    LocalTensor<ExpandXType> sendLocal_;

    LocalTensor<half> fp16CastTensor_;
    LocalTensor<float> absFloatTensor_;
    LocalTensor<float> reduceMaxFloatTensor_;
    LocalTensor<float> scaleDivFloatLocal_;
    LocalTensor<float> scaleFloatDup_;
    LocalTensor<float> sendFloatLocal_;

    uint32_t mask_{0};
    uint32_t repeatNum_{0};
    uint32_t scaleNum_{0};
    uint32_t scaleLen_{0};
    uint32_t scaleGranu_{0};
    half scaleVal_;
    float scaleValFloat_;
};

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::Init(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount, GM_ADDR tpSendCount, GM_ADDR scales,
    GM_ADDR XOut, GM_ADDR workspaceGM, TPipe *pipe, const MoeCombineShmemTilingData *tilingData)
{
    tpipe_ = pipe;
    coreIdx_ = GetBlockIdx();
    epRankId_ = tilingData->moeDistributeCombineInfo.epRankId;
    GM_ADDR statusDataSpaceGm;
    GlobalTensor<int32_t> selfDataStatusTensor;
    gva_gm = (GM_ADDR)tilingData->moeDistributeCombineInfo.shmemPtr;
    statusDataSpaceGm = (GM_ADDR)(gva_gm);
    selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));

    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfDataStatusTensor[coreIdx_ * UB_ALIGN]);
    dataState_ = selfDataStatusTensor(coreIdx_ * UB_ALIGN);
    if (dataState_ == 0) {
        selfDataStatusTensor(coreIdx_ * UB_ALIGN) = 1;
    } else {
        selfDataStatusTensor(coreIdx_ * UB_ALIGN) = 0;
    }
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfDataStatusTensor[coreIdx_ * UB_ALIGN]);
    pipe_barrier(PIPE_ALL);

    workspaceGM_ = workspaceGM;
    expandXGM_.SetGlobalBuffer((__gm__ ExpandXType *)expandX);
    expertIdsGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expertIds);
    expandIdxGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expandIdx);
    epSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)epSendCount);
    expandScalesGM_.SetGlobalBuffer((__gm__ float *)scales);
    expandOutGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)XOut);
    axisBS_ = tilingData->moeDistributeCombineInfo.bs;
    axisH_ = tilingData->moeDistributeCombineInfo.h;
    axisK_ = tilingData->moeDistributeCombineInfo.k;
    aivNum_ = tilingData->moeDistributeCombineInfo.aivNum;
    ubSize_ = tilingData->moeDistributeCombineInfo.totalUbSize;
    sharedExpertRankNum_ = tilingData->moeDistributeCombineInfo.sharedExpertRankNum;
    moeExpertNum_ = tilingData->moeDistributeCombineInfo.moeExpertNum;
    moeExpertPerRankNum_ = tilingData->moeDistributeCombineInfo.moeExpertPerRankNum;
    epWorldSize_ = tilingData->moeDistributeCombineInfo.epWorldSize;
    axisMaxBS_ = tilingData->moeDistributeCombineInfo.globalBs / epWorldSize_;
    moeSendNum_ = epWorldSize_ * moeExpertPerRankNum_;
    tpWorldSize_ = tilingData->moeDistributeCombineInfo.tpWorldSize;
    tpRankId_ = tilingData->moeDistributeCombineInfo.tpRankId;
    totalWinSize_ = tilingData->moeDistributeCombineInfo.totalWinSize;
    stateOffset_ = (moeSendNum_ > 512) ? (STATE_OFFSET / 2) : STATE_OFFSET;
    expertPerSizeOnWin_ =
        static_cast<uint64_t>(axisMaxBS_) * static_cast<uint64_t>(axisH_) * static_cast<uint64_t>(sizeof(ExpandXType));
    winDataSizeOffset_ = static_cast<uint64_t>(dataState_) * static_cast<uint64_t>(moeSendNum_) * expertPerSizeOnWin_;
    epWindowGM_ = GetWinAddrByRankId(epRankId_, EP_DOMAIN);
    epStatusSpaceGm_ = GetWinStateAddrByRankId(epRankId_, EP_DOMAIN);
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
    OOMCheckAddrRange<ExpandXType>((__gm__ ExpandXType *)(epWindowGM_), totalWinSize_);
    OOMCheckAddrRange<float>((__gm__ float *)(epStatusSpaceGm_), STATE_SIZE);
#endif
    epStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)epStatusSpaceGm_);
    epDataOffsetOnWin_ = epRankId_ * moeExpertPerRankNum_ * static_cast<uint32_t>(expertPerSizeOnWin_);
    epStateOffsetOnWin_ = epRankId_ * stateOffset_;
    isShardExpert_ = (epRankId_ < sharedExpertRankNum_);
    axisHFloatSize_ = axisH_ * sizeof(float);
    axisHExpandXTypeSize_ = axisH_ * sizeof(ExpandXType);
    bsKNum_ = axisBS_ * axisK_;

    if constexpr (IsQuant) {
        scaleValFloat_ = static_cast<float>(1.0f / SCALE_PARAM);
        // Compute the number of reduceMax results per block
        scaleGranu_ = UB_ALIGN / static_cast<uint32_t>(sizeof(float));
        scaleNum_ = axisH_ / scaleGranu_;
        scaleLen_ = scaleNum_;
        repeatNum_ = static_cast<uint32_t>(axisH_ / (VEC_LEN / sizeof(float)));
        mask_ = static_cast<uint32_t>(VEC_LEN / sizeof(float));
    }

    if constexpr (IsNeedReduceScatter) {
        tpSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)tpSendCount);
        tpWorldSize_ = tilingData->moeDistributeCombineInfo.tpWorldSize;
        tpRankId_ = tilingData->moeDistributeCombineInfo.tpRankId;
        tpWindowGM_ = GetWinAddrByRankId(tpRankId_, TP_DOMAIN);
        tpStatusSpaceGm_ = GetWinStateAddrByRankId(tpRankId_, TP_DOMAIN);
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
        OOMCheckAddrRange<ExpandXType>((__gm__ ExpandXType *)(tpWindowGM_), totalWinSize_);
        OOMCheckAddrRange<float>((__gm__ float *)(tpStatusSpaceGm_), STATE_SIZE);
#endif
        tpStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)tpStatusSpaceGm_);
        tpDataOffsetOnWin_ = tpRankId_ * TP_RANK_SIZE_ON_WIN;
        tpStateOffsetOnWin_ = tpRankId_ * stateOffset_;
        uint32_t tpScatterRankWinOffset = (tpRankId_ == 0) ? TP_RANK_SIZE_ON_WIN : 0;
        GM_ADDR rankGM = tpWindowGM_ + tpScatterRankWinOffset;
        tpRankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    }

    tpipe_->InitBuffer(moeQueue_, BUFFER_NUM, axisHExpandXTypeSize_);  // 7168 * 2 * 2 = 28672
    InitStatusTargetSum();
    SplitCoreCal();
}

// Select 1.5K space at 512K offset within 1M to record local card historical state
template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::InitStatusTargetSum()
{
    // EP domain state
    GlobalTensor<int32_t> selfStatusTensor;
    selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(epStatusSpaceGm_ + SELF_STATE_OFFSET));
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfStatusTensor[coreIdx_ * UB_ALIGN]);
    int32_t state = selfStatusTensor(coreIdx_ * UB_ALIGN);
    if (state == 0) {
        sumTarget_ = static_cast<float>(1.0);
        selfStatusTensor(coreIdx_ * UB_ALIGN) = 0x3F800000;
        epStateValue_ = 0x3F800000;
    } else {
        sumTarget_ = static_cast<float>(0.0);
        selfStatusTensor(coreIdx_ * UB_ALIGN) = 0;
        epStateValue_ = 0;
    }
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfStatusTensor[coreIdx_ * UB_ALIGN]);
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::BuffInit()
{
    tpipe_->Reset();
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);                                       // 32
    uint32_t sendNumAlign = Ceil(moeSendNum_ * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;  // Round up to 32B
    tpipe_->InitBuffer(sendCountBuf_, sendNumAlign);  // epWorldSize_ * moeExpertPerRankNum_ * 4, rounded up to 32B
    if constexpr (IsNeedReduceScatter) {
        tpipe_->InitBuffer(winTpSendCountInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);  // 28K
        tpipe_->InitBuffer(gmTpSendCountInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);   // 28K
        tpipe_->InitBuffer(xOutQueue_, BUFFER_NUM, axisHExpandXTypeSize_);              // 28K
        if constexpr (AscendC::IsSameType<ExpandXType, bfloat16_t>::value) {
            tpipe_->InitBuffer(winTpSendCountFloatBuf_, axisHFloatSize_);
            tpipe_->InitBuffer(gmTpSendCountFloatBuf_, axisHFloatSize_);
            winTpSendCountFloatTensor_ = winTpSendCountFloatBuf_.Get<float>();
            gmTpSendCountFloatTensor_ = gmTpSendCountFloatBuf_.Get<float>();
        }
    } else {
        tpipe_->InitBuffer(gmTpSendCountQueue_, BUFFER_NUM, axisHExpandXTypeSize_);  // 28K
        if constexpr (IsQuant) {
            tpipe_->InitBuffer(gmQuantInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);      // 28K
            tpipe_->InitBuffer(xOutQueue_, BUFFER_NUM, axisHExpandXTypeSize_);           // 28K
            tpipe_->InitBuffer(xAbsBuf_, axisHFloatSize_);                               // 28K
            tpipe_->InitBuffer(xMaxBuf_, axisHFloatSize_ / (UB_ALIGN / sizeof(float)));  // 28K
            tpipe_->InitBuffer(xScaleMulBuf_, axisHFloatSize_);                          // 28K
            tpipe_->InitBuffer(winTpSendCountFloatBuf_, axisHFloatSize_);                // 28K

            winTpSendCountFloatTensor_ = winTpSendCountFloatBuf_.Get<float>();
            absFloatTensor_ = xAbsBuf_.Get<float>();
            reduceMaxFloatTensor_ = xMaxBuf_.Get<float>();
            scaleFloatDup_ = xScaleMulBuf_.Get<float>();
            fp16CastTensor_ = xAbsBuf_.Get<half>();
        }
    }
    epSendCountLocal_ = sendCountBuf_.Get<int32_t>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::AlltoAllBuffInit()
{
    tpipe_->Reset();
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);                              // 32 * moeExpertPerRankNum_
    tpipe_->InitBuffer(statusBuf_, sendRankNum_ * UB_ALIGN);                  // 288 * 32 = 9216
    tpipe_->InitBuffer(expertIdsBuf_, axisBS_ * axisK_ * sizeof(int32_t));    // 32 * 8 * 4 = 1024
    tpipe_->InitBuffer(expandScalesBuf_, axisBS_ * axisK_ * sizeof(float));   // 32 * 8 * 4 = 1024
    tpipe_->InitBuffer(tokenBuf_, axisH_ * sizeof(ExpandXType));              // 7168 * 2 = 14336
    tpipe_->InitBuffer(rowTmpFloatBuf_, axisHFloatSize_);                     // 7168 * 4 = 28672
    tpipe_->InitBuffer(mulBuf_, axisHFloatSize_);                             // 7168 * 4 = 28672
    tpipe_->InitBuffer(sumFloatBuf_, axisHFloatSize_);                        // 7168 * 4 = 28672
    tpipe_->InitBuffer(indexCountsBuf_, axisBS_ * axisK_ * sizeof(int32_t));  // 32 * 8 * 4 = 1024
    tpipe_->InitBuffer(moeSumQueue_, BUFFER_NUM, axisHExpandXTypeSize_);      // 7168 * 2 * 2 = 28672
    tpipe_->InitBuffer(gatherMaskOutBuf_, epWorldSize_ * sizeof(float));      // 288 * 4 = 1152
    tpipe_->InitBuffer(gatherTmpBuf_, sizeof(uint32_t));                      // 4
    tpipe_->InitBuffer(statusSumOutBuf_, sizeof(float));                      // 4

    if constexpr (IsQuant) {
        tpipe_->InitBuffer(xAbsBuf_, axisHFloatSize_);  // 28K
        fp16CastTensor_ = mulBuf_.Get<half>();
        absFloatTensor_ = rowTmpFloatBuf_.Get<float>();
        scaleFloatDup_ = mulBuf_.Get<float>();
        scaleDivFloatLocal_ = xAbsBuf_.Get<float>();
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::SplitCoreCal()
{
    // Split worldSize across cores by card, get the number of cards each core handles,
    // for setting/clearing state and MOE sending
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

// Current logic assumes tp=2 scenario, generalization needs re-adaptation, local card tokens are at the front
// When tp=2, directly distribute peer TP data across cores for sending
// TP remains on local rank, no shmem needed
template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::ReduceScatterTrans()
{
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(tpSendCountGM_[tpRankId_]);
    // Get dataCopyInGM offset based on tpRankId
    uint32_t offset = tpSendCountGM_.GetValue(tpRankId_) * axisH_;
    GlobalTensor<ExpandXType> dataCopyInGM = expandXGM_[offset];
    GM_ADDR rankGM = GetWinAddrByRankId(1 - tpRankId_, TP_DOMAIN) + tpDataOffsetOnWin_;
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
    OOMCheckAddrRange<ExpandXType>((__gm__ ExpandXType *)(GetWinAddrByRankId(1 - tpRankId_, TP_DOMAIN)), totalWinSize_);
#endif
    rankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    uint32_t copyStartIdx = 0;
    if (startRankId_ > 0) {
        DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            epSendCountGM_[epWorldSize_ + startRankId_ - 1]);
        copyStartIdx = epSendCountGM_.GetValue(epWorldSize_ + startRankId_ - 1);
    }
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        epSendCountGM_[epWorldSize_ + endRankId_ - 1]);
    uint32_t copyEndIdx = epSendCountGM_.GetValue(epWorldSize_ + endRankId_ - 1);
    LocalTensor<ExpandXType> tmpUb;
    for (uint32_t tokenNumIdx = copyStartIdx; tokenNumIdx < copyEndIdx; tokenNumIdx++) {
        tmpUb = moeQueue_.AllocTensor<ExpandXType>();
        // dataCopyInGM is the input data obtained by taking an offset from expandXGM_
        // GM --> UB
        DataCopy(tmpUb, dataCopyInGM[tokenNumIdx * axisH_], axisH_);
        moeQueue_.EnQue(tmpUb);
        tmpUb = moeQueue_.DeQue<ExpandXType>();
        // UB --> GM
        DataCopy(rankWindow_[tokenNumIdx * axisH_], tmpUb, axisH_);
        moeQueue_.FreeTensor<ExpandXType>(tmpUb);
    }
}

// Pipeline flow
// 46 -> gm -> ub syncall win->gm add -> alltoall
// 2 -> win wait syncall gm -> ub win ->gm add -> alltoall
// Reference Dispatch_a3, DataCopy here also does not need shmem
template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::SetWaitTpStatusAndDisPatch()
{
    pipe_barrier(PIPE_ALL);
    if (startRankId_ >= epWorldSize_) {
        return;
    }
    if constexpr (IsNeedReduceScatter) {
        uint32_t tpToRankId = 1 - tpRankId_;  // Currently adapted for tpWorldSize_==2
        pipe_barrier(PIPE_ALL);
        LocalTensor<float> statusFlagUb = readStateBuf_.Get<float>();
        statusFlagUb(0) = sumTarget_;
        SyncFunc<AscendC::HardEvent::S_MTE3>();
        GlobalTensor<float> tpWindowInstatusFp32Tensor_;
        stateGM_ = GetWinStateAddrByRankId(tpToRankId, TP_DOMAIN) + coreIdx_ * stateOffset_;
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
        OOMCheckAddrRange<int32_t>((__gm__ int32_t *)(GetWinStateAddrByRankId(tpToRankId, TP_DOMAIN)), STATE_SIZE);
#endif
        tpWindowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)stateGM_);
        // UB --> GM
        DataCopy<float>(tpWindowInstatusFp32Tensor_, statusFlagUb, 8UL);  // 8 is data size, copy with 32-byte alignment
        SyncFunc<AscendC::HardEvent::MTE3_S>();
        LocalTensor<float> statusFp32Tensor_ = readStateBuf_.Get<float>();
        float sumOfFlag = static_cast<float>(-1.0);
        uint32_t statusRankOffset = coreIdx_ * stateOffset_ / sizeof(float);  // tp = 2 scenario
        while (sumOfFlag != sumTarget_) {
            DataCopy<float>(statusFp32Tensor_, tpStatusSpaceGlobalTensor_[statusRankOffset], 8);
            SyncFunc<AscendC::HardEvent::MTE2_S>();
            sumOfFlag = statusFp32Tensor_.GetValue(0);
            SyncFunc<AscendC::HardEvent::S_MTE2>();
        }
    }
    // Copy win gm->ub add ->alltoall send
    ExpertAlltoAllDispatchCopyAdd();
    SyncFunc<AscendC::HardEvent::MTE3_S>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::ExpertAlltoAllDispatchCopyAdd()
{
    if (startRankId_ >= epWorldSize_) {  // Idle core, return directly
        return;
    }
    uint32_t curRankExpertNum = 0;
    DataCopyExtParams epSendCntParams;
    if (isShardExpert_) {
        curRankExpertNum = 1;  // For shared expert, epSendCount input dimension is epWorldSize
        epSendCntParams = {1U, static_cast<uint32_t>(epWorldSize_ * sizeof(uint32_t)), 0U, 0U, 0U};
    } else {
        curRankExpertNum = moeExpertPerRankNum_;
        epSendCntParams = {1U, static_cast<uint32_t>(moeSendNum_ * sizeof(uint32_t)), 0U, 0U, 0U};
    }
    DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
    // local GM --> UB
    DataCopyPad(epSendCountLocal_, epSendCountGM_, epSendCntParams, copyPadParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();
    uint32_t preCount = 0;
    uint32_t startTokenIdx = 0;
    uint32_t curTokenNum = 0;
    // Core assignment is based on card count; first loop over each expert on a single card,
    // then loop over the card IDs handled by this core,
    // because one expert's data in the network is processed together
    for (uint32_t expertIdx = 0U; expertIdx < curRankExpertNum; expertIdx++) {
#ifdef USE_WRITE_SHUFFLE
#pragma message("use write shuffle")
        uint32_t sendEpCount = endRankId_ - startRankId_;
        for (uint32_t i = 0; i < sendEpCount; ++i) {
            uint32_t ep = startRankId_ + (i + epRankId_) % sendEpCount;
            if ((ep > 0) || (expertIdx > 0U)) {
                preCount = epSendCountLocal_.GetValue(expertIdx * epWorldSize_ + ep - 1);
            } else {
                preCount = 0;
            }
#else
        for (uint32_t ep = startRankId_; ep < endRankId_; ep++) {
            if ((ep > 0) || (expertIdx > 0)) {
                preCount = epSendCountLocal_.GetValue(expertIdx * epWorldSize_ + ep - 1);
            }
#endif
            curTokenNum = epSendCountLocal_.GetValue(expertIdx * epWorldSize_ + ep) - preCount;
            if (curTokenNum == 0) {
                continue;
            }
            startTokenIdx = preCount * axisH_;
            ExpertAlltoAllDispatchInnerCopyAdd(curTokenNum, startTokenIdx, ep, expertIdx);
        }
    }
}

/*
    Interface function: Quantize one token data,
    The first H bytes store the quantized int8 data,
    the last scaleNum_ fp16/bf16 values store the quantization parameters
*/
template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::QuantProcess()
{
    SyncFunc<AscendC::HardEvent::MTE2_V>();
    castLocal_ = sendLocal_.template ReinterpretCast<int8_t>();
    scaleDivLocal_ = castLocal_[axisH_].template ReinterpretCast<ExpandXType>();

    Cast(winTpSendCountFloatTensor_, gmTpSendCountTensor_, RoundMode::CAST_NONE, axisH_);
    pipe_barrier(PIPE_V);
    Abs(absFloatTensor_, winTpSendCountFloatTensor_, axisH_);
    pipe_barrier(PIPE_V);
    BlockReduceMax(reduceMaxFloatTensor_, absFloatTensor_, repeatNum_, mask_, 1, 1, BLOCK_NUM);
    pipe_barrier(PIPE_V);
    Muls(reduceMaxFloatTensor_, reduceMaxFloatTensor_, scaleValFloat_, scaleNum_);
    pipe_barrier(PIPE_V);
    Cast(scaleDivLocal_, reduceMaxFloatTensor_, RoundMode::CAST_RINT, scaleNum_);
    pipe_barrier(PIPE_V);
    Brcb(scaleFloatDup_, reduceMaxFloatTensor_, repeatNum_, {1, BLOCK_NUM});
    pipe_barrier(PIPE_V);
    Div(winTpSendCountFloatTensor_, winTpSendCountFloatTensor_, scaleFloatDup_, axisH_);
    pipe_barrier(PIPE_V);
    Cast(fp16CastTensor_, winTpSendCountFloatTensor_, RoundMode::CAST_RINT, axisH_);
    pipe_barrier(PIPE_V);
    Cast(castLocal_, fp16CastTensor_, RoundMode::CAST_RINT, axisH_);
    SyncFunc<AscendC::HardEvent::V_MTE3>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::ExpertAlltoAllDispatchReduceScatterCopyAdd(
    uint32_t srcStartTokenIdx, uint32_t dataCnt, uint32_t loopIdx, uint32_t ep)
{
    gmTpSendCountTensor_ = gmTpSendCountInQueue_.AllocTensor<ExpandXType>();
    DataCopy(gmTpSendCountTensor_, expandXGM_[srcStartTokenIdx], dataCnt);
    gmTpSendCountInQueue_.EnQue(gmTpSendCountTensor_);

    winTpSendCountTensor_ = winTpSendCountInQueue_.AllocTensor<ExpandXType>();
    DataCopy(winTpSendCountTensor_, tpRankWindow_[srcStartTokenIdx], dataCnt);
    winTpSendCountInQueue_.EnQue(winTpSendCountTensor_);

    gmTpSendCountTensor_ = gmTpSendCountInQueue_.DeQue<ExpandXType>();
    winTpSendCountTensor_ = winTpSendCountInQueue_.DeQue<ExpandXType>();
    outTensor_ = xOutQueue_.AllocTensor<ExpandXType>();

    CustomAdd(outTensor_, winTpSendCountTensor_, gmTpSendCountTensor_, dataCnt);
    gmTpSendCountInQueue_.FreeTensor<ExpandXType>(gmTpSendCountTensor_);
    winTpSendCountInQueue_.FreeTensor<ExpandXType>(winTpSendCountTensor_);
    xOutQueue_.EnQue(outTensor_);

    outTensor_ = xOutQueue_.DeQue<ExpandXType>();
    // UB --> GM [This should be written to the corresponding rank index]
    SHMEM_PUT_BY_DTYPE(ExpandXType, rankWindow_[loopIdx * dataCnt], outTensor_, dataCnt, ep);
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::ExpertAlltoAllDispatchInnerCopyAdd(
    uint32_t tokenNumLoop, uint32_t srcStartTokenIdx, uint32_t ep, uint32_t expertIdx)
{
    // Get the base address of the corresponding card's window
    GM_ADDR rankGM = GetWinAddrByRankId(ep, EP_DOMAIN, expertIdx) + epDataOffsetOnWin_;
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
    OOMCheckAddrRange<ExpandXType>((__gm__ ExpandXType *)(GetWinAddrByRankId(ep, EP_DOMAIN)), totalWinSize_);
#endif
    if ((isShardExpert_) && (ep < sharedExpertRankNum_)) {  // This is local card data, simulating data sent from EP
        rankGM = GetWinAddrByRankId(epRankId_, EP_DOMAIN, expertIdx) + ep * moeExpertPerRankNum_ * expertPerSizeOnWin_;
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
        OOMCheckAddrRange<ExpandXType>((__gm__ ExpandXType *)(GetWinAddrByRankId(epRankId_, EP_DOMAIN)), totalWinSize_);
#endif
    }
    rankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    uint32_t dataCnt = axisH_;
    for (uint32_t loopIdx = 0; loopIdx < tokenNumLoop; loopIdx++) {
        if constexpr (IsNeedReduceScatter) {
            ExpertAlltoAllDispatchReduceScatterCopyAdd(srcStartTokenIdx, dataCnt, loopIdx, ep);
        } else {
            if constexpr (IsQuant) {
                gmTpSendCountTensor_ = gmQuantInQueue_.AllocTensor<ExpandXType>();
                DataCopy(gmTpSendCountTensor_, expandXGM_[srcStartTokenIdx], dataCnt);
                gmQuantInQueue_.EnQue(gmTpSendCountTensor_);
                gmTpSendCountTensor_ = gmQuantInQueue_.DeQue<ExpandXType>();
                sendLocal_ = xOutQueue_.AllocTensor<ExpandXType>();
                QuantProcess();
                xOutQueue_.EnQue(sendLocal_);
                sendLocal_ = xOutQueue_.DeQue<ExpandXType>();
                SHMEM_PUT_BY_DTYPE(ExpandXType, rankWindow_[loopIdx * dataCnt], sendLocal_, axisH_ / 2 + scaleLen_, ep);
                gmQuantInQueue_.FreeTensor<ExpandXType>(gmTpSendCountTensor_);
                xOutQueue_.FreeTensor<ExpandXType>(sendLocal_);
            } else {
                gmTpSendCountTensor_ = gmTpSendCountQueue_.AllocTensor<ExpandXType>();
                DataCopy(gmTpSendCountTensor_, expandXGM_[srcStartTokenIdx], dataCnt);
                gmTpSendCountQueue_.EnQue(gmTpSendCountTensor_);
                gmTpSendCountTensor_ = gmTpSendCountQueue_.DeQue<ExpandXType>();
                SHMEM_PUT_BY_DTYPE(ExpandXType, rankWindow_[loopIdx * dataCnt], gmTpSendCountTensor_, dataCnt, ep);
                gmTpSendCountQueue_.FreeTensor<ExpandXType>(gmTpSendCountTensor_);
            }
        }
        srcStartTokenIdx += dataCnt;
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::CustomAdd(LocalTensor<ExpandXType> &dst,
    LocalTensor<ExpandXType> &src0,
    LocalTensor<ExpandXType> &src1,
    uint32_t dataCnt)
{
    if constexpr (AscendC::IsSameType<ExpandXType, bfloat16_t>::value) {
        Cast(winTpSendCountFloatTensor_, src0, RoundMode::CAST_NONE, dataCnt);
        Cast(gmTpSendCountFloatTensor_, src1, RoundMode::CAST_NONE, dataCnt);
        pipe_barrier(PIPE_V);
        Add(winTpSendCountFloatTensor_, winTpSendCountFloatTensor_, gmTpSendCountFloatTensor_, dataCnt);
        pipe_barrier(PIPE_V);
        Cast(dst, winTpSendCountFloatTensor_, RoundMode::CAST_ROUND, dataCnt);
    } else {
        Add(dst, src0, src1, dataCnt);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::SetStatus()
{
    pipe_barrier(PIPE_ALL);
    if (startRankId_ >= epWorldSize_) {
        // Idle core, return directly
        return;
    }
    LocalTensor<int32_t> statusFlagUb = readStateBuf_.Get<int32_t>();
    statusFlagUb.SetValue(0, epStateValue_);
    for (uint32_t epIdx = startRankId_; epIdx < endRankId_; epIdx++) {
        stateGM_ = GetWinStateAddrByRankId(epIdx, EP_DOMAIN) + epStateOffsetOnWin_;
#if defined(ASCENDC_OOM) && ASCENDC_OOM == 1
        OOMCheckAddrRange<int32_t>((__gm__ int32_t *)(GetWinStateAddrByRankId(epIdx, EP_DOMAIN)), STATE_SIZE);
#endif
        rankStates_.SetGlobalBuffer((__gm__ int32_t *)stateGM_);
        aclshmem_int32_put_nbi(rankStates_, statusFlagUb, 8, epIdx);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::WaitDispatch()
{
    if (startRankId_ >= epWorldSize_) {
        SyncAll<true>();
        return;
    }
    LocalTensor<float> statusTensor = statusBuf_.Get<float>();
    LocalTensor<float> gatherMaskOutTensor = gatherMaskOutBuf_.Get<float>();
    LocalTensor<uint32_t> gatherTmpTensor = gatherTmpBuf_.Get<uint32_t>();
    LocalTensor<float> statusSumOutTensor = statusSumOutBuf_.Get<float>();
    gatherTmpTensor.SetValue(0, 1);
    uint32_t mask = 1;  // gatherMask + sum related parameters
    uint64_t rsvdCnt = 0;
    DataCopyParams intriParams{static_cast<uint16_t>(sendRankNum_), 1,
                               static_cast<uint16_t>((moeSendNum_ > 512) ? 7 : 15), 0};  // srcStride is 15 blocks
    float sumOfFlag = static_cast<float>(-1.0);
    float minTarget = (sumTarget_ * sendRankNum_) - (float)0.5;
    float maxTarget = (sumTarget_ * sendRankNum_) + (float)0.5;
    SumParams sumParams{1, sendRankNum_, sendRankNum_};
    SyncFunc<AscendC::HardEvent::S_V>();
    while ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
        // GM --> UB
        DataCopy<float>(statusTensor, epStatusSpaceGlobalTensor_[startRankId_ * stateOffset_ / sizeof(float)],
                        intriParams);
        SyncFunc<AscendC::HardEvent::MTE2_V>();
        GatherMask(gatherMaskOutTensor, statusTensor, gatherTmpTensor, true, mask, {1, (uint16_t)sendRankNum_, 1, 0},
                   rsvdCnt);
        PipeBarrier<PIPE_V>();
        Sum(statusSumOutTensor, gatherMaskOutTensor, sumParams);
        SyncFunc<AscendC::HardEvent::V_S>();
        sumOfFlag = statusSumOutTensor.GetValue(0);
    }
    SyncAll<true>();
}

/*
    Interface function: Dequantize the quantized int8 token
*/
template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::DequantProcess(LocalTensor<ExpandXType> &src)
{
    SyncFunc<AscendC::HardEvent::MTE2_V>();
    castLocal_ = src.template ReinterpretCast<int8_t>();
    scaleDivLocal_ = src[axisH_ / 2];

    SyncFunc<AscendC::HardEvent::S_V>();
    Cast(scaleDivFloatLocal_, scaleDivLocal_, AscendC::RoundMode::CAST_NONE, scaleNum_);
    Cast(fp16CastTensor_, castLocal_, AscendC::RoundMode::CAST_NONE, axisH_);
    pipe_barrier(PIPE_V);
    Cast(absFloatTensor_, fp16CastTensor_, AscendC::RoundMode::CAST_NONE, axisH_);
    Brcb(scaleFloatDup_, scaleDivFloatLocal_, repeatNum_, {1, BLOCK_NUM});
    pipe_barrier(PIPE_V);
    Mul(absFloatTensor_, absFloatTensor_, scaleFloatDup_, axisH_);
    pipe_barrier(PIPE_V);
    Cast(src, absFloatTensor_, AscendC::RoundMode::CAST_RINT, axisH_);
    pipe_barrier(PIPE_V);
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::LocalWindowCopy()
{
    uint32_t beginIndex = 0;
    uint32_t endIndex = 0;
    uint32_t processLen = 0;
    uint32_t tokenOffset = 0;
    uint32_t quantCopyLen = axisH_ / 2U + scaleLen_;  // Length per token in int8 quantization

    if (axisBS_ < aivNum_) {
        uint32_t aivNumPerToken = aivNum_ / axisBS_;  // Requires axisBS_ < aivNum_
        if constexpr (IsQuant) {
            aivNumPerToken = 1U;  // No need to split H in int8 quantization
        }
        if (coreIdx_ >= (axisBS_ * aivNumPerToken)) {
            return;
        }
        uint32_t tokenIndex = coreIdx_ / aivNumPerToken;  // Which token to process
        // Split H, aligned by UB_ALIGN
        processLen = ((axisH_ / UB_ALIGN) / aivNumPerToken) * UB_ALIGN;
        tokenOffset = processLen * (coreIdx_ % aivNumPerToken);     // Offset position
        // The last core in aivNumPerToken handles the remainder
        if ((coreIdx_ % aivNumPerToken) == (aivNumPerToken - 1)) {
            processLen = axisH_ - ((aivNumPerToken - 1) * processLen);
        }
        beginIndex = tokenIndex;
        endIndex = beginIndex + 1U;
    } else {
        uint32_t tokenPerAivNum = axisBS_ / aivNum_;
        uint32_t remainderToken = axisBS_ % aivNum_;
        beginIndex = tokenPerAivNum * coreIdx_;
        if (coreIdx_ < remainderToken) {
            tokenPerAivNum++;
            beginIndex = tokenPerAivNum * coreIdx_;
        } else {
            beginIndex += remainderToken;
        }
        endIndex = beginIndex + tokenPerAivNum;
        processLen = axisH_;
    }

    LocalTensor<ExpandIdxType> expertIdsLocal = expertIdsBuf_.Get<ExpandIdxType>();
    LocalTensor<float> expandScalesLocal = expandScalesBuf_.Get<float>();

    LocalTensor<float> rowTmpFloatLocal = rowTmpFloatBuf_.Get<float>();
    LocalTensor<float> mulBufLocal = mulBuf_.Get<float>();
    LocalTensor<float> sumFloatBufLocal = sumFloatBuf_.Get<float>();

    LocalTensor<ExpandIdxType> indexCountsLocal = indexCountsBuf_.Get<ExpandIdxType>();
    const DataCopyExtParams bskParams = {1U, static_cast<uint32_t>(bsKNum_ * sizeof(uint32_t)), 0U, 0U, 0U};
    const DataCopyPadExtParams<ExpandIdxType> copyPadParams{false, 0U, 0U, 0U};
    const DataCopyPadExtParams<float> copyPadFloatParams{false, 0U, 0U, 0U};

    DataCopyPad(indexCountsLocal, expandIdxGM_, bskParams, copyPadParams);
    DataCopyPad(expertIdsLocal, expertIdsGM_, bskParams, copyPadParams);
    DataCopyPad(expandScalesLocal, expandScalesGM_, bskParams, copyPadFloatParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();

    for (uint32_t tokenIndex = beginIndex; tokenIndex < endIndex; tokenIndex++) {
        uint32_t index = tokenIndex * axisK_;
        int32_t moeExpert = 0;
        float scaleVal = 0.0;
        GM_ADDR wAddr;
        SyncFunc<AscendC::HardEvent::MTE3_V>();  // Same tensor as result output DataCopy
        Duplicate(sumFloatBufLocal, (float)0, axisH_);
        LocalTensor<ExpandXType> tmpUb;
        for (uint32_t i = 0; i < axisK_; i++) {
            moeExpert = expertIdsLocal.GetValue(index);
            scaleVal = expandScalesLocal.GetValue(index);
            wAddr = (__gm__ uint8_t *)(epWindowGM_) +
                    expertPerSizeOnWin_ * moeExpertPerRankNum_ * sharedExpertRankNum_ +
                    expertPerSizeOnWin_ * moeExpert + indexCountsLocal.GetValue(index) * axisHExpandXTypeSize_ +
                    tokenOffset * sizeof(ExpandXType);
            rowTmpGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)wAddr);
            tmpUb = moeSumQueue_.AllocTensor<ExpandXType>();
            if constexpr (IsQuant) {
                SHMEM_GET_BY_DTYPE(ExpandXType, tmpUb, rowTmpGlobal_, quantCopyLen, epRankId_);
            } else {
                SHMEM_GET_BY_DTYPE(ExpandXType, tmpUb, rowTmpGlobal_, processLen, epRankId_);
                SyncFunc<AscendC::HardEvent::MTE2_V>();
            }
            moeSumQueue_.EnQue(tmpUb);
            tmpUb = moeSumQueue_.DeQue<ExpandXType>();

            if constexpr (IsQuant) {
                DequantProcess(tmpUb);
            }

            Cast(rowTmpFloatLocal, tmpUb, AscendC::RoundMode::CAST_NONE, processLen);
            pipe_barrier(PIPE_V);
            AscendC::Muls(mulBufLocal, rowTmpFloatLocal, scaleVal, processLen);
            pipe_barrier(PIPE_V);
            AscendC::Add(sumFloatBufLocal, sumFloatBufLocal, mulBufLocal, processLen);
            index++;
            moeSumQueue_.FreeTensor<ExpandXType>(tmpUb);
        }
        LocalTensor<ExpandXType> rowTmpLocal = tokenBuf_.Get<ExpandXType>();
        if (sharedExpertRankNum_ > 0U) {
            // Accumulate shared expert data, within current BS range, one core processes one token,
            // deduce the corresponding shared expert from the current tokenId
            uint32_t temp = (epRankId_ * axisBS_) / sharedExpertRankNum_;
            uint32_t moeOnShareRank = Ceil((tokenIndex + 1 + temp) * sharedExpertRankNum_, axisBS_) - 1 - epRankId_;
            uint32_t preCnt = (moeOnShareRank + epRankId_) * axisBS_ / sharedExpertRankNum_ -
                epRankId_ * axisBS_ / sharedExpertRankNum_;
            __gm__ ExpandXType *shareAddr =
                (__gm__ ExpandXType *)(epWindowGM_ + moeOnShareRank * expertPerSizeOnWin_ * moeExpertPerRankNum_) +
                (tokenIndex - preCnt) * axisH_ + tokenOffset;
            if (isShardExpert_) {
                shareAddr =
                    (__gm__ ExpandXType *)(epWindowGM_ + epRankId_ * expertPerSizeOnWin_ * moeExpertPerRankNum_) +
                    tokenIndex * axisH_ + tokenOffset;
            }
            GlobalTensor<ExpandXType> shareTokGlobal;
            shareTokGlobal.SetGlobalBuffer((__gm__ ExpandXType *)(shareAddr));
            SyncFunc<AscendC::HardEvent::V_MTE2>();  // Same address as result output Cast
            if constexpr (IsQuant) {
                SHMEM_GET_BY_DTYPE(ExpandXType, rowTmpLocal, shareTokGlobal, quantCopyLen, epRankId_);
                DequantProcess(rowTmpLocal);
            } else {
                SHMEM_GET_BY_DTYPE(ExpandXType, rowTmpLocal, shareTokGlobal, processLen, epRankId_);
                SyncFunc<AscendC::HardEvent::MTE2_V>();
            }

            Cast(rowTmpFloatLocal, rowTmpLocal, AscendC::RoundMode::CAST_NONE, processLen);
            pipe_barrier(PIPE_V);
            AscendC::Add(sumFloatBufLocal, sumFloatBufLocal, rowTmpFloatLocal, processLen);
        }
        // Output results
        pipe_barrier(PIPE_V);
        LocalTensor<ExpandXType> sumBufLocal = tokenBuf_.Get<ExpandXType>();
        Cast(sumBufLocal, sumFloatBufLocal, AscendC::RoundMode::CAST_RINT, processLen);
        SyncFunc<AscendC::HardEvent::V_MTE3>();
        DataCopy(expandOutGlobal_[tokenIndex * axisH_ + tokenOffset], sumBufLocal, processLen);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeCombineShmem<TemplateMC2TypeFunc>::Process()
{
    if constexpr (IsNeedReduceScatter) {
        ReduceScatterTrans();
    }
    BuffInit();
    SetWaitTpStatusAndDisPatch();
    AlltoAllBuffInit();
    SetStatus();
    WaitDispatch();
    LocalWindowCopy();
}
}  // namespace MoeDistributeCombineImpl
#endif  // MOE_COMBINE_SHMEM_H
