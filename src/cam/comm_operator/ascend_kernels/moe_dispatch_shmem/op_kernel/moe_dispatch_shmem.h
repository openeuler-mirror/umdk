/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shmem dispatch function device header file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create shmem dispatch header file in device part
 */

#ifndef MOE_DISPATCH_SHMEM_H
#define MOE_DISPATCH_SHMEM_H
#define OPT_RANK_OFFSET 512

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "moe_dispatch_shmem_tiling.h"
#include "shmem.h"

#include <cassert>
#include <type_traits>

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

namespace MoeDistributeDispatchImpl {
constexpr uint8_t BUFFER_NUM = 2;             // Multi-buffer
constexpr uint32_t STATE_OFFSET = 512;        // State space offset address
constexpr uint32_t STATE_SIZE = 1024 * 1024;  // 1M
constexpr uint32_t UB_ALIGN = 32;             // UB aligned to 32 bytes
constexpr uint32_t SELF_STATE_OFFSET = 256 * 1024;
constexpr uint8_t COMM_NUM = 2;  // Communication domain size
constexpr uint8_t COMM_EP_IDX = 0;
constexpr uint8_t COMM_TP_IDX = 1;
constexpr uint32_t GATHER_NUM_PER_TIME = 6;
// Hardcode this offset for now; if TP is fixed to 2, can directly read/write starting from the data offset
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint32_t TP_STATE_SIZE = 100 * 1024;
constexpr int CAM_MAX_RANK_SIZE = 384;                // Max NPU card count supported by CAM communication library
constexpr int64_t IPC_DATA_OFFSET = 2 * 1024 * 1024;  // First 2MB for flag bits, then 100MB for data storage

// Loop optimization related variables
using countType = uint8_t;  // Data type used for loop optimization
constexpr uint32_t LOOP_OPT_MAX_BS = 64;
constexpr uint32_t LOOP_OPT_MAX_MOE_RANK = 256;
constexpr uint32_t TOPK_ELEM_COUNT_PER_BLOCK = UB_ALIGN / sizeof(int32_t);
constexpr uint32_t TABLE_ELEM_COUNT_PER_BLOCK = UB_ALIGN / sizeof(countType);
constexpr uint32_t INT32_NUM_PER_BLOCK = UB_ALIGN / sizeof(int32_t);

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

#define TemplateMC2TypeClass                                                                               \
    typename XType, typename ExpandXOutType, bool StaticQuant, bool DynamicQuant, bool IsSmoothScaleExist, \
        bool IsNeedAllgather
#define TemplateMC2TypeFunc XType, ExpandXOutType, StaticQuant, DynamicQuant, IsSmoothScaleExist, IsNeedAllgather

template <TemplateMC2TypeClass>
class MoeDispatchShmem {
public:
    __aicore__ inline MoeDispatchShmem(){};
    __aicore__ inline void Init(GM_ADDR x, GM_ADDR expertIds, GM_ADDR scales, GM_ADDR expandXOut,
                                GM_ADDR dynamicScalesOut, GM_ADDR expandIdxOut, GM_ADDR expertTokenNumsOut,
                                GM_ADDR sendCountsOut, GM_ADDR tpSendCountsOut, GM_ADDR workspaceGM, TPipe *pipe,
                                const MoeDispatchShmemTilingData *tilingData);
    __aicore__ inline void Process();

private:
    __aicore__ inline void SendToSharedExpert();
    __aicore__ inline void SendToMoeExpert();
    __aicore__ inline void AlltoAllDispatch();
    __aicore__ inline void LocalWindowCopy();
    __aicore__ inline void QuantProcess(uint32_t expertIndex);
    __aicore__ inline void SetStatus();
    __aicore__ inline void WaitDispatch();
    __aicore__ inline void GetCumSum(LocalTensor<int32_t> &inLocal, LocalTensor<int32_t> &outLocal, int32_t totalCount);
    __aicore__ inline void CreateZeroTensor(LocalTensor<uint32_t> &outTensor);
    __aicore__ inline void AllGatherSetStatusAndWait();
    __aicore__ inline void ResetStatus();
    __aicore__ inline void QuantInit(GM_ADDR scales);
    __aicore__ inline void AllgatherProcessOut();
    __aicore__ inline void UpdateMultiMoeTokenNumsOut();
    __aicore__ inline void UpdateTokenNumsOut();
    __aicore__ inline GM_ADDR GetWindAddrByRankId(uint8_t ctxIdx, const int32_t rankId)
    {
        return (GM_ADDR)(gva_gm) + IPC_DATA_OFFSET + winDataSizeOffset_;
    }
    __aicore__ inline GM_ADDR GetWindStateAddrByRankId(uint8_t ctxIdx, const int32_t rankId)
    {
        return (GM_ADDR)(gva_gm) + dataState_ * WIN_STATE_OFFSET;
    }

    __aicore__ inline uint32_t MIN(uint32_t x, uint32_t y)
    {
        return (x < y) ? x : y;
    }
    TPipe *tpipe_{nullptr};
    GlobalTensor<XType> xGMTensor_;
    GlobalTensor<int32_t> expertIdsGMTensor_;
    GlobalTensor<float> scalesGMTensor_;
    GlobalTensor<ExpandXOutType> expandXOutGMTensor_;
    GlobalTensor<float> dynamicScalesOutGMTensor_;
    GlobalTensor<int64_t> expertTokenNumsOutGMTensor_;
    GlobalTensor<ExpandXOutType> windowInQuantTensor_;
    GlobalTensor<int32_t> windowInstatusTensor_;
    GlobalTensor<float> windowInstatusFp32Tensor_;
    GlobalTensor<ExpandXOutType> winTpGatherOutGMTensor_;
    GlobalTensor<float> fpWinTpGatherOutGMTensor_;
    GlobalTensor<int32_t> winTpEpCntGMTensor_;
    LocalTensor<ExpandXOutType> xTmpTensor_;
    LocalTensor<int32_t> tpTmpTensor_;
    LocalTensor<XType> xInTensor_;
    LocalTensor<ExpandXOutType> xOutTensor_;
    LocalTensor<float> xOutFp32Tensor_;
    LocalTensor<int32_t> expertCountTensor_;
    LocalTensor<int32_t> expertIdsTensor_;
    LocalTensor<int32_t> receivestatusTensor_;
    LocalTensor<float> rowMaxTensor_;
    LocalTensor<int32_t> statusTensor_;
    LocalTensor<float> statusFp32Tensor_;
    LocalTensor<float> smoothScalesTensor_;
    LocalTensor<float> dynamicScalesTensor_;
    TBuf<> dynamicScalesBuf_;
    TBuf<> expertCountBuf_;
    TBuf<> expertIdsBuf_;
    TBuf<> statusBuf_;
    TBuf<> gatherMaskOutBuf_;  // Gather mask output buffer
    TBuf<> getTotalBuf_;       // Compute totalCnt
    TBuf<> scalarBuf_;         // Auxiliary gather tensor definition
    TBuf<> rowMaxBuf_;
    TBuf<> receiveDataCastFloatBuf_;
    TBuf<> smoothScalesBuf_;
    // Used in non-quantization, also usable for receiving in quantization
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> xQueue_;
    TQue<QuePosition::VECIN, 1> xInQueue_;                         // Used in quantization, input before quantization
    TQue<QuePosition::VECOUT, 1> xOutQueue_;                       // Used in quantization, output after quantization
    GM_ADDR expandXOutGM_;
    GM_ADDR expandIdxOutGM_;
    GM_ADDR expertTokenNumsOutGM_;  // This output is not used
    GM_ADDR sendCountsOutGM_;
    GM_ADDR sendTpCountOutGM_;
    GM_ADDR statusSpaceGm_;
    GM_ADDR windowGM_;
    GM_ADDR tpWindowGM_;
    GM_ADDR tpStatusWindowGM_;
    GM_ADDR tpLocalWindowGM_;
    GM_ADDR tpLocalStatusWindowGM_;
    GlobalTensor<GM_ADDR> peerMemsAddrGm_;
    // Tiling guarantees data upper bounds, multiplication won't overflow, so uint32_t is used uniformly
    uint32_t axisBS_{0};
    uint32_t axisMaxBS_{0};
    uint32_t axisH_{0};
    uint32_t axisK_{0};
    uint32_t aivNum_{0};
    uint32_t sharedUsedAivNum_{0};
    uint32_t moeUsedAivNum_{0};
    uint32_t epWorldSize_{0};
    uint32_t tpWorldSize_{0};
    uint32_t epRankId_{0};
    uint32_t tpGatherRankId_{0};       // Gather peer ID
    uint32_t tpRankId_{0};             // Local card ID
    uint32_t aivId_{0};                // AIV ID
    uint32_t sharedExpertRankNum_{0};  // Shared expert card count
    uint32_t moeExpertRankNum_{0};     // MoE expert card count, equals worldSize_ - shared expert card count
    uint32_t moeExpertNumPerRank_{0};
    uint32_t moeExpertNum_{0};
    uint32_t totalExpertNum_{0};
    uint32_t bufferSizePerRank_{0};
    uint32_t recvWinBlockNum_{0};
    uint32_t hSize_{0};
    uint32_t hOutSize_{0};
    uint32_t hCommuSize_{0};
    uint32_t scaleParamPad_{0};
    uint32_t axisHCommu_{0};
    uint32_t startExpertId_;
    uint32_t endExpertId_;
    uint32_t sendExpertNum_;
    uint32_t localCopyCoreNum_;
    uint32_t totalCnt_;
    uint32_t lastCore_{0};
    uint32_t dataState_{0};
    uint32_t stateOffset_{0};
    uint64_t winDataSizeOffset_{0};
    uint64_t expertPerSizeOnWin_{0};
    uint64_t windyquantOffset_;
    bool isShareExpertRank_ = false;
    bool isQuant_ = false;
    float sumTarget_;
    uint64_t totalWinSize_{0};
    uint32_t gatherCount_{0};
    uint32_t expertTokenNumsType_{1};
    uint32_t preCnt_{0};

    GM_ADDR gva_gm;
    uint32_t halfWinSize_{0};

    DataCopyExtParams floatDataCopyParams_;
    DataCopyExtParams expandXCopyParams_;
    DataCopyExtParams xCopyParams_;
    DataCopyExtParams hCommuCopyOutParams_;

    // ------------- non contiguous copy params from shmem api ---------------
    non_contiguous_copy_param floatDataCopyParams_shmem;
    non_contiguous_copy_param expandXCopyParams_shmem;
    non_contiguous_copy_param xCopyParams_shmem;
    non_contiguous_copy_param hCommuCopyOutParams_shmem;

    // Variables used for loop optimization
    TBuf<> sendTableIdsBuf_;
    LocalTensor<countType> tableLocalTensor_;
    LocalTensor<countType> sendCountLocalTensor_;
    uint32_t moeExpertRankNumAligned_;
    uint32_t moeExpertRankNumInt16Aligned_;
    uint32_t tableElemCount_;
    bool enableAivOpt_{false};
};

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::Init(
    GM_ADDR x, GM_ADDR expertIds, GM_ADDR scales, GM_ADDR expandXOut, GM_ADDR dynamicScalesOut, GM_ADDR expandIdxOut,
    GM_ADDR expertTokenNumsOut, GM_ADDR sendCountsOut, GM_ADDR tpSendCountsOut, GM_ADDR workspaceGM, TPipe *pipe,
    const MoeDispatchShmemTilingData *tilingData)
{
    tpipe_ = pipe;
    aivId_ = GetBlockIdx();
    epRankId_ = tilingData->moeDistributeDispatchInfo.epRankId;
    GlobalTensor<int32_t> selfDataStatusTensor;
    GM_ADDR statusDataSpaceGm;
    gva_gm = (GM_ADDR)tilingData->moeDistributeDispatchInfo.shmemPtr;
    halfWinSize_ = tilingData->moeDistributeDispatchInfo.totalWinSize / 2;
    statusDataSpaceGm = (GM_ADDR)(gva_gm);
    selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfDataStatusTensor[aivId_ * UB_ALIGN]);
    // ================== Split into two memory blocks --> allows concurrent execution ===================
    dataState_ = selfDataStatusTensor(aivId_ * UB_ALIGN);

    if (dataState_ == 0) {
        selfDataStatusTensor(aivId_ * UB_ALIGN) = 1;
    } else {
        selfDataStatusTensor(aivId_ * UB_ALIGN) = 0;
    }
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfDataStatusTensor[aivId_ * UB_ALIGN]);

    pipe_barrier(PIPE_ALL);

    axisBS_ = tilingData->moeDistributeDispatchInfo.bs;
    axisH_ = tilingData->moeDistributeDispatchInfo.h;
    epWorldSize_ = tilingData->moeDistributeDispatchInfo.epWorldSize;
    axisMaxBS_ = tilingData->moeDistributeDispatchInfo.globalBs / epWorldSize_;
    moeExpertNum_ = tilingData->moeDistributeDispatchInfo.moeExpertNum;
    sharedExpertRankNum_ = tilingData->moeDistributeDispatchInfo.sharedExpertRankNum;
    expertTokenNumsType_ = tilingData->moeDistributeDispatchInfo.expertTokenNumsType;
    totalWinSize_ = tilingData->moeDistributeDispatchInfo.totalWinSize;
    moeExpertRankNum_ = epWorldSize_ - sharedExpertRankNum_;
    moeExpertNumPerRank_ = moeExpertNum_ / moeExpertRankNum_;
    expertPerSizeOnWin_ = axisMaxBS_ * axisH_ * sizeof(XType);
    // When dataState == 1, start address of the second GM block, i.e., the size of the first GM block
    winDataSizeOffset_ = dataState_ * epWorldSize_ * expertPerSizeOnWin_ * moeExpertNumPerRank_;
    tpRankId_ = tilingData->moeDistributeDispatchInfo.tpRankId;
    windowGM_ = GetWindAddrByRankId(COMM_EP_IDX, epRankId_);
    statusSpaceGm_ = GetWindStateAddrByRankId(COMM_EP_IDX, epRankId_);
    tpGatherRankId_ = tpRankId_ == 0 ? 1 : 0;
    axisK_ = tilingData->moeDistributeDispatchInfo.k;
    aivNum_ = tilingData->moeDistributeDispatchInfo.aivNum;
    tpWorldSize_ = tilingData->moeDistributeDispatchInfo.tpWorldSize;
    xGMTensor_.SetGlobalBuffer((__gm__ XType *)x);
    expertIdsGMTensor_.SetGlobalBuffer((__gm__ int32_t *)expertIds);
    expandXOutGMTensor_.SetGlobalBuffer((__gm__ ExpandXOutType *)expandXOut);
    dynamicScalesOutGMTensor_.SetGlobalBuffer((__gm__ float *)dynamicScalesOut);
    expertTokenNumsOutGMTensor_.SetGlobalBuffer((__gm__ int64_t *)expertTokenNumsOut);
    windowInQuantTensor_.SetGlobalBuffer((__gm__ ExpandXOutType *)windowGM_);
    windowInstatusTensor_.SetGlobalBuffer((__gm__ int32_t *)(statusSpaceGm_));
    windowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)(statusSpaceGm_));
    if constexpr (IsNeedAllgather) {
        tpLocalWindowGM_ = GetWindAddrByRankId(COMM_TP_IDX, tpRankId_);
        tpLocalStatusWindowGM_ = GetWindStateAddrByRankId(COMM_TP_IDX, tpRankId_);
        tpWindowGM_ = GetWindAddrByRankId(COMM_TP_IDX, tpGatherRankId_);
        tpStatusWindowGM_ = GetWindStateAddrByRankId(COMM_TP_IDX, tpGatherRankId_);
        winTpGatherOutGMTensor_.SetGlobalBuffer((__gm__ ExpandXOutType *)tpWindowGM_);
        fpWinTpGatherOutGMTensor_.SetGlobalBuffer((__gm__ float *)tpWindowGM_);
        winTpEpCntGMTensor_.SetGlobalBuffer((__gm__ int32_t *)(tpStatusWindowGM_ + TP_STATE_SIZE));
    }
    expandXOutGM_ = expandXOut;
    expandIdxOutGM_ = expandIdxOut;    // No GlobalTensor
    sendCountsOutGM_ = sendCountsOut;  // No GlobalTensor
    sendTpCountOutGM_ = tpSendCountsOut;
    isQuant_ = StaticQuant | DynamicQuant;

    // No alignment
    hSize_ = axisH_ * sizeof(XType);              // Actual size of input token
    // If quantized, actual size of output token after quantization for communication
    hOutSize_ = axisH_ * sizeof(ExpandXOutType);
    // Reserve 128B for quantization parameters, only 4B (fp32) actually used
    scaleParamPad_ = (isQuant_ ? 128 : 0);
    hCommuSize_ = hOutSize_ + scaleParamPad_;
    axisHCommu_ = hCommuSize_ / sizeof(ExpandXOutType);  // Output token dimension

    if (sharedExpertRankNum_ != 0) {                 // Only later cards need to send data to shared experts
        sharedUsedAivNum_ = aivNum_ / (axisK_ + 1);  // Equal division, rounded
        if (sharedUsedAivNum_ == 0) {
            sharedUsedAivNum_ = 1;
        }
    }
    moeUsedAivNum_ = aivNum_ - sharedUsedAivNum_;
    bufferSizePerRank_ = 32 * hSize_;
    // recvWinBlockNum >= expertNum
    recvWinBlockNum_ = epWorldSize_ * moeExpertNumPerRank_;
    isShareExpertRank_ = (epRankId_ < sharedExpertRankNum_) ? true : false;
    windyquantOffset_ = epWorldSize_ * axisMaxBS_ * hOutSize_;
    GlobalTensor<int32_t> selfStatusTensor;
    selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusSpaceGm_ + SELF_STATE_OFFSET));
    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfStatusTensor[aivId_ * UB_ALIGN]);

    // AIV core state synchronization
    int32_t state = selfStatusTensor(aivId_ * UB_ALIGN);
    stateOffset_ = (recvWinBlockNum_ > 512) ? (STATE_OFFSET / 2) : STATE_OFFSET;
    // expertNum * 32B ----> Each expert has one status,
    tpipe_->InitBuffer(statusBuf_, recvWinBlockNum_ * UB_ALIGN);
    // Stores sent data count and flag, also used for computing window offsets
    statusTensor_ = statusBuf_.Get<int32_t>();
    Duplicate<int32_t>(statusTensor_, 0, recvWinBlockNum_ * 8);  // 8 = UB_ALIGN / sizeof(int32_t)

    // If state is 0, set selfStatusTensor for this core to 1, and statusTensor all to 1; otherwise set to 0
    if (state == 0) {
        sumTarget_ = (float)1.0;
        selfStatusTensor(aivId_ * UB_ALIGN) = 0x3F800000;
        // Operate 256 bytes at once (64 int32_t), set the first of every 8 values to 0x3F800000
        uint64_t mask[2] = {0x101010101010101, 0};
        Duplicate<int32_t>(statusTensor_, 0x3F800000, mask, recvWinBlockNum_ / 8, 1, 8);  // 0x3F800000 is float 1
    } else {
        sumTarget_ = 0.0;
        selfStatusTensor(aivId_ * UB_ALIGN) = 0;
    }

    DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
        selfStatusTensor[aivId_ * UB_ALIGN]);
    tpipe_->InitBuffer(xQueue_, BUFFER_NUM, hCommuSize_);  // 14k *2
    if (isQuant_) {
        QuantInit(scales);
    }

    uint32_t expertIdsSize = axisBS_ * axisK_ * sizeof(int32_t);  // Constrain 32-byte alignment
    tpipe_->InitBuffer(expertIdsBuf_, expertIdsSize);             // BS * K * 4
    expertIdsTensor_ = expertIdsBuf_.Get<int32_t>();
    tpipe_->InitBuffer(expertCountBuf_, expertIdsSize);  // BS * K * 4
    expertCountTensor_ = expertCountBuf_.Get<int32_t>();
    tpipe_->InitBuffer(gatherMaskOutBuf_, recvWinBlockNum_ * sizeof(float));  // worldSize * 4B
    // worldSize * per-card expert count * 4B
    tpipe_->InitBuffer(getTotalBuf_,
                       epWorldSize_ * moeExpertNumPerRank_ * sizeof(int32_t));
    tpipe_->InitBuffer(scalarBuf_, UB_ALIGN * 2);                               // 72B

    moeExpertRankNumAligned_ = Ceil(moeExpertNum_, TABLE_ELEM_COUNT_PER_BLOCK) * TABLE_ELEM_COUNT_PER_BLOCK;
    if (axisBS_ <= LOOP_OPT_MAX_BS && moeExpertRankNumAligned_ <= LOOP_OPT_MAX_MOE_RANK &&
        axisK_ % TOPK_ELEM_COUNT_PER_BLOCK == 0) {
        // UB space limits BS <= 64 and routing expert count <= 256; alignment requires axisK_ to be a multiple of 8
        enableAivOpt_ = true;
        moeExpertRankNumInt16Aligned_ = moeExpertRankNumAligned_ / 2;  // Pack 2 uint8_t into each int16_t
        tableElemCount_ = (axisBS_ + 1) * moeExpertRankNumAligned_;    // Extra row added (first row is all zeros)

        tpipe_->InitBuffer(sendTableIdsBuf_, tableElemCount_ * sizeof(countType));
        tableLocalTensor_ = sendTableIdsBuf_.Get<countType>();
        // After computation, the last row is the count
        sendCountLocalTensor_ = tableLocalTensor_[axisBS_ * moeExpertRankNumAligned_];
    }

    floatDataCopyParams_shmem = {1U, sizeof(float), 0U, 0U};
    xCopyParams_shmem = {1U, static_cast<uint32_t>(axisH_ * sizeof(XType)), 0U, 0U};
    hCommuCopyOutParams_shmem = {1U, static_cast<uint32_t>(axisHCommu_), 0U, 0U};
    expandXCopyParams_shmem = {1U, static_cast<uint32_t>(axisH_), 0U, 0U};
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::QuantInit(GM_ADDR scales)
{
    tpipe_->InitBuffer(xInQueue_, BUFFER_NUM, hSize_);        // 14K *2
    tpipe_->InitBuffer(xOutQueue_, BUFFER_NUM, hCommuSize_);  // 7K *2
    scalesGMTensor_.SetGlobalBuffer((__gm__ float *)scales);
    uint32_t hFp32Size = axisH_ * sizeof(float);
    if constexpr (DynamicQuant) {
        tpipe_->InitBuffer(rowMaxBuf_, UB_ALIGN);  // 32B
    }
    tpipe_->InitBuffer(receiveDataCastFloatBuf_, 1 * hFp32Size);   // 28KB
    tpipe_->InitBuffer(smoothScalesBuf_, axisH_ * sizeof(float));  // 28KB
    smoothScalesTensor_ = smoothScalesBuf_.Get<float>();
    tpipe_->InitBuffer(dynamicScalesBuf_, axisBS_ * sizeof(float));  // 32 * 4
    dynamicScalesTensor_ = dynamicScalesBuf_.Get<float>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::SendToSharedExpert()
{
    uint32_t sendTokenNum = axisBS_ / sharedUsedAivNum_;       // Token count each AIV needs to send
    uint32_t remainderTokenNum = axisBS_ % sharedUsedAivNum_;  // Remainder
    // Since later cores act as shared expert senders, we need to convert
    uint32_t newAivId = aivId_ - moeUsedAivNum_;
    // Distribute tokens across cores
    uint32_t startTokenId = sendTokenNum * newAivId;  // Starting rank ID for each AIV when sending
    if (newAivId < remainderTokenNum) {               // The first remainderRankNum AIVs send one extra card of data
        sendTokenNum += 1;
        startTokenId += newAivId;
    } else {
        startTokenId += remainderTokenNum;
    }
    if (startTokenId >= axisBS_) {
        return;
    }
    uint32_t endTokenId = startTokenId + sendTokenNum;
    for (uint32_t tokenShuffleIndex = 0; tokenShuffleIndex < sendTokenNum; ++tokenShuffleIndex) {
        uint32_t tokenIndex = startTokenId + ((tokenShuffleIndex + epRankId_) % sendTokenNum);

        uint32_t temp = (epRankId_ * axisBS_) / sharedExpertRankNum_;  // sharedExpertRankNum_ >= sharedExpertNum_
        // Target Shared Expert Rank --> Evenly distribute within shared experts
        uint32_t moeOnShareRank = Ceil((tokenIndex + 1 + temp) * sharedExpertRankNum_, axisBS_) - 1 - epRankId_;
        // How many tokens have already been sent to this shared expert --> Derived from load-balancing formula
        uint32_t preCnt =
            (moeOnShareRank + epRankId_) * axisBS_ / sharedExpertRankNum_ - epRankId_ * axisBS_ / sharedExpertRankNum_;

        // GetWind returns the peer rank winGW, the following offset is reserved for epRankId
        GlobalTensor<ExpandXOutType> dstWinGMTensor;
        dstWinGMTensor.SetGlobalBuffer((__gm__ ExpandXOutType *)(GetWindAddrByRankId(COMM_EP_IDX, moeOnShareRank) +
                                                                 expertPerSizeOnWin_ * epRankId_));
        if constexpr (DynamicQuant || StaticQuant) {
            // Use EnQue/Deque for synchronization
            xInTensor_ = xInQueue_.AllocTensor<XType>();
            // GM --> UB
            DataCopy(xInTensor_, xGMTensor_[tokenIndex * axisH_], axisH_);  // Alignment constraint
            xInQueue_.EnQue(xInTensor_);
            xInTensor_ = xInQueue_.DeQue<XType>();

            xOutTensor_ = xOutQueue_.AllocTensor<ExpandXOutType>();
            // Should pass an expertIdx; Cast is done internally
            QuantProcess(0);
            xOutQueue_.EnQue(xOutTensor_);
            xOutTensor_ = xOutQueue_.DeQue<ExpandXOutType>();

            if (isShareExpertRank_) {
                xOutFp32Tensor_ = xOutTensor_.template ReinterpretCast<float>();
                DataCopyExtParams dataCopyParamsFloat = {1U, sizeof(float), 0U, 0U, 0U};
                DataCopyPad(dynamicScalesOutGMTensor_[tokenIndex], xOutFp32Tensor_[axisH_ / sizeof(float)],
                            dataCopyParamsFloat);
                if constexpr (IsNeedAllgather) {
                    // Alignment constraint
                    DataCopy(winTpGatherOutGMTensor_[tokenIndex * axisHCommu_], xOutTensor_, axisHCommu_);
                }
                DataCopy(expandXOutGMTensor_[tokenIndex * axisH_], xOutTensor_, axisH_);  // Alignment constraint
            } else {
                aclshmem_int8_put_nbi(dstWinGMTensor[(tokenIndex - preCnt) * axisHCommu_], xOutTensor_,
                                       hCommuCopyOutParams_shmem, moeOnShareRank);
            }
            xOutQueue_.FreeTensor(xOutTensor_);
        } else {
            xTmpTensor_ = xQueue_.AllocTensor<ExpandXOutType>();
            DataCopy(xTmpTensor_, xGMTensor_[tokenIndex * axisH_], axisH_);  // Alignment constraint
            xQueue_.EnQue(xTmpTensor_);
            xTmpTensor_ = xQueue_.DeQue<ExpandXOutType>();
            // If self --> direct output
            if (isShareExpertRank_) {
                if constexpr (IsNeedAllgather) {
                    DataCopy(winTpGatherOutGMTensor_[tokenIndex * axisHCommu_], xTmpTensor_, axisHCommu_);
                }
                DataCopy(expandXOutGMTensor_[tokenIndex * axisHCommu_], xTmpTensor_, axisHCommu_);
            } else {
                SHMEM_PUT_BY_DTYPE(ExpandXOutType, dstWinGMTensor[(tokenIndex - preCnt) * axisHCommu_], xTmpTensor_,
                                   hCommuCopyOutParams_shmem, moeOnShareRank);
            }
            xQueue_.FreeTensor<ExpandXOutType>(xTmpTensor_);
        }
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::SendToMoeExpert()
{
    uint32_t expertIdsCnt = axisBS_ * axisK_;
    uint32_t sendTokenNum = expertIdsCnt / moeUsedAivNum_;       // Token count each AIV needs to send
    uint32_t remainderTokenNum = expertIdsCnt % moeUsedAivNum_;  // Remainder
    uint32_t startTokenId = sendTokenNum * aivId_;               // Starting rank ID for each AIV when sending
    if (aivId_ < remainderTokenNum) {  // The first remainderRankNum AIVs send one extra card of data
        sendTokenNum += 1;
        startTokenId += aivId_;
    } else {
        startTokenId += remainderTokenNum;
    }
    uint32_t endTokenId = startTokenId + sendTokenNum;
    GlobalTensor<ExpandXOutType> dstWinGMTensor;
    for (uint32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
        uint32_t dstExpertId = expertIdsTensor_(tokenIndex);
        uint32_t tempRankId = dstExpertId / moeExpertNumPerRank_ + sharedExpertRankNum_;
        // Peer GM + EP rank offset + Intra-rank offset + Token offset
        GM_ADDR rankGM = (__gm__ uint8_t *)(GetWindAddrByRankId(COMM_EP_IDX, tempRankId) +
                                            (expertPerSizeOnWin_ *
                                             (epRankId_ * moeExpertNumPerRank_ + dstExpertId % moeExpertNumPerRank_)) +
                                            hCommuSize_ * expertCountTensor_(tokenIndex));  // Compute address offset
        dstWinGMTensor.SetGlobalBuffer((__gm__ ExpandXOutType *)rankGM);
        if constexpr (DynamicQuant || StaticQuant) {
            xInTensor_ = xInQueue_.AllocTensor<XType>();
            DataCopy(xInTensor_, xGMTensor_[tokenIndex / axisK_ * axisH_], axisH_);  // Alignment constraint
            xInQueue_.EnQue(xInTensor_);
            xInTensor_ = xInQueue_.DeQue<XType>();
            xOutTensor_ = xOutQueue_.AllocTensor<ExpandXOutType>();
            uint32_t expertIndex = sharedExpertRankNum_ != 0 ? (dstExpertId + 1) : dstExpertId;
            QuantProcess(expertIndex);
            xOutQueue_.EnQue(xOutTensor_);

            xOutTensor_ = xOutQueue_.DeQue<ExpandXOutType>();
            aclshmem_int8_put_nbi(dstWinGMTensor, xOutTensor_, hCommuCopyOutParams_shmem, tempRankId);
            xOutQueue_.FreeTensor(xOutTensor_);
        } else {
            xTmpTensor_ = xQueue_.AllocTensor<ExpandXOutType>();
            DataCopy(xTmpTensor_, xGMTensor_[tokenIndex / axisK_ * axisH_], axisH_);  // Alignment constraint
            xQueue_.EnQue(xTmpTensor_);
            xTmpTensor_ = xQueue_.DeQue<ExpandXOutType>();
            SHMEM_PUT_BY_DTYPE(ExpandXOutType, dstWinGMTensor, xTmpTensor_, hCommuCopyOutParams_shmem, tempRankId);
            xQueue_.FreeTensor<ExpandXOutType>(xTmpTensor_);
        }
    }

    // Only the last core needs to write results when loop optimization is disabled
    if (aivId_ == (moeUsedAivNum_ - 1) && (!enableAivOpt_)) {
        GlobalTensor<int32_t> expandIdxGMTensor;
        expandIdxGMTensor.SetGlobalBuffer((__gm__ int32_t *)expandIdxOutGM_);
        DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(expertIdsCnt * sizeof(uint32_t)), 0U, 0U, 0U};
        DataCopyPad(expandIdxGMTensor, expertCountTensor_, expertIdsCntParams);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::AlltoAllDispatch()
{
    uint32_t expertIdsCnt = axisBS_ * axisK_;
    DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(expertIdsCnt * sizeof(uint32_t)), 0U, 0U, 0U};
    DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
    DataCopyPad(expertIdsTensor_, expertIdsGMTensor_, expertIdsCntParams, copyPadParams);
    AscendC::TQueSync<PIPE_MTE2, PIPE_S> expertCntLocalSync;
    expertCntLocalSync.SetFlag(0);
    expertCntLocalSync.WaitFlag(0);
    // Optimization section --->
    if (enableAivOpt_) {
        LocalTensor<int16_t> tableInt16LocalTensor_ = tableLocalTensor_.template ReinterpretCast<int16_t>();
        Duplicate(tableInt16LocalTensor_, (int16_t)0, tableElemCount_ / 2);  // Zero out
        SyncFunc<AscendC::HardEvent::V_S>();
        // Fill the table. Default is 0, set to 1 for sent
        for (int tokenIndex = 0; tokenIndex < expertIdsCnt; ++tokenIndex) {
            int expertId = expertIdsTensor_(tokenIndex);
            tableLocalTensor_((tokenIndex / axisK_ + 1) * moeExpertRankNumAligned_ + expertId) = 1;
        }
        pipe_barrier(PIPE_ALL);
        // Distribute across cores, determine tokens per core
        uint32_t sendTokenNum = expertIdsCnt / moeUsedAivNum_;
        uint32_t remainderTokenNum = expertIdsCnt % moeUsedAivNum_;
        uint32_t startTokenId = sendTokenNum * aivId_;
        if (aivId_ < remainderTokenNum) {
            sendTokenNum += 1;
            startTokenId += aivId_;
        } else {
            startTokenId += remainderTokenNum;
        }
        uint32_t endTokenId = startTokenId + sendTokenNum;
        uint32_t startTokenRow = startTokenId / axisK_;
        uint32_t endTokenRow = (endTokenId + axisK_ - 1) / axisK_;

        for (int row = 1; row <= axisBS_; ++row) {
            Add(tableInt16LocalTensor_[row * moeExpertRankNumInt16Aligned_],
                tableInt16LocalTensor_[row * moeExpertRankNumInt16Aligned_],
                tableInt16LocalTensor_[(row - 1) * moeExpertRankNumInt16Aligned_], moeExpertRankNumInt16Aligned_);
            pipe_barrier(PIPE_V);
        }
        // After computation, row i is the remote offset for token at index i+1, last row is total count
        GlobalTensor<int32_t> expandIdxGMTensor;
        if (aivId_ < moeUsedAivNum_) {
            SyncFunc<AscendC::HardEvent::V_S>();
            for (int row = startTokenRow; row < endTokenRow; ++row) {
                for (int expertIndex = 0; expertIndex < axisK_; ++expertIndex) {
                    int32_t expertId = expertIdsTensor_(row * axisK_ + expertIndex);
                    expertCountTensor_(row * axisK_ + expertIndex) =
                        (int32_t)tableLocalTensor_(row * moeExpertRankNumAligned_ + expertId);
                }
                SyncFunc<AscendC::HardEvent::S_MTE3>();
                expandIdxGMTensor.SetGlobalBuffer(
                    (__gm__ int32_t *)(expandIdxOutGM_ + row * axisK_ * sizeof(uint32_t)));
                DataCopy(expandIdxGMTensor, expertCountTensor_[row * axisK_], axisK_);
            }
        }

        // Distribute across cores, determine ranks for each core to set status
        uint32_t preTotalExpertNum = sharedExpertRankNum_ + moeExpertNum_;
        uint32_t preSendExpertNum = preTotalExpertNum / aivNum_;
        uint32_t preRemainderRankNum = preTotalExpertNum % aivNum_;
        uint32_t preStartExpertId = preSendExpertNum * aivId_;
        if (aivId_ < preRemainderRankNum) {
            preSendExpertNum += 1;
            preStartExpertId += aivId_;
        } else {
            preStartExpertId += preRemainderRankNum;
        }
        uint32_t preEndExpertId = preStartExpertId + preSendExpertNum;
        preStartExpertId = preStartExpertId >= sharedExpertRankNum_ ? preStartExpertId : sharedExpertRankNum_;
        SyncFunc<AscendC::HardEvent::V_S>();
        for (int32_t tmpExpertId = preStartExpertId; tmpExpertId < preEndExpertId; ++tmpExpertId) {
            statusTensor_(tmpExpertId * INT32_NUM_PER_BLOCK + 1) =
                (int32_t)sendCountLocalTensor_(tmpExpertId - sharedExpertRankNum_);
        }
    } else {
        for (uint32_t tokenIndex = 0; tokenIndex < expertIdsCnt; ++tokenIndex) {
            // Bounds check: (expertId >= epWorldSize_) || (expertId < sharedExpertRankNum_)
            // Compute MoE ExpertId (shared experts occupy the first few ranks)
            int32_t expertId = expertIdsTensor_(tokenIndex) + sharedExpertRankNum_;
            // expertCountTensor is BS * K * 4(int32)
            // --> Each tokenIndex position corresponds to how many tokens
            // this token is for the current expert, so ExpandIdx is counted from the sender's perspective
            expertCountTensor_(tokenIndex) = statusTensor_(expertId * INT32_NUM_PER_BLOCK + 1);
            // Expert status count + 1 --> statusTensor stores token count received by MoE expert
            statusTensor_(expertId * INT32_NUM_PER_BLOCK + 1)++;
        }
    }
    if (!isShareExpertRank_) {
        for (uint32_t curSatatusExpId = 0; curSatatusExpId < sharedExpertRankNum_; ++curSatatusExpId) {
            int32_t curExpertCnt = (curSatatusExpId + 1 + epRankId_) * axisBS_ / sharedExpertRankNum_ -
                                   (curSatatusExpId + epRankId_) * axisBS_ / sharedExpertRankNum_;
            statusTensor_((curSatatusExpId)*INT32_NUM_PER_BLOCK + 1) = curExpertCnt;
        }
    }
    if ((sharedExpertRankNum_ != 0) && (aivId_ >= moeUsedAivNum_)) {  // Later cores send data to shared experts
        SendToSharedExpert();
        return;
    }
    SendToMoeExpert();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::SetStatus()
{
    pipe_barrier(PIPE_ALL);
    SyncAll<true>();
    totalExpertNum_ = sharedExpertRankNum_ + moeExpertNum_;
    sendExpertNum_ = totalExpertNum_ / aivNum_;  // Expert count each AIV needs to process
    uint32_t remainderRankNum = totalExpertNum_ % aivNum_;
    startExpertId_ = sendExpertNum_ * aivId_;  // + sharedExpertRankNum_, starting rank ID for each AIV when sending
    if (aivId_ < remainderRankNum) {           // The first remainderRankNum AIVs send one extra card of data
        sendExpertNum_ += 1;
        startExpertId_ += aivId_;
    } else {
        startExpertId_ += remainderRankNum;
    }
    endExpertId_ = startExpertId_ + sendExpertNum_;
    if (startExpertId_ >= totalExpertNum_) {  // Redundant cores return
        return;
    }

    GlobalTensor<int32_t> rankGMTensor;
    uint32_t offset = stateOffset_ * epRankId_;
    for (uint32_t rankIndex = startExpertId_; rankIndex < endExpertId_; ++rankIndex) {
        uint32_t dstRankId = rankIndex;
        if (moeExpertNumPerRank_ > 1 && (rankIndex >= sharedExpertRankNum_)) {
            dstRankId = ((rankIndex - sharedExpertRankNum_) / moeExpertNumPerRank_ + sharedExpertRankNum_);
            offset =
                (epRankId_ + (rankIndex - sharedExpertRankNum_) % moeExpertNumPerRank_ * epWorldSize_) * stateOffset_;
        }
        // Compute address offset
        GM_ADDR rankGM = (__gm__ uint8_t *)(GetWindStateAddrByRankId(COMM_EP_IDX, dstRankId) + offset);
        rankGMTensor.SetGlobalBuffer((__gm__ int32_t *)rankGM);
        // statusTensor --> current rank's
        // ---> rankIndex * 8 for alignment, one rankIndex int -- size 4
        aclshmem_int32_put_nbi(rankGMTensor, statusTensor_[rankIndex * 8], 8UL, dstRankId);
    }
    SyncFunc<AscendC::HardEvent::MTE3_MTE2>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::QuantProcess(uint32_t expertIndex)
{
    float dynamicScale = 0.0;
    LocalTensor<float> floatLocalTemp;
    floatLocalTemp = receiveDataCastFloatBuf_.Get<float>();
    Cast(floatLocalTemp, xInTensor_, RoundMode::CAST_NONE, axisH_);
    xInQueue_.FreeTensor<XType>(xInTensor_);
    pipe_barrier(PIPE_V);
    if constexpr (IsSmoothScaleExist) {
        if constexpr (DynamicQuant) {
            SyncFunc<AscendC::HardEvent::V_MTE2>();  // UB reuse, loop synchronization
        }
        DataCopy(smoothScalesTensor_, scalesGMTensor_[expertIndex * axisH_], axisH_);
        SyncFunc<AscendC::HardEvent::MTE2_V>();
        Mul(floatLocalTemp, floatLocalTemp, smoothScalesTensor_, axisH_);
        pipe_barrier(PIPE_V);
    }
    if constexpr (DynamicQuant) {
        LocalTensor<float> floatLocalAbsTemp = smoothScalesBuf_.Get<float>();
        rowMaxTensor_ = rowMaxBuf_.Get<float>();
        Abs(floatLocalAbsTemp, floatLocalTemp, axisH_);
        pipe_barrier(PIPE_V);
        ReduceMax(rowMaxTensor_, floatLocalAbsTemp, floatLocalAbsTemp, axisH_, false);
        SyncFunc<AscendC::HardEvent::V_S>();
        dynamicScale = float(127.0) / rowMaxTensor_.GetValue(0);
        SyncFunc<AscendC::HardEvent::S_V>();
        Muls(floatLocalTemp, floatLocalTemp, dynamicScale, axisH_);
        pipe_barrier(PIPE_V);
    }
    LocalTensor<half> halfLocalTemp = floatLocalTemp.ReinterpretCast<half>();
    LocalTensor<int32_t> int32LocalTemp = floatLocalTemp.ReinterpretCast<int32_t>();
    Cast(int32LocalTemp, floatLocalTemp, RoundMode::CAST_RINT, axisH_);
    pipe_barrier(PIPE_V);
    SetDeqScale((half)1.000000e+00f);
    PipeBarrier<PIPE_V>();
    Cast(halfLocalTemp, int32LocalTemp, RoundMode::CAST_ROUND, axisH_);
    pipe_barrier(PIPE_V);
    Cast(xOutTensor_, halfLocalTemp, RoundMode::CAST_TRUNC, axisH_);
    floatLocalTemp = xOutTensor_.template ReinterpretCast<float>();
    floatLocalTemp.SetValue(axisH_ / sizeof(float), float(1.0) / dynamicScale);  // int8 -> float32
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::WaitDispatch()
{
    uint32_t rscvStatusNum = isShareExpertRank_ ? epWorldSize_ : recvWinBlockNum_;
    uint32_t recStatusNumPerCore = rscvStatusNum / aivNum_;  // Expert count each AIV needs to process
    uint32_t remainderRankNum = rscvStatusNum % aivNum_;
    // + sharedExpertRankNum_, starting rank ID for each AIV when sending
    uint32_t startStatusIndex = recStatusNumPerCore * aivId_;
    // The first remainderRankNum AIVs send one extra card of data
    if (aivId_ < remainderRankNum) {
        recStatusNumPerCore += 1;
        startStatusIndex += aivId_;
    } else {
        startStatusIndex += remainderRankNum;
    }
    if (startStatusIndex >= rscvStatusNum) {
        SyncAll<true>();
        return;
    }
    LocalTensor<float> gatherMaskOutTensor = gatherMaskOutBuf_.Get<float>();
    LocalTensor<uint32_t> gatherTmpTensor = scalarBuf_.GetWithOffset<uint32_t>(UB_ALIGN / sizeof(uint32_t), 0);
    gatherTmpTensor.SetValue(0, 1);
    LocalTensor<float> statusSumOutTensor = scalarBuf_.GetWithOffset<float>(UB_ALIGN / sizeof(float), UB_ALIGN);
    statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();
    uint32_t mask = 1;  // GatherMask + sum related parameters
    uint64_t rsvdCnt = 0;
    SumParams sumParams{1, recStatusNumPerCore, recStatusNumPerCore};
    float sumOfFlag = static_cast<float>(-1.0);
    float minTarget = (sumTarget_ * recStatusNumPerCore) - (float)0.5;
    float maxTarget = (sumTarget_ * recStatusNumPerCore) + (float)0.5;
    DataCopyParams intriParams{static_cast<uint16_t>(recStatusNumPerCore), 1,
                               static_cast<uint16_t>((recvWinBlockNum_ > 512) ? 7 : 15), 0};  // srcStride is 15 blocks
    SyncFunc<AscendC::HardEvent::S_V>();
    while ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
        DataCopy(statusFp32Tensor_, windowInstatusFp32Tensor_[startStatusIndex * stateOffset_ / sizeof(float)],
                 intriParams);
        SyncFunc<AscendC::HardEvent::MTE2_V>();
        GatherMask(gatherMaskOutTensor, statusFp32Tensor_, gatherTmpTensor, true, mask,
                   {1, (uint16_t)recStatusNumPerCore, 1, 0}, rsvdCnt);
        pipe_barrier(PIPE_V);
        Sum(statusSumOutTensor, gatherMaskOutTensor, sumParams);
        SyncFunc<AscendC::HardEvent::V_S>();
        sumOfFlag = statusSumOutTensor.GetValue(0);
    }
    SyncAll<true>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::GetCumSum(LocalTensor<int32_t> &inLocal,
                                                                                  LocalTensor<int32_t> &outLocal,
                                                                                  int32_t totalCount)
{
    statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();
    DataCopyParams intriParams{static_cast<uint16_t>(recvWinBlockNum_), 1,
                               static_cast<uint16_t>((recvWinBlockNum_ > 512) ? 7 : 15), 0};  // srcStride is 15 blocks
    DataCopy(statusTensor_, windowInstatusTensor_, intriParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();
    if (isShareExpertRank_) {
        for (uint32_t curSatatusExpId = 0; curSatatusExpId < sharedExpertRankNum_; ++curSatatusExpId) {
            int32_t curExpertCnt = curSatatusExpId == epRankId_ ? axisBS_ : 0;
            statusTensor_((curSatatusExpId)*INT32_NUM_PER_BLOCK + 1) = curExpertCnt;
        }
    }
    outLocal = gatherMaskOutBuf_.Get<int32_t>();  // Memory reuse
    LocalTensor<float> getTotalLocal = getTotalBuf_.Get<float>();
    // Gather mask combined
    TBuf<> gatherTmpBuf;
    TBuf<> workLocalBuf;
    tpipe_->InitBuffer(gatherTmpBuf, sizeof(uint32_t) * recvWinBlockNum_ / 4);
    LocalTensor<uint32_t> gatherTmpTensor = gatherTmpBuf.Get<uint32_t>();
    Duplicate(gatherTmpTensor, (uint32_t)33686018, recvWinBlockNum_ / 4);  // 0000 0010 0000 0010 0000 0010 0000 0010
    PipeBarrier<PIPE_V>();
    uint32_t mask = recvWinBlockNum_ * 8;  // 512 / 32
    uint64_t rsvdCnt = 0;
    GatherMask(outLocal, inLocal, gatherTmpTensor, true, mask, {1, 1, 0, 0}, rsvdCnt);
    // Cumsum accumulation, column-wise addition
    int typeSize = sizeof(int32_t);
    int32_t elementsPerBlock = 32 / typeSize;
    int32_t elementsPerRepeat = 256 / typeSize;
    int32_t firstMaxRepeat = epWorldSize_;
    int32_t iter1OutputCount = firstMaxRepeat;
    int32_t iter1AlignEnd = ((iter1OutputCount + elementsPerBlock - 1) / elementsPerBlock) * elementsPerBlock;
    int32_t finalWorkLocalNeedSize = iter1AlignEnd;
    tpipe_->InitBuffer(workLocalBuf, finalWorkLocalNeedSize * sizeof(int32_t));
    LocalTensor<float> workLocalTensor = workLocalBuf.Get<float>();
    LocalTensor<float> tmpFp32 = outLocal.ReinterpretCast<float>();
    PipeBarrier<PIPE_V>();
    ReduceSum<float>(getTotalLocal, tmpFp32, workLocalTensor, epWorldSize_);
    totalCnt_ = getTotalLocal.ReinterpretCast<int32_t>().GetValue(0);
    PipeBarrier<PIPE_V>();
    ReduceSum<float>(tmpFp32, tmpFp32, workLocalTensor, totalCount);
    PipeBarrier<PIPE_V>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void
MoeDispatchShmem<TemplateMC2TypeFunc>::CreateZeroTensor(LocalTensor<uint32_t> &outLocal)
{
    TBuf<> outBuf;
    tpipe_->InitBuffer(outBuf, UB_ALIGN);
    outLocal = outBuf.Get<uint32_t>();
    for (uint32_t i = 0; i < 2; i++) {
        outLocal.SetValue(i, 0);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::LocalWindowCopy()
{
    uint32_t totalMoeExpert = 0;
    LocalTensor<int32_t> outCountLocal;
    if (isShareExpertRank_) {
        totalMoeExpert = epWorldSize_;
    } else {
        totalMoeExpert = epWorldSize_ * moeExpertNumPerRank_;
    }
    sendExpertNum_ = totalMoeExpert / aivNum_;  // Expert count each AIV needs to process
    uint32_t remainderRankNum = totalMoeExpert % aivNum_;
    startExpertId_ = sendExpertNum_ * aivId_;  // + sharedExpertRankNum_, starting rank ID for each AIV when sending
    if (aivId_ < remainderRankNum) {           // The first remainderRankNum AIVs send one extra card of data
        sendExpertNum_ += 1;
        startExpertId_ += aivId_;
    } else {
        startExpertId_ += remainderRankNum;
    }
    endExpertId_ = startExpertId_ + sendExpertNum_;
    if (startExpertId_ >= totalMoeExpert) {  // Redundant cores return
        return;
    }
    GetCumSum(statusTensor_, outCountLocal, startExpertId_ + 1);
    uint32_t index = 0;
    uint32_t beginIdx = 0;
    DataCopyExtParams dataCopyParamsFloat = {1U, sizeof(float), 0U, 0U, 0U};
    for (uint32_t index = startExpertId_; index < endExpertId_; index++) {
        uint32_t i = index - startExpertId_;
        if (i > 0) {
            outCountLocal.SetValue(i, outCountLocal.GetValue(i - 1) + outCountLocal.GetValue(index));
        }
        uint32_t count = statusTensor_.GetValue(index * INT32_NUM_PER_BLOCK + 1);
        beginIdx = outCountLocal.GetValue(i) - count;
        if constexpr (IsNeedAllgather) {
            gatherCount_ += count;
        }
        if (i == 0) {
            preCnt_ = beginIdx;
        }
        if (isShareExpertRank_) {
            // Shared experts have local card data at the front; only count epRecvCnt, no need to copy out
            if (index < sharedExpertRankNum_) {
                beginIdx += count;
                continue;
            }
        }
        uint32_t winOffset = index;
        if (!isShareExpertRank_) {
            if (moeExpertNumPerRank_ > 1) {
                // Convert to data region layout offset
                winOffset =
                    index % epWorldSize_ * moeExpertNumPerRank_ + index / epWorldSize_;
            }
        }
        // This wAddr is on the communication domain
        GM_ADDR wAddr = (__gm__ uint8_t *)(windowGM_) + winOffset * expertPerSizeOnWin_;
        GlobalTensor<ExpandXOutType> tokGlobal;
        GlobalTensor<ExpandXOutType> expandXOutGlobal;
        for (uint32_t j = 0; j < count; j++) {
            tokGlobal.SetGlobalBuffer((__gm__ ExpandXOutType *)(wAddr + j * hCommuSize_));
            xTmpTensor_ = xQueue_.AllocTensor<ExpandXOutType>();
            DataCopy(xTmpTensor_, tokGlobal, axisHCommu_);
            xQueue_.EnQue(xTmpTensor_);
            xTmpTensor_ = xQueue_.DeQue<ExpandXOutType>();
            if constexpr (DynamicQuant || StaticQuant) {
                pipe_barrier(PIPE_ALL);
                xOutFp32Tensor_ = xTmpTensor_.template ReinterpretCast<float>();
                DataCopyPad(dynamicScalesOutGMTensor_[beginIdx + j], xOutFp32Tensor_[axisH_ / sizeof(float)],
                            dataCopyParamsFloat);
                pipe_barrier(PIPE_ALL);
            }
            if constexpr (IsNeedAllgather) {
                DataCopy(winTpGatherOutGMTensor_[(beginIdx + j) * axisHCommu_], xTmpTensor_, axisHCommu_);
            }
            // GM --> UB --> GM, both transfers are local
            expandXOutGlobal.SetGlobalBuffer((__gm__ ExpandXOutType *)(expandXOutGM_) + (beginIdx + j) * axisH_,
                                             axisH_);
            DataCopy(expandXOutGlobal, xTmpTensor_, axisH_);
            xQueue_.FreeTensor(xTmpTensor_);
        }
        beginIdx += count;
    }
    if constexpr (!IsNeedAllgather) {
        totalCnt_ = beginIdx;
    }
    lastCore_ = MIN(totalMoeExpert, aivNum_) - 1;
    if constexpr (IsNeedAllgather) {
        DataCopyExtParams dataCopyOutParams = {1U, static_cast<uint32_t>(sendExpertNum_ * sizeof(int32_t)), 0U, 0U, 0U};
        DataCopyPad(winTpEpCntGMTensor_[startExpertId_], outCountLocal, dataCopyOutParams);
    }
    DataCopyExtParams dataCopyOutParams = {1U, static_cast<uint32_t>(sendExpertNum_ * sizeof(int32_t)), 0U, 0U, 0U};
    GlobalTensor<int32_t> sendCountsGlobal;
    sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(sendCountsOutGM_));
    DataCopyPad(sendCountsGlobal[startExpertId_], outCountLocal, dataCopyOutParams);
    PipeBarrier<PIPE_MTE3>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::AllGatherSetStatusAndWait()
{
    pipe_barrier(PIPE_ALL);
    if (startExpertId_ >= totalExpertNum_) {
        return;
    }
    GM_ADDR rankGM = (__gm__ uint8_t *)(GetWindStateAddrByRankId(COMM_TP_IDX, tpGatherRankId_) + stateOffset_ * aivId_);
    GlobalTensor<float> tpwindowInstatusFp32Tensor_;
    tpwindowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)(rankGM));
    statusTensor_(aivId_ * INT32_NUM_PER_BLOCK + 1) = gatherCount_;
    statusTensor_(aivId_ * INT32_NUM_PER_BLOCK + 2) = preCnt_;
    LocalTensor<float> statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();
    statusFp32Tensor_(aivId_ * 8) = sumTarget_;
    SyncFunc<AscendC::HardEvent::S_MTE3>();
    DataCopy<float>(tpwindowInstatusFp32Tensor_, statusFp32Tensor_[aivId_ * 8],
                    UB_ALIGN);  // Data size is 12, copy with 32-byte alignment
    SyncFunc<AscendC::HardEvent::MTE3_S>();
    float sumOfFlag = static_cast<float>(-1.0);
    // Compute address offset
    rankGM =
        (__gm__ uint8_t *)(GetWindStateAddrByRankId(COMM_TP_IDX, tpRankId_) + stateOffset_ * aivId_);
    tpwindowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)(rankGM));
    while (sumOfFlag != sumTarget_) {
        DataCopy(statusFp32Tensor_, tpwindowInstatusFp32Tensor_, UB_ALIGN);
        SyncFunc<AscendC::HardEvent::MTE2_S>();
        sumOfFlag = statusFp32Tensor_.GetValue(0);
        SyncFunc<AscendC::HardEvent::S_MTE2>();
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::AllgatherProcessOut()
{
    if (startExpertId_ >= totalExpertNum_) {
        return;
    }
    // Get the number of tokens that need allgather
    GlobalTensor<float> tpwindowInstatusFp32Tensor_;
    GM_ADDR rankGM = (__gm__ uint8_t *)(GetWindStateAddrByRankId(COMM_TP_IDX, tpRankId_) + stateOffset_ * aivId_);
    tpwindowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)rankGM);
    LocalTensor<float> statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();
    DataCopy(statusFp32Tensor_, tpwindowInstatusFp32Tensor_, UB_ALIGN);
    SyncFunc<AscendC::HardEvent::MTE2_S>();
    uint32_t coreGatherCount = statusFp32Tensor_.ReinterpretCast<int32_t>().GetValue(1);
    uint32_t preCount = statusFp32Tensor_.ReinterpretCast<int32_t>().GetValue(2);
    gatherCount_ = coreGatherCount;
    preCnt_ = preCount;
    GlobalTensor<int32_t> sendCountsGlobal;
    GlobalTensor<int32_t> tpGlobal;
    // Copy epRecvCnt from the other TP domain card
    sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(sendCountsOutGM_));
    tpGlobal.SetGlobalBuffer((__gm__ int32_t *)(tpLocalStatusWindowGM_ + TP_STATE_SIZE));
    DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(sendExpertNum_ * sizeof(int32_t)), 0U, 0U, 0U};
    DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
    tpTmpTensor_ = xQueue_.AllocTensor<int32_t>();
    DataCopyPad(tpTmpTensor_, tpGlobal[startExpertId_], dataCopyParams, copyPadParams);
    xQueue_.EnQue(tpTmpTensor_);
    tpTmpTensor_ = xQueue_.DeQue<int32_t>();
    DataCopyPad(sendCountsGlobal[epWorldSize_ + startExpertId_], tpTmpTensor_, dataCopyParams);
    xQueue_.FreeTensor(tpTmpTensor_);
    if (coreGatherCount == 0) {
        return;
    }
    // Output start offset for local card data
    GlobalTensor<ExpandXOutType> tokGlobal;
    GlobalTensor<ExpandXOutType> expandXOutGlobal;
    DataCopyExtParams dataCopyParamsFloat = {1U, sizeof(float), 0U, 0U, 0U};
    for (uint32_t i = 0; i < coreGatherCount; i++) {
        tokGlobal.SetGlobalBuffer((__gm__ ExpandXOutType *)(tpLocalWindowGM_ + (preCount + i) * hCommuSize_));
        xTmpTensor_ = xQueue_.AllocTensor<ExpandXOutType>();
        DataCopy(xTmpTensor_, tokGlobal, axisHCommu_);
        xQueue_.EnQue(xTmpTensor_);
        xTmpTensor_ = xQueue_.DeQue<ExpandXOutType>();
        expandXOutGlobal.SetGlobalBuffer(
            (__gm__ ExpandXOutType *)(expandXOutGM_ + (preCount + totalCnt_ + i) * hOutSize_));
        DataCopy(expandXOutGlobal, xTmpTensor_, axisH_);
        if constexpr (StaticQuant || DynamicQuant) {
            xOutFp32Tensor_ = xTmpTensor_.template ReinterpretCast<float>();
            DataCopyPad(dynamicScalesOutGMTensor_[preCount + totalCnt_ + i], xOutFp32Tensor_[axisH_ / sizeof(float)],
                        dataCopyParamsFloat);
        }
        xQueue_.FreeTensor(xTmpTensor_);
    }
}

// Update tokenNumsOut tensor on multi-expert cards
template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::UpdateMultiMoeTokenNumsOut()
{
    uint32_t tokenSums = 0;
    GlobalTensor<int32_t> sendCountsGlobal;
    sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(sendCountsOutGM_));
    for (uint32_t localMoeIndex = 0; localMoeIndex < moeExpertNumPerRank_; ++localMoeIndex) {
        if (localMoeIndex == 0) {
            DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
                sendCountsGlobal[epWorldSize_ - 1]);
            uint32_t firstMoeCnt = sendCountsGlobal.GetValue(epWorldSize_ - 1);
            tokenSums = firstMoeCnt + gatherCount_;
            expertTokenNumsOutGMTensor_.SetValue(localMoeIndex, tokenSums);
            DataCacheCleanAndInvalid<int64_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
                expertTokenNumsOutGMTensor_[localMoeIndex]);
        } else {
            uint32_t preIndex = epWorldSize_ * (localMoeIndex - 1) + epWorldSize_ - 1;
            uint32_t curIndex = epWorldSize_ * localMoeIndex + epWorldSize_ - 1;
            DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
                sendCountsGlobal[preIndex]);
            DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
                sendCountsGlobal[curIndex]);
            uint32_t preMoeIndexCnt = sendCountsGlobal.GetValue(preIndex);
            uint32_t curMoeIndexCnt = sendCountsGlobal.GetValue(curIndex);
            tokenSums =
                ((expertTokenNumsType_ == 0) ? tokenSums : 0) + (curMoeIndexCnt - preMoeIndexCnt) + gatherCount_;
            expertTokenNumsOutGMTensor_.SetValue(localMoeIndex, tokenSums);
            DataCacheCleanAndInvalid<int64_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
                expertTokenNumsOutGMTensor_[localMoeIndex]);
        }
    }
}

// Update tokenNumsOut tensor
template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::UpdateTokenNumsOut()
{
    // Only the last core updates; MoE expert's last core has computed all sendCountsGlobal
    if (!isShareExpertRank_ && moeExpertNumPerRank_ > 1) {
        SyncAll<true>();
        if (aivId_ != lastCore_) return;
        SyncFunc<AscendC::HardEvent::MTE3_S>();
        UpdateMultiMoeTokenNumsOut();
    } else {
        if (aivId_ != lastCore_) return;
        uint32_t tokenNum = 0;
        // MoE expert total token count is computed inside Cumsum
        tokenNum = totalCnt_;
        if constexpr (IsNeedAllgather) {
            tokenNum += preCnt_;
            tokenNum += gatherCount_;
        }
        expertTokenNumsOutGMTensor_.SetValue(0, tokenNum);
        DataCacheCleanAndInvalid<int64_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            expertTokenNumsOutGMTensor_);
    }
    // Total tokens = tokens from other experts + tokens from allgather from the other card
    if constexpr (IsNeedAllgather) {
        GlobalTensor<int32_t> sendTpCountsGlobal;
        sendTpCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(sendTpCountOutGM_));
        sendTpCountsGlobal.SetValue(tpRankId_, totalCnt_);
        sendTpCountsGlobal.SetValue(tpGatherRankId_, gatherCount_ + preCnt_);
        DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            sendTpCountsGlobal);  // Current tpId is only 0 or 1, only need to flush cache once
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void MoeDispatchShmem<TemplateMC2TypeFunc>::Process()
{
    if ASCEND_IS_AIV {  // All AIV processing
        AlltoAllDispatch();
        SetStatus();
        WaitDispatch();
        LocalWindowCopy();
        if constexpr (IsNeedAllgather) {
            AllGatherSetStatusAndWait();
            AllgatherProcessOut();
        }
        UpdateTokenNumsOut();
    }
}

}  // namespace MoeDistributeDispatchImpl
#endif  // MOE_DISPATCH_SHMEM_H
