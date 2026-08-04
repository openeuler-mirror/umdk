/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeDispatchNormalZb operator kernel function header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeDispatchNormalZb operator kernel function header file
 */
#ifndef MOE_DISPATCH_NORMAL_ZB_H
#define MOE_DISPATCH_NORMAL_ZB_H

#include "zb_api.h"
#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "moe_dispatch_normal_zb_tiling.h"
#include "zb_sync_flag.h"

namespace MoeDispatchNormalZbImpl {
constexpr uint8_t BUFFER_NUM = 2;
constexpr uint32_t UB_ALIGN = 32U;

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

#define CamTypeClass \
    typename XType, typename ExpandXOutType, bool DynamicQuant, bool IsSmoothScaleExist, bool IsShareExpertRank

#define CamTypeFunc XType, ExpandXOutType, DynamicQuant, IsSmoothScaleExist, IsShareExpertRank

using namespace AscendC;
template <CamTypeClass>
class MoeDispatchNormalZb {
public:
    constexpr static int32_t PHASE_ENTRY = 1;  // kernel entered, input tensors ready
    constexpr static int32_t PHASE_DONE  = 2;  // compute/DMA complete, output tensors finalized

    __aicore__ inline MoeDispatchNormalZb(){};
    __aicore__ inline void Init(GM_ADDR x, GM_ADDR topkIdx, GM_ADDR sendTokenIdx, GM_ADDR putOffset,
        GM_ADDR recvX, GM_ADDR recvXScales, GM_ADDR workspaceGM, TPipe *pipe,
        const MoeDispatchNormalZbTilingData *tilingData);
    __aicore__ inline void Process();

private:
    __aicore__ inline void InputToDstOutput();
    __aicore__ inline void QuantInit();
    __aicore__ inline void ReduceMaxInplace(const LocalTensor<float> &srcLocal, uint32_t count);
    __aicore__ inline void QuantProcess();

    TPipe *tpipe_{nullptr};
    GlobalTensor<XType> xGT;
    GlobalTensor<int32_t> topkIdxGT;
    GlobalTensor<int32_t> putOffsetGT;
    GlobalTensor<int32_t> sendTokenIdxGT;
    GlobalTensor<float> recvXScalesGT;

    GlobalTensor<ExpandXOutType> dstGT;
    GlobalTensor<float> dstScaleOutGT;

    LocalTensor<XType> xInTensor;
    LocalTensor<ExpandXOutType> xOutTensor;
    LocalTensor<ExpandXOutType> xTmpTensor;
    LocalTensor<int32_t> topkIdxTensor;
    LocalTensor<int32_t> putOffsetTensor;  // global recv_count prefix sum
    LocalTensor<int32_t> sendTokenIdxTensor;

    TBuf<> topkIdxBuf;
    TBuf<> putOffsetBuf;
    TBuf<> sendTokenIdxBuf;
    TBuf<> tokenCastFloatBuf;
    TBuf<> tokenAbsFloatBuf;

    GM_ADDR recvXGM;

    uint32_t batchSize{0};
    uint32_t globalBatchSize{0};
    uint32_t h{0};
    uint32_t topK{0};
    uint32_t blockNum{0};
    uint32_t blockIdx{0};
    uint32_t epRankSize{0};
    uint32_t epRankId{0};
    uint32_t moeExpertNum{0};
    uint32_t moeExpertNumPerRank{0};

    uint32_t hUBAlignSize{0};
    uint32_t hOutUBAlignSize{0};
    uint32_t putOffsetAlignSize{0};
    uint32_t topkIdxCnt{0};

    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> xQueue;
    TQue<QuePosition::VECIN, 1> xInQueue;
    TQue<QuePosition::VECOUT, 1> xOutQueue;

    GM_ADDR gva_gm;
    TBuf<QuePosition::VECCALC> syncFlagBuf_;
    ZbSyncFlagImpl::ZbSyncFlag syncFlag_;
};

template <CamTypeClass>
__aicore__ inline void MoeDispatchNormalZb<CamTypeFunc>::Init(
    GM_ADDR x, GM_ADDR topkIdx, GM_ADDR sendTokenIdx, GM_ADDR putOffset, GM_ADDR recvX,
    GM_ADDR recvXScales, GM_ADDR workspaceGM, TPipe *pipe,
    const MoeDispatchNormalZbTilingData *tilingData)
{
    tpipe_ = pipe;
    blockIdx = GetBlockIdx();

    gva_gm = (GM_ADDR)(tilingData->commMetaPtr);

    batchSize = tilingData->moeDispatchNormalInfo.bs;
    globalBatchSize = tilingData->moeDispatchNormalInfo.globalBs;
    h = tilingData->moeDispatchNormalInfo.h;
    topK = tilingData->moeDispatchNormalInfo.k;
    blockNum = tilingData->moeDispatchNormalInfo.aivNum;
    epRankSize = tilingData->moeDispatchNormalInfo.epWorldSize;
    epRankId = tilingData->moeDispatchNormalInfo.epRankId;
    moeExpertNum = tilingData->moeDispatchNormalInfo.moeExpertNum;
    moeExpertNumPerRank = moeExpertNum / epRankSize;

    xGT.SetGlobalBuffer((__gm__ XType *)x);
    topkIdxGT.SetGlobalBuffer((__gm__ int32_t *)topkIdx);
    putOffsetGT.SetGlobalBuffer((__gm__ int32_t *)(putOffset));
    sendTokenIdxGT.SetGlobalBuffer((__gm__ int32_t *)(sendTokenIdx));
    recvXScalesGT.SetGlobalBuffer((__gm__ float *)recvXScales);
    recvXGM = recvX;
    topkIdxCnt = batchSize * topK;

    hUBAlignSize = Ceil(h * sizeof(ExpandXOutType), UB_ALIGN) * UB_ALIGN;
    uint32_t hScaleSizeAlign = hUBAlignSize + UB_ALIGN;

    hOutUBAlignSize = Ceil(hScaleSizeAlign, UB_ALIGN) * UB_ALIGN;  // h_align_32b + scale(32b)
    if constexpr (DynamicQuant) {
        QuantInit();
    } else {
        tpipe_->InitBuffer(xQueue, BUFFER_NUM, hOutUBAlignSize);  // 2 * 14K = 28K
    }

    putOffsetAlignSize = Ceil(epRankSize * moeExpertNum * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;  // 4 * ranks * moeNum
    tpipe_->InitBuffer(putOffsetBuf, putOffsetAlignSize);
    putOffsetTensor = putOffsetBuf.Get<int32_t>();

    // Init ZbSyncFlag — per-core granularity (slotsPerRank = blockNum)
    tpipe_->InitBuffer(syncFlagBuf_, ZbSyncFlagImpl::FLAG_SLOT_SIZE);
    syncFlag_.Init(gva_gm, epRankId, epRankSize, blockNum, syncFlagBuf_);
}

template <CamTypeClass>
__aicore__ inline void MoeDispatchNormalZb<CamTypeFunc>::QuantInit()
{
    uint32_t hAlignSize = Ceil(h * sizeof(XType), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(xInQueue, BUFFER_NUM, hAlignSize);        // 14K * 2
    tpipe_->InitBuffer(xOutQueue, BUFFER_NUM, hOutUBAlignSize);  // 7K * 2

    uint32_t hFloatAlignSize = Ceil(h * sizeof(float), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(tokenCastFloatBuf, hFloatAlignSize);
    tpipe_->InitBuffer(tokenAbsFloatBuf, hFloatAlignSize);
}

template <CamTypeClass>
__aicore__ inline void MoeDispatchNormalZb<CamTypeFunc>::ReduceMaxInplace(const LocalTensor<float> &srcLocal,
    uint32_t count)
{
    uint64_t repsFp32 = count >> 6;        // 6 is count / elemPerRefFp32
    uint64_t offsetsFp32 = repsFp32 << 6;  // 6 is repsFp32 * elemPerRefFp32
    uint64_t remsFp32 = count & 0x3f;      // 0x3f 63, count % elemPerRefFp32
    const uint64_t elemPerRefFp32 = 64UL;  // 256 bit / sizeof(float)
    if (likely(repsFp32 > 1)) {
        // 8 is rep stride
        Max(srcLocal, srcLocal[elemPerRefFp32], srcLocal, elemPerRefFp32, repsFp32 - 1, {1, 1, 1, 0, 8, 0});
        PipeBarrier<PIPE_V>();
    }
    if (unlikely(remsFp32 > 0) && unlikely(offsetsFp32 > 0)) {
        Max(srcLocal, srcLocal[offsetsFp32], srcLocal, remsFp32, 1, {1, 1, 1, 0, 8, 0});
        PipeBarrier<PIPE_V>();
    }
    uint32_t mask = (repsFp32 > 0) ? elemPerRefFp32 : count;
    // 8 is rep stride
    WholeReduceMax(srcLocal, srcLocal, mask, 1, 8, 1, 8);
}

template <CamTypeClass>
__aicore__ inline void MoeDispatchNormalZb<CamTypeFunc>::QuantProcess()
{
    float dynamicScale = 0.0;
    LocalTensor<float> floatLocalTemp;
    floatLocalTemp = tokenCastFloatBuf.Get<float>();

    Cast(floatLocalTemp, xInTensor, RoundMode::CAST_NONE, h);
    xInQueue.FreeTensor<XType>(xInTensor);
    PipeBarrier<PIPE_V>();
    if constexpr (DynamicQuant) {
        LocalTensor<float> floatLocalAbsTemp = tokenAbsFloatBuf.Get<float>();

        Abs(floatLocalAbsTemp, floatLocalTemp, h);
        PipeBarrier<PIPE_V>();
        ReduceMaxInplace(floatLocalAbsTemp, h);

        SyncFunc<AscendC::HardEvent::V_S>();
        dynamicScale = float(127.0) / (floatLocalAbsTemp.GetValue(0) + 1e-12f);
        SyncFunc<AscendC::HardEvent::S_V>();
        Muls(floatLocalTemp, floatLocalTemp, dynamicScale, h);
        PipeBarrier<PIPE_V>();
    }
    LocalTensor<half> halfLocalTemp = floatLocalTemp.ReinterpretCast<half>();
    LocalTensor<int32_t> int32LocalTemp = floatLocalTemp.ReinterpretCast<int32_t>();
    Cast(int32LocalTemp, floatLocalTemp, RoundMode::CAST_RINT, h);
    PipeBarrier<PIPE_V>();
    SetDeqScale((half)1.000000e+00f);
    PipeBarrier<PIPE_V>();

    Cast(halfLocalTemp, int32LocalTemp, RoundMode::CAST_ROUND, h);

    PipeBarrier<PIPE_V>();
    Cast(xOutTensor, halfLocalTemp, RoundMode::CAST_TRUNC, h);

    floatLocalTemp = xOutTensor.template ReinterpretCast<float>();
    floatLocalTemp.SetValue(hUBAlignSize / sizeof(float), float(1.0) / dynamicScale);  // int8->float32
}

template <CamTypeClass>
__aicore__ inline void MoeDispatchNormalZb<CamTypeFunc>::InputToDstOutput()
{
    uint32_t startTokenId, endTokenId, sendTokenNum, remainTokenNum;
    sendTokenNum = topkIdxCnt / blockNum;
    remainTokenNum = topkIdxCnt % blockNum;
    startTokenId = sendTokenNum * blockIdx;
    if (blockIdx < remainTokenNum) {
        sendTokenNum += 1;
        startTokenId += blockIdx;
    } else {
        startTokenId += remainTokenNum;
    }
    endTokenId = startTokenId + sendTokenNum;

    if (startTokenId >= topkIdxCnt) {
        return;  // core assignment by bs*k token count
    }

    DataCopyExtParams putOffsetParams = {1U, static_cast<uint32_t>(epRankSize * moeExpertNum * sizeof(uint32_t)), 0U,
        0U, 0U};

    DataCopyPadExtParams<int32_t> putOffsetCopyPadParams{false, 0U, 0U, 0U};
    DataCopyPad(putOffsetTensor, putOffsetGT, putOffsetParams, putOffsetCopyPadParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();

    tpipe_->InitBuffer(topkIdxBuf, sendTokenNum * sizeof(int32_t));     // 4 * bs * k / 48
    tpipe_->InitBuffer(sendTokenIdxBuf, sendTokenNum * sizeof(int32_t));  // 4 * bs * k / 48
    topkIdxTensor = topkIdxBuf.Get<int32_t>();
    sendTokenIdxTensor = sendTokenIdxBuf.Get<int32_t>();
    DataCopyExtParams topkIdxCntParams = {1U, static_cast<uint32_t>(sendTokenNum * sizeof(uint32_t)), 0U, 0U, 0U};
    DataCopyExtParams sendTokenIdxParams = {1U, static_cast<uint32_t>(sendTokenNum * sizeof(uint32_t)), 0U, 0U, 0U};
    DataCopyPadExtParams<int32_t> copyPadExtParams{false, 0U, 0U, 0U};
    DataCopyPad(topkIdxTensor, topkIdxGT[startTokenId], topkIdxCntParams, copyPadExtParams);
    DataCopyPad(sendTokenIdxTensor, sendTokenIdxGT[startTokenId], sendTokenIdxParams, copyPadExtParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();

    DataCopyExtParams xCopyParams = {1U, static_cast<uint32_t>(h * sizeof(XType)), 0U, 0U, 0U};
    DataCopyPadExtParams<XType> tokenCopyPadExtParams{false, 0U, 0U, 0U};
    DataCopyExtParams xOutCopyParams = {1U, static_cast<uint32_t>(hUBAlignSize), 0U, 0U, 0U};  // copy hidden_size only
    DataCopyExtParams scaleCopyParams = {1U, sizeof(float), 0U, 0U, 0U};  // copy dynamicScales

    for (int32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
        uint32_t dstExpertId = topkIdxTensor(tokenIndex - startTokenId);
        uint32_t dstRankId = dstExpertId / moeExpertNumPerRank;
        // Peer output fine offset: token index this rank sends to the expert
        // (within the expert, among tokens from different source ranks)
        int32_t curExpertIdx = sendTokenIdxTensor(tokenIndex - startTokenId);
        // Peer output coarse offset across experts/source ranks: locate expert and src rank
        int32_t dstExpertOffset = putOffsetTensor(dstExpertId * epRankSize + epRankId);
        auto ptr = reinterpret_cast<__gm__ uint8_t *>(shmem_ptr(recvXGM, dstRankId));
        uint64_t recvXByteOffset = static_cast<uint64_t>(hUBAlignSize) *
            static_cast<uint64_t>(dstExpertOffset + curExpertIdx);
        dstGT.SetGlobalBuffer((__gm__ ExpandXOutType *)(ptr + recvXByteOffset));
        if constexpr (DynamicQuant) {
            auto dsPtr = shmem_ptr((__gm__ uint8_t *)(recvXScalesGT.GetPhyAddr()), dstRankId);
            dstScaleOutGT.SetGlobalBuffer((__gm__ float *)(dsPtr) + (dstExpertOffset + curExpertIdx));

            xInTensor = xInQueue.AllocTensor<XType>();
            DataCopyPad(xInTensor, xGT[tokenIndex / topK * h], xCopyParams, tokenCopyPadExtParams);
            xInQueue.EnQue(xInTensor);
            xInTensor = xInQueue.DeQue<XType>();
            xOutTensor = xOutQueue.AllocTensor<ExpandXOutType>();
            QuantProcess();
            xOutQueue.EnQue(xOutTensor);
            xOutTensor = xOutQueue.DeQue<ExpandXOutType>();
            DataCopyPad(dstGT, xOutTensor, xOutCopyParams);  // copy token

            LocalTensor<float> xOutFp32Tensor = xOutTensor.template ReinterpretCast<float>();
            DataCopyPad(dstScaleOutGT, xOutFp32Tensor[hUBAlignSize / sizeof(float)], scaleCopyParams);

            xOutQueue.FreeTensor(xOutTensor);
        } else {
            xTmpTensor = xQueue.AllocTensor<ExpandXOutType>();
            DataCopyPad(xTmpTensor, xGT[tokenIndex / topK * h], xCopyParams, tokenCopyPadExtParams);
            xQueue.EnQue(xTmpTensor);
            xTmpTensor = xQueue.DeQue<ExpandXOutType>();
            DataCopyPad(dstGT, xTmpTensor, xOutCopyParams);
            xQueue.FreeTensor<ExpandXOutType>(xTmpTensor);
        }
    }
}

template <CamTypeClass>
__aicore__ inline void MoeDispatchNormalZb<CamTypeFunc>::Process()
{
    if ASCEND_IS_AIV {
        // ====== Dispatch Sync Protocol (magic = M+1) ======
        // Step 1: IncrementMagic — get magic M+1
        syncFlag_.IncrementMagic();

        // Step 2: BarrierAll — ensure Notify results are visible on all ranks
        //         (putOffset, recvData etc. computed by Notify must be committed)
        syncFlag_.BarrierAll();

        // Step 3: Write token data to remote ranks via shmem
        InputToDstOutput();

        // Step 4: BarrierAll — guarantee all ranks have finished writing
        //         (all remote ranks have finished writing to this rank's recvX)
        //         so that the subsequent GMM kernel can safely consume it.
        syncFlag_.BarrierAll();
    }
}

}  // namespace MoeDispatchNormalZbImpl
#endif
