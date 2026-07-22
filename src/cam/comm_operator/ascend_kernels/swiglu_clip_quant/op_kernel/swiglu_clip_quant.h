/**
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

/*!
 * \file swiglu_clip_quant.h
 * \brief
 */

#ifndef SWIGLU_CLIP_QUANT_H
#define SWIGLU_CLIP_QUANT_H

#include "kernel_tiling/kernel_tiling.h"
#include "kernel_operator.h"

#define TEMPLATE_DSQ_DECLARE template <typename TBias, typename TQuantScale, typename TGroup, typename TXGm>
#define TEMPLATE_DSQ_ARGS TBias, TQuantScale, TGroup, TXGm

namespace SwigluClipQuantOps {
using namespace AscendC;
struct TempLoopInfo {
    constexpr static int64_t dbBuffer = 1;
    constexpr static int64_t blockSize = 32;
    constexpr static int64_t blockElem = blockSize / sizeof(float);
    constexpr static int64_t maskNumT32 = 256 / sizeof(float);
    constexpr static int64_t maskBlkStride = 8;
    constexpr static int64_t swiFactor = 2;
    constexpr static float dynamicQuantFactor = 1.0 / 127.0;
    constexpr static float dynamicQuantNegFactor = -1.0 / 127.0;
};

TEMPLATE_DSQ_DECLARE
class SwigluClipQuantBase {
public:
    static constexpr bool hasGroupIndex_ = !IsSameType<TGroup, float>::value;
    // static constexpr bool ifGroupAlpha_ = true;
    __aicore__ inline SwigluClipQuantBase(TPipe* pipe)
    {
        pipe_ = pipe;
    };

    __aicore__ inline void Init(
        GM_ADDR x,
        GM_ADDR groupIndex, GM_ADDR groupAlpha, GM_ADDR y, GM_ADDR scale, const SwigluClipQuantTilingData* tilingData);
    __aicore__ inline void Process();
    __aicore__ inline void ComputeReduceMax(const LocalTensor<float>& tempRes, int32_t calCount);
    __aicore__ inline void ProcessSingleGroup(int64_t groupIdx, int64_t realCount,
        int64_t globalOffset, int32_t rawGroupIdx);
    __aicore__ inline void ProcessSingleGroupPerCore(int64_t groupIdx, int64_t dimxCore, int64_t dimxCoreOffset,
        int32_t rawGroupIdx);
    __aicore__ inline void DynamicQuant(
        const LocalTensor<float>& tmpUbF32Act, const LocalTensor<float>& tmpUbF32Gate,
        uint32_t proDimsx, int32_t rawGroupIdx);
    __aicore__ inline void CopyInXAct(int32_t proDimsx, int64_t xDimxOffset);
    __aicore__ inline void Compute(int32_t proDimsx, int32_t rawGroupIdx);
    __aicore__ inline void ComputeDequant(int32_t proDimsx);
    __aicore__ inline void ComputeSwiGLU(int32_t proDimsx);
    __aicore__ inline void ComputeQuant(int32_t proDimsx, int32_t rawGroupIdx);
    __aicore__ inline void CopyOut(int32_t proDimsx, int64_t xDimxOffset);
    __aicore__ inline void CastFloatToInt8(
        const LocalTensor<float>& tmpUbF32Act, const LocalTensor<float>& tmpUbF32Gate, uint32_t proDimsx,
        LocalTensor<int8_t>& yOut);
    template<typename T>
    __aicore__ inline void CopyReshape(LocalTensor<T>& dstTensor, LocalTensor<T>& oriTensor, uint32_t rowNum,
        uint32_t colNum, CopyRepeatParams param);

protected:
    /* global memory address */
    // input global mem
    GlobalTensor<TXGm> xGm_;
    GlobalTensor<TGroup> groupIndexGm_;
    GlobalTensor<float> groupAlphaGm_;

    // output global mem
    GlobalTensor<int8_t> yGm_;
    GlobalTensor<float> scaleGm_;

    /* ub memory tensor */
    LocalTensor<float> biasLocalF32_;

    /* ascendc variable */
    TPipe* pipe_ = nullptr;
    TQue<QuePosition::VECIN, 1> xActQueue_;
    TQue<QuePosition::VECOUT, 1> outQueue_;

    TBuf<TPosition::VECCALC> tmpBuf1_;

    uint32_t blockIdx_ = GetBlockIdx();
    int64_t realDimx_ = 0;
    int64_t groupOffset_ = 0;

    uint32_t UbSingleOutSize_ = 0;
    uint32_t TBufActSclInOfs_ = 0;
    uint32_t TBufXLocalInOfs_ = 0;

    int32_t actOffset_;
    int32_t gateOffset_;

    const SwigluClipQuantTilingData* tl_ = nullptr;
    TempLoopInfo tempLoopInfo{};
};
// 公共函数实现

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::Init(
    GM_ADDR x,
    GM_ADDR groupIndex, GM_ADDR groupAlpha, GM_ADDR y, GM_ADDR scale, const SwigluClipQuantTilingData* tilingData)
{
    tl_ = tilingData;
    xGm_.SetGlobalBuffer((__gm__ TXGm*)x);
    if constexpr (hasGroupIndex_) {
        groupIndexGm_.SetGlobalBuffer((__gm__ TGroup*)groupIndex);
    }
    groupAlphaGm_.SetGlobalBuffer((__gm__ float*)groupAlpha);
    yGm_.SetGlobalBuffer((__gm__ int8_t*)y);
    scaleGm_.SetGlobalBuffer((__gm__ float*)scale);

    UbSingleOutSize_ = static_cast<uint32_t>(tl_->UbFactorDimx * tl_->outDimy);
    TBufActSclInOfs_ = static_cast<uint32_t>(tl_->UbFactorDimx * tl_->inDimy);
#if (ORIG_DTYPE_X == DT_BF16)
    TBufXLocalInOfs_ = TBufActSclInOfs_;
#endif

    // swiglu offset
    actOffset_ = tl_->actRight * tl_->UbFactorDimy;
    gateOffset_ = tl_->UbFactorDimy - actOffset_;

    // init buffer
    pipe_->InitBuffer(
        xActQueue_, tempLoopInfo.dbBuffer,
        (UbSingleOutSize_ * tempLoopInfo.swiFactor + tl_->UbFactorDimx * tempLoopInfo.blockElem) * sizeof(int32_t));
    pipe_->InitBuffer(outQueue_, 1,
        UbSingleOutSize_ * sizeof(int8_t) + tl_->UbFactorDimx * sizeof(float) + tempLoopInfo.blockSize);
    pipe_->InitBuffer(tmpBuf1_, UbSingleOutSize_ * tempLoopInfo.swiFactor * sizeof(float));
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::Process()
{
    if constexpr (!hasGroupIndex_) {
        realDimx_ = tl_->inDimx;
        // do protect realDimx_ < 0, ignore this group
        realDimx_ = (realDimx_ < 0) ? 0 : realDimx_;
        ProcessSingleGroup(0, realDimx_, 0, static_cast<int32_t>(0));
        return;
    }

    groupOffset_ = 0;
    for (int32_t groupIdx = 0; groupIdx < tl_->inGroupNum; ++groupIdx) {
        int64_t realGroupIdx =
            tl_->speGroupType == 0 ? static_cast<int64_t>(groupIdx) : static_cast<int64_t>(groupIndexGm_(groupIdx * 2));
        realDimx_ = tl_->speGroupType == 0 ? static_cast<int64_t>(groupIndexGm_(groupIdx)) :
                                             static_cast<int64_t>(groupIndexGm_(groupIdx * 2 + 1));
        // do protect realDimx_ < 0, ignore this group
        realDimx_ = (realDimx_ < 0) ? 0 : realDimx_;
        if (realDimx_ > 0 && groupOffset_ < tl_->inDimx) {
            ProcessSingleGroup(realGroupIdx, realDimx_, groupOffset_, groupIdx);
            groupOffset_ += realDimx_;
        }
        // speGroupindex场景下出现异常值(realDimx_ < 0), 退出计算
        if (tl_->speGroupType == 1 && realDimx_ <= 0) {
            break;
        }
    }
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::ProcessSingleGroup(
    int64_t groupIdx, int64_t realCount, int64_t globalOffset, int32_t rawGroupIdx)
{
    // do block tiling again
    int32_t blockDimxFactor = (realCount + tl_->maxCoreNum - 1) / tl_->maxCoreNum;
    int32_t realCoreDim = (realCount + blockDimxFactor - 1) / blockDimxFactor;

    if (blockIdx_ < realCoreDim) {
        int32_t blockDimxTailFactor = realCount - blockDimxFactor * (realCoreDim - 1);
        int32_t dimxCore = blockIdx_ == (realCoreDim - 1) ? blockDimxTailFactor : blockDimxFactor;
        int64_t coreDimxOffset = blockDimxFactor * blockIdx_ + globalOffset;
        ProcessSingleGroupPerCore(static_cast<int64_t>(groupIdx),
                                  static_cast<int64_t>(dimxCore), coreDimxOffset, rawGroupIdx);
    }
}


TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::CopyInXAct(int32_t proDimsx, int64_t xDimxOffset)
{
    // copyin x and Act scale
    DataCopyPadParams padParams{false, 0, 0, 0};
    LocalTensor<TXGm> xActLocal = xActQueue_.AllocTensor<TXGm>();
    DataCopyParams dataCopyXParams;
    dataCopyXParams.blockCount = proDimsx;
    dataCopyXParams.blockLen = tl_->inDimy * sizeof(TXGm);
    dataCopyXParams.srcStride = 0;
    dataCopyXParams.dstStride = 0;
    DataCopyPad(xActLocal[TBufXLocalInOfs_], xGm_[xDimxOffset * tl_->inDimy], dataCopyXParams, padParams);

    // copy act scale: [proDimsx,8] offset:tl_->UbFactorDimx * tl_->inDimy = TBufActSclInOfs_
    DataCopyParams dataCopyActScaleParams;
    dataCopyActScaleParams.blockCount = proDimsx;
    dataCopyActScaleParams.blockLen = sizeof(float);
    dataCopyActScaleParams.srcStride = 0;
    dataCopyActScaleParams.dstStride = 0;
    LocalTensor<float> xActLocalF32 = xActLocal.template ReinterpretCast<float>();

    xActQueue_.EnQue(xActLocal);
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::ComputeDequant(int32_t proDimsx)
{
    LocalTensor<TXGm> xActLocal = xActQueue_.DeQue<TXGm>();
    LocalTensor<float> xActLocalF32 = xActLocal.template ReinterpretCast<float>();
    LocalTensor<float> xLocalF32 = xActLocalF32;
    LocalTensor<float> activationScaleLocal = xActLocalF32[TBufActSclInOfs_];
    LocalTensor<float> tmpUbF32 = tmpBuf1_.AllocTensor<float>(); // weight scale FP32
    LocalTensor<int32_t> tmpUbI32 = tmpUbF32.template ReinterpretCast<int32_t>();

    // x 为 bf16时
    Cast(xLocalF32, xActLocal[TBufXLocalInOfs_],
        RoundMode::CAST_NONE, tempLoopInfo.swiFactor * proDimsx * tl_->UbFactorDimy);
    PipeBarrier<PIPE_V>();

    xActQueue_.EnQue(xLocalF32);
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::ComputeSwiGLU(int32_t proDimsx)
{
    LocalTensor<float> xLocalF32 = xActQueue_.DeQue<float>();

    uint32_t calEleNum = tl_->UbFactorDimy * proDimsx;
    LocalTensor<float> tmpUbF32 = tmpBuf1_.AllocTensor<float>();
    // do normal swi pre
    LocalTensor<float> tmpUbF32Act = tmpUbF32;
    LocalTensor<float> tmpUbF32Gate = tmpUbF32[calEleNum];
    // Copy dequant result: xLocalF32[actOffset] -> tmpUbF32Act, [proDimsx,H]
    // Copy dequant result: xLocalF32[gateOffset] -> tmpUbF32Gate, [proDimsx,H]
    SetMaskCount();
    SetVectorMask<float, MaskMode::COUNTER>(tl_->UbFactorDimy);
    Copy<float, false>(
        tmpUbF32Act, xLocalF32[actOffset_], AscendC::MASK_PLACEHOLDER, proDimsx,
        {1, 1, static_cast<uint16_t>(tl_->UbFactorDimy / tempLoopInfo.blockElem),
            static_cast<uint16_t>(tl_->UbFactorDimy / tempLoopInfo.blockElem * tempLoopInfo.swiFactor)});
    Copy<float, false>(
        tmpUbF32Gate, xLocalF32[gateOffset_], AscendC::MASK_PLACEHOLDER, proDimsx,
        {1, 1, static_cast<uint16_t>(tl_->UbFactorDimy / tempLoopInfo.blockElem),
            static_cast<uint16_t>(tl_->UbFactorDimy / tempLoopInfo.blockElem * tempLoopInfo.swiFactor)});
    SetMaskNorm();
    ResetMask();
    PipeBarrier<PIPE_V>();
    Muls(xLocalF32, tmpUbF32Act, static_cast<float>(-1.0), calEleNum);
    PipeBarrier<PIPE_V>();
    Exp(xLocalF32, xLocalF32, calEleNum);
    PipeBarrier<PIPE_V>();
    Adds(xLocalF32, xLocalF32, static_cast<float>(1.0), calEleNum);
    PipeBarrier<PIPE_V>();
    Div(tmpUbF32Act, tmpUbF32Act, xLocalF32, calEleNum);
    PipeBarrier<PIPE_V>();
    Mul(tmpUbF32Act, tmpUbF32Gate, tmpUbF32Act, calEleNum);
    PipeBarrier<PIPE_V>();

    // x compute done, free
    xActQueue_.FreeTensor(xLocalF32);
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::ComputeQuant(int32_t proDimsx, int32_t rawGroupIdx)
{
    LocalTensor<float> tmpUbF32 = tmpBuf1_.AllocTensor<float>();
    LocalTensor<float> tmpUbF32Act = tmpUbF32;
    LocalTensor<float> tmpUbF32Gate = tmpUbF32[tl_->UbFactorDimy * proDimsx];
    if (tl_->quantMode == 1) {
        DynamicQuant(tmpUbF32Act, tmpUbF32Gate, proDimsx, rawGroupIdx);
    }
    tmpBuf1_.FreeTensor(tmpUbF32);
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::Compute(int32_t proDimsx, int32_t rawGroupIdx)
{
    ComputeDequant(proDimsx);
    ComputeSwiGLU(proDimsx);
    ComputeQuant(proDimsx, rawGroupIdx);
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::CopyOut(int32_t proDimsx, int64_t xDimxOffset)
{
    // copy out
    LocalTensor<float> outLocal = outQueue_.DeQue<float>();
    LocalTensor<float> scaleOut = outLocal[UbSingleOutSize_ * sizeof(int8_t) / sizeof(float)];
    LocalTensor<int8_t> yOut = outLocal.template ReinterpretCast<int8_t>();

    if (tl_->quantMode == 1) {
        DataCopyParams dataCopyOutScaleParams;
        dataCopyOutScaleParams.blockCount = 1;
        dataCopyOutScaleParams.blockLen = proDimsx * sizeof(float);
        dataCopyOutScaleParams.srcStride = 0;
        dataCopyOutScaleParams.dstStride = 0;
        DataCopyPad(scaleGm_[xDimxOffset], scaleOut, dataCopyOutScaleParams);
    }
    DataCopyParams dataCopyOutyParams;
    dataCopyOutyParams.blockCount = 1;
    dataCopyOutyParams.blockLen = proDimsx * tl_->outDimy * sizeof(int8_t);
    dataCopyOutyParams.srcStride = 0;
    dataCopyOutyParams.dstStride = 0;
    DataCopyPad(yGm_[xDimxOffset * tl_->outDimy], yOut, dataCopyOutyParams);
    outQueue_.FreeTensor(outLocal);
}


TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::ProcessSingleGroupPerCore(
    int64_t groupIdx, int64_t dimxCore, int64_t coreDimxOffset, int32_t rawGroupIdx)
{
    // do ub tiling again
    int32_t ubDimxLoop = (dimxCore + tl_->UbFactorDimx - 1) / tl_->UbFactorDimx;
    int32_t ubDimxTailFactor = dimxCore - tl_->UbFactorDimx * (ubDimxLoop - 1);

    /*
      1. copyin x, activation scale
      2. compute
      3. copyout y, scale
    */
    for (uint32_t loopIdx = 0; loopIdx < ubDimxLoop; ++loopIdx) {
        int64_t xDimxOffset = coreDimxOffset + loopIdx * tl_->UbFactorDimx;
        int32_t proDimsx = loopIdx == (ubDimxLoop - 1) ? ubDimxTailFactor : tl_->UbFactorDimx;
        CopyInXAct(proDimsx, xDimxOffset);
        Compute(proDimsx, rawGroupIdx);
        CopyOut(proDimsx, xDimxOffset);
    }
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::ComputeReduceMax(
    const LocalTensor<float>& tempRes, int32_t calCount)
{
    uint32_t vectorCycles = calCount / tempLoopInfo.maskNumT32;
    uint32_t remainElements = calCount % tempLoopInfo.maskNumT32;

    BinaryRepeatParams repeatParams;
    repeatParams.dstBlkStride = 1;
    repeatParams.src0BlkStride = 1;
    repeatParams.src1BlkStride = 1;
    repeatParams.dstRepStride = 0;
    repeatParams.src0RepStride = tempLoopInfo.maskBlkStride;
    repeatParams.src1RepStride = 0;

    if (vectorCycles > 0 && remainElements > 0) {
        Max(tempRes, tempRes, tempRes[vectorCycles * tempLoopInfo.maskNumT32], remainElements, 1, repeatParams);
        PipeBarrier<PIPE_V>();
    }

    if (vectorCycles > 1) {
        Max(tempRes, tempRes[tempLoopInfo.maskNumT32], tempRes,
            tempLoopInfo.maskNumT32, vectorCycles - 1, repeatParams);
        PipeBarrier<PIPE_V>();
    }
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::DynamicQuant(
    const LocalTensor<float>& tmpUbF32Act, const LocalTensor<float>& tmpUbF32Gate,
    uint32_t proDimsx, int32_t rawGroupIdx)
{
    // Calc quant: tmpUbF32Gate = abs(tmpUbF32Act)
    Abs(tmpUbF32Gate, tmpUbF32Act, tl_->UbFactorDimy * proDimsx);

    LocalTensor<float> outLocal = outQueue_.AllocTensor<float>();
    LocalTensor<float> scaleOut = outLocal[UbSingleOutSize_ * sizeof(int8_t) / sizeof(float)];
    LocalTensor<int8_t> yOut = outLocal.template ReinterpretCast<int8_t>();
    PipeBarrier<PIPE_V>();
    // Calc quant: proDimsx * tl_->UbFactorDimy -> proDimsx * 64
    for (uint32_t i = 0; i < proDimsx; ++i) {
        ComputeReduceMax(tmpUbF32Gate[i * tl_->UbFactorDimy], tl_->UbFactorDimy);
    }
    // Calc quant: proDimsx * 64 -> proDimsx
    // repeatTimes:proDimsx, dstRepStride:1(dtype), srcBlkStride:1, srcRepStride:tl_->UbFactorDimy / 64 * 8
    WholeReduceMax(
        tmpUbF32Gate, tmpUbF32Gate, tempLoopInfo.maskNumT32,
        proDimsx, 1, 1, tl_->UbFactorDimy / tempLoopInfo.maskNumT32 * tempLoopInfo.maskBlkStride,
        ReduceOrder::ORDER_ONLY_VALUE);
    PipeBarrier<PIPE_V>();

    if (tl_->clampMode == 1 && tl_->hasGroupAlpha==1) {
        float singleGroupAlpha = static_cast<float>(groupAlphaGm_.GetValue(rawGroupIdx));
        float alpha = static_cast<float>(-1.0) * singleGroupAlpha;
        Muls(tmpUbF32Gate, tmpUbF32Gate, alpha, proDimsx);
        PipeBarrier<PIPE_V>();
    }
    // Calc quant: scaleOut / 127.0
    Muls(scaleOut, tmpUbF32Gate, static_cast<float>(1.0), proDimsx);
    PipeBarrier<PIPE_V>();
    // Calc Broadcast: proDimsx -> proDimsx,8
    int64_t blockCount = (proDimsx + tempLoopInfo.blockElem - 1) / tempLoopInfo.blockElem;
    Brcb(outLocal, scaleOut, blockCount, {1, static_cast<uint16_t>(tempLoopInfo.maskBlkStride)});
    PipeBarrier<PIPE_V>();
    // Copy scale: [proDimsx,8] -> [proDimsx,H]
    SetMaskCount();
    SetVectorMask<float, MaskMode::COUNTER>(tl_->UbFactorDimy);
    Copy<float, false>(
        tmpUbF32Gate, outLocal, AscendC::MASK_PLACEHOLDER, proDimsx,
        {1, 0, static_cast<uint16_t>(tl_->UbFactorDimy / tempLoopInfo.blockElem), 1});
    SetMaskNorm();
    ResetMask();
    PipeBarrier<PIPE_V>();

    if (tl_->clampMode == 1 && tl_->hasGroupAlpha==1) {
        // clamp min
        Max(tmpUbF32Act, tmpUbF32Act, tmpUbF32Gate, tl_->UbFactorDimy * proDimsx);
        PipeBarrier<PIPE_V>();
        // clamp max
        Muls(tmpUbF32Gate, tmpUbF32Gate, static_cast<float>(-1.0), tl_->UbFactorDimy * proDimsx);
        PipeBarrier<PIPE_V>();
        Min(tmpUbF32Act, tmpUbF32Act, tmpUbF32Gate, tl_->UbFactorDimy * proDimsx);
        PipeBarrier<PIPE_V>();
        // calc real scale
        Muls(scaleOut, scaleOut, tempLoopInfo.dynamicQuantNegFactor, proDimsx);
        PipeBarrier<PIPE_V>();
    } else {
        Muls(scaleOut, scaleOut, tempLoopInfo.dynamicQuantFactor, proDimsx);
        PipeBarrier<PIPE_V>();
    }

    // Calc y: tmpUbF32Act = tmpUbF32Act / scaleOut
    Muls(tmpUbF32Gate, tmpUbF32Gate, tempLoopInfo.dynamicQuantFactor, tl_->UbFactorDimy * proDimsx);
    PipeBarrier<PIPE_V>();
    Div(tmpUbF32Act, tmpUbF32Act, tmpUbF32Gate, tl_->UbFactorDimy * proDimsx);
    PipeBarrier<PIPE_V>();

    CastFloatToInt8(tmpUbF32Act, tmpUbF32Gate, proDimsx, yOut);
    outQueue_.EnQue<float>(outLocal);
}

TEMPLATE_DSQ_DECLARE
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::CastFloatToInt8(
    const LocalTensor<float>& tmpUbF32Act, const LocalTensor<float>& tmpUbF32Gate,
    uint32_t proDimsx, LocalTensor<int8_t>& yOut)
{
    LocalTensor<int32_t> tmpUbF32ActI32 = tmpUbF32Act.ReinterpretCast<int32_t>();
    Cast(tmpUbF32ActI32, tmpUbF32Act, RoundMode::CAST_RINT, tl_->UbFactorDimy * proDimsx);
    SetDeqScale((half)1.000000e+00f);

    LocalTensor<half> tmpUbF32Gate16 = tmpUbF32Gate.template ReinterpretCast<half>();
    Cast(tmpUbF32Gate16, tmpUbF32ActI32, RoundMode::CAST_ROUND, tl_->UbFactorDimy * proDimsx);
    PipeBarrier<PIPE_V>();

    Cast(yOut, tmpUbF32Gate16, RoundMode::CAST_TRUNC, tl_->UbFactorDimy * proDimsx);
    PipeBarrier<PIPE_V>();
}

TEMPLATE_DSQ_DECLARE
template<typename T>
__aicore__ inline void SwigluClipQuantBase<TEMPLATE_DSQ_ARGS>::CopyReshape(
    LocalTensor<T>& dstTensor, LocalTensor<T>& oriTensor, uint32_t rowNum, uint32_t colNum, CopyRepeatParams param)
{
    SetMaskCount();
    SetVectorMask<T, MaskMode::COUNTER>(colNum);
    Copy<T, false>(dstTensor, oriTensor, AscendC::MASK_PLACEHOLDER, rowNum, param);
    SetMaskNorm();
    ResetMask();
}

} // namespace SwigluClipQuantOps
#endif // SWIGLU_CLIP_QUANT_H