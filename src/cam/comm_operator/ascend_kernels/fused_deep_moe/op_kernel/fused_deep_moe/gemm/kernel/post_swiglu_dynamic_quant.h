/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoe operator kernel utils function header file, for a3
 * Create: 2026-05-12
 * Note:
 * History: 2026-05-12 create FusedDeepMoe operator kernel utils function header file, for a3
 */
#ifndef POST_SWIGLU_DYNMAIC_QUANT_H
#define POST_SWIGLU_DYNMAIC_QUANT_H
#include "catlass/catlass.hpp"
#include "catlass/arch/cross_core_sync.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/coord.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/matrix_coord.hpp"
#include "catlass/epilogue/tile/tile_swizzle.hpp"
#include "catlass/epilogue/tile/tile_copy.hpp"


namespace Catlass::Gemm::Kernel {

namespace QuantSpaceInfo {
    constexpr uint32_t UB_SIZE = 32;
    constexpr uint32_t MAX_QUANT_ROW_ONCE = 8;
    constexpr uint32_t QUANT_SPACE_FACTOR = 176 * 1024 / 11;  // up to 176KB for quant
}

__aicore__ inline void CalQuantRow(const uint32_t column, uint32_t &row)
{
    row = QuantSpaceInfo::QUANT_SPACE_FACTOR / column;
    row = row < QuantSpaceInfo::MAX_QUANT_ROW_ONCE ? row : QuantSpaceInfo::MAX_QUANT_ROW_ONCE;
}

template <class ArchTag>
class BlockQuant {
public:
    using ElementInput = float;
    using LayoutInput = layout::RowMajor;
    using ElementDequantScale = float;
    using LayoutDequantScale = layout::VectorLayout;
    using ElementOutput = int8_t;
    using LayoutOutput = layout::RowMajor;

    using InputType = GemmType<ElementInput, LayoutInput>;
    using DequantScaleType = GemmType<ElementDequantScale, LayoutDequantScale>;
    using OutputType = GemmType<ElementOutput, LayoutOutput>;

    using EpilogueTileSwizzle = Epilogue::Tile::EpilogueHorizontalTileSwizzle;

    struct Params {
        __gm__ ElementInput *ptrInput{nullptr};
        LayoutInput layoutInput;
        __gm__ ElementDequantScale *ptrDequantScale{nullptr};
        LayoutDequantScale layoutDequantScale;
        __gm__ ElementOutput *ptrOutput{nullptr};
        LayoutOutput layoutOutput;
        uint32_t tileRow;
        uint32_t tileColumn;

        CATLASS_DEVICE
        Params() {};

        CATLASS_DEVICE
        Params(__gm__ ElementInput *ptrInput_, LayoutInput const &layoutInput_,
               __gm__ ElementDequantScale *ptrQuantScale_, LayoutDequantScale const &layoutQuantScale_,
               __gm__ ElementOutput *ptrOutput_, LayoutOutput const layoutOutput_, const uint32_t tileRow_,
               const uint32_t tileColumn_)
            : ptrInput(ptrInput_),
              layoutInput(layoutInput_),
              ptrDequantScale(ptrQuantScale_),
              layoutDequantScale(layoutQuantScale_),
              ptrOutput(ptrOutput_),
              layoutOutput(layoutOutput_),
              tileRow(tileRow_),
              tileColumn(tileColumn_)
        {}
    };

    CATLASS_DEVICE
    BlockQuant(Arch::Resource<ArchTag> const &resource, Params const &params_) : params(params_)
    {
        int64_t ubOffset = 0;
        tileRow = params_.tileRow;
        tileColumn = params_.tileColumn;
        tileCount = tileRow * tileColumn;
        halfTileColumn = tileColumn >> 1U;
        halfTileCount = tileRow * halfTileColumn;

        ubInput = resource.ubBuf.template GetBufferByByte<ElementInput>(ubOffset);
        ubOffset += tileCount * sizeof(ElementInput);
        ubDequantScale = resource.ubBuf.template GetBufferByByte<ElementDequantScale>(ubOffset);
        ubOffset += AscendC::Ceil(tileRow * sizeof(ElementDequantScale), QuantSpaceInfo::UB_SIZE) *
                        QuantSpaceInfo::UB_SIZE;
        ubOutput = resource.ubBuf.template GetBufferByByte<ElementOutput>(ubOffset);
        ubOffset += tileCount * sizeof(ElementOutput);

        ubAbs = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += tileCount * sizeof(float);
        ubMax = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += halfTileCount * sizeof(float);
        ubReduceMax = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += AscendC::Ceil(tileRow * sizeof(float), QuantSpaceInfo::UB_SIZE) * QuantSpaceInfo::UB_SIZE;
        ubQuantScale = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += AscendC::Ceil(tileRow * sizeof(float), QuantSpaceInfo::UB_SIZE) * QuantSpaceInfo::UB_SIZE;
        ubInputTmp = ubAbs;
        ubInputRightHalf = ubAbs;
        ubQuantF32 = ubAbs;
        ubQuantS32 = ubAbs.ReinterpretCast<int32_t>();
        ubQuantF16 = ubAbs.ReinterpretCast<half>();

        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(1);
    }

    CATLASS_DEVICE
    ~BlockQuant()
    {
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(1);
    }

    CATLASS_DEVICE
    void operator()(MatrixCoord const &blockShape, MatrixCoord const &blockCoord, MatrixCoord const &actualBlockShape)
    {
        MatrixCoord blockOffset = blockCoord * blockShape;

        AscendC::GlobalTensor<ElementInput> gmInput;
        gmInput.SetGlobalBuffer(params.ptrInput);
        AscendC::GlobalTensor<ElementDequantScale> gmDequantScale;
        gmDequantScale.SetGlobalBuffer(params.ptrDequantScale);
        AscendC::GlobalTensor<ElementOutput> gmOutput;
        gmOutput.SetGlobalBuffer(params.ptrOutput);

        auto ubTileStride = MakeCoord(static_cast<int64_t>(tileColumn), 1L);
        auto ubHalfTileStride = MakeCoord(static_cast<int64_t>(halfTileColumn), 1L);
        auto tileShape = MakeCoord(tileRow, tileColumn);
        EpilogueTileSwizzle epilogueTileSwizzle(actualBlockShape, tileShape);
        uint32_t tileLoops = epilogueTileSwizzle.GetLoops();
        uint32_t subblockIdx = AscendC::GetSubBlockIdx();
        uint32_t subblockNum = AscendC::GetSubBlockNum();
        for (uint32_t loopIdx = subblockIdx; loopIdx < tileLoops; loopIdx += subblockNum) {
            auto tileCoord = epilogueTileSwizzle.GetTileCoord(loopIdx);
            auto actualTileShape = epilogueTileSwizzle.GetActualTileShape(tileCoord);
            auto tileOffsetInBlock = tileCoord * tileShape;
            auto tileOffset = blockOffset + tileOffsetInBlock;

            auto gmTileInput = gmInput[params.layoutInput.GetOffset(tileOffset)];
            auto layoutGmTileInput = params.layoutInput.GetTileLayout(actualTileShape);

            layout::RowMajor layoutUbInput{actualTileShape, ubTileStride};

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
            // continue swiglu computing here and then quant
            copyGmToUbInput(ubInput, gmTileInput, layoutUbInput, layoutGmTileInput);
            copyGmToUbInput(ubInputRightHalf, gmTileInput[params.layoutInput.shape(1) >> 1],
                            layoutUbInput, layoutGmTileInput);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);

            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::Mul(ubInput, ubInput, ubInputRightHalf, tileCount);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Abs(ubAbs, ubInput, tileCount);
            AscendC::PipeBarrier<PIPE_V>();

            for (uint32_t rowIdx = 0; rowIdx < tileRow; ++rowIdx) {
                AscendC::Max(ubMax[rowIdx * halfTileColumn], ubAbs[rowIdx * tileColumn],
                             ubAbs[rowIdx * tileColumn + halfTileColumn], halfTileColumn);
            }

            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Muls(ubInputTmp, ubInput, 127.f, tileCount);

            constexpr uint32_t elementPerBlk = BYTE_PER_BLK / sizeof(float);
            constexpr int32_t mask = 64;

            AscendC::BinaryRepeatParams maxParams;
            maxParams.dstBlkStride = halfTileColumn / elementPerBlk;
            maxParams.src0BlkStride = halfTileColumn / elementPerBlk;
            maxParams.src1BlkStride = halfTileColumn / elementPerBlk;
            maxParams.dstRepStride = 1;
            maxParams.src0RepStride = 1;
            maxParams.src1RepStride = 1;
            constexpr uint32_t colNumPerCompute = BYTE_PER_VECTOR_FRACTAL / sizeof(float);
            uint32_t reduceWidth = halfTileColumn;
            while (reduceWidth > (BLK_NUM_PER_VECTOR_FRACTAL * BYTE_PER_BLK / sizeof(float))) {
                reduceWidth >>= 1;
                AscendC::Max(ubMax, ubMax, ubMax[reduceWidth], mask, reduceWidth / elementPerBlk, maxParams);
                AscendC::PipeBarrier<PIPE_V>();
            }

            AscendC::WholeReduceMax(ubReduceMax, ubMax, mask, tileRow, 1, 1, halfTileColumn / elementPerBlk,
                                    AscendC::ReduceOrder::ORDER_ONLY_VALUE);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
            AscendC::PipeBarrier<PIPE_V>();

            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(0);
            AscendC::Muls(ubDequantScale, ubReduceMax, 1.0f / 127.0f, tileRow);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);

            auto dequantScaleTileOffset = tileOffset.template GetCoordByAxis<0>();
            auto dequantScaleTileShape = actualTileShape.template GetCoordByAxis<0>();

            auto gmTileDequantScale = gmDequantScale[params.layoutDequantScale.GetOffset(dequantScaleTileOffset)];
            auto layoutGmTileDequantScale = params.layoutDequantScale.GetTileLayout(dequantScaleTileShape);

            auto layoutUbDequantScale =
                LayoutDequantScale::template MakeLayoutInUb<ElementDequantScale>(dequantScaleTileShape);

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            copyUbToGmDequantScale(gmTileDequantScale, ubDequantScale, layoutGmTileDequantScale, layoutUbDequantScale);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(0);

            AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
            for (uint32_t rowIdx = 0; rowIdx < tileRow; ++rowIdx) {
                AscendC::Muls(ubQuantF32[rowIdx * tileColumn], ubInputTmp[rowIdx * tileColumn],
                              1.f / ubReduceMax.GetValue(rowIdx), tileColumn);
            }

            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Cast(ubQuantS32, ubQuantF32, AscendC::RoundMode::CAST_RINT, tileCount);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::SetDeqScale(static_cast<half>(1.0));
            AscendC::Cast(ubQuantF16, ubQuantS32, AscendC::RoundMode::CAST_RINT, tileCount);
            AscendC::PipeBarrier<PIPE_V>();

            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(1);
            AscendC::Cast(ubOutput, ubQuantF16, AscendC::RoundMode::CAST_RINT, tileCount);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(1);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
            auto gmTileOutput = gmOutput[params.layoutOutput.GetOffset(tileOffset)];
            auto layoutGmTileOutput = params.layoutOutput.GetTileLayout(actualTileShape);

            LayoutOutput layoutUbOutput{actualTileShape, ubTileStride};

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(1);
            copyUbToGmOutput(gmTileOutput, ubOutput, layoutGmTileOutput, layoutUbOutput);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(1);
        }
    }

private:
    Params params;
    uint32_t tileRow;
    uint32_t tileColumn;
    uint32_t tileCount;
    uint32_t halfTileColumn;
    uint32_t halfTileCount;

    AscendC::LocalTensor<ElementInput> ubInput;
    AscendC::LocalTensor<ElementDequantScale> ubDequantScale;
    AscendC::LocalTensor<ElementOutput> ubOutput;

    AscendC::LocalTensor<float> ubAbs;
    AscendC::LocalTensor<float> ubMax;
    AscendC::LocalTensor<float> ubReduceMax;
    AscendC::LocalTensor<float> ubQuantScale;
    AscendC::LocalTensor<float> ubQuantScaleBrcb;
    AscendC::LocalTensor<float> ubInputTmp;
    AscendC::LocalTensor<float> ubInputRightHalf;
    AscendC::LocalTensor<float> ubQuantF32;
    AscendC::LocalTensor<int32_t> ubQuantS32;
    AscendC::LocalTensor<half> ubQuantF16;

    Epilogue::Tile::CopyGm2Ub<ArchTag, InputType> copyGmToUbInput;
    Epilogue::Tile::CopyUb2Gm<ArchTag, DequantScaleType> copyUbToGmDequantScale;
    Epilogue::Tile::CopyUb2Gm<ArchTag, OutputType> copyUbToGmOutput;
};

}

#endif // POST_SWIGLU_DYNMAIC_QUANT_H