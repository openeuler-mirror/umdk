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
    // AscendC::ReduceMax emits {value, index} at dst, so per-row results are spaced one
    // 32B block apart to keep every destination address aligned and non-overlapping.
    // One block is also what WholeReduceMax advances per repeat when it gathers them back.
    constexpr uint32_t REDUCE_MAX_DST_STRIDE = UB_SIZE / sizeof(float);
}

// MTE3_V event id used to drain the MTE3 pipe at the BlockEpilogue <-> BlockQuant handoff, where
// the two objects share the same UB region (both allocated from offset 0) and BlockQuant reads the
// GM swiglu output that BlockEpilogue has just written. MTE3_V id map while both are alive:
// 0 = BlockEpilogue (ubStages = 1; id 1 stays reserved for a potential 2-stage epilogue),
// 2/3 = BlockQuant, 4 = this handoff drain.
constexpr int32_t EPILOGUE_QUANT_HANDOFF_EVENT_ID = 4;

// Wait until every MTE3 copy issued so far on this core has completed, so the consumer side can
// safely read back the GM data just written out and reuse the producer's UB region.
__aicore__ inline void SyncEpilogueQuantHandoff()
{
    AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(EPILOGUE_QUANT_HANDOFF_EVENT_ID);
    AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(EPILOGUE_QUANT_HANDOFF_EVENT_ID);
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
        ubOffset += AscendC::Ceil(tileRow * QuantSpaceInfo::REDUCE_MAX_DST_STRIDE * sizeof(float),
                                  QuantSpaceInfo::UB_SIZE) * QuantSpaceInfo::UB_SIZE;
        ubQuantScale = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += AscendC::Ceil(tileRow * sizeof(float), QuantSpaceInfo::UB_SIZE) * QuantSpaceInfo::UB_SIZE;
        ubInputTmp = ubAbs;
        ubInputRightHalf = ubAbs;
        ubQuantF32 = ubAbs;
        ubQuantS32 = ubAbs.ReinterpretCast<int32_t>();
        ubQuantF16 = ubAbs.ReinterpretCast<half>();

        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(3);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(3);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(2);
    }

    // Kept from the "grouped swiglu" line (the rest of its plumbing is reverted): the
    // kernels construct BlockQuant once and update the per-group pointers through this,
    // so the event pre-Sets above are not re-issued per group. Note the ids stay at
    // 0/1 (the a86f6bce 3/2 allocation only matters if a BlockEpilogue is ever alive on
    // the SAME core at the same time - i.e. the quant-on-send-core variant; the default
    // recv-quant build has each object on its own core type).
    CATLASS_DEVICE
    void UpdateParams(Params const &params_)
    {
        params = params_;
    }

    CATLASS_DEVICE
    ~BlockQuant()
    {
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(3);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(3);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(2);
    }

    CATLASS_DEVICE
    void operator()(MatrixCoord const &blockShape, MatrixCoord const &blockCoord, MatrixCoord const &actualBlockShape,
                    bool singleAiv = false)
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
        // A single AIV (deep-fuse send core) covers all tiles of the block on its own; otherwise
        // the tiles are split between the two subblocks of the block. Without this, a send core
        // (GetSubBlockIdx() == 1) would skip the only tile of a quantRowOnce-row block entirely.
        uint32_t subblockIdx = singleAiv ? 0 : AscendC::GetSubBlockIdx();
        uint32_t subblockNum = singleAiv ? 1 : AscendC::GetSubBlockNum();
        for (uint32_t loopIdx = subblockIdx; loopIdx < tileLoops; loopIdx += subblockNum) {
            auto tileCoord = epilogueTileSwizzle.GetTileCoord(loopIdx);
            auto actualTileShape = epilogueTileSwizzle.GetActualTileShape(tileCoord);
            auto tileOffsetInBlock = tileCoord * tileShape;
            auto tileOffset = blockOffset + tileOffsetInBlock;

            auto gmTileInput = gmInput[params.layoutInput.GetOffset(tileOffset)];
            auto layoutGmTileInput = params.layoutInput.GetTileLayout(actualTileShape);

            layout::RowMajor layoutUbInput{actualTileShape, ubTileStride};

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(3);
            // continue swiglu computing here and then quant
            copyGmToUbInput(ubInput, gmTileInput, layoutUbInput, layoutGmTileInput);
            copyGmToUbInput(ubInputRightHalf, gmTileInput[params.layoutInput.shape(1) >> 1],
                            layoutUbInput, layoutGmTileInput);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(3);

            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(3);
            AscendC::Mul(ubInput, ubInput, ubInputRightHalf, tileCount);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Abs(ubAbs, ubInput, tileCount);
            AscendC::PipeBarrier<PIPE_V>();

            for (uint32_t rowIdx = 0; rowIdx < tileRow; ++rowIdx) {
                AscendC::Max(ubMax[rowIdx * halfTileColumn], ubAbs[rowIdx * tileColumn],
                             ubAbs[rowIdx * tileColumn + halfTileColumn], halfTileColumn);
            }

            AscendC::PipeBarrier<PIPE_V>();
            // ubInput is dead after this and is reused as ReduceMax's work buffer below.
            AscendC::Muls(ubInputTmp, ubInput, 127.f, tileCount);
            AscendC::PipeBarrier<PIPE_V>();

            // Rows of ubMax are halfTileColumn floats apart. The host guarantees that stride is
            // a whole number of 64-float vector repeats, which both keeps every ReduceMax source
            // address aligned and keeps the reduction free of a trailing partial repeat. Each row
            // also gets its own slice of the work buffer so the calls carry no mutual dependency.
            for (uint32_t rowIdx = 0; rowIdx < tileRow; ++rowIdx) {
                AscendC::ReduceMax<float>(ubReduceMax[rowIdx * QuantSpaceInfo::REDUCE_MAX_DST_STRIDE],
                    ubMax[rowIdx * halfTileColumn], ubInput[rowIdx * halfTileColumn], halfTileColumn, false);
            }
            AscendC::PipeBarrier<PIPE_V>();

            // Gather the per-row maxima back into tileRow contiguous floats: one element per
            // repeat, with the source advancing one 32B block (REDUCE_MAX_DST_STRIDE floats).
            AscendC::WholeReduceMax(ubQuantScale, ubReduceMax, 1, tileRow, 1, 1, 1,
                                    AscendC::ReduceOrder::ORDER_ONLY_VALUE);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(3);
            AscendC::PipeBarrier<PIPE_V>();

            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(3);
            AscendC::Muls(ubDequantScale, ubQuantScale, 1.0f / 127.0f, tileRow);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(3);

            auto dequantScaleTileOffset = tileOffset.template GetCoordByAxis<0>();
            auto dequantScaleTileShape = actualTileShape.template GetCoordByAxis<0>();

            auto gmTileDequantScale = gmDequantScale[params.layoutDequantScale.GetOffset(dequantScaleTileOffset)];
            auto layoutGmTileDequantScale = params.layoutDequantScale.GetTileLayout(dequantScaleTileShape);

            auto layoutUbDequantScale =
                LayoutDequantScale::template MakeLayoutInUb<ElementDequantScale>(dequantScaleTileShape);

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(3);
            copyUbToGmDequantScale(gmTileDequantScale, ubDequantScale, layoutGmTileDequantScale, layoutUbDequantScale);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(3);

            AscendC::WaitFlag<AscendC::HardEvent::V_S>(3);
            for (uint32_t rowIdx = 0; rowIdx < tileRow; ++rowIdx) {
                AscendC::Muls(ubQuantF32[rowIdx * tileColumn], ubInputTmp[rowIdx * tileColumn],
                              1.f / ubReduceMax.GetValue(rowIdx * QuantSpaceInfo::REDUCE_MAX_DST_STRIDE),
                              tileColumn);
            }

            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Cast(ubQuantS32, ubQuantF32, AscendC::RoundMode::CAST_RINT, tileCount);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::SetDeqScale(static_cast<half>(1.0));
            AscendC::Cast(ubQuantF16, ubQuantS32, AscendC::RoundMode::CAST_RINT, tileCount);
            AscendC::PipeBarrier<PIPE_V>();

            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(2);
            AscendC::Cast(ubOutput, ubQuantF16, AscendC::RoundMode::CAST_RINT, tileCount);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(2);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(3);
            auto gmTileOutput = gmOutput[params.layoutOutput.GetOffset(tileOffset)];
            auto layoutGmTileOutput = params.layoutOutput.GetTileLayout(actualTileShape);

            LayoutOutput layoutUbOutput{actualTileShape, ubTileStride};

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(2);
            copyUbToGmOutput(gmTileOutput, ubOutput, layoutGmTileOutput, layoutUbOutput);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(2);
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