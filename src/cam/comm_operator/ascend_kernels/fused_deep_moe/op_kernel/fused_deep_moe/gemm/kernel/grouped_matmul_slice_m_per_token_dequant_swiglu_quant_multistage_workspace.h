/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function implementation file
 */
#pragma once

#include "ascendc/basic_api/interface/kernel_operator_list_tensor_intf.h"
#include "catlass/catlass.hpp"
#include "catlass/arch/cross_core_sync.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/coord.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/matrix_coord.hpp"
#include "catlass/epilogue/tile/tile_swizzle.hpp"
#include "catlass/epilogue/tile/tile_copy.hpp"
#include "shmem.h"

#include "../../../fused_deep_moe_base.h"

constexpr uint32_t STATE_OFFSET = 512;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint64_t GROUP_TOKEN_NUM_OFFSET = 932 * 1024;
constexpr uint64_t SOFT_SYNC_OFFSET = 964 * 1024;
constexpr uint64_t SHARE_QUANT_SOFT_SYNC_OFFSET = 988 * 1024;
constexpr uint32_t SELF_STATE_OFFSET = 256 * 1024;
constexpr uint32_t SUM_TMP_TENSOR_SIZE = 1024;
constexpr uint32_t UB_ALIGN = 32;
constexpr uint32_t TOKEN_EXTRA_SPACE = 512;
constexpr uint32_t INT32_COUNT_PER_BLOCK = 8;
constexpr uint32_t SOFT_SYNC_SPACE_SIZE = 512;
constexpr int64_t LOOP_TMP_SIZE = 4096;
constexpr int32_t SUB_AIV_NUM = 2;
constexpr int32_t ODD_EVEN_BASE = 2;
constexpr int32_t BUFFER_NUM = 2;
constexpr int32_t GATHER_SECOND_NUM = 2;
constexpr uint32_t MAX_QUANT_ROW_ONCE = 8;
constexpr uint32_t QUANT_SPACE_FACTOR = 176 * 1024 / 11;  // up to 176KB for quant
constexpr uint32_t SEND_CORE_NUM = 24;
constexpr uint32_t FLAG_CNT_ALIGN = 8;
constexpr uint32_t UB_32B_ALIGN = 32;
constexpr uint32_t ALIGNED_LEN_64 = 64;
constexpr uint32_t UB_MAX_SIZE = 192 * 1024;
constexpr uint32_t UB_PART_SIZE = 4;
constexpr uint32_t DISPATCH_SEND_CORE_NUM = 36;
constexpr uint32_t DISPATCH_RECV_CORE_NUM = 12;
constexpr uint32_t COPY_FULL_EXPERT_IDS_BS = 512;
constexpr float CROSS_RANK_SYNC_FLAG = 2.0f;
#define OPT_RANK_OFFSET 512

#define CEIL_UP(x) ((x + UB_ALIGN - 1) / UB_ALIGN * UB_ALIGN)
#define CEIL(x, y) (((x) + (y - 1)) / (y))
#define UB_BLOCK_SIZE (32)
#define TOKEN_FLAG_1 (0x55555555)
#define TOKEN_FLAG_2 (0x33333333)
#define V_TO_C_FLAG_1 (0x03030303)
#define V_TO_C_FLAG_2 (0x05050505)
#define CV_FLAG_INDEX 0
#define GROUP_ID_INDEX 1
#define PRE_COUNT_INDEX 2
#define SELF_COUNT_INDEX 3
#define TOTAL_COUNT_INDEX 4
#define GROUP_TOKEN_COUNT 3  // equal to SELF_COUNT_INDEX
#define GROUP_INFO_SIZE 32

using namespace Cam;
namespace Catlass::Gemm::Kernel {

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
        ubOffset += CEIL_UP(tileRow * sizeof(ElementDequantScale));
        ubOutput = resource.ubBuf.template GetBufferByByte<ElementOutput>(ubOffset);
        ubOffset += tileCount * sizeof(ElementOutput);

        ubAbs = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += tileCount * sizeof(float);
        ubMax = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += halfTileCount * sizeof(float);
        ubReduceMax = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(tileRow * sizeof(float));
        ubQuantScale = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(tileRow * sizeof(float));
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

__aicore__ inline static void EncreaseSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx)
{
    // flag++, like set flag
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<uint32_t> global;
    if constexpr (g_coreType == AscendC::AIV) {
        global.SetGlobalBuffer((__gm__ uint32_t *)(flagAddr +
            idx * SOFT_SYNC_SPACE_SIZE + AscendC::GetSubBlockIdx() * (SOFT_SYNC_SPACE_SIZE / SUB_AIV_NUM)));
    } else {
        global.SetGlobalBuffer((__gm__ uint32_t *)(flagAddr + idx * SOFT_SYNC_SPACE_SIZE));
    }
    __asm__ __volatile__("");
    AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
        global);
    __asm__ __volatile__("");
    uint32_t value = global.GetValue(0);
    global.SetValue(0, value + 1);
    __asm__ __volatile__("");
    AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
        global);
    __asm__ __volatile__("");
    AscendC::PipeBarrier<PIPE_ALL>();
}

__aicore__ inline static void CheckSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx, uint32_t target)
{
    //  check flag, like wait flag
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<uint32_t> global;
    if constexpr (g_coreType == AscendC::AIV) {
        global.SetGlobalBuffer((__gm__ uint32_t *)(flagAddr + idx * SOFT_SYNC_SPACE_SIZE));
        while (true) {
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                            AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            uint32_t value = global.GetValue(0);
            if (value >= target) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                AscendC::DcciDst::CACHELINE_OUT>(global);
                __asm__ __volatile__("");
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    } else {
        global.SetGlobalBuffer((__gm__ uint32_t *)(flagAddr + idx * SOFT_SYNC_SPACE_SIZE));
        while (true) {
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                            AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            uint32_t value = global.GetValue(0);
            if (value >= target) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                AscendC::DcciDst::CACHELINE_OUT>(global);
                __asm__ __volatile__("");
                break;
            }
            SPIN_WAIT_CYCLES();
        }
        global.SetGlobalBuffer((__gm__ uint32_t *)(flagAddr + idx * SOFT_SYNC_SPACE_SIZE +
                                                   1 * (SOFT_SYNC_SPACE_SIZE / SUB_AIV_NUM)));
        while (true) {
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                            AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            uint32_t value = global.GetValue(0);
            if (value >= target) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                AscendC::DcciDst::CACHELINE_OUT>(global);
                __asm__ __volatile__("");
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    }
    AscendC::PipeBarrier<PIPE_ALL>();
}

__aicore__ inline static void CalQuantRow(const uint32_t column, uint32_t &row)
{
    row = QUANT_SPACE_FACTOR / column;
    row = row < MAX_QUANT_ROW_ONCE ? row : MAX_QUANT_ROW_ONCE;
}

template <TemplateMC2TypeClass, class BlockMmad_, class BlockEpilogue_, class BlockScheduler_,
          uint32_t WORKSPACE_STAGES_, class ElementGroupList_>
class GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspace {
public:
    using BlockMmad = BlockMmad_;
    using ArchTag = typename BlockMmad::ArchTag;
    using L1TileShape = typename BlockMmad::L1TileShape;
    using ElementA = typename BlockMmad::ElementA;
    using LayoutA = typename BlockMmad::LayoutA;
    using ElementB = typename BlockMmad::ElementB;
    using LayoutB = typename BlockMmad::LayoutB;
    using ElementC = typename BlockMmad::ElementC;
    using LayoutC = typename BlockMmad::LayoutC;
    using ElementAccumulator = typename BlockMmad::ElementAccumulator;

    using BlockEpilogue = BlockEpilogue_;
    using ElementScale = typename BlockEpilogue::ElementRawScale;
    using LayoutScale = typename BlockEpilogue::LayoutScale;
    using ElementPerTokenScale = typename BlockEpilogue::ElementPerTokenScale;
    using LayoutPerTokenScale = typename BlockEpilogue::LayoutPerTokenScale;
    using ElementD = typename BlockEpilogue::ElementD;
    using LayoutD = typename BlockEpilogue::LayoutD;
    using EpilogueParams = typename BlockEpilogue::Params;

    using ElementDequantScale = typename BlockQuant<ArchTag>::ElementDequantScale;
    using LayoutDequantScale = typename BlockQuant<ArchTag>::LayoutDequantScale;
    using ElementOutput = typename BlockQuant<ArchTag>::ElementOutput;
    using LayoutOutput = typename BlockQuant<ArchTag>::LayoutOutput;

    using BlockScheduler = BlockScheduler_;
    static constexpr uint32_t WORKSPACE_STAGES = WORKSPACE_STAGES_;
    using ElementGroupList = ElementGroupList_;

    using XType = ExpandXType;

    template<typename T>
    __aicore__ inline void CpGM2GMMTE(AscendC::GlobalTensor<T> inputTensor, AscendC::GlobalTensor<T> outputTensor,
                                      uint32_t elemNum)
    {
        constexpr uint32_t UB_DMA_MAX_SIZE = 190 * 1024;
        AscendC::DataCopyPadExtParams<T> padParams;
        uint32_t leftCopySize = elemNum * sizeof(T);
        uint32_t times = 0;
        uint32_t preCopyNum = UB_DMA_MAX_SIZE / sizeof(T);

        int64_t tempUbOffset = ubOffset;
        do {
            uint32_t curCopySize = (leftCopySize > UB_DMA_MAX_SIZE) ? UB_DMA_MAX_SIZE : leftCopySize;
            AscendC::LocalTensor<T> tempLocal = resource.ubBuf.template GetBufferByByte<T>(tempUbOffset);
            AscendC::DataCopyExtParams dataCopyParams(1, curCopySize, 0, 0, 0);
            AscendC::DataCopyPad(tempLocal, inputTensor[times * preCopyNum], dataCopyParams, padParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_MTE3>(0);
            AscendC::DataCopyPad(outputTensor[times * preCopyNum], tempLocal, dataCopyParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
            leftCopySize = (leftCopySize > UB_DMA_MAX_SIZE) ? leftCopySize - UB_DMA_MAX_SIZE : 0;
            times++;
        } while (leftCopySize > 0);

        AscendC::PipeBarrier<PIPE_ALL>();
    }

    // Parameters structure
    struct Params {
        // Data members
        GemmCoord problemShape;
        uint32_t problemCount;
        __gm__ ElementGroupList_ *ptrGroupList;
        __gm__ ElementA *ptrA;
        LayoutA layoutA;
        __gm__ ElementB *ptrShareB;
        LayoutB layoutShareB;
        __gm__ ElementB *ptrB;
        LayoutB layoutB;
        __gm__ ElementScale *ptrShareScale;
        LayoutScale layoutShareScale;
        __gm__ ElementScale *ptrScale;
        LayoutScale layoutScale;
        __gm__ ElementPerTokenScale *ptrPerTokenScale;
        LayoutPerTokenScale layoutPerTokenScale;
        __gm__ ElementOutput *ptrOutput;
        LayoutOutput layoutOutput;
        __gm__ ElementDequantScale *ptrDequantScale;
        LayoutDequantScale layoutDequantScale;
        GM_ADDR ptrWorkspace;
        GM_ADDR gmX;
        GM_ADDR gmMoeSmoothScales;
        GM_ADDR gmShareSmoothScales;
        GM_ADDR gmexpertIds;
        GM_ADDR gmXActiveMask;
        GM_ADDR gmShareX1;
        GM_ADDR gmShareX1Scale;
        GM_ADDR gmShareSwigluOut;
        GM_ADDR gmShareX2;
        LayoutOutput layoutShareOutput;
        GM_ADDR gmShareX2Scale;
        GM_ADDR gmSwigluOut;

        GM_ADDR gmExpandIdx;
        GM_ADDR gmEpSendCount;
        GM_ADDR gmResvered;
        GM_ADDR gmExpertTokenNums;
        GM_ADDR metaInfoGm;
        GM_ADDR gmAllExpertTokenNums;
        GM_ADDR gmTokenFlag;
        GM_ADDR gmCombineSend;

        uint32_t epRankSize;
        uint32_t epRankId;
        uint32_t moeExpertNum;
        uint32_t moeExpertNumPerRank;
        uint32_t quantMode;
        uint32_t globalBs;
        uint32_t bs;
        uint32_t topK;
        uint32_t tokenLen;
        uint32_t shareN;
        // Methods
        CATLASS_DEVICE
        Params() {}

        CATLASS_DEVICE
        Params(GemmCoord problemShape_, uint32_t problemCount_, GM_ADDR ptrGroupList_, GM_ADDR ptrA_,
               LayoutA const &layoutA_, GM_ADDR ptrShareB_, LayoutB const &layoutShareB_, GM_ADDR ptrB_,
               LayoutB const &layoutB_, GM_ADDR ptrShareScale_, LayoutScale const &layoutShareScale_,
               GM_ADDR ptrScale_, LayoutScale const &layoutScale_, GM_ADDR ptrPerTokenScale_,
               LayoutPerTokenScale const &layoutPerTokenScale_, GM_ADDR ptrOutput_, LayoutOutput const &layoutOutput_,
               GM_ADDR ptrDequantScale_, LayoutDequantScale const &layoutDequantScale_, GM_ADDR ptrWorkspace_,
               GM_ADDR gmX_, GM_ADDR gmMoeSmoothScales_, GM_ADDR gmShareSmoothScales_, GM_ADDR gmexpertIds_,
               GM_ADDR gmExpandIdx_, GM_ADDR gmEpSendCount_, GM_ADDR gmXActiveMask_, GM_ADDR gmResvered_,
               GM_ADDR gmExpertTokenNums_, GM_ADDR gmShareX1_, GM_ADDR gmShareX1Scale_, GM_ADDR gmShareSwigluOut_,
               GM_ADDR gmShareX2_, LayoutOutput const &layoutShareOutput_, GM_ADDR gmShareX2Scale_,
               GM_ADDR gmSwigluOut_, GM_ADDR metaInfoGm_, GM_ADDR gmAllExpertTokenNums_, GM_ADDR gmTokenFlag_,
               const FusedDeepMoeInfo &disGmmDeqSwigluQuantGmmDeqComInfo, GM_ADDR gmCombineSend_)
            : problemShape(problemShape_),
              problemCount(problemCount_),
              ptrGroupList(reinterpret_cast<__gm__ ElementGroupList *>(ptrGroupList_)),
              ptrA(reinterpret_cast<__gm__ ElementA *>(ptrA_)),
              layoutA(layoutA_),
              ptrShareB(reinterpret_cast<__gm__ ElementB *>(ptrShareB_)),
              layoutShareB(layoutShareB_),
              ptrB(reinterpret_cast<__gm__ ElementB *>(ptrB_)),
              layoutB(layoutB_),
              ptrShareScale(reinterpret_cast<__gm__ ElementScale *>(ptrShareScale_)),
              layoutShareScale(layoutShareScale_),
              ptrScale(reinterpret_cast<__gm__ ElementScale *>(ptrScale_)),
              layoutScale(layoutScale_),
              ptrPerTokenScale(reinterpret_cast<__gm__ ElementPerTokenScale *>(ptrPerTokenScale_)),
              layoutPerTokenScale(layoutPerTokenScale_),
              ptrOutput(reinterpret_cast<__gm__ ElementOutput *>(ptrOutput_)),
              layoutOutput(layoutOutput_),
              ptrDequantScale(reinterpret_cast<__gm__ ElementDequantScale *>(ptrDequantScale_)),
              layoutDequantScale(layoutDequantScale_),
              ptrWorkspace(ptrWorkspace_),
              gmX(gmX_),
              gmMoeSmoothScales(gmMoeSmoothScales_),
              gmShareSmoothScales(gmShareSmoothScales_),
              gmexpertIds(gmexpertIds_),
              gmExpandIdx(gmExpandIdx_),
              gmEpSendCount(gmEpSendCount_),
              gmExpertTokenNums(gmExpertTokenNums_),
              gmXActiveMask(gmXActiveMask_),
              gmResvered(gmResvered_),
              gmShareX1(gmShareX1_),
              gmShareX1Scale(gmShareX1Scale_),
              gmShareSwigluOut(gmShareSwigluOut_),
              gmShareX2(gmShareX2_),
              layoutShareOutput(layoutShareOutput_),
              gmShareX2Scale(gmShareX2Scale_),
              gmSwigluOut(gmSwigluOut_),
              metaInfoGm(metaInfoGm_),
              gmAllExpertTokenNums(gmAllExpertTokenNums_),
              gmTokenFlag(gmTokenFlag_),
              gmCombineSend(gmCombineSend_),
              epRankSize(disGmmDeqSwigluQuantGmmDeqComInfo.epRankSize),
              epRankId(disGmmDeqSwigluQuantGmmDeqComInfo.epRankId),
              moeExpertNum(disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNum),
              moeExpertNumPerRank(disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank),
              quantMode(disGmmDeqSwigluQuantGmmDeqComInfo.quantMode),
              globalBs(disGmmDeqSwigluQuantGmmDeqComInfo.globalBs),
              bs(disGmmDeqSwigluQuantGmmDeqComInfo.bs),
              topK(disGmmDeqSwigluQuantGmmDeqComInfo.k),
              tokenLen(disGmmDeqSwigluQuantGmmDeqComInfo.h),
              shareN(disGmmDeqSwigluQuantGmmDeqComInfo.shareGmm1HLen)
        {}
    };

    // Methods
    CATLASS_DEVICE
    GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspace() {}

    template <int32_t CORE_TYPE = g_coreType>
    CATLASS_DEVICE void operator()(Params const &params);

    __aicore__ inline void WaitGroupTokenNumReady(AscendC::GlobalTensor<int32_t>& groupTokenNumStateTensor,
                                                      uint32_t expected)
    {
        while (true) {
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                            AscendC::DcciDst::CACHELINE_OUT>(groupTokenNumStateTensor);
            __asm__ __volatile__("");
            if (groupTokenNumStateTensor.GetValue(0) == static_cast<int32_t>(expected)) {
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    }

    __aicore__ inline GM_ADDR GetWindStateAddrByRankId(int64_t rankId)
    {
        return ((epRankId == rankId)
                ? ((GM_ADDR)(winContext_->localWindowsExp))
                : ((GM_ADDR)(((HcclRankRelationResV2 *)(winContext_->remoteRes[rankId].nextDevicePtr))->windowsExp))) +
            dataState * WIN_STATE_OFFSET;
    }

    __aicore__ inline GM_ADDR GetWindAddrByRankId(int64_t rankId)
    {
        return (((epRankId == rankId)
                ? ((GM_ADDR)(winContext_->localWindowsIn))
                : ((GM_ADDR)(((HcclRankRelationResV2 *)(winContext_->remoteRes[rankId].nextDevicePtr))->windowsIn))) +
            winDataSizeOffset + rankId * OPT_RANK_OFFSET);
    }

    __aicore__ inline GM_ADDR GetShmemAddrByRankId(GM_ADDR baseAddr, int64_t rankId)
    {
        if (epRankId == rankId) {
            return baseAddr;
        }
        return (GM_ADDR)aclshmem_ptr(baseAddr, rankId);
    }

    __aicore__ inline GM_ADDR GetShmemMagicValAddr(int64_t coreId)
    {
        return GetShmemAddrByRankId(metaInfoGm + coreId * UB_32B_ALIGN, epRankId);
    }

    __aicore__ inline GM_ADDR GetShmemLayoutStatusAddr(int64_t rankId)
    {
        uint64_t offset = aivNum * UB_32B_ALIGN;
        return GetShmemAddrByRankId(metaInfoGm + offset, rankId);
    }

    __aicore__ inline GM_ADDR GetShmemLocalNotifyDataAddr(int64_t rankId)
    {
        uint64_t offset = aivNum * UB_32B_ALIGN + epRankSize * UB_32B_ALIGN;
        return GetShmemAddrByRankId(metaInfoGm + offset, rankId);
    }

    __aicore__ inline GM_ADDR GetShmemStateAddrByOffset(int64_t rankId, uint64_t offset)
    {
        return GetShmemAddrByRankId(metaInfoGm + offset + dataState * WIN_STATE_OFFSET, rankId);
    }

    CATLASS_DEVICE
    void ShmemLocalLayout(GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmSwigluOut, GM_ADDR gmCombineSend)
    {
        if (startTokenId_ >= expertIdsCnt) {
            return;
        }

        AscendC::LocalTensor<int32_t> sendCountTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(moeExpertNum * sizeof(int32_t));
        AscendC::Duplicate(sendCountTensor, (int32_t)0, moeExpertNum);

        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);

        for (uint32_t i = startTokenId_; i < endTokenId_; ++i) {
            int32_t expertIdx = useFullExpertIdsCopy_ ? expertIdsTensor_(i) : expertIdsTensor_(i - startTokenId_);
            int32_t curCnt = sendCountTensor.GetValue(expertIdx) + 1;
            sendCountTensor.SetValue(expertIdx, curCnt);
        }

        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<int32_t> localNotifyDataTensor;
        GM_ADDR localNotifyDataAddr = GetShmemLocalNotifyDataAddr(epRankId);
        localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)localNotifyDataAddr);
        AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum * sizeof(int32_t)),
            0U, 0U, 0U};
        AscendC::SetAtomicAdd<int32_t>();
        AscendC::DataCopyPad(localNotifyDataTensor, sendCountTensor, dataCopyParams);
        AscendC::SetAtomicNone();
        AscendC::PipeBarrier<PIPE_MTE3>();
    }

    CATLASS_DEVICE
    void ShmemSetLayoutStatus()
    {
        uint32_t rankNumPerBlock = epRankSize / sendCoreNum;
        uint32_t remainderRankNum = epRankSize % sendCoreNum;
        uint32_t startRankId = rankNumPerBlock * sendCoreIdx;
        if (sendCoreIdx < remainderRankNum) {
            rankNumPerBlock += 1;
            startRankId += sendCoreIdx;
        } else {
            startRankId += remainderRankNum;
        }
        uint32_t endRankId = startRankId + rankNumPerBlock;
        if (startRankId >= epRankSize) {
            return;
        }

        AscendC::LocalTensor<float> statusTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += UB_32B_ALIGN;
        statusTensor.SetValue(0, exp_flag_);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<float> layoutStatusTensor;
        AscendC::DataCopyParams intriParams{1, static_cast<uint16_t>(sizeof(float)), 0, 0};
        for (uint32_t targetRankId = startRankId; targetRankId < endRankId; ++targetRankId) {
            GM_ADDR layoutStatusAddr = GetShmemLayoutStatusAddr(targetRankId);
            layoutStatusTensor.SetGlobalBuffer((__gm__ float *)layoutStatusAddr);
            AscendC::DataCopy(layoutStatusTensor[epRankId * INT32_COUNT_PER_BLOCK], statusTensor,
                INT32_COUNT_PER_BLOCK);
        }
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    CATLASS_DEVICE
    void ShmemSendCountNotify(GM_ADDR gmAllExpertTokenNums)
    {
        uint32_t rankNumPerBlock = epRankSize / sendCoreNum;
        uint32_t remainderRankNum = epRankSize % sendCoreNum;
        uint32_t startRankId = rankNumPerBlock * sendCoreIdx;
        if (sendCoreIdx < remainderRankNum) {
            rankNumPerBlock += 1;
            startRankId += sendCoreIdx;
        } else {
            startRankId += remainderRankNum;
        }
        uint32_t endRankId = startRankId + rankNumPerBlock;
        if (startRankId >= epRankSize) {
            return;
        }

        AscendC::LocalTensor<float> layoutWaitStatusTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += UB_32B_ALIGN;
        AscendC::GlobalTensor<float> layoutStatusTensor;
        AscendC::GlobalTensor<int32_t> localNotifyDataTensor;
        AscendC::GlobalTensor<int32_t> allExpertTokenNumsTensor;
        allExpertTokenNumsTensor.SetGlobalBuffer((__gm__ int32_t *)gmAllExpertTokenNums);

        AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum * sizeof(int32_t)),
            0U, 0U, 0U};

        float minFlagVal = exp_flag_ - static_cast<float>(0.5);
        float maxFlagVal = exp_flag_ + static_cast<float>(0.5);

        uint64_t tensorAddrOffset = aivNum * UB_32B_ALIGN + epRankSize * UB_32B_ALIGN +
                                    moeExpertNum * sizeof(int32_t);

        AscendC::GlobalTensor<uint64_t> remoteMetaAddrGt1;
        AscendC::GlobalTensor<uint64_t> localMetaAddrGt1;
        AscendC::GlobalTensor<uint64_t> remoteMetaAddrGt2;
        AscendC::GlobalTensor<uint64_t> localMetaAddrGt2;
        AscendC::GlobalTensor<uint64_t> remoteMetaAddrGt3;
        AscendC::GlobalTensor<uint64_t> localMetaAddrGt3;
        AscendC::GlobalTensor<uint64_t> remoteMetaAddrGt4;
        AscendC::GlobalTensor<uint64_t> localMetaAddrGt4;

        for (uint32_t targetRankId = startRankId; targetRankId < endRankId; ++targetRankId) {
            float curVal = static_cast<float>(-1.0);
            GM_ADDR layoutStatusAddr = GetShmemLayoutStatusAddr(epRankId);
            layoutStatusTensor.SetGlobalBuffer((__gm__ float *)layoutStatusAddr);

            while ((curVal < minFlagVal) || (curVal > maxFlagVal)) {
                AscendC::DataCopy(layoutWaitStatusTensor, layoutStatusTensor[targetRankId * INT32_COUNT_PER_BLOCK],
                    INT32_COUNT_PER_BLOCK);
                AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
                curVal = layoutWaitStatusTensor.GetValue(0);
                if ((curVal < minFlagVal) || (curVal > maxFlagVal)) {
                    SPIN_WAIT_CYCLES();
                }
            }

            GM_ADDR localNotifyDataAddr = GetShmemLocalNotifyDataAddr(targetRankId);
            localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)localNotifyDataAddr);
            CpGM2GMMTE<int32_t>(localNotifyDataTensor, allExpertTokenNumsTensor[targetRankId * moeExpertNum],
                moeExpertNum);
            AscendC::PipeBarrier<PIPE_ALL>();
        }
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    CATLASS_DEVICE
    void ShmemWaitNotify(GM_ADDR gmEpSendCount, GM_ADDR gmAllExpertTokenNums)
    {
        AscendC::LocalTensor<int32_t> allExpertTokenNumsTensor = resource.ubBuf.template GetBufferByByte<int32_t>(
            ubOffset);
        AscendC::GlobalTensor<int32_t> allExpertTokenNumsGMTensor;
        allExpertTokenNumsGMTensor.SetGlobalBuffer((__gm__ int32_t *)gmAllExpertTokenNums);

        AscendC::DataCopyExtParams dataCopyParams = {
            1U,
            static_cast<uint32_t>(moeExpertNum * epRankSize * sizeof(int32_t)),
            0U,
            0U,
            0U
        };
        const AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(allExpertTokenNumsTensor, allExpertTokenNumsGMTensor, dataCopyParams, copyPadParams);
        AscendC::PipeBarrier<PIPE_ALL>();

        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);

        uint32_t moeExpertNumPerRank = moeExpertNum / epRankSize;

        uint32_t rankNumPerCore = epRankSize / sendCoreNum;
        uint32_t remainderRankNum = epRankSize % sendCoreNum;
        uint32_t startRankId = rankNumPerCore * sendCoreIdx;
        if (sendCoreIdx < remainderRankNum) {
            rankNumPerCore += 1;
            startRankId += sendCoreIdx;
        } else {
            startRankId += remainderRankNum;
        }
        uint32_t endRankId = startRankId + rankNumPerCore;
        if (startRankId >= epRankSize) {
            return;
        }

        AscendC::LocalTensor<int32_t> recvTokenLt = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset +
            moeExpertNum * epRankSize * sizeof(int32_t));
        AscendC::GlobalTensor<int32_t> sendCountsGlobalTensor;
        sendCountsGlobalTensor.SetGlobalBuffer((__gm__ int32_t *)gmEpSendCount);

        for (uint32_t rank = startRankId; rank < endRankId; ++rank) {
            uint32_t startExpId = rank * moeExpertNumPerRank;
            uint32_t endExpId = rank * moeExpertNumPerRank + moeExpertNumPerRank;
            int32_t prefixSum = 0;
            for (uint32_t expId = startExpId; expId < endExpId; ++expId) {
                for (uint32_t srcRank = 0; srcRank < epRankSize; ++srcRank) {
                    uint32_t index = (expId - startExpId) * epRankSize + srcRank;
                    uint32_t pairIdx = srcRank * moeExpertNum + expId;
                    int32_t curCount = allExpertTokenNumsTensor.GetValue(pairIdx);
                    prefixSum += curCount;
                    recvTokenLt.SetValue(index, prefixSum);
                }
            }
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::DataCopyExtParams copyParams{1, static_cast<uint32_t>(moeExpertNumPerRank * epRankSize *
                sizeof(int32_t)), 0, 0, 0};
            AscendC::DataCopyPad(sendCountsGlobalTensor[rank * moeExpertNum], recvTokenLt, copyParams);
            AscendC::PipeBarrier<PIPE_ALL>();
        }
    }

    CATLASS_DEVICE
    void ShmemSendToMoeExprt(GM_ADDR gmX, GM_ADDR gmExpandIdx, GM_ADDR gmMoeSmoothScales, GM_ADDR gmEpSendCount,
            GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmSwigluOut)
    {
        if (startTokenId_ >= expertIdsCnt) {
            return;
        }

        AscendC::LocalTensor<int32_t> expertCountTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(localTokenNum_ * sizeof(int32_t));
        AscendC::Duplicate(expertCountTensor, (int32_t)0, localTokenNum_);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(1);

        AscendC::LocalTensor<int32_t> dstExpertCntTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(moeExpertNum * sizeof(int32_t));
        AscendC::Duplicate(dstExpertCntTensor, (int32_t)-1, moeExpertNum);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(1);

        AscendC::LocalTensor<XType> xInTensor[BUFFER_NUM];
        AscendC::LocalTensor<int8_t> yInt8Tensor[BUFFER_NUM];
        AscendC::LocalTensor<float> yFp32Tensor[BUFFER_NUM];
        AscendC::LocalTensor<float> moeSmoothScaleTensor[BUFFER_NUM];
        AscendC::LocalTensor<int32_t> tmpFlagTensor;

        AscendC::GlobalTensor<XType> srcWinGMTensor;
        srcWinGMTensor.SetGlobalBuffer((__gm__ XType *)gmX);
        AscendC::GlobalTensor<float> moeSmoothScaleGMTensor;

        xInTensor[0] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(XType));
        xInTensor[1] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(XType));
        yInt8Tensor[0] = resource.ubBuf.template GetBufferByByte<int8_t>(ubOffset);
        yFp32Tensor[0] = yInt8Tensor[0].template ReinterpretCast<float>();
        ubOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        yInt8Tensor[1] = resource.ubBuf.template GetBufferByByte<int8_t>(ubOffset);
        yFp32Tensor[1] = yInt8Tensor[1].template ReinterpretCast<float>();
        ubOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            moeSmoothScaleGMTensor.SetGlobalBuffer((__gm__ float*) gmMoeSmoothScales);
            moeSmoothScaleTensor[0] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
            moeSmoothScaleTensor[1] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
        }
        AscendC::DataCopyExtParams scaleCopyParams = {1U, sizeof(float), 0U, 0U, 0U};
        AscendC::DataCopyExtParams flagCopyParams = {1U, sizeof(int32_t), 0U, 0U, 0U};
        tmpFlagTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(INT32_COUNT_PER_BLOCK * sizeof(int32_t));
        tmpFlagTensor.SetValue(0, tokenFlag);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<int8_t> dstWinGMTensor;
        AscendC::GlobalTensor<float> dstScaleGMTensor;
        AscendC::GlobalTensor<int32_t> dstTokenFlagGMTensor;
        AscendC::GlobalTensor<int32_t> sendCountsGlobalTensor;
        sendCountsGlobalTensor.SetGlobalBuffer((__gm__ int32_t *)gmEpSendCount);
        AscendC::LocalTensor<int32_t> sendCountsTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(moeExpertNum * epRankSize * sizeof(int32_t));
        AscendC::DataCopyExtParams sendCountsCopyParams = {
            1U,
            static_cast<uint32_t>(moeExpertNum * epRankSize * sizeof(int32_t)),
            0U, 0U, 0U
        };
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(sendCountsTensor, sendCountsGlobalTensor, sendCountsCopyParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);

        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(1);
        uint32_t sendValidTokenIndex = 0;
        for (uint32_t sendGroupIndex = 0; sendGroupIndex < moeExpertNumPerRank; ++sendGroupIndex) {
            for (uint32_t tokenIndex = startTokenId_; tokenIndex < endTokenId_; ++tokenIndex) {
                int32_t dstExpertId = useFullExpertIdsCopy_ ? expertIdsTensor_(tokenIndex) :
                    expertIdsTensor_(tokenIndex - startTokenId_);
                if (dstExpertId < 0) {
                    continue;
                }
                if ((dstExpertId % moeExpertNumPerRank) != sendGroupIndex) {
                    continue;
                }
                uint32_t index = (sendValidTokenIndex & 1) ? 0 : 1;
                int32_t eventId = (sendValidTokenIndex & 1) ? 0 : 1;
                sendValidTokenIndex += 1;
                int32_t curExpertCnt = dstExpertCntTensor.GetValue(dstExpertId);
                if (!useFullExpertIdsCopy_) {
                    if (curExpertCnt == -1) {
                        curExpertCnt = 0;
                        CalExpandxIdxInRound(dstExpertId, tokenIndex, curExpertCnt, ubOffset);
                    } else {
                        curExpertCnt++;
                    }
                    dstExpertCntTensor.SetValue(dstExpertId, curExpertCnt);
                    AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(1);
                    AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(1);
                } else {
                    curExpertCnt = 0;
                    CalExpandxIdx(dstExpertId, tokenIndex, curExpertCnt, ubOffset);
                }
                expertCountTensor(tokenIndex - startTokenId_) = curExpertCnt;

                uint32_t tempRankId = dstExpertId / moeExpertNumPerRank;
                uint32_t offsetIdx = dstExpertId * epRankSize + epRankId;
                uint32_t col = offsetIdx % moeExpertNum;
                int32_t dstExpertOffset = (col == 0) ? 0 : sendCountsTensor.GetValue(offsetIdx - 1);

                auto dstX1Addr = reinterpret_cast<__gm__ uint8_t *>(aclshmem_ptr(gmX1, tempRankId));
                auto dstX1ScaleAddr = reinterpret_cast<__gm__ uint8_t *>(aclshmem_ptr(gmX1Scale, tempRankId));
                auto dstSwigluOutAddr = reinterpret_cast<__gm__ uint8_t *>(aclshmem_ptr(gmSwigluOut, tempRankId));

                dstWinGMTensor.SetGlobalBuffer((__gm__ int8_t *)(dstX1Addr + hOutSize *
                    (dstExpertOffset + curExpertCnt)));
                dstScaleGMTensor.SetGlobalBuffer((__gm__ float *)(dstX1ScaleAddr +
                    (dstExpertOffset + curExpertCnt) * sizeof(float)));
                dstTokenFlagGMTensor.SetGlobalBuffer((__gm__ int32_t *)(dstSwigluOutAddr +
                    (dstExpertOffset + curExpertCnt) * sizeof(int32_t)));

                AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
                AscendC::DataCopy(xInTensor[index], srcWinGMTensor[tokenIndex / axisK * tokenLength], tokenLength);
                if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
                    AscendC::PipeBarrier<PIPE_MTE2>();
                    AscendC::DataCopy(moeSmoothScaleTensor[index], moeSmoothScaleGMTensor[dstExpertId * tokenLength],
                        tokenLength);
                }
                AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
                QuantToken(xInTensor[index], moeSmoothScaleTensor[index], yInt8Tensor[index], ubOffset);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(eventId);

                AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
                AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(eventId);

                AscendC::DataCopy(dstWinGMTensor, yInt8Tensor[index], tokenLength);
                AscendC::PipeBarrier<PIPE_MTE3>();
                AscendC::DataCopyPad(dstScaleGMTensor, yFp32Tensor[index][tokenLength / sizeof(float)],
                    scaleCopyParams);
                AscendC::PipeBarrier<PIPE_MTE3>();
                AscendC::DataCopyPad(dstTokenFlagGMTensor, tmpFlagTensor, flagCopyParams);
                AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventId);
            }
        }

        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(1);
        AscendC::GlobalTensor<int32_t> expandIdxGMTensor;
        expandIdxGMTensor.SetGlobalBuffer((__gm__ int32_t *)gmExpandIdx + startTokenId_);
        AscendC::DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(localTokenNum_ * sizeof(uint32_t)),
            0U, 0U, 0U};
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::DataCopyPad(expandIdxGMTensor, expertCountTensor, expertIdsCntParams);
    }

    CATLASS_DEVICE
    void ShmemCleanUp()
    {
        if (sendCoreIdx != 0) {
            return;
        }

        AscendC::LocalTensor<int32_t> cleanTempLt = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(moeExpertNum * sizeof(int32_t));
        AscendC::Duplicate(cleanTempLt, (int32_t)0, moeExpertNum);
        AscendC::PipeBarrier<PIPE_ALL>();

        AscendC::GlobalTensor<int32_t> localNotifyDataTensor;
        GM_ADDR localNotifyDataAddr = GetShmemLocalNotifyDataAddr(epRankId);
        localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)localNotifyDataAddr);
        AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum * sizeof(int32_t)),
            0U, 0U, 0U};
        AscendC::DataCopyPad(localNotifyDataTensor, cleanTempLt, dataCopyParams);
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void ShmemRecvCoreFunc(GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmEpSendCount)
    {
        uint32_t recvCoreNumPerGroup = recvCoreNum;
        uint32_t recvRankNumPerCore = epRankSize / recvCoreNumPerGroup;
        uint32_t remainderRankNum = epRankSize % recvCoreNumPerGroup;

        uint32_t recvCoreIdxInGroup = recvCoreIdx % recvCoreNumPerGroup;
        uint32_t startRankIdInGroup = recvRankNumPerCore * recvCoreIdxInGroup;
        if (recvCoreIdxInGroup < remainderRankNum) {
            recvRankNumPerCore += 1;
            startRankIdInGroup += recvCoreIdxInGroup;
        } else {
            startRankIdInGroup += remainderRankNum;
        }
        uint32_t endRankIdInGroup = startRankIdInGroup + recvRankNumPerCore;

        uint32_t subUbOffset = CEIL_UP(expertCntUp * UB_BLOCK_SIZE) + CEIL_UP(UB_BLOCK_SIZE) + CEIL_UP(expertCntUp *
            sizeof(float));

        for (uint32_t groupId = 0; groupId < localExpertNum; ++groupId) {
            uint32_t startRankId = startRankIdInGroup;
            uint32_t endRankId = endRankIdInGroup;

            uint32_t coreTokenCount = 0;
            ShmemRecvToken(gmX1, gmX1Scale, gmEpSendCount, coreTokenCount, startRankId, endRankId, recvRankNumPerCore,
                ubOffset, groupId);

            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::LocalTensor<int32_t> tmpLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(
                subUbOffset);
            tmpLocalTensor.SetValue(CV_FLAG_INDEX, vToCFlag);
            tmpLocalTensor.SetValue(GROUP_ID_INDEX, groupId);
            tmpLocalTensor.SetValue(SELF_COUNT_INDEX, coreTokenCount);
            AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);

            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET));
            AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
            AscendC::SetAtomicAdd<int32_t>();
            AscendC::DataCopy(groupTokenNumStateTensor[groupId * GROUP_INFO_SIZE], tmpLocalTensor,
                INT32_COUNT_PER_BLOCK);
            AscendC::SetAtomicNone();
            AscendC::PipeBarrier<PIPE_ALL>();
        }
    }

    CATLASS_DEVICE
    void ShmemRecvToken(GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmEpSendCount, uint32_t &coreTokenCount,
                        uint32_t startRankId, uint32_t endRankId, uint32_t recvRankNumPerCore, int64_t ubOffset,
                        uint32_t groupId)
    {
        AscendC::GlobalTensor<int32_t> dstTokenFlagGMTensor;
        AscendC::LocalTensor<int32_t> tmpFlagTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        AscendC::GlobalTensor<int32_t> sendCountsGlobalTensor;
        sendCountsGlobalTensor.SetGlobalBuffer((__gm__ int32_t *)gmEpSendCount);

        uint32_t globalExpertId = epRankId * moeExpertNumPerRank + groupId;

        for (uint32_t srcRank = startRankId; srcRank < endRankId; srcRank++) {
            uint32_t offsetIdx = globalExpertId * epRankSize + srcRank;
            uint32_t col = offsetIdx % moeExpertNum;
            int32_t prevOffset = (col == 0) ? 0 : sendCountsGlobalTensor.GetValue(offsetIdx - 1);
            int32_t count = sendCountsGlobalTensor.GetValue(offsetIdx) - prevOffset;
            if (count == 0) continue;
            coreTokenCount += count;
            for (uint32_t j = 0; j < count; j++) {
                dstTokenFlagGMTensor.SetGlobalBuffer((__gm__ int32_t *)(gmTokenFlagGm + (prevOffset + j) *
                    sizeof(int32_t)));
                while (true) {
                    AscendC::DataCopy(tmpFlagTensor, dstTokenFlagGMTensor, INT32_COUNT_PER_BLOCK);
                    AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
                    AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
                    if (tmpFlagTensor.GetValue(0) == tokenFlag) {
                        break;
                    }
                    SPIN_WAIT_CYCLES();
                }
            }
        }
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIC>(Params const &params)
    {
        aicIdx = AscendC::GetBlockIdx();
        subBlockNum = AscendC::GetSubBlockNum();
        aiCoreGroupNum = AscendC::GetBlockNum();
        aicNum = aiCoreGroupNum;
        aivNum = aiCoreGroupNum * SUB_AIV_NUM;
        aicStateGlobalCoreIdx = aivNum + aicIdx;
        moeExpertNumPerRank = params.moeExpertNumPerRank;
        localExpertNum = moeExpertNumPerRank;
        // when localExpertNum=1, all cores send token and recv token in sequence
        recvCoreNum = aivNum;
        // when localExpertNum>1, half of cores send token and another half recv token in parallel
        recvCoreNum = (localExpertNum > 1) ? aiCoreGroupNum : recvCoreNum;
        uint32_t coreNumPerGroup = DISPATCH_RECV_CORE_NUM;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            shareQuantCoreNum = aivNum;
        }

        // state of cv flag
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            metaInfoGm = params.metaInfoGm;
            epRankSize = params.epRankSize;
            moeExpertNum = params.moeExpertNum;
            uint64_t offset = aivNum * UB_32B_ALIGN + epRankSize * UB_32B_ALIGN +
                          moeExpertNum * sizeof(int32_t) +
                          4 * epRankSize * sizeof(uint64_t);
            statusDataSpaceGm = metaInfoGm + offset;
        } else {
            winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
            statusDataSpaceGm = (GM_ADDR)(winContext_->localWindowsExp);
        }
        AscendC::GlobalTensor<int32_t> selfDataStatusTensor;
        selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aicStateGlobalCoreIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        cvDataState = selfDataStatusTensor(aicStateGlobalCoreIdx * UB_ALIGN);
        if (cvDataState == 0) {
            selfDataStatusTensor(aicStateGlobalCoreIdx * UB_ALIGN) = 1;
            vToCFlag = V_TO_C_FLAG_1;
        } else {
            selfDataStatusTensor(aicStateGlobalCoreIdx * UB_ALIGN) = 0;
            vToCFlag = V_TO_C_FLAG_2;
        }

        BlockScheduler blockScheduler;
        BlockMmad blockMmad(resource);

        // Represent the full gm
        AscendC::GlobalTensor<ElementA> gmA;
        AscendC::GlobalTensor<ElementB> gmB;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            gmA.SetGlobalBuffer((__gm__ ElementA*)params.gmShareX1);
            gmB.SetGlobalBuffer((__gm__ ElementB*)params.ptrShareB);
            gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_DISABLE);
        }
        AscendC::ListTensorDesc gmBlistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrB));

        AscendC::GlobalTensor<ElementGroupList> groupList;
        groupList.SetGlobalBuffer(params.ptrGroupList);

        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        auto layoutC = layout::RowMajor{L1TileShape::M * aicNum * WORKSPACE_STAGES, L1TileShape::N};

        uint32_t stageId = 0;
        uint32_t stageUsed = 0;
        uint32_t startCoreIdx = 0;
        AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
        aicSetFunc1 = {statusDataSpaceGm + SOFT_SYNC_OFFSET,
                       static_cast<uint8_t>(aicNum + AscendC::GetBlockIdx())};  // AIV wait for flags in latter part
        uint32_t target = 1;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            uint32_t currentM = params.bs;
            GemmCoord inGroupProblemShape{currentM, params.shareN, params.problemShape.k()};
            LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
            LayoutB layoutB = params.layoutShareB;
            blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
            uint32_t coreLoops = blockScheduler.GetCoreLoops();

            // Determine the starting loopIdx of the current core under the current groupIdx
            uint32_t startLoopIdx = ((aicIdx < startCoreIdx) ? (aicIdx + aicNum) : aicIdx) - startCoreIdx;
            // wait AIV quantize needed tokens
            AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
            uint32_t waitFlagCount = params.bs < shareQuantCoreNum ? params.bs : shareQuantCoreNum;
            shareQuantTokenStateTensor.SetGlobalBuffer((__gm__ int32_t*)(
                statusDataSpaceGm + SHARE_QUANT_SOFT_SYNC_OFFSET));
            uint32_t expected = waitFlagCount * vToCFlag;
            WaitGroupTokenNumReady(shareQuantTokenStateTensor, expected);
            // Loop through the matmul of each groupIdx
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aicNum) {
                // Compute block location
                GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                Callback callbackBeforeFixpipe{};
                if (stageUsed == WORKSPACE_STAGES) {
                    aicWaitFunc1 = {statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(AscendC::GetBlockIdx()),
                                    target};  // AIC wait for flags in former part
                    target += 1;
                    callbackBeforeFixpipe = MakeCallback(&aicWaitFunc1);
                } else {
                    ++stageUsed;
                }
                Callback callbackAfterFixpipe = MakeCallback(&aicSetFunc1);

                // Compute initial location in logical coordinates
                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{(stageId * aicNum + aicIdx) * L1TileShape::M, 0};
                int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                int64_t gmOffsetC = layoutC.GetOffset(offsetC);

                // Compute block-scoped matrix multiply-add
                if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                    blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB, gmC[gmOffsetC],
                        layoutC, actualBlockShape, callbackBeforeFixpipe, callbackAfterFixpipe);
                } else {
                    callbackBeforeFixpipe();
                    blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB,
                                gmC[gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }

                stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
            }
            startCoreIdx = (startCoreIdx + coreLoops) % aicNum;
        }

        gmA.SetGlobalBuffer(params.ptrA);
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(gmBlistTensorDesc.GetDataPtr<int32_t>(0)));
        }
        int64_t gmGroupOffsetA = 0;
        int64_t gmGroupOffsetB = 0;
        for (uint32_t groupIdx = 0; groupIdx < localExpertNum; ++groupIdx) {
            if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(
                        gmBlistTensorDesc.GetDataPtr<int32_t>(groupIdx)));
            }
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET) +
                                                     groupIdx * GROUP_INFO_SIZE);
            // wait AIV recv needed tokens
            uint32_t expected = coreNumPerGroup * vToCFlag;
            WaitGroupTokenNumReady(groupTokenNumStateTensor, expected);
            uint32_t currentM = groupTokenNumStateTensor.GetValue(GROUP_TOKEN_COUNT);
            GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

            LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
            LayoutB layoutB = params.layoutB;

            blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
            uint32_t coreLoops = blockScheduler.GetCoreLoops();

            // Determine the starting loopIdx of the current core under the current groupIdx
            uint32_t startLoopIdx = ((aicIdx < startCoreIdx) ? (aicIdx + aicNum) : aicIdx) - startCoreIdx;
            // Loop through the matmul of each groupIdx
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aicNum) {
                // Compute block location
                GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                Callback callbackBeforeFixpipe{};
                if (stageUsed == WORKSPACE_STAGES) {
                    aicWaitFunc1 = {statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(AscendC::GetBlockIdx()),
                                    target};  // AIC wait for flags in former part
                    target += 1;
                    callbackBeforeFixpipe = MakeCallback(&aicWaitFunc1);
                } else {
                    ++stageUsed;
                }
                Callback callbackAfterFixpipe = MakeCallback(&aicSetFunc1);

                // Compute initial location in logical coordinates
                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{(stageId * aicNum + aicIdx) * L1TileShape::M, 0};
                int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                int64_t gmOffsetC = layoutC.GetOffset(offsetC);

                // Compute block-scoped matrix multiply-add
                if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmOffsetC], layoutC, actualBlockShape, callbackBeforeFixpipe, callbackAfterFixpipe);
                } else {
                    callbackBeforeFixpipe();
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }

                stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
            }

            gmGroupOffsetA += inGroupProblemShape.m() * inGroupProblemShape.k();
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmGroupOffsetB += inGroupProblemShape.k() * inGroupProblemShape.n();
            }

            startCoreIdx = (startCoreIdx + coreLoops) % aicNum;
        }

        if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
            blockMmad.SynchronizeBlock();
        }

        while (stageUsed > 0) {
            uint32_t aivComputeStageId =
                (stageId >= stageUsed) ? (stageId - stageUsed) : (stageId + WORKSPACE_STAGES - stageUsed);
            target += 1;
            --stageUsed;
        }
        AscendC::SyncAll<false>();
    }

    CATLASS_DEVICE
    void TokenActiveMaskCal(GM_ADDR gmXActiveMask, int64_t ubOffset)
    {
        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<bool> maskInputTensor = (resource.ubBuf.template
                                                            GetBufferByByte<bool>(subUbOffset));
        AscendC::LocalTensor<int8_t> maskInputInt8Tensor = maskInputTensor.template ReinterpretCast<int8_t>();
        subUbOffset += CEIL_UP(axisBS * sizeof(bool));
        AscendC::LocalTensor<half> maskTmpTensor = (resource.ubBuf.template
                                                            GetBufferByByte<half>(subUbOffset));
        subUbOffset += CEIL_UP(axisBS * sizeof(half));
        AscendC::LocalTensor<half> sumOutTensor = (resource.ubBuf.template
                                                            GetBufferByByte<half>(subUbOffset));
        subUbOffset += CEIL_UP(SUM_TMP_TENSOR_SIZE);
        AscendC::LocalTensor<uint8_t> sharedTmpBuffer = resource.ubBuf.template GetBufferByByte<uint8_t>(subUbOffset);

        AscendC::GlobalTensor<bool> xActiveMaskGMTensor;
        xActiveMaskGMTensor.SetGlobalBuffer((__gm__ bool *)gmXActiveMask);
        uint32_t axisBsAlignSize = CEIL_UP(axisBS * sizeof(bool));

        AscendC::DataCopyExtParams maskParams = {1U, static_cast<uint32_t>(axisBS * sizeof(bool)), 0U, 0U, 0U};
        AscendC::DataCopyPadExtParams<bool> maskCopyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(maskInputTensor, xActiveMaskGMTensor, maskParams, maskCopyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::Cast(maskTmpTensor, maskInputInt8Tensor, AscendC::RoundMode::CAST_NONE, axisBS);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::SumParams params{1, axisBsAlignSize, axisBS};
        AscendC::Sum(sumOutTensor, maskTmpTensor, sharedTmpBuffer, params);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        activeMaskBsCnt = static_cast<int32_t>(sumOutTensor.GetValue(0));
    }

    CATLASS_DEVICE
    void CalExpandxIdx(int32_t dstExpertId, uint32_t tokenIndex, int32_t &curExpertCnt, int64_t ubOffset)
    {
        // calculate index in remote
        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<int32_t> dstExpIdTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        subUbOffset += LOOP_TMP_SIZE;
        AscendC::LocalTensor<int32_t> subExpIdTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        subUbOffset += LOOP_TMP_SIZE;
        AscendC::LocalTensor<float> workLocalTensor_ = (resource.ubBuf.template GetBufferByByte<float>(ubOffset));
        subUbOffset += LOOP_TMP_SIZE;
        AscendC::Duplicate<int32_t>(dstExpIdTensor_, dstExpertId, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Sub(subExpIdTensor_, expertIdsTensor_, dstExpIdTensor_, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::LocalTensor<float> tmpFp32 = subExpIdTensor_.ReinterpretCast<float>();
        AscendC::LocalTensor<float> tmpoutFp32 = dstExpIdTensor_.ReinterpretCast<float>();
        AscendC::Abs(tmpoutFp32, tmpFp32, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Mins(subExpIdTensor_, dstExpIdTensor_, 1, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceSum<float>(tmpoutFp32, tmpFp32, workLocalTensor_, tokenIndex);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        int32_t curOtherExpertCnt = dstExpIdTensor_(0);
        if (tokenIndex > curOtherExpertCnt) {
            curExpertCnt = tokenIndex - curOtherExpertCnt;
        }
    }

    CATLASS_DEVICE
    void CalExpandxIdxInRound(int32_t dstExpertId, uint32_t tokenIndex, int32_t &curExpertCnt, int64_t ubOffset)
    {
        if (tokenIndex == 0) {
            return;
        }
        uint32_t roundSize = (UB_MAX_SIZE - ubOffset) / sizeof(int32_t) / UB_PART_SIZE;
        uint32_t roundBs = roundSize / axisK;
        uint32_t num_rounds = (activeMaskBsCnt + roundBs - 1) / roundBs;
        if (roundBs > activeMaskBsCnt) {
            roundSize = expertIdsCnt;
        }

        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<int32_t> roundExpertIds =
            (resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset));
        subUbOffset += CEIL_UP(roundSize * sizeof(int32_t));

        AscendC::LocalTensor<int32_t> dstExpIdTensor_ =
            (resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset));
        subUbOffset += CEIL_UP(roundSize * sizeof(int32_t));
        AscendC::LocalTensor<int32_t> subExpIdTensor_ =
            (resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset));
        subUbOffset += CEIL_UP(roundSize * sizeof(int32_t));
        AscendC::LocalTensor<float> workLocalTensor_ =
            (resource.ubBuf.template GetBufferByByte<float>(subUbOffset));

        curExpertCnt = 0;

        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(EVENT_ID2);
        AscendC::SetFlag<AscendC::HardEvent::S_V>(EVENT_ID2);
        for (uint32_t round = 0; round < num_rounds; ++round) {
            uint32_t roundStart = round * roundSize;
            uint32_t roundEnd = (round == num_rounds - 1) ? expertIdsCnt : (roundStart + roundSize);
            uint32_t curRoundSize = roundEnd - roundStart;

            if (curRoundSize == 0 || roundStart > tokenIndex) break;

            AscendC::DataCopyExtParams roundCopyParams = {
                1U, static_cast<uint32_t>(curRoundSize * sizeof(int32_t)), 0U, 0U, 0U};
            AscendC::DataCopyPadExtParams<int32_t> roundPadParams{false, 0U, 0U, 0U};
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(EVENT_ID2);
            AscendC::DataCopyPad(roundExpertIds, expertIdsGMTensor_[roundStart], roundCopyParams, roundPadParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);

            uint32_t calcSize = curRoundSize;
            if (roundStart <= tokenIndex && tokenIndex < roundEnd) {
                calcSize = tokenIndex - roundStart;
            }

            AscendC::WaitFlag<AscendC::HardEvent::S_V>(EVENT_ID2);
            AscendC::Duplicate<int32_t>(dstExpIdTensor_, dstExpertId, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Sub(subExpIdTensor_, roundExpertIds, dstExpIdTensor_, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::LocalTensor<float> tmpFp32 = subExpIdTensor_.ReinterpretCast<float>();
            AscendC::LocalTensor<float> tmpoutFp32 = dstExpIdTensor_.ReinterpretCast<float>();
            AscendC::Abs(tmpoutFp32, tmpFp32, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Mins(subExpIdTensor_, dstExpIdTensor_, 1, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::ReduceSum<float>(tmpoutFp32, tmpFp32, workLocalTensor_, calcSize);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(EVENT_ID2);
            AscendC::WaitFlag<AscendC::HardEvent::V_S>(EVENT_ID2);
            int32_t roundMatchCnt = dstExpIdTensor_(0);
            AscendC::SetFlag<AscendC::HardEvent::S_V>(EVENT_ID2);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(EVENT_ID2);

            if (roundStart <= tokenIndex && tokenIndex <= roundEnd) {
                curExpertCnt += (calcSize - roundMatchCnt);
                AscendC::PipeBarrier<PIPE_ALL>();
                break;
            } else {
                curExpertCnt += (curRoundSize - roundMatchCnt);
            }
        }
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(EVENT_ID2);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(EVENT_ID2);
    }

    CATLASS_DEVICE
    void CalAndSendTokenCount()
    {
        uint32_t totalExpertNum = moeExpertNum;
        uint32_t sendCountExpertNum = totalExpertNum / sendCoreNum;
        uint32_t remainderRankNum = totalExpertNum % sendCoreNum;
        uint32_t startExpertId = sendCountExpertNum * sendCoreIdx;
        if (sendCoreIdx < remainderRankNum) {
            sendCountExpertNum += 1;
            startExpertId += sendCoreIdx;
        } else {
            startExpertId += remainderRankNum;
        }
        uint32_t endExpertId = startExpertId + sendCountExpertNum;
        if (startExpertId >= totalExpertNum) {
            return;
        }

        AscendC::LocalTensor<int32_t> statusTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(CEIL(expertCntUp, INT32_COUNT_PER_BLOCK) * INT32_COUNT_PER_BLOCK * UB_BLOCK_SIZE);
        AscendC::Duplicate(statusTensor_, (int32_t)0,
                           expertCntUp * INT32_COUNT_PER_BLOCK);
        if (state == 0) {
            // set the first number of every 8 numbers as 0x3F800000(float 1.0)
            uint64_t mask[2] = {0x101010101010101, 0};
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Duplicate<int32_t>(statusTensor_, 0x3F800000, mask, CEIL(expertCntUp, INT32_COUNT_PER_BLOCK), 1,
                                        INT32_COUNT_PER_BLOCK);
        }

        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);

        for (uint32_t curExpertId = startExpertId; curExpertId < endExpertId; ++curExpertId) {
            int32_t curExpertCnt = 0;
            int32_t dstExpertId = curExpertId;
            CalExpandxIdxInRound(dstExpertId, expertIdsCnt, curExpertCnt, ubOffset);
            int32_t cntPosIndex = curExpertId * INT32_COUNT_PER_BLOCK + 1;
            statusTensor_(cntPosIndex) = curExpertCnt;
        }

        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<int32_t> rankGMTensor;
        uint32_t offset = stateOffset * epRankId;
        for (uint32_t rankIndex = startExpertId; rankIndex < endExpertId; ++rankIndex) {
            uint32_t dstRankId = rankIndex;
            if (moeExpertNumPerRank > 1) {
                dstRankId = ((rankIndex) / moeExpertNumPerRank);
                offset =
                    (epRankId + (rankIndex) % moeExpertNumPerRank * epRankSize) * stateOffset;
            }
            GM_ADDR rankGM = (__gm__ uint8_t *)(GetWindStateAddrByRankId(dstRankId) + offset);
            rankGMTensor.SetGlobalBuffer((__gm__ int32_t *)rankGM);
            AscendC::DataCopy<int32_t>(rankGMTensor, statusTensor_[rankIndex * INT32_COUNT_PER_BLOCK], 8UL);
        }
    }

    CATLASS_DEVICE
    void QuantToken(AscendC::LocalTensor<XType> &xInTensor, AscendC::LocalTensor<float> &smoothScaleTensor,
        AscendC::LocalTensor<int8_t> &yInt8Tensor, int64_t ubOffset)
    {
        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<float> xFp32TmpTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(float));
        AscendC::LocalTensor<float> xFp32AbsTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(float));
        AscendC::LocalTensor<float> xRowMaxTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        AscendC::LocalTensor<int32_t> ytmpInt32Tensor = xFp32TmpTensor.template ReinterpretCast<int32_t>();
        AscendC::LocalTensor<half> yHalfTensor = xFp32TmpTensor.template ReinterpretCast<half>();
        AscendC::LocalTensor<float> yFp32Tensor = yInt8Tensor.template ReinterpretCast<float>();
        AscendC::LocalTensor<int32_t> yInt32Tensor = yInt8Tensor.template ReinterpretCast<int32_t>();

        AscendC::Cast(xFp32TmpTensor, xInTensor, AscendC::RoundMode::CAST_NONE, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            AscendC::Mul(xFp32TmpTensor, xFp32TmpTensor, smoothScaleTensor, tokenLength);
            AscendC::PipeBarrier<PIPE_V>();
        }
        AscendC::Abs(xFp32AbsTensor, xFp32TmpTensor, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceMax(xRowMaxTensor, xFp32AbsTensor, xFp32AbsTensor, tokenLength, false);
        AscendC::PipeBarrier<PIPE_V>();

        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        float dynamicQuantScale = float(127.0) / xRowMaxTensor.GetValue(0);
        yFp32Tensor.SetValue(tokenLength / sizeof(float), float(1.0) / dynamicQuantScale);
        yInt32Tensor.SetValue(tokenLength / sizeof(int32_t) + 1, tokenFlag);
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);

        AscendC::Muls(xFp32TmpTensor, xFp32TmpTensor, dynamicQuantScale, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(ytmpInt32Tensor, xFp32TmpTensor, AscendC::RoundMode::CAST_RINT, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(yHalfTensor, ytmpInt32Tensor, AscendC::RoundMode::CAST_ROUND, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(yInt8Tensor, yHalfTensor, AscendC::RoundMode::CAST_TRUNC, tokenLength);
    }

    CATLASS_DEVICE
    void SendToMoeExprt(GM_ADDR gmX, GM_ADDR gmExpandIdx, GM_ADDR gmMoeSmoothScales)
    {
        if (startTokenId_ >= expertIdsCnt) {
            return;
        }
        AscendC::LocalTensor<int32_t> expertCountTensor = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        ubOffset += CEIL_UP(localTokenNum_ * sizeof(int32_t));
        AscendC::Duplicate(expertCountTensor, (int32_t)0, localTokenNum_);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(1);

        AscendC::LocalTensor<XType> xInTensor[BUFFER_NUM];
        AscendC::LocalTensor<int8_t> yInt8Tensor[BUFFER_NUM];
        AscendC::LocalTensor<float> yFp32Tensor[BUFFER_NUM];
        AscendC::LocalTensor<float> moeSmoothScaleTensor[BUFFER_NUM];

        AscendC::GlobalTensor<XType> srcWinGMTensor;
        srcWinGMTensor.SetGlobalBuffer((__gm__ XType *)gmX);
        AscendC::GlobalTensor<float> moeSmoothScaleGMTensor;

        xInTensor[0] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(XType));
        xInTensor[1] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(XType));
        yInt8Tensor[0] = resource.ubBuf.template GetBufferByByte<int8_t>(ubOffset);
        ubOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        yInt8Tensor[1] = resource.ubBuf.template GetBufferByByte<int8_t>(ubOffset);
        ubOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            moeSmoothScaleGMTensor.SetGlobalBuffer((__gm__ float*) gmMoeSmoothScales);
            moeSmoothScaleTensor[0] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
            moeSmoothScaleTensor[1] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
        }
        AscendC::GlobalTensor<int8_t> dstWinGMTensor;
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(1);
        uint32_t sendValidTokenIndex = 0;
        for (uint32_t sendGroupIndex = 0; sendGroupIndex < moeExpertNumPerRank; ++sendGroupIndex) {
            for (uint32_t tokenIndex = startTokenId_; tokenIndex < endTokenId_; ++tokenIndex) {
                int32_t dstExpertId = expertIdsTensor_(tokenIndex - startTokenId_);
                if (dstExpertId < 0) {
                    continue;
                }
                // Send to preferentically to the specicied expert
                if ((dstExpertId % moeExpertNumPerRank) != sendGroupIndex) {
                    continue;
                }
                uint32_t index = (sendValidTokenIndex & 1) ? 0 : 1;
                int32_t eventId = (sendValidTokenIndex & 1) ? 0 : 1;
                sendValidTokenIndex += 1;
                int32_t curExpertCnt = 0;
                CalExpandxIdxInRound(dstExpertId, tokenIndex, curExpertCnt, ubOffset);
                expertCountTensor(tokenIndex - startTokenId_) = curExpertCnt;
                uint32_t tempRankId = dstExpertId / moeExpertNumPerRank;
                GM_ADDR rankGM = (__gm__ uint8_t *)(
                    GetWindAddrByRankId(tempRankId) +
                    (expertPerSizeOnWin * (epRankId * moeExpertNumPerRank + dstExpertId % moeExpertNumPerRank)) +
                    hCommuSize * curExpertCnt);
                dstWinGMTensor.SetGlobalBuffer((__gm__ int8_t *)rankGM);

                AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
                AscendC::DataCopy(xInTensor[index], srcWinGMTensor[tokenIndex / axisK * tokenLength], tokenLength);
                if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
                    AscendC::PipeBarrier<PIPE_MTE2>();
                    AscendC::DataCopy(
                        moeSmoothScaleTensor[index], moeSmoothScaleGMTensor[dstExpertId * tokenLength], tokenLength);
                }
                AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
                QuantToken(xInTensor[index], moeSmoothScaleTensor[index], yInt8Tensor[index], ubOffset);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(eventId);

                AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
                AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(eventId);

                AscendC::DataCopy(dstWinGMTensor, yInt8Tensor[index], tokenLength);
                AscendC::PipeBarrier<PIPE_MTE3>();
                AscendC::DataCopy(dstWinGMTensor[tokenLength], yInt8Tensor[index][tokenLength], scaleParamPad);
                AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventId);
            }
        }
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(1);

        AscendC::GlobalTensor<int32_t> expandIdxGMTensor;
        expandIdxGMTensor.SetGlobalBuffer((__gm__ int32_t *)gmExpandIdx + startTokenId_);
        AscendC::DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(localTokenNum_ * sizeof(uint32_t)),
                                                         0U, 0U, 0U};
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::DataCopyPad(expandIdxGMTensor, expertCountTensor, expertIdsCntParams);
    }

    CATLASS_DEVICE void
    SendCoreFunc(GM_ADDR gmX, GM_ADDR gmExpertIds, GM_ADDR gmMoeSmoothScales, GM_ADDR gmX1, GM_ADDR gmX1Scale,
                 GM_ADDR gmExpandIdx, GM_ADDR gmXActiveMask, GM_ADDR gmEpSendCount, GM_ADDR gmAllExpertTokenNums,
                 GM_ADDR gmCombineSend)
    {
        ubOffset = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_X_ACTIVE_MASK) {
            TokenActiveMaskCal(gmXActiveMask, ubOffset);
        }
        expertIdsCnt = activeMaskBsCnt * axisK;

        expertIdsGMTensor_.SetGlobalBuffer((__gm__ int32_t *)gmExpertIds);

        // determine the copy strategy based on ActiveMaskBsCnt
        useFullExpertIdsCopy_ = (activeMaskBsCnt <= COPY_FULL_EXPERT_IDS_BS);

        uint32_t sendTokenNum = expertIdsCnt / sendCoreNum;
        uint32_t remainderTokenNum = expertIdsCnt % sendCoreNum;
        startTokenId_ = sendTokenNum * sendCoreIdx;
        if (sendCoreIdx < remainderTokenNum) {
            sendTokenNum += 1;
            startTokenId_ += sendCoreIdx;
        } else {
            startTokenId_ += remainderTokenNum;
        }
        endTokenId_ = startTokenId_ + sendTokenNum;
        localTokenNum_ = endTokenId_ - startTokenId_;

        uint32_t copySize = useFullExpertIdsCopy_ ? expertIdsCnt : localTokenNum_;
        uint32_t copyStart = useFullExpertIdsCopy_ ? 0 : startTokenId_;

        uint32_t expertIdsSize = copySize;
        expertIdsTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        ubOffset += CEIL_UP(expertIdsSize * sizeof(int32_t));

        AscendC::DataCopyExtParams expertIdsCntParams = {
            1U,
            static_cast<uint32_t>(expertIdsSize * sizeof(uint32_t)),
            0U,
            0U,
            0U
        };
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(expertIdsTensor_, expertIdsGMTensor_[copyStart], expertIdsCntParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);

        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            ShmemLocalLayout(gmX1, gmX1Scale, gmTokenFlagGm, gmCombineSend);
            AscendC::SyncAll<true>();
            ShmemSetLayoutStatus();
            ShmemSendCountNotify(gmAllExpertTokenNums);
            AscendC::SyncAll<true>();
            ShmemWaitNotify(gmEpSendCount, gmAllExpertTokenNums);
            AscendC::SyncAll<true>();
        } else {
            CalAndSendTokenCount();
            AscendC::PipeBarrier<PIPE_ALL>();
        }
        sendToMoeAivNum = sendCoreNum;
        AscendC::SetDeqScale((half)1.000000e+00f);
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            ShmemSendToMoeExprt(gmX, gmExpandIdx, gmMoeSmoothScales, gmEpSendCount, gmX1, gmX1Scale, gmTokenFlagGm);
        } else {
            SendToMoeExprt(gmX, gmExpandIdx, gmMoeSmoothScales);
        }
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE void
    SendCoreLayoutFunc(GM_ADDR gmX, GM_ADDR gmExpertIds, GM_ADDR gmMoeSmoothScales, GM_ADDR gmX1, GM_ADDR gmX1Scale,
                       GM_ADDR gmExpandIdx, GM_ADDR gmXActiveMask, GM_ADDR gmEpSendCount, GM_ADDR gmAllExpertTokenNums,
                       GM_ADDR gmCombineSend)
    {
        ubOffset = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_X_ACTIVE_MASK) {
            TokenActiveMaskCal(gmXActiveMask, ubOffset);
        }
        expertIdsCnt = activeMaskBsCnt * axisK;

        expertIdsGMTensor_.SetGlobalBuffer((__gm__ int32_t *)gmExpertIds);

        useFullExpertIdsCopy_ = (activeMaskBsCnt <= COPY_FULL_EXPERT_IDS_BS);

        // Phase 1: all cores do layout, token distributed across all send cores
        uint32_t layoutTokenNum = expertIdsCnt / sendCoreNum;
        uint32_t layoutRemainder = expertIdsCnt % sendCoreNum;
        startTokenId_ = layoutTokenNum * sendCoreIdx;
        if (sendCoreIdx < layoutRemainder) {
            layoutTokenNum += 1;
            startTokenId_ += sendCoreIdx;
        } else {
            startTokenId_ += layoutRemainder;
        }
        endTokenId_ = startTokenId_ + layoutTokenNum;
        localTokenNum_ = endTokenId_ - startTokenId_;

        // reserve UB for 36 cores size (used later in SendCoreDataFunc)
        uint32_t sendDataCoreNum = sendCoreNum / 2;
        uint32_t sendTokenNum = expertIdsCnt / sendDataCoreNum;
        uint32_t sendRemainder = expertIdsCnt % sendDataCoreNum;
        uint32_t reserveTokenNum = sendTokenNum + (sendRemainder > 0 ? 1 : 0);
        uint32_t expertIdsSize = useFullExpertIdsCopy_ ? expertIdsCnt : reserveTokenNum;
        expertIdsTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        ubOffset += CEIL_UP(expertIdsSize * sizeof(int32_t));

        // copy expertIds for layout phase
        uint32_t layoutCopySize = useFullExpertIdsCopy_ ? expertIdsCnt : localTokenNum_;
        uint32_t layoutCopyStart = useFullExpertIdsCopy_ ? 0 : startTokenId_;
        AscendC::DataCopyExtParams layoutCopyParams = {
            1U,
            static_cast<uint32_t>(layoutCopySize * sizeof(uint32_t)),
            0U, 0U, 0U
        };
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(expertIdsTensor_, expertIdsGMTensor_[layoutCopyStart], layoutCopyParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);

        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            ShmemLocalLayout(gmX1, gmX1Scale, gmTokenFlagGm, gmCombineSend);
            AscendC::SyncAll<true>();
            ShmemSetLayoutStatus();
            ShmemSendCountNotify(gmAllExpertTokenNums);
            AscendC::SyncAll<true>();
            ShmemWaitNotify(gmEpSendCount, gmAllExpertTokenNums);
            AscendC::SyncAll<true>();
        } else {
            CalAndSendTokenCount();
            AscendC::PipeBarrier<PIPE_ALL>();
        }
    }

    CATLASS_DEVICE void
    SendCoreDataFunc(GM_ADDR gmX, GM_ADDR gmExpandIdx, GM_ADDR gmMoeSmoothScales, GM_ADDR gmEpSendCount, GM_ADDR gmX1,
                    GM_ADDR gmX1Scale)
    {
        // Phase 2: 36 cores do ShmemSendToMoeExprt
        // recalculate startTokenId_/endTokenId_ for 36 distribution
        uint32_t sendDataIdx = sendCoreIdx;
        uint32_t newTokenNum = expertIdsCnt / sendCoreNum;
        uint32_t newRemainder = expertIdsCnt % sendCoreNum;
        startTokenId_ = newTokenNum * sendDataIdx;
        if (sendDataIdx < newRemainder) {
            newTokenNum += 1;
            startTokenId_ += sendDataIdx;
        } else {
            startTokenId_ += newRemainder;
        }
        endTokenId_ = startTokenId_ + newTokenNum;
        localTokenNum_ = endTokenId_ - startTokenId_;

        // re-copy expertIds for send phase
        if (!useFullExpertIdsCopy_) {
            uint32_t sendCopySize = useFullExpertIdsCopy_ ? expertIdsCnt : localTokenNum_;
            uint32_t sendCopyStart = useFullExpertIdsCopy_ ? 0 : startTokenId_;
            AscendC::DataCopyExtParams sendCopyParams = {
                1U,
                static_cast<uint32_t>(sendCopySize * sizeof(uint32_t)),
                0U, 0U, 0U
            };
            AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
            AscendC::DataCopyPad(expertIdsTensor_, expertIdsGMTensor_[sendCopyStart], sendCopyParams, copyPadParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
        }

        sendToMoeAivNum = sendCoreNum;
        AscendC::SetDeqScale((half)1.000000e+00f);
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            ShmemSendToMoeExprt(gmX, gmExpandIdx, gmMoeSmoothScales, gmEpSendCount, gmX1, gmX1Scale, gmTokenFlagGm);
        } else {
            SendToMoeExprt(gmX, gmExpandIdx, gmMoeSmoothScales);
        }
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void shareQuantCoreFunc(GM_ADDR gmX, GM_ADDR gmShareSmoothScales, GM_ADDR gmShareX1Token, GM_ADDR gmShareX1Scale)
    {
        int64_t subUbOffset = 0;
        uint32_t quantTokenPerCore = axisBS / shareQuantCoreNum;
        uint32_t remainTokenNum = axisBS % shareQuantCoreNum;
        uint32_t startTokenId = quantTokenPerCore * shareQuantCoreIdx;
        if (shareQuantCoreIdx < remainTokenNum) {
            quantTokenPerCore += 1;
            startTokenId += shareQuantCoreIdx;
        } else {
            startTokenId += remainTokenNum;
        }
        uint32_t endTokenId = startTokenId + quantTokenPerCore;
        if (startTokenId >= axisBS) {
            return;
        }
        AscendC::SetDeqScale(static_cast<half>(1.0));
        AscendC::GlobalTensor<XType> srcXGMTensor; // token输入
        srcXGMTensor.SetGlobalBuffer((__gm__ XType*)gmX);
        AscendC::GlobalTensor<int8_t> dstXInt8GMTensor; // token输出
        dstXInt8GMTensor.SetGlobalBuffer((__gm__ int8_t*)gmShareX1Token);
        AscendC::GlobalTensor<float> dstXScaleGMTensor; // token scale输出
        dstXScaleGMTensor.SetGlobalBuffer((__gm__ float*)gmShareX1Scale);
        AscendC::GlobalTensor<float> shareSmoothScaleGMTensor;
        shareSmoothScaleGMTensor.SetGlobalBuffer((__gm__ float*)gmShareSmoothScales);

        AscendC::LocalTensor<XType> xInTensor[BUFFER_NUM];
        AscendC::LocalTensor<int8_t> yInt8Tensor[BUFFER_NUM];
        AscendC::LocalTensor<float> yFp32Tensor[BUFFER_NUM];
        xInTensor[0] = resource.ubBuf.template GetBufferByByte<XType>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(XType));
        xInTensor[1] = resource.ubBuf.template GetBufferByByte<XType>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(XType));
        yInt8Tensor[0] = resource.ubBuf.template GetBufferByByte<int8_t>(subUbOffset);
        yFp32Tensor[0] = yInt8Tensor[0].template ReinterpretCast<float>();
        subUbOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        yInt8Tensor[1] = resource.ubBuf.template GetBufferByByte<int8_t>(subUbOffset);
        yFp32Tensor[1] = yInt8Tensor[1].template ReinterpretCast<float>();
        subUbOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        AscendC::LocalTensor shareSmoothScaleTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            subUbOffset += CEIL_UP(tokenLength * sizeof(float));
            AscendC::DataCopy(shareSmoothScaleTensor, shareSmoothScaleGMTensor, tokenLength);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
        }
        // 输入输出开double buffer
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0); // MTE2等MTE3
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1); // MTE2等MTE3
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(1);
        AscendC::DataCopyExtParams dataCopyParamsFloat = {1U, sizeof(float), 0U, 0U, 0U};
        for (uint32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
            uint32_t index = (tokenIndex & 1) ? 0 : 1;
            int32_t eventId = (tokenIndex & 1) ? 0 : 1;
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
            AscendC::DataCopy(xInTensor[index], srcXGMTensor[tokenIndex * tokenLength], tokenLength);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
            QuantToken(xInTensor[index], shareSmoothScaleTensor, yInt8Tensor[index], subUbOffset);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(eventId);
            AscendC::DataCopy(dstXInt8GMTensor[tokenIndex * tokenLength], yInt8Tensor[index], tokenLength);
            AscendC::DataCopyPad(
                dstXScaleGMTensor[tokenIndex], yFp32Tensor[index][tokenLength / sizeof(float)], dataCopyParamsFloat);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventId);
        }
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0); // MTE2等MTE3
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(1); // MTE2等MTE3
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(1);

        // 量化完成，通过写GM告知C核
        AscendC::PipeBarrier<PIPE_ALL>();
        AscendC::LocalTensor<int32_t> tmpLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        tmpLocalTensor.SetValue(CV_FLAG_INDEX, vToCFlag);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
        shareQuantTokenStateTensor.SetGlobalBuffer(
            (__gm__ int32_t*)(statusDataSpaceGm + SHARE_QUANT_SOFT_SYNC_OFFSET));
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::SetAtomicAdd<int32_t>();
        // 用原子加，写入vToCFlag
        AscendC::DataCopy(shareQuantTokenStateTensor, tmpLocalTensor, INT32_COUNT_PER_BLOCK);
        AscendC::SetAtomicNone();
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void RecvCount(int64_t ubOffset)
    {
        uint32_t recStatusNumPerCore = expertCntUp;
        uint32_t startStatusIndex = 0;  // every wait for all token counts

        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<int32_t> statusTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * UB_BLOCK_SIZE);
        AscendC::LocalTensor<uint32_t> gatherTmpTensor = (resource.ubBuf.template GetBufferByByte<uint32_t>
                                                                                                      (subUbOffset));
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        AscendC::LocalTensor<float> gatherMaskOutTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * sizeof(float));
        AscendC::LocalTensor<float> statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();

        AscendC::LocalTensor<float> statusSumOutTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        AscendC::LocalTensor<uint8_t> sumTmpTensor = resource.ubBuf.template GetBufferByByte<uint8_t>(subUbOffset);
        subUbOffset += CEIL_UP(SUM_TMP_TENSOR_SIZE);
        gatherTmpTensor.SetValue(0, 1);

        uint32_t mask = 1;
        uint64_t rsvdCnt = 0;
        AscendC::SumParams sumParams{1, recStatusNumPerCore, recStatusNumPerCore};
        float sumOfFlag = static_cast<float>(-1.0);
        float minTarget = (sumTarget * recStatusNumPerCore) - (float)0.5;
        float maxTarget = (sumTarget * recStatusNumPerCore) + (float)0.5;
        AscendC::DataCopyParams intriParams{static_cast<uint16_t>(recStatusNumPerCore), 1, static_cast<uint16_t>(15),
                                            0};
        AscendC::GlobalTensor<float> windowInstatusFp32Tensor_;
        windowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)GetWindStateAddrByRankId(epRankId));
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);

        uint32_t preRecvTokenCount = 0;
        while ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
            AscendC::DataCopy(statusFp32Tensor_, windowInstatusFp32Tensor_[startStatusIndex *
                                                                           stateOffset / sizeof(float)], intriParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::GatherMask(gatherMaskOutTensor, statusFp32Tensor_, gatherTmpTensor, true, mask,
                                {1, (uint16_t)recStatusNumPerCore, 1, 0}, rsvdCnt);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Sum(statusSumOutTensor, gatherMaskOutTensor, sumTmpTensor, sumParams);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
            sumOfFlag = statusSumOutTensor.GetValue(0);
            if ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
                SPIN_WAIT_CYCLES();
            }
        }
    }

    CATLASS_DEVICE
    void GetCumSum(int32_t startRankId, int32_t recvExpertNum, int64_t ubOffset)
    {
        // calculate token index in output tensor
        int64_t subUbOffset = ubOffset;
        uint32_t recStatusNumPerCore = expertCntUp;
        AscendC::LocalTensor<int32_t> statusTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * UB_BLOCK_SIZE);
        AscendC::LocalTensor<uint32_t> gatherTmpTensor = (resource.ubBuf.template GetBufferByByte<uint32_t>
                                                                                                      (subUbOffset));
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        AscendC::LocalTensor<float> gatherMaskOutTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * sizeof(float));
        AscendC::LocalTensor<float> statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();

        uint64_t rsvdCnt = 0;
        gatherTmpTensor.SetValue(0, GATHER_SECOND_NUM);
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);
        AscendC::GatherMask(gatherMaskOutTensor, statusFp32Tensor_, gatherTmpTensor, true, GATHER_SECOND_NUM,
                            {1, (uint16_t)recStatusNumPerCore, 1, 0}, rsvdCnt);
        AscendC::LocalTensor<float> workLocalTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceSum<float>(gatherMaskOutTensor, gatherMaskOutTensor, workLocalTensor,
                                (startRankId + 1) <= recvExpertNum ? (startRankId + 1) : recvExpertNum);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
    }

    CATLASS_DEVICE
    void RecvToken(GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmEpSendCount, uint32_t &coreTokenCount,
                   uint32_t startRankId, uint32_t endRankId, uint32_t recvRankNumPerCore, int64_t ubOffset)
    {
        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<int32_t> statusTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * UB_BLOCK_SIZE);
        AscendC::LocalTensor<uint32_t> gatherTmpTensor = (resource.ubBuf.template GetBufferByByte<uint32_t>
                                                                                                      (subUbOffset));
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        AscendC::LocalTensor<float> gatherMaskOutTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * sizeof(float));
        AscendC::LocalTensor<float> statusFp32Tensor_ = statusTensor_.ReinterpretCast<float>();

        AscendC::DataCopyExtParams dataCopyParamsFloat = {1U, sizeof(float), 0U, 0U, 0U};
        AscendC::LocalTensor<int8_t> xTmpTensor_ = resource.ubBuf.template GetBufferByByte<int8_t>(subUbOffset);
        subUbOffset += CEIL_UP(axisHCommu * sizeof(int8_t));
        AscendC::LocalTensor<float> xOutFp32Tensor_ = xTmpTensor_.template ReinterpretCast<float>();
        AscendC::LocalTensor<int32_t> tmpLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        AscendC::LocalTensor<int32_t> gatherMaskOutCountTensor =
                                    (gatherMaskOutTensor.template ReinterpretCast<int32_t>());
        AscendC::GlobalTensor<int8_t> tokGlobal;
        AscendC::GlobalTensor<int32_t> tokGlobalInt32;
        AscendC::GlobalTensor<int8_t> expandXOutGlobal;
        AscendC::GlobalTensor<float> dynamicScalesOutGMTensor_;
        dynamicScalesOutGMTensor_.SetGlobalBuffer((__gm__ float *)(gmX1Scale));
        uint32_t beginIdx = 0;
        uint32_t targetTokenCount = 0;
        uint32_t curRecvTokenCount = 0;
        for (uint32_t index = startRankId; index < endRankId; index++) {
            uint32_t i = index - startRankId;
            if (i > 0) {
                gatherMaskOutCountTensor.SetValue(
                    i, gatherMaskOutCountTensor.GetValue(i - 1) + gatherMaskOutCountTensor.GetValue(index));
            }
            uint32_t count = statusTensor_.GetValue(index * INT32_COUNT_PER_BLOCK + 1);
            coreTokenCount += count;
            beginIdx = gatherMaskOutCountTensor.GetValue(i) - count;
            countPerRank[i] = count;
            rankBeginIdx[i] = beginIdx;
            curTokenIdx[i] = 0;
            beginIdx += count;
            targetTokenCount += count;
        }
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        while (curRecvTokenCount < targetTokenCount) {
            for (uint32_t index = startRankId; index < endRankId; index++) {
                uint32_t i = index - startRankId;
                beginIdx = rankBeginIdx[i];
                uint32_t winOffset = index;
                winOffset = (index % epRankSize) * moeExpertNumPerRank + index / epRankSize;
                GM_ADDR wAddr = (__gm__ uint8_t *)(GetWindAddrByRankId(epRankId)) + winOffset * expertPerSizeOnWin;
                for (uint32_t j = curTokenIdx[i]; j < countPerRank[i]; j++) {
                    tokGlobal.SetGlobalBuffer((__gm__ int8_t *)(wAddr + j * hCommuSize));
                    tokGlobalInt32.SetGlobalBuffer((__gm__ int32_t *)(wAddr + j * hCommuSize + hOutSize));
                    expandXOutGlobal.SetGlobalBuffer(
                        (__gm__ int8_t *)(gmX1) + (beginIdx + j) * tokenLength, tokenLength);

                    AscendC::DataCopy(tmpLocalTensor, tokGlobalInt32, INT32_COUNT_PER_BLOCK);
                    AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
                    AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
                    if (tmpLocalTensor.GetValue(1) == tokenFlag) {
                        tokGlobalInt32.SetValue(1, 0);
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                        AscendC::DcciDst::CACHELINE_OUT>(tokGlobalInt32[1]);
                        __asm__ __volatile__("");
                    } else {
                        SPIN_WAIT_CYCLES();
                        break;
                    }
                    curRecvTokenCount += 1;
                    curTokenIdx[i] += 1;
                    AscendC::PipeBarrier<PIPE_ALL>();

                    AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
                    AscendC::DataCopy(xTmpTensor_, tokGlobal, axisHCommu);
                    AscendC::SetFlag<AscendC::HardEvent::MTE2_MTE3>(0);
                    AscendC::WaitFlag<AscendC::HardEvent::MTE2_MTE3>(0);
                    AscendC::DataCopyPad(dynamicScalesOutGMTensor_[beginIdx + j],
                        xOutFp32Tensor_[tokenLength / sizeof(float)], dataCopyParamsFloat);
                    AscendC::DataCopy(expandXOutGlobal, xTmpTensor_, tokenLength);
                    AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
                }
            }
        }
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::PipeBarrier<PIPE_ALL>();

        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::DataCopyExtParams dataCopyOutParams = {1U,
                                                        static_cast<uint32_t>(recvRankNumPerCore * sizeof(int32_t)),
                                                        0U, 0U, 0U};
        AscendC::GlobalTensor<int32_t> sendCountsGlobal;
        sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(gmEpSendCount));
        AscendC::DataCopyPad(sendCountsGlobal[startRankId], gatherMaskOutCountTensor, dataCopyOutParams);
    }

    CATLASS_DEVICE
    void RecvCoreFunc(GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmEpSendCount)
    {
        ubOffset = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            AscendC::SyncAll<true>();
            AscendC::SyncAll<true>();
            AscendC::SyncAll<true>();
            ShmemRecvCoreFunc(gmX1, gmX1Scale, gmEpSendCount);
            return;
        }

        RecvCount(ubOffset);

        uint32_t recvExpertNum = expertCntUp;
        uint32_t recvCoreNumPerGroup = recvCoreNum;
        uint32_t recvRankNumPerCore = epRankSize / recvCoreNumPerGroup;
        uint32_t remainderRankNum = epRankSize % recvCoreNumPerGroup;

        uint32_t recvCoreIdxInGroup = recvCoreIdx % recvCoreNumPerGroup;
        uint32_t startRankIdInGroup = recvRankNumPerCore * recvCoreIdxInGroup;
        if (recvCoreIdxInGroup < remainderRankNum) {
            recvRankNumPerCore += 1;
            startRankIdInGroup += recvCoreIdxInGroup;
        } else {
            startRankIdInGroup += remainderRankNum;
        }
        uint32_t endRankIdInGroup = startRankIdInGroup + recvRankNumPerCore;
        uint32_t subUbOffset = CEIL_UP(expertCntUp * UB_BLOCK_SIZE) + CEIL_UP(UB_BLOCK_SIZE) +
                                CEIL_UP(expertCntUp * sizeof(float));
        for (uint32_t groupId = 0; groupId < localExpertNum; ++groupId) {
            uint32_t startRankId = epRankSize * groupId + startRankIdInGroup;
            uint32_t endRankId = epRankSize * groupId + endRankIdInGroup;

            uint32_t coreTokenCount = 0;

            if (startRankId < recvExpertNum) {
                // RecvCount, GetCumSum, RecvToken must use the same ubOffset to get right info
                GetCumSum(startRankId, recvExpertNum, ubOffset);
                RecvToken(gmX1, gmX1Scale, gmEpSendCount, coreTokenCount, startRankId, endRankId,
                        recvRankNumPerCore, ubOffset);
            }

            // recv finish, inform AIC
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::LocalTensor<int32_t> tmpLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(
                                                                                                        subUbOffset);
            tmpLocalTensor.SetValue(CV_FLAG_INDEX, vToCFlag);
            tmpLocalTensor.SetValue(GROUP_ID_INDEX, groupId);
            tmpLocalTensor.SetValue(SELF_COUNT_INDEX, coreTokenCount);
            AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);

            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET));
            AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
            AscendC::SetAtomicAdd<int32_t>();
            AscendC::DataCopy(
                groupTokenNumStateTensor[groupId * GROUP_INFO_SIZE], tmpLocalTensor, INT32_COUNT_PER_BLOCK);
            AscendC::SetAtomicNone();
            AscendC::PipeBarrier<PIPE_ALL>();
        }
    }

    CATLASS_DEVICE
    void CompCoreFunc(GM_ADDR gmCVSwapBuff, __gm__ ElementScale *gmShareMm1Scale, __gm__ ElementScale *gmScale,
                __gm__ ElementPerTokenScale *gmShareTokenScale, __gm__ ElementPerTokenScale *gmTokenScale,
                __gm__ float *gmShareSwigluOutput, __gm__ float *gmSwigluOutput, uint32_t shareN, uint32_t n,
                uint32_t k, LayoutScale layoutShareScale, LayoutScale layoutScale,
                LayoutPerTokenScale wholeLayoutPerTokenScale)
    {
        uint32_t coreNumPerGroup = DISPATCH_RECV_CORE_NUM;
        int64_t gmGroupOffsetScale = 0;
        int64_t gmGroupOffsetPerTokenScale = 0;
        int64_t gmGroupOffsetD = 0;

        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(gmCVSwapBuff));
        auto layoutC = layout::RowMajor{L1TileShape::M * aiCoreGroupNum * WORKSPACE_STAGES, L1TileShape::N};
        {
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource);

            uint32_t stageId = 0;
            uint32_t target = 1;
            uint32_t startCoreIdx = 0;
            AscendC::ListTensorDesc gmScaleListTensor;
            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                // 前面不需要等待，C核已经等待过了
                uint32_t currentM = axisBS;
                GemmCoord inGroupProblemShape{currentM, shareN, k};
                LayoutPerTokenScale layoutPerTokenScale =
                    wholeLayoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = layout::RowMajor{currentM, shareN};

                EpilogueParams epilogueParams{
                    gmShareMm1Scale, layoutShareScale,
                    gmShareTokenScale, layoutPerTokenScale,
                    gmShareSwigluOutput, layoutD
                };

                blockScheduler.Update(inGroupProblemShape, L1TileShape::ToCoordMN());
                blockEpilogue.UpdateParams(epilogueParams);
                uint32_t coreLoops = blockScheduler.GetCoreLoops();

                GemmCoord blockShapeMNK = L1TileShape::ToCoord();
                uint32_t startLoopIdx = ((compCoreIdx < startCoreIdx) ? (compCoreIdx + aiCoreGroupNum) : compCoreIdx)
                                            - startCoreIdx;
                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aiCoreGroupNum) {
                    GemmCoord blockCoordMNK = blockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShapeMNK = blockScheduler.GetActualBlockShape(blockCoordMNK);

                    MatrixCoord offsetC{(stageId * aiCoreGroupNum + aiCoreGroupIdx) * L1TileShape::M, 0};
                    int64_t gmOffsetC = layoutC.GetOffset(offsetC);
                    auto gmBlockC = gmC[gmOffsetC];
                    auto layoutBlockC = layoutC.GetTileLayout(actualBlockShapeMNK.GetCoordMN());
                    CheckSyncFlag(statusDataSpaceGm + SOFT_SYNC_OFFSET,
                        static_cast<uint8_t>(compCoreNum + compCoreIdx), target); // AIV等待的信号在24~28
                    target += 1;
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC, layoutBlockC);
                    EncreaseSyncFlag(statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(compCoreIdx));
                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }
                startCoreIdx = (startCoreIdx + coreLoops) % aiCoreGroupNum;
            }
            gmScaleListTensor = AscendC::ListTensorDesc(reinterpret_cast<__gm__ void *>(gmScale));
            __gm__ ElementScale* gmScalePtr;
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(gmScaleListTensor.GetDataPtr<int32_t>(0));
            }
            for (uint32_t groupIdx = 0; groupIdx < localExpertNum; ++groupIdx) {
                // just like AIC
                groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)
                                                         (statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET) +
                                                         groupIdx * GROUP_INFO_SIZE);
                while (true) {
                    __asm__ __volatile__("");
                    AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                    AscendC::DcciDst::CACHELINE_OUT>(groupTokenNumStateTensor);
                    __asm__ __volatile__("");
                    if (groupTokenNumStateTensor.GetValue(0) == coreNumPerGroup * vToCFlag) {
                        break;
                    }
                    SPIN_WAIT_CYCLES();
                }
                uint32_t currentM = groupTokenNumStateTensor.GetValue(GROUP_TOKEN_COUNT);
                GemmCoord inGroupProblemShape{currentM, n, k};
                LayoutPerTokenScale layoutPerTokenScale =
                    wholeLayoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = layout::RowMajor{currentM, n};
                EpilogueParams epilogueParams;
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                                                gmScalePtr, layoutScale,
                                                gmTokenScale + gmGroupOffsetPerTokenScale, layoutPerTokenScale,
                                                gmSwigluOutput + gmGroupOffsetD, layoutD};
                } else {
                    epilogueParams = EpilogueParams{gmScalePtr + gmGroupOffsetScale,
                                                layoutScale,
                                                gmTokenScale + gmGroupOffsetPerTokenScale,
                                                layoutPerTokenScale,
                                                gmSwigluOutput + gmGroupOffsetD,
                                                layoutD};
                }
                blockScheduler.Update(inGroupProblemShape, L1TileShape::ToCoordMN());
                blockEpilogue.UpdateParams(epilogueParams);
                uint32_t coreLoops = blockScheduler.GetCoreLoops();

                GemmCoord blockShapeMNK = L1TileShape::ToCoord();
                uint32_t startLoopIdx =
                    ((compCoreIdx < startCoreIdx) ? (compCoreIdx + aiCoreGroupNum) : compCoreIdx) - startCoreIdx;
                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aiCoreGroupNum) {
                    GemmCoord blockCoordMNK = blockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShapeMNK = blockScheduler.GetActualBlockShape(blockCoordMNK);

                    MatrixCoord offsetC{(stageId * aiCoreGroupNum + aiCoreGroupIdx) * L1TileShape::M, 0};
                    int64_t gmOffsetC = layoutC.GetOffset(offsetC);
                    auto gmBlockC = gmC[gmOffsetC];
                    auto layoutBlockC = layoutC.GetTileLayout(actualBlockShapeMNK.GetCoordMN());
                    CheckSyncFlag(statusDataSpaceGm + SOFT_SYNC_OFFSET,
                        static_cast<uint8_t>(compCoreNum + compCoreIdx), target);
                    target += 1;
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC, layoutBlockC);
                    EncreaseSyncFlag(statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(compCoreIdx));
                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }

                if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                    gmGroupOffsetScale += inGroupProblemShape.n();
                }
                gmGroupOffsetPerTokenScale += inGroupProblemShape.m();
                gmGroupOffsetD += currentM * n;

                startCoreIdx = (startCoreIdx + coreLoops) % aiCoreGroupNum;
            }
        }
        // clean
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void AivInitParams(Params const &params)
    {
        aiCoreGroupNum = AscendC::GetBlockNum();
        subBlockNum = AscendC::GetSubBlockNum();  // 1C2V
        aicNum = aiCoreGroupNum;
        aivNum = aiCoreGroupNum * subBlockNum;
        aivIdx = AscendC::GetBlockIdx();
        aiCoreGroupIdx = aivIdx / subBlockNum;
        aivStateGlobalCoreIdx = aivNum + aicNum + aivIdx;

        isCompCore = true;
        compCoreNum = aiCoreGroupNum;
        compCoreIdx = aiCoreGroupIdx;
        // when localExpertNum=1, all cores send token and recv token in sequence
        isRecvCore = true;
        isSendCore = true;
        recvCoreIdx = aivIdx;
        sendCoreIdx = aivIdx;
        sendCoreNum = aivNum;
        recvCoreNum = aivNum;

        moeExpertNumPerRank = params.moeExpertNumPerRank;

        epRankSize = params.epRankSize;
        epRankId = params.epRankId;
        expertCntUp = epRankSize * moeExpertNumPerRank;
        localExpertNum = moeExpertNumPerRank;
        moeExpertNum = params.moeExpertNum;
        tokenLength = params.tokenLen;
        metaInfoGm = params.metaInfoGm;

        // when localExpertNum>1, all cores do layout phase first,
        // then half do ShmemSendToMoeExprt and half do ShmemRecvCoreFunc
        if (localExpertNum > 1) {
            isSendCore = true;
            isRecvCore = (aivIdx >= aiCoreGroupNum);
            sendCoreIdx = aivIdx;
            sendCoreNum = aivNum;
            recvCoreIdx = aivIdx - aiCoreGroupNum;
            recvCoreNum = aiCoreGroupNum;
        }
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            // 接收核参与计算共享专家量化
            isShareQuantCore = true;
            shareQuantCoreNum = aivNum;
            shareQuantCoreIdx = aivIdx;
        }

        hOutSize = tokenLength * sizeof(int8_t);
        scaleParamPad = TOKEN_EXTRA_SPACE;  // 512B for dynamic quant scale
        hCommuSize = hOutSize + scaleParamPad;
        axisHCommu = hCommuSize / sizeof(int8_t);
        axisBS = params.bs;
        activeMaskBsCnt = axisBS;
        axisK = params.topK;
        uint32_t maxAxisBs = params.globalBs / epRankSize;

        stateOffset = STATE_OFFSET;
        expertPerSizeOnWin = maxAxisBs * tokenLength * sizeof(XType);
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            uint64_t offset = aivNum * UB_32B_ALIGN + epRankSize * UB_32B_ALIGN +
                          moeExpertNum * sizeof(int32_t) +
                          4 * epRankSize * sizeof(uint64_t);
            statusDataSpaceGm = metaInfoGm + offset;
            gmTokenFlagGm = params.gmTokenFlag;
        } else {
            winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
            statusDataSpaceGm = (GM_ADDR)(winContext_->localWindowsExp);
        }
    }

    CATLASS_DEVICE
    void AivInitState()
    {
        // state of data sapce
        AscendC::GlobalTensor<int32_t> selfDataStatusTensor;
        selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(selfDataStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        dataState = selfDataStatusTensor(aivIdx * UB_ALIGN);
        if (dataState == 0) {
            selfDataStatusTensor(aivIdx * UB_ALIGN) = 1;
        } else {
            selfDataStatusTensor(aivIdx * UB_ALIGN) = 0;
        }
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(selfDataStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");

        // state of cv flag
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aivStateGlobalCoreIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        cvDataState = selfDataStatusTensor(aivStateGlobalCoreIdx * UB_ALIGN);
        if (cvDataState == 0) {
            selfDataStatusTensor(aivStateGlobalCoreIdx * UB_ALIGN) = 1;
            vToCFlag = V_TO_C_FLAG_1;
        } else {
            selfDataStatusTensor(aivStateGlobalCoreIdx * UB_ALIGN) = 0;
            vToCFlag = V_TO_C_FLAG_2;
        }
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aivStateGlobalCoreIdx * UB_ALIGN]);
        __asm__ __volatile__("");

        AscendC::PipeBarrier<PIPE_ALL>();
        winDataSizeOffset = dataState * epRankSize * expertPerSizeOnWin * moeExpertNumPerRank;
        GM_ADDR statusSpaceGm_;
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            uint64_t offset = aivNum * UB_32B_ALIGN + epRankSize * UB_32B_ALIGN +
                          moeExpertNum * sizeof(int32_t) +
                          4 * epRankSize * sizeof(uint64_t);
            statusSpaceGm_ = GetShmemStateAddrByOffset(epRankId, offset);
        } else {
            statusSpaceGm_ = GetWindStateAddrByRankId(epRankId);
        }
        AscendC::GlobalTensor<int32_t> selfStatusTensor;
        selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusSpaceGm_ + SELF_STATE_OFFSET));
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(selfStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        state = selfStatusTensor(aivIdx * UB_ALIGN);
        if (state == 0) {
            sumTarget = (float)1.0;
            tokenFlag = TOKEN_FLAG_1;
            selfStatusTensor(aivIdx * UB_ALIGN) = 0x3F800000;
            exp_flag_ = (float)1.0;
        } else {
            sumTarget = 0.0;
            tokenFlag = TOKEN_FLAG_2;
            selfStatusTensor(aivIdx * UB_ALIGN) = 0;
            exp_flag_ = (float)CROSS_RANK_SYNC_FLAG;
        }
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(selfStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");
    }

    CATLASS_DEVICE
    void UpdateAndCleanInfo(__gm__ ElementGroupList_ *ptrGroupList, GM_ADDR gmEpSendCount, GM_ADDR gmExpertTokenNums)
    {
        if (isCompCore) {
            // 清理软同步残留信息，避免影响别处或者下次运行
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer((__gm__ int32_t*)(statusDataSpaceGm + SOFT_SYNC_OFFSET));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(0);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, INT32_COUNT_PER_BLOCK);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            if (AscendC::GetSubBlockIdx() == 0) {
                // 前一半为V核写的Flag
                AscendC::DataCopy(softSyncTensor[compCoreIdx * SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                                                    tmpZeroLocalTensor, INT32_COUNT_PER_BLOCK);
                // 后一半为C核写的Flag
                AscendC::DataCopy(softSyncTensor[(compCoreIdx + compCoreNum)
                                * SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)], tmpZeroLocalTensor, INT32_COUNT_PER_BLOCK);
            } else {
                AscendC::DataCopy(softSyncTensor[compCoreIdx * SOFT_SYNC_SPACE_SIZE / sizeof(int32_t) +
                                    (SOFT_SYNC_SPACE_SIZE / SUB_AIV_NUM / sizeof(int32_t))],
                                    tmpZeroLocalTensor, INT32_COUNT_PER_BLOCK);
            }
        }
        if (aivIdx == aiCoreGroupNum * subBlockNum - 1) {
            // clean
            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(512);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, GROUP_INFO_SIZE * localExpertNum);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopy(groupTokenNumStateTensor, tmpZeroLocalTensor, GROUP_INFO_SIZE * localExpertNum);
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
                shareQuantTokenStateTensor.SetGlobalBuffer(
                    (__gm__ int32_t*)(statusDataSpaceGm + SHARE_QUANT_SOFT_SYNC_OFFSET));
                AscendC::DataCopy(shareQuantTokenStateTensor, tmpZeroLocalTensor, 8);
            }
        }

        if (isRecvCore && recvCoreIdx == (recvCoreNum - 1)) {
            // record token count for each local expert
            AscendC::GlobalTensor<int64_t> expertTokenNumsOutGMTensor_;
            expertTokenNumsOutGMTensor_.SetGlobalBuffer((__gm__ int64_t *)(ptrGroupList));
            AscendC::GlobalTensor<int32_t> sendCountsGlobal;
            sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(gmEpSendCount));
            AscendC::GlobalTensor<int64_t> nonCumSumExpertTokenNumsTensor;
            nonCumSumExpertTokenNumsTensor.SetGlobalBuffer((__gm__ int64_t *)gmExpertTokenNums);
            uint32_t tmpTokenNum = 0;
            for (uint32_t localMoeIndex = 0; localMoeIndex < localExpertNum; ++localMoeIndex) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                AscendC::DcciDst::CACHELINE_OUT>(
                    sendCountsGlobal[localMoeIndex * epRankSize + epRankSize - 1]);
                __asm__ __volatile__("");

                uint32_t tokenNum = sendCountsGlobal.GetValue(localMoeIndex * epRankSize + epRankSize - 1);
                expertTokenNumsOutGMTensor_.SetValue(localMoeIndex, tokenNum);
                uint32_t nonCumSumTokenNum = tokenNum - tmpTokenNum;
                nonCumSumExpertTokenNumsTensor.SetValue(localMoeIndex, nonCumSumTokenNum);
                tmpTokenNum = tokenNum;

                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int64_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                AscendC::DcciDst::CACHELINE_OUT>(
                    expertTokenNumsOutGMTensor_[localMoeIndex]);
                __asm__ __volatile__("");
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int64_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                AscendC::DcciDst::CACHELINE_OUT>(
                    nonCumSumExpertTokenNumsTensor[localMoeIndex]);
                __asm__ __volatile__("");
            }
        }
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIV>(Params const &params)
    {
        AivInitParams(params);
        AivInitState();
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            if (isShareQuantCore) {
                shareQuantCoreFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmShareSmoothScales,
                                    (GM_ADDR)params.gmShareX1, (GM_ADDR)params.gmShareX1Scale);
            }
        }
        if (localExpertNum > 1 && (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER)) {
            // all cores do layout phase first
            SendCoreLayoutFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmexpertIds, (GM_ADDR)params.gmMoeSmoothScales,
                        (GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale, (GM_ADDR)params.gmExpandIdx,
                        (GM_ADDR)params.gmXActiveMask, (GM_ADDR)params.gmEpSendCount,
                        (GM_ADDR)params.gmAllExpertTokenNums, (GM_ADDR)params.gmCombineSend);
            // 36 aiv-core do SendCoreDataFunc, 12 aiv-core do RecvCoreFunc
            isRecvCore = aivIdx >= DISPATCH_SEND_CORE_NUM;
            isSendCore = aivIdx < DISPATCH_SEND_CORE_NUM;
            recvCoreIdx = aivIdx - DISPATCH_SEND_CORE_NUM;
            sendCoreIdx = aivIdx;
            sendCoreNum = DISPATCH_SEND_CORE_NUM;
            recvCoreNum = DISPATCH_RECV_CORE_NUM;
            if (!isRecvCore) {
                SendCoreDataFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmExpandIdx,
                            (GM_ADDR)params.gmMoeSmoothScales, (GM_ADDR)params.gmEpSendCount,
                            (GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale);
            } else {
                ShmemRecvCoreFunc((GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale,
                    (GM_ADDR)params.gmEpSendCount);
            }
        } else {
            if (isSendCore) {
                SendCoreFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmexpertIds, (GM_ADDR)params.gmMoeSmoothScales,
                            (GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale, (GM_ADDR)params.gmExpandIdx,
                            (GM_ADDR)params.gmXActiveMask, (GM_ADDR)params.gmEpSendCount,
                            (GM_ADDR)params.gmAllExpertTokenNums, (GM_ADDR)params.gmCombineSend);
            }
            if (isRecvCore) {
                RecvCoreFunc((GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale, (GM_ADDR)params.gmEpSendCount);
            }
        }

        isRecvCore = ((aivIdx % ODD_EVEN_BASE) == 0);
        isSendCore = ((aivIdx % ODD_EVEN_BASE) == 1);
        recvCoreIdx = aivIdx / subBlockNum;
        sendCoreIdx = aivIdx / subBlockNum;
        sendCoreNum = aiCoreGroupNum;
        recvCoreNum = aiCoreGroupNum;

        auto gmSwigluOutput = reinterpret_cast<__gm__ float *>(params.gmSwigluOut);
        auto gmShareSwigluOutput = reinterpret_cast<__gm__ float *>(params.gmShareSwigluOut);
        if (isCompCore) {
            CompCoreFunc(params.ptrWorkspace, params.ptrShareScale,  params.ptrScale,
                (__gm__ float*)params.gmShareX1Scale, (__gm__ float*)params.ptrPerTokenScale,
                gmShareSwigluOutput, gmSwigluOutput, params.shareN, params.problemShape.n(), params.problemShape.k(),
                params.layoutShareScale, params.layoutScale, params.layoutPerTokenScale);
        }

        icache_preload(8);
        AscendC::SyncAll<false>();
        AscendC::PipeBarrier<PIPE_ALL>();

        UpdateAndCleanInfo(params.ptrGroupList, params.gmEpSendCount +
            epRankId * epRankSize * moeExpertNumPerRank * sizeof(int32_t), params.gmExpertTokenNums);
        AscendC::PipeBarrier<PIPE_ALL>();
        uint32_t startCoreIdx = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            // dynamic quant
            totalTokenCount = axisBS;
            uint32_t n = params.shareN;
            uint32_t nOut = params.shareN / 2;
            uint32_t quantRowOnce = 0;
            CalQuantRow(nOut, quantRowOnce);
            typename BlockQuant<ArchTag>::Params quantParams;
            auto swigluLayout = layout::RowMajor{totalTokenCount, n};
            quantParams = typename BlockQuant<ArchTag>::Params {
                (__gm__ float*)params.gmShareSwigluOut, swigluLayout,  // input: swiglu output
                (__gm__ float*)params.gmShareX2Scale, params.layoutDequantScale,  // output: quant token scale
                (__gm__ int8_t*)params.gmShareX2, params.layoutShareOutput, // output: x2
                quantRowOnce,           nOut};
            BlockQuant<ArchTag> blockQuant(resource, quantParams);
            MatrixCoord quantShape(totalTokenCount, nOut);
            MatrixCoord quantBlockShape((uint16_t)(subBlockNum * quantRowOnce), nOut);
            Epilogue::Tile::EpilogueHorizontalTileSwizzle quantSwizzle(quantShape, quantBlockShape);
            uint32_t coreLoops = quantSwizzle.GetLoops();
            uint32_t startLoopIdx =
                        ((sendCoreIdx < startCoreIdx) ? (sendCoreIdx + aiCoreGroupNum) : sendCoreIdx) - startCoreIdx;
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aiCoreGroupNum) {
                auto blockCoord = quantSwizzle.GetTileCoord(loopIdx);
                auto actualBlockShape = quantSwizzle.GetActualTileShape(blockCoord);
                blockQuant(quantBlockShape, blockCoord, actualBlockShape);
            }
            startCoreIdx = (startCoreIdx + coreLoops) % aiCoreGroupNum;
            AscendC::PipeBarrier<PIPE_ALL>();
        }
        {
            // dynamic quant
            AscendC::GlobalTensor<int32_t> sendCountsGlobal;
            sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(params.gmEpSendCount +
                epRankId * epRankSize * moeExpertNumPerRank  * sizeof(int32_t)));
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                            AscendC::DcciDst::CACHELINE_OUT>(sendCountsGlobal);
            __asm__ __volatile__("");
            totalTokenCount = sendCountsGlobal.GetValue(localExpertNum * epRankSize - 1);
            AscendC::PipeBarrier<PIPE_ALL>();
            uint32_t n = params.problemShape.n();
            uint32_t nOut = params.problemShape.n() / 2;
            uint32_t quantRowOnce = 0;
            CalQuantRow(nOut, quantRowOnce);
            typename BlockQuant<ArchTag>::Params quantParams;
            auto swigluLayout = layout::RowMajor{totalTokenCount, n};
            quantParams = typename BlockQuant<ArchTag>::Params {
                gmSwigluOutput,   swigluLayout,        params.ptrDequantScale, params.layoutDequantScale,
                params.ptrOutput, params.layoutOutput, quantRowOnce,           nOut};
            BlockQuant<ArchTag> blockQuant(resource, quantParams);
            MatrixCoord quantShape(totalTokenCount, nOut);
            MatrixCoord quantBlockShape((uint16_t)(subBlockNum * quantRowOnce), nOut);
            Epilogue::Tile::EpilogueHorizontalTileSwizzle quantSwizzle(quantShape, quantBlockShape);
            uint32_t coreLoops = quantSwizzle.GetLoops();
            uint32_t startLoopIdx =
                    ((sendCoreIdx < startCoreIdx) ? (sendCoreIdx + aiCoreGroupNum) : sendCoreIdx) - startCoreIdx;
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aiCoreGroupNum) {
                auto blockCoord = quantSwizzle.GetTileCoord(loopIdx);
                auto actualBlockShape = quantSwizzle.GetActualTileShape(blockCoord);
                blockQuant(quantBlockShape, blockCoord, actualBlockShape);
            }
        }
    }

private:
    friend struct AicWaitFunc1;
    friend struct AicSetFunc1;

    struct AicWaitFunc1 {
        CATLASS_DEVICE
        AicWaitFunc1() = default;

        CATLASS_DEVICE
        AicWaitFunc1(__gm__ uint8_t *flagAddr, uint8_t idx, uint32_t target) :
            flagAddr(flagAddr), idx(idx), target(target) {}

        CATLASS_DEVICE
        void operator()() const
        {
            CheckSyncFlag(flagAddr, idx, target);
        }

        __gm__ uint8_t *flagAddr;
        uint8_t idx;
        uint32_t target;
    };

    struct AicSetFunc1 {
        CATLASS_DEVICE
        AicSetFunc1() = default;

        CATLASS_DEVICE
        AicSetFunc1(__gm__ uint8_t *flagAddr, uint8_t idx) : flagAddr(flagAddr), idx(idx) {}

        CATLASS_DEVICE
        void operator()() const
        {
            EncreaseSyncFlag(flagAddr, idx);
        }

        __gm__ uint8_t *flagAddr;
        uint8_t idx;
    };

    AicWaitFunc1 aicWaitFunc1;
    AicSetFunc1 aicSetFunc1;
    Arch::Resource<ArchTag> resource;

    AscendC::LocalTensor<int32_t> expertIdsTensor_;
    AscendC::GlobalTensor<int32_t> expertIdsGMTensor_;
    uint32_t startTokenId_{0};
    uint32_t endTokenId_{0};
    uint32_t localTokenNum_{0};
    // count info
    int32_t countPerRank[16]{0};
    int32_t curTokenIdx[16]{0};
    int32_t rankBeginIdx[16]{0};

    // rank and expert info
    uint32_t epRankSize{0};
    uint32_t epRankId{0};
    uint32_t expertCntUp{0};
    uint32_t localExpertNum{0};
    uint32_t moeExpertNumPerRank{0};
    uint32_t moeExpertNum{0};

    // token info
    uint32_t hOutSize{0};
    uint32_t scaleParamPad{0};
    uint32_t hCommuSize{0};
    uint32_t axisHCommu{0};
    uint32_t axisBS{0};
    uint32_t activeMaskBsCnt{0};
    uint32_t axisK{0};
    uint32_t totalTokenCount{0};
    uint32_t expertIdsCnt{0};
    uint32_t tokenLength{0};
    bool useFullExpertIdsCopy_{false};  // 是否全量拷贝 expertIds

    // state info
    int32_t tokenFlag{0};    // token flag
    int32_t vToCFlag{0};     // cv flag, decided by cvDataState
    int32_t dataState{0};    // data space state
    int32_t cvDataState{0};  // cv flag state
    int32_t state{0};        // count flag state
    int32_t magicVal_{0};    // magic value for SHMEM sync
    float exp_flag_{0.0f};   // magic value转换为float，用于范围比较
    float sumTarget{0.0};

    // memory info
    __gm__ HcclOpResParam *winContext_;
    GM_ADDR statusDataSpaceGm;
    GM_ADDR metaInfoGm;
    GM_ADDR gmTokenFlagGm;
    uint32_t stateOffset{0};
    uint64_t expertPerSizeOnWin{0};
    uint64_t winDataSizeOffset{0};

    int64_t ubOffset;

    // core info
    bool isSendCore{false};
    bool isRecvCore{false};
    bool isCompCore{false};  // calculate deq_swiglu
    bool isShareQuantCore{false}; // calculate share quant
    uint32_t aiCoreGroupNum{0};
    uint32_t aiCoreGroupIdx{0};
    uint32_t subBlockNum{0};
    uint32_t aicNum{0};
    uint32_t aivNum{0};
    uint32_t sendCoreNum{0};
    uint32_t recvCoreNum{0};
    uint32_t compCoreNum{0};
    uint32_t shareQuantCoreNum{0};
    uint32_t aivIdx{0};
    uint32_t aicIdx{0};
    uint32_t sendCoreIdx{0};
    uint32_t recvCoreIdx{0};
    uint32_t compCoreIdx{0};
    uint32_t shareQuantCoreIdx{0};
    uint32_t aivStateGlobalCoreIdx{0};
    uint32_t aicStateGlobalCoreIdx{0};
    uint32_t sendToMoeAivNum{0};
    uint32_t sendToShareAivNum{0};
};

}  // namespace Catlass::Gemm::Kernel

namespace Catlass::Gemm::Kernel {

template <TemplateMC2TypeClass, class BlockMmad_, class BlockEpilogue_, class BlockScheduler_,
            uint32_t WORKSPACE_STAGES_, class ElementGroupList_>
class GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspaceWithShallowDispatch {
public:
    using BlockMmad = BlockMmad_;
    using ArchTag = typename BlockMmad::ArchTag;
    using L1TileShape = typename BlockMmad::L1TileShape;
    using ElementA = typename BlockMmad::ElementA;
    using LayoutA = typename BlockMmad::LayoutA;
    using ElementB = typename BlockMmad::ElementB;
    using LayoutB = typename BlockMmad::LayoutB;
    using ElementC = typename BlockMmad::ElementC;
    using LayoutC = typename BlockMmad::LayoutC;
    using ElementAccumulator = typename BlockMmad::ElementAccumulator;

    using BlockEpilogue = BlockEpilogue_;
    using ElementScale = typename BlockEpilogue::ElementRawScale;
    using LayoutScale = typename BlockEpilogue::LayoutScale;
    using ElementPerTokenScale = typename BlockEpilogue::ElementPerTokenScale;
    using LayoutPerTokenScale = typename BlockEpilogue::LayoutPerTokenScale;
    using ElementD = typename BlockEpilogue::ElementD;
    using LayoutD = typename BlockEpilogue::LayoutD;
    using EpilogueParams = typename BlockEpilogue::Params;

    using ElementDequantScale = typename BlockQuant<ArchTag>::ElementDequantScale;
    using LayoutDequantScale = typename BlockQuant<ArchTag>::LayoutDequantScale;
    using ElementOutput = typename BlockQuant<ArchTag>::ElementOutput;
    using LayoutOutput = typename BlockQuant<ArchTag>::LayoutOutput;

    using BlockScheduler = BlockScheduler_;
    static constexpr uint32_t WORKSPACE_STAGES = WORKSPACE_STAGES_;
    using ElementGroupList = ElementGroupList_;

    /// Parameters structure
    struct Params {
        // Data members
        GemmCoord problemShape;
        uint32_t problemCount;
        __gm__ ElementGroupList_ *ptrGroupList;
        __gm__ ElementA *ptrA;
        LayoutA layoutA;
        __gm__ ElementB *ptrShareB;
        LayoutB layoutShareB;
        __gm__ ElementB *ptrB;
        LayoutB layoutB;
        __gm__ ElementScale *ptrShareScale;
        LayoutScale layoutShareScale;
        __gm__ ElementScale *ptrScale;
        LayoutScale layoutScale;
        __gm__ ElementPerTokenScale *ptrPerTokenScale;
        LayoutPerTokenScale layoutPerTokenScale;
        __gm__ ElementOutput *ptrOutput;
        LayoutOutput layoutOutput;
        __gm__ ElementDequantScale *ptrDequantScale;
        LayoutDequantScale layoutDequantScale;
        GM_ADDR ptrWorkspace;

        GM_ADDR gmShareX1;
        GM_ADDR gmShareX1Scale;
        GM_ADDR gmShareSwigluOut;
        GM_ADDR gmShareX2;
        LayoutOutput layoutShareOutput;
        GM_ADDR gmShareX2Scale;
        GM_ADDR gmSwigluOut;
        uint32_t bs;
        uint32_t shareN;
        // Methods
        CATLASS_DEVICE
        Params() {}

        CATLASS_DEVICE
        Params(GemmCoord problemShape_, uint32_t problemCount_, GM_ADDR ptrGroupList_, GM_ADDR ptrA_,
               LayoutA const &layoutA_, GM_ADDR ptrShareB_, LayoutB const &layoutShareB_, GM_ADDR ptrB_,
               LayoutB const &layoutB_, GM_ADDR ptrShareScale_, LayoutScale const &layoutShareScale_,
               GM_ADDR ptrScale_, LayoutScale const &layoutScale_, GM_ADDR ptrPerTokenScale_,
               LayoutPerTokenScale const &layoutPerTokenScale_, GM_ADDR ptrOutput_, LayoutOutput const &layoutOutput_,
               GM_ADDR ptrDequantScale_, LayoutDequantScale const &layoutDequantScale_, GM_ADDR ptrWorkspace_,
               GM_ADDR gmShareX1_, GM_ADDR gmShareX1Scale_, GM_ADDR gmShareSwigluOut_, GM_ADDR gmShareX2_,
               LayoutOutput const &layoutShareOutput_, GM_ADDR gmShareX2Scale_, GM_ADDR gmSwigluOut_,
               const FusedDeepMoeInfo &disGmmDeqSwigluQuantGmmDeqComInfo)
            : problemShape(problemShape_),
              problemCount(problemCount_),
              ptrGroupList(reinterpret_cast<__gm__ ElementGroupList *>(ptrGroupList_)),
              ptrA(reinterpret_cast<__gm__ ElementA *>(ptrA_)),
              layoutA(layoutA_),
              ptrShareB(reinterpret_cast<__gm__ ElementB *>(ptrShareB_)),
              layoutShareB(layoutShareB_),
              ptrB(reinterpret_cast<__gm__ ElementB *>(ptrB_)),
              layoutB(layoutB_),
              ptrShareScale(reinterpret_cast<__gm__ ElementScale *>(ptrShareScale_)),
              layoutShareScale(layoutShareScale_),
              ptrScale(reinterpret_cast<__gm__ ElementScale *>(ptrScale_)),
              layoutScale(layoutScale_),
              ptrPerTokenScale(reinterpret_cast<__gm__ ElementPerTokenScale *>(ptrPerTokenScale_)),
              layoutPerTokenScale(layoutPerTokenScale_),
              ptrOutput(reinterpret_cast<__gm__ ElementOutput *>(ptrOutput_)),
              layoutOutput(layoutOutput_),
              ptrDequantScale(reinterpret_cast<__gm__ ElementDequantScale *>(ptrDequantScale_)),
              layoutDequantScale(layoutDequantScale_),
              ptrWorkspace(ptrWorkspace_),
              gmShareX1(gmShareX1_),
              gmShareX1Scale(gmShareX1Scale_),
              gmShareSwigluOut(gmShareSwigluOut_),
              gmShareX2(gmShareX2_),
              layoutShareOutput(layoutShareOutput_),
              gmShareX2Scale(gmShareX2Scale_),
              gmSwigluOut(gmSwigluOut_),
              bs(disGmmDeqSwigluQuantGmmDeqComInfo.bs),
              shareN(disGmmDeqSwigluQuantGmmDeqComInfo.shareGmm1HLen)
        {}
    };

    // Methods
    CATLASS_DEVICE
    GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspaceWithShallowDispatch()
    {
        Arch::FlagID flagId = 0;
        for (uint32_t stageId = 0; stageId < WORKSPACE_STAGES; ++stageId) {
            flagAicFinishStoreList[stageId] = Arch::CrossCoreFlag(flagId++);
            flagAivFinishComputeList[stageId] = Arch::CrossCoreFlag(flagId++);
            aicWaitFuncList[stageId] = {this, stageId};
            aicSetFuncList[stageId] = {this, stageId};
        }
    }

    template <int32_t CORE_TYPE = g_coreType>
    CATLASS_DEVICE void operator()(Params const &params);

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIC>(Params const &params)
    {
        BlockScheduler blockScheduler;
        BlockMmad blockMmad(resource);

        // Represent the full gm
        AscendC::GlobalTensor<ElementA> gmA;
        AscendC::GlobalTensor<ElementB> gmB;
        AscendC::ListTensorDesc gmBlistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrB));
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(gmBlistTensorDesc.GetDataPtr<int32_t>(0)));
        }
        AscendC::GlobalTensor<ElementGroupList> groupList;
        groupList.SetGlobalBuffer(params.ptrGroupList);

        uint32_t coreIdx = AscendC::GetBlockIdx();
        uint32_t coreNum = AscendC::GetBlockNum();
        int64_t gmGroupOffsetA = 0;
        int64_t gmGroupOffsetB = 0;

        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        auto layoutC = layout::RowMajor{L1TileShape::M * coreNum * WORKSPACE_STAGES, L1TileShape::N};

        uint32_t stageId = 0;
        uint32_t stageUsed = 0;
        uint32_t startCoreIdx = 0;

        // Process shared expert first if enabled
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            gmA.SetGlobalBuffer((__gm__ ElementA*)params.gmShareX1);
            gmB.SetGlobalBuffer((__gm__ ElementB*)params.ptrShareB);
            gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_DISABLE);

            uint32_t currentM = params.bs;
            GemmCoord inGroupProblemShape{currentM, params.shareN, params.problemShape.k()};
            LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
            LayoutB layoutB = params.layoutShareB;
            blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
            uint32_t coreLoops = blockScheduler.GetCoreLoops();

            uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                Callback callbackBeforeFixpipe{};
                if (stageUsed == WORKSPACE_STAGES) {
                    callbackBeforeFixpipe = MakeCallback(&aicWaitFuncList[stageId]);
                } else {
                    ++stageUsed;
                }
                Callback callbackAfterFixpipe = MakeCallback(&aicSetFuncList[stageId]);

                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
                int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                int64_t gmOffsetC = layoutC.GetOffset(offsetC);

                if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                    blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB,
                              gmC[gmOffsetC], layoutC, actualBlockShape, callbackBeforeFixpipe, callbackAfterFixpipe);
                } else {
                    callbackBeforeFixpipe();
                    blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB,
                              gmC[gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }

                stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
            }
            startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
        }

        // Process routing experts
        gmA.SetGlobalBuffer(params.ptrA);
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(gmBlistTensorDesc.GetDataPtr<int32_t>(0)));
        }
        for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
            if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(
                        gmBlistTensorDesc.GetDataPtr<int32_t>(groupIdx)));
            }
            uint32_t currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                                : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
            GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

            LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
            LayoutB layoutB = params.layoutB;

            blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
            uint32_t coreLoops = blockScheduler.GetCoreLoops();

            // Determine the starting loopIdx of the current core under the current groupIdx
            uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
            // Loop through the matmul of each groupIdx
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                // Compute block location
                GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                Callback callbackBeforeFixpipe{};
                if (stageUsed == WORKSPACE_STAGES) {
                    callbackBeforeFixpipe = MakeCallback(&aicWaitFuncList[stageId]);
                } else {
                    ++stageUsed;
                }
                Callback callbackAfterFixpipe = MakeCallback(&aicSetFuncList[stageId]);

                // Compute initial location in logical coordinates
                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
                int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                int64_t gmOffsetC = layoutC.GetOffset(offsetC);

                // Compute block-scoped matrix multiply-add
                if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmOffsetC], layoutC, actualBlockShape, callbackBeforeFixpipe, callbackAfterFixpipe);
                } else {
                    callbackBeforeFixpipe();
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }

                stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
            }

            gmGroupOffsetA += inGroupProblemShape.m() * inGroupProblemShape.k();
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmGroupOffsetB += inGroupProblemShape.k() * inGroupProblemShape.n();
            }

            startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
        }

        if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
            blockMmad.SynchronizeBlock();
        }

        while (stageUsed > 0) {
            uint32_t aivComputeStageId =
                (stageId >= stageUsed) ? (stageId - stageUsed) : (stageId + WORKSPACE_STAGES - stageUsed);
            Arch::CrossCoreWaitFlag(flagAivFinishComputeList[aivComputeStageId]);
            --stageUsed;
        }
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIV>(Params const &params)
    {
        uint32_t coreIdx = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
        uint32_t coreNum = AscendC::GetBlockNum();
        int64_t gmGroupOffsetScale = 0;
        int64_t gmGroupOffsetPerTokenScale = 0;
        int64_t gmGroupOffsetD = 0;

        AscendC::GlobalTensor<ElementGroupList> groupList;
        groupList.SetGlobalBuffer(params.ptrGroupList);

        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        auto layoutC = layout::RowMajor{L1TileShape::M * coreNum * WORKSPACE_STAGES, L1TileShape::N};

        auto ptrD = reinterpret_cast<__gm__ float *>(
            params.gmSwigluOut);

        uint32_t mActual = groupList.GetValue(params.problemCount - 1);
        uint32_t n = params.problemShape.n();
        uint32_t nOut = params.problemShape.n() / 2;

        {
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource);

            uint32_t stageId = 0;
            uint32_t startCoreIdx = 0;
            AscendC::ListTensorDesc gmScaleListTensor;
            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;

            // Process shared expert first if enabled
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                uint32_t currentM = params.bs;
                GemmCoord inGroupProblemShape{currentM, params.shareN, params.problemShape.k()};
                LayoutPerTokenScale layoutPerTokenScale =
                    params.layoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = layout::RowMajor{currentM, params.shareN};

                EpilogueParams epilogueParams{
                    params.ptrShareScale, params.layoutShareScale,
                    reinterpret_cast<__gm__ float*>(params.gmShareX1Scale), layoutPerTokenScale,
                    reinterpret_cast<__gm__ float*>(params.gmShareSwigluOut), layoutD
                };

                blockScheduler.Update(inGroupProblemShape, L1TileShape::ToCoordMN());
                blockEpilogue.UpdateParams(epilogueParams);
                uint32_t coreLoops = blockScheduler.GetCoreLoops();

                GemmCoord blockShapeMNK = L1TileShape::ToCoord();
                uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                    GemmCoord blockCoordMNK = blockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShapeMNK = blockScheduler.GetActualBlockShape(blockCoordMNK);

                    MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
                    int64_t gmOffsetC = layoutC.GetOffset(offsetC);
                    auto gmBlockC = gmC[gmOffsetC];
                    auto layoutBlockC = layoutC.GetTileLayout(actualBlockShapeMNK.GetCoordMN());

                    Arch::CrossCoreWaitFlag(flagAicFinishStoreList[stageId]);
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC, layoutBlockC);
                    Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(flagAivFinishComputeList[stageId]);

                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }
                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
            }

            gmScaleListTensor = AscendC::ListTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrScale));
            __gm__ ElementScale* gmScalePtr;
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(gmScaleListTensor.GetDataPtr<int32_t>(0));
            }
            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                uint32_t currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                                : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

                LayoutScale layoutScale = params.layoutScale;
                LayoutPerTokenScale layoutPerTokenScale =
                    params.layoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = layout::RowMajor{currentM, n};
                EpilogueParams epilogueParams;
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                                                gmScalePtr, layoutScale,
                                                params.ptrPerTokenScale + gmGroupOffsetPerTokenScale,
                                                layoutPerTokenScale,
                                                ptrD + gmGroupOffsetD, layoutD};
                } else {
                    epilogueParams = EpilogueParams{gmScalePtr + gmGroupOffsetScale,
                                                layoutScale,
                                                params.ptrPerTokenScale + gmGroupOffsetPerTokenScale,
                                                layoutPerTokenScale,
                                                ptrD + gmGroupOffsetD,
                                                layoutD};
                }

                blockScheduler.Update(inGroupProblemShape, L1TileShape::ToCoordMN());
                blockEpilogue.UpdateParams(epilogueParams);
                uint32_t coreLoops = blockScheduler.GetCoreLoops();

                GemmCoord blockShapeMNK = L1TileShape::ToCoord();
                uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                    GemmCoord blockCoordMNK = blockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShapeMNK = blockScheduler.GetActualBlockShape(blockCoordMNK);

                    MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
                    int64_t gmOffsetC = layoutC.GetOffset(offsetC);
                    auto gmBlockC = gmC[gmOffsetC];
                    auto layoutBlockC = layoutC.GetTileLayout(actualBlockShapeMNK.GetCoordMN());

                    Arch::CrossCoreWaitFlag(flagAicFinishStoreList[stageId]);
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC, layoutBlockC);
                    Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(flagAivFinishComputeList[stageId]);

                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }

                if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                    gmGroupOffsetScale += inGroupProblemShape.n();
                }
                gmGroupOffsetPerTokenScale += inGroupProblemShape.m();
                gmGroupOffsetD += currentM * n;

                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
            }
        }

        Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();

        // Quantize shared expert output if enabled
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            uint32_t quantRowOnce = 0;
            uint32_t shareNOut = params.shareN / 2;
            CalQuantRow(shareNOut, quantRowOnce);
            auto swigluLayout = layout::RowMajor{params.bs, params.shareN};
            typename BlockQuant<ArchTag>::Params quantParams{
                reinterpret_cast<__gm__ float*>(params.gmShareSwigluOut),
                swigluLayout,
                reinterpret_cast<__gm__ float*>(params.gmShareX2Scale),
                params.layoutDequantScale,
                reinterpret_cast<__gm__ int8_t*>(params.gmShareX2),
                params.layoutShareOutput,
                quantRowOnce,
                shareNOut
            };

            BlockQuant<ArchTag> blockQuant(resource, quantParams);
            MatrixCoord quantShape(params.bs, shareNOut);
            MatrixCoord quantBlockShape((uint16_t)(AscendC::GetSubBlockNum() * quantRowOnce), shareNOut);
            Epilogue::Tile::EpilogueHorizontalTileSwizzle quantSwizzle(quantShape, quantBlockShape);
            for (uint32_t loopIdx = coreIdx; loopIdx < quantSwizzle.GetLoops(); loopIdx += coreNum) {
                auto blockCoord = quantSwizzle.GetTileCoord(loopIdx);
                auto actualBlockShape = quantSwizzle.GetActualTileShape(blockCoord);

                blockQuant(quantBlockShape, blockCoord, actualBlockShape);
            }
        }

        {
            uint32_t quantRowOnce = 0;
            CalQuantRow(nOut, quantRowOnce);
            auto swigluLayout = layout::RowMajor{mActual, n};
            typename BlockQuant<ArchTag>::Params quantParams{ptrD,
                                                             swigluLayout,
                                                             params.ptrDequantScale,
                                                             params.layoutDequantScale,
                                                             params.ptrOutput,
                                                             params.layoutOutput,
                                                             quantRowOnce,
                                                             nOut};

            BlockQuant<ArchTag> blockQuant(resource, quantParams);
            MatrixCoord quantShape(mActual, nOut);
            MatrixCoord quantBlockShape((uint16_t)(AscendC::GetSubBlockNum() * quantRowOnce), nOut);
            Epilogue::Tile::EpilogueHorizontalTileSwizzle quantSwizzle(quantShape, quantBlockShape);
            for (uint32_t loopIdx = coreIdx; loopIdx < quantSwizzle.GetLoops(); loopIdx += coreNum) {
                auto blockCoord = quantSwizzle.GetTileCoord(loopIdx);
                auto actualBlockShape = quantSwizzle.GetActualTileShape(blockCoord);

                blockQuant(quantBlockShape, blockCoord, actualBlockShape);
            }
        }
    }

private:
    friend struct AicWaitFunc;
    friend struct AicSetFunc;

    struct AicWaitFunc {
        using MatmulKernel = GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspaceWithShallowDispatch<
                                TemplateMC2TypeFunc, BlockMmad, BlockEpilogue, BlockScheduler,
                                WORKSPACE_STAGES, ElementGroupList>;

        CATLASS_DEVICE
        AicWaitFunc() = default;

        CATLASS_DEVICE
        void operator()() const
        {
            Arch::CrossCoreWaitFlag(ptr->flagAivFinishComputeList[stageId]);
        }

        MatmulKernel *ptr{nullptr};
        uint32_t stageId;
    };

    struct AicSetFunc {
        using MatmulKernel = GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspaceWithShallowDispatch<
                                TemplateMC2TypeFunc, BlockMmad, BlockEpilogue, BlockScheduler,
                                WORKSPACE_STAGES, ElementGroupList>;

        CATLASS_DEVICE
        AicSetFunc() = default;

        CATLASS_DEVICE
        void operator()() const
        {
            Arch::CrossCoreSetFlag<0x2, PIPE_FIX>(ptr->flagAicFinishStoreList[stageId]);
        }

        MatmulKernel *ptr{nullptr};
        uint32_t stageId;
    };

    Arch::CrossCoreFlag flagAicFinishStoreList[WORKSPACE_STAGES];
    Arch::CrossCoreFlag flagAivFinishComputeList[WORKSPACE_STAGES];

    AicWaitFunc aicWaitFuncList[WORKSPACE_STAGES];
    AicSetFunc aicSetFuncList[WORKSPACE_STAGES];
    Arch::Resource<ArchTag> resource;
};

}  // namespace Catlass::Gemm::Kernel
