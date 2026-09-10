/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function implementation file
 */
#ifndef ACT_EPILOGUE_BLOCK_EPILOGUE_PER_TOKEN_DEQUANT_HPP
#define ACT_EPILOGUE_BLOCK_EPILOGUE_PER_TOKEN_DEQUANT_HPP

#include "../../raw_distributed/cam_moe_distribute_combine.h"
#include "catlass/catlass.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/epilogue/dispatch_policy.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/layout/layout.hpp"
#include "catlass/matrix_coord.hpp"
#include "shmem.h"


namespace Catlass::Epilogue::Block {

template <uint32_t UB_STAGES_, uint32_t EXEC_FLAG_,
          class CType_, class ScaleType_, class LayoutScale_, class LayoutPerTokenScale_, class DType_,
          class TileRowBroadcastMul_, class TileBroadcastOneBlk_, class TileOneBlkColumnBroadcastMul_,
          class TileCopy_, class EpilogueTileSwizzle_>
class BlockEpilogue<EpilogueAtlasA2PerTokenDequantCombine<UB_STAGES_, EXEC_FLAG_>,
          CType_, Gemm::GemmType<ScaleType_, LayoutScale_>, Gemm::GemmType<float, LayoutPerTokenScale_>, DType_,
          TileRowBroadcastMul_, TileBroadcastOneBlk_, TileOneBlkColumnBroadcastMul_,
          TileCopy_, EpilogueTileSwizzle_>
{
public:
    using DispatchPolicy = EpilogueAtlasA2PerTokenDequantCombine<UB_STAGES_, EXEC_FLAG_>;
    using ArchTag = typename DispatchPolicy::ArchTag;
    static constexpr uint32_t UB_STAGES = UB_STAGES_;
    static constexpr uint32_t EXEC_FLAG = EXEC_FLAG_;

    // Data infos
    using ElementC = typename CType_::Element;
    using LayoutC = typename CType_::Layout;
    using ElementRawScale = ScaleType_;
    using ElementFp32Scale = float;
    using LayoutScale = LayoutScale_;
    using ElementPerTokenScale = float;
    using LayoutPerTokenScale = LayoutPerTokenScale_;
    using ElementD = typename DType_::Element;
    using LayoutD = typename DType_::Layout;

    // Check data infos
    static_assert(std::is_same_v<ElementC, int32_t> &&
                      (std::is_same_v<ElementD, half> || std::is_same_v<ElementD, bfloat16_t>),
                  "The element type template parameters of BlockEpilogue are wrong");
    static_assert(std::is_same_v<LayoutC, layout::RowMajor> && std::is_same_v<LayoutScale, layout::VectorLayout> &&
                      std::is_same_v<LayoutPerTokenScale, layout::VectorLayout> &&
                      std::is_same_v<LayoutD, layout::RowMajor>,
                  "The layout template parameters of BlockEpilogue are wrong");

    // Tile compute ops
    using TileRowBroadcastMul = TileRowBroadcastMul_;
    using TileBroadcastOneBlk = TileBroadcastOneBlk_;
    using TileOneBlkColumnBroadcastMul = TileOneBlkColumnBroadcastMul_;

    // Tile copy
    using CopyGmToUbC = typename TileCopy_::CopyGmToUbC;
    using CopyGmToUbScale = typename TileCopy_::CopyGmToUbX;
    using CopyGmToUbPerTokenScale = typename TileCopy_::CopyGmToUbY;
    using CopyUbToGmD = typename TileCopy_::CopyUbToGmD;

    using EpilogueTileSwizzle = EpilogueTileSwizzle_;

    using TileShape = typename TileRowBroadcastMul::TileShape;

    static_assert(TileShape::ROW == TileBroadcastOneBlk::COMPUTE_LENGTH &&
                      std::is_same_v<TileShape, typename TileOneBlkColumnBroadcastMul::TileShape>,
                  "TileShape must be consistent for all tile compute ops");

    static_assert((UB_STAGES * (TileShape::COUNT * sizeof(ElementC) +
                  (std::is_same_v<ElementRawScale, ElementFp32Scale> ?
                      0 : TileShape::COLUMN * sizeof(ElementRawScale)) +
                  TileShape::COLUMN * sizeof(ElementFp32Scale) +
                                TileShape::ROW * sizeof(ElementPerTokenScale) + TileShape::COUNT * sizeof(ElementD)) +
                   (TileShape::COUNT + TileShape::COUNT) * sizeof(float) + TileShape::ROW * BYTE_PER_BLK) <=
                      ArchTag::UB_SIZE,
                  "TileShape is too large to fit in UB");

    struct Params {
        __gm__ ElementRawScale *ptrScale{nullptr};
        LayoutScale layoutScale{};
        // W4A8: bias/compensation matrix pointer
        __gm__ float *ptrBias{nullptr};
        __gm__ ElementPerTokenScale *ptrPerTokenScale{nullptr};
        LayoutPerTokenScale layoutPerTokenScale{};
        __gm__ ElementD *ptrD{nullptr};
        LayoutD layoutD{};

        CATLASS_DEVICE
        Params(){};

        CATLASS_DEVICE
        Params(__gm__ ElementRawScale *ptrScale_, LayoutScale const &layoutScale_,
               __gm__ float *ptrBias_,
               __gm__ ElementPerTokenScale *ptrPerTokenScale_, LayoutPerTokenScale const &layoutPerTokenScale_,
               __gm__ ElementD *ptrD_, LayoutD const &layoutD_)
            : ptrScale(ptrScale_),
              layoutScale(layoutScale_),
              ptrBias(ptrBias_),
              ptrPerTokenScale(ptrPerTokenScale_),
              layoutPerTokenScale(layoutPerTokenScale_),
              ptrD(ptrD_),
              layoutD(layoutD_)
        {
        }
    };

    CATLASS_DEVICE void AlignUbOffset()
    {
        size_t ubMask = ubOffset & (MoeDistributeCombineImpl::UB_ALIGN - 1);
        if (ubMask != 0) {
            ubOffset += MoeDistributeCombineImpl::UB_ALIGN - ubMask;
        }
    }

    __aicore__ inline GM_ADDR GetShmemAddrByRankId(GM_ADDR baseAddr, int64_t rankId)
    {
        if (calcInfo.epRankId_ == rankId) {
            return baseAddr;
        }
        return (GM_ADDR)aclshmem_ptr(baseAddr, rankId);
    }

    CATLASS_DEVICE
    void ShmemCalRecv(int64_t ubOffset, GM_ADDR gmAllEpRecvCount, GM_ADDR gmAllExpertTokenNums)
    {
        AscendC::LocalTensor<int32_t> allExpertTokenNumsTensor = resource.ubBuf.template GetBufferByByte<int32_t>(
            ubOffset);
        AscendC::GlobalTensor<int32_t> allExpertTokenNumsGMTensor;
        allExpertTokenNumsGMTensor.SetGlobalBuffer((__gm__ int32_t *)gmAllExpertTokenNums);

        AscendC::DataCopyExtParams dataCopyParams = {
            1U,
            static_cast<uint32_t>(calcInfo.moeExpertNum_ * calcInfo.epWorldSize_ * sizeof(int32_t)),
            0U,
            0U,
            0U
        };
        const AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(allExpertTokenNumsTensor, allExpertTokenNumsGMTensor, dataCopyParams, copyPadParams);
        AscendC::PipeBarrier<PIPE_ALL>();

        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);

        AscendC::LocalTensor<int32_t> recvTokenLt = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset +
            calcInfo.moeExpertNum_ * calcInfo.epWorldSize_ * sizeof(int32_t));
        AscendC::GlobalTensor<int32_t> recvCountsGlobalTensor;
        recvCountsGlobalTensor.SetGlobalBuffer((__gm__ int32_t *)gmAllEpRecvCount);

        for (uint32_t srcRank = 0; srcRank < calcInfo.epWorldSize_; ++srcRank) {
            int32_t rankPrefixSum = 0;
            for (uint32_t expId = 0; expId < calcInfo.moeExpertNum_; ++expId) {
                uint32_t index = srcRank * calcInfo.moeExpertNum_ + expId;

                int32_t curCount = allExpertTokenNumsTensor.GetValue(index);
                rankPrefixSum += curCount;
                recvTokenLt.SetValue(index, rankPrefixSum);
            }
        }

        AscendC::PipeBarrier<PIPE_ALL>();

        AscendC::DataCopyExtParams copyParams{1, static_cast<uint32_t>(calcInfo.moeExpertNum_ *
            calcInfo.epWorldSize_ * sizeof(int32_t)), 0, 0, 0};
        AscendC::DataCopyPad(recvCountsGlobalTensor, recvTokenLt, copyParams);
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    BlockEpilogue(Arch::Resource<ArchTag> &resource, MoeDistributeCombineImpl::CombineCalcInfo &calcInfo,
                  Params const &params = Params{})
        : resource(resource),
          calcInfo(calcInfo),
          params(params)
    {
        for (uint32_t i = 0; i < UB_STAGES; ++i) {
            ubCList[i] = resource.ubBuf.template GetBufferByByte<ElementC>(ubOffset);
            ubOffset += TileShape::COUNT * sizeof(ElementC);
            if constexpr (!std::is_same_v<ElementRawScale, ElementFp32Scale>) {
                ubRawScaleList[i] = resource.ubBuf.template GetBufferByByte<ElementRawScale>(ubOffset);
                ubOffset += TileShape::COLUMN * sizeof(ElementRawScale);
            }
            ubFp32ScaleList[i] = resource.ubBuf.template GetBufferByByte<ElementFp32Scale>(ubOffset);
            ubOffset += TileShape::COLUMN * sizeof(ElementFp32Scale);
            ubPerTokenScaleList[i] = resource.ubBuf.template GetBufferByByte<ElementPerTokenScale>(ubOffset);
            ubOffset += TileShape::ROW * sizeof(ElementPerTokenScale);
            ubDList[i] = resource.ubBuf.template GetBufferByByte<ElementD>(ubOffset);
            ubOffset += TileShape::COUNT * sizeof(ElementD);

            // W4A8: ubweighAux local tensor
            if constexpr (EXEC_FLAG & EXEC_FLAG_W4A8) {
                ubweighAuxList[i] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
                ubOffset += TileShape::COLUMN * sizeof(float);
            }

            eventUbCVMTE2List[i] = eventVMTE2++;
            eventUbCMTE2VList[i] = eventMTE2V++;
            eventUbScaleVMTE2List[i] = eventVMTE2++;
            eventUbScaleMTE2VList[i] = eventMTE2V++;
            eventUbPerTokenScaleVMTE2List[i] = eventVMTE2++;
            eventUbPerTokenScaleMTE2VList[i] = eventMTE2V++;
            eventUbDMTE3VList[i] = eventMTE3V++;
            eventUbDVMTE3List[i] = eventVMTE3++;

            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventUbCVMTE2List[i]);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventUbScaleVMTE2List[i]);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventUbPerTokenScaleVMTE2List[i]);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(eventUbDMTE3VList[i]);
        }
        ubCFp32 = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += TileShape::COUNT * sizeof(float);
        ubMul = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += TileShape::COUNT * sizeof(float);
        ubPerTokenScaleBrcb = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += TileShape::ROW * BYTE_PER_BLK;
        ubPerTokenMul = ubCFp32;

        AlignUbOffset();
        epSendCountLocal_ = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += calcInfo.moeSendNum_ * sizeof(int32_t);
        AlignUbOffset();
        AscendC::GlobalTensor<int32_t> epSendCountGM;
        epSendCountGM.SetGlobalBuffer((__gm__ int32_t *)calcInfo.epSendCount_);
        uint32_t epSendCountSize = calcInfo.moeSendNum_;
        AscendC::DataCopyExtParams epSendCntParams = {1U, static_cast<uint32_t>(epSendCountSize * sizeof(uint32_t)),
                                                      0U, 0U, 0U};
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(epSendCountLocal_, epSendCountGM, epSendCntParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(eventMTE2S);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(eventMTE2S);

        AlignUbOffset();
        ShmemCalRecv(ubOffset, calcInfo.allEpRecvCount_, calcInfo.allExpertTokenNums_);

        AlignUbOffset();
        allEpRecvCountLocal_ = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += calcInfo.epWorldSize_ * calcInfo.moeExpertNum_ *sizeof(uint32_t);
        AlignUbOffset();
        AscendC::GlobalTensor<int32_t> allEpRecvCountGM;
        allEpRecvCountGM.SetGlobalBuffer((__gm__ int32_t *)calcInfo.allEpRecvCount_);
        uint32_t allEpRecvCountSize = calcInfo.epWorldSize_ * calcInfo.moeExpertNum_;
        AscendC::DataCopyExtParams allEpRecvCountParams = {
            1U,
            static_cast<uint32_t>(allEpRecvCountSize * sizeof(uint32_t)),
            0U,
            0U,
            0U
        };
        AscendC::DataCopyPad(allEpRecvCountLocal_, allEpRecvCountGM, allEpRecvCountParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(eventMTE2S);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(eventMTE2S);
    }

    CATLASS_DEVICE
    ~BlockEpilogue()
    {
        for (uint32_t i = 0; i < UB_STAGES; ++i) {
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventUbCVMTE2List[i]);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventUbScaleVMTE2List[i]);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventUbPerTokenScaleVMTE2List[i]);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(eventUbDMTE3VList[i]);
        }
    }

    CATLASS_DEVICE
    void UpdateParams(Params const &params_)
    {
        params = params_;
    }

    // tile粒度的发送
    // 一个tile的expertIdx是固定的
    // tile根据目的rank不同而分小块发送，小块粒度为rank粒度
    CATLASS_DEVICE void ShmemDoCombineSend(AscendC::LocalTensor<ElementD> &ubD, layout::RowMajor &layoutGmTileD,
                                      LayoutD &layoutUbD, int64_t groupOffsetD, uint32_t expertIdx,
                                      uint32_t tileOffsetD, GM_ADDR combineSend)
    {
        const uint32_t copyTokenLen = layoutGmTileD.shape(1) * sizeof(ElementD);
        const uint32_t copyTokenSrcStride =
            (layoutUbD.stride(0) - layoutUbD.shape(1)) / (BYTE_PER_C0 / sizeof(ElementD));
        const uint32_t copyTokenDstStride = (layoutGmTileD.stride(0) - layoutGmTileD.shape(1)) * sizeof(ElementD);

        int64_t offsetD = groupOffsetD + tileOffsetD;
        uint32_t startToken = offsetD / calcInfo.axisH_;
        uint32_t tokenOffset = offsetD - startToken * calcInfo.axisH_;
        uint32_t itToken = startToken;
        uint32_t endToken = startToken + layoutGmTileD.shape(0);
        constexpr uint32_t epRankStart = 0;
        uint32_t expertId = calcInfo.epRankId_ * calcInfo.moeExpertPerRankNum_ + expertIdx;
        uint32_t sendCount =
            expertIdx == 0 && epRankStart == 0 ? 0 : epSendCountLocal_.GetValue(expertOffset + epRankStart - 1);
        for (uint32_t epRank = epRankStart; epRank < calcInfo.epWorldSize_ && itToken < endToken; ++epRank) {
            uint32_t prevSendCount = sendCount;
            sendCount = epSendCountLocal_.GetValue(expertOffset + epRank);
            uint32_t dstExpertOffset =
                expertId == 0 ? 0 : allEpRecvCountLocal_.GetValue(epRank * calcInfo.moeExpertNum_ + expertId - 1);
            if (prevSendCount <= itToken && itToken < sendCount) {
                uint32_t copyTokenCount = (sendCount < endToken ? sendCount : endToken) - itToken;
                AscendC::DataCopyExtParams dataCopyParams(copyTokenCount, copyTokenLen, copyTokenSrcStride,
                                                          copyTokenDstStride, 0);
                GM_ADDR dstCombinSendAddr = (GM_ADDR)aclshmem_ptr(combineSend, epRank) +
                                                     dstExpertOffset * calcInfo.axisH_ * sizeof(ElementD);
                AscendC::GlobalTensor<ElementD> dstComBineSendGMTensor;
                dstComBineSendGMTensor.SetGlobalBuffer((__gm__ ElementD *)dstCombinSendAddr);
                AscendC::DataCopyPad(dstComBineSendGMTensor[(itToken - prevSendCount) * calcInfo.axisH_ + tokenOffset],
                                     ubD[(itToken - startToken) * layoutUbD.stride(0)], dataCopyParams);
                itToken += copyTokenCount;
            }
        }
    }

    CATLASS_DEVICE
    void operator()(int64_t groupOffsetD, uint32_t expertIdx, GemmCoord const &blockShapeMNK,
                    GemmCoord const &blockCoordMNK, GemmCoord const &actualBlockShapeMNK,
                    AscendC::GlobalTensor<ElementC> const &gmBlockC, LayoutC const &layoutBlockC,
                    Callback &&callback = Callback{})
    {
        if (actualBlockShapeMNK.k() == 0) {
            return;
        }

        expertOffset = expertIdx * calcInfo.epWorldSize_;

        // W4A8 constants
        constexpr float DEFAULT_MUL_SCALE = 16.0f;
        constexpr uint32_t mulsMask = 64;
        constexpr uint32_t mulsRepeatTimes = 16;
        constexpr uint32_t src0RepStride = 64;
        constexpr uint32_t addDstRepStride = 1;
        constexpr uint32_t addSrc0RepStride = 32;
        constexpr uint32_t addSrc1RepStride = 64;
        constexpr uint32_t addSrc0RepStrideWeightAux = 32;
        constexpr uint32_t addSrc1RepStrideWeightAux = 0;
        constexpr uint32_t TILE_HALF_SPLIT = 2;
        constexpr uint32_t TILE_QUARTER_SPLIT = 4;
        constexpr uint32_t TILE_OFFSET_FACTOR = 3;

        callback();
        // Calculate the offset of the current block
        MatrixCoord blockShape = blockShapeMNK.GetCoordMN();
        MatrixCoord blockCoord = blockCoordMNK.GetCoordMN();
        MatrixCoord actualBlockShape = actualBlockShapeMNK.GetCoordMN();
        MatrixCoord blockOffset = blockCoord * blockShape;

        AscendC::GlobalTensor<ElementRawScale> gmScale;
        gmScale.SetGlobalBuffer(params.ptrScale);
        // W4A8: bias/compensation matrix - only set when in W4A8 mode
        AscendC::GlobalTensor<float> gmBias;
        if constexpr (EXEC_FLAG & EXEC_FLAG_W4A8) {
            gmBias.SetGlobalBuffer(params.ptrBias);
        }
        AscendC::GlobalTensor<ElementPerTokenScale> gmPerTokenScale;
        gmPerTokenScale.SetGlobalBuffer(params.ptrPerTokenScale);
        AscendC::GlobalTensor<ElementD> gmD;
        gmD.SetGlobalBuffer(params.ptrD);

        auto ubTileStride = MakeCoord(static_cast<int64_t>(TileShape::COLUMN), 1L);
        auto tileShape = TileShape::ToCoord();
        EpilogueTileSwizzle epilogueTileSwizzle(actualBlockShape, tileShape);
        uint32_t tileLoops = epilogueTileSwizzle.GetLoops();
        uint32_t subblockIdx = expertIdx == UINT32_MAX ? 0 : AscendC::GetSubBlockIdx();
        uint32_t subblockNum = expertIdx == UINT32_MAX ? 1 : AscendC::GetSubBlockNum();
        for (uint32_t loopIdx = subblockIdx; loopIdx < tileLoops; loopIdx += subblockNum) {
            auto tileCoord = epilogueTileSwizzle.GetTileCoord(loopIdx);
            auto actualTileShape = epilogueTileSwizzle.GetActualTileShape(tileCoord);
            auto tileOffsetInBlock = tileCoord * tileShape;
            auto tileOffset = blockOffset + tileOffsetInBlock;

            auto gmTileC = gmBlockC[layoutBlockC.GetOffset(tileOffsetInBlock)];
            auto layoutGmTileC = layoutBlockC.GetTileLayout(actualTileShape);

            auto &ubC = ubCList[ubListId];
            LayoutC layoutUbC{actualTileShape, ubTileStride};

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventUbCVMTE2List[ubListId]);
            copyGmToUbC(ubC, gmTileC, layoutUbC, layoutGmTileC);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventUbCMTE2VList[ubListId]);

            auto scaleTileOffset = tileOffset.template GetCoordByAxis<1>();
            auto scaleTileShape = actualTileShape.template GetCoordByAxis<1>();

            auto gmTileScale = gmScale[params.layoutScale.GetOffset(scaleTileOffset)];
            auto layoutGmTileScale = params.layoutScale.GetTileLayout(scaleTileShape);

            auto &ubFp32Scale = ubFp32ScaleList[ubListId];
            auto layoutFp32UbScale = LayoutScale::template MakeLayoutInUb<ElementFp32Scale>(scaleTileShape);
            auto &ubRawScale = ubRawScaleList[ubListId];
            auto layoutRawUbScale = LayoutScale::template MakeLayoutInUb<ElementRawScale>(scaleTileShape);

            // W4A8: load weightAux matrix
            auto &ubweighAux = ubweighAuxList[ubListId];
            AscendC::DataCopyExtParams copyParams{
                1, static_cast<uint32_t>(TileShape::COLUMN * sizeof(float)), 0, 0, 0};
            AscendC::DataCopyPadExtParams<float> padParams{false, 0, 0, 0};

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventUbScaleVMTE2List[ubListId]);
            // W4A8: load bias/compensation matrix
            if constexpr (EXEC_FLAG & EXEC_FLAG_W4A8) {
                AscendC::DataCopyPad(ubweighAux,
                    gmBias[params.layoutScale.GetOffset(scaleTileOffset)],
                    copyParams, padParams);
            }
            if constexpr (!std::is_same_v<ElementRawScale, ElementFp32Scale>) {
                copyGmToUbScale(ubRawScale, gmTileScale, layoutRawUbScale, layoutGmTileScale);
            } else {
                copyGmToUbScale(ubFp32Scale, gmTileScale, layoutFp32UbScale, layoutGmTileScale);
            }
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventUbScaleMTE2VList[ubListId]);

            auto perTokenScaleTileOffset = tileOffset.template GetCoordByAxis<0>();
            auto perTokenScaleTileShape = actualTileShape.template GetCoordByAxis<0>();

            // W4A8: recalculate offset
            Catlass::Coord<1> newperTokenScaleOffset(perTokenScaleTileOffset[0] / TILE_HALF_SPLIT);
            Catlass::Coord<1> newperTokenScaleTileShape(perTokenScaleTileShape[0] / TILE_HALF_SPLIT);

            auto gmTilePerTokenScale = gmPerTokenScale[params.layoutPerTokenScale.GetOffset(
                (EXEC_FLAG & EXEC_FLAG_W4A8) ? newperTokenScaleOffset : perTokenScaleTileOffset)];
            auto layoutGmTilePerTokenScale = params.layoutPerTokenScale.GetTileLayout(
                (EXEC_FLAG & EXEC_FLAG_W4A8) ? newperTokenScaleTileShape : perTokenScaleTileShape);
            auto &ubPerTokenScale = ubPerTokenScaleList[ubListId];
            auto layoutUbPerTokenScale =
                LayoutScale::template MakeLayoutInUb<ElementPerTokenScale>(
                    (EXEC_FLAG & EXEC_FLAG_W4A8) ? newperTokenScaleTileShape : perTokenScaleTileShape);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventUbPerTokenScaleVMTE2List[ubListId]);
            copyGmToUbPerTokenScale(ubPerTokenScale, gmTilePerTokenScale, layoutUbPerTokenScale,
                                    layoutGmTilePerTokenScale);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventUbPerTokenScaleMTE2VList[ubListId]);

            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventUbCMTE2VList[ubListId]);
            AscendC::Cast(ubCFp32, ubC, AscendC::RoundMode::CAST_RINT, TileShape::COUNT);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventUbCVMTE2List[ubListId]);

            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventUbScaleMTE2VList[ubListId]);
            if constexpr (!std::is_same_v<ElementRawScale, ElementFp32Scale>) {
                AscendC::Cast(ubFp32Scale, ubRawScale, AscendC::RoundMode::CAST_NONE, TileShape::COLUMN);
                AscendC::PipeBarrier<PIPE_V>();
            }
            tileRowBroadcastMul(ubMul, ubCFp32, ubFp32Scale);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventUbScaleVMTE2List[ubListId]);

            // W4A8: merge high/low bits and add weightAux compensation
            if constexpr (EXEC_FLAG & EXEC_FLAG_W4A8) {
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Muls(ubMul, ubMul, DEFAULT_MUL_SCALE, mulsMask, mulsRepeatTimes,
                    {1, 1, src0RepStride, src0RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Muls(ubMul[TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN / TILE_QUARTER_SPLIT], DEFAULT_MUL_SCALE, mulsMask, mulsRepeatTimes,
                    {1, 1, src0RepStride, src0RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Muls(ubMul[TileShape::COLUMN / TILE_HALF_SPLIT], ubMul[TileShape::COLUMN / TILE_HALF_SPLIT],
                    DEFAULT_MUL_SCALE, mulsMask, mulsRepeatTimes,
                    {1, 1, src0RepStride, src0RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Muls(ubMul[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    DEFAULT_MUL_SCALE, mulsMask, mulsRepeatTimes,
                    {1, 1, src0RepStride, src0RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul, ubMul, ubMul[TileShape::COLUMN],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStride,
                    addSrc1RepStride, addSrc1RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul[TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN + TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStride,
                    addSrc1RepStride, addSrc1RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul[TileShape::COLUMN / TILE_HALF_SPLIT],
                    ubMul[TileShape::COLUMN / TILE_HALF_SPLIT],
                    ubMul[TileShape::COLUMN + TileShape::COLUMN / TILE_HALF_SPLIT],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStride,
                    addSrc1RepStride, addSrc1RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN + TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStride,
                    addSrc1RepStride, addSrc1RepStride});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul, ubMul, ubweighAux, mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStrideWeightAux,
                    addSrc0RepStrideWeightAux, addSrc1RepStrideWeightAux});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul[TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    ubweighAux[TileShape::COLUMN / TILE_QUARTER_SPLIT],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStrideWeightAux,
                    addSrc0RepStrideWeightAux, addSrc1RepStrideWeightAux});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul[TileShape::COLUMN / TILE_HALF_SPLIT],
                    ubMul[TileShape::COLUMN / TILE_HALF_SPLIT],
                    ubweighAux[TileShape::COLUMN / TILE_HALF_SPLIT],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStrideWeightAux,
                    addSrc0RepStrideWeightAux, addSrc1RepStrideWeightAux});
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(ubMul[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    ubMul[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    ubweighAux[TileShape::COLUMN * TILE_OFFSET_FACTOR / TILE_QUARTER_SPLIT],
                    mulsMask, mulsRepeatTimes,
                    {1, 1, addDstRepStride, addSrc0RepStrideWeightAux,
                    addSrc0RepStrideWeightAux, addSrc1RepStrideWeightAux});
            }

            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventUbPerTokenScaleMTE2VList[ubListId]);
            tileBroadcastOneBlk(ubPerTokenScaleBrcb, ubPerTokenScale);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventUbPerTokenScaleVMTE2List[ubListId]);

            AscendC::PipeBarrier<PIPE_V>();
            tileOneBlkColumnBroadcastMul(ubPerTokenMul, ubMul, ubPerTokenScaleBrcb);
            AscendC::PipeBarrier<PIPE_V>();

            auto &ubD = ubDList[ubListId];
            LayoutD layoutUbD{actualTileShape, ubTileStride};
            // W4A8: adjust layout shape(0)
            auto newlayoutUbD = layoutUbD;
            if constexpr (EXEC_FLAG & EXEC_FLAG_W4A8) {
                newlayoutUbD.shape(0) = newlayoutUbD.shape(0) / TILE_HALF_SPLIT;
            }

            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(eventUbDMTE3VList[ubListId]);
            AscendC::Cast(ubD, ubPerTokenMul, AscendC::RoundMode::CAST_RINT, TileShape::COUNT);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(eventUbDVMTE3List[ubListId]);

            auto tileOffsetD = params.layoutD.GetOffset(
                (EXEC_FLAG & EXEC_FLAG_W4A8) ?
                MatrixCoord(tileOffset.row() / TILE_HALF_SPLIT, tileOffset.column()) : tileOffset);
            auto layoutGmTileD = params.layoutD.GetTileLayout(actualTileShape);
            // W4A8: adjust layout shape(0)
            auto newlayoutGmTileD = layoutGmTileD;
            if constexpr (EXEC_FLAG & EXEC_FLAG_W4A8) {
                newlayoutGmTileD.shape(0) = layoutGmTileD.shape(0) / TILE_HALF_SPLIT;
            }

            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(eventUbDVMTE3List[ubListId]);

            if (expertIdx == UINT32_MAX) {
                auto gmTileD = gmD[tileOffsetD];
                copyUbToGmD(gmTileD, ubD,
                    (EXEC_FLAG & EXEC_FLAG_W4A8) ? newlayoutGmTileD : layoutGmTileD,
                    (EXEC_FLAG & EXEC_FLAG_W4A8) ? newlayoutUbD : layoutUbD);
            } else {
                ShmemDoCombineSend(ubD,
                    (EXEC_FLAG & EXEC_FLAG_W4A8) ? newlayoutGmTileD : layoutGmTileD,
                    (EXEC_FLAG & EXEC_FLAG_W4A8) ? newlayoutUbD : layoutUbD,
                    groupOffsetD, expertIdx, tileOffsetD,
                    calcInfo.combineSend_);
            }

            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(eventUbDMTE3VList[ubListId]);

            ubListId = (ubListId + 1 < UB_STAGES) ? (ubListId + 1) : 0;
        }
    }

private:
    Params params;
    Arch::Resource<ArchTag> &resource;
    MoeDistributeCombineImpl::CombineCalcInfo calcInfo;

    AscendC::LocalTensor<ElementC> ubCList[UB_STAGES];
    AscendC::LocalTensor<ElementRawScale> ubRawScaleList[UB_STAGES];
    AscendC::LocalTensor<ElementFp32Scale> ubFp32ScaleList[UB_STAGES];
    AscendC::LocalTensor<ElementPerTokenScale> ubPerTokenScaleList[UB_STAGES];
    AscendC::LocalTensor<ElementD> ubDList[UB_STAGES];

    // W4A8: compensation matrix
    AscendC::LocalTensor<float> ubweighAuxList[UB_STAGES];

    int32_t eventUbCVMTE2List[UB_STAGES];
    int32_t eventUbCMTE2VList[UB_STAGES];
    int32_t eventUbScaleVMTE2List[UB_STAGES];
    int32_t eventUbScaleMTE2VList[UB_STAGES];
    int32_t eventUbPerTokenScaleVMTE2List[UB_STAGES];
    int32_t eventUbPerTokenScaleMTE2VList[UB_STAGES];
    int32_t eventUbDMTE3VList[UB_STAGES];
    int32_t eventUbDVMTE3List[UB_STAGES];

    AscendC::LocalTensor<int32_t> epSendCountLocal_;
    AscendC::LocalTensor<int32_t> allEpRecvCountLocal_;

    size_t ubOffset{0};
    int32_t eventVMTE2{0};
    int32_t eventMTE2V{0};
    int32_t eventMTE3V{0};
    int32_t eventVMTE3{0};
    int32_t eventVS{0};
    int32_t eventMTE2S{0};

    uint32_t expertOffset;

    uint32_t ubListId{0};

    AscendC::LocalTensor<float> ubCFp32;
    AscendC::LocalTensor<float> ubMul;
    AscendC::LocalTensor<float> ubPerTokenScaleBrcb;
    AscendC::LocalTensor<float> ubPerTokenMul;

    TileRowBroadcastMul tileRowBroadcastMul;
    TileBroadcastOneBlk tileBroadcastOneBlk;
    TileOneBlkColumnBroadcastMul tileOneBlkColumnBroadcastMul;

    CopyGmToUbC copyGmToUbC;
    CopyGmToUbScale copyGmToUbScale;
    CopyGmToUbPerTokenScale copyGmToUbPerTokenScale;
    CopyUbToGmD copyUbToGmD;
};

}  // namespace Catlass::Epilogue::Block

#endif  // ACT_EPILOGUE_BLOCK_EPILOGUE_PER_TOKEN_DEQUANT_HPP
