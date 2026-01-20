/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: FusedDeepMoeFwkFwk operator kernel function implementation file
 * Create: 2026-01-20
 */

#pragma once

#include "catlass/catlass.hpp"
#include "catlass/arch/cross_core_sync.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/coord.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/matrix_coord.hpp"
#include "catlass/epilogue/tile/tile_swizzle.hpp"
#include "catlass/epilogue/tile/tile_copy.hpp"

#include "fused_deep_moe_fwk/lib_ops.h"

constexpr uint32_t STATE_OFFSET = 512;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint64_t GROUP_TOKEN_NUM_OFFSET = 932 * 1024;
constexpr uint64_t SOFT_SYNC_OFFSET = 964 * 1024;
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
constexpr uint32_t QUANT_SPACE_FACTOR = 176 * 1024 / 11; // ub usage of quant is limited to 176kb

#define CEIL_UP(x) ((x + UB_ALIGN - 1) / UB_ALIGN * UB_ALIGN)
#define CEIL(x, y) (((x) + (y - 1)) / (y))
#define UB_BLOCK_SIZE (32)
#define GET_WIND_STATE_ADDR_BY_RANK_ID(rankId)                                                                    \
    (((epRankId == rankId)                                                                                        \
          ? ((GM_ADDR)(winContext_->localWindowsExp))                                                             \
          : ((GM_ADDR)(((HcclRankRelationResV2 *)(winContext_->remoteRes[rankId].nextDevicePtr))->windowsExp))) + \
     dataState * WIN_STATE_OFFSET)
#define GET_WIND_ADDR_BY_RANK_ID(rankId)                                                                         \
    (((epRankId == rankId)                                                                                       \
          ? ((GM_ADDR)(winContext_->localWindowsIn))                                                             \
          : ((GM_ADDR)(((HcclRankRelationResV2 *)(winContext_->remoteRes[rankId].nextDevicePtr))->windowsIn))) + \
     winDataSizeOffset + rankId * OPT_RANK_OFFSET)
#define TOKEN_FLAG_1 (0x55555555)
#define TOKEN_FLAG_2 (0x33333333)
#define V_TO_C_FLAG_1 (0x03030303)
#define V_TO_C_FLAG_2 (0x05050505)
#define CV_FLAG_INDEX 0
#define GROUP_ID_INDEX 1
#define PRE_COUNT_INDEX 2
#define SELF_COUNT_INDEX 3
#define TOTAL_COUNT_INDEX 4
#define GROUP_TOKEN_COUNT SELF_COUNT_INDEX
#define GROUP_INFO_SIZE 32

namespace Catlass::Gemm::Kernel {


__aicore__ inline static void EncreaseSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx)
{
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<uint8_t> global;
    global.SetGlobalBuffer(flagAddr + idx * SOFT_SYNC_SPACE_SIZE);
    __asm__ __volatile__("");
    AscendC::DataCacheCleanAndInvalid<uint8_t, AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
        global);
    __asm__ __volatile__("");
    uint8_t value = global.GetValue(0);
    global.SetValue(0, value + 1);
    __asm__ __volatile__("");
    AscendC::DataCacheCleanAndInvalid<uint8_t, AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
        global);
    __asm__ __volatile__("");
    AscendC::PipeBarrier<PIPE_ALL>();
}

__aicore__ inline static void CheckSyncFlag(__gm__ uint8_t *flagAddr, uint8_t idx, uint32_t target)
{
    AscendC::PipeBarrier<PIPE_ALL>();
    AscendC::GlobalTensor<uint8_t> global;
    global.SetGlobalBuffer(flagAddr + idx * SOFT_SYNC_SPACE_SIZE);
    while (true) {
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<uint8_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(global);
        __asm__ __volatile__("");
        uint8_t value = global.GetValue(0);
        if (value >= target) {
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint8_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                              AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            break;
        }
    }
    AscendC::PipeBarrier<PIPE_ALL>();
}

__aicore__ inline static void CalQuantRow(const uint32_t column, uint32_t &row)
{
    row = QUANT_SPACE_FACTOR / column;
    row = row < MAX_QUANT_ROW_ONCE ? row : MAX_QUANT_ROW_ONCE;
}

template <uint32_t EXEC_FLAG, typename XType_, class BlockMmad_, class BlockEpilogue_, class BlockScheduler_, uint32_t WORKSPACE_STAGES_,
          class ElementGroupList_>
class GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspace
{
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
    using ElementScale = typename BlockEpilogue::ElementScale;
    using LayoutScale = typename BlockEpilogue::LayoutScale;
    using ElementPerTokenScale = typename BlockEpilogue::ElementPerTokenScale;
    using LayoutPerTokenScale = typename BlockEpilogue::LayoutPerTokenScale;
    using ElementD = typename BlockEpilogue::ElementD;
    using LayoutD = typename BlockEpilogue::LayoutD;
    using EpilogueParams = typename BlockEpilogue::Params;

    using ElementDequantScale = float;
    using LayoutDequantScale = layout::VectorLayout;
    using ElementOutput = int8_t;
    using LayoutOutput = layout::RowMajor;

    using BlockScheduler = BlockScheduler_;
    static constexpr uint32_t WORKSPACE_STAGES = WORKSPACE_STAGES_;
    using ElementGroupList = ElementGroupList_;

    using XType = XType_;

    // Parameters structure
    struct Params {
        // Data members
        GemmCoord problemShape;
        uint32_t problemCount;
        __gm__ ElementGroupList_ *ptrGroupList;
        __gm__ ElementA *ptrA;
        LayoutA layoutA;
        __gm__ ElementB *ptrB;
        LayoutB layoutB;
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
        GM_ADDR debugGm;
        GM_ADDR gmexpertIds;

        GM_ADDR gmExpandIdx;
        GM_ADDR gmEpSendCount;
        GM_ADDR gmResvered;
        GM_ADDR gmExpertTokenNums;

        uint32_t epRankSize;
        uint32_t epRankId;
        uint32_t moeExpertNum;
        uint32_t moeExpertNumPerRank;
        uint32_t sharedExpertNum;
        uint32_t sharedExpertRankNum;
        uint32_t quantMode;
        uint32_t globalBs;
        uint32_t bs;
        uint32_t topK;
        uint32_t tokenLen;
        // Methods
        CATLASS_DEVICE
        Params() {}

        CATLASS_DEVICE
        Params(GemmCoord problemShape_, uint32_t problemCount_, GM_ADDR ptrGroupList_, GM_ADDR ptrA_,
               LayoutA const &layoutA_, GM_ADDR ptrB_, LayoutB const &layoutB_, GM_ADDR ptrScale_,
               LayoutScale const &layoutScale_, GM_ADDR ptrPerTokenScale_,
               LayoutPerTokenScale const &layoutPerTokenScale_, GM_ADDR ptrOutput_, LayoutOutput const &layoutOutput_,
               GM_ADDR ptrDequantScale_, LayoutDequantScale const &layoutDequantScale_, GM_ADDR ptrWorkspace_,
               GM_ADDR gmX_, GM_ADDR debugGm_, GM_ADDR gmexpertIds_, GM_ADDR gmExpandIdx_, GM_ADDR gmEpSendCount_,
               GM_ADDR gmResvered_, GM_ADDR gmExpertTokenNums_, uint32_t epRankSize_, uint32_t epRankId_,
               uint32_t moeExpertNum_, uint32_t moeExpertNumPerRank_, uint32_t sharedExpertNum_,
               uint32_t sharedExpertRankNum_, uint32_t quantMode_, uint32_t globalBs_, uint32_t bs_, uint32_t topK_,
               uint32_t h)
            : problemShape(problemShape_),
              problemCount(problemCount_),
              ptrGroupList(reinterpret_cast<__gm__ ElementGroupList *>(ptrGroupList_)),
              ptrA(reinterpret_cast<__gm__ ElementA *>(ptrA_)),
              layoutA(layoutA_),
              ptrB(reinterpret_cast<__gm__ ElementB *>(ptrB_)),
              layoutB(layoutB_),
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
              debugGm(debugGm_),
              gmexpertIds(gmexpertIds_),
              gmExpandIdx(gmExpandIdx_),
              gmEpSendCount(gmEpSendCount_),
              gmExpertTokenNums(gmExpertTokenNums_),
              gmResvered(gmResvered_),
              epRankSize(epRankSize_),
              epRankId(epRankId_),
              moeExpertNum(moeExpertNum_),
              moeExpertNumPerRank(moeExpertNumPerRank_),
              sharedExpertNum(sharedExpertNum_),
              sharedExpertRankNum(sharedExpertRankNum_),
              quantMode(quantMode_),
              globalBs(globalBs_),
              bs(bs_),
              topK(topK_),
              tokenLen(h)
        {}
    };

    // Methods
    CATLASS_DEVICE
    GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspace() {}

    template <int32_t CORE_TYPE = g_coreType>
    CATLASS_DEVICE void operator()(Params const &params);

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
        isShareExpert = (params.epRankId < params.sharedExpertRankNum);
        localExpertNum = isShareExpert ? 1 : moeExpertNumPerRank;
        recvCoreNum = aivNum; // 48 send 48 recv in 1-expert per rank sence
        if (localExpertNum > 1) { // 24 send 24 recv in multi-expert per rank sence
            recvCoreNum = aiCoreGroupNum;
        }
        uint32_t coreNumPerGroup = recvCoreNum / localExpertNum; // Required it's divided evenly
        winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();

        // Update the status of cv communication flag
        statusDataSpaceGm = (GM_ADDR)(winContext_->localWindowsExp);
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
        gmA.SetGlobalBuffer(params.ptrA);
        AscendC::GlobalTensor<ElementB> gmB;
        AscendC::ListTensorDesc gmBlistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrB));
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(gmBlistTensorDesc.GetDataPtr<int32_t>(0)));
        }

        AscendC::GlobalTensor<ElementGroupList> groupList;
        groupList.SetGlobalBuffer(params.ptrGroupList);

        int64_t gmGroupOffsetA = 0;
        int64_t gmGroupOffsetB = 0;

        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        auto layoutC = layout::RowMajor{L1TileShape::M * aicNum * WORKSPACE_STAGES, L1TileShape::N};

        uint32_t stageId = 0;
        uint32_t stageUsed = 0;
        uint32_t startCoreIdx = 0;
        AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
        aicSetFunc1 = {statusDataSpaceGm + SOFT_SYNC_OFFSET,
                       static_cast<uint8_t>(aicNum + AscendC::GetBlockIdx())};
        uint32_t target = 1;
        for (uint32_t groupIdx = 0; groupIdx < localExpertNum; ++groupIdx) {
            if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(
                        gmBlistTensorDesc.GetDataPtr<int32_t>(groupIdx)));
            }
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET) +
                                                     groupIdx * GROUP_INFO_SIZE);
            // Wait until all tokens is received by aiv
            while (true) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                                  AscendC::DcciDst::CACHELINE_OUT>(groupTokenNumStateTensor);
                __asm__ __volatile__("");
                if (groupTokenNumStateTensor.GetValue(0) == params.epRankSize * vToCFlag) {
                    break;
                }
            }

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
                                    target};
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


    struct ComputeGroupTokenNumGetter
    {
        GM_ADDR gmGroupState;
        uint32_t groupReadyValue;

        CATLASS_DEVICE
        uint32_t GetValue(uint32_t groupIdx)
        {
            AscendC::GlobalTensor<uint32_t> tmpGroupStateGlobal;
            tmpGroupStateGlobal.SetGlobalBuffer((__gm__ uint32_t*)gmGroupState + groupIdx * GROUP_INFO_SIZE);
            while (true) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                    AscendC::DcciDst::CACHELINE_OUT>(tmpGroupStateGlobal);
                __asm__ __volatile__("");
                if (tmpGroupStateGlobal.GetValue(0) == groupReadyValue) {
                    break;
                }
            }
            return tmpGroupStateGlobal.GetValue(GROUP_TOKEN_COUNT);
        }
    };

    struct ComputePreBlockCallback
    {
        GM_ADDR gmSync;
        uint32_t target = 1;

        CATLASS_DEVICE
        void operator()(const opx::MatrixDataContext& ctx)
        {
            CheckSyncFlag(gmSync, static_cast<uint8_t>(ctx.block_num + ctx.block_idx), target);
            target += 1;
        }
    };

    struct ComputePstBlockCallback
    {
        GM_ADDR gmSync;

        CATLASS_DEVICE
        void operator()(const opx::MatrixDataContext& ctx)
        {
            EncreaseSyncFlag(gmSync, static_cast<uint8_t>(ctx.block_idx));
        }
    };

    struct ComputeCleanupCallback
    {
        GM_ADDR gmSync;

        CATLASS_DEVICE
        void operator()(const opx::MatrixDataContext& ctx)
        {
            // Clear the flags of the soft-sync
            AscendC::PipeBarrier<PIPE_ALL>();

            AscendC::GlobalTensor<int32_t> syncGlobal;
            syncGlobal.SetGlobalBuffer((__gm__ int32_t*)gmSync);
            AscendC::LocalTensor<int32_t> zeroLocal = GetBufferByByte<int32_t>(0);
            AscendC::Duplicate(zeroLocal, (int32_t)0, INT32_COUNT_PER_BLOCK);
            PipeSync<AscendC::HardEvent::V_MTE3>();
            AscendC::DataCopy(syncGlobal[ctx.block_idx * SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                zeroLocal, INT32_COUNT_PER_BLOCK);
            AscendC::DataCopy(syncGlobal[(ctx.block_idx + ctx.block_num) * SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                zeroLocal, INT32_COUNT_PER_BLOCK);

            AscendC::PipeBarrier<PIPE_ALL>();
            GetTPipePtr()->Reset();
        }
    };

    struct BlockQuantGroupTokenNumGetter
    {
        __gm__ uint32_t* gmTotalTokenNum;

        CATLASS_DEVICE
        uint32_t GetValue(uint32_t groupIdx)
        {
            // Only 1 group
            AscendC::GlobalTensor<uint32_t> totalTokenNumGlobal;
            totalTokenNumGlobal.SetGlobalBuffer(gmTotalTokenNum);
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                AscendC::DcciDst::CACHELINE_OUT>(totalTokenNumGlobal);
            __asm__ __volatile__("");
            return totalTokenNumGlobal.GetValue(0);
        }
    };

    template <>
    CATLASS_DEVICE
    void operator()<AscendC::AIV>(Params const &params)
    {
        using LibOps::MoEContext;
        using LibOps::OpDispatchSendToken;
        using LibOps::OpDispatchRecvToken;
        using LibOps::OpDequant;
        using LibOps::OpSwiglu;
        using LibOps::OpSyncAllCleanAndUpdate;
        using LibOps::OpBlockQuant;
        using LibOps::GmScaleReader;
        using LibOps::GmPerTokenScaleReader;
        using LibOps::GmSwigluOutputWriter;

        AscendC::PipeBarrier<PIPE_ALL>();
        GetTPipePtr()->Reset();

        auto ctx = MoEContext{
            (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>(),
            params.epRankSize, params.epRankId, params.moeExpertNumPerRank,
            params.bs, params.globalBs, params.topK, params.tokenLen, sizeof(XType)
        };

        using DispatchPolicy = typename BlockEpilogue::DispatchPolicy;
        using BlockShape = MatrixShape<GMM1_L1M, GMM1_L1N>;
        using TileShape = MatrixShape<GMM1_EPIM, GMM1_L1N>;

        constexpr uint32_t UB_STAGES = BlockEpilogue::UB_STAGES;
        uint32_t problemShapeM = params.problemShape.m();
        uint32_t problemShapeN = params.problemShape.n();

        LayoutC layoutC{uint32_t(BlockShape::ROW * AscendC::GetBlockNum() * WORKSPACE_STAGES), BlockShape::COLUMN};
        LayoutScale layoutScale = params.layoutScale;
        LayoutPerTokenScale layoutPerTokenScale = params.layoutPerTokenScale;
        LayoutD layoutD{problemShapeM, problemShapeN / 2};
        LayoutDequantScale layoutDequantScale = params.layoutDequantScale;
        LayoutOutput layoutOutput = params.layoutOutput;

        AscendC::GlobalTensor<ElementC> cGlobal;
        AscendC::GlobalTensor<ElementPerTokenScale> perTokenScaleGlobal;
        AscendC::GlobalTensor<ElementD> dGlobal;
        AscendC::GlobalTensor<ElementDequantScale> outDequantScaleGlobal;
        AscendC::GlobalTensor<ElementOutput> outputGlobal;

        cGlobal.SetGlobalBuffer((__gm__ ElementC *)params.ptrWorkspace);
        perTokenScaleGlobal.SetGlobalBuffer((__gm__ ElementPerTokenScale *)params.ptrPerTokenScale);
        dGlobal.SetGlobalBuffer((__gm__ ElementD *)
            ((GM_ADDR)params.ptrWorkspace + sizeof(ElementC) * layoutC.shape(0) * layoutC.shape(1)));
        outDequantScaleGlobal.SetGlobalBuffer((__gm__ ElementDequantScale *)params.ptrDequantScale);
        outputGlobal.SetGlobalBuffer((__gm__ ElementOutput *)params.ptrOutput);

        using Gmm1BlockScheduler =
            typename Gemm::Block::GemmIdentityBlockSwizzle<GMM1_SWIZZLE_OFFSET, GMM1_SWIZZLE_DIRECTION>;

        using GemmTypeC = GemmType<ElementC, LayoutC>;
        using GemmTypeScale = GemmType<ElementScale, LayoutScale>;
        using GemmTypePerTokenScale = GemmType<ElementPerTokenScale, LayoutPerTokenScale>;
        using GemmTypeD = GemmType<ElementD, LayoutD>;
        using GemmTypeDequantScale = GemmType<ElementDequantScale, LayoutDequantScale>;
        using GemmTypeOutput = GemmType<ElementOutput, LayoutOutput>;

        GM_ADDR gmGroupTokenNumState = ctx.gmStatusDataSpace + GROUP_TOKEN_NUM_OFFSET;
        GM_ADDR gmComputeSyncAddr = ctx.gmStatusDataSpace + SOFT_SYNC_OFFSET;

        auto opSendToken = OpDispatchSendToken<XType, BUFFER_NUM, false>{
            ctx, (GM_ADDR)params.gmX, (GM_ADDR)params.gmexpertIds, (GM_ADDR)params.gmExpandIdx};

        auto opRecvToken = OpDispatchRecvToken{
            ctx, (GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale, params.gmEpSendCount, gmGroupTokenNumState};

        constexpr bool ENABLE_TENSOR_LIST = (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) > 0;

        auto opComputeStart = opx::MatrixOpStart<>::GetFactory()
            .SetProblemShape(ComputeGroupTokenNumGetter{gmGroupTokenNumState, ctx.epRankSize * ctx.vToCFlag},
                ctx.moeExpertNumPerRank, problemShapeN)
            .template SetBlockSwizzle<Gmm1BlockScheduler>()
            .SetBlockShape(BlockShape::ToCoord())
            .SetTileShape(TileShape::ToCoord())
            .AddReader(opx::MatrixStackedBlockDataReader<GemmTypeC, UB_STAGES, WORKSPACE_STAGES>{
                cGlobal, layoutC})
            .AddReader(GmScaleReader<GemmTypeScale, UB_STAGES, ENABLE_TENSOR_LIST>{
                (GM_ADDR)params.ptrScale, layoutScale})
            .AddReader(GmPerTokenScaleReader<GemmTypePerTokenScale, UB_STAGES>{
                perTokenScaleGlobal, layoutPerTokenScale})
            .template RegisterCallback<opx::EPILOGUE_PRE_BLOCK_LOOP_CB>(
                ComputePreBlockCallback{gmComputeSyncAddr})
            .template RegisterCallback<opx::EPILOGUE_PST_BLOCK_LOOP_CB>(
                ComputePstBlockCallback{gmComputeSyncAddr})
            .template RegisterCallback<opx::EPILOGUE_PST_LOOP_CB>(
                ComputeCleanupCallback{gmComputeSyncAddr})
            .Build();

        auto opComputeEnd = opx::MatrixOpEnd<>::GetFactory()
            .AddWriter(GmSwigluOutputWriter<GemmTypeD, UB_STAGES>{dGlobal, layoutD})
            .Build();

        auto opDequant = OpDequant<
            DispatchPolicy,
            GemmTypeC,
            GemmTypeScale,
            GemmTypePerTokenScale,
            typename BlockEpilogue::TileRowBroadcastMul,
            typename BlockEpilogue::TileBroadcastOneBlk,
            typename BlockEpilogue::TileOneBlkColumnBroadcastMul>();

        auto opSwiglu = OpSwiglu<DispatchPolicy, TileShape, GemmTypeD>();

        auto opComputeToken = opx::MakeFusedVV(opComputeStart, opDequant, opSwiglu, opComputeEnd);

        auto opRecvAndCompute = opx::MakeSequential(opRecvToken, opComputeToken);

        auto opSyncAllCleanAndUpdate = OpSyncAllCleanAndUpdate{
            ctx, gmGroupTokenNumState, params.gmEpSendCount, (GM_ADDR)params.ptrGroupList, params.gmExpertTokenNums};

        // BlockQuant
        auto gmGroupTokenNum =
            (__gm__ uint32_t*)params.gmEpSendCount + ctx.moeExpertNumPerRank * ctx.epRankSize - 1;
        uint32_t nOut = layoutD.shape(1); // Read from the output of the Swiglu above
        uint32_t quantRowOnce = 0;
        CalQuantRow(nOut, quantRowOnce);

        auto opBlockQuantStart = opx::MatrixOpStart<>::GetFactory()
            .SetProblemShape(BlockQuantGroupTokenNumGetter{gmGroupTokenNum}, 1, nOut)
            .SetBlockShape(MakeCoord(quantRowOnce * (uint32_t)AscendC::GetSubBlockNum(), nOut)) // 1C2V
            .SetTileShape(MakeCoord(quantRowOnce, nOut))
            .AddReader(opx::MatrixDataReader<GemmTypeD, UB_STAGES>{dGlobal, layoutD})
            .Build();

        auto opBlockQuantEnd = opx::MatrixOpEnd<>::GetFactory()
            .AddWriter(opx::MatrixRowDataWriter<GemmTypeDequantScale, UB_STAGES>{
                outDequantScaleGlobal, layoutDequantScale})
            .AddWriter(opx::MatrixDataWriter<GemmTypeOutput, UB_STAGES>{
                outputGlobal, layoutOutput})
            .Build();

        auto opBlockQuantOperation = OpBlockQuant{};

        auto opBlockQuant = opx::MakeFusedVV(opBlockQuantStart, opBlockQuantOperation, opBlockQuantEnd);

        // Merge all together
        auto opParallel = opx::MakeParallel(
            opSendToken, opx::OddParallelStrategy{},
            opRecvAndCompute, opx::EvenParallelStrategy{});

        auto opMerged = opx::MakeSequential(opParallel, opSyncAllCleanAndUpdate, opBlockQuant);

        opMerged.Process();

        AscendC::PipeBarrier<PIPE_ALL>();
    }

private:
    friend struct AicWaitFunc1;
    friend struct AicSetFunc1;

    struct AicWaitFunc1 {
        CATLASS_DEVICE
        AicWaitFunc1() = default;

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

    uint32_t epRankSize{0};
    uint32_t epRankId{0};
    bool hasShareExpert{false};
    bool isShareExpert{false};
    uint32_t expertCntUp{0};
    uint32_t localExpertNum{0};
    uint32_t sharedExpertRankNum{0};
    uint32_t moeExpertNumPerRank{0};
    uint32_t moeExpertNum{0};

    uint32_t hOutSize{0};
    uint32_t scaleParamPad{0};
    uint32_t hCommuSize{0};
    uint32_t axisHCommu{0};
    uint32_t axisBS{0};
    uint32_t axisK{0};
    uint32_t totalTokenCount{0};
    uint32_t expertIdsCnt{0};
    uint32_t tokenLength{0};

    int32_t tokenFlag{0};
    int32_t vToCFlag{0};
    int32_t dataState{0};
    int32_t cvDataState{0};
    int32_t state{0};
    float sumTarget{0.0};

    __gm__ HcclOpResParam *winContext_;
    GM_ADDR statusDataSpaceGm;
    uint32_t stateOffset{0};
    uint64_t expertPerSizeOnWin{0};
    uint64_t winDataSizeOffset{0};

    int64_t ubOffset;

    bool isSendCore{false};
    bool isRecvCore{false};
    bool isCompCore{false};
    uint32_t aiCoreGroupNum{0};
    uint32_t aiCoreGroupIdx{0};
    uint32_t subBlockNum{0};
    uint32_t aicNum{0};
    uint32_t aivNum{0};
    uint32_t sendCoreNum{0};
    uint32_t recvCoreNum{0};
    uint32_t compCoreNum{0};
    uint32_t aivIdx{0};
    uint32_t aicIdx{0};
    uint32_t sendCoreIdx{0};
    uint32_t recvCoreIdx{0};
    uint32_t compCoreIdx{0};
    uint32_t aivStateGlobalCoreIdx{0};
    uint32_t aicStateGlobalCoreIdx{0};
    uint32_t sendToMoeAivNum{0};
    uint32_t sendToShareAivNum{0};
};

}  // namespace Catlass::Gemm::Kernel

namespace Catlass::Gemm::Kernel {

template <class ArchTag>
class BlockQuant
{
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
        halfTileColumn = tileColumn / 2;
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
            copyGmToUbInput(ubInput, gmTileInput, layoutUbInput, layoutGmTileInput);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);

            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
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
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
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
    AscendC::LocalTensor<float> ubQuantF32;
    AscendC::LocalTensor<int32_t> ubQuantS32;
    AscendC::LocalTensor<half> ubQuantF16;

    Epilogue::Tile::CopyGm2Ub<ArchTag, InputType> copyGmToUbInput;
    Epilogue::Tile::CopyUb2Gm<ArchTag, DequantScaleType> copyUbToGmDequantScale;
    Epilogue::Tile::CopyUb2Gm<ArchTag, OutputType> copyUbToGmOutput;
};

template <class BlockMmad_, class BlockEpilogue_, class BlockScheduler_, uint32_t WORKSPACE_STAGES_,
          class ElementGroupList_>
class GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspaceWithShallowDispatch
{
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
    using ElementScale = typename BlockEpilogue::ElementScale;
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
        __gm__ ElementB *ptrB;
        LayoutB layoutB;
        __gm__ ElementScale *ptrScale;
        LayoutScale layoutScale;
        __gm__ ElementPerTokenScale *ptrPerTokenScale;
        LayoutPerTokenScale layoutPerTokenScale;
        __gm__ ElementOutput *ptrOutput;
        LayoutOutput layoutOutput;
        __gm__ ElementDequantScale *ptrDequantScale;
        LayoutDequantScale layoutDequantScale;
        GM_ADDR ptrWorkspace;

        // Methods
        CATLASS_DEVICE
        Params() {}

        CATLASS_DEVICE
        Params(GemmCoord problemShape_, uint32_t problemCount_, GM_ADDR ptrGroupList_, GM_ADDR ptrA_,
               LayoutA const &layoutA_, GM_ADDR ptrB_, LayoutB const &layoutB_, GM_ADDR ptrScale_,
               LayoutScale const &layoutScale_, GM_ADDR ptrPerTokenScale_,
               LayoutPerTokenScale const &layoutPerTokenScale_, GM_ADDR ptrOutput_, LayoutOutput const &layoutOutput_,
               GM_ADDR ptrDequantScale_, LayoutDequantScale const &layoutDequantScale_, GM_ADDR ptrWorkspace_)
            : problemShape(problemShape_),
              problemCount(problemCount_),
              ptrGroupList(reinterpret_cast<__gm__ ElementGroupList *>(ptrGroupList_)),
              ptrA(reinterpret_cast<__gm__ ElementA *>(ptrA_)),
              layoutA(layoutA_),
              ptrB(reinterpret_cast<__gm__ ElementB *>(ptrB_)),
              layoutB(layoutB_),
              ptrScale(reinterpret_cast<__gm__ ElementScale *>(ptrScale_)),
              layoutScale(layoutScale_),
              ptrPerTokenScale(reinterpret_cast<__gm__ ElementPerTokenScale *>(ptrPerTokenScale_)),
              layoutPerTokenScale(layoutPerTokenScale_),
              ptrOutput(reinterpret_cast<__gm__ ElementOutput *>(ptrOutput_)),
              layoutOutput(layoutOutput_),
              ptrDequantScale(reinterpret_cast<__gm__ ElementDequantScale *>(ptrDequantScale_)),
              layoutDequantScale(layoutDequantScale_),
              ptrWorkspace(ptrWorkspace_)
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
        gmA.SetGlobalBuffer(params.ptrA);
        AscendC::GlobalTensor<ElementB> gmB;
        gmB.SetGlobalBuffer(params.ptrB);
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
        for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
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
            gmGroupOffsetB += inGroupProblemShape.k() * inGroupProblemShape.n();

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
            params.ptrWorkspace + sizeof(int32_t) * (L1TileShape::M * coreNum * WORKSPACE_STAGES * L1TileShape::N));

        uint32_t mActual = groupList.GetValue(params.problemCount - 1);
        uint32_t nOut = params.problemShape.n() / 2;

        {
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource);

            uint32_t stageId = 0;
            uint32_t startCoreIdx = 0;
            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                uint32_t currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                                    : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

                LayoutScale layoutScale = params.layoutScale;
                LayoutPerTokenScale layoutPerTokenScale =
                    params.layoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = params.layoutOutput.GetTileLayout(MakeCoord(currentM, nOut));

                EpilogueParams epilogueParams{params.ptrScale + gmGroupOffsetScale,
                                              layoutScale,
                                              params.ptrPerTokenScale + gmGroupOffsetPerTokenScale,
                                              layoutPerTokenScale,
                                              ptrD + gmGroupOffsetD,
                                              layoutD};

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

                gmGroupOffsetScale += inGroupProblemShape.n();
                gmGroupOffsetPerTokenScale += inGroupProblemShape.m();
                gmGroupOffsetD += currentM * nOut;

                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
            }
        }

        Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();

        {
            uint32_t quantRowOnce = 0;
            CalQuantRow(nOut, quantRowOnce);
            typename BlockQuant<ArchTag>::Params quantParams{ptrD,
                                                             params.layoutOutput,
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
            BlockMmad, BlockEpilogue, BlockScheduler, WORKSPACE_STAGES, ElementGroupList>;

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
            BlockMmad, BlockEpilogue, BlockScheduler, WORKSPACE_STAGES, ElementGroupList>;

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
