/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function implementation file
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function implementation file
 */
#ifndef ACT_GEMM_KERNEL_GROUPED_MATMUL_M_PER_TOKEN_DEQUANT_MULTISTAGE_WORKSPACE_HPP
#define ACT_GEMM_KERNEL_GROUPED_MATMUL_M_PER_TOKEN_DEQUANT_MULTISTAGE_WORKSPACE_HPP

#include "ascendc/basic_api/interface/kernel_operator_list_tensor_intf.h"
#include "../../raw_distributed/cam_moe_distribute_combine.h"
#include "catlass/catlass.hpp"
#include "catlass/arch/cross_core_sync.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/coord.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/matrix_coord.hpp"

using namespace Cam;
// Use this to make a callback
template <typename Func>
CATLASS_DEVICE
Callback MakeCallbackWithCall(Func *func)
{
    Callback callback;
    callback.func = func;
    callback.caller = [](void const *f) {
        static_cast<Func const *>(f)->Call();
    };
    return callback;
}

template <typename Func>
CATLASS_DEVICE
Callback MakeCallbackWithCall2(Func *func)
{
    Callback callback;
    callback.func = func;
    callback.caller = [](void const *f) {
        static_cast<Func const *>(f)->Call2();
    };
    return callback;
}

#define ENABLE_TENSOR_LIST

namespace Catlass::Gemm::Kernel {
namespace GMM2 {
    constexpr uint32_t SOFT_SYNC_SPACE_SIZE = 128;
    constexpr uint64_t SOFT_SYNC_OFFSET = 964 * 1024;
    constexpr int64_t AIV_NUM_PER_GROUP = 2;
    constexpr int64_t CORE_NUM_PER_GROUP = 3;
}

template <TemplateMC2TypeClass, class BlockMmad_, class BlockEpilogue_, class BlockScheduler_,
          uint32_t WORKSPACE_STAGES_, class ElementGroupList_>
class GroupedMatmulSliceMPerTokenDequantMultiStageWorkspace {
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
        __gm__ ElementD *ptrD;
        LayoutD layoutD;
        uint32_t batchSize;
        GemmCoord sharedGmm2ProblemShape;
        __gm__ ElementA *ptrSharedA;
        __gm__ ElementB *ptrSharedB;
        __gm__ ElementD *ptrSharedD;
        __gm__ ElementScale *ptrSharedScale;
        __gm__ ElementPerTokenScale *ptrSharedPtrPerTokenScale;
        LayoutA sharedLayoutA;
        LayoutB sharedLayoutB;
        LayoutPerTokenScale sharedLayoutPerTokenScale;
        LayoutD sharedLayoutD;
        GM_ADDR ptrWorkspace;
        void *combiner;

        // Methods
        CATLASS_DEVICE
        Params() {}

        CATLASS_DEVICE
        Params(GemmCoord problemShape_, uint32_t problemCount_, GM_ADDR ptrGroupList_, GM_ADDR ptrA_, LayoutA layoutA_,
               GM_ADDR ptrB_, LayoutB layoutB_, GM_ADDR ptrScale_, LayoutScale layoutScale_, GM_ADDR ptrPerTokenScale_,
               LayoutPerTokenScale layoutPerTokenScale_, GM_ADDR ptrD_, LayoutD layoutD_, uint32_t batchSize_,
               GemmCoord sharedGmm2ProblemShape_, GM_ADDR ptrSharedA_, GM_ADDR ptrSharedB_, GM_ADDR ptrSharedD_,
               GM_ADDR ptrSharedScale_, GM_ADDR ptrSharedPtrPerTokenScale_, LayoutA sharedLayoutA_,
               LayoutB sharedLayoutB_,
               LayoutPerTokenScale sharedLayoutPerTokenScale_, LayoutD sharedLayoutD_,
               GM_ADDR ptrWorkspace_, void *combiner_)
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
              ptrD(reinterpret_cast<__gm__ ElementD *>(ptrD_)),
              layoutD(layoutD_),
              batchSize(batchSize_),
              sharedGmm2ProblemShape(sharedGmm2ProblemShape_),
              ptrSharedB(reinterpret_cast<__gm__ ElementB *>(ptrSharedB_)),
              ptrSharedScale(reinterpret_cast<__gm__ ElementScale *>(ptrSharedScale_)),
              ptrSharedD(reinterpret_cast<__gm__ ElementD *>(ptrSharedD_)),
              ptrSharedA(reinterpret_cast<__gm__ ElementA *>(ptrSharedA_)),
              ptrSharedPtrPerTokenScale(reinterpret_cast<__gm__ ElementPerTokenScale *>(ptrSharedPtrPerTokenScale_)),
              sharedLayoutA(sharedLayoutA_),
              sharedLayoutB(sharedLayoutB_),
              sharedLayoutPerTokenScale(sharedLayoutPerTokenScale_),
              sharedLayoutD(sharedLayoutD_),
              ptrWorkspace(ptrWorkspace_),
              combiner(combiner_)
        {}
    };

    // Methods
    CATLASS_DEVICE
    GroupedMatmulSliceMPerTokenDequantMultiStageWorkspace(uint32_t epRankId = 0)
    {
        Arch::FlagID flagId = 0;
        for (uint32_t stageId = 0; stageId < WORKSPACE_STAGES; ++stageId) {
            flagAicFinishStoreList[stageId] = Arch::CrossCoreFlag(flagId++);
            flagAivFinishComputeList[stageId] = Arch::CrossCoreFlag(flagId++);
            aicWaitFuncList[stageId] = {this, stageId};
            aicSetFuncList[stageId] = {this, stageId};
        }
        winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
        syncGmAddr = (GM_ADDR)((winContext_)->localWindowsExp) + GMM2::SOFT_SYNC_OFFSET +
                        (AscendC::GetBlockIdx() / AscendC::GetSubBlockNum() * GMM2::CORE_NUM_PER_GROUP) *
                        WORKSPACE_STAGES * GMM2::SOFT_SYNC_SPACE_SIZE;
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

            // Determine the starting loopIdx of the current core under the current
            // groupIdx
            uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
            // Loop through the matmul of each groupIdx
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                // Compute block location
                GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                Callback callbackBeforeFixpipe{};
                if (stageUsed == WORKSPACE_STAGES) {
                    callbackBeforeFixpipe = MakeCallbackWithCall2(&aicWaitFuncList[stageId]);
                } else {
                    ++stageUsed;
                }
                Callback callbackAfterFixpipe = MakeCallbackWithCall2(&aicSetFuncList[stageId]);

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
        
        bool skipWithSoft[WORKSPACE_STAGES] = {};
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            gmA.SetGlobalBuffer(params.ptrSharedA);
            gmB.SetGlobalBuffer(params.ptrSharedB);
            uint32_t softStageUsed = 0;
            GemmCoord inGroupProblemShape = params.sharedGmm2ProblemShape;

            LayoutA layoutA = params.sharedLayoutA;
            LayoutB layoutB = params.sharedLayoutB;

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
                if (softStageUsed == WORKSPACE_STAGES) {
                    callbackBeforeFixpipe = MakeCallbackWithCall(&aicWaitFuncList[stageId]);
                } else {
                    if (stageUsed == WORKSPACE_STAGES) {
                        callbackBeforeFixpipe = MakeCallbackWithCall2(&aicWaitFuncList[stageId]);
                    } else {
                        ++stageUsed;
                    }
                    ++softStageUsed;
                    skipWithSoft[stageId] = true;
                }
                Callback callbackAfterFixpipe = MakeCallbackWithCall(&aicSetFuncList[stageId]);

                // Compute initial location in logical coordinates
                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
                int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                int64_t gmOffsetC = layoutC.GetOffset(offsetC);

                // Compute block-scoped matrix multiply-add
                if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                    blockMmad(
                        gmA[gmOffsetA], layoutA,
                        gmB[gmOffsetB], layoutB,
                        gmC[gmOffsetC], layoutC,
                        actualBlockShape,
                        callbackBeforeFixpipe, callbackAfterFixpipe
                    );
                } else {
                    callbackBeforeFixpipe();
                    blockMmad(
                        gmA[gmOffsetA], layoutA,
                        gmB[gmOffsetB], layoutB,
                        gmC[gmOffsetC], layoutC,
                        actualBlockShape
                    );
                    callbackAfterFixpipe();
                }

                stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
            }
        }

        if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
            blockMmad.SynchronizeBlock();
        }

        while (stageUsed > 0) {
            uint32_t aivComputeStageId = (stageId >= stageUsed) ?
                (stageId - stageUsed) : (stageId + WORKSPACE_STAGES - stageUsed);
            if (skipWithSoft[aivComputeStageId]) {
                Callback callbackBeforeFixpipe = MakeCallbackWithCall(&aicWaitFuncList[aivComputeStageId]);
                callbackBeforeFixpipe();
            } else {
                Callback callbackBeforeFixpipe = MakeCallbackWithCall2(&aicWaitFuncList[aivComputeStageId]);
                callbackBeforeFixpipe();
            }
            --stageUsed;
        }
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIV>(Params const &params)
    {
        auto *combiner = (MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *)params.combiner;
        do {
            if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                if (AscendC::GetSubBlockIdx() == 0) {
                    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                }
            }
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource, combiner->GetCalcInfo());

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

            uint32_t stageId = 0;
            uint32_t startCoreIdx = 0;
            AscendC::ListTensorDesc gmScaleListTensor;
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
                LayoutD layoutD = params.layoutD.GetTileLayout(inGroupProblemShape.GetCoordMN());
                EpilogueParams epilogueParams;
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                            gmScalePtr, layoutScale,
                            params.ptrPerTokenScale + gmGroupOffsetPerTokenScale, layoutPerTokenScale,
                            params.ptrD + gmGroupOffsetD, layoutD};
                } else {
                    epilogueParams = EpilogueParams{gmScalePtr + gmGroupOffsetScale,
                                              layoutScale,
                                              params.ptrPerTokenScale + gmGroupOffsetPerTokenScale,
                                              layoutPerTokenScale,
                                              params.ptrD + gmGroupOffsetD,
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
                    Callback callbackBeforeBlockEpilogue = MakeCallbackWithCall2(&aicWaitFuncList[stageId]);
                    Callback callbackAfterBlockEpilogue = MakeCallbackWithCall2(&aicSetFuncList[stageId]);

                    callbackBeforeBlockEpilogue();
                    blockEpilogue(gmGroupOffsetD, groupIdx, blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC,
                                  layoutBlockC);
                    callbackAfterBlockEpilogue();

                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }

                if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                    gmGroupOffsetScale += inGroupProblemShape.n();
                }
                gmGroupOffsetPerTokenScale += inGroupProblemShape.m();
                gmGroupOffsetD += inGroupProblemShape.m() * inGroupProblemShape.n();

                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
            }
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                if (AscendC::GetSubBlockIdx() == 0) {
                    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                    if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
                        AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                    }
                    GemmCoord inGroupProblemShape = params.sharedGmm2ProblemShape;

                    LayoutScale layoutScale = params.layoutScale;
                    LayoutPerTokenScale layoutPerTokenScale =
                        params.sharedLayoutPerTokenScale.GetTileLayout(
                            inGroupProblemShape.template GetCoordByAxis<0>());
                    LayoutD layoutD = params.sharedLayoutD.GetTileLayout(inGroupProblemShape.GetCoordMN());

                    EpilogueParams epilogueParams{
                        params.ptrSharedScale, layoutScale,
                        params.ptrSharedPtrPerTokenScale, layoutPerTokenScale,
                        params.ptrSharedD, layoutD
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
                        Callback callbackBeforeBlockEpilogue = MakeCallbackWithCall(&aicWaitFuncList[stageId]);
                        Callback callbackAfterBlockEpilogue = MakeCallbackWithCall(&aicSetFuncList[stageId]);

                        callbackBeforeBlockEpilogue();
                        blockEpilogue(0, UINT32_MAX, blockShapeMNK, blockCoordMNK, actualBlockShapeMNK,
                            gmBlockC, layoutBlockC);
                        callbackAfterBlockEpilogue();

                        stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                    }
                    AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                    AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                }
            }
        } while (false);

        icache_preload(4);
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            if (AscendC::GetSubBlockIdx() == 1) {
                resource.pipe.Init();
                combiner->TPipeSet(&resource.pipe);
                combiner->ProcessCombine();
                combiner->TPipeSet(nullptr);
                resource.pipe.Destroy();
            }
        } else if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            if (AscendC::GetSubBlockIdx() == 0) {
                resource.pipe.Init();
                combiner->TPipeSet(&resource.pipe);
                combiner->AllToAllSend();
                combiner->TPipeSet(nullptr);
                resource.pipe.Destroy();
            } else {
                resource.pipe.Init();
                combiner->TPipeSet(&resource.pipe);
                combiner->ReducePermute();
                combiner->TPipeSet(nullptr);
                resource.pipe.Destroy();
            }
        } else {
            resource.pipe.Init();
            combiner->TPipeSet(&resource.pipe);
            combiner->Process();
            combiner->TPipeSet(nullptr);
            resource.pipe.Destroy();
        }
    }

private:
    friend struct AicWaitFunc;
    friend struct AicSetFunc;

    struct AicWaitFunc {
        using MatmulKernel =
            GroupedMatmulSliceMPerTokenDequantMultiStageWorkspace<TemplateMC2TypeFunc, BlockMmad, BlockEpilogue,
                                                                  BlockScheduler, WORKSPACE_STAGES, ElementGroupList>;

        CATLASS_DEVICE
        AicWaitFunc() = default;

        CATLASS_DEVICE
        void Call() const
        {
            constexpr uint32_t waitValue = g_coreType == AscendC::AIC ? 0 : 1;
            // wait flag
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint8_t> global;
            global.SetGlobalBuffer(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::CORE_NUM_PER_GROUP +
                GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::AIV_NUM_PER_GROUP);
            while (true) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
                __asm__ __volatile__("");
                uint8_t value = global.GetValue(0);
                if (value == waitValue) {
                    __asm__ __volatile__("");
                    AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
                    __asm__ __volatile__("");
                    break;
                }
                SPIN_WAIT_CYCLES();
            }
            AscendC::PipeBarrier<PIPE_ALL>();
        }

        CATLASS_DEVICE
        void Call2() const
        {
            constexpr uint32_t waitValue = g_coreType == AscendC::AIC ? 0 : 1;
            // wait flag
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint8_t> global;
            global.SetGlobalBuffer(ptr->syncGmAddr + stageId *  GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::CORE_NUM_PER_GROUP);
            int32_t waitOffset[2];
            if constexpr (g_coreType == AscendC::AIC) {
                waitOffset[0] = 0;
                waitOffset[1] = GMM2::SOFT_SYNC_SPACE_SIZE;
            } else {
                waitOffset[0] = get_subblockid() * GMM2::SOFT_SYNC_SPACE_SIZE;
            }

            while (true) {
                if constexpr (g_coreType == AscendC::AIC) {
                    if (waitOffset[0] != -1) {
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                            global[waitOffset[0]]);
                        __asm__ __volatile__("");
                        uint8_t value = global.GetValue(waitOffset[0]);
                        if (value == waitValue) {
                            __asm__ __volatile__("");
                            AscendC::DataCacheCleanAndInvalid<uint8_t,
                                AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                                global[waitOffset[0]]);
                            __asm__ __volatile__("");
                            waitOffset[0] = -1;
                        }
                    }
                    if (waitOffset[1] != -1) {
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                            global[waitOffset[1]]);
                        __asm__ __volatile__("");
                        uint8_t value = global.GetValue(waitOffset[1]);
                        if (value == waitValue) {
                            __asm__ __volatile__("");
                            AscendC::DataCacheCleanAndInvalid<uint8_t,
                                AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                                global[waitOffset[1]]);
                            __asm__ __volatile__("");
                            waitOffset[1] = -1;
                        }
                    }
                    if (waitOffset[0] == -1 && waitOffset[1] == -1) {
                        break;
                    }
                } else {
                    __asm__ __volatile__("");
                    AscendC::DataCacheCleanAndInvalid<uint8_t,
                        AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                        global[waitOffset[0]]);
                    __asm__ __volatile__("");
                    uint8_t value = global.GetValue(waitOffset[0]);
                    if (value == waitValue) {
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                            global[waitOffset[0]]);
                        __asm__ __volatile__("");
                        break;
                    }
                }
                SPIN_WAIT_CYCLES();
            }
            AscendC::PipeBarrier<PIPE_ALL>();
        }

        CATLASS_DEVICE
        void operator()() const
        {
            Arch::CrossCoreWaitFlag(ptr->flagAivFinishComputeList[stageId]);
        }

        MatmulKernel *ptr{nullptr};
        uint32_t stageId;
    };

    struct AicSetFunc {
        using MatmulKernel =
            GroupedMatmulSliceMPerTokenDequantMultiStageWorkspace<TemplateMC2TypeFunc, BlockMmad, BlockEpilogue,
                                                                  BlockScheduler, WORKSPACE_STAGES, ElementGroupList>;

        CATLASS_DEVICE
        AicSetFunc() = default;

        CATLASS_DEVICE
        void Call() const
        {
            constexpr uint32_t setValue = g_coreType == AscendC::AIC ? 1 : 0;
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint8_t> global;
            global.SetGlobalBuffer(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::CORE_NUM_PER_GROUP +
                GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::AIV_NUM_PER_GROUP);
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            global.SetValue(0, setValue);
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint8_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            AscendC::PipeBarrier<PIPE_ALL>();
        }

        CATLASS_DEVICE
        void Call2() const
        {
            constexpr uint32_t setValue = g_coreType == AscendC::AIC ? 1 : 0;
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint8_t> global;
            global.SetGlobalBuffer(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::CORE_NUM_PER_GROUP);
            int32_t waitOffset[2];
            if constexpr (g_coreType == AscendC::AIC) {
                waitOffset[0] = 0;
                waitOffset[1] = GMM2::SOFT_SYNC_SPACE_SIZE;
            } else {
                waitOffset[0] = get_subblockid() * (GMM2::SOFT_SYNC_SPACE_SIZE);
            }
            if constexpr (g_coreType == AscendC::AIC) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
                global.SetValue(waitOffset[0], setValue);
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[1]]);
                __asm__ __volatile__("");
                global.SetValue(waitOffset[1], setValue);
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[1]]);
                __asm__ __volatile__("");
            } else {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
                global.SetValue(waitOffset[0], setValue);
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint8_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
            }
            AscendC::PipeBarrier<PIPE_ALL>();
        }

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
    AscendC::GlobalTensor<GM_ADDR> epWinContext_;
    __gm__ HcclOpResParam *winContext_;
    GM_ADDR syncGmAddr;
    Arch::Resource<ArchTag> resource;
};

}  // namespace Catlass::Gemm::Kernel

#endif  // ACT_GEMM_KERNEL_GROUPED_MATMUL_M_PER_TOKEN_DEQUANT_MULTISTAGE_WORKSPACE_HPP
