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
#include "../../fused_deep_moe_utils.h"
#include "catlass/catlass.hpp"
#include "catlass/arch/cross_core_sync.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/coord.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/matrix_coord.hpp"

using namespace Cam;

namespace Catlass::Gemm::Kernel {
namespace GMM2 {
    constexpr uint64_t SOFT_SYNC_OFFSET = 976 * 1024;
    constexpr int64_t AIV_NUM_PER_GROUP = 2;
    constexpr int64_t CORE_NUM_PER_GROUP = 3;
    constexpr int64_t INT32_COUNT_PER_BLOCK = 32 / sizeof(int32_t);
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
        winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
        syncGmAddr = (GM_ADDR)((winContext_)->localWindowsExp);
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
        int64_t gmGroupOffsetC = 0;

        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            // shared expert data is in the front of the workspace
            gmGroupOffsetC += params.sharedGmm2ProblemShape.m() * params.sharedGmm2ProblemShape.n();
        }

        uint32_t startCoreIdx = 0;
        aicSetFunc = {syncGmAddr + GMM2::SOFT_SYNC_OFFSET, static_cast<uint8_t>(AscendC::GetBlockIdx())};
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
            layout::RowMajor layoutC = layout::RowMajor{currentM, params.problemShape.n()};

            blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
            uint32_t coreLoops = blockScheduler.GetCoreLoops();

            // Determine the starting loopIdx of the current core under the current
            uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
            // Loop through the matmul of each groupIdx
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                // Compute block location
                GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                Callback callbackBeforeFixpipe{};
                Callback callbackAfterFixpipe = MakeCallback(&aicSetFunc);

                // Compute initial location in logical coordinates
                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{blockCoord.m() * L1TileShape::M, blockCoord.n() * L1TileShape::N};
                int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                int64_t gmOffsetC = layoutC.GetOffset(offsetC);

                // Compute block-scoped matrix multiply-add
                if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmGroupOffsetC + gmOffsetC], layoutC, actualBlockShape, callbackBeforeFixpipe,
                              callbackAfterFixpipe);
                } else {
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmGroupOffsetC + gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }
            }

            gmGroupOffsetA += inGroupProblemShape.m() * inGroupProblemShape.k();
            gmGroupOffsetC += inGroupProblemShape.m() * inGroupProblemShape.n();
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmGroupOffsetB += inGroupProblemShape.k() * inGroupProblemShape.n();
            }
            startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
        }
        
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            gmA.SetGlobalBuffer(params.ptrSharedA);
            gmB.SetGlobalBuffer(params.ptrSharedB);
            gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));

            GemmCoord inGroupProblemShape = params.sharedGmm2ProblemShape;

            LayoutA layoutA = params.sharedLayoutA;
            LayoutB layoutB = params.sharedLayoutB;
            layout::RowMajor layoutC = layout::RowMajor{
                params.sharedGmm2ProblemShape.m(), params.sharedGmm2ProblemShape.n()};

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
                Callback callbackAfterFixpipe = MakeCallback(&aicSetFunc);

                // Compute initial location in logical coordinates
                MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                MatrixCoord offsetC{blockCoord.m() * L1TileShape::M, blockCoord.n() * L1TileShape::N};
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
            }
        }

        if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
            blockMmad.SynchronizeBlock();
        }
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIV>(Params const &params)
    {
        auto *combiner = (MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *)params.combiner;
        uint32_t coreIdx = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
        uint32_t coreNum = AscendC::GetBlockNum();
        do {
            if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                if (AscendC::GetSubBlockIdx() == 0) {
                    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                }
            }
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource, combiner->GetCalcInfo());

            int64_t gmGroupOffsetC = 0;
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                gmGroupOffsetC += params.sharedGmm2ProblemShape.m() * params.sharedGmm2ProblemShape.n();
            }
            int64_t gmGroupOffsetScale = 0;
            int64_t gmGroupOffsetPerTokenScale = 0;
            int64_t gmGroupOffsetD = 0;
            AscendC::GlobalTensor<ElementGroupList> groupList;
            groupList.SetGlobalBuffer(params.ptrGroupList);

            uint32_t target = 1;
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

                auto layoutC = layout::RowMajor{currentM, params.problemShape.n()};
                LayoutScale layoutScale = params.layoutScale;
                LayoutPerTokenScale layoutPerTokenScale =
                    params.layoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = params.layoutD.GetTileLayout(inGroupProblemShape.GetCoordMN());
                EpilogueParams epilogueParams;
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                            reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace) + gmGroupOffsetC,
                            gmScalePtr, layoutScale,
                            params.ptrPerTokenScale + gmGroupOffsetPerTokenScale, layoutPerTokenScale,
                            params.ptrD + gmGroupOffsetD, layoutD};
                } else {
                    epilogueParams = EpilogueParams{
                                            reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace) + gmGroupOffsetC,
                                            gmScalePtr + gmGroupOffsetScale,
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
                    CheckSyncFlag(syncGmAddr + GMM2::SOFT_SYNC_OFFSET, static_cast<uint8_t>(coreIdx), target);
                    target += 1;
                    blockEpilogue(gmGroupOffsetD, groupIdx, blockShapeMNK, blockCoordMNK, actualBlockShapeMNK);
                }

                gmGroupOffsetC += currentM * params.problemShape.n();
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

                    auto layoutC = layout::RowMajor{
                        params.sharedGmm2ProblemShape.m(), params.sharedGmm2ProblemShape.n()};
                    LayoutScale layoutScale = params.layoutScale;
                    LayoutPerTokenScale layoutPerTokenScale =
                        params.sharedLayoutPerTokenScale.GetTileLayout(
                            inGroupProblemShape.template GetCoordByAxis<0>());
                    LayoutD layoutD = params.sharedLayoutD.GetTileLayout(inGroupProblemShape.GetCoordMN());

                    EpilogueParams epilogueParams{
                        reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace),
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
                        CheckSyncFlag(syncGmAddr + GMM2::SOFT_SYNC_OFFSET, static_cast<uint8_t>(coreIdx), target);
                        target += 1;
                        blockEpilogue(0, UINT32_MAX, blockShapeMNK, blockCoordMNK, actualBlockShapeMNK);
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
        if (AscendC::GetSubBlockIdx() == 0) {
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer((__gm__ int32_t*)(syncGmAddr + GMM2::SOFT_SYNC_OFFSET));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(0);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, GMM2::INT32_COUNT_PER_BLOCK);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopy(softSyncTensor[coreIdx * CVSoftSync::SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                                                tmpZeroLocalTensor, GMM2::INT32_COUNT_PER_BLOCK);
        }
    }

private:

    friend struct AicSetFunc;
    struct AicSetFunc {
        CATLASS_DEVICE
        AicSetFunc() = default;

        CATLASS_DEVICE
        void operator()() const
        {
            EncreaseSyncFlag(flagAddr, idx);
        }

        __gm__ uint8_t *flagAddr;
        uint8_t idx;
    };

    AicSetFunc aicSetFunc;

    AscendC::GlobalTensor<GM_ADDR> epWinContext_;
    __gm__ HcclOpResParam *winContext_;
    GM_ADDR syncGmAddr;
    Arch::Resource<ArchTag> resource;
};

}  // namespace Catlass::Gemm::Kernel

#endif  // ACT_GEMM_KERNEL_GROUPED_MATMUL_M_PER_TOKEN_DEQUANT_MULTISTAGE_WORKSPACE_HPP
