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
    // Matmul high-level staging uses CrossCore flag IDs 0..7 when WORKSPACE_STAGES is 4.
    constexpr uint32_t ROUND_READY_FLAG_ID = 10;
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
        GM_ADDR gmEpSendCount;
        uint32_t epRankSize;
        uint32_t epRankId;
        uint32_t moeExpertNum;
        uint32_t moeExpertNumPerRank;
        uint32_t roundRecvTokenNum;
        uint32_t roundIdx;
        uint32_t *roundNum;

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
               GM_ADDR ptrWorkspace_, void *combiner_, GM_ADDR gmEpSendCount_ = nullptr,
               uint32_t epRankSize_ = 0, uint32_t epRankId_ = 0, uint32_t moeExpertNum_ = 0,
               uint32_t moeExpertNumPerRank_ = 0, uint32_t roundRecvTokenNum_ = 0,
               uint32_t roundIdx_ = 0xFFFFFFFFU, uint32_t *roundNum_ = nullptr)
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
              combiner(combiner_),
              gmEpSendCount(gmEpSendCount_),
              epRankSize(epRankSize_),
              epRankId(epRankId_),
              moeExpertNum(moeExpertNum_),
              moeExpertNumPerRank(moeExpertNumPerRank_),
              roundRecvTokenNum(roundRecvTokenNum_),
              roundIdx(roundIdx_),
              roundNum(roundNum_)
        {}
    };

    // Methods
    CATLASS_DEVICE
    GroupedMatmulSliceMPerTokenDequantMultiStageWorkspace(
        uint32_t epRankId = 0,
        GM_ADDR metaInfoGm = nullptr,
        uint64_t statusDataSpaceOffset = 0)
    {
        Arch::FlagID flagId = 0;
        for (uint32_t stageId = 0; stageId < WORKSPACE_STAGES; ++stageId) {
            flagAicFinishStoreList[stageId] = Arch::CrossCoreFlag(flagId++);
            flagAivFinishComputeList[stageId] = Arch::CrossCoreFlag(flagId++);
            aicWaitFuncList[stageId] = {this, stageId};
            aicSetFuncList[stageId] = {this, stageId};
        }
        if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
            syncGmAddr = metaInfoGm + statusDataSpaceOffset + GMM2::SOFT_SYNC_OFFSET +
                         (AscendC::GetBlockIdx() / AscendC::GetSubBlockNum() * GMM2::CORE_NUM_PER_GROUP) *
                         WORKSPACE_STAGES * GMM2::SOFT_SYNC_SPACE_SIZE;
        } else {
            winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
            syncGmAddr = (GM_ADDR)((winContext_)->localWindowsExp) + GMM2::SOFT_SYNC_OFFSET +
                         (AscendC::GetBlockIdx() / AscendC::GetSubBlockNum() * GMM2::CORE_NUM_PER_GROUP) *
                         WORKSPACE_STAGES * GMM2::SOFT_SYNC_SPACE_SIZE;
        }
    }

    template <int32_t CORE_TYPE = g_coreType>
    CATLASS_DEVICE void operator()(Params const &params);

    CATLASS_DEVICE
    void GetLocalBucketRange(Params const &params, uint32_t srcRank, uint32_t groupIdx,
                             uint32_t &bucketStart, uint32_t &bucketEnd)
    {
        AscendC::GlobalTensor<int32_t> sendCountsGlobalTensor;
        sendCountsGlobalTensor.SetGlobalBuffer((__gm__ int32_t *)params.gmEpSendCount);
        uint32_t globalExpertId = params.epRankId * params.moeExpertNumPerRank + groupIdx;
        uint32_t offsetIdx = globalExpertId * params.epRankSize + srcRank;
        uint32_t col = offsetIdx % params.moeExpertNum;

        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                          AscendC::DcciDst::CACHELINE_OUT>(sendCountsGlobalTensor[offsetIdx]);
        if (col != 0) {
            AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                              AscendC::DcciDst::CACHELINE_OUT>(
                sendCountsGlobalTensor[offsetIdx - 1]);
        }
        __asm__ __volatile__("");

        bucketEnd = sendCountsGlobalTensor.GetValue(offsetIdx);
        bucketStart = (col == 0) ? 0 : sendCountsGlobalTensor.GetValue(offsetIdx - 1);
    }

    CATLASS_DEVICE
    void GetRoundGroupRange(Params const &params, uint32_t srcRank, uint32_t groupIdx, uint32_t roundIdx,
                            uint32_t &groupRoundStart, uint32_t &groupRoundEnd)
    {
        uint32_t bucketStart = 0;
        uint32_t bucketEnd = 0;
        GetLocalBucketRange(params, srcRank, groupIdx, bucketStart, bucketEnd);
        uint32_t roundStart = roundIdx * params.roundRecvTokenNum;
        uint32_t roundEnd = roundStart + params.roundRecvTokenNum;

        if (roundStart >= bucketEnd || roundEnd <= bucketStart || bucketEnd <= bucketStart) {
            groupRoundStart = bucketStart;
            groupRoundEnd = bucketStart;
            return;
        }

        groupRoundStart = roundStart > bucketStart ? roundStart : bucketStart;
        groupRoundEnd = roundEnd < bucketEnd ? roundEnd : bucketEnd;
    }

    CATLASS_DEVICE
    void RunRoutingAicRound(Params const &params, uint32_t roundIdx)
    {
        BlockScheduler blockScheduler;
        BlockMmad blockMmad(resource);

        AscendC::GlobalTensor<ElementA> gmA;
        gmA.SetGlobalBuffer(params.ptrA);
        AscendC::GlobalTensor<ElementB> gmB;
        AscendC::ListTensorDesc gmBlistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrB));
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(gmBlistTensorDesc.GetDataPtr<int32_t>(0)));
        }

        uint32_t coreIdx = AscendC::GetBlockIdx();
        uint32_t coreNum = AscendC::GetBlockNum();
        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        auto layoutC = layout::RowMajor{L1TileShape::M * coreNum * WORKSPACE_STAGES, L1TileShape::N};

        uint32_t stageId = 0;
        uint32_t stageUsed = 0;
        uint32_t startCoreIdx = 0;
        for (uint32_t srcRank = 0; srcRank < params.epRankSize; ++srcRank) {
            int64_t gmGroupOffsetB = 0;
            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(
                            gmBlistTensorDesc.GetDataPtr<int32_t>(groupIdx)));
                }

                uint32_t groupRoundStart = 0;
                uint32_t groupRoundEnd = 0;
                GetRoundGroupRange(params, srcRank, groupIdx, roundIdx, groupRoundStart, groupRoundEnd);
                uint32_t currentM = groupRoundEnd - groupRoundStart;
                if (currentM == 0) {
                    if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                        gmGroupOffsetB += params.problemShape.k() * params.problemShape.n();
                    }
                    continue;
                }

                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};
                LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
                LayoutB layoutB = params.layoutB;
                blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
                uint32_t coreLoops = blockScheduler.GetCoreLoops();
                uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                    GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);

                    Callback callbackBeforeFixpipe{};
                    if (stageUsed == WORKSPACE_STAGES) {
                        callbackBeforeFixpipe = MakeCallbackWithCall2(&aicWaitFuncList[stageId]);
                    } else {
                        ++stageUsed;
                    }
                    Callback callbackAfterFixpipe = MakeCallbackWithCall2(&aicSetFuncList[stageId]);

                    MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
                    MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
                    MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
                    int64_t gmOffsetA = layoutA.GetOffset(offsetA);
                    int64_t gmOffsetB = layoutB.GetOffset(offsetB);
                    int64_t gmOffsetC = layoutC.GetOffset(offsetC);
                    uint32_t roundBufferStart = groupRoundStart - roundIdx * params.roundRecvTokenNum;
                    int64_t gmGroupOffsetA = static_cast<int64_t>(roundBufferStart) * params.problemShape.k();

                    if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                        blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB],
                                  layoutB, gmC[gmOffsetC], layoutC, actualBlockShape, callbackBeforeFixpipe,
                                  callbackAfterFixpipe);
                    } else {
                        callbackBeforeFixpipe();
                        blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB],
                                  layoutB, gmC[gmOffsetC], layoutC, actualBlockShape);
                        callbackAfterFixpipe();
                    }
                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }
                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
                if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                    gmGroupOffsetB += params.problemShape.k() * params.problemShape.n();
                }
            }
        }

        if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
            blockMmad.SynchronizeBlock();
        }
        while (stageUsed > 0) {
            uint32_t aivComputeStageId =
                (stageId >= stageUsed) ? (stageId - stageUsed) : (stageId + WORKSPACE_STAGES - stageUsed);
            Callback callbackBeforeFixpipe = MakeCallbackWithCall2(&aicWaitFuncList[aivComputeStageId]);
            callbackBeforeFixpipe();
            --stageUsed;
        }
    }

    CATLASS_DEVICE
    void RunRoutingAivRound(Params const &params, uint32_t roundIdx)
    {
        auto *combiner = (MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *)params.combiner;
        BlockScheduler blockScheduler;
        BlockEpilogue blockEpilogue(resource, combiner->GetCalcInfo());
        uint32_t coreIdx = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
        uint32_t coreNum = AscendC::GetBlockNum();
        AscendC::GlobalTensor<ElementC> gmC;
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        auto layoutC = layout::RowMajor{L1TileShape::M * coreNum * WORKSPACE_STAGES, L1TileShape::N};

        uint32_t stageId = 0;
        uint32_t startCoreIdx = 0;
        AscendC::ListTensorDesc gmScaleListTensor(reinterpret_cast<__gm__ void *>(params.ptrScale));
        __gm__ ElementScale* gmScalePtr;
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(gmScaleListTensor.GetDataPtr<int32_t>(0));
        }

        for (uint32_t srcRank = 0; srcRank < params.epRankSize; ++srcRank) {
            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                uint32_t groupRoundStart = 0;
                uint32_t groupRoundEnd = 0;
                GetRoundGroupRange(params, srcRank, groupIdx, roundIdx, groupRoundStart, groupRoundEnd);
                uint32_t currentM = groupRoundEnd - groupRoundStart;
                if (currentM == 0) {
                    continue;
                }

                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};
                LayoutScale layoutScale = params.layoutScale;
                LayoutPerTokenScale layoutPerTokenScale = layout::VectorLayout{currentM};
                LayoutD layoutD = layout::RowMajor{currentM, params.problemShape.n()};
                uint32_t roundBufferStart = groupRoundStart - roundIdx * params.roundRecvTokenNum;
                EpilogueParams epilogueParams;
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                            gmScalePtr, layoutScale,
                            params.ptrPerTokenScale + roundBufferStart, layoutPerTokenScale,
                            params.ptrD + static_cast<int64_t>(groupRoundStart) * params.problemShape.n(), layoutD};
                } else {
                    epilogueParams = EpilogueParams{gmScalePtr + groupIdx * params.problemShape.n(),
                                              layoutScale,
                                              params.ptrPerTokenScale + roundBufferStart,
                                              layoutPerTokenScale,
                                              params.ptrD + static_cast<int64_t>(groupRoundStart) *
                                                params.problemShape.n(),
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
                    blockEpilogue(static_cast<int64_t>(groupRoundStart) * params.problemShape.n(), groupIdx,
                                  blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC, layoutBlockC);
                    callbackAfterBlockEpilogue();
                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }
                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
            }
        }
        icache_preload(4);
    }

    CATLASS_DEVICE
    void RunFinalizeAic(Params const &params)
    {
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT)) {
            return;
        }
        BlockScheduler blockScheduler;
        BlockMmad blockMmad(resource);
        AscendC::GlobalTensor<ElementA> gmA;
        AscendC::GlobalTensor<ElementB> gmB;
        AscendC::GlobalTensor<ElementC> gmC;
        gmA.SetGlobalBuffer(params.ptrSharedA);
        gmB.SetGlobalBuffer(params.ptrSharedB);
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        uint32_t coreIdx = AscendC::GetBlockIdx();
        uint32_t coreNum = AscendC::GetBlockNum();
        auto layoutC = layout::RowMajor{L1TileShape::M * coreNum * WORKSPACE_STAGES, L1TileShape::N};

        uint32_t stageId = 0;
        uint32_t stageUsed = 0;
        uint32_t softStageUsed = 0;
        uint32_t startCoreIdx = 0;
        bool skipWithSoft[WORKSPACE_STAGES] = {};
        GemmCoord inGroupProblemShape = params.sharedGmm2ProblemShape;
        LayoutA layoutA = params.sharedLayoutA;
        LayoutB layoutB = params.sharedLayoutB;
        blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
        uint32_t coreLoops = blockScheduler.GetCoreLoops();
        uint32_t startLoopIdx = ((coreIdx < startCoreIdx) ? (coreIdx + coreNum) : coreIdx) - startCoreIdx;
        for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
            GemmCoord blockCoord = blockScheduler.GetBlockCoord(loopIdx);
            GemmCoord actualBlockShape = blockScheduler.GetActualBlockShape(blockCoord);
            Callback callbackBeforeFixpipe{};
            if (softStageUsed == WORKSPACE_STAGES) {
                callbackBeforeFixpipe = MakeCallbackWithCall(&aicWaitFuncList[stageId]);
            } else {
                ++stageUsed;
                ++softStageUsed;
                skipWithSoft[stageId] = true;
            }
            Callback callbackAfterFixpipe = MakeCallbackWithCall(&aicSetFuncList[stageId]);
            MatrixCoord offsetA{blockCoord.m() * L1TileShape::M, blockCoord.k() * L1TileShape::K};
            MatrixCoord offsetB{blockCoord.k() * L1TileShape::K, blockCoord.n() * L1TileShape::N};
            MatrixCoord offsetC{(stageId * coreNum + coreIdx) * L1TileShape::M, 0};
            int64_t gmOffsetA = layoutA.GetOffset(offsetA);
            int64_t gmOffsetB = layoutB.GetOffset(offsetB);
            int64_t gmOffsetC = layoutC.GetOffset(offsetC);
            if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB, gmC[gmOffsetC], layoutC,
                    actualBlockShape, callbackBeforeFixpipe, callbackAfterFixpipe);
            } else {
                callbackBeforeFixpipe();
                blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB, gmC[gmOffsetC], layoutC,
                    actualBlockShape);
                callbackAfterFixpipe();
            }
            stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
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

    CATLASS_DEVICE
    void RunFinalizeAiv(Params const &params)
    {
        auto *combiner = (MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *)params.combiner;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            if (AscendC::GetSubBlockIdx() == 0) {
                BlockScheduler blockScheduler;
                BlockEpilogue blockEpilogue(resource, combiner->GetCalcInfo());
                uint32_t coreIdx = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
                uint32_t coreNum = AscendC::GetBlockNum();
                AscendC::GlobalTensor<ElementC> gmC;
                gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
                auto layoutC = layout::RowMajor{L1TileShape::M * coreNum * WORKSPACE_STAGES, L1TileShape::N};
                uint32_t stageId = 0;
                uint32_t startCoreIdx = 0;
                AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
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
                    blockEpilogue(0, UINT32_MAX, blockShapeMNK, blockCoordMNK, actualBlockShapeMNK, gmBlockC,
                        layoutBlockC);
                    callbackAfterBlockEpilogue();
                    stageId = (stageId + 1 < WORKSPACE_STAGES) ? (stageId + 1) : 0;
                }
                AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
            }
            if (AscendC::GetSubBlockIdx() == 1) {
                resource.pipe.Init();
                combiner->TPipeSet(&resource.pipe);
                combiner->ProcessCombine();
                combiner->TPipeSet(nullptr);
                resource.pipe.Destroy();
            }
        } else if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            // Restore the pre-combine receive event issued by the original non-round GMM2 path.
            if (AscendC::GetSubBlockIdx() == 0) {
                AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
            }
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

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIC>(Params const &params)
    {
        RunRoundAic(params);
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIV>(Params const &params)
    {
        RunRoundAiv(params);
    }

    CATLASS_DEVICE
    void RunRoundAic(Params const &params)
    {
        uint32_t roundNum = params.roundNum == nullptr ? 1 : *(params.roundNum);
        if (params.roundIdx >= roundNum) {
            RunFinalizeAic(params);
            return;
        }

        Arch::CrossCoreFlag gmm2RoundReady{static_cast<Arch::FlagID>(GMM2::ROUND_READY_FLAG_ID)};
        RunRoutingAicRound(params, params.roundIdx);
        Arch::CrossCoreWaitFlag(gmm2RoundReady);
    }

    CATLASS_DEVICE
    void RunRoundAiv(Params const &params)
    {
        uint32_t roundNum = params.roundNum == nullptr ? 1 : *(params.roundNum);
        if (params.roundIdx >= roundNum) {
            RunFinalizeAiv(params);
            return;
        }

        Arch::CrossCoreFlag gmm2RoundReady{static_cast<Arch::FlagID>(GMM2::ROUND_READY_FLAG_ID)};
        RunRoutingAivRound(params, params.roundIdx);
        Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();
        Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(gmm2RoundReady);
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
            // 查看flag，类似wait flag
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint32_t> global;
            global.SetGlobalBuffer((__gm__ uint32_t *)(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE *
                GMM2::CORE_NUM_PER_GROUP + GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::AIV_NUM_PER_GROUP));
            while (true) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
                __asm__ __volatile__("");
                uint32_t value = global.GetValue(0);
                if (value == waitValue) {
                    __asm__ __volatile__("");
                    AscendC::DataCacheCleanAndInvalid<uint32_t,
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
            // 查看flag，类似wait flag
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint32_t> global;
            global.SetGlobalBuffer((__gm__ uint32_t *)(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE *
                GMM2::CORE_NUM_PER_GROUP));
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
                        AscendC::DataCacheCleanAndInvalid<uint32_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                            global[waitOffset[0]]);
                        __asm__ __volatile__("");
                        uint32_t value = global.GetValue(waitOffset[0]);
                        if (value == waitValue) {
                            __asm__ __volatile__("");
                            AscendC::DataCacheCleanAndInvalid<uint32_t,
                                AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                                global[waitOffset[0]]);
                            __asm__ __volatile__("");
                            waitOffset[0] = -1;
                        }
                    }
                    if (waitOffset[1] != -1) {
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<uint32_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                            global[waitOffset[1]]);
                        __asm__ __volatile__("");
                        uint32_t value = global.GetValue(waitOffset[1]);
                        if (value == waitValue) {
                            __asm__ __volatile__("");
                            AscendC::DataCacheCleanAndInvalid<uint32_t,
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
                    AscendC::DataCacheCleanAndInvalid<uint32_t,
                        AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                        global[waitOffset[0]]);
                    __asm__ __volatile__("");
                    uint32_t value = global.GetValue(waitOffset[0]);
                    if (value == waitValue) {
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<uint32_t,
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
            AscendC::GlobalTensor<uint32_t> global;
            global.SetGlobalBuffer((__gm__ uint32_t *)(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE *
                GMM2::CORE_NUM_PER_GROUP + GMM2::SOFT_SYNC_SPACE_SIZE * GMM2::AIV_NUM_PER_GROUP));
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint32_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            global.SetValue(0, setValue);
            __asm__ __volatile__("");
            AscendC::DataCacheCleanAndInvalid<uint32_t,
                            AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(global);
            __asm__ __volatile__("");
            AscendC::PipeBarrier<PIPE_ALL>();
        }

        CATLASS_DEVICE
        void Call2() const
        {
            constexpr uint32_t setValue = g_coreType == AscendC::AIC ? 1 : 0;
            AscendC::PipeBarrier<PIPE_ALL>();
            AscendC::GlobalTensor<uint32_t> global;
            global.SetGlobalBuffer((__gm__ uint32_t *)(ptr->syncGmAddr + stageId * GMM2::SOFT_SYNC_SPACE_SIZE *
                GMM2::CORE_NUM_PER_GROUP));
            int32_t waitOffset[2];
            if constexpr (g_coreType == AscendC::AIC) {
                waitOffset[0] = 0;
                waitOffset[1] = GMM2::SOFT_SYNC_SPACE_SIZE;
            } else {
                waitOffset[0] = get_subblockid() * (GMM2::SOFT_SYNC_SPACE_SIZE);
            }
            if constexpr (g_coreType == AscendC::AIC) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
                global.SetValue(waitOffset[0], setValue);
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[1]]);
                __asm__ __volatile__("");
                global.SetValue(waitOffset[1], setValue);
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[1]]);
                __asm__ __volatile__("");
            } else {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
                    AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
                    global[waitOffset[0]]);
                __asm__ __volatile__("");
                global.SetValue(waitOffset[0], setValue);
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<uint32_t,
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
