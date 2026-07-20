/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: FusedDeepMoe operator kernel function header file, for a3
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 create FusedDeepMoe operator kernel function header file, for a3
 */
#ifndef FUSED_DEEP_MOE_H
#define FUSED_DEEP_MOE_H

#include "lib/matmul_intf.h"
#include <kernel_operator.h>

#include "catlass/catlass.hpp"
#include "catlass/arch/arch.hpp"
#include "catlass/layout/layout.hpp"
#include "catlass/epilogue/tile/tile_broadcast_mul.hpp"
#include "catlass/epilogue/tile/tile_broadcast_one_blk.hpp"
#include "catlass/epilogue/tile/tile_swizzle.hpp"
#include "catlass/gemm/block/block_swizzle.hpp"
#include "fused_deep_moe/gemm/kernel/grouped_matmul_slice_m_per_token_dequant_multistage_workspace.h"
#include "catlass/gemm/gemm_type.hpp"
#include "fused_deep_moe/epilogue/dispatch_policy.h"
#include "fused_deep_moe/gemm/dispatch_policy.h"
#include "fused_deep_moe/epilogue/block/block_epilogue.h"
#include "fused_deep_moe/gemm/block/block_mmad.h"
#include "fused_deep_moe/gemm/kernel/grouped_matmul_slice_m_per_token_dequant_swiglu_quant_multistage_workspace.h"

#include "fused_deep_moe/raw_distributed/cam_moe_distribute_dispatch.h"

#include "fused_deep_moe_tiling.h"
#include "fused_deep_moe_base.h"

using namespace Catlass;
using namespace Cam;

constexpr uint32_t FDM_ROUND_SYNC_FLOATS_PER_RANK = 8;

template <AscendC::HardEvent event>
__aicore__ inline void FdmRoundSyncFunc()
{
    int32_t eventId = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventId);
    AscendC::WaitFlag<event>(eventId);
}
using MmadAtlasA2Custom =
    Gemm::MmadAtlasA2PreloadAsyncWithCallback<CUSTOM_PRELOAD_STAGES, CUSTOM_L1_STAGES, CUSTOM_L0A_STAGES,
                                              CUSTOM_L0B_STAGES, CUSTOM_L0C_STAGES, CUSTOM_ENABLE_UNIT_FLAG,
                                              CUSTOM_ENABLE_SHUFFLE_K>;

using Gmm1L1TileShape = GemmShape<GMM1_L1M, GMM1_L1N, GMM1_L1K>;
using Gmm1L0TileShape = GemmShape<GMM1_L1M, GMM1_L1N, GMM1_L0K>;
using Gmm1EpilogueTileShape = MatrixShape<GMM1_EPIM, Gmm1L1TileShape::N>;
using Gmm1BlockScheduler = typename Gemm::Block::GemmIdentityBlockSwizzle<GMM1_SWIZZLE_OFFSET, GMM1_SWIZZLE_DIRECTION>;

using Gmm2L1TileShape = GemmShape<GMM2_L1M, GMM2_L1N, GMM2_L1K>;
using Gmm2L0TileShape = GemmShape<Gmm2L1TileShape::M, Gmm2L1TileShape::N, GMM2_L0K>;
using Gmm2EpilogueTileShape = MatrixShape<GMM2_EPIM, Gmm2L1TileShape::N>;
using Gmm2BlockScheduler = typename Gemm::Block::GemmIdentityBlockSwizzle<GMM2_SWIZZLE_OFFSET, GMM2_SWIZZLE_DIRECTION>;
using Gmm2DispatchPolicy =
    Gemm::MmadAtlasA2PreloadAsyncWithCallbackResidentA<CUSTOM_PRELOAD_STAGES, GMM2_L1A_STAGES, GMM2_L1B_STAGES,
                                                       GMM2_L0A_STAGES, GMM2_L0B_STAGES, CUSTOM_L0C_STAGES,
                                                       CUSTOM_ENABLE_UNIT_FLAG, CUSTOM_ENABLE_SHUFFLE_K>;

template <TemplateMC2TypeClass, class L1TileShape_, class L0TileShape_, class EpilogueTileShape_,
          class BlockScheduler_, class DispatchPolicy_ = MmadAtlasA2Custom>
CATLASS_DEVICE void GmmDeqSwigluQuant(GemmCoord problemShape, uint32_t groupCount, GM_ADDR gmGroupList, GM_ADDR gmA,
                                  layout::RowMajor layoutA, GM_ADDR gmShareB, layout::zN layoutShareB, GM_ADDR gmB,
                                  layout::zN layoutB, GM_ADDR gmShareScale, layout::VectorLayout layoutShareScale,
                                  GM_ADDR gmScale, layout::VectorLayout layoutScale, GM_ADDR gmPerTokenScale,
                                  layout::VectorLayout layoutPerTokenScale, GM_ADDR gmD, layout::RowMajor layoutD,
                                  GM_ADDR gmDequantScale, layout::VectorLayout layoutDequantScale, GM_ADDR gmShareX1,
                                  GM_ADDR gmShareX1Scale, GM_ADDR gmShareSwigluOut, GM_ADDR gmShareX2,
                                  layout::RowMajor layoutShareD, GM_ADDR gmShareX2Scale, GM_ADDR gmSwigluOut,
                                  GM_ADDR gmWorkspace, GM_ADDR gmX, GM_ADDR gmMoeSmoothScales,
                                  GM_ADDR gmShareSmoothScales, GM_ADDR gmexpertIds, GM_ADDR gmExpandIdx,
                                  GM_ADDR gmEpSendCount, GM_ADDR xActiveMask, GM_ADDR gmResvered,
                                  GM_ADDR gmExpertTokenNums, GM_ADDR gmAllExpertTokenNums,
                                  GM_ADDR metaInfoGm_, GM_ADDR gmTokenFlag,
                                  const FusedDeepMoeInfo &disGmmDeqSwigluQuantGmmDeqComInfo,
                                  uint32_t roundRecvTokenNum, GM_ADDR gmCombineSend,
                                  uint32_t roundIdx = 0xFFFFFFFFU, uint32_t *roundNum = nullptr)
{
    using ArchTag = Arch::AtlasA2;
    using DispatchPolicy = DispatchPolicy_;
    using L1TileShape = L1TileShape_;
    using L0TileShape = L0TileShape_;


    using AType = Gemm::GemmType<int8_t, layout::RowMajor>;
    using BType = Gemm::GemmType<int8_t, layout::zN>;
    using CType = Gemm::GemmType<int32_t, layout::RowMajor>;

    using BlockMmad = Gemm::Block::BlockMmad<DispatchPolicy, L1TileShape, L0TileShape, AType, BType, CType>;

    constexpr uint32_t ubStages = 1;
    using EpilogueDispatchPolicy = Epilogue::EpilogueAtlasA2PerTokenDequantSwiglu<ubStages, 0>;
    using ScaleType = Gemm::GemmType<W1ScaleType, layout::VectorLayout>;
    using PerTokenScaleType = Gemm::GemmType<float, layout::VectorLayout>;
    using DType = Gemm::GemmType<float, layout::RowMajor>;

    using RowBroadcastMulType = Gemm::GemmType<float, layout::RowMajor>;
    using BroadcastOneBlkType = Gemm::GemmType<float, layout::RowMajor>;
    using OneBlkColumnBroadcastMulType = Gemm::GemmType<float, layout::RowMajor>;

    using EpilogueTileShape = EpilogueTileShape_;
    using TileRowBroadcastMul = Epilogue::Tile::TileRowBroadcastMul<ArchTag, RowBroadcastMulType, EpilogueTileShape>;
    using TileBroadcastOneBlk =
        Epilogue::Tile::TileBroadcastOneBlk<ArchTag, BroadcastOneBlkType, EpilogueTileShape::ROW>;
    using TileOneBlkColumnBroadcastMul =
        Epilogue::Tile::TileOneBlkColumnBroadcastMul<ArchTag, OneBlkColumnBroadcastMulType, EpilogueTileShape>;
    using TileCopy = Epilogue::Tile::TileCopy<ArchTag, CType, ScaleType, PerTokenScaleType, DType>;
    using TileScheduler = Epilogue::Tile::EpilogueHorizontalTileSwizzle;

    using BlockEpilogue = Epilogue::Block::BlockEpilogue<EpilogueDispatchPolicy, CType, ScaleType, PerTokenScaleType,
                                                         DType, TileRowBroadcastMul, TileBroadcastOneBlk,
                                                         TileOneBlkColumnBroadcastMul, TileCopy, TileScheduler>;

    using BlockScheduler = BlockScheduler_;

    // kernel level
    using ElementGroupList = int64_t;

    using GemmKernel = typename std::conditional<
        (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE),
        Gemm::Kernel::GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspace<
            TemplateMC2TypeFunc, BlockMmad, BlockEpilogue, BlockScheduler, WORKSPACE_STAGES, ElementGroupList>,
        Gemm::Kernel::GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspaceWithShallowDispatch<
            TemplateMC2TypeFunc, BlockMmad, BlockEpilogue, BlockScheduler, WORKSPACE_STAGES, ElementGroupList>>::type;

    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        typename GemmKernel::Params params{problemShape,
                                           groupCount,
                                           gmGroupList,
                                           gmA,
                                           layoutA,
                                           gmShareB,
                                           layoutShareB,
                                           gmB,
                                           layoutB,
                                           gmShareScale,
                                           layoutShareScale,
                                           gmScale,
                                           layoutScale,
                                           gmPerTokenScale,
                                           layoutPerTokenScale,
                                           gmD,
                                           layoutD,
                                           gmDequantScale,
                                           layoutDequantScale,
                                           gmWorkspace,
                                           gmX,
                                           gmMoeSmoothScales,
                                           gmShareSmoothScales,
                                           gmexpertIds,
                                           gmExpandIdx,
                                           gmEpSendCount,
                                           xActiveMask,
                                           gmResvered,
                                           gmExpertTokenNums,
                                           gmShareX1,
                                           gmShareX1Scale,
                                           gmShareSwigluOut,
                                           gmShareX2,
                                           layoutShareD,
                                           gmShareX2Scale,
                                           gmSwigluOut,
                                           metaInfoGm_,
                                           gmAllExpertTokenNums,
                                           gmTokenFlag,
                                           disGmmDeqSwigluQuantGmmDeqComInfo,
                                           roundRecvTokenNum,
                                           gmCombineSend,
                                           roundIdx,
                                           roundNum};
        // call a kernel
        GemmKernel gemm;
        gemm(params);
    } else {
        typename GemmKernel::Params params{problemShape,
                                           groupCount,
                                           gmGroupList,
                                           gmA,
                                           layoutA,
                                           gmShareB,
                                           layoutShareB,
                                           gmB,
                                           layoutB,
                                           gmShareScale,
                                           layoutShareScale,
                                           gmScale,
                                           layoutScale,
                                           gmPerTokenScale,
                                           layoutPerTokenScale,
                                           gmD,
                                           layoutD,
                                           gmDequantScale,
                                           layoutDequantScale,
                                           gmWorkspace,
                                           gmShareX1,
                                           gmShareX1Scale,
                                           gmShareSwigluOut,
                                           gmShareX2,
                                           layoutShareD,
                                           gmShareX2Scale,
                                           gmSwigluOut,
                                           disGmmDeqSwigluQuantGmmDeqComInfo};
        // call a kernel
        GemmKernel gemm;
        gemm(params);
    }
}

template <TemplateMC2TypeClass, class L1TileShape_, class L0TileShape_, class EpilogueTileShape_, class BlockScheduler_,
          class DispatchPolicy_ = MmadAtlasA2Custom>
CATLASS_DEVICE void GmmDeq(GemmCoord problemShape, uint32_t groupCount, GM_ADDR gmGroupList, GM_ADDR gmA,
                       layout::RowMajor layoutA, GM_ADDR gmB, layout::zN layoutB, GM_ADDR gmScale,
                       layout::VectorLayout layoutScale, GM_ADDR gmPerTokenScale,
                       layout::VectorLayout layoutPerTokenScale, GM_ADDR gmD, layout::RowMajor layoutD,
                       uint32_t batchSize, GemmCoord sharedGmm2ProblemShape,
                       GM_ADDR gmSharedA, GM_ADDR gmSharedB, GM_ADDR gmSharedD,
                       GM_ADDR gmSharedScale, GM_ADDR gmSharedPtrPerTokenScale,
                       layout::RowMajor sharedLayoutA, layout::zN sharedLayoutB,
                       layout::VectorLayout sharedLayoutPerTokenScale, layout::RowMajor sharedLayoutD,
                       uint32_t epRankId, GM_ADDR gmWorkspace, void *combiner, GM_ADDR metaInfoGm,
                       uint64_t statusDataSpaceOffset, GM_ADDR gmEpSendCount = nullptr,
                       uint32_t epRankSize = 0, uint32_t moeExpertNum = 0, uint32_t moeExpertNumPerRank = 0,
                       uint32_t roundRecvTokenNum = 0, uint32_t roundIdx = 0xFFFFFFFFU,
                       uint32_t *roundNum = nullptr)
{
    using ArchTag = Arch::AtlasA2;
    using DispatchPolicy = DispatchPolicy_;
    using L1TileShape = L1TileShape_;
    using L0TileShape = L0TileShape_;

    using AType = Gemm::GemmType<int8_t, layout::RowMajor>;
    using BType = Gemm::GemmType<int8_t, layout::zN>;
    using CType = Gemm::GemmType<int32_t, layout::RowMajor>;

    using BlockMmad = Gemm::Block::BlockMmad<DispatchPolicy, L1TileShape, L0TileShape, AType, BType, CType>;

    constexpr uint32_t ubStages = 1;
    using EpilogueDispatchPolicy = Epilogue::EpilogueAtlasA2PerTokenDequantCombine<ubStages, EXEC_FLAG>;
    using ScaleType = Gemm::GemmType<W2ScaleType, layout::VectorLayout>;
    using PerTokenScaleType = Gemm::GemmType<float, layout::VectorLayout>;
    using DType = Gemm::GemmType<ExpandXType, layout::RowMajor>;

    using RowBroadcastMulType = Gemm::GemmType<float, layout::RowMajor>;
    using BroadcastOneBlkType = Gemm::GemmType<float, layout::RowMajor>;
    using OneBlkColumnBroadcastMulType = Gemm::GemmType<float, layout::RowMajor>;

    using EpilogueTileShape = EpilogueTileShape_;
    using TileRowBroadcastMul = Epilogue::Tile::TileRowBroadcastMul<ArchTag, RowBroadcastMulType, EpilogueTileShape>;
    using TileBroadcastOneBlk =
        Epilogue::Tile::TileBroadcastOneBlk<ArchTag, BroadcastOneBlkType, EpilogueTileShape::ROW>;
    using TileOneBlkColumnBroadcastMul =
        Epilogue::Tile::TileOneBlkColumnBroadcastMul<ArchTag, OneBlkColumnBroadcastMulType, EpilogueTileShape>;
    using TileCopy = Epilogue::Tile::TileCopy<ArchTag, CType, ScaleType, PerTokenScaleType, DType>;
    using TileScheduler = Epilogue::Tile::EpilogueHorizontalTileSwizzle;

    using BlockEpilogue = Epilogue::Block::BlockEpilogue<EpilogueDispatchPolicy, CType, ScaleType, PerTokenScaleType,
                                                         DType, TileRowBroadcastMul, TileBroadcastOneBlk,
                                                         TileOneBlkColumnBroadcastMul, TileCopy, TileScheduler>;

    using BlockScheduler = BlockScheduler_;

    // kernel level
    using ElementGroupList = int64_t;
    using GemmKernel = Gemm::Kernel::GroupedMatmulSliceMPerTokenDequantMultiStageWorkspace<
        TemplateMC2TypeFunc, BlockMmad, BlockEpilogue, BlockScheduler, WORKSPACE_STAGES, ElementGroupList>;

    typename GemmKernel::Params params{problemShape,
                                       groupCount,
                                       gmGroupList,
                                       gmA,
                                       layoutA,
                                       gmB,
                                       layoutB,
                                       gmScale,
                                       layoutScale,
                                       gmPerTokenScale,
                                       layoutPerTokenScale,
                                       gmD,
                                       layoutD,
                                       batchSize,
                                       sharedGmm2ProblemShape,
                                       gmSharedA,
                                       gmSharedB,
                                       gmSharedD,
                                       gmSharedScale,
                                       gmSharedPtrPerTokenScale,
                                       sharedLayoutA,
                                       sharedLayoutB,
                                       sharedLayoutPerTokenScale,
                                       sharedLayoutD,
                                       gmWorkspace,
                                       combiner,
                                       gmEpSendCount,
                                       epRankSize,
                                       epRankId,
                                       moeExpertNum,
                                       moeExpertNumPerRank,
                                       roundRecvTokenNum,
                                       roundIdx,
                                       roundNum};

    // call a kernel
    GemmKernel gemm{epRankId, metaInfoGm, statusDataSpaceOffset};
    gemm(params);
}

template <TemplateMC2TypeClass>
class FusedDeepMoe {
public:
    __aicore__ inline FusedDeepMoe(){};
    __aicore__ inline void Init(
        // input
        GM_ADDR x, GM_ADDR expert_ids, GM_ADDR gmm1_weight, GM_ADDR gmm1_weight_scale,
        GM_ADDR gmm2_weight, GM_ADDR gmm2_weight_scale, GM_ADDR expert_scales,
        GM_ADDR share_gmm1_weight, GM_ADDR share_gmm1_weight_scale,
        GM_ADDR share_gmm2_weight, GM_ADDR share_gmm2_weight_scale,
        GM_ADDR expert_smooth_scales, GM_ADDR share_smooth_scales, GM_ADDR x_active_mask,
        // output
        GM_ADDR output, GM_ADDR share_output, GM_ADDR expertTokenNums,
        // system
        GM_ADDR workspaceGM, AscendC::TPipe *pipe, const FusedDeepMoeTilingData *tilingData);
    __aicore__ inline void Process();

private:
    __aicore__ inline GM_ADDR GetRoundStateAddrByRankId(GM_ADDR localRoundState, int32_t rankId);
    __aicore__ inline float SetRoundStatus(GM_ADDR gmRoundInfo);
    __aicore__ inline void WaitRoundStatus(GM_ADDR gmRoundInfo, float expectedStatus);

    GM_ADDR gmX_;
    GM_ADDR gmexpertIds_;
    GM_ADDR gmWeight1_;
    GM_ADDR gmScale1_;
    GM_ADDR gmWeight2_;
    GM_ADDR gmScale2_;
    GM_ADDR gmOutput_;

    GM_ADDR gmShareWeight1_;
    GM_ADDR gmShareWeight1Scale_;
    GM_ADDR gmShareWeight2_;
    GM_ADDR gmShareWeight2Scale_;
    GM_ADDR gmShareOutput_;
    GM_ADDR gmExpertTokenNums_;
    GM_ADDR workspaceGM_;
    GM_ADDR shmemWorkspaceGM_;
    GM_ADDR metaInfoGm_;
    GM_ADDR gmSmoothScales_;
    GM_ADDR gmShareSmoothScales_;
    GM_ADDR gmexpertScales_;
    GM_ADDR xActiveMask_;

    uint32_t maxTokenNum_{0};
    uint32_t shareGmm1OutputDim_{0};
    uint32_t gmm1OutputDim_{0};
    uint32_t tokenHiddenSize_{0};
    uint32_t groupCount_{0};
    uint32_t gmm2OutputDim_{0};
    uint32_t shareGmm2InputDim_{0};
    uint32_t gmm2InputDim_{0};
    uint32_t globalRankId_{0};
    uint32_t winSizePerRank_{0};
    uint32_t blockDim_{0};
    uint32_t epRankSize_{0};
    uint32_t epRankId_{0};
    uint32_t moeExpertNumPerRank_{0};
    uint32_t globalBs_{0};
    uint32_t bs_{0};
    uint32_t maxBs_{0};
    uint32_t topK_{0};
    int32_t roundRecvTokenNum_{0};
    uint64_t statusDataSpaceOffset_{0};
    uint32_t moeExpertNum_{0};

    AscendC::TPipe *tpipe_{nullptr};
    const FusedDeepMoeTilingData *tilingData_;
    AscendC::TBuf<> roundStatusBuf_;
};

template <TemplateMC2TypeClass>
__aicore__ inline GM_ADDR FusedDeepMoe<TemplateMC2TypeFunc>::GetRoundStateAddrByRankId(
    GM_ADDR localRoundState, int32_t rankId)
{
    if (epRankId_ == static_cast<uint32_t>(rankId)) {
        return localRoundState;
    }
    return (GM_ADDR)aclshmem_ptr(localRoundState, rankId);
}

template <TemplateMC2TypeClass>
__aicore__ inline float FusedDeepMoe<TemplateMC2TypeFunc>::SetRoundStatus(GM_ADDR gmRoundInfo)
{
    if (AscendC::GetBlockIdx() != 0) {
        return 0.0f;
    }
    AscendC::GlobalTensor<float> ownRoundStatus;
    GM_ADDR ownRoundStatusAddr = GetRoundStateAddrByRankId(gmRoundInfo, epRankId_) + UB_ALIGN * epRankId_;
    ownRoundStatus.SetGlobalBuffer((__gm__ float *)ownRoundStatusAddr);
    // Keep barrier generations monotonic so a fast rank cannot overwrite a
    // slower rank's next-round notification while clearing the previous one.
    __asm__ __volatile__("");
    AscendC::DataCacheCleanAndInvalid<float, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                      AscendC::DcciDst::CACHELINE_OUT>(ownRoundStatus);
    __asm__ __volatile__("");
    float currentStatus = ownRoundStatus.GetValue(0);
    float expectedStatus = currentStatus >= 0.0f && currentStatus < 16777215.0f ? currentStatus + 1.0f : 1.0f;

    tpipe_->InitBuffer(roundStatusBuf_, epRankSize_ * UB_ALIGN);
    AscendC::LocalTensor<float> roundStatus = roundStatusBuf_.AllocTensor<float>();
    AscendC::Duplicate<float>(roundStatus, expectedStatus, FDM_ROUND_SYNC_FLOATS_PER_RANK);
    AscendC::GlobalTensor<float> dstRoundStatus;
    for (uint32_t rankId = 0; rankId < epRankSize_; ++rankId) {
        GM_ADDR rankStatus = GetRoundStateAddrByRankId(gmRoundInfo, rankId) + UB_ALIGN * epRankId_;
        dstRoundStatus.SetGlobalBuffer((__gm__ float *)rankStatus);
        AscendC::DataCopy<float>(dstRoundStatus, roundStatus, FDM_ROUND_SYNC_FLOATS_PER_RANK);
    }
    FdmRoundSyncFunc<AscendC::HardEvent::MTE3_S>();
    return expectedStatus;
}

template <TemplateMC2TypeClass>
__aicore__ inline void FusedDeepMoe<TemplateMC2TypeFunc>::WaitRoundStatus(
    GM_ADDR gmRoundInfo, float expectedStatus)
{
    if (AscendC::GetBlockIdx() != 0) {
        return;
    }
    uint32_t count = epRankSize_ * FDM_ROUND_SYNC_FLOATS_PER_RANK;
    AscendC::GlobalTensor<float> roundStatusGlobal;
    roundStatusGlobal.SetGlobalBuffer((__gm__ float *)GetRoundStateAddrByRankId(gmRoundInfo, epRankId_));
    AscendC::LocalTensor<float> roundStatus = roundStatusBuf_.Get<float>();
    bool allRanksReady = false;
    while (!allRanksReady) {
        FdmRoundSyncFunc<AscendC::HardEvent::S_MTE2>();
        AscendC::DataCopy<float>(roundStatus, roundStatusGlobal, count);
        FdmRoundSyncFunc<AscendC::HardEvent::MTE2_S>();
        allRanksReady = true;
        for (uint32_t index = 0; index < count; ++index) {
            if (roundStatus.GetValue(index) < expectedStatus) {
                allRanksReady = false;
                break;
            }
        }
    }

    roundStatusBuf_.FreeTensor(roundStatus);
}

template <TemplateMC2TypeClass>
__aicore__ inline void FusedDeepMoe<TemplateMC2TypeFunc>::Init(
    // input
    GM_ADDR x, GM_ADDR expert_ids, GM_ADDR gmm1_weight, GM_ADDR gmm1_weight_scale,
    GM_ADDR gmm2_weight, GM_ADDR gmm2_weight_scale, GM_ADDR expert_scales,
    GM_ADDR share_gmm1_weight, GM_ADDR share_gmm1_weight_scale,
    GM_ADDR share_gmm2_weight, GM_ADDR share_gmm2_weight_scale,
    GM_ADDR expert_smooth_scales, GM_ADDR share_smooth_scales, GM_ADDR x_active_mask,
    // output
    GM_ADDR output, GM_ADDR share_output, GM_ADDR expertTokenNums,
    // system
    GM_ADDR workspaceGM, AscendC::TPipe *pipe, const FusedDeepMoeTilingData *tilingData)
{
    tpipe_ = pipe;
    blockDim_ = AscendC::GetBlockNum();

    gmSmoothScales_ = expert_smooth_scales;  // not used now
    gmShareSmoothScales_ = share_smooth_scales;
    gmX_ = x;                                // input token
    gmexpertIds_ = expert_ids;
    gmWeight1_ = gmm1_weight;
    gmScale1_ = gmm1_weight_scale;
    gmWeight2_ = gmm2_weight;
    gmScale2_ = gmm2_weight_scale;
    gmOutput_ = output;
    gmShareWeight1_ = share_gmm1_weight;
    gmShareWeight1Scale_ = share_gmm1_weight_scale;
    gmShareWeight2_ = share_gmm2_weight;
    gmShareWeight2Scale_ = share_gmm2_weight_scale;
    gmShareOutput_ = share_output;
    gmExpertTokenNums_ = expertTokenNums;
    if constexpr (EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) {
        shmemWorkspaceGM_ = (GM_ADDR)(tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.shmemWorkspacePtr);
    }
    workspaceGM_ = workspaceGM;
    metaInfoGm_ = (GM_ADDR)(tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.metaInfoPtr);
    gmexpertScales_ = expert_scales;
    xActiveMask_ = x_active_mask;
    tilingData_ = tilingData;
    epRankSize_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.epRankSize;
    epRankId_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.epRankId;
    moeExpertNumPerRank_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    moeExpertNum_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNum;
    globalBs_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.globalBs;
    bs_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.bs;
    topK_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.k;
    roundRecvTokenNum_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.roundRecvTokenNum;
    maxBs_ = globalBs_ / epRankSize_;

    maxTokenNum_ = maxBs_ * epRankSize_ * (topK_ < moeExpertNumPerRank_ ? topK_ : moeExpertNumPerRank_);
    shareGmm1OutputDim_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.shareGmm1HLen;
    gmm1OutputDim_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.gmm1HLen;
    tokenHiddenSize_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.h;
    groupCount_ = tilingData->disGmmDeqSwigluQuantGmmDeqComInfo.moeExpertNumPerRank;
    gmm2OutputDim_ = tokenHiddenSize_;
    shareGmm2InputDim_ = shareGmm1OutputDim_ / 2;
    gmm2InputDim_ = gmm1OutputDim_ / 2;

    statusDataSpaceOffset_ = blockDim_ * 2 * UB_32B_ALIGN + epRankSize_ * UB_32B_ALIGN +
                            moeExpertNumPerRank_ * epRankSize_ * sizeof(int32_t) +
                            4 * epRankSize_ * sizeof(uint64_t);
}

template <TemplateMC2TypeClass>
__aicore__ inline void FusedDeepMoe<TemplateMC2TypeFunc>::Process()
{
    GemmCoord gmm1ProblemShape{maxTokenNum_, gmm1OutputDim_, tokenHiddenSize_};
    GemmCoord gmm2ProblemShape{maxTokenNum_, gmm2OutputDim_, gmm2InputDim_};

    layout::RowMajor layoutX1{maxTokenNum_, tokenHiddenSize_};
    layout::zN layoutShareWeight1 = layout::zN::template MakeLayout<int8_t>(tokenHiddenSize_, shareGmm1OutputDim_);
    layout::zN layoutWeight1 = layout::zN::template MakeLayout<int8_t>(tokenHiddenSize_, gmm1OutputDim_);
    layout::VectorLayout layoutShareW1Scale{shareGmm1OutputDim_};
    layout::VectorLayout layoutW1Scale{gmm1OutputDim_};
    layout::VectorLayout layoutX1Scale{maxTokenNum_};
    layout::RowMajor layoutX2{maxTokenNum_, gmm2InputDim_};
    layout::zN layoutWeight2 = layout::zN::template MakeLayout<int8_t>(gmm2InputDim_, gmm2OutputDim_);
    layout::VectorLayout layoutW2Scale{gmm2OutputDim_};
    layout::VectorLayout layoutX2Scale{maxTokenNum_};
    layout::RowMajor layoutOutput{maxTokenNum_, gmm2OutputDim_};
    
    layout::RowMajor layoutShareX2{bs_, shareGmm2InputDim_};
    layout::zN layoutShareWeight2 = layout::zN::template MakeLayout<int8_t>(shareGmm2InputDim_, gmm2OutputDim_);
    GemmCoord shareGmm2ProblemShape{bs_, gmm2OutputDim_, shareGmm2InputDim_};
    layout::VectorLayout layoutShareX2Scale{bs_};
    layout::RowMajor layoutShareOutput{bs_, gmm2OutputDim_};

    GM_ADDR gmShareX1 = nullptr;
    GM_ADDR gmShareX1Scale = nullptr;
    GM_ADDR gmShareSwigluOut = nullptr;
    GM_ADDR gmShareX2 = nullptr;
    GM_ADDR gmShareX2Scale = nullptr;

    GM_ADDR gmX1 = nullptr;
    GM_ADDR gmX1Scale = nullptr;
    GM_ADDR gmSwigluOut = nullptr;
    GM_ADDR gmTokenFlag = nullptr;
    GM_ADDR gmX2 = nullptr;
    GM_ADDR gmX2Scale = nullptr;
    size_t shareExpertTokenNum = 0;
    if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
        shareExpertTokenNum = bs_;
    }
    uint32_t roundBufferTokenNum = static_cast<uint32_t>(roundRecvTokenNum_);
    size_t moeBufferTokenNum = roundBufferTokenNum;
    size_t maxHandleTokenNum = moeBufferTokenNum + shareExpertTokenNum;
    size_t workspaceOffset = 0;
    size_t shmemWorkspaceOffset = 0;
    constexpr int32_t resveredWorkSpaceSize = 256 * 1024;
    constexpr int32_t roundInfoWorkSpaceSize = 16 * 1024;
    int64_t x1TokenSize = maxHandleTokenNum * tokenHiddenSize_ * sizeof(int8_t);
    int64_t x2TokenSize = (moeBufferTokenNum * gmm2InputDim_ +
                           shareExpertTokenNum * shareGmm2InputDim_) * sizeof(int8_t);
    int64_t maxTokenSize = x1TokenSize < x2TokenSize ? x2TokenSize : x1TokenSize;
    int64_t tokenScaleSize = maxHandleTokenNum * sizeof(float);
    gmShareX1 = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    gmShareX2 = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    gmX1 = gmShareX1 + (static_cast<size_t>(shareExpertTokenNum) * tokenHiddenSize_ * sizeof(int8_t));
    gmX2 = gmShareX2 + (static_cast<size_t>(shareExpertTokenNum) * shareGmm2InputDim_ * sizeof(int8_t));
    shmemWorkspaceOffset += RoundUp<GM_ALIGN_BYTE>(maxTokenSize);
    gmShareX1Scale = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    gmShareX2Scale = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    gmX1Scale = gmShareX1Scale + (static_cast<size_t>(shareExpertTokenNum) * sizeof(float));
    gmX2Scale = gmShareX2Scale + (static_cast<size_t>(shareExpertTokenNum) * sizeof(float));
    shmemWorkspaceOffset += RoundUp<GM_ALIGN_BYTE>(tokenScaleSize);
    gmTokenFlag = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    shmemWorkspaceOffset += RoundUp<GM_ALIGN_BYTE>(moeBufferTokenNum * TOKEN_FLAG_SLOT_BYTES);


    GM_ADDR gmWorkspace = workspaceGM_ + workspaceOffset;
    GM_ADDR gmCVSwap = workspaceGM_ + workspaceOffset;
    workspaceOffset += RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(blockDim_) * (GMM1_L1M * GMM1_L1N) *
                                              WORKSPACE_STAGES * sizeof(int32_t));
    int64_t swigluOutSize = (maxTokenNum_ * gmm1OutputDim_ + shareExpertTokenNum * shareGmm1OutputDim_) * sizeof(float);
    int64_t gmm2OutSize = maxTokenNum_ * tokenHiddenSize_ * sizeof(ExpandXType);
    int64_t maxSwigluGmm2Size = swigluOutSize < gmm2OutSize ? gmm2OutSize : swigluOutSize;
    gmShareSwigluOut = workspaceGM_ + workspaceOffset;
    gmSwigluOut = gmShareSwigluOut + (static_cast<size_t>(shareExpertTokenNum) * shareGmm1OutputDim_ * sizeof(float));
    GM_ADDR gmGmm2DepOut = workspaceGM_ + workspaceOffset;
    workspaceOffset += RoundUp<GM_ALIGN_BYTE>(maxSwigluGmm2Size);

    GM_ADDR gmGroupList = workspaceGM_ + workspaceOffset;
    workspaceOffset += RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(groupCount_) * sizeof(int64_t));
    GM_ADDR gmExpandIdx = workspaceGM_ + workspaceOffset;
    workspaceOffset += RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(bs_) * topK_ * sizeof(int32_t));
    GM_ADDR gmEpSendCount = workspaceGM_ + workspaceOffset;
    workspaceOffset +=
        RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(epRankSize_) * epRankSize_ * groupCount_ * sizeof(int32_t));
    GM_ADDR gmResvered = workspaceGM_ + workspaceOffset;
    workspaceOffset += RoundUp<GM_ALIGN_BYTE>(resveredWorkSpaceSize);
    GM_ADDR gmAllExpertTokenNums = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    shmemWorkspaceOffset +=
        RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(epRankSize_) * epRankSize_ * groupCount_ * sizeof(int64_t));
    GM_ADDR gmCombineSend = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    shmemWorkspaceOffset += RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(bs_) * topK_ * tokenHiddenSize_ * sizeof(float));
    GM_ADDR gmRoundInfo = shmemWorkspaceGM_ + shmemWorkspaceOffset;
    shmemWorkspaceOffset += RoundUp<GM_ALIGN_BYTE>(roundInfoWorkSpaceSize);
    GM_ADDR gmAllEpRecvCount = workspaceGM_ + workspaceOffset;
    workspaceOffset += RoundUp<GM_ALIGN_BYTE>(static_cast<size_t>(epRankSize_) * moeExpertNum_ * sizeof(int32_t));

    if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
        if constexpr (g_coreType == AscendC::AIV) {
            AscendC::TPipe tpipe;
            MoeDistributeDispatchImpl::CamMoeDistributeDispatch<ExpandXType, int8_t, false, true,
                                static_cast<bool>(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT), false, EXEC_FLAG> dispatcher;
            dispatcher.Init(gmX_, gmexpertIds_, gmSmoothScales_, gmShareSmoothScales_, xActiveMask_, gmShareX1, gmX1,
                            gmShareX1Scale, gmX1Scale, gmExpandIdx, gmGroupList, gmEpSendCount, gmExpertTokenNums_,
                            nullptr, gmWorkspace, &tpipe, tilingData_);
            dispatcher.Process();
            tpipe.Destroy();
            icache_preload(8);
        }

        AscendC::PipeBarrier<PIPE_ALL>();
        Arch::CrossCoreFlag gmm1AivFinished{0};
        if constexpr (g_coreType == AscendC::AIV) {
            Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();
            Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(gmm1AivFinished);
        } else {
            Arch::CrossCoreWaitFlag(gmm1AivFinished);
        }
    }

    if constexpr ((EXEC_FLAG & EXEC_FLAG_ZERO_BUFFER) && (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE)) {
        uint32_t roundNum = 1;
        MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> combiner;
        for (uint32_t roundIdx = 0;; ++roundIdx) {
            if (roundIdx >= roundNum) {
                break;
            }
            GmmDeqSwigluQuant<TemplateMC2TypeFunc, Gmm1L1TileShape, Gmm1L0TileShape, Gmm1EpilogueTileShape,
                              Gmm1BlockScheduler>(
                gmm1ProblemShape, groupCount_, gmGroupList, gmX1, layoutX1, gmShareWeight1_, layoutShareWeight1,
                gmWeight1_, layoutWeight1, gmShareWeight1Scale_, layoutShareW1Scale, gmScale1_, layoutW1Scale,
                gmX1Scale, layoutX1Scale, gmX2, layoutX2, gmX2Scale, layoutX2Scale, gmShareX1, gmShareX1Scale,
                gmShareSwigluOut, gmShareX2, layoutShareX2, gmShareX2Scale, gmSwigluOut, gmWorkspace, gmX_,
                gmSmoothScales_, gmShareSmoothScales_, gmexpertIds_, gmExpandIdx, gmEpSendCount, xActiveMask_,
                gmResvered, gmExpertTokenNums_, gmAllExpertTokenNums, metaInfoGm_, gmTokenFlag,
                tilingData_->disGmmDeqSwigluQuantGmmDeqComInfo, roundBufferTokenNum, gmCombineSend,
                roundIdx, &roundNum);
            AscendC::PipeBarrier<PIPE_ALL>();
            Arch::CrossCoreFlag gmm1RoundAivFinished{0};
            if constexpr (g_coreType == AscendC::AIV) {
                Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();
                Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(gmm1RoundAivFinished);
            } else {
                Arch::CrossCoreWaitFlag(gmm1RoundAivFinished);
            }

            if constexpr (g_coreType == AscendC::AIV) {
                if (roundIdx == 0) {
                    combiner.Init(gmGmm2DepOut, gmexpertIds_, gmExpandIdx,
                                  (GM_ADDR)(gmEpSendCount + epRankId_ * epRankSize_ * moeExpertNumPerRank_ *
                                            sizeof(int32_t)),
                                  nullptr, gmexpertScales_, xActiveMask_, gmOutput_, workspaceGM_, nullptr,
                                  tilingData_, gmAllExpertTokenNums, gmAllEpRecvCount, gmCombineSend,
                                  statusDataSpaceOffset_);
                }
            }
            GmmDeq<TemplateMC2TypeFunc, Gmm2L1TileShape, Gmm2L0TileShape, Gmm2EpilogueTileShape,
                   Gmm2BlockScheduler, Gmm2DispatchPolicy>(
                gmm2ProblemShape, groupCount_, gmGroupList, gmX2, layoutX2, gmWeight2_, layoutWeight2,
                gmScale2_, layoutW2Scale, gmX2Scale, layoutX2Scale, gmGmm2DepOut, layoutOutput, bs_,
                shareGmm2ProblemShape, gmShareX2, gmShareWeight2_, gmShareOutput_, gmShareWeight2Scale_,
                gmShareX2Scale, layoutShareX2, layoutShareWeight2, layoutShareX2Scale, layoutShareOutput,
                epRankId_, gmWorkspace, &combiner, metaInfoGm_, statusDataSpaceOffset_, gmEpSendCount,
                epRankSize_, moeExpertNum_, moeExpertNumPerRank_, roundBufferTokenNum, roundIdx,
                &roundNum);
            // The final round also needs a rank barrier before the out-of-loop combine consumes
            // payloads written by every rank's in-loop GMM2 epilogue.
            {
                tpipe_ = GetTPipePtr();
                tpipe_->Init();
                AscendC::SyncAll<false>();
                if constexpr (g_coreType == AscendC::AIV) {
                    float expectedRoundStatus = SetRoundStatus(gmRoundInfo);
                    WaitRoundStatus(gmRoundInfo, expectedRoundStatus);
                }
                AscendC::SyncAll<false>();
                tpipe_->Destroy();
            }
        }
        // cleanup/finalize: aic skip, aiv PrepareFinalizeAivState() and UpdateAndCleanInfo()
        GmmDeqSwigluQuant<TemplateMC2TypeFunc, Gmm1L1TileShape, Gmm1L0TileShape, Gmm1EpilogueTileShape,
                          Gmm1BlockScheduler>(
            gmm1ProblemShape, groupCount_, gmGroupList, gmX1, layoutX1, gmShareWeight1_, layoutShareWeight1,
            gmWeight1_, layoutWeight1, gmShareWeight1Scale_, layoutShareW1Scale, gmScale1_, layoutW1Scale,
            gmX1Scale, layoutX1Scale, gmX2, layoutX2, gmX2Scale, layoutX2Scale, gmShareX1, gmShareX1Scale,
            gmShareSwigluOut, gmShareX2, layoutShareX2, gmShareX2Scale, gmSwigluOut, gmWorkspace, gmX_,
            gmSmoothScales_, gmShareSmoothScales_, gmexpertIds_, gmExpandIdx, gmEpSendCount, xActiveMask_,
            gmResvered, gmExpertTokenNums_, gmAllExpertTokenNums, metaInfoGm_, gmTokenFlag,
            tilingData_->disGmmDeqSwigluQuantGmmDeqComInfo, roundBufferTokenNum, gmCombineSend,
            roundNum, &roundNum);
        AscendC::PipeBarrier<PIPE_ALL>();


        Arch::CrossCoreFlag gmm1RoundAivFinished{0};
        if constexpr (g_coreType == AscendC::AIV) {
            Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();
            Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(gmm1RoundAivFinished);
        } else {
            Arch::CrossCoreWaitFlag(gmm1RoundAivFinished);
        }

        // last combine reduce
        GmmDeq<TemplateMC2TypeFunc, Gmm2L1TileShape, Gmm2L0TileShape, Gmm2EpilogueTileShape,
               Gmm2BlockScheduler, Gmm2DispatchPolicy>(
            gmm2ProblemShape, groupCount_, gmGroupList, gmX2, layoutX2, gmWeight2_, layoutWeight2, gmScale2_,
            layoutW2Scale, gmX2Scale, layoutX2Scale, gmGmm2DepOut, layoutOutput, bs_, shareGmm2ProblemShape,
            gmShareX2, gmShareWeight2_, gmShareOutput_, gmShareWeight2Scale_, gmShareX2Scale, layoutShareX2,
            layoutShareWeight2, layoutShareX2Scale, layoutShareOutput, epRankId_, gmWorkspace, &combiner,
            metaInfoGm_, statusDataSpaceOffset_, gmEpSendCount, epRankSize_, moeExpertNum_, moeExpertNumPerRank_,
            roundBufferTokenNum, roundNum, &roundNum);
        return;
    }

    GmmDeqSwigluQuant<TemplateMC2TypeFunc, Gmm1L1TileShape, Gmm1L0TileShape, Gmm1EpilogueTileShape,
                      Gmm1BlockScheduler>(
        gmm1ProblemShape, groupCount_, gmGroupList, gmX1, layoutX1, gmShareWeight1_, layoutShareWeight1,
        gmWeight1_, layoutWeight1, gmShareWeight1Scale_, layoutShareW1Scale, gmScale1_, layoutW1Scale,
        gmX1Scale, layoutX1Scale, gmX2, layoutX2, gmX2Scale, layoutX2Scale, gmShareX1, gmShareX1Scale,
        gmShareSwigluOut, gmShareX2, layoutShareX2, gmShareX2Scale, gmSwigluOut, gmWorkspace, gmX_, gmSmoothScales_,
        gmShareSmoothScales_, gmexpertIds_, gmExpandIdx, gmEpSendCount, xActiveMask_, gmResvered, gmExpertTokenNums_,
        gmAllExpertTokenNums, metaInfoGm_, gmTokenFlag, tilingData_->disGmmDeqSwigluQuantGmmDeqComInfo,
        roundBufferTokenNum, gmCombineSend);
    AscendC::PipeBarrier<PIPE_ALL>();
    Arch::CrossCoreFlag gmm1AivFinished{0};
    if constexpr (g_coreType == AscendC::AIV) {
        Arch::CrossCoreBarrier<0x0, PIPE_MTE3>();
        Arch::CrossCoreSetFlag<0x2, PIPE_MTE3>(gmm1AivFinished);
    } else {
        Arch::CrossCoreWaitFlag(gmm1AivFinished);
    }

    MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> combiner;
    if (g_coreType == AscendC::AIV) {
        combiner.Init(gmGmm2DepOut, gmexpertIds_, gmExpandIdx, (GM_ADDR)(gmEpSendCount + epRankId_ * epRankSize_ *
                      moeExpertNumPerRank_ * sizeof(int32_t)), nullptr, gmexpertScales_, xActiveMask_, gmOutput_,
                      workspaceGM_, nullptr, tilingData_, gmAllExpertTokenNums, gmAllEpRecvCount, gmCombineSend,
                      statusDataSpaceOffset_);
    }
    GmmDeq<TemplateMC2TypeFunc, Gmm2L1TileShape, Gmm2L0TileShape, Gmm2EpilogueTileShape, Gmm2BlockScheduler,
           Gmm2DispatchPolicy>(gmm2ProblemShape, groupCount_, gmGroupList, gmX2, layoutX2, gmWeight2_, layoutWeight2,
                               gmScale2_, layoutW2Scale, gmX2Scale, layoutX2Scale, gmGmm2DepOut, layoutOutput, bs_,
                               shareGmm2ProblemShape, gmShareX2, gmShareWeight2_, gmShareOutput_, gmShareWeight2Scale_,
                               gmShareX2Scale, layoutShareX2, layoutShareWeight2, layoutShareX2Scale,
                               layoutShareOutput, epRankId_, gmWorkspace, &combiner, metaInfoGm_,
                               statusDataSpaceOffset_, gmEpSendCount, epRankSize_, moeExpertNum_,
                               moeExpertNumPerRank_, roundBufferTokenNum);
}
#endif  // FUSED_DEEP_MOE_H
