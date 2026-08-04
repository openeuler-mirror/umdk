/**
 * This program is free software, you can redistribute it and/or modify.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This file is a part of the CANN Open Software.
 * Licensed under CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSES/cann-osl-2.0.txt for the full text of the License.
 */

#ifndef CATLASS_GEMM_KERNEL_DISPATCH_MX_GMM1_SWIGLU_H
#define CATLASS_GEMM_KERNEL_DISPATCH_MX_GMM1_SWIGLU_H

#include "ascendc/basic_api/interface/kernel_operator_list_tensor_intf.h"
#include "catlass/catlass.hpp"
#include "catlass/arch/cross_core_sync.hpp"
#include "catlass/arch/resource.hpp"
#include "catlass/coord.hpp"
#include "catlass/detail/callback.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/matrix_coord.hpp"
#include "tla/layout.hpp"
#include "tla/tensor.hpp"
#include "catlass/epilogue/tile/tile_swizzle.hpp"
#include "catlass/epilogue/tile/tile_copy.hpp"

#include "dynamic_mx_quant.h"
#include "../../../fused_deep_moe_base.h"
#include "../../fused_deep_moe_utils.h"
#include "../../../fused_deep_moe_tiling.h"

constexpr uint32_t SUM_TMP_TENSOR_SIZE = 1024;
constexpr uint32_t UB_BLOCK_SIZE = 32;
constexpr uint32_t TOKEN_EXTRA_SPACE = 512;
constexpr uint32_t INT32_COUNT_PER_BLOCK = 8;
constexpr int64_t REDUCE_SUM_WORK_SIZE = 4096; // Max support: 64k fp32 accumulation
constexpr int32_t SUB_AIV_NUM = 2;
constexpr int32_t ODD_EVEN_BASE = 2;
constexpr int32_t BUFFER_NUM = 2;
constexpr int32_t GATHER_SECOND_NUM = 2;
constexpr float CROSS_RANK_SYNC_FLAG = 2.0f;
constexpr uint32_t COPY_FULL_EXPERT_IDS_BS = 512;
constexpr uint32_t UB_MAX_SIZE = 248 * 1024; // Chip-dependent
constexpr uint32_t UB_PART_SIZE = 4;
constexpr uint32_t FLOAT_PAIR = 2;
constexpr uint32_t TOKEN_FLAG_BUF_INT32_COUNT = 16 * 1024;
constexpr uint32_t MX_SCALE_GROUP_SIZE = 32;

constexpr int32_t TOKEN_FLAG_1 = 0x3F800000; // FP32 1.0
constexpr int32_t TOKEN_FLAG_2 = 0x40000000; // FP32 2.0
constexpr double TOKEN_FLAG_SUM_TARGET_ALT = 2.0;

#define V_TO_C_FLAG_1 (0x03030303)
#define V_TO_C_FLAG_2 (0x05050505)
#define CV_FLAG_INDEX 0
#define SELF_COUNT_INDEX 1
#define GROUP_TOKEN_COUNT SELF_COUNT_INDEX  // equal to SELF_COUNT_INDEX

using namespace Cam;
namespace Catlass::Gemm::Kernel {

CATLASS_DEVICE constexpr uint32_t CEIL_UP(uint32_t x)
{
    return ((x + UB_BLOCK_SIZE - 1) / UB_BLOCK_SIZE) * UB_BLOCK_SIZE;
}

CATLASS_DEVICE constexpr uint32_t CEIL(uint32_t x, uint32_t y)
{
    if (y == 0) {
        return 0;
    }
    return (x + (y - 1)) / y;
}

#if (defined(CATLASS_ARCH) && CATLASS_ARCH == 3510)

template <typename ElementMx>
CATLASS_DEVICE constexpr uint32_t MxActPackedLen(uint32_t logicalLen)
{
    if constexpr (AscendC::Std::is_one_of_v<ElementMx, float4_e2m1x2_t, float4_e1m2x2_t>) {
        return (logicalLen + 1U) / 2U;
    }
    return logicalLen;
}

// FP4 GlobalTensor DataCopy count is logical; packed byteLen * 2 for even lengths.
template <typename ElementMx>
CATLASS_DEVICE constexpr uint32_t MxGmDataCopyCount(uint32_t packedLen)
{
    if constexpr (AscendC::Std::is_one_of_v<ElementMx, float4_e2m1x2_t, float4_e1m2x2_t>) {
        return packedLen * 2U;
    }
    return packedLen;
}

// MX scale is 1 byte per block; in FP4 LocalTensor logical indexing each byte spans 2 FP4 slots.
template <typename ElementMx>
CATLASS_DEVICE constexpr uint32_t MxScaleLogicalLen(uint32_t mxScaleNum)
{
    if constexpr (AscendC::Std::is_one_of_v<ElementMx, float4_e2m1x2_t, float4_e1m2x2_t>) {
        return mxScaleNum * 2U;
    }
    return mxScaleNum;
}

template <typename ElementMx>
CATLASS_DEVICE constexpr uint64_t MxActGroupOffsetA(uint32_t m, uint32_t k)
{
    return static_cast<uint64_t>(m) * MxActPackedLen<ElementMx>(k);
}

// Template for GroupedMxMatmulSliceM kernel
template <
    TemplateMC2TypeClass,
    class BlockMmad_,
    class BlockEpilogue_,
    class BlockScheduler_,
    class ElementGroupList_
>
class DispatchMxGmm1Swiglu {
public:
    using BlockMmad = BlockMmad_;
    using ArchTag = typename BlockMmad::ArchTag;
    using L1TileShape = typename BlockMmad::L1TileShape;
    using ElementA = typename BlockMmad::ElementA;
    using LayoutA = typename BlockMmad::LayoutA;
    using ElementB = typename BlockMmad::ElementB;
    using LayoutB = typename BlockMmad::LayoutB;
    using ElementMxScaleA = typename BlockMmad::TileCopy::ElementMxScaleA;
    using LayoutMxScaleA = typename BlockMmad::TileCopy::LayoutMxScaleA;
    using ElementMxScaleB = typename BlockMmad::TileCopy::ElementMxScaleB;
    using LayoutMxScaleB = typename BlockMmad::TileCopy::LayoutMxScaleB;
    using ElementC = typename BlockMmad::ElementC;
    using LayoutC = typename BlockMmad::LayoutC;
    using ElementAccumulator = typename BlockMmad::ElementAccumulator;

    using BlockEpilogue = BlockEpilogue_;
    using EpilogueParams = typename BlockEpilogue::Params;

    using ElementGroupList = ElementGroupList_;
    using BlockScheduler = BlockScheduler_;
    using XType = ExpandXType;

    static constexpr uint32_t L1_TILE_M = tla::get<0>(L1TileShape{});
    static constexpr uint32_t L1_TILE_N = tla::get<1>(L1TileShape{});
    static constexpr uint32_t L1_TILE_K = tla::get<2>(L1TileShape{});

    /// Parameters structure
    struct Params {
        // Data members
        GemmCoord problemShape, shareProblemShape;
        uint32_t problemCount;
        __gm__ ElementGroupList *ptrGroupList;
        __gm__ ElementA *ptrA, *ptrShareA;
        LayoutA layoutA;
        __gm__ ElementB *ptrB, *ptrShareB;
        LayoutB layoutB, layoutShareB;
        __gm__ ElementMxScaleA *ptrMxScaleA, *ptrShareMxScaleA;
        LayoutMxScaleA layoutMxScaleA;
        __gm__ ElementMxScaleB *ptrMxScaleB, *ptrShareMxScaleB;
        LayoutMxScaleB layoutMxScaleB, layoutShareMxScaleB;
        __gm__ ElementC *ptrC, *ptrShareC;
        LayoutC layoutC, layoutShareC;

        __gm__ ElementC *gmSwigluOut;
        __gm__ ElementC *gmShareSwigluOut;
        __gm__ ElementA *ptrX2, *ptrShareX2;
        __gm__ ElementMxScaleA *gmX2Scale, *gmShareX2Scale;

        GM_ADDR gmX;
        GM_ADDR gmExpertIds;
        GM_ADDR gmXActiveMask;
        GM_ADDR gmMoeSmoothScales;
        GM_ADDR gmShareSmoothScales;
        GM_ADDR gmExpandIdx;
        GM_ADDR gmEpSendCount;
        GM_ADDR gmExpertTokenNums;
        GM_ADDR gmAllRankSendCount;

        int64_t x1TokenOffset;
        int64_t x1ScaleOffset;
        int64_t x1FlagOffset;

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
        CATLASS_HOST_DEVICE
        Params() {}

        CATLASS_HOST_DEVICE
        Params(
            GemmCoord const &problemShape_, uint32_t problemCount_, GM_ADDR ptrGroupList_,
            GM_ADDR ptrA_, LayoutA const &layoutA_,
            GM_ADDR ptrB_, LayoutB const &layoutB_,
            GM_ADDR ptrMxScaleA_, LayoutMxScaleA layoutMxScaleA_,
            GM_ADDR ptrMxScaleB_, LayoutMxScaleB layoutMxScaleB_,
            GM_ADDR ptrC_, LayoutC const &layoutC_,
            GM_ADDR gmSwigluOut_, GM_ADDR ptrX2_, GM_ADDR gmX2Scale_,
            GemmCoord const &shareProblemShape_,
            GM_ADDR ptrShareA_,
            GM_ADDR ptrShareB_, LayoutB const &layoutShareB_,
            GM_ADDR ptrShareMxScaleA_,
            GM_ADDR ptrShareMxScaleB_, LayoutMxScaleB layoutShareMxScaleB_,
            GM_ADDR ptrShareC_, LayoutC const &layoutShareC_,
            GM_ADDR gmShareSwigluOut_, GM_ADDR ptrShareX2_, GM_ADDR gmShareX2Scale_,
            GM_ADDR gmX_, GM_ADDR gmExpertIds_, GM_ADDR gmXActiveMask_, GM_ADDR gmMoeSmoothScales_,
                GM_ADDR gmShareSmoothScales_,
            GM_ADDR gmExpandIdx_, GM_ADDR gmEpSendCount_, GM_ADDR gmExpertTokenNums_, GM_ADDR gmAllRankSendCount_,
            const FusedDeepMoeInfo &fusedDeepMoeInfo, const IPCDataOffset &ipcDataOffset
        ) : problemShape(problemShape_),
            problemCount(problemCount_), ptrGroupList(reinterpret_cast<__gm__ ElementGroupList *>(ptrGroupList_)),
            ptrA(reinterpret_cast<__gm__ ElementA *>(ptrA_)), layoutA(layoutA_),
            ptrB(reinterpret_cast<__gm__ ElementB *>(ptrB_)), layoutB(layoutB_),
            ptrMxScaleA(reinterpret_cast<__gm__ ElementMxScaleA *>(ptrMxScaleA_)), layoutMxScaleA(layoutMxScaleA_),
            ptrMxScaleB(reinterpret_cast<__gm__ ElementMxScaleB *>(ptrMxScaleB_)), layoutMxScaleB(layoutMxScaleB_),
            ptrC(reinterpret_cast<__gm__ ElementC *>(ptrC_)), layoutC(layoutC_),
            gmSwigluOut(reinterpret_cast<__gm__ ElementC *>(gmSwigluOut_)),
                ptrX2(reinterpret_cast<__gm__ ElementA *>(ptrX2_)),
                gmX2Scale(reinterpret_cast<__gm__ ElementMxScaleA *>(gmX2Scale_)),
            shareProblemShape(shareProblemShape_),
            ptrShareA(reinterpret_cast<__gm__ ElementA *>(ptrShareA_)),
            ptrShareB(reinterpret_cast<__gm__ ElementB *>(ptrShareB_)), layoutShareB(layoutShareB_),
            ptrShareMxScaleA(reinterpret_cast<__gm__ ElementMxScaleA *>(ptrShareMxScaleA_)),
            ptrShareMxScaleB(reinterpret_cast<__gm__ ElementMxScaleB *>(ptrShareMxScaleB_)),
                layoutShareMxScaleB(layoutShareMxScaleB_),
            ptrShareC(reinterpret_cast<__gm__ ElementC *>(ptrShareC_)), layoutShareC(layoutShareC_),
            gmShareSwigluOut(reinterpret_cast<__gm__ ElementC *>(gmShareSwigluOut_)),
                ptrShareX2(reinterpret_cast<__gm__ ElementA *>(ptrShareX2_)),
                gmShareX2Scale(reinterpret_cast<__gm__ ElementMxScaleA *>(gmShareX2Scale_)),
            gmX(gmX_), gmExpertIds(gmExpertIds_), gmXActiveMask(gmXActiveMask_),
            gmMoeSmoothScales(gmMoeSmoothScales_), gmShareSmoothScales(gmShareSmoothScales_),
            gmExpandIdx(gmExpandIdx_), gmEpSendCount(gmEpSendCount_), gmExpertTokenNums(gmExpertTokenNums_),
                gmAllRankSendCount(gmAllRankSendCount_),
            epRankSize(fusedDeepMoeInfo.epRankSize), epRankId(fusedDeepMoeInfo.epRankId),
            moeExpertNum(fusedDeepMoeInfo.moeExpertNum), moeExpertNumPerRank(fusedDeepMoeInfo.moeExpertNumPerRank),
            quantMode(fusedDeepMoeInfo.quantMode), globalBs(fusedDeepMoeInfo.globalBs), bs(fusedDeepMoeInfo.bs),
            topK(fusedDeepMoeInfo.k), tokenLen(fusedDeepMoeInfo.h), shareN(fusedDeepMoeInfo.shareGmm1HLen),
            x1TokenOffset(ipcDataOffset.x1TokenOffset),
            x1ScaleOffset(ipcDataOffset.x1ScaleOffset),
            x1FlagOffset(ipcDataOffset.x1FlagOffset)
        {}
    };

    // Methods
    CATLASS_DEVICE
    DispatchMxGmm1Swiglu()
    {
        aiCoreGroupNum = AscendC::GetBlockNum();
        subBlockNum = AscendC::GetSubBlockNum();
        aiCoreGroupIdx = AscendC::GetBlockIdx() / subBlockNum;
        aicNum = aiCoreGroupNum;
        aivNum = aiCoreGroupNum * SUB_AIV_NUM; // 1C2V
        if ASCEND_IS_AIC {
            aicIdx = AscendC::GetBlockIdx();
        }
        if ASCEND_IS_AIV {
            aivIdx = AscendC::GetBlockIdx();
        }

        winContext_ = (__gm__ Mc2Kernel::HcclOpParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
        statusDataSpaceGm = Mc2Kernel::GetStatusDataSpaceGm(winContext_);

        if ASCEND_IS_AIV {
            compCoreNum = aiCoreGroupNum;
            isCompCore = true;
            compCoreIdx = aiCoreGroupIdx;
        }
        if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
            return ;
        }

        recvCoreNum = aiCoreGroupNum;
        sendCoreNum = aiCoreGroupNum;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            shareQuantCoreNum = aivNum;
        }
        AscendC::GlobalTensor<int32_t> selfDataStatusTensor;
        selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm +
            IPCStateOffset::AI_CORE_STATE_OFFSET));
        if ASCEND_IS_AIC {
            aicStateGlobalCoreIdx = aivNum + aicIdx;
            dataState = FlushAndSpinValue<int32_t>(selfDataStatusTensor, aicStateGlobalCoreIdx * UB_BLOCK_SIZE);
            // Reset to 0 on exit; toggle here for easier debugging
            vToCFlag = (dataState == 0) ? V_TO_C_FLAG_1 : V_TO_C_FLAG_2;
        }
        if ASCEND_IS_AIV {
            isRecvCore = ((aivIdx % ODD_EVEN_BASE) == 0);
            recvCoreIdx = aiCoreGroupIdx;
            isSendCore = ((aivIdx % ODD_EVEN_BASE) == 1);
            sendCoreIdx = aiCoreGroupIdx;
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                isShareQuantCore = true;
                shareQuantCoreIdx = aivIdx;
            }

            dataState = FlushAndSpinValue<int32_t>(selfDataStatusTensor, aivIdx * UB_BLOCK_SIZE);
            vToCFlag = (dataState == 0) ? V_TO_C_FLAG_1 : V_TO_C_FLAG_2;
        }
    }

    template <int32_t CORE_TYPE = g_coreType>
    CATLASS_DEVICE
    void operator()(Params const &params);
    __aicore__ inline void WaitGroupTokenNumReady(AscendC::GlobalTensor<int32_t>& groupTokenNumStateTensor,
                                                      uint32_t expected)
    {
        while (true) {
            if (FlushAndGetValue<int32_t>(groupTokenNumStateTensor, 0) == static_cast<int32_t>(expected)) {
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    }

    __aicore__ inline GM_ADDR GetWindStateAddrByRankId(int64_t rankId)
    {
        return Mc2Kernel::GetBaseWindStateAddrByRankId(winContext_, rankId, epRankId);
    }

    __aicore__ inline GM_ADDR GetWindAddrByRankId(int64_t rankId)
    {
        return Mc2Kernel::GetBaseWindAddrByRankId(winContext_, rankId, epRankId);
    }

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

    template <>
    CATLASS_DEVICE
    void operator()<AscendC::AIC>(Params const &params)
    {
        AscendC::ICachePreLoad(1);
        uint32_t actualRecvCoreNumPerGroup = recvCoreNum;

        BlockScheduler blockScheduler;
        BlockMmad blockMmad(resource);

        AscendC::GlobalTensor<ElementA> gmA;
        AscendC::GlobalTensor<ElementMxScaleA> gmMxScaleA;
        AscendC::GlobalTensor<ElementB> gmB;
        AscendC::GlobalTensor<ElementMxScaleB> gmMxScaleB;
        AscendC::GlobalTensor<ElementC> gmC;

        uint32_t currentM = 0;
        uint32_t startCoreIdx = 0;
        aicSetFunc = {reinterpret_cast<__gm__ int32_t *>(statusDataSpaceGm +
            IPCStateOffset::DispatchgGmm1::SOFT_SYNC_OFFSET), static_cast<int32_t>(AscendC::GetBlockIdx())};
        Callback callbackAfterFixpipe = MakeCallback(&aicSetFunc);
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            currentM = params.bs;
            gmA.SetGlobalBuffer(params.ptrShareA);
            gmMxScaleA.SetGlobalBuffer(params.ptrShareMxScaleA);
            gmB.SetGlobalBuffer(params.ptrShareB);
            gmMxScaleB.SetGlobalBuffer(params.ptrShareMxScaleB);
            gmC.SetGlobalBuffer(params.ptrShareC);
            GemmCoord inGroupProblemShape{currentM, params.shareProblemShape.n(), params.shareProblemShape.k()};

            BlockScheduler matmulBlockScheduler(inGroupProblemShape, MakeCoord(L1_TILE_M, L1_TILE_N));
            uint32_t coreLoops = matmulBlockScheduler.GetCoreLoops();

            if (CeilDiv(currentM, L1_TILE_M) == 1) {
                gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_DISABLE);
            } else {
                gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_NORMAL);
            }

            uint32_t startLoopIdx;
            if (aicIdx < startCoreIdx) {
                startLoopIdx = aicIdx + aicNum - startCoreIdx;
            } else {
                startLoopIdx = aicIdx - startCoreIdx;
            }

            auto tensorA = tla::MakeTensor(gmA, params.layoutA, Arch::PositionGM{});
            auto tensorMxScaleA = tla::MakeTensor(gmMxScaleA, params.layoutMxScaleA, Arch::PositionGM{});
            auto tensorB = tla::MakeTensor(gmB, params.layoutShareB, Arch::PositionGM{});
            auto tensorMxScaleB = tla::MakeTensor(gmMxScaleB, params.layoutShareMxScaleB, Arch::PositionGM{});
            auto tensorC = tla::MakeTensor(gmC, params.layoutShareC, Arch::PositionGM{});
            if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                // wait AIV quantize needed tokens
                AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
                uint32_t waitFlagCount = params.bs < shareQuantCoreNum ? params.bs : shareQuantCoreNum;
                shareQuantTokenStateTensor.SetGlobalBuffer((__gm__ int32_t*)(
                    statusDataSpaceGm + IPCStateOffset::DispatchgGmm1::SHARE_QUANT_SOFT_SYNC_OFFSET));
                uint32_t expected = waitFlagCount * vToCFlag;
                WaitGroupTokenNumReady(shareQuantTokenStateTensor, expected);
            }
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aicNum) {
                GemmCoord blockCoord = matmulBlockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = matmulBlockScheduler.GetActualBlockShape(blockCoord);

                auto tensorBlockA = GetTile(tensorA,
                    tla::MakeCoord(blockCoord.m() * L1_TILE_M, blockCoord.k() * L1_TILE_K),
                    tla::MakeShape(actualBlockShape.m(), actualBlockShape.k()));

                auto tensorBlockB = GetTile(tensorB,
                    tla::MakeCoord(blockCoord.k() * L1_TILE_K, blockCoord.n() * L1_TILE_N),
                    tla::MakeShape(actualBlockShape.k(), actualBlockShape.n()));

                auto tensorBlockC = GetTile(tensorC,
                    tla::MakeCoord(blockCoord.m() * L1_TILE_M, blockCoord.n() * L1_TILE_N),
                    tla::MakeShape(actualBlockShape.m(), actualBlockShape.n()));

                auto tensorBlockMxScaleA = GetTile(
                    tensorMxScaleA,
                    tla::MakeCoord(blockCoord.m() * L1_TILE_M, blockCoord.k() * L1_TILE_K / MX_SCALE_GROUP_NUM),
                    tla::MakeShape(actualBlockShape.m(), CeilDiv<MX_SCALE_GROUP_NUM>(actualBlockShape.k())));

                auto tensorBlockMxScaleB = GetTile(
                    tensorMxScaleB,
                    tla::MakeCoord(blockCoord.k() * L1_TILE_K / MX_SCALE_GROUP_NUM, blockCoord.n() * L1_TILE_N),
                    tla::MakeShape(CeilDiv<MX_SCALE_GROUP_NUM>(actualBlockShape.k()), actualBlockShape.n()));

                blockMmad(tensorBlockA, tensorBlockB, tensorBlockC, actualBlockShape,
                    tensorBlockMxScaleA, tensorBlockMxScaleB);
                callbackAfterFixpipe();
            }

            startCoreIdx = (startCoreIdx + coreLoops) % aicNum;
        }
        {
            AscendC::GlobalTensor<ElementGroupList> groupList;
            groupList.SetGlobalBuffer(params.ptrGroupList);
            gmA.SetGlobalBuffer((__gm__ ElementA *)params.ptrA);
            gmC.SetGlobalBuffer((__gm__ ElementC *)params.ptrC);
            AscendC::ListTensorDesc gmBlistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrB));
            AscendC::ListTensorDesc gmBScalelistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrMxScaleB));

            int64_t gmGroupOffsetB = 0;
            int64_t gmGroupOffsetMxScaleA = 0;
            int64_t gmGroupOffsetMxScaleB = 0;
            int64_t mxScaleAlignedK = static_cast<int64_t>(CeilDiv<MX_BASEK_FACTOR>(params.problemShape.k()) *
                MX_SCALE_COPY_GROUP_NUM);

            int64_t totalM = 0;
            auto tensorA = tla::MakeTensor(gmA, params.layoutA, Arch::PositionGM{});
            auto tensorC = tla::MakeTensor(gmC, params.layoutC, Arch::PositionGM{});

            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                gmMxScaleA.SetGlobalBuffer(params.ptrMxScaleA + gmGroupOffsetMxScaleA);
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmB.SetGlobalBuffer(gmBlistTensorDesc.GetDataPtr<ElementB>(groupIdx));
                    gmMxScaleB.SetGlobalBuffer(gmBScalelistTensorDesc.GetDataPtr<ElementMxScaleB>(groupIdx));
                } else {
                    gmB.SetGlobalBuffer(gmBlistTensorDesc.GetDataPtr<ElementB>(0) + gmGroupOffsetB);
                    gmMxScaleB.SetGlobalBuffer(gmBScalelistTensorDesc.GetDataPtr<ElementMxScaleB>(0) +
                        gmGroupOffsetMxScaleB);
                }
                if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                    groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(
                        statusDataSpaceGm + IPCStateOffset::DispatchgGmm1::GROUP_TOKEN_NUM_OFFSET) + groupIdx *
                            IPCStateOffset::DispatchgGmm1::GROUP_INFO_SIZE);
                    // wait AIV recv needed tokens
                    uint32_t expected = actualRecvCoreNumPerGroup * vToCFlag;
                    WaitGroupTokenNumReady(groupTokenNumStateTensor, expected);
                    callbackAfterFixpipe();
                    currentM = groupTokenNumStateTensor.GetValue(GROUP_TOKEN_COUNT);
                } else {
                    currentM = groupList.GetValue(groupIdx);
                }
                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

                BlockScheduler matmulBlockScheduler(inGroupProblemShape, MakeCoord(L1_TILE_M, L1_TILE_N));
                uint32_t coreLoops = matmulBlockScheduler.GetCoreLoops();

                if (CeilDiv(currentM, L1_TILE_M) == 1) {
                    gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_DISABLE);
                } else {
                    gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_NORMAL);
                }

                uint32_t startLoopIdx;
                if (aicIdx < startCoreIdx) {
                    startLoopIdx = aicIdx + aicNum - startCoreIdx;
                } else {
                    startLoopIdx = aicIdx - startCoreIdx;
                }

                auto tensorB = tla::MakeTensor(gmB, params.layoutB, Arch::PositionGM{});
                auto tensorMxScaleA = tla::MakeTensor(gmMxScaleA, params.layoutMxScaleA, Arch::PositionGM{});
                auto tensorMxScaleB = tla::MakeTensor(gmMxScaleB, params.layoutMxScaleB, Arch::PositionGM{});

                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aicNum) {
                    GemmCoord blockCoord = matmulBlockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShape = matmulBlockScheduler.GetActualBlockShape(blockCoord);

                    auto tensorBlockA = GetTile(tensorA,
                        tla::MakeCoord(totalM + blockCoord.m() * L1_TILE_M, blockCoord.k() * L1_TILE_K),
                        tla::MakeShape(actualBlockShape.m(), actualBlockShape.k()));

                    auto tensorBlockB = GetTile(tensorB,
                        tla::MakeCoord(blockCoord.k() * L1_TILE_K, blockCoord.n() * L1_TILE_N),
                        tla::MakeShape(actualBlockShape.k(), actualBlockShape.n()));

                    auto tensorBlockC = GetTile(tensorC,
                        tla::MakeCoord(totalM + blockCoord.m() * L1_TILE_M, blockCoord.n() * L1_TILE_N),
                        tla::MakeShape(actualBlockShape.m(), actualBlockShape.n()));

                    auto tensorBlockMxScaleA = GetTile(
                        tensorMxScaleA,
                        tla::MakeCoord(blockCoord.m() * L1_TILE_M, blockCoord.k() * L1_TILE_K / MX_SCALE_GROUP_NUM),
                        tla::MakeShape(actualBlockShape.m(), CeilDiv<MX_SCALE_GROUP_NUM>(actualBlockShape.k())));

                    auto tensorBlockMxScaleB = GetTile(
                        tensorMxScaleB,
                        tla::MakeCoord(blockCoord.k() * L1_TILE_K / MX_SCALE_GROUP_NUM, blockCoord.n() * L1_TILE_N),
                        tla::MakeShape(CeilDiv<MX_SCALE_GROUP_NUM>(actualBlockShape.k()), actualBlockShape.n()));

                    blockMmad(tensorBlockA, tensorBlockB, tensorBlockC, actualBlockShape,
                        tensorBlockMxScaleA, tensorBlockMxScaleB);
                    callbackAfterFixpipe();
                }
                totalM += inGroupProblemShape.m();

                if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                    if constexpr (AscendC::Std::is_one_of_v<ElementB, float4_e2m1x2_t, float4_e1m2x2_t>) {
                        gmGroupOffsetB += std::is_same_v<LayoutB, layout::ColumnMajor> ?
                            CeilDiv<2>(inGroupProblemShape.k()) * inGroupProblemShape.n() :
                            CeilDiv<2>(inGroupProblemShape.n()) * inGroupProblemShape.k();
                    } else {
                        gmGroupOffsetB += inGroupProblemShape.k() * inGroupProblemShape.n();
                    }
                    gmGroupOffsetMxScaleB += mxScaleAlignedK * inGroupProblemShape.n();
                }
                gmGroupOffsetMxScaleA += inGroupProblemShape.m() * mxScaleAlignedK;

                startCoreIdx = (startCoreIdx + coreLoops) % aicNum;
            }

            if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
                blockMmad.template SynchronizeBlock<decltype(tensorC)>();
            }
        }

        AscendC::PipeBarrier<PIPE_ALL>();
        AscendC::SyncAll<false>();
    }

    CATLASS_DEVICE
    void QuantDynamicMx(
        AscendC::LocalTensor<ElementA>& outLocal, AscendC::LocalTensor<XType>& inLocal,
            AscendC::LocalTensor<float>& tokenF32LT, uint32_t quantLength, uint32_t mxScaleNumPerToken)
    {
        __ubuf__ XType* srcAddr = (__ubuf__ XType*)inLocal.GetPhyAddr();
        __ubuf__ uint16_t* maxExpAddr = (__ubuf__ uint16_t*)tokenF32LT.GetPhyAddr();
        __ubuf__ uint16_t* halfScaleLocalAddr = (__ubuf__ uint16_t*)tokenF32LT[mxScaleNumPerToken].GetPhyAddr();
        __ubuf__ int8_t* outLocalAddr = (__ubuf__ int8_t*)outLocal.GetPhyAddr();
        __ubuf__ uint16_t* mxScaleLocalAddr = (__ubuf__ uint16_t*)outLocal[quantLength].GetPhyAddr();

        quant::ComputeMaxExp(srcAddr, maxExpAddr, quantLength);
        quant::ComputeScale<ElementA>(maxExpAddr, mxScaleLocalAddr, halfScaleLocalAddr, mxScaleNumPerToken);
        if constexpr (AscendC::Std::is_one_of_v<ElementA, float4_e2m1x2_t, float4_e1m2x2_t>) {
            quant::ComputeFp4Data<XType, ElementA, AscendC::RoundMode::CAST_TRUNC, AscendC::RoundMode::CAST_RINT>(
                srcAddr, halfScaleLocalAddr, outLocalAddr, quantLength);
        } else {
            quant::ComputeFp8Data<XType, ElementA, AscendC::RoundMode::CAST_TRUNC, AscendC::RoundMode::CAST_RINT>(
                srcAddr, halfScaleLocalAddr, outLocalAddr, quantLength);
        }
    }

    CATLASS_DEVICE
    void TokenActiveMaskCal(GM_ADDR gmXActiveMask, int64_t ubOffset)
    {
        int64_t subUbOffset = ubOffset;

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
        AscendC::Duplicate<int32_t>(dstExpIdTensor_, dstExpertId, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Sub(dstExpIdTensor_, expertIdsTensor_, dstExpIdTensor_, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Abs(dstExpIdFp32Tensor_, dstExpIdFp32Tensor_, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Mins(dstExpIdTensor_, dstExpIdTensor_, 1, tokenIndex);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceSum<float>(dstExpIdFp32Tensor_, dstExpIdFp32Tensor_, reduceSumWorkLocalTensor, tokenIndex);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        int32_t curOtherExpertCnt = dstExpIdTensor_(0);
        if (tokenIndex > curOtherExpertCnt) {
            curExpertCnt = tokenIndex - curOtherExpertCnt;
        }
    }

    CATLASS_DEVICE
    void QuantToken(AscendC::LocalTensor<XType> &xInTensor, AscendC::LocalTensor<float> &smoothScaleTensor,
        AscendC::LocalTensor<ElementA> &yInt8Tensor, int64_t ubOffset)
    {
        int64_t subUbOffset = ubOffset;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            AscendC::Cast(xFp32TmpTensor, xInTensor, AscendC::RoundMode::CAST_NONE, tokenLength);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Mul(xFp32TmpTensor, xFp32TmpTensor, smoothScaleTensor, tokenLength);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Cast(xInTensor, xFp32TmpTensor, AscendC::RoundMode::CAST_RINT, tokenLength);
            AscendC::PipeBarrier<PIPE_V>();
        }
        QuantDynamicMx(yInt8Tensor, xInTensor, tokenF32LT, tokenLength, x1MxScaleNum);
    }

    CATLASS_DEVICE
    void ShmemSendToMoeExprt(GM_ADDR gmX, GM_ADDR gmExpandIdx, GM_ADDR gmMoeSmoothScales, GM_ADDR gmEpSendCount,
            int64_t x1TokenOffset, int64_t x1ScaleOffset, int64_t x1FlagOffset)
    {
        if (startTokenId_ >= expertIdsCnt || localTokenNum_ == 0) {
            return;
        }

        AscendC::Duplicate(expertCountTensor, (int32_t)0, localTokenNum_);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(1);

        AscendC::LocalTensor<int32_t> dstExpertCntTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(moeExpertNum * sizeof(int32_t));
        AscendC::Duplicate(dstExpertCntTensor, (int32_t)-1, moeExpertNum);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(1);

        AscendC::LocalTensor<int32_t> tmpFlagTensor;

        AscendC::GlobalTensor<XType> srcWinGMTensor;
        srcWinGMTensor.SetGlobalBuffer((__gm__ XType *)gmX);
        AscendC::GlobalTensor<float> moeSmoothScaleGMTensor;

        if constexpr (EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            moeSmoothScaleGMTensor.SetGlobalBuffer((__gm__ float*) gmMoeSmoothScales);
        }
        AscendC::DataCopyExtParams flagCopyParams = {1U, sizeof(int32_t), 0U, 0U, 0U};
        tmpFlagTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(INT32_COUNT_PER_BLOCK * sizeof(int32_t));
        tmpFlagTensor.SetValue(0, tokenFlag);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<ElementA> dstWinGMTensor;
        AscendC::GlobalTensor<ElementMxScaleA> dstScaleGMTensor;
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
        AscendC::DataCopyExtParams x1MxScaleCopyParams = {
            1U, (uint32_t)(x1MxScaleNum * sizeof(ElementMxScaleA)), 0U, 0U, 0U};
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);

        // CompareScalar needs a 256B-aligned element count; GatherMask srcLength uses real localTokenNum_ to skip pad.
        constexpr uint32_t COMPARE_ALIGN_BYTES = 256U;
        uint32_t compareCountBytes =
            CEIL(localTokenNum_ * static_cast<uint32_t>(sizeof(int32_t)), COMPARE_ALIGN_BYTES) * COMPARE_ALIGN_BYTES;
        uint32_t compareCount = compareCountBytes / static_cast<uint32_t>(sizeof(int32_t));
        uint32_t maskAlignSize = CEIL(compareCount / 8U, UB_BLOCK_SIZE) * UB_BLOCK_SIZE;

        AscendC::LocalTensor<int32_t> cmpExpertIds =
            resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(compareCountBytes);
        AscendC::LocalTensor<int32_t> tokenIdxTensor =
            resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(compareCountBytes);
        AscendC::LocalTensor<int32_t> validTokenIdxTensor =
            resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(localTokenNum_ * sizeof(int32_t));
        AscendC::LocalTensor<int32_t> slotIdsTensor =
            resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(compareCountBytes);
        AscendC::LocalTensor<int32_t> modScratchTensor =
            resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(compareCountBytes);
        AscendC::LocalTensor<uint8_t> maskBuf =
            resource.ubBuf.template GetBufferByByte<uint8_t>(ubOffset);
        ubOffset += CEIL_UP(maskAlignSize);
        AscendC::LocalTensor<uint32_t> maskBufU32 = maskBuf.template ReinterpretCast<uint32_t>();

        AscendC::Duplicate(cmpExpertIds, (int32_t)0, compareCount);
        AscendC::PipeBarrier<PIPE_V>();
        // UB->UB exact copy of localTokenNum_; keep Duplicate zeros in the tail
        // (no aligned over-copy + scalar tail clear).
        if (useFullExpertIdsCopy_) {
            AscendC::Copy(cmpExpertIds, expertIdsTensor_[startTokenId_], localTokenNum_);
        } else {
            AscendC::Copy(cmpExpertIds, expertIdsTensor_, localTokenNum_);
        }
        AscendC::PipeBarrier<PIPE_V>();
        // Build absolute indices [startTokenId_, startTokenId_+1, ...) without a scalar SetValue loop.
        AscendC::CreateVecIndex(tokenIdxTensor, static_cast<int32_t>(startTokenId_), localTokenNum_);
        AscendC::PipeBarrier<PIPE_V>();

        // slotIds = expertIds % moeExpertNumPerRank
        //         ≡ expertIds - (expertIds / moeExpertNumPerRank) * moeExpertNumPerRank
        // Divs does not support int32; use Div instead.
        AscendC::Duplicate(modScratchTensor, static_cast<int32_t>(moeExpertNumPerRank), compareCount);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Div(slotIdsTensor, cmpExpertIds, modScratchTensor, static_cast<int32_t>(compareCount));
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Muls(slotIdsTensor, slotIdsTensor, static_cast<int32_t>(moeExpertNumPerRank),
            static_cast<int32_t>(compareCount));
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Sub(slotIdsTensor, cmpExpertIds, slotIdsTensor, static_cast<int32_t>(compareCount));
        AscendC::PipeBarrier<PIPE_V>();

        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(1);
        uint32_t sendValidTokenIndex = 0;
        for (uint32_t sendGroupIndex = 0; sendGroupIndex < moeExpertNumPerRank; ++sendGroupIndex) {
            AscendC::CompareScalar(maskBuf, slotIdsTensor, static_cast<int32_t>(sendGroupIndex),
                AscendC::CMPMODE::EQ, compareCount);
            uint64_t sendCnt = 0;
            AscendC::GatherMask(validTokenIdxTensor, tokenIdxTensor, maskBufU32, true,
                static_cast<uint32_t>(localTokenNum_), {1, 1, 0, 0}, sendCnt);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
            if (sendCnt == 0) {
                continue;
            }

            for (uint64_t j = 0; j < sendCnt; ++j) {
                uint32_t tokenIndex = static_cast<uint32_t>(validTokenIdxTensor.GetValue(j));
                int32_t dstExpertId = cmpExpertIds.GetValue(tokenIndex - startTokenId_);
                if (dstExpertId < 0) {
                    continue;
                }
                uint32_t index = (sendValidTokenIndex & 1) ? 0 : 1;
                int32_t eventId = (sendValidTokenIndex & 1) ? 0 : 1;
                sendValidTokenIndex += 1;
                int32_t curExpertCnt = dstExpertCntTensor.GetValue(dstExpertId);
                if (!useFullExpertIdsCopy_) {
                    if (curExpertCnt == -1) {
                        curExpertCnt = 0;
                        // Init for the first token
                        CalExpandxIdxInRound(dstExpertId, tokenIndex, curExpertCnt, ubOffset);
                    } else {
                        curExpertCnt++;
                    }
                    dstExpertCntTensor.SetValue(dstExpertId, curExpertCnt);
                    AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(1);
                    AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(1);
                } else {
                    // Full-copy mode: call CalExpandxIdx directly (does not depend on a running count)
                    curExpertCnt = 0;
                    CalExpandxIdx(dstExpertId, tokenIndex, curExpertCnt, ubOffset);
                }
                // Store and write to gmExpandIdx at the end
                expertCountTensor(tokenIndex - startTokenId_) = curExpertCnt;

                uint32_t tempRankId = static_cast<uint32_t>(dstExpertId) / moeExpertNumPerRank;
                uint32_t offsetIdx = static_cast<uint32_t>(dstExpertId) * epRankSize + epRankId;
                uint32_t col = offsetIdx % moeExpertNum;
                int32_t dstExpertOffset = (col == 0) ? 0 : sendCountsTensor.GetValue(offsetIdx - 1);
                auto dstX1Addr = GetWindAddrByRankId(tempRankId) + x1TokenOffset;
                auto dstX1ScaleAddr = GetWindAddrByRankId(tempRankId) + x1ScaleOffset;
                auto dstSwigluOutAddr = GetWindAddrByRankId(tempRankId) + x1FlagOffset;

                dstWinGMTensor.SetGlobalBuffer((__gm__ ElementA *)(dstX1Addr + hOutSize *
                    (dstExpertOffset + curExpertCnt) * sizeof(ElementA)));
                dstScaleGMTensor.SetGlobalBuffer((__gm__ ElementMxScaleA *)(dstX1ScaleAddr +
                    (dstExpertOffset + curExpertCnt) * x1MxScaleNum * sizeof(ElementMxScaleA)));
                dstTokenFlagGMTensor.SetGlobalBuffer((__gm__ int32_t *)(dstSwigluOutAddr +
                    (dstExpertOffset + curExpertCnt) * sizeof(int32_t)));

                AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
                AscendC::DataCopy(xInTensor[index], srcWinGMTensor[tokenIndex / axisK * tokenLength], tokenLength);
                if constexpr (EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
                    AscendC::PipeBarrier<PIPE_MTE2>();
                    AscendC::DataCopy(moeSmoothScaleTensor[index], moeSmoothScaleGMTensor[dstExpertId * tokenLength],
                        tokenLength);
                }
                AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
                QuantToken(xInTensor[index], moeSmoothScaleTensor[index], yInt8Tensor[index], ubOffset);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(eventId);

                AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(eventId);
                AscendC::DataCopy(dstWinGMTensor, yInt8Tensor[index], tokenLength);
                AscendC::DataCopyPad(dstScaleGMTensor, yScaleTensor[index], x1MxScaleCopyParams);
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

    CATLASS_DEVICE void
    SendCoreDataFunc(GM_ADDR gmX, GM_ADDR gmExpandIdx, GM_ADDR gmMoeSmoothScales, GM_ADDR gmEpSendCount,
            int64_t x1TokenOffset, int64_t x1ScaleOffset, int64_t x1FlagOffset)
    {
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

        expertCountTensor = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        ubOffset += CEIL_UP(localTokenNum_ * sizeof(int32_t));

        for (uint32_t i = 0; i < BUFFER_NUM; ++i) {
            xInTensor[i] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(XType));
            yInt8Tensor[i] = resource.ubBuf.template GetBufferByByte<ElementA>(ubOffset);
            yScaleTensor[i] = yInt8Tensor[i][tokenLength].template ReinterpretCast<ElementMxScaleA>();
            ubOffset += CEIL_UP(axisHCommu * sizeof(ElementA));
            if constexpr (EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
                moeSmoothScaleTensor[i] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
                ubOffset += CEIL_UP(tokenLength * sizeof(float));
            }
        }
        xFp32TmpTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(float));
        tokenF32LT = resource.ubBuf.template GetBufferByByte<ElementC>(ubOffset);
        ubOffset += x1MxScaleNum * FLOAT_PAIR * sizeof(float);

        if (!useFullExpertIdsCopy_) {
            roundSize = (UB_MAX_SIZE - ubOffset) / sizeof(int32_t) / UB_PART_SIZE;
            uint32_t roundBs = roundSize / axisK;
            num_rounds = (activeMaskBsCnt + roundBs - 1) / roundBs;
            if (roundBs > activeMaskBsCnt) {
                roundSize = expertIdsCnt;
            }
            roundExpertIds = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
            ubOffset += CEIL_UP(roundSize * sizeof(int32_t));
            dstExpIdTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
            dstExpIdFp32Tensor_ = dstExpIdTensor_.ReinterpretCast<float>();
            ubOffset += CEIL_UP(roundSize * sizeof(int32_t));
        } else {
            dstExpIdTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
            dstExpIdFp32Tensor_ = dstExpIdTensor_.ReinterpretCast<float>();
            ubOffset += CEIL_UP(expertIdsCnt * sizeof(int32_t));
        }
        reduceSumWorkLocalTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += REDUCE_SUM_WORK_SIZE;

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
        ShmemSendToMoeExprt(gmX, gmExpandIdx, gmMoeSmoothScales, gmEpSendCount, x1TokenOffset, x1ScaleOffset,
            x1FlagOffset);
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void shareQuantCoreFunc(GM_ADDR gmX, GM_ADDR gmShareSmoothScales, GM_ADDR gmShareX1Token, GM_ADDR gmShareX1Scale)
    {
        ubOffset = 0;
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
        AscendC::GlobalTensor<XType> srcXGMTensor;
        srcXGMTensor.SetGlobalBuffer((__gm__ XType*)gmX);
        AscendC::GlobalTensor<ElementA> dstXInt8GMTensor;
        dstXInt8GMTensor.SetGlobalBuffer((__gm__ ElementA*)gmShareX1Token);
        AscendC::GlobalTensor<ElementMxScaleA> dstXScaleGMTensor;
        dstXScaleGMTensor.SetGlobalBuffer((__gm__ ElementMxScaleA*)gmShareX1Scale);
        AscendC::GlobalTensor<float> shareSmoothScaleGMTensor;
        shareSmoothScaleGMTensor.SetGlobalBuffer((__gm__ float*)gmShareSmoothScales);

        for (uint32_t i = 0; i < BUFFER_NUM; ++i) {
            xInTensor[i] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(XType));
            yInt8Tensor[i] = resource.ubBuf.template GetBufferByByte<ElementA>(ubOffset);
            yScaleTensor[i] = yInt8Tensor[i][tokenLength].template ReinterpretCast<ElementMxScaleA>();
            ubOffset += CEIL_UP(axisHCommu * sizeof(ElementA));
        }
        xFp32TmpTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(float));
        tokenF32LT = resource.ubBuf.template GetBufferByByte<ElementC>(ubOffset);
        ubOffset += x1MxScaleNum * FLOAT_PAIR * sizeof(float);
        tmpLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(UB_BLOCK_SIZE);
        if constexpr (EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            shareSmoothScaleTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
            AscendC::DataCopy(shareSmoothScaleTensor, shareSmoothScaleGMTensor, tokenLength);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
        }
        // double buffer
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(1);
        AscendC::DataCopyExtParams x1MxScaleCopyParams = {
            1U, (uint32_t)(x1MxScaleNum * sizeof(ElementMxScaleA)), 0U, 0U, 0U};
        for (uint32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
            uint32_t index = (tokenIndex & 1) ? 0 : 1;
            int32_t eventId = (tokenIndex & 1) ? 0 : 1;
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
            AscendC::DataCopy(xInTensor[index], srcXGMTensor[tokenIndex * tokenLength], tokenLength);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
            QuantToken(xInTensor[index], shareSmoothScaleTensor, yInt8Tensor[index], ubOffset);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(eventId);
            AscendC::DataCopy(dstXInt8GMTensor[tokenIndex * tokenLength], yInt8Tensor[index], tokenLength);
            AscendC::DataCopyPad(
                dstXScaleGMTensor[tokenIndex * x1MxScaleNum], yScaleTensor[index], x1MxScaleCopyParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(eventId);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventId);
        }
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(1);

        // Set GM to info AIC
        AscendC::PipeBarrier<PIPE_ALL>();
        tmpLocalTensor.SetValue(CV_FLAG_INDEX, vToCFlag);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
        shareQuantTokenStateTensor.SetGlobalBuffer(
            (__gm__ int32_t*)(statusDataSpaceGm + IPCStateOffset::DispatchgGmm1::SHARE_QUANT_SOFT_SYNC_OFFSET));
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::SetAtomicAdd<int32_t>();
        // Atomic add
        AscendC::DataCopy(shareQuantTokenStateTensor, tmpLocalTensor, INT32_COUNT_PER_BLOCK);
        AscendC::SetAtomicNone();
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void RecvToken(uint32_t startTokenIdx, uint32_t recvTokenPerCore, int64_t x1FlagOffset)
    {
        AscendC::GlobalTensor<float> x1FlagGlobalTensor;
        x1FlagGlobalTensor.SetGlobalBuffer((__gm__ float *)(GetWindAddrByRankId(epRankId) + x1FlagOffset) +
            startTokenIdx);
        AscendC::DataCopyExtParams flagCopyParams = {
            1U, static_cast<uint32_t>(recvTokenPerCore * sizeof(float)), 0U, 0U, 0U};
        AscendC::DataCopyPadExtParams<float> copyPadParams{false, 0U, 0U, 0U};
        float minTarget = recvTokenPerCore * tokenFlagSumTarget - (float)0.5;
        float maxTarget = recvTokenPerCore * tokenFlagSumTarget + (float)0.5;
        float curSum = 0.0;
        while (true) {
            AscendC::DataCopyPad(tokenFlagLocalTensor, x1FlagGlobalTensor, flagCopyParams, copyPadParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::ReduceSum(tokenFlagSumLocalTensor, tokenFlagLocalTensor, reduceSumWorkLocalTensor,
                recvTokenPerCore);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
            curSum = tokenFlagSumLocalTensor.GetValue(0);
            if (curSum > minTarget && curSum < maxTarget) {
                break;
            }
            SPIN_WAIT_CYCLES();
        }
    }

    CATLASS_DEVICE
    void RecvCoreFunc(GM_ADDR gmEpSendCount, int64_t x1FlagOffset)
    {
        ubOffset = 0;
        AscendC::LocalTensor<int32_t> notifyCubeTensor = resource.ubBuf.template GetBufferByByte<int32_t>(
                                                                                                    ubOffset);
        ubOffset += CEIL_UP(UB_BLOCK_SIZE);
        tokenFlagLocalTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(TOKEN_FLAG_BUF_INT32_COUNT * sizeof(int32_t));
        tokenFlagSumLocalTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(UB_BLOCK_SIZE);
        reduceSumWorkLocalTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += REDUCE_SUM_WORK_SIZE;

        AscendC::GlobalTensor<int32_t> sendCountsGlobal;
        sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(gmEpSendCount));

        uint32_t startCoreIdx = 0;
        uint32_t preExpertToken = 0;
        for (uint32_t groupId = 0; groupId < localExpertNum; ++groupId) {
            uint32_t currentM = sendCountsGlobal.GetValue(epRankId * epRankSize * moeExpertNumPerRank + (groupId + 1) *
                epRankSize - 1) - preExpertToken;

            uint32_t recvTokenPerCore = currentM / recvCoreNum;
            uint32_t remainToken = currentM % recvCoreNum;

            uint32_t newRecvCoreIdx = (recvCoreIdx + recvCoreNum - startCoreIdx) % recvCoreNum;
            uint32_t startTokenIdx = newRecvCoreIdx * recvTokenPerCore + preExpertToken;
            if (newRecvCoreIdx < remainToken) {
                recvTokenPerCore += 1;
                startTokenIdx += newRecvCoreIdx;
            } else {
                startTokenIdx += remainToken;
            }
            uint32_t endTokenIdx = startTokenIdx + recvTokenPerCore;

            if (recvTokenPerCore > 0) {
                RecvToken(startTokenIdx, recvTokenPerCore, x1FlagOffset);
            }
            // recv finish, inform AIC
            AscendC::PipeBarrier<PIPE_ALL>();
            notifyCubeTensor.SetValue(CV_FLAG_INDEX, vToCFlag);
            notifyCubeTensor.SetValue(SELF_COUNT_INDEX, recvTokenPerCore);
            AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);

            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm +
                IPCStateOffset::DispatchgGmm1::GROUP_TOKEN_NUM_OFFSET));
            AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
            AscendC::SetAtomicAdd<int32_t>();
            AscendC::DataCopy(
                groupTokenNumStateTensor[groupId * IPCStateOffset::DispatchgGmm1::GROUP_INFO_SIZE], notifyCubeTensor,
                    INT32_COUNT_PER_BLOCK);
            AscendC::SetAtomicNone();
            AscendC::PipeBarrier<PIPE_ALL>();
            if (recvTokenPerCore > 0) {
                AscendC::GlobalTensor<float> x1FlagGlobalTensor;
                x1FlagGlobalTensor.SetGlobalBuffer((__gm__ float *)(GetWindAddrByRankId(epRankId) + x1FlagOffset) +
                    startTokenIdx);
                AscendC::Duplicate(tokenFlagLocalTensor, (float)0.0, recvTokenPerCore);
                AscendC::DataCopyExtParams zerosCopyParams = {1U,
                    static_cast<uint32_t>(recvTokenPerCore * sizeof(float)), 0U, 0U, 0U};
                AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
                AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
                AscendC::DataCopyPad(x1FlagGlobalTensor, tokenFlagLocalTensor, zerosCopyParams);
            }
            startCoreIdx = (startCoreIdx + currentM) % recvCoreNum;
            preExpertToken += currentM;
        }
    }

    CATLASS_DEVICE
    void AivInitParams(Params const &params)
    {
        moeExpertNumPerRank = params.moeExpertNumPerRank;

        epRankSize = params.epRankSize;
        epRankId = params.epRankId;
        expertCntUp = epRankSize * moeExpertNumPerRank;
        localExpertNum = moeExpertNumPerRank;
        moeExpertNum = params.moeExpertNum;
        tokenLength = params.tokenLen;

        x1MxScaleNum = CEIL(tokenLength, MX_SCALE_GROUP_SIZE);
        mxActPackedLen_ = MxActPackedLen<ElementA>(tokenLength);
        hOutSize = mxActPackedLen_ * sizeof(ElementA);
        scaleSize = x1MxScaleNum * sizeof(ElementMxScaleA);
        scaleParamPad =  CEIL(scaleSize + sizeof(int32_t), TOKEN_EXTRA_SPACE) * TOKEN_EXTRA_SPACE;
        hCommuSize = hOutSize + scaleParamPad;
        axisHCommu = hCommuSize / sizeof(ElementA);
        axisBS = params.bs;
        activeMaskBsCnt = axisBS;
        axisK = params.topK;
        uint32_t maxAxisBs = params.globalBs / epRankSize;
    }

    CATLASS_DEVICE
    void AivInitState()
    {
        // state of data sapce
        sumTarget = dataState == 0 ? 1.0f : 0.0f;
        tokenFlag = dataState == 0 ? TOKEN_FLAG_1 : TOKEN_FLAG_2;
        tokenFlagSumTarget = dataState == 0 ? 1.0 : TOKEN_FLAG_SUM_TARGET_ALT;
        exp_flag_ = dataState == 0 ? (float)1.0 : (float)CROSS_RANK_SYNC_FLAG;
    }

    CATLASS_DEVICE
    void LocalRankLayout()
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
        GM_ADDR localNotifyDataAddr = statusDataSpaceGm + IPCStateOffset::DispatchgGmm1::LOCAL_SEND_COUNT_OFFSET; /*
            GetShmemLocalNotifyDataAddr(epRankId); */
        localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)localNotifyDataAddr);
        AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum * sizeof(int32_t)),
            0U, 0U, 0U};
        AscendC::SetAtomicAdd<int32_t>();
        AscendC::DataCopyPad(localNotifyDataTensor, sendCountTensor, dataCopyParams);
        AscendC::SetAtomicNone();
        AscendC::PipeBarrier<PIPE_MTE3>();
    }

    CATLASS_DEVICE
    void SetLayoutStatus()
    {
        uint32_t rankNumPerBlock = epRankSize / aivNum;
        uint32_t remainderRankNum = epRankSize % aivNum;
        uint32_t startRankId = rankNumPerBlock * aivIdx;
        if (aivIdx < remainderRankNum) {
            rankNumPerBlock += 1;
            startRankId += aivIdx;
        } else {
            startRankId += remainderRankNum;
        }
        uint32_t endRankId = startRankId + rankNumPerBlock;
        if (startRankId >= epRankSize) {
            return;
        }

        AscendC::LocalTensor<float> statusTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += UB_BLOCK_SIZE;
        statusTensor.SetValue(0, exp_flag_);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<float> layoutStatusTensor;
        AscendC::DataCopyParams intriParams{1, static_cast<uint16_t>(sizeof(float)), 0, 0};
        for (uint32_t targetRankId = startRankId; targetRankId < endRankId; ++targetRankId) {
            GM_ADDR layoutStatusAddr = GetWindStateAddrByRankId(targetRankId) +
                IPCStateOffset::DispatchgGmm1::SEND_COUNT_FLAG_OFFSET + dataState *
                IPCStateOffset::DispatchgGmm1::MAX_SEND_COUNT_SIZE;
            layoutStatusTensor.SetGlobalBuffer((__gm__ float *)layoutStatusAddr);
            AscendC::DataCopy(layoutStatusTensor[epRankId * INT32_COUNT_PER_BLOCK], statusTensor,
                INT32_COUNT_PER_BLOCK);
        }
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    CATLASS_DEVICE
    void WaitLayoutStatusAndFetchCounts(GM_ADDR gmAllRankSendCount)
    {
        uint32_t rankNumPerBlock = epRankSize / aivNum;
        uint32_t remainderRankNum = epRankSize % aivNum;
        uint32_t startRankId = rankNumPerBlock * aivIdx;
        if (aivIdx < remainderRankNum) {
            rankNumPerBlock += 1;
            startRankId += aivIdx;
        } else {
            startRankId += remainderRankNum;
        }
        uint32_t endRankId = startRankId + rankNumPerBlock;
        if (startRankId >= epRankSize) {
            return;
        }

        AscendC::LocalTensor<float> layoutWaitStatusTensor = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += UB_BLOCK_SIZE;
        AscendC::GlobalTensor<float> layoutStatusTensor;
        AscendC::GlobalTensor<int32_t> localNotifyDataTensor;
        AscendC::GlobalTensor<int32_t> allExpertTokenNumsTensor;
        allExpertTokenNumsTensor.SetGlobalBuffer((__gm__ int32_t *)gmAllRankSendCount);

        AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum * sizeof(int32_t)),
            0U, 0U, 0U};

        float minFlagVal = exp_flag_ - static_cast<float>(0.5);
        float maxFlagVal = exp_flag_ + static_cast<float>(0.5);

        for (uint32_t targetRankId = startRankId; targetRankId < endRankId; ++targetRankId) {
            float curVal = static_cast<float>(-1.0);
            GM_ADDR layoutStatusAddr = GetWindStateAddrByRankId(targetRankId) +
                IPCStateOffset::DispatchgGmm1::SEND_COUNT_FLAG_OFFSET + dataState *
                IPCStateOffset::DispatchgGmm1::MAX_SEND_COUNT_SIZE; /* GetShmemLayoutStatusAddr(targetRankId); */
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

            GM_ADDR localNotifyDataAddr = GetWindStateAddrByRankId(targetRankId) +
                IPCStateOffset::DispatchgGmm1::LOCAL_SEND_COUNT_OFFSET; /* GetShmemLocalNotifyDataAddr(targetRankId); */
            localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)localNotifyDataAddr);
            CpGM2GMMTE<int32_t>(localNotifyDataTensor, allExpertTokenNumsTensor[targetRankId * moeExpertNum],
                moeExpertNum);
            AscendC::PipeBarrier<PIPE_ALL>();
        }
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    CATLASS_DEVICE
    void ExpertTokenCountCumsum(GM_ADDR gmEpSendCount, GM_ADDR gmAllRankSendCount)
    {
        AscendC::LocalTensor<int32_t> allExpertTokenNumsTensor = resource.ubBuf.template GetBufferByByte<int32_t>(
            ubOffset);
        AscendC::GlobalTensor<int32_t> allExpertTokenNumsGMTensor;
        allExpertTokenNumsGMTensor.SetGlobalBuffer((__gm__ int32_t *)gmAllRankSendCount);

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

        uint32_t rankNumPerCore = epRankSize / aivNum;
        uint32_t remainderRankNum = epRankSize % aivNum;
        uint32_t startRankId = rankNumPerCore * aivIdx;
        if (aivIdx < remainderRankNum) {
            rankNumPerCore += 1;
            startRankId += aivIdx;
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

    CATLASS_DEVICE void
    SendCoreLayoutFunc(GM_ADDR gmExpertIds, GM_ADDR gmXActiveMask, GM_ADDR gmEpSendCount, GM_ADDR gmAllRankSendCount)
    {
        if constexpr (EXEC_FLAG & EXEC_FLAG_X_ACTIVE_MASK) {
            ubOffset = 0;
            maskInputTensor = resource.ubBuf.template GetBufferByByte<bool>(ubOffset);
            ubOffset += CEIL_UP(axisBS * sizeof(bool));
            maskInputInt8Tensor = maskInputTensor.template ReinterpretCast<int8_t>();
            maskTmpTensor = resource.ubBuf.template GetBufferByByte<half>(ubOffset);
            ubOffset += CEIL_UP(axisBS * sizeof(half));
            sumOutTensor = resource.ubBuf.template GetBufferByByte<half>(ubOffset);
            ubOffset += CEIL_UP(SUM_TMP_TENSOR_SIZE);
            sharedTmpBuffer = resource.ubBuf.template GetBufferByByte<uint8_t>(ubOffset);
            TokenActiveMaskCal(gmXActiveMask, ubOffset);
        }
        ubOffset = 0;
        expertIdsCnt = activeMaskBsCnt * axisK;

        useFullExpertIdsCopy_ = (activeMaskBsCnt <= COPY_FULL_EXPERT_IDS_BS);

        uint32_t layoutTokenNum = expertIdsCnt / aivNum;
        uint32_t layoutRemainder = expertIdsCnt % aivNum;
        startTokenId_ = layoutTokenNum * aivIdx;
        if (aivIdx < layoutRemainder) {
            layoutTokenNum += 1;
            startTokenId_ += aivIdx;
        } else {
            startTokenId_ += layoutRemainder;
        }
        endTokenId_ = startTokenId_ + layoutTokenNum;
        localTokenNum_ = endTokenId_ - startTokenId_;

        uint32_t sendDataCoreNum = aivNum / 2;
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

        LocalRankLayout();
        AscendC::SyncAll<true>();
        SetLayoutStatus();
        WaitLayoutStatusAndFetchCounts(gmAllRankSendCount);
        AscendC::SyncAll<true>();
        ExpertTokenCountCumsum(gmEpSendCount, gmAllRankSendCount);
        AscendC::SyncAll<true>();
    }

    // Compute token offset curExpertCnt in the destination expert buffer (round-based version):
    // When UB cannot hold all expertIds at once, copy expertIds from GM in rounds of roundSize and count
    // occurrences of dstExpertId in [0, tokenIndex). Used for large-bs cases.
    CATLASS_DEVICE
    void CalExpandxIdxInRound(int32_t dstExpertId, uint32_t tokenIndex, int32_t &curExpertCnt, int64_t ubOffset)
    {
        if (tokenIndex == 0) {
            return;
        }
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
            AscendC::Sub(dstExpIdTensor_, roundExpertIds, dstExpIdTensor_, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Abs(dstExpIdFp32Tensor_, dstExpIdFp32Tensor_, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Mins(dstExpIdTensor_, dstExpIdTensor_, 1, calcSize);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::ReduceSum<float>(dstExpIdFp32Tensor_, dstExpIdFp32Tensor_, reduceSumWorkLocalTensor, calcSize);
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
    void UpdateAndCleanInfo(__gm__ ElementGroupList_ *ptrGroupList, GM_ADDR gmEpSendCount, GM_ADDR gmExpertTokenNums)
    {
        if (isCompCore && AscendC::GetSubBlockIdx() == 0) {
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer((__gm__ int32_t*)(statusDataSpaceGm +
                IPCStateOffset::DispatchgGmm1::SOFT_SYNC_OFFSET));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(0);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, INT32_COUNT_PER_BLOCK);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopy(softSyncTensor[compCoreIdx * CVSoftSync::SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                                                tmpZeroLocalTensor, INT32_COUNT_PER_BLOCK);
        }
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_DEEP_FUSE)) {
            return ;
        }
        if (aivIdx == aiCoreGroupNum * subBlockNum - 1) {
            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm +
                IPCStateOffset::DispatchgGmm1::GROUP_TOKEN_NUM_OFFSET));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(512);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0,
                IPCStateOffset::DispatchgGmm1::GROUP_INFO_SIZE * localExpertNum);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopy(groupTokenNumStateTensor, tmpZeroLocalTensor,
                IPCStateOffset::DispatchgGmm1::GROUP_INFO_SIZE * localExpertNum);
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
                shareQuantTokenStateTensor.SetGlobalBuffer(
                    (__gm__ int32_t*)(statusDataSpaceGm + IPCStateOffset::DispatchgGmm1::SHARE_QUANT_SOFT_SYNC_OFFSET));
                AscendC::DataCopy(shareQuantTokenStateTensor, tmpZeroLocalTensor, 8);
            }
        }

        if (aivIdx == aiCoreGroupNum * subBlockNum - 5) {
            AscendC::GlobalTensor<int32_t> localNotifyDataTensor;
            localNotifyDataTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm +
                IPCStateOffset::DispatchgGmm1::LOCAL_SEND_COUNT_OFFSET));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(512);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, moeExpertNum);
            AscendC::DataCopyExtParams dataCopyParams = {1U, static_cast<uint32_t>(moeExpertNum * sizeof(int32_t)), 0U,
                0U, 0U};
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopyPad(localNotifyDataTensor, tmpZeroLocalTensor, dataCopyParams);
        }

        if (aivIdx == aiCoreGroupNum * subBlockNum - 3) {
            AscendC::GlobalTensor<int32_t> layoutStatusTensor;
            layoutStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm +
                IPCStateOffset::DispatchgGmm1::SEND_COUNT_FLAG_OFFSET + dataState *
                IPCStateOffset::DispatchgGmm1::MAX_SEND_COUNT_SIZE));
            AscendC::LocalTensor<int32_t> tmpZeroLocalTensor = resource.ubBuf.template GetBufferByByte<int32_t>(512);
            AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, epRankSize * INT32_COUNT_PER_BLOCK);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopy(layoutStatusTensor, tmpZeroLocalTensor, epRankSize * INT32_COUNT_PER_BLOCK);
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
                uint32_t tokenNum = FlushAndGetValue<int32_t>(sendCountsGlobal,
                    epRankId * moeExpertNum + localMoeIndex * epRankSize + epRankSize - 1);
                uint32_t nonCumSumTokenNum = tokenNum - tmpTokenNum;
                SetValueAndFlush<int64_t>(nonCumSumExpertTokenNumsTensor, localMoeIndex, nonCumSumTokenNum);
                tmpTokenNum = tokenNum;
            }
        }
    }

    CATLASS_DEVICE
    void PostSwigluDynamicQuant(__gm__ ElementC *swigluOutAddr, __gm__ ElementA *x2Addr,
        __gm__ ElementMxScaleA *x2ScaleAddr,
                                uint32_t tokenNum, uint32_t mmOutDim, uint32_t &startCoreIdx) {
        uint32_t quantLength = mmOutDim / 2;
        uint32_t quantPackedLen = MxActPackedLen<ElementA>(quantLength);
        uint32_t mxScaleNumPerToken = CeilDiv(CeilDiv(quantLength, 32), 2) * 2;
        AscendC::GlobalTensor<ElementC> gmSwigluOutTensor;
        gmSwigluOutTensor.SetGlobalBuffer(swigluOutAddr);
        AscendC::GlobalTensor<ElementA> gmX2;
        gmX2.SetGlobalBuffer(x2Addr);
        AscendC::GlobalTensor<uint8_t> gmX2MxScale;
        gmX2MxScale.SetGlobalBuffer(reinterpret_cast<__gm__ uint8_t *>(x2ScaleAddr));

        uint32_t startTokenIdx;
        if (aivIdx < startCoreIdx) {
            startTokenIdx = aivIdx + aivNum - startCoreIdx;
        } else {
            startTokenIdx = aivIdx - startCoreIdx;
        }

        uint32_t ubOffset = 0;
        AscendC::LocalTensor<ElementC> fp32TokenLocalTensor = resource.ubBuf.template
            GetBufferByByte<ElementC>(ubOffset);
        ubOffset += mmOutDim * sizeof(ElementC);
        AscendC::LocalTensor<XType> bf16TokenLocalTensor = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += mmOutDim * sizeof(XType);
        AscendC::LocalTensor<ElementA> fp8TokenLocalTensor = resource.ubBuf.template
            GetBufferByByte<ElementA>(ubOffset);
        ubOffset += quantPackedLen * sizeof(ElementA) + CEIL_UP(mxScaleNumPerToken * sizeof(ElementMxScaleA));
        AscendC::LocalTensor<uint8_t> mxScaleLocalTensor = fp8TokenLocalTensor[quantLength].template
            ReinterpretCast<uint8_t>();
        AscendC::LocalTensor<ElementC> tokenF32LT = resource.ubBuf.template GetBufferByByte<ElementC>(ubOffset);
        ubOffset += CEIL_UP(mxScaleNumPerToken * 2 * sizeof(float));
        AscendC::DataCopyExtParams mxScaleParams = {1U, static_cast<uint32_t>(mxScaleNumPerToken * sizeof(uint8_t)), 0U,
            0U, 0U};
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        for (uint32_t tokenIdx = startTokenIdx; tokenIdx < tokenNum; tokenIdx += aivNum) {
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
            AscendC::DataCopy(fp32TokenLocalTensor, gmSwigluOutTensor[tokenIdx * mmOutDim], mmOutDim);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::Mul(fp32TokenLocalTensor, fp32TokenLocalTensor, fp32TokenLocalTensor[quantLength], quantLength);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Cast(bf16TokenLocalTensor, fp32TokenLocalTensor, AscendC::RoundMode::CAST_RINT, quantLength);
            AscendC::PipeBarrier<PIPE_V>();
            QuantDynamicMx(fp8TokenLocalTensor, bf16TokenLocalTensor, tokenF32LT, quantLength, mxScaleNumPerToken);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
            AscendC::DataCopy(gmX2[tokenIdx * quantLength], fp8TokenLocalTensor, quantLength);

            AscendC::DataCopyPad(gmX2MxScale[tokenIdx * mxScaleNumPerToken], mxScaleLocalTensor, mxScaleParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        }
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        startCoreIdx = (startCoreIdx + tokenNum) % aivNum;
    }

    template <>
    CATLASS_DEVICE
    void operator()<AscendC::AIV>(Params const &params) {
        AscendC::SetCtrlSpr<60, 60>(0);
        AivInitParams(params);
        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            AivInitState();
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                shareQuantCoreFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmShareSmoothScales,
                                    (GM_ADDR)params.ptrShareA, (GM_ADDR)params.ptrShareMxScaleA);
            }
            expertIdsGMTensor_.SetGlobalBuffer((__gm__ int32_t *)params.gmExpertIds);
            SendCoreLayoutFunc(params.gmExpertIds, params.gmXActiveMask, params.gmEpSendCount,
                params.gmAllRankSendCount);
            if (isSendCore) {
                SendCoreDataFunc(params.gmX, params.gmExpandIdx, params.gmMoeSmoothScales, params.gmEpSendCount,
                    params.x1TokenOffset, params.x1ScaleOffset, params.x1FlagOffset);
            }
            if (isRecvCore) {
                RecvCoreFunc(params.gmEpSendCount, params.x1FlagOffset);
            }
        }

        uint32_t totalTokenNum = 0;

        uint32_t coreIdx = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
        uint32_t coreNum = AscendC::GetBlockNum();

        AscendC::GlobalTensor<ElementC> gmC;
        AscendC::GlobalTensor<ElementC> gmSwigluOutTensor;
        AscendC::GlobalTensor<ElementC> gmShareSwigluOutTensor;

        BlockEpilogue blockEpilogue(resource);
        uint32_t startCoreIdx = 0;
        uint32_t currentM = 0;
        uint32_t target = 1;

        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            currentM = axisBS;
            gmC.SetGlobalBuffer(params.ptrShareC);
            gmShareSwigluOutTensor.SetGlobalBuffer(params.gmShareSwigluOut);

            auto tensorC = tla::MakeTensor(gmC, params.layoutShareC, Arch::PositionGM{});
            auto tensorD = tla::MakeTensor(gmShareSwigluOutTensor, params.layoutShareC, Arch::PositionGM{});

            GemmCoord inGroupProblemShape{currentM, params.shareProblemShape.n(), params.shareProblemShape.k()};
            BlockScheduler matmulBlockScheduler(inGroupProblemShape, MakeCoord(L1_TILE_M, L1_TILE_N));
            uint32_t coreLoops = matmulBlockScheduler.GetCoreLoops();

            uint32_t startLoopIdx;
            if (coreIdx < startCoreIdx) {
                startLoopIdx = coreIdx + coreNum - startCoreIdx;
            } else {
                startLoopIdx = coreIdx - startCoreIdx;
            }

            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                GemmCoord blockCoord = matmulBlockScheduler.GetBlockCoord(loopIdx);
                GemmCoord actualBlockShape = matmulBlockScheduler.GetActualBlockShape(blockCoord);

                auto tensorBlockC = GetTile(tensorC,
                    tla::MakeCoord(blockCoord.m() * L1_TILE_M, blockCoord.n() * L1_TILE_N),
                    tla::MakeShape(actualBlockShape.m(), actualBlockShape.n()));

                auto tensorBlockD = GetTile(tensorD,
                    tla::MakeCoord(blockCoord.m() * L1_TILE_M, blockCoord.n() * L1_TILE_N),
                    tla::MakeShape(actualBlockShape.m(), actualBlockShape.n()));

                bool isLeft = (blockCoord.n() * L1_TILE_N < params.shareProblemShape.n() / 2);
                CheckSyncFlag(reinterpret_cast<__gm__ int32_t*>(statusDataSpaceGm +
                    IPCStateOffset::DispatchgGmm1::SOFT_SYNC_OFFSET), static_cast<int32_t>(compCoreIdx), target);
                target += 1;
                blockEpilogue(tensorBlockC, tensorBlockD, actualBlockShape, isLeft);
            }
            startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
        }
        {
            int64_t totalM = 0;
            uint32_t coreNumPerGroup = recvCoreNum;
            gmC.SetGlobalBuffer(params.ptrC);
            gmSwigluOutTensor.SetGlobalBuffer(params.gmSwigluOut);
            AscendC::GlobalTensor<ElementGroupList> groupList;
            groupList.SetGlobalBuffer(params.ptrGroupList);

            auto tensorC = tla::MakeTensor(gmC, params.layoutC, Arch::PositionGM{});
            auto tensorD = tla::MakeTensor(gmSwigluOutTensor, params.layoutC, Arch::PositionGM{});
            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;

            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                    groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)
                                                            (statusDataSpaceGm +
                                                                IPCStateOffset::DispatchgGmm1::GROUP_TOKEN_NUM_OFFSET) +
                                                            groupIdx * IPCStateOffset::DispatchgGmm1::GROUP_INFO_SIZE);
                    CheckSyncFlag(reinterpret_cast<__gm__ int32_t*>(statusDataSpaceGm +
                        IPCStateOffset::DispatchgGmm1::SOFT_SYNC_OFFSET), static_cast<int32_t>(compCoreIdx), target);
                    target += 1;
                    currentM = FlushAndGetValue<int32_t>(groupTokenNumStateTensor, GROUP_TOKEN_COUNT);
                } else {
                    currentM = groupList.GetValue(groupIdx);
                }
                totalTokenNum += currentM;
                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};
                BlockScheduler matmulBlockScheduler(inGroupProblemShape, MakeCoord(L1_TILE_M, L1_TILE_N));
                uint32_t coreLoops = matmulBlockScheduler.GetCoreLoops();

                uint32_t startLoopIdx;
                if (coreIdx < startCoreIdx) {
                    startLoopIdx = coreIdx + coreNum - startCoreIdx;
                } else {
                    startLoopIdx = coreIdx - startCoreIdx;
                }

                for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum) {
                    GemmCoord blockCoord = matmulBlockScheduler.GetBlockCoord(loopIdx);
                    GemmCoord actualBlockShape = matmulBlockScheduler.GetActualBlockShape(blockCoord);

                    auto tensorBlockC = GetTile(tensorC,
                        tla::MakeCoord(totalM + blockCoord.m() * L1_TILE_M, blockCoord.n() * L1_TILE_N),
                        tla::MakeShape(actualBlockShape.m(), actualBlockShape.n()));

                    auto tensorBlockD = GetTile(tensorD,
                        tla::MakeCoord(totalM + blockCoord.m() * L1_TILE_M, blockCoord.n() * L1_TILE_N),
                        tla::MakeShape(actualBlockShape.m(), actualBlockShape.n()));

                    bool isLeft = (blockCoord.n() * L1_TILE_N < params.problemShape.n() / 2);
                    CheckSyncFlag(reinterpret_cast<__gm__ int32_t*>(statusDataSpaceGm +
                        IPCStateOffset::DispatchgGmm1::SOFT_SYNC_OFFSET), static_cast<int32_t>(compCoreIdx), target);
                    target += 1;
                    blockEpilogue(tensorBlockC, tensorBlockD, actualBlockShape, isLeft);
                }

                totalM += inGroupProblemShape.m();

                startCoreIdx = (startCoreIdx + coreLoops) % coreNum;
            }
            AscendC::PipeBarrier<PIPE_ALL>();
        }
        icache_preload(8);
        AscendC::SyncAll<false>();
        AscendC::PipeBarrier<PIPE_ALL>();

        UpdateAndCleanInfo(params.ptrGroupList, params.gmEpSendCount, params.gmExpertTokenNums);
        AscendC::PipeBarrier<PIPE_ALL>();
        startCoreIdx = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            PostSwigluDynamicQuant(params.gmShareSwigluOut, params.ptrShareX2, params.gmShareX2Scale,
                                   axisBS, params.shareProblemShape.n(), startCoreIdx);
        }
        {
            PostSwigluDynamicQuant(params.gmSwigluOut, params.ptrX2, params.gmX2Scale,
                                   totalTokenNum, params.problemShape.n(), startCoreIdx);
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

        __gm__ int32_t *flagAddr;
        int32_t idx;
    };

    AicSetFunc aicSetFunc;
    Arch::Resource<ArchTag> resource;

    AscendC::LocalTensor<int32_t> expertIdsTensor_;
    uint32_t startTokenId_{0};
    uint32_t endTokenId_{0};
    uint32_t localTokenNum_{0};
    uint32_t roundSize{0};
    uint32_t num_rounds{0};
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
    bool useFullExpertIdsCopy_{false};  // Whether to copy expertIds in full

    // token info
    uint32_t hOutSize{0};
    uint32_t scaleParamPad{0};
    uint32_t scaleSize{0};
    uint32_t hCommuSize{0};
    uint32_t axisHCommu{0};
    uint32_t axisBS{0};
    uint32_t activeMaskBsCnt{0};
    uint32_t axisK{0};
    uint32_t totalTokenCount{0};
    uint32_t expertIdsCnt{0};
    uint32_t tokenLength{0};
    uint32_t mxActPackedLen_{0};
    uint32_t x1MxScaleNum{0};
    uint32_t x2MxScaleNum{0};

    // state info
    int32_t tokenFlag{0};    // token flag
    int32_t vToCFlag{0};     // cv flag, decided by cvDataState
    int32_t dataState{0};    // data space state
    int32_t cvDataState{0};  // cv flag state
    int32_t state{0};        // count flag state
    int32_t magicVal_{0};    // magic value for SHMEM sync
    float exp_flag_{0.0f};   // Magic value as float for range compare
    float sumTarget{0.0};
    float tokenFlagSumTarget{0.0};

    // memory info
    __gm__ Mc2Kernel::HcclOpParam *winContext_;
    GM_ADDR statusDataSpaceGm;
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

    AscendC::GlobalTensor<int32_t> expertIdsGMTensor_;

    AscendC::LocalTensor<bool> maskInputTensor;
    AscendC::LocalTensor<int8_t> maskInputInt8Tensor;
    AscendC::LocalTensor<half> maskTmpTensor;
    AscendC::LocalTensor<half> sumOutTensor;
    AscendC::LocalTensor<uint8_t> sharedTmpBuffer;

    AscendC::LocalTensor<int32_t> dstExpIdTensor_;
    AscendC::LocalTensor<float> dstExpIdFp32Tensor_;

    AscendC::LocalTensor<float> xFp32TmpTensor;
    AscendC::LocalTensor<ElementC> tokenF32LT;
    AscendC::LocalTensor<int32_t> yInt32Tensor;

    AscendC::LocalTensor<int32_t> expertCountTensor;

    AscendC::LocalTensor<XType> xInTensor[BUFFER_NUM];
    AscendC::LocalTensor<ElementA> yInt8Tensor[BUFFER_NUM];
    AscendC::LocalTensor<ElementMxScaleA> yScaleTensor[BUFFER_NUM];
    AscendC::LocalTensor<float> moeSmoothScaleTensor[BUFFER_NUM];
    AscendC::LocalTensor<float> shareSmoothScaleTensor;

    AscendC::LocalTensor<int32_t> roundExpertIds;

    AscendC::LocalTensor<int32_t> statusTensor_;
    AscendC::LocalTensor<float> statusFp32Tensor_;
    AscendC::LocalTensor<float> gatherMaskOutTensor;
    AscendC::LocalTensor<int32_t> gatherMaskOutCountTensor;
    AscendC::LocalTensor<float> statusSumOutTensor;
    AscendC::LocalTensor<uint8_t> sumTmpTensor;
    AscendC::LocalTensor<ElementA> xTmpTensor_;
    AscendC::LocalTensor<uint32_t> gatherTmpTensor;
    AscendC::LocalTensor<int32_t> tmpLocalTensor;
    AscendC::LocalTensor<int32_t> sendCountsLocalTensor;
    AscendC::LocalTensor<float> tokenFlagLocalTensor;
    AscendC::LocalTensor<float> tokenFlagSumLocalTensor;
    AscendC::LocalTensor<float> reduceSumWorkLocalTensor;
};

#endif // (defined(CATLASS_ARCH) && CATLASS_ARCH == 3510)

} // namespace Catlass::Gemm::Kernel

#endif // CATLASS_GEMM_KERNEL_DISPATCH_MX_GMM1_SWIGLU_H
