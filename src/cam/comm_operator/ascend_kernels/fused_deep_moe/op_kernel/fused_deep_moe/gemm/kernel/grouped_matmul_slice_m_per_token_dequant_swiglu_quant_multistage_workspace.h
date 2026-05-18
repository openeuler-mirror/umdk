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

#include "post_swiglu_dynamic_quant.h"
#include "../../../fused_deep_moe_base.h"
#include "../../fused_deep_moe_utils.h"

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
constexpr int64_t LOOP_TMP_SIZE = 4096;
constexpr int32_t SUB_AIV_NUM = 2;
constexpr int32_t ODD_EVEN_BASE = 2;
constexpr int32_t BUFFER_NUM = 2;
constexpr int32_t GATHER_SECOND_NUM = 2;
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
    using ElementGroupList = ElementGroupList_;

    using XType = ExpandXType;

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
        GM_ADDR gmReserved;
        GM_ADDR gmExpertTokenNums;

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
               GM_ADDR gmExpandIdx_, GM_ADDR gmEpSendCount_, GM_ADDR gmXActiveMask_, GM_ADDR gmReserved_,
               GM_ADDR gmExpertTokenNums_, GM_ADDR gmShareX1_, GM_ADDR gmShareX1Scale_, GM_ADDR gmShareSwigluOut_,
               GM_ADDR gmShareX2_, LayoutOutput const &layoutShareOutput_, GM_ADDR gmShareX2Scale_,
               GM_ADDR gmSwigluOut_, const FusedDeepMoeInfo &fusedDeepMoeInfo)
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
              gmReserved(gmReserved_),
              gmShareX1(gmShareX1_),
              gmShareX1Scale(gmShareX1Scale_),
              gmShareSwigluOut(gmShareSwigluOut_),
              gmShareX2(gmShareX2_),
              layoutShareOutput(layoutShareOutput_),
              gmShareX2Scale(gmShareX2Scale_),
              gmSwigluOut(gmSwigluOut_),
              epRankSize(fusedDeepMoeInfo.epRankSize),
              epRankId(fusedDeepMoeInfo.epRankId),
              moeExpertNum(fusedDeepMoeInfo.moeExpertNum),
              moeExpertNumPerRank(fusedDeepMoeInfo.moeExpertNumPerRank),
              quantMode(fusedDeepMoeInfo.quantMode),
              globalBs(fusedDeepMoeInfo.globalBs),
              bs(fusedDeepMoeInfo.bs),
              topK(fusedDeepMoeInfo.k),
              tokenLen(fusedDeepMoeInfo.h),
              shareN(fusedDeepMoeInfo.shareGmm1HLen)
        {}
    };

    // Methods
    CATLASS_DEVICE
    GroupedMatmulSliceMPerTokenDequantSwigluQuantMultiStageWorkspace()
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
        winContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<AscendC::HCCL_GROUP_ID_0>();
        statusDataSpaceGm = (GM_ADDR)(winContext_->localWindowsExp);
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
            shareQuantCoreNum = recvCoreNum;
        }

        AscendC::GlobalTensor<int32_t> selfDataStatusTensor;
        selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
        if ASCEND_IS_AIC {
            aicStateGlobalCoreIdx = aivNum + aicIdx;
            cvDataState = FlushAndSpinValue<int32_t>(selfDataStatusTensor, aicStateGlobalCoreIdx * UB_ALIGN);
            vToCFlag = (cvDataState == 0) ? V_TO_C_FLAG_1 : V_TO_C_FLAG_2;
        }
        if ASCEND_IS_AIV {
            isRecvCore = ((aivIdx % ODD_EVEN_BASE) == 0);
            recvCoreIdx = aiCoreGroupIdx;
            isSendCore = ((aivIdx % ODD_EVEN_BASE) == 1);
            sendCoreIdx = aiCoreGroupIdx;
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                isShareQuantCore = isRecvCore;
                shareQuantCoreIdx = recvCoreIdx;
            }
            aivStateGlobalCoreIdx = aivNum + aicNum + aivIdx;

            dataState = FlushAndSpinValue<int32_t>(selfDataStatusTensor, aivIdx * UB_ALIGN);
            cvDataState = FlushAndSpinValue<int32_t>(selfDataStatusTensor, aivStateGlobalCoreIdx * UB_ALIGN);
            vToCFlag = (cvDataState == 0) ? V_TO_C_FLAG_1 : V_TO_C_FLAG_2;
        }
    }

    template <int32_t CORE_TYPE = g_coreType>
    CATLASS_DEVICE void operator()(Params const &params);

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

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIC>(Params const &params)
    {
        moeExpertNumPerRank = params.moeExpertNumPerRank;
        localExpertNum = moeExpertNumPerRank;
        uint32_t coreNumPerGroup = recvCoreNum;

        BlockScheduler blockScheduler;
        BlockMmad blockMmad(resource);

        // Represent the full gm
        AscendC::GlobalTensor<ElementA> gmA;
        AscendC::GlobalTensor<ElementB> gmB;
        AscendC::GlobalTensor<ElementC> gmC;
        AscendC::ListTensorDesc gmBlistTensorDesc(reinterpret_cast<__gm__ void *>(params.ptrB));
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(params.ptrWorkspace));
        AscendC::GlobalTensor<ElementGroupList> groupList;
        groupList.SetGlobalBuffer(params.ptrGroupList);

        uint32_t currentM = 0;
        uint32_t startCoreIdx = 0;
        aicSetFunc = {statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(AscendC::GetBlockIdx())};
        int64_t gmGroupOffsetC = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            gmA.SetGlobalBuffer((__gm__ ElementA*)params.gmShareX1);
            gmB.SetGlobalBuffer((__gm__ ElementB*)params.ptrShareB);
            gmB.SetL2CacheHint(AscendC::CacheMode::CACHE_MODE_DISABLE);
            currentM = params.bs;
            GemmCoord inGroupProblemShape{currentM, params.shareN, params.problemShape.k()};
            LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
            LayoutB layoutB = params.layoutShareB;
            LayoutC layoutC = {currentM, params.shareN};
            blockScheduler.Update(inGroupProblemShape, MakeCoord(L1TileShape::M, L1TileShape::N));
            uint32_t coreLoops = blockScheduler.GetCoreLoops();
            // Determine the starting loopIdx of the current core under the current groupIdx
            uint32_t startLoopIdx = ((aicIdx < startCoreIdx) ? (aicIdx + aicNum) : aicIdx) - startCoreIdx;

            if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                // wait AIV quantize needed tokens
                AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
                uint32_t waitFlagCount = params.bs < shareQuantCoreNum ? params.bs : shareQuantCoreNum;
                shareQuantTokenStateTensor.SetGlobalBuffer((__gm__ int32_t*)(
                    statusDataSpaceGm + SHARE_QUANT_SOFT_SYNC_OFFSET));
                uint32_t expected = waitFlagCount * vToCFlag;
                WaitGroupTokenNumReady(shareQuantTokenStateTensor, expected);
            }
            // Loop through the matmul of each groupIdx
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aicNum) {
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
                    blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB, gmC[gmOffsetC],
                        layoutC, actualBlockShape, callbackBeforeFixpipe, callbackAfterFixpipe);
                } else {
                    callbackBeforeFixpipe();
                    blockMmad(gmA[gmOffsetA], layoutA, gmB[gmOffsetB], layoutB,
                                gmC[gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }
            }
            startCoreIdx = (startCoreIdx + coreLoops) % aicNum;
            gmGroupOffsetC += currentM * params.shareN;
        }

        gmA.SetGlobalBuffer(params.ptrA);
        if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
            gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(gmBlistTensorDesc.GetDataPtr<int32_t>(0)));
        }
        AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
        int64_t gmGroupOffsetA = 0;
        int64_t gmGroupOffsetB = 0;
        for (uint32_t groupIdx = 0; groupIdx < localExpertNum; ++groupIdx) {
            if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(
                        gmBlistTensorDesc.GetDataPtr<int32_t>(groupIdx)));
            }
            if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(
                    statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET) + groupIdx * GROUP_INFO_SIZE);
                // wait AIV recv needed tokens
                uint32_t expected = coreNumPerGroup * vToCFlag;
                WaitGroupTokenNumReady(groupTokenNumStateTensor, expected);
                currentM = groupTokenNumStateTensor.GetValue(GROUP_TOKEN_COUNT);
            } else {
                currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                                : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
            }
            GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

            LayoutA layoutA = params.layoutA.GetTileLayout(inGroupProblemShape.GetCoordMK());
            LayoutB layoutB = params.layoutB;
            LayoutC layoutC = {currentM, params.problemShape.n()};

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
                    callbackBeforeFixpipe();
                    blockMmad(gmA[gmGroupOffsetA + gmOffsetA], layoutA, gmB[gmGroupOffsetB + gmOffsetB], layoutB,
                              gmC[gmGroupOffsetC + gmOffsetC], layoutC, actualBlockShape);
                    callbackAfterFixpipe();
                }
            }

            gmGroupOffsetA += inGroupProblemShape.m() * inGroupProblemShape.k();
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmGroupOffsetB += inGroupProblemShape.k() * inGroupProblemShape.n();
            }
            gmGroupOffsetC += inGroupProblemShape.m() * inGroupProblemShape.n();

            startCoreIdx = (startCoreIdx + coreLoops) % aicNum;
        }

        if constexpr (BlockMmad::DispatchPolicy::ASYNC) {
            blockMmad.SynchronizeBlock();
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
            CalExpandxIdx(dstExpertId, expertIdsCnt, curExpertCnt, ubOffset);
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
        uint32_t sendTokenNum = expertIdsCnt / sendToMoeAivNum;
        uint32_t remainderTokenNum = expertIdsCnt % sendToMoeAivNum;
        uint32_t startTokenId = sendTokenNum * sendCoreIdx;
        if (sendCoreIdx < remainderTokenNum) {
            sendTokenNum += 1;
            startTokenId += sendCoreIdx;
        } else {
            startTokenId += remainderTokenNum;
        }
        uint32_t endTokenId = startTokenId + sendTokenNum;
        if (startTokenId >= expertIdsCnt) {
            return;
        }
        AscendC::LocalTensor<int32_t> expertCountTensor = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        ubOffset += CEIL_UP(expertIdsCnt * sizeof(int32_t));
        AscendC::Duplicate(expertCountTensor, (int32_t)0, expertIdsCnt);
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
            for (uint32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
                int32_t dstExpertId = expertIdsTensor_(tokenIndex);
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
                CalExpandxIdx(dstExpertId, tokenIndex, curExpertCnt, ubOffset);
                expertCountTensor(tokenIndex - startTokenId) = curExpertCnt;
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
        expandIdxGMTensor.SetGlobalBuffer((__gm__ int32_t *)gmExpandIdx + startTokenId);
        AscendC::DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(sendTokenNum * sizeof(uint32_t)),
                                                         0U, 0U, 0U};
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::DataCopyPad(expandIdxGMTensor, expertCountTensor, expertIdsCntParams);
    }

    CATLASS_DEVICE void
    SendCoreFunc(GM_ADDR gmX, GM_ADDR gmExpertIds, GM_ADDR gmMoeSmoothScales, GM_ADDR gmX1, GM_ADDR gmX1Scale,
                 GM_ADDR gmExpandIdx, GM_ADDR gmXActiveMask)
    {
        ubOffset = 0;
        if constexpr (EXEC_FLAG & EXEC_FLAG_X_ACTIVE_MASK) {
            TokenActiveMaskCal(gmXActiveMask, ubOffset);
        }
        expertIdsCnt = activeMaskBsCnt * axisK;

        AscendC::GlobalTensor<int32_t> expertIdsGMTensor_;
        expertIdsGMTensor_.SetGlobalBuffer((__gm__ int32_t *)gmExpertIds);
        expertIdsTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        ubOffset += CEIL_UP(expertIdsCnt * sizeof(int32_t));

        AscendC::DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(expertIdsCnt * sizeof(uint32_t)),
                                                         0U, 0U, 0U};
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(expertIdsTensor_, expertIdsGMTensor_, expertIdsCntParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);

        CalAndSendTokenCount();
        AscendC::PipeBarrier<PIPE_ALL>();
        sendToMoeAivNum = sendCoreNum;
        AscendC::SetDeqScale((half)1.000000e+00f);
        SendToMoeExprt(gmX, gmExpandIdx, gmMoeSmoothScales);
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
        AscendC::GlobalTensor<XType> srcXGMTensor;
        srcXGMTensor.SetGlobalBuffer((__gm__ XType*)gmX);
        AscendC::GlobalTensor<int8_t> dstXInt8GMTensor;
        dstXInt8GMTensor.SetGlobalBuffer((__gm__ int8_t*)gmShareX1Token);
        AscendC::GlobalTensor<float> dstXScaleGMTensor;
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
        // double buffer
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1);
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
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(1);

        // Set GM to info AIC
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
        // Atomic add
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
                        SetValueAndFlush<int32_t>(tokGlobalInt32, 1, 0);
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
                __gm__ float *gmShareSwigluOutput, __gm__ float *gmSwigluOutput, __gm__ ElementGroupList *gmGroupList,
                uint32_t shareN, uint32_t n, uint32_t k, LayoutScale layoutShareScale, LayoutScale layoutScale,
                LayoutPerTokenScale wholeLayoutPerTokenScale)
    {
        uint32_t coreNumPerGroup = recvCoreNum;
        int64_t gmGroupOffsetC = 0;
        int64_t gmGroupOffsetScale = 0;
        int64_t gmGroupOffsetPerTokenScale = 0;
        int64_t gmGroupOffsetD = 0;

        {
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource);

            uint32_t target = 1;
            uint32_t currentM = 0;
            uint32_t startCoreIdx = 0;
            AscendC::ListTensorDesc gmScaleListTensor;
            AscendC::GlobalTensor<ElementGroupList> groupList;
            groupList.SetGlobalBuffer(gmGroupList);
            AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                currentM = axisBS;
                GemmCoord inGroupProblemShape{currentM, shareN, k};
                layout::RowMajor layoutC = {currentM, shareN};
                LayoutPerTokenScale layoutPerTokenScale =
                    wholeLayoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = layout::RowMajor{currentM, shareN};

                EpilogueParams epilogueParams{
                    reinterpret_cast<__gm__ ElementC *>(gmCVSwapBuff) + gmGroupOffsetC,
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
                    CheckSyncFlag(statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(compCoreIdx), target);
                    target += 1;
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK);
                }
                startCoreIdx = (startCoreIdx + coreLoops) % aiCoreGroupNum;
                gmGroupOffsetC += currentM * shareN;
            }
            gmScaleListTensor = AscendC::ListTensorDesc(reinterpret_cast<__gm__ void *>(gmScale));
            __gm__ ElementScale* gmScalePtr;
            if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(gmScaleListTensor.GetDataPtr<int32_t>(0));
            }
            for (uint32_t groupIdx = 0; groupIdx < localExpertNum; ++groupIdx) {
                if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                    // just like AIC
                    groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)
                                                            (statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET) +
                                                            groupIdx * GROUP_INFO_SIZE);
                    uint32_t expected = coreNumPerGroup * vToCFlag;
                    WaitGroupTokenNumReady(groupTokenNumStateTensor, expected);
                    currentM = groupTokenNumStateTensor.GetValue(GROUP_TOKEN_COUNT);
                } else {
                    currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                                : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
                }
                GemmCoord inGroupProblemShape{currentM, n, k};
                LayoutPerTokenScale layoutPerTokenScale =
                    wholeLayoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = layout::RowMajor{currentM, n};
                EpilogueParams epilogueParams;
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                                                reinterpret_cast<__gm__ ElementC *>(gmCVSwapBuff) + gmGroupOffsetC,
                                                gmScalePtr, layoutScale,
                                                gmTokenScale + gmGroupOffsetPerTokenScale, layoutPerTokenScale,
                                                gmSwigluOutput + gmGroupOffsetD, layoutD};
                } else {
                    epilogueParams = EpilogueParams{
                                                reinterpret_cast<__gm__ ElementC *>(gmCVSwapBuff) + gmGroupOffsetC,
                                                gmScalePtr + gmGroupOffsetScale,
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
                    CheckSyncFlag(statusDataSpaceGm + SOFT_SYNC_OFFSET, static_cast<uint8_t>(compCoreIdx), target);
                    target += 1;
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK);
                }

                gmGroupOffsetC += currentM * n;
                if constexpr (!(EXEC_FLAG & EXEC_FLAG_TENSOR_LIST)) {
                    gmGroupOffsetScale += inGroupProblemShape.n();
                }
                gmGroupOffsetPerTokenScale += inGroupProblemShape.m();
                gmGroupOffsetD += currentM * n;

                startCoreIdx = (startCoreIdx + coreLoops) % aiCoreGroupNum;
            }
        }
        AscendC::PipeBarrier<PIPE_ALL>();
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
    }

    CATLASS_DEVICE
    void AivInitState()
    {
        // state of data sapce
        winDataSizeOffset = dataState * epRankSize * expertPerSizeOnWin * moeExpertNumPerRank;
        GM_ADDR statusSpaceGm_ = GetWindStateAddrByRankId(epRankId);
        AscendC::GlobalTensor<int32_t> selfStatusTensor;
        selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusSpaceGm_ + SELF_STATE_OFFSET));
        state = FlushAndGetValue<int32_t>(selfStatusTensor, aivIdx * UB_ALIGN);
        sumTarget = state == 0 ? 1.0f : 0.0f;
        tokenFlag = state == 0 ? TOKEN_FLAG_1 : TOKEN_FLAG_2;
        if (state == 0) {
            SetValueAndFlush<int32_t>(selfStatusTensor, aivIdx * UB_ALIGN, 0x3F800000);
        } else {
            SetValueAndFlush<int32_t>(selfStatusTensor, aivIdx * UB_ALIGN, 0);
        }
    }

    CATLASS_DEVICE
    void UpdateAndCleanInfo(__gm__ ElementGroupList_ *ptrGroupList, GM_ADDR gmEpSendCount, GM_ADDR gmExpertTokenNums)
    {
        if (isCompCore && AscendC::GetSubBlockIdx() == 0) {
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer((__gm__ int32_t*)(statusDataSpaceGm + SOFT_SYNC_OFFSET));
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
                uint32_t tokenNum = FlushAndGetValue<int32_t>(sendCountsGlobal,
                    localMoeIndex * epRankSize + epRankSize - 1);
                SetValueAndFlush<int64_t>(expertTokenNumsOutGMTensor_, localMoeIndex, tokenNum);
                uint32_t nonCumSumTokenNum = tokenNum - tmpTokenNum;
                SetValueAndFlush<int64_t>(nonCumSumExpertTokenNumsTensor, localMoeIndex, nonCumSumTokenNum);
                tmpTokenNum = tokenNum;
            }
        }
    }

    template <>
    CATLASS_DEVICE void operator()<AscendC::AIV>(Params const &params)
    {
        AivInitParams(params);
        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            AivInitState();
            if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
                if (isShareQuantCore) {
                    shareQuantCoreFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmShareSmoothScales,
                                        (GM_ADDR)params.gmShareX1, (GM_ADDR)params.gmShareX1Scale);
                }
            }
            if (isSendCore) {
                SendCoreFunc((GM_ADDR)params.gmX, (GM_ADDR)params.gmexpertIds, (GM_ADDR)params.gmMoeSmoothScales,
                            (GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale, (GM_ADDR)params.gmExpandIdx,
                            (GM_ADDR)params.gmXActiveMask);
            }
            if (isRecvCore) {
                RecvCoreFunc((GM_ADDR)params.ptrA, (GM_ADDR)params.ptrPerTokenScale, (GM_ADDR)params.gmEpSendCount);
            }
        }

        auto gmSwigluOutput = reinterpret_cast<__gm__ float *>(params.gmSwigluOut);
        auto gmShareSwigluOutput = reinterpret_cast<__gm__ float *>(params.gmShareSwigluOut);

        if (isCompCore) {
            CompCoreFunc(params.ptrWorkspace, params.ptrShareScale,  params.ptrScale,
                (__gm__ float*)params.gmShareX1Scale, (__gm__ float*)params.ptrPerTokenScale,
                gmShareSwigluOutput, gmSwigluOutput, params.ptrGroupList, params.shareN, params.problemShape.n(),
                params.problemShape.k(), params.layoutShareScale, params.layoutScale, params.layoutPerTokenScale);
        }

        icache_preload(8);
        AscendC::SyncAll<false>();
        AscendC::PipeBarrier<PIPE_ALL>();

        UpdateAndCleanInfo(params.ptrGroupList, params.gmEpSendCount, params.gmExpertTokenNums);
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
            uint32_t startLoopIdx = ((aiCoreGroupIdx < startCoreIdx) ?
                (aiCoreGroupIdx + aiCoreGroupNum) : aiCoreGroupIdx) - startCoreIdx;
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
            sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(params.gmEpSendCount));
            totalTokenCount = FlushAndGetValue<int32_t>(sendCountsGlobal, localExpertNum * epRankSize - 1);
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
            uint32_t startLoopIdx = ((aiCoreGroupIdx < startCoreIdx) ?
                (aiCoreGroupIdx + aiCoreGroupNum) : aiCoreGroupIdx) - startCoreIdx;
            for (uint32_t loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += aiCoreGroupNum) {
                auto blockCoord = quantSwizzle.GetTileCoord(loopIdx);
                auto actualBlockShape = quantSwizzle.GetActualTileShape(blockCoord);
                blockQuant(quantBlockShape, blockCoord, actualBlockShape);
            }
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
    Arch::Resource<ArchTag> resource;

    AscendC::LocalTensor<int32_t> expertIdsTensor_;
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

    // state info
    int32_t tokenFlag{0};    // token flag
    int32_t vToCFlag{0};     // cv flag, decided by cvDataState
    int32_t dataState{0};    // data space state
    int32_t cvDataState{0};  // cv flag state
    int32_t state{0};        // count flag state
    float sumTarget{0.0};

    // memory info
    __gm__ HcclOpResParam *winContext_;
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
};

}  // namespace Catlass::Gemm::Kernel

