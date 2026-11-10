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
// Physical experts that still fit a full-size state slot; past this the slot halves so the
// whole expert roster keeps its place in the window state area.
constexpr uint32_t MAX_EXPERTS_FULL_STATE_SLOT = 512;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint64_t GROUP_TOKEN_NUM_OFFSET = 932 * 1024;
constexpr uint64_t SOFT_SYNC_OFFSET = 964 * 1024;
constexpr uint64_t SHARE_QUANT_SOFT_SYNC_OFFSET = 988 * 1024;
constexpr uint32_t SELF_STATE_OFFSET = 256 * 1024;
constexpr uint32_t SUM_TMP_TENSOR_SIZE = 1024;
constexpr uint32_t UB_ALIGN = 32;
// Scratch for moving a state word through the DMA engine in the kernel prologue, before anything
// else has claimed UB.
constexpr int64_t STATE_SLOT_DMA_READ_UB_OFFSET = 0;
constexpr int64_t STATE_SLOT_DMA_WRITE_UB_OFFSET = 32;
// A cube core has no UB, so its state word cannot travel by DMA and keeps the scalar
// clean-and-invalidate path. It buys isolation with address space instead: one whole cache line each.
// At the old 128B stride four cubes shared a line, so every access dragged the neighbours' words in
// and pushed them back out. This block sits past both AIV regions, which end at index 120 (15360B),
// and 24 x 512B still fits inside the 32KB before GROUP_TOKEN_NUM_OFFSET.
constexpr uint32_t AIC_STATE_SLOT_INTS = 512 / sizeof(int32_t);
constexpr uint32_t AIC_STATE_BASE_INTS = 15360 / sizeof(int32_t);
constexpr uint32_t TOKEN_EXTRA_SPACE = 512;
// A token travels in fixed 512B blocks, each holding 480B of payload and a 32B data-as-flag tail.
// The tail is pre-filled once and never overwritten, so a block's flag becomes visible exactly when
// that block's payload does: the flag rides in the same 512B transfer unit, it is not a separate
// store afterwards. That is what lets the sender publish with a single DataCopy instead of a token
// copy followed by a barrier and a scale/flag copy.
constexpr uint32_t SPLIT_BLOCK_SIZE = 512;
constexpr uint32_t SPLIT_BLOCK_DATA_SIZE = 480;
constexpr uint32_t SPLIT_BLOCK_FLAG_BYTES = SPLIT_BLOCK_SIZE - SPLIT_BLOCK_DATA_SIZE;  // 32
constexpr uint32_t SPLIT_BLOCK_DATA_INTS = SPLIT_BLOCK_DATA_SIZE / sizeof(int32_t);    // 120
constexpr uint32_t SPLIT_BLOCK_SIZE_INTS = SPLIT_BLOCK_SIZE / sizeof(int32_t);        // 128
// The flag vector copy handles 256B (64 int32) per repeat, so a 480B payload takes two passes.
constexpr uint32_t SPLIT_COPY_HEAD_INTS = 64;
constexpr uint32_t SPLIT_COPY_TAIL_INTS = SPLIT_BLOCK_DATA_INTS - SPLIT_COPY_HEAD_INTS;  // 56
constexpr uint32_t INT32_COUNT_PER_BLOCK = 8;
// Per-expert receive records published into the reserved workspace. Magic, the expert total and the
// running prefix over source ranks live at fixed words inside a 512B line; the prefix run starts at
// index 8 so a vector load of it is 32B aligned.
constexpr uint64_t RECV_PREFIX_OFFSET = 4096;
constexpr uint32_t RECV_PREFIX_GROUP_STRIDE = 512;
constexpr uint32_t RECV_PREFIX_GROUP_INTS = RECV_PREFIX_GROUP_STRIDE / sizeof(int32_t);
constexpr uint32_t RECV_PREFIX_MAX_GROUPS = 16;
constexpr uint32_t RECV_PREFIX_MAGIC = 0x52454356;     // 'RECV'
constexpr uint32_t RECV_PREFIX_MAGIC_INDEX = 0;
constexpr uint32_t RECV_PREFIX_TOTAL_INDEX = 1;
constexpr uint32_t RECV_PREFIX_DATA_INDEX = 8;
// One ready flag per (expert, receive core) instead of one per expert. With a single shared word all
// receive cores polled the same 32B address, and the last core to observe it paid for the whole
// queue -- that queue is what the microsecond-long first prefix-wait was measuring. The flags keep
// their own region (cleared every launch, so a stale value can never read as ready) and only ever
// travel by DMA. RECV_REPLICATE_MAX_CORES bounds the receive-core count for the GM layout only; the
// record width itself is derived from epRankSize at run time.
constexpr uint32_t RECV_REPLICATE_MAX_CORES = 32;
// One flag per (expert, receive core), each on its own 512B line. At a 32B stride all the waiters
// still packed into two lines, so their polls contended in L2 even though each nominally owned a
// word of its own.
constexpr uint32_t RECV_PERFLAG_CORE_INTS = 512 / sizeof(int32_t);   // one full line per core
constexpr uint32_t RECV_PERFLAG_GROUP_INTS = RECV_REPLICATE_MAX_CORES * RECV_PERFLAG_CORE_INTS;
constexpr uint64_t RECV_PREFIX_FLAG_BASE =
    RECV_PREFIX_OFFSET + RECV_PREFIX_MAX_GROUPS * RECV_PREFIX_GROUP_STRIDE;
constexpr uint32_t RECV_PREFIX_FLAG_INDEX = 0;
constexpr uint64_t RECV_PREFIX_COPY_BASE =
    RECV_PREFIX_FLAG_BASE +
    static_cast<uint64_t>(RECV_PREFIX_MAX_GROUPS) * RECV_PERFLAG_GROUP_INTS * sizeof(int32_t);
// Record copies are touched only by DMA, so they no longer need a line each: the stride is just the
// widest record rounded to a DMA block, which leaves room for the per-core flag lines.
constexpr uint32_t RECV_PREFIX_COPY_STRIDE = 288;   // (8 header + 64 ranks) * 4B, EP64 worst case
constexpr uint32_t RECV_PREFIX_COPY_INTS =
    RECV_PREFIX_MAX_GROUPS * RECV_REPLICATE_MAX_CORES * (RECV_PREFIX_COPY_STRIDE / sizeof(int32_t));
constexpr uint32_t RECV_FLAG_BLOCK_INTS = 8;           // 32B / sizeof(int32_t)
constexpr int64_t RECV_FLAG_READ_OFFSET = 128;         // past the 128B record line in scratch
constexpr uint32_t RECV_FLAG_STAGE_BYTES = RECV_REPLICATE_MAX_CORES * 512;  // line per core staged
// Scratch for the vector arrival check. It sits near the top of UB, above everything RecvCoreFunc and
// RecvToken lay out, so it cannot collide with the per-stage buffers below it.
constexpr int64_t RECV_ARRIVE_GATHER_OFFSET = 176 * 1024;
constexpr int64_t RECV_ARRIVE_TMP_OFFSET = RECV_ARRIVE_GATHER_OFFSET + 512;
constexpr int64_t RECV_ARRIVE_SUM_OFFSET = RECV_ARRIVE_TMP_OFFSET + 512;
constexpr int64_t RECV_ARRIVE_TARGET_OFFSET = RECV_ARRIVE_SUM_OFFSET + 512;
constexpr int64_t RECV_ARRIVE_TSRC_OFFSET = RECV_ARRIVE_TARGET_OFFSET + 512;
// Scratch for the vector prefix scan and the pattern tensor that pulls it back out of the
// block-strided layout.
constexpr int64_t RECV_PREFIX_SCAN_OFFSET = RECV_ARRIVE_TSRC_OFFSET + 512;   // 2KB, EP64 worst case
constexpr int64_t RECV_PREFIX_DENSE_OFFSET = RECV_PREFIX_SCAN_OFFSET + 2048;  // 256B
constexpr int64_t RECV_PREFIX_PATTERN_OFFSET = RECV_PREFIX_DENSE_OFFSET + 256;  // 32B
constexpr int64_t LOOP_TMP_SIZE = 4096;
constexpr int32_t SUB_AIV_NUM = 2;
constexpr int32_t ODD_EVEN_BASE = 2;
constexpr int32_t BUFFER_NUM = 2;
constexpr int32_t GATHER_SECOND_NUM = 2;
constexpr int32_t MAX_OUT_BUFFER_NUM = 8;
constexpr int32_t UB_SIZE = 184 * 1024;
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
    // Move a core's persistent state word through the DMA engine instead of scalar load/store.
    // The scalar path cleans and invalidates a whole 512B line per access. The slots are 128B
    // apart, so four cores share a line and take turns invalidating each other: every access pays
    // a full-line writeback plus a full-line refill, and the order depends on scheduling. DMA never
    // reads or dirties the core's cache, so the cores stop interfering with each other. The word
    // stays private to this core for the whole launch, so no other core can observe a transfer in
    // flight.
    CATLASS_DEVICE
    int32_t LoadStateSlotByDma(AscendC::GlobalTensor<int32_t> &stateTensor, uint64_t index)
    {
        auto readBuf = resource.ubBuf.template GetBufferByByte<int32_t>(STATE_SLOT_DMA_READ_UB_OFFSET);
        AscendC::DataCopyParams oneBlock{1U, 1U, 0U, 0U};
        AscendC::DataCopy(readBuf, stateTensor[index], oneBlock);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
        return readBuf.GetValue(0);
    }

    CATLASS_DEVICE
    void StoreStateSlotByDma(AscendC::GlobalTensor<int32_t> &stateTensor, uint64_t index, int32_t value)
    {
        auto writeBuf = resource.ubBuf.template GetBufferByByte<int32_t>(STATE_SLOT_DMA_WRITE_UB_OFFSET);
        // The transfer is one 32B block because that is the smallest DMA granule. The slot only
        // uses its first word, so clear the rest rather than spilling stale staging data into it.
        for (uint32_t i = 0; i < INT32_COUNT_PER_BLOCK; ++i) {
            writeBuf.SetValue(static_cast<int64_t>(i), 0);
        }
        writeBuf.SetValue(0, value);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::DataCopyParams oneBlock{1U, 1U, 0U, 0U};
        AscendC::DataCopy(stateTensor[index], writeBuf, oneBlock);
        // The staging buffer is rewritten by the next swap on the scalar pipe, so wait for the
        // transfer to finish reading it before returning.
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    CATLASS_DEVICE
    int32_t FlipStateSlotByDma(AscendC::GlobalTensor<int32_t> &stateTensor, uint64_t index)
    {
        int32_t value = LoadStateSlotByDma(stateTensor, index);
        StoreStateSlotByDma(stateTensor, index, (value == 0) ? 1 : 0);
        return value;
    }

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
            aicStateGlobalCoreIdx = AIC_STATE_BASE_INTS + aicIdx * AIC_STATE_SLOT_INTS;
            cvDataState = FlushAndSpinValue<int32_t>(selfDataStatusTensor, aicStateGlobalCoreIdx);
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

            dataState = FlipStateSlotByDma(selfDataStatusTensor, aivIdx * UB_ALIGN);
            cvDataState = FlipStateSlotByDma(selfDataStatusTensor, aivStateGlobalCoreIdx * UB_ALIGN);
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
    void CalExpandxIdx(int32_t dstExpertId, uint32_t tokenIndex, int32_t &curExpertCnt)
    {
        // calculate index in remote
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
        // Split by AIV, not by send core: every AIV runs this, so all of them share the expert sweep
        // instead of the send cores carrying all of it.
        uint32_t totalExpertNum = moeExpertNum;
        uint32_t sendCountExpertNum = totalExpertNum / aivNum;
        uint32_t remainderRankNum = totalExpertNum % aivNum;
        uint32_t startExpertId = sendCountExpertNum * aivIdx;
        if (aivIdx < remainderRankNum) {
            sendCountExpertNum += 1;
            startExpertId += aivIdx;
        } else {
            startExpertId += remainderRankNum;
        }
        uint32_t endExpertId = startExpertId + sendCountExpertNum;
        if (startExpertId >= totalExpertNum || sendCountExpertNum == 0) {
            return;
        }

        // The run is fully staged first and copied out afterwards, so every expert that shares a
        // destination rank goes out in one DataCopy instead of one copy per expert.
        AscendC::LocalTensor<int32_t> statusTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        ubOffset += CEIL_UP(sendCountExpertNum * INT32_COUNT_PER_BLOCK * static_cast<int32_t>(sizeof(int32_t)));
        AscendC::Duplicate(statusTensor_, (int32_t)0, sendCountExpertNum * INT32_COUNT_PER_BLOCK);
        // Only word 0 of each 8-int record carries the arrival flag. The masked Duplicate writes eight
        // words per repeat, which would run past this reservation, so the flag words go in scalar.
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        if (state == 0) {
            for (uint32_t i = 0; i < sendCountExpertNum; ++i) {
                statusTensor_(i * INT32_COUNT_PER_BLOCK) = 0x3F800000;
            }
        }

        for (uint32_t curExpertId = startExpertId; curExpertId < endExpertId; ++curExpertId) {
            int32_t curExpertCnt = 0;
            int32_t dstExpertId = curExpertId;
            CalExpandxIdx(dstExpertId, expertIdsCnt, curExpertCnt);
            statusTensor_((curExpertId - startExpertId) * INT32_COUNT_PER_BLOCK + 1) = curExpertCnt;
        }
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        PublishStagedExpertCounts(statusTensor_, startExpertId, endExpertId);
    }

    // Consecutive experts of one destination rank sit epRankSize bucket slots apart; blockLen counts
    // 32B blocks, so one record is exactly one block.
    CATLASS_DEVICE
    void PublishStagedExpertCounts(AscendC::LocalTensor<int32_t> &statusTensor_, uint32_t startExpertId,
                                   uint32_t endExpertId)
    {
        uint32_t dstStrideBlocks = epRankSize * (stateOffset / UB_BLOCK_SIZE) - 1;
        AscendC::GlobalTensor<int32_t> rankGMTensor;
        for (uint32_t curExpertId = startExpertId; curExpertId < endExpertId;) {
            uint32_t dstRankId = curExpertId;
            uint32_t offset = stateOffset * epRankId;
            uint32_t segNum = endExpertId - curExpertId;
            if (moeExpertNumPerRank > 1) {
                uint32_t localExpertId = curExpertId % moeExpertNumPerRank;
                dstRankId = curExpertId / moeExpertNumPerRank;
                offset = (epRankId + localExpertId * epRankSize) * stateOffset;
                uint32_t leftInRank = moeExpertNumPerRank - localExpertId;
                segNum = segNum < leftInRank ? segNum : leftInRank;
            }
            GM_ADDR rankGM = (__gm__ uint8_t *)(GetWindStateAddrByRankId(dstRankId) + offset);
            rankGMTensor.SetGlobalBuffer((__gm__ int32_t *)rankGM);
            if (segNum == 1) {
                AscendC::DataCopy<int32_t>(rankGMTensor,
                                           statusTensor_[(curExpertId - startExpertId) * INT32_COUNT_PER_BLOCK],
                                           INT32_COUNT_PER_BLOCK);
            } else {
                AscendC::DataCopyParams cntParams{static_cast<uint16_t>(segNum), 1U, 0,
                                                  static_cast<uint16_t>(dstStrideBlocks)};
                AscendC::DataCopy<int32_t>(rankGMTensor,
                                           statusTensor_[(curExpertId - startExpertId) * INT32_COUNT_PER_BLOCK],
                                           cntParams);
            }
            curExpertId += segNum;
        }
        // One flag covers every copy above: setting an MTE3 flag orders all earlier MTE3 work.
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    // Shared by every AIV core: the expert sweep behind CalAndSendTokenCount is O(expertNum * tokenNum)
    // of vector work, so splitting it over all cores instead of only the send cores cuts the per-core
    // cost and lets the last count land sooner, which is what unblocks RecvCount.
    CATLASS_DEVICE
    void PrepareAndSendTokenCount(GM_ADDR gmExpertIds, GM_ADDR gmXActiveMask)
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
        dstExpIdTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        subExpIdTensor_ = (resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset));
        workLocalTensor_ = (resource.ubBuf.template GetBufferByByte<float>(ubOffset));
        ubOffset += CEIL_UP(expertIdsCnt * sizeof(int32_t));

        AscendC::DataCopyExtParams expertIdsCntParams = {1U, static_cast<uint32_t>(expertIdsCnt * sizeof(uint32_t)),
                                                         0U, 0U, 0U};
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
        AscendC::DataCopyPad(expertIdsTensor_, expertIdsGMTensor_, expertIdsCntParams, copyPadParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);

        CalAndSendTokenCount();
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    // Spread the dense per-token payload over the wire layout: 480B of payload per 512B block, with
    // the 32B tail left as the flag that was filled once at buffer allocation. Two vector copies
    // because one repeat moves at most 256B; the source advances 480B per block while the destination
    // advances 512B, so the tails are stepped over rather than clobbered.
    CATLASS_DEVICE
    void SpreadTokenToBlocks(AscendC::LocalTensor<int8_t> &yBlocks, AscendC::LocalTensor<int8_t> &yDense)
    {
        AscendC::LocalTensor<int32_t> dstInt32 = yBlocks.template ReinterpretCast<int32_t>();
        AscendC::LocalTensor<int32_t> srcInt32 = yDense.template ReinterpretCast<int32_t>();
        AscendC::CopyRepeatParams spreadParams(1, 1,
                                               static_cast<uint16_t>(SPLIT_BLOCK_SIZE_INTS /
                                                                     INT32_COUNT_PER_BLOCK),
                                               static_cast<uint16_t>(SPLIT_BLOCK_DATA_INTS /
                                                                     INT32_COUNT_PER_BLOCK));
        AscendC::Copy(dstInt32, srcInt32, static_cast<uint64_t>(SPLIT_COPY_HEAD_INTS),
                      static_cast<uint8_t>(blockCntPerToken), spreadParams);
        AscendC::Copy(dstInt32[SPLIT_COPY_HEAD_INTS], srcInt32[SPLIT_COPY_HEAD_INTS],
                      static_cast<uint64_t>(SPLIT_COPY_TAIL_INTS),
                      static_cast<uint8_t>(blockCntPerToken), spreadParams);
    }

    CATLASS_DEVICE
    void QuantToken(AscendC::LocalTensor<XType> &xInTensor, AscendC::LocalTensor<float> &smoothScaleTensor,
        AscendC::LocalTensor<int8_t> &yInt8Tensor, int32_t syncFlag = 0)
    {
        AscendC::LocalTensor<int32_t> ytmpInt32Tensor = xFp32TmpTensor_.template ReinterpretCast<int32_t>();
        AscendC::LocalTensor<half> yHalfTensor = xFp32TmpTensor_.template ReinterpretCast<half>();
        AscendC::LocalTensor<float> yFp32Tensor = yInt8Tensor.template ReinterpretCast<float>();

        AscendC::Cast(xFp32TmpTensor_, xInTensor, AscendC::RoundMode::CAST_NONE, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            AscendC::Mul(xFp32TmpTensor_, xFp32TmpTensor_, smoothScaleTensor, tokenLength);
            AscendC::PipeBarrier<PIPE_V>();
        }
        AscendC::Abs(xFp32AbsTensor_, xFp32TmpTensor_, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceMax(xRowMaxTensor_, xFp32AbsTensor_, xFp32AbsTensor_, tokenLength, false);
        AscendC::PipeBarrier<PIPE_V>();

        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(syncFlag);
        float dynamicQuantScale = float(127.0) / xRowMaxTensor_.GetValue(0);
        // Only the dequant scale goes into the payload now. The old per-token flag word is gone: the
        // ready signal is the per-block tail, which the sender fills once for the whole buffer.
        yFp32Tensor.SetValue(tokenLength / sizeof(float), float(1.0) / dynamicQuantScale);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(syncFlag);
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);

        AscendC::Muls(xFp32TmpTensor_, xFp32TmpTensor_, dynamicQuantScale, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(ytmpInt32Tensor, xFp32TmpTensor_, AscendC::RoundMode::CAST_RINT, tokenLength);
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
        AscendC::LocalTensor<float> yFp32Tensor[BUFFER_NUM];
        AscendC::LocalTensor<float> moeSmoothScaleTensor[BUFFER_NUM];

        AscendC::GlobalTensor<XType> srcWinGMTensor;
        srcWinGMTensor.SetGlobalBuffer((__gm__ XType *)gmX);
        AscendC::GlobalTensor<float> moeSmoothScaleGMTensor;

        xInTensor[0] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(XType));
        xInTensor[1] = resource.ubBuf.template GetBufferByByte<XType>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(XType));
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            moeSmoothScaleGMTensor.SetGlobalBuffer((__gm__ float*) gmMoeSmoothScales);
            moeSmoothScaleTensor[0] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
            moeSmoothScaleTensor[1] = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
            ubOffset += CEIL_UP(tokenLength * sizeof(float));
        }
        xFp32TmpTensor_ = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(float));
        xFp32AbsTensor_ = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(tokenLength * sizeof(float));
        xRowMaxTensor_ = resource.ubBuf.template GetBufferByByte<float>(ubOffset);
        ubOffset += CEIL_UP(UB_BLOCK_SIZE);
        // The dense payload QuantToken writes is consumed by the spread in the same iteration, both on
        // the vector pipe, and MTE3 only ever reads the block layout -- so one staging buffer serves
        // every ring slot instead of one per slot. It overlays xFp32AbsTensor_, which is dead from the
        // row-max onward and is 4 * tokenLength bytes, comfortably wider than the ~1.07 * tokenLength
        // the dense payload needs at any realistic token length; the guard covers the degenerate short
        // tokens where that no longer holds. Reserving per-slot staging instead costs two ring slots at
        // h = 7168, which is in-flight depth the send pipeline cannot spare.
        AscendC::LocalTensor<int8_t> yDenseTensor;
        if (CEIL_UP(tokenLength * sizeof(float)) >= denseTokenBytes) {
            yDenseTensor = xFp32AbsTensor_.template ReinterpretCast<int8_t>();
        } else {
            yDenseTensor = resource.ubBuf.template GetBufferByByte<int8_t>(ubOffset);
            ubOffset += CEIL_UP(denseTokenBytes);
        }
        int32_t outBufferNum = (UB_SIZE - ubOffset) / hCommuSize;
        if (outBufferNum > MAX_OUT_BUFFER_NUM) {
            outBufferNum = MAX_OUT_BUFFER_NUM;
        }
        AscendC::LocalTensor<int8_t> yInt8Tensor[MAX_OUT_BUFFER_NUM];
        for (int i = 0; i < outBufferNum; ++i) {
            yInt8Tensor[i] = resource.ubBuf.template GetBufferByByte<int8_t>(ubOffset);
            ubOffset += CEIL_UP(hCommuSize);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(i);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(i);
        }
        // Fill the 32B tails once, up front. Nothing below ever writes them again -- the spread only
        // touches the 480B payload of each block -- so every block carries this launch's flag value
        // for free, and a flag becomes visible to a reader exactly when its block's payload does.
        // The value alternates per launch, so a stale tail from the previous run can never equal this
        // launch's target sum.
        for (int i = 0; i < outBufferNum; ++i) {
            AscendC::Duplicate<float>(yInt8Tensor[i].template ReinterpretCast<float>(), blockFlag,
                                      hCommuSize / sizeof(float));
        }
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::GlobalTensor<int8_t> dstWinGMTensor;
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
                uint32_t outIndex = sendValidTokenIndex % outBufferNum;
                int32_t outEventId = sendValidTokenIndex % outBufferNum;
                sendValidTokenIndex += 1;
                int32_t curExpertCnt = 0;
                CalExpandxIdx(dstExpertId, tokenIndex, curExpertCnt);
                expertCountTensor(tokenIndex - startTokenId) = curExpertCnt;
                uint32_t tempRankId = dstExpertId / moeExpertNumPerRank;
                GM_ADDR rankGM = (__gm__ uint8_t *)(
                    GetWindAddrByRankId(tempRankId) +
                    (expertPerSizeOnWin * (epRankId * moeExpertNumPerRank + dstExpertId % moeExpertNumPerRank)) +
                    hCommuSize * curExpertCnt);
                dstWinGMTensor.SetGlobalBuffer((__gm__ int8_t *)rankGM);

                AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
                AscendC::DataCopy(xInTensor[index], srcWinGMTensor[tokenIndex / axisK * tokenLength], tokenLength);
                if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
                    AscendC::PipeBarrier<PIPE_MTE2>();
                    AscendC::DataCopy(
                        moeSmoothScaleTensor[index], moeSmoothScaleGMTensor[dstExpertId * tokenLength], tokenLength);
                }
                AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
                AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(outEventId);
                QuantToken(xInTensor[index], moeSmoothScaleTensor[index], yDenseTensor, outEventId);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventId);
                // Both QuantToken and the spread run on the vector pipe, so they are already ordered
                // against each other, and the same in-order issue is what lets the shared dense buffer
                // be reused by the next token: the barrier at the head of QuantToken separates this
                // spread's read from the next iteration's write. The V->MTE3 release must come after
                // the spread, not after QuantToken: set earlier it would let the store read a
                // half-written block buffer.
                SpreadTokenToBlocks(yInt8Tensor[outIndex], yDenseTensor);
                AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(outEventId);

                AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(outEventId);
                AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(outEventId);

                // One transfer publishes payload and flags together, so the barrier that used to
                // order the token store before the scale/flag store is gone.
                AscendC::DataCopy(dstWinGMTensor, yInt8Tensor[outIndex], axisHCommu);
                AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(outEventId);
                AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(outEventId);
            }
        }
        for (int i = 0; i < outBufferNum; ++i) {
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(i);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(i);
        }
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
        // The expert-id copy and the count sweep already ran for every AIV in PrepareAndSendTokenCount,
        // so ubOffset carries on from there and SendToMoeExprt reuses the same base.
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
        xInTensor[0] = resource.ubBuf.template GetBufferByByte<XType>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(XType));
        xInTensor[1] = resource.ubBuf.template GetBufferByByte<XType>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(XType));
        AscendC::LocalTensor shareSmoothScaleTensor = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        if constexpr(EXEC_FLAG & EXEC_FLAG_SMOOTH_QUANT) {
            subUbOffset += CEIL_UP(tokenLength * sizeof(float));
            AscendC::DataCopy(shareSmoothScaleTensor, shareSmoothScaleGMTensor, tokenLength);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(EVENT_ID2);
        }
        xFp32TmpTensor_ = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(float));
        xFp32AbsTensor_ = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(tokenLength * sizeof(float));
        xRowMaxTensor_ = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);

        int32_t outBufferNum = (UB_SIZE - subUbOffset) / hCommuSize;
        if (outBufferNum > MAX_OUT_BUFFER_NUM) {
            outBufferNum = MAX_OUT_BUFFER_NUM;
        }
        AscendC::LocalTensor<int8_t> yInt8Tensor[MAX_OUT_BUFFER_NUM];
        AscendC::LocalTensor<float> yFp32Tensor[MAX_OUT_BUFFER_NUM];
        for (int i = 0; i < outBufferNum; ++i) {
            yInt8Tensor[i] = resource.ubBuf.template GetBufferByByte<int8_t>(subUbOffset);
            yFp32Tensor[i] = yInt8Tensor[i].template ReinterpretCast<float>();
            subUbOffset += CEIL_UP(hCommuSize);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(i);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(i);
        }
        // double buffer
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(1);
        AscendC::DataCopyExtParams dataCopyParamsFloat = {1U, sizeof(float), 0U, 0U, 0U};
        for (uint32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
            uint32_t index = (tokenIndex & 1) ? 0 : 1;
            int32_t eventId = (tokenIndex & 1) ? 0 : 1;
            uint32_t outIndex = tokenIndex % outBufferNum;
            int32_t outEventId = tokenIndex % outBufferNum;
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(eventId);
            AscendC::DataCopy(xInTensor[index], srcXGMTensor[tokenIndex * tokenLength], tokenLength);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(eventId);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(outEventId);
            QuantToken(xInTensor[index], shareSmoothScaleTensor, yInt8Tensor[outIndex], outEventId);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(eventId);
            AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(outEventId);
            AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(outEventId);
            AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(outEventId);
            AscendC::DataCopy(dstXInt8GMTensor[tokenIndex * tokenLength], yInt8Tensor[outIndex], tokenLength);
            AscendC::DataCopyPad(
                dstXScaleGMTensor[tokenIndex], yFp32Tensor[outIndex][tokenLength / sizeof(float)], dataCopyParamsFloat);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(outEventId);
            AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(outEventId);
        }
        for (int i = 0; i < outBufferNum; ++i) {
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(i);
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(i);
        }
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

    // Fallback for shapes the split poll cannot cover: every receive core builds the whole table from
    // the raw bucket heads, exactly as before this feature.
    CATLASS_DEVICE
    void RecvCountLegacy(int64_t ubOffset)
    {
        uint32_t recStatusNumPerCore = expertCntUp;
        uint32_t startStatusIndex = 0;

        int64_t subUbOffset = ubOffset;
        AscendC::LocalTensor<int32_t> statusTensor_ = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * UB_BLOCK_SIZE);
        AscendC::LocalTensor<uint32_t> gatherTmpTensor =
            (resource.ubBuf.template GetBufferByByte<uint32_t>(subUbOffset));
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
        AscendC::DataCopyParams intriParams{static_cast<uint16_t>(recStatusNumPerCore), 1,
                                            static_cast<uint16_t>(stateOffset / UB_BLOCK_SIZE - 1), 0};
        AscendC::GlobalTensor<float> windowInstatusFp32Tensor_;
        windowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)GetWindStateAddrByRankId(epRankId));
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);

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
    void GetCumSumLegacy(AscendC::LocalTensor<int32_t> &tokenPrefix, int64_t ubOffset)
    {
        auto statusTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        int32_t tokenCount = 0;
        for (uint32_t index = 0; index < expertCntUp; ++index) {
            tokenCount += statusTensor.GetValue(index * INT32_COUNT_PER_BLOCK + 1);
            tokenPrefix.SetValue(index, tokenCount);
        }
    }

    // The split poll needs one receive core per expert; with fewer cores than experts some expert would
    // never be published and every core would spin forever. The published record also has to fit in one
    // 512B line: header at word 0, prefix run starting at word 8.
    __aicore__ inline bool UseSplitRecvCount() const
    {
        return localExpertNum != 0 && localExpertNum <= recvCoreNum &&
               localExpertNum <= RECV_PREFIX_MAX_GROUPS &&
               (RECV_PREFIX_DATA_INDEX + epRankSize) <= RECV_PREFIX_GROUP_INTS;
    }

    // Words moved per record: the header plus one int32 per source rank, rounded up to a DataCopy
    // block so the strided publish stays 32B aligned. Derived from epRankSize, not a fixed floor, so
    // a wider world gets a wider record instead of silently truncating at a constant width.
    __aicore__ inline uint32_t PrefixCopyInts() const
    {
        return (RECV_PREFIX_DATA_INDEX + epRankSize + INT32_COUNT_PER_BLOCK - 1) /
               INT32_COUNT_PER_BLOCK * INT32_COUNT_PER_BLOCK;
    }

    __aicore__ inline uint32_t PrefixReplicateBytes() const
    {
        return recvCoreNum * PrefixCopyInts() * static_cast<uint32_t>(sizeof(int32_t));
    }

    // Record sits in the unused tail of the bucket-head block when that tail is long enough. One
    // expert per rank leaves no tail, so the record moves behind the replicate buffer instead of
    // being overwritten by the second core's copy.
    __aicore__ inline int64_t PrefixRecordBytes() const
    {
        return static_cast<int64_t>(PrefixCopyInts()) * static_cast<int64_t>(sizeof(int32_t));
    }

    __aicore__ inline int64_t PrefixExtraRecordBytes() const
    {
        int64_t heads = CEIL_UP(static_cast<int64_t>(expertCntUp) * UB_BLOCK_SIZE);
        int64_t recordInGap = static_cast<int64_t>(epRankSize) * UB_BLOCK_SIZE;
        return (recordInGap + PrefixRecordBytes() <= heads) ? 0 : PrefixRecordBytes();
    }

    __aicore__ inline int64_t ExpertPrefixRecordOffset(int64_t ubOffset) const
    {
        if (PrefixExtraRecordBytes() == 0) {
            return ubOffset + static_cast<int64_t>(epRankSize) * UB_BLOCK_SIZE;
        }
        return ubOffset + CEIL_UP(static_cast<int64_t>(expertCntUp) * UB_BLOCK_SIZE) +
               CEIL_UP(static_cast<int64_t>(PrefixReplicateBytes()));
    }

    // UB that RecvToken claims below the notify buffer: the per-rank cursor, two ping-pong payload
    // slots, the strided flag landing area, the gathered flag run, the gather pattern, the reduce
    // workspace and the scalar sum target. Every term has to be here -- a reservation short of what
    // RecvToken actually lays out puts the notify buffer inside one of these scratch areas.
    __aicore__ inline int64_t RecvTokenUbBytes() const
    {
        int64_t cursor = CEIL_UP(static_cast<int64_t>(epRankSize) * sizeof(int32_t));
        int64_t payload = 2 * CEIL_UP(static_cast<int64_t>(blockCntPerToken) * SPLIT_BLOCK_DATA_SIZE);
        // The strided read lands one whole 32B block per token block, so this is sized in blocks, not
        // in the blockCntPerToken floats the sum finally consumes.
        int64_t flags = CEIL_UP(static_cast<int64_t>(blockCntPerToken) * UB_BLOCK_SIZE);
        int64_t gathered = CEIL_UP(static_cast<int64_t>(blockCntPerToken) * sizeof(float));
        return cursor + payload + flags + gathered + CEIL_UP(UB_BLOCK_SIZE) +
               CEIL_UP(UB_BLOCK_SIZE * 8) + CEIL_UP(UB_BLOCK_SIZE);
    }

    // The bucket flag word is 0x3F800000 (float 1.0) on one launch and 0 on the next, so a stale
    // value left by the previous launch can never pass for complete.
    CATLASS_DEVICE
    void WaitLocalExpertArrival(int64_t ubOffset)
    {
        const int32_t expectedFlag = (state == 0) ? 0x3F800000 : 0;
        const uint32_t group = recvCoreIdx;
        auto statusTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        AscendC::GlobalTensor<int32_t> windowInstatusFp32Tensor_;
        windowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ int32_t *)GetWindStateAddrByRankId(epRankId));
        // epRankSize bucket heads, 32B each, STATE_OFFSET / UB_BLOCK_SIZE - 1 blocks apart.
        AscendC::DataCopyParams intriParams{static_cast<uint16_t>(epRankSize), 1,
                                            static_cast<uint16_t>(STATE_OFFSET / UB_BLOCK_SIZE - 1), 0};
        uint32_t bucketBase = group * epRankSize * (stateOffset / sizeof(int32_t));
        // Fold the arrival check on the vector pipe. The flags sit one per 32B block, so a gather
        // with pattern 1 collects them contiguously, and the bucket flag is exactly 1.0f (or 0) --
        // so a plain Sum of the gathered float view is the arrival count. That replaces epRankSize
        // serial scalar reads inside the spin, which is where the cost actually sat at EP64.
        auto arriveGather = resource.ubBuf.template GetBufferByByte<float>(ubOffset + RECV_ARRIVE_GATHER_OFFSET);
        auto arriveTmp = resource.ubBuf.template GetBufferByByte<uint32_t>(ubOffset + RECV_ARRIVE_TMP_OFFSET);
        auto arriveSum = resource.ubBuf.template GetBufferByByte<float>(ubOffset + RECV_ARRIVE_SUM_OFFSET);
        auto arriveTargetSrc = resource.ubBuf.template GetBufferByByte<float>(ubOffset + RECV_ARRIVE_TSRC_OFFSET);
        auto arriveTargetDst = resource.ubBuf.template GetBufferByByte<float>(ubOffset + RECV_ARRIVE_TARGET_OFFSET);
        uint32_t innerArrive =
            (epRankSize * static_cast<uint32_t>(sizeof(float)) + UB_ALIGN - 1) / UB_ALIGN * UB_ALIGN /
            static_cast<uint32_t>(sizeof(float));
        AscendC::SumParams arriveParams{1, innerArrive, epRankSize};
        // Each flag is exactly 1.0f, so "all arrived" is epRankSize of them added up. The sum has to
        // be built on the vector pipe: an aicore scalar cannot convert between float and unsigned.
        AscendC::Duplicate(arriveTargetSrc, 1.0f, epRankSize);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Sum(arriveTargetDst, arriveTargetSrc, arriveParams);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        const float arriveTarget = (expectedFlag == 0) ? 0.0f : arriveTargetDst.GetValue(0);
        arriveTmp.SetValue(0, 1);
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);
        uint64_t rsvdCnt = 0;
        bool bucketsReady = false;
        while (!bucketsReady) {
            AscendC::DataCopy(statusTensor, windowInstatusFp32Tensor_[bucketBase], intriParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
            AscendC::GatherMask(arriveGather, statusTensor.template ReinterpretCast<float>(), arriveTmp, true, 1,
                                {1, static_cast<uint16_t>(epRankSize), 1, 0}, rsvdCnt);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Sum(arriveSum, arriveGather, arriveParams);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
            if (arriveSum.GetValue(0) == arriveTarget) {
                bucketsReady = true;
            } else {
                AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
                AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);
                SPIN_WAIT_CYCLES();
            }
        }
    }

    // Assemble this expert's prefix record in UB. The prefix run is the vector scan below.
    CATLASS_DEVICE
    void BuildExpertPrefixRecord(int64_t ubOffset)
    {
        const uint32_t group = recvCoreIdx;
        auto statusTensor = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        auto record = resource.ubBuf.template GetBufferByByte<int32_t>(ExpertPrefixRecordOffset(ubOffset));
        // Prefix over the source ranks, on the vector pipe. Each count sits in its own 32B block, so
        // shifting by d blocks is a d*32B shift -- always aligned, which is the whole reason the
        // scalar loop existed. log2(epRankSize) block adds replace epRankSize serial reads, and at
        // EP64 that is the difference between four adds and sixty-four scalar round trips.
        auto scanBuf = resource.ubBuf.template GetBufferByByte<int32_t>(RECV_PREFIX_SCAN_OFFSET);
        auto prefixDense = resource.ubBuf.template GetBufferByByte<int32_t>(RECV_PREFIX_DENSE_OFFSET);
        auto countPattern = resource.ubBuf.template GetBufferByByte<uint32_t>(RECV_PREFIX_PATTERN_OFFSET);
        AscendC::Adds(scanBuf, statusTensor, 0, epRankSize * INT32_COUNT_PER_BLOCK);
        AscendC::PipeBarrier<PIPE_V>();
        for (uint32_t step = 1; step < epRankSize; step <<= 1) {
            uint32_t shift = step * INT32_COUNT_PER_BLOCK;
            AscendC::Add(scanBuf[shift], scanBuf[0], scanBuf[shift],
                         (epRankSize - step) * INT32_COUNT_PER_BLOCK);
            AscendC::PipeBarrier<PIPE_V>();
        }
        // Pull word 1 of every block back into a dense run. GATHER_SECOND_NUM selects the second
        // element of each block, which is the count.
        countPattern.SetValue(0, static_cast<uint32_t>(GATHER_SECOND_NUM));
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);
        uint64_t prefixRsvd = 0;
        AscendC::GatherMask(prefixDense, scanBuf, countPattern, true, static_cast<uint32_t>(GATHER_SECOND_NUM),
                            {1, static_cast<uint16_t>(epRankSize), 1, 0}, prefixRsvd);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Adds(record[RECV_PREFIX_DATA_INDEX], prefixDense, 0, epRankSize);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        int32_t running = prefixDense.GetValue(epRankSize - 1);
        record(RECV_PREFIX_MAGIC_INDEX) = static_cast<int32_t>(RECV_PREFIX_MAGIC);
        record(RECV_PREFIX_TOTAL_INDEX) = running;
        // This core is the publisher for `group`, so it never has to wait for its own record: the
        // prefix run is still sitting in prefixDense. Keep the total and remember which expert it
        // belongs to, so LoadGroupPrefix can answer without a GM round trip. Reading it back would
        // depend on the store below having reached memory already, which it need not have.
        ownPublishGroup = static_cast<int32_t>(group);
        ownPrefixTotal = running;
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
    }

    // Reproduce the record once per receive core, then let one strided copy spread the copies one
    // stride apart, so no two cores read the same line.
    CATLASS_DEVICE
    void ReplicateExpertPrefix(int64_t ubOffset)
    {
        const uint32_t group = recvCoreIdx;
        auto record = resource.ubBuf.template GetBufferByByte<int32_t>(ExpertPrefixRecordOffset(ubOffset));
        auto replicate = resource.ubBuf.template GetBufferByByte<int32_t>(
            ubOffset + CEIL_UP(expertCntUp * UB_BLOCK_SIZE));
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);
        uint32_t prefixCopyInts = PrefixCopyInts();
        for (uint32_t core = 0; core < recvCoreNum; ++core) {
            AscendC::Adds(replicate[core * prefixCopyInts], record, 0, prefixCopyInts);
        }
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
        uint32_t prefixBlocks = prefixCopyInts / INT32_COUNT_PER_BLOCK;
        uint32_t lineBlocks = RECV_PREFIX_COPY_STRIDE / UB_BLOCK_SIZE;
        AscendC::DataCopyParams copyParams{static_cast<uint16_t>(recvCoreNum),
                                           static_cast<uint16_t>(prefixBlocks), 0,
                                           static_cast<uint16_t>(lineBlocks - prefixBlocks)};
        AscendC::GlobalTensor<int32_t> copyTensor;
        copyTensor.SetGlobalBuffer((__gm__ int32_t *)(gmReserved_ + RECV_PREFIX_COPY_BASE), RECV_PREFIX_COPY_INTS);
        uint32_t copyInts = RECV_PREFIX_COPY_STRIDE / sizeof(int32_t);
        AscendC::DataCopy(copyTensor[group * recvCoreNum * copyInts], replicate, copyParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    // Raise one flag per receive core. Each flag owns a whole cache line, so the copy steps 512B
    // between them rather than writing them back to back.
    CATLASS_DEVICE
    void PublishExpertReadyFlags(int64_t ubOffset)
    {
        const uint32_t group = recvCoreIdx;
        const int32_t publishFlag = (state == 0) ? 1 : 2;
        AscendC::GlobalTensor<int32_t> flagTensor;
        flagTensor.SetGlobalBuffer((__gm__ int32_t *)(gmReserved_ + RECV_PREFIX_FLAG_BASE), RECV_FLAG_BLOCK_INTS);
        int64_t flagUbOffset = ubOffset + CEIL_UP(static_cast<int64_t>(expertCntUp) * UB_BLOCK_SIZE) +
                               CEIL_UP(static_cast<int64_t>(PrefixReplicateBytes())) + PrefixExtraRecordBytes();
        auto flagBuf = resource.ubBuf.template GetBufferByByte<int32_t>(flagUbOffset);
        // One Duplicate writes every flag: the mask selects element 0 of each 32B block, and one
        // repeat steps a whole 512B line, so a single vector instruction replaces a store per core.
        {
            uint64_t flagMask[2] = {0x1ULL, 0ULL};
            AscendC::Duplicate<int32_t>(flagBuf, publishFlag, flagMask, static_cast<uint8_t>(recvCoreNum), 1,
                                        static_cast<uint8_t>(RECV_PERFLAG_CORE_INTS / INT32_COUNT_PER_BLOCK));
        }
        // The flags are written on the vector pipe now, so the hand-over to the copy below is V->MTE3.
        AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
        uint16_t flagStep = static_cast<uint16_t>(RECV_PERFLAG_CORE_INTS / INT32_COUNT_PER_BLOCK - 1);
        AscendC::DataCopyParams flagParams{static_cast<uint16_t>(recvCoreNum), 1U, flagStep, flagStep};
        AscendC::DataCopy(flagTensor[group * RECV_PERFLAG_GROUP_INTS], flagBuf, flagParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
    }

    // One receive core owns one local expert: it polls only that expert's epRankSize bucket flags and
    // publishes its running prefix, so the expertCntUp-bucket sweep runs once per expert instead of
    // once per receive core. No barrier at the end: each expert gates its own consumers, so expert 0
    // can be received while the rest are still being counted.
    CATLASS_DEVICE
    void RecvCount(int64_t ubOffset)
    {
        if (!UseSplitRecvCount()) {
            RecvCountLegacy(ubOffset);
            return;
        }
        if (recvCoreIdx >= localExpertNum) {
            return;
        }
        WaitLocalExpertArrival(ubOffset);
        BuildExpertPrefixRecord(ubOffset);
        ReplicateExpertPrefix(ubOffset);
        PublishExpertReadyFlags(ubOffset);
    }

    // Loads one expert's published prefix and turns it into absolute bucket boundaries, so the caller can
    // start that expert's recvToken without waiting for any later expert. base is the running sum of the
    // experts before this one; the return value is this expert's total.
    CATLASS_DEVICE
    int32_t LoadGroupPrefix(uint32_t group, AscendC::LocalTensor<int32_t> &tokenPrefix,
                            int64_t ubOffset, int32_t base)
    {
        // Fast path for the core that published this expert. It already computed the prefix run and is
        // holding it in UB, so it must not wait on its own flag nor read its own record back: the store
        // it issued need not have reached memory yet, and the round trip it would take to find out is
        // what made the first prefix-wait expensive even on the publisher.
        if (ownPublishGroup >= 0 && static_cast<uint32_t>(ownPublishGroup) == group) {
            auto prefixDense = resource.ubBuf.template GetBufferByByte<int32_t>(RECV_PREFIX_DENSE_OFFSET);
            AscendC::Adds(tokenPrefix[group * epRankSize], prefixDense, base, epRankSize);
            AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
            int32_t selfTotal = ownPrefixTotal;
            return selfTotal;
        }
        const int32_t publishFlag = (state == 0) ? 1 : 2;
        // This core's own flag word: no two waiters share an address.
        const int64_t flagElem = static_cast<int64_t>(sizeof(int32_t));
        const int64_t flagByteOffset = group * RECV_PERFLAG_GROUP_INTS * flagElem +
                                       recvCoreIdx * RECV_PERFLAG_CORE_INTS * flagElem;
        AscendC::GlobalTensor<int32_t> flagTensor;
        flagTensor.SetGlobalBuffer((__gm__ int32_t *)(gmReserved_ + RECV_PREFIX_FLAG_BASE + flagByteOffset),
                                   RECV_FLAG_BLOCK_INTS);
        // Back off with a plain empty loop. The old form read SYS_CNT twice per round to bound the wait,
        // but that counter is just a MOV from the system register -- it is not precise across cores and
        // it costs scalar work inside the spin. A fixed instruction count is enough to keep the poll
        // rate down, which is what the backoff is for. The gap is much wider than before: at 24 cores
        // polling, the old tens-of-cycles spacing kept the L2 port saturated and the measured wait was
        // mostly queuing behind the other waiters.
        constexpr uint32_t SPIN_ROUNDS = 64;
        auto flagBuf = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset + RECV_FLAG_READ_OFFSET);
        AscendC::DataCopyParams flagParams{1U, 1U, 0U, 0U};
        bool flagSeen = false;
        while (!flagSeen) {
            AscendC::DataCopy(flagBuf, flagTensor[0], flagParams);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
            if (flagBuf(RECV_PREFIX_FLAG_INDEX) == publishFlag) {
                flagSeen = true;
            } else {
                for (uint32_t spin = 0; spin < SPIN_ROUNDS; ++spin) {
                    __asm__ __volatile__("");
                }
            }
        }
        // Each core reads its own copy of the record, so the cores never queue on one address.
        AscendC::GlobalTensor<int32_t> publishTensor;
        publishTensor.SetGlobalBuffer((__gm__ int32_t *)(gmReserved_ + RECV_PREFIX_COPY_BASE +
                                                         (group * recvCoreNum + recvCoreIdx) *
                                                             RECV_PREFIX_COPY_STRIDE),
                                      RECV_PREFIX_COPY_STRIDE / sizeof(int32_t));
        auto line = resource.ubBuf.template GetBufferByByte<int32_t>(ubOffset);
        AscendC::DataCopy(line, publishTensor, PrefixCopyInts());
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
        // One vector add folds the base in; this expert's slice of tokenPrefix is contiguous and both
        // operands are 32B aligned.
        AscendC::Adds(tokenPrefix[group * epRankSize], line[RECV_PREFIX_DATA_INDEX], base, epRankSize);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        int32_t expertTotal = line.GetValue(RECV_PREFIX_TOTAL_INDEX);
        // line is reused by the next group's copy, so the vector read above must retire first.
        AscendC::SetFlag<AscendC::HardEvent::V_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE2>(0);
        return expertTotal;
    }

    CATLASS_DEVICE
    void InitRecvRankCursor(AscendC::LocalTensor<int32_t> &rankCursor,
                            AscendC::LocalTensor<int32_t> &tokenPrefix, uint32_t startRankId,
                            uint32_t startTokenIdx, uint32_t endTokenIdx)
    {
        for (uint32_t rank = 0; rank < epRankSize; ++rank) {
            uint32_t index = startRankId + rank;
            uint32_t bucketBegin = index == 0 ? 0 : tokenPrefix.GetValue(index - 1);
            uint32_t bucketEnd = tokenPrefix.GetValue(index);
            uint32_t begin = startTokenIdx > bucketBegin ? startTokenIdx : bucketBegin;
            uint32_t end = endTokenIdx < bucketEnd ? endTokenIdx : bucketEnd;
            rankCursor.SetValue(rank, begin < end ? begin - bucketBegin : bucketEnd - bucketBegin);
        }
    }

    // Waits until every 512B block of one token has landed, by summing that token's block tails.
    // The tails were filled at the sender before any payload was written and are never rewritten, so
    // a tail becomes visible exactly when its own block's payload does -- the flag and the data it
    // guards travel in the same 512B unit. The value alternates per launch, so a stale tail left by
    // the previous run sums to the other target and can never be mistaken for this one.
    CATLASS_DEVICE
    bool TokenBlocksReady(GM_ADDR tokAddr, AscendC::LocalTensor<float> &flagBuf,
                          AscendC::LocalTensor<float> &gatherBuf,
                          AscendC::LocalTensor<uint32_t> &flagPattern,
                          AscendC::LocalTensor<float> &reduceWork, AscendC::LocalTensor<float> &sumOut)
    {
        AscendC::GlobalTensor<float> flagGlobal;
        flagGlobal.SetGlobalBuffer((__gm__ float *)(tokAddr + SPLIT_BLOCK_DATA_SIZE));
        // One 32B block per 512B unit: blockLen 1 block, then skip the 480B payload (15 blocks), so the
        // period between flags is 16 blocks = 512B. Getting this wrong reads payload bytes as flags.
        AscendC::DataCopyParams flagParams{static_cast<uint16_t>(blockCntPerToken), 1U,
                                           static_cast<uint16_t>(SPLIT_BLOCK_DATA_INTS / INT32_COUNT_PER_BLOCK),
                                           0U};
        AscendC::DataCopy(flagBuf, flagGlobal, flagParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(0);
        // The tails land one whole 32B block each, so consecutive flags sit eight elements apart and
        // seven of every eight elements are padding copies of the same flag. Pull word 0 of every block
        // into a dense run before summing, the same way RecvCount reads the bucket flags: summing
        // flagBuf directly would weigh the early blocks eight times each and reach the target while
        // most of the token was still in flight. One repeat per block, mask bit 0 only, so the repeat
        // stride is a single block.
        uint64_t rsvdCnt = 0;
        AscendC::GatherMask(gatherBuf, flagBuf, flagPattern, true, 1,
                            {1, static_cast<uint16_t>(blockCntPerToken), 1, 0}, rsvdCnt);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceSum(sumOut, gatherBuf, reduceWork, static_cast<int32_t>(blockCntPerToken));
        AscendC::SetFlag<AscendC::HardEvent::V_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(0);
        float arrived = sumOut.GetValue(0);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE2>(0);
        return arrived == blockFlagSum;
    }

    // Ping-pong so the write of one token overlaps the read of the next: the payload read is MTE2
    // and the output write is MTE3, two different pipes.
    CATLASS_DEVICE
    void LayoutRecvTokenScratch(int64_t ubOffset, AscendC::LocalTensor<int32_t> &rankCursor,
                                AscendC::LocalTensor<int8_t> (&dataBuf)[BUFFER_NUM],
                                AscendC::LocalTensor<float> &flagBuf, AscendC::LocalTensor<float> &gatherBuf,
                                AscendC::LocalTensor<uint32_t> &flagPattern, AscendC::LocalTensor<float> &reduceWork,
                                AscendC::LocalTensor<float> &sumOut)
    {
        int64_t subUbOffset = ubOffset;
        rankCursor = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(epRankSize * sizeof(int32_t));
        for (int32_t bufIdx = 0; bufIdx < BUFFER_NUM; ++bufIdx) {
            dataBuf[bufIdx] = resource.ubBuf.template GetBufferByByte<int8_t>(subUbOffset);
            subUbOffset += CEIL_UP(blockCntPerToken * SPLIT_BLOCK_DATA_SIZE);
        }
        // Sized in 32B blocks: the strided read puts one whole block per token block here, and only
        // word 0 of each is the flag.
        flagBuf = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(blockCntPerToken * UB_BLOCK_SIZE);
        gatherBuf = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(blockCntPerToken * sizeof(float));
        flagPattern = resource.ubBuf.template GetBufferByByte<uint32_t>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE);
        reduceWork = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
        subUbOffset += CEIL_UP(UB_BLOCK_SIZE * 8);
        sumOut = resource.ubBuf.template GetBufferByByte<float>(subUbOffset);
    }

    // Walk forward while this rank keeps delivering. On the first token that is not fully landed,
    // move to the next rank instead of spinning: the ranks fill independently, so the token holding
    // us up is rarely the one that arrives next.
    CATLASS_DEVICE
    bool RecvReadyRanks(GM_ADDR gmX1, uint32_t groupId, uint32_t startRankId, uint32_t endTokenIdx,
                        uint32_t &curRecvTokenCount, AscendC::LocalTensor<int32_t> &rankCursor,
                        AscendC::LocalTensor<int32_t> &tokenPrefix,
                        AscendC::LocalTensor<int8_t> (&dataBuf)[BUFFER_NUM],
                        AscendC::LocalTensor<float> &flagBuf, AscendC::LocalTensor<float> &gatherBuf,
                        AscendC::LocalTensor<uint32_t> &flagPattern, AscendC::LocalTensor<float> &reduceWork,
                        AscendC::LocalTensor<float> &sumOut, AscendC::GlobalTensor<int8_t> &tokGlobal,
                        AscendC::GlobalTensor<int8_t> &expandXOutGlobal,
                        AscendC::GlobalTensor<float> &scaleOut, AscendC::DataCopyExtParams &scaleParams,
                        AscendC::DataCopyParams &payloadParams)
    {
        bool progressed = false;
        for (uint32_t rank = 0; rank < epRankSize; ++rank) {
            uint32_t index = startRankId + rank;
            uint32_t bucketBegin = index == 0 ? 0 : tokenPrefix.GetValue(index - 1);
            uint32_t bucketEnd = tokenPrefix.GetValue(index);
            uint32_t end = endTokenIdx < bucketEnd ? endTokenIdx : bucketEnd;
            uint32_t ordinalEnd = end > bucketBegin ? end - bucketBegin : 0;
            uint32_t winOffset = rank * moeExpertNumPerRank + groupId;
            GM_ADDR wAddr = (__gm__ uint8_t *)GetWindAddrByRankId(epRankId) + winOffset * expertPerSizeOnWin;
            for (uint32_t j = static_cast<uint32_t>(rankCursor.GetValue(rank)); j < ordinalEnd; ++j) {
                GM_ADDR tokAddr = wAddr + j * hCommuSize;
                if (!TokenBlocksReady(tokAddr, flagBuf, gatherBuf, flagPattern, reduceWork, sumOut)) {
                    break;
                }
                uint32_t outputRow = bucketBegin + j;
                uint32_t bufIdx = curRecvTokenCount & 1U;
                auto dense = dataBuf[bufIdx];
                auto denseFp32 = dense.template ReinterpretCast<float>();
                expandXOutGlobal.SetGlobalBuffer((__gm__ int8_t *)gmX1 + outputRow * tokenLength, tokenLength);
                // Release this slot only once its previous write has drained.
                AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(bufIdx);
                tokGlobal.SetGlobalBuffer((__gm__ int8_t *)tokAddr);
                AscendC::DataCopy(dense, tokGlobal, payloadParams);
                AscendC::SetFlag<AscendC::HardEvent::MTE2_MTE3>(bufIdx);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_MTE3>(bufIdx);
                // The dequant scale rides at the end of the dense payload, where QuantToken put it.
                AscendC::DataCopyPad(scaleOut[outputRow], denseFp32[tokenLength / sizeof(float)], scaleParams);
                AscendC::DataCopy(expandXOutGlobal, dense, tokenLength);
                AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(bufIdx);
                rankCursor.SetValue(rank, j + 1);
                ++curRecvTokenCount;
                progressed = true;
            }
        }
        return progressed;
    }

    CATLASS_DEVICE
    void RecvToken(GM_ADDR gmX1, GM_ADDR gmX1Scale, uint32_t groupId, uint32_t startTokenIdx,
                   uint32_t coreTokenCount, AscendC::LocalTensor<int32_t> &tokenPrefix, int64_t ubOffset)
    {
        AscendC::LocalTensor<int32_t> rankCursor;
        AscendC::LocalTensor<int8_t> dataBuf[BUFFER_NUM];
        AscendC::LocalTensor<float> flagBuf;
        AscendC::LocalTensor<float> gatherBuf;
        AscendC::LocalTensor<uint32_t> flagPattern;
        AscendC::LocalTensor<float> reduceWork;
        AscendC::LocalTensor<float> sumOut;
        LayoutRecvTokenScratch(ubOffset, rankCursor, dataBuf, flagBuf, gatherBuf, flagPattern, reduceWork, sumOut);

        uint32_t endTokenIdx = startTokenIdx + coreTokenCount;
        uint32_t startRankId = groupId * epRankSize;
        InitRecvRankCursor(rankCursor, tokenPrefix, startRankId, startTokenIdx, endTokenIdx);

        AscendC::DataCopyExtParams scaleParams = {1U, sizeof(float), 0U, 0U, 0U};
        // One strided read takes the 480B payload of every block: blockLen 15 blocks (480B), stride
        // 1 block (32B), so the flag tails are stepped over and the payload lands dense.
        AscendC::DataCopyParams payloadParams{static_cast<uint16_t>(blockCntPerToken),
                                              static_cast<uint16_t>(SPLIT_BLOCK_DATA_INTS / INT32_COUNT_PER_BLOCK),
                                              1U, 0U};
        AscendC::GlobalTensor<int8_t> tokGlobal;
        AscendC::GlobalTensor<int8_t> expandXOutGlobal;
        AscendC::GlobalTensor<float> scaleOut;
        scaleOut.SetGlobalBuffer((__gm__ float *)gmX1Scale);
        // Mask bit 0 only, reused by every arrival check below, so it is written once here.
        flagPattern.SetValue(0, 1);
        AscendC::SetFlag<AscendC::HardEvent::S_V>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_V>(0);
        // Seed both slots so the first two reads have a matching release.
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        uint32_t curRecvTokenCount = 0;
        while (curRecvTokenCount < coreTokenCount) {
            if (!RecvReadyRanks(gmX1, groupId, startRankId, endTokenIdx, curRecvTokenCount, rankCursor, tokenPrefix,
                                dataBuf, flagBuf, gatherBuf, flagPattern, reduceWork, sumOut, tokGlobal,
                                expandXOutGlobal, scaleOut, scaleParams, payloadParams)) {
                SPIN_WAIT_CYCLES();
            }
        }
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(1);
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void NotifyExpertTokens(AscendC::LocalTensor<int32_t> &notifyTensor, uint32_t groupId,
                            uint32_t coreTokenCount)
    {
        AscendC::PipeBarrier<PIPE_ALL>();
        for (uint32_t field = 0; field < INT32_COUNT_PER_BLOCK; ++field) {
            notifyTensor.SetValue(field, 0);
        }
        notifyTensor.SetValue(CV_FLAG_INDEX, vToCFlag);
        notifyTensor.SetValue(GROUP_ID_INDEX, groupId);
        notifyTensor.SetValue(SELF_COUNT_INDEX, coreTokenCount);
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);

        AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
        groupTokenNumStateTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + GROUP_TOKEN_NUM_OFFSET));
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::SetAtomicAdd<int32_t>();
        AscendC::DataCopy(groupTokenNumStateTensor[groupId * GROUP_INFO_SIZE], notifyTensor,
                          INT32_COUNT_PER_BLOCK);
        AscendC::SetAtomicNone();
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    // Every boundary is in tokenPrefix by now, so the public table is written once instead of
    // competing with the per-expert publishes.
    CATLASS_DEVICE
    void PublishEpSendCount(GM_ADDR gmEpSendCount, AscendC::LocalTensor<int32_t> &tokenPrefix)
    {
        AscendC::GlobalTensor<int32_t> sendCountsGlobal;
        sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(gmEpSendCount));
        AscendC::DataCopyExtParams copyParams = {
            1U, static_cast<uint32_t>(expertCntUp * sizeof(int32_t)), 0U, 0U, 0U};
        AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
        AscendC::DataCopyPad(sendCountsGlobal, tokenPrefix, copyParams);
        AscendC::PipeBarrier<PIPE_ALL>();
    }

    CATLASS_DEVICE
    void RecvCoreFunc(GM_ADDR gmX1, GM_ADDR gmX1Scale, GM_ADDR gmEpSendCount)
    {
        ubOffset = 0;
        // RecvCount's bucket heads and publish staging share this first block, so tokenPrefix starts
        // after both. The replicated staging grows with epRankSize; a record that does not fit in the
        // head-block tail is reserved behind it, and the per-core flags occupy a full block at the end.
        int64_t subUbOffset = CEIL_UP(static_cast<int64_t>(expertCntUp) * UB_BLOCK_SIZE) +
                              CEIL_UP(static_cast<int64_t>(PrefixReplicateBytes())) +
                              PrefixExtraRecordBytes() + CEIL_UP(RECV_FLAG_STAGE_BYTES);
        auto tokenPrefix = resource.ubBuf.template GetBufferByByte<int32_t>(subUbOffset);
        subUbOffset += CEIL_UP(expertCntUp * sizeof(int32_t));
        // Scratch for one published record line, loaded per expert below.
        int64_t recordUbOffset = subUbOffset;
        subUbOffset += CEIL_UP(RECV_PREFIX_GROUP_STRIDE);
        const bool splitRecv = UseSplitRecvCount();
        RecvCount(ubOffset);
        AscendC::PipeBarrier<PIPE_ALL>();
        if (!splitRecv) {
            GetCumSumLegacy(tokenPrefix, ubOffset);
            AscendC::PipeBarrier<PIPE_ALL>();
        }

        // RecvToken now holds two ping-pong payload slots plus the flag/reduce scratch, so the notify
        // buffer has to be reserved past all of that rather than past a single token copy.
        int64_t notifyUbOffset = subUbOffset + RecvTokenUbBytes();
        auto notifyTensor = resource.ubBuf.template GetBufferByByte<int32_t>(notifyUbOffset);
        uint32_t startCoreIdx = 0;
        uint32_t expertStart = 0;
        int32_t prefixBase = 0;
        for (uint32_t groupId = 0; groupId < localExpertNum; ++groupId) {
            uint32_t expertEnd;
            if (splitRecv) {
                // Only this expert's own record is needed, so an early expert starts moving tokens while
                // the later ones are still being counted. LoadGroupPrefix returns this expert's total and
                // the running prefix is exactly the last bucket boundary, so the caller does not need to
                // read that word back: a scalar read right after the vector add stalls the scalar unit
                // behind the vector pipe, and that stall showed up as a gap before recv-token.
                prefixBase += LoadGroupPrefix(groupId, tokenPrefix, recordUbOffset, prefixBase);
                expertEnd = static_cast<uint32_t>(prefixBase);
            } else {
                expertEnd = tokenPrefix.GetValue((groupId + 1) * epRankSize - 1);
            }
            uint32_t currentM = expertEnd - expertStart;
            uint32_t logicalCoreIdx = (recvCoreIdx + recvCoreNum - startCoreIdx) % recvCoreNum;
            uint32_t tokensPerCore = currentM / recvCoreNum;
            uint32_t remainder = currentM % recvCoreNum;
            uint32_t startTokenIdx = expertStart + logicalCoreIdx * tokensPerCore +
                                    (logicalCoreIdx < remainder ? logicalCoreIdx : remainder);
            uint32_t coreTokenCount = tokensPerCore + (logicalCoreIdx < remainder ? 1 : 0);
            if (coreTokenCount > 0) {
                RecvToken(gmX1, gmX1Scale, groupId, startTokenIdx, coreTokenCount, tokenPrefix, subUbOffset);
            }

            // Every receive core notifies every expert, including empty assignments.
            NotifyExpertTokens(notifyTensor, groupId, coreTokenCount);
            startCoreIdx = (startCoreIdx + currentM) % recvCoreNum;
            expertStart = expertEnd;
        }
        if (recvCoreIdx == 0) {
            PublishEpSendCount(gmEpSendCount, tokenPrefix);
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
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK,
                                  true, Callback{}, static_cast<bool>(EXEC_FLAG & EXEC_FLAG_DEEP_FUSE));
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
                    blockEpilogue(blockShapeMNK, blockCoordMNK, actualBlockShapeMNK,
                                  true, Callback{}, static_cast<bool>(EXEC_FLAG & EXEC_FLAG_DEEP_FUSE));
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
        // The payload of one token is its quantised bytes followed by the per-token dequant scale, laid
        // out densely and then spread over 512B blocks with a 32B flag tail each. Rounding happens on
        // the dense payload, so a token that fills its last block exactly costs no extra block.
        uint32_t payloadBytes = hOutSize + static_cast<uint32_t>(sizeof(float));
        blockCntPerToken = (payloadBytes + SPLIT_BLOCK_DATA_SIZE - 1) / SPLIT_BLOCK_DATA_SIZE;
        denseTokenBytes = CEIL_UP(blockCntPerToken * SPLIT_BLOCK_DATA_SIZE);
        scaleParamPad = 0;
        hCommuSize = blockCntPerToken * SPLIT_BLOCK_SIZE;
        axisHCommu = hCommuSize / sizeof(int8_t);
        axisBS = params.bs;
        activeMaskBsCnt = axisBS;
        axisK = params.topK;
        uint32_t maxAxisBs = params.globalBs / epRankSize;

        stateOffset = expertCntUp > MAX_EXPERTS_FULL_STATE_SLOT ? STATE_OFFSET >> 1 : STATE_OFFSET;
        expertPerSizeOnWin = maxAxisBs * tokenLength * sizeof(XType);
        gmReserved_ = params.gmReserved;
    }

    CATLASS_DEVICE
    void AivInitState()
    {
        // state of data sapce
        winDataSizeOffset = dataState * epRankSize * expertPerSizeOnWin * moeExpertNumPerRank;
        GM_ADDR statusSpaceGm_ = GetWindStateAddrByRankId(epRankId);
        AscendC::GlobalTensor<int32_t> selfStatusTensor;
        selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusSpaceGm_ + SELF_STATE_OFFSET));
        // Same slot, same reason as in the constructor: a scalar flush here cleans and invalidates a
        // whole 512B line, and at a 128B stride four cores share one, so they take turns evicting each
        // other's words. This runs before anything has claimed UB, so the prologue scratch is free.
        state = LoadStateSlotByDma(selfStatusTensor, aivIdx * UB_ALIGN);
        sumTarget = state == 0 ? 1.0f : 0.0f;
        tokenFlag = state == 0 ? TOKEN_FLAG_1 : TOKEN_FLAG_2;
        // The 512B-block flags alternate on the same schedule. A tail left over from the previous
        // launch carries the other value, so a partially filled token sums strictly between the two
        // targets and can never be read as complete.
        blockFlag = state == 0 ? 1.0f : 2.0f;
        // aicore forbids an explicit unsigned-to-float cast. Multiplying by a float constant does the
        // conversion implicitly, which is the same reason the reference implementation writes it this way.
        blockFlagSum = blockFlag * (1.0f * static_cast<int32_t>(blockCntPerToken));
        StoreStateSlotByDma(selfStatusTensor, aivIdx * UB_ALIGN, state == 0 ? 0x3F800000 : 0);
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
            {
                // Zero the flags this rank can publish, so a stale value can never read as ready on the
                // next launch. Only the flag lines need clearing: they are now one cache line per core,
                // so the region is far too big for one buffer and is wiped in chunks.
                constexpr uint32_t CLEAN_CHUNK_INTS = 8192;   // 32KB
                const uint32_t flagInts = localExpertNum * RECV_PERFLAG_GROUP_INTS;
                AscendC::GlobalTensor<int32_t> flagRegion;
                flagRegion.SetGlobalBuffer((__gm__ int32_t *)(gmReserved_ + RECV_PREFIX_FLAG_BASE));
                for (uint32_t done = 0; done < flagInts; done += CLEAN_CHUNK_INTS) {
                    uint32_t thisChunk = (flagInts - done < CLEAN_CHUNK_INTS) ? (flagInts - done)
                                                                              : CLEAN_CHUNK_INTS;
                    AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, thisChunk);
                    AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
                    AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);
                    AscendC::DataCopy(flagRegion[done], tmpZeroLocalTensor, thisChunk);
                    AscendC::SetFlag<AscendC::HardEvent::MTE3_S>(0);
                    AscendC::WaitFlag<AscendC::HardEvent::MTE3_S>(0);
                }
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
            // Every core runs the expert-id copy and the count sweep: the counts it publishes are what
            // RecvCount waits on, and SendCoreFunc reuses the same UB layout afterwards.
            PrepareAndSendTokenCount((GM_ADDR)params.gmexpertIds, (GM_ADDR)params.gmXActiveMask);
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

        if (isCompCore && (!(EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) || isSendCore)) {
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
    AscendC::LocalTensor<int32_t> dstExpIdTensor_;
    AscendC::LocalTensor<int32_t> subExpIdTensor_;
    AscendC::LocalTensor<float> workLocalTensor_;
    AscendC::LocalTensor<float> xFp32TmpTensor_;
    AscendC::LocalTensor<float> xFp32AbsTensor_;
    AscendC::LocalTensor<float> xRowMaxTensor_;
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
    uint32_t blockCntPerToken{0};   // 512B blocks per token, each with a 32B flag tail
    uint32_t denseTokenBytes{0};    // the 480B-per-block payload region, tight on both sides
    uint32_t axisBS{0};
    uint32_t activeMaskBsCnt{0};
    uint32_t axisK{0};
    uint32_t totalTokenCount{0};
    uint32_t expertIdsCnt{0};
    uint32_t tokenLength{0};

    // state info
    int32_t tokenFlag{0};    // token flag
    float blockFlag{0.0f};   // this launch's 512B-block flag value: 1.0f or 2.0f, alternating
    float blockFlagSum{0.0f};  // blockCntPerToken * blockFlag: one token's fully-arrived sum
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
    // The expert this core publishes, and that expert's own record. The publishing core already holds
    // the answer in UB, so it must not round-trip through GM for it: the write it just issued is not
    // guaranteed to be visible to its own next read yet, which is what made the first prefix-wait
    // expensive even on the core that had just produced the value.
    int32_t ownPublishGroup{-1};
    int32_t ownPrefixTotal{0};
    // Reserved workspace, used by the receive-side prefix publish.
    GM_ADDR gmReserved_{nullptr};
};

}  // namespace Catlass::Gemm::Kernel

