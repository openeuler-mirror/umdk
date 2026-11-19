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
    // gmm2-moving-forward quant-ready slots; must match the constants in
    // grouped_matmul_slice_m_per_token_dequant_swiglu_quant_multistage_workspace.h.
    // 802KB = right after the 48-slot epilogue-done announce array at 800KB (it ends at
    // 801.5KB, already on the 512B window granularity), inside the [792KB, 900KB) band
    // both dataState halves leave untouched (see ANNOUNCE_EPILOGUE_OFFSET). The
    // (localExpertNum + 1) 128B slots then have 98KB - 784 slots - so the per-rank
    // expert cap is back to the GROUP_TOKEN_NUM region's 255 (host-side guard).
    constexpr uint64_t NOTIFY_GMM2_SOFT_SYNC_OFFSET = 802 * 1024;
    constexpr uint32_t NOTIFY_GMM2_SLOT_STRIDE = 32;  // int32 units, 128B per slot (one spinner per DCCI sector)
    // gmm2-moving-forward currentM table: one 768B row per expert group = 24 private 32B
    // consumer cells, no header. It lives in the EXPANDED groupList workspace region:
    // base = ptrGroupList + CeilUp(problemCount * 8, 512) - see the gmm1 kernel and the
    // host's groupListSize.
    constexpr uint32_t GMM2_GROUP_M_COLS = 72;         // private consumer cells: AICs 0..23, AIVs 24..71
    constexpr uint32_t GMM2_GROUP_M_ROW_STRIDE = 576;  // int32 units: 72 cells x 32B = 2304B per group
    constexpr uint32_t GMM2_GROUP_M_AIV_COL_BASE = 24; // AIV columns start right after the AIC ones
    constexpr uint32_t GROUP_LIST_REGION_ALIGN = 512;  // bytes; matches the host's GM_ALIGN_SIZE
    // gmm1's swiglu-done table geometry (that file owns the authoritative copy): the
    // LAST send core - the currentM row writer - doubles its per-group announce into one
    // contiguous 1536B copy covering its own row and the 25th publish row, so the
    // ReducePermute side can gate each group's currentM read on its private cell of the
    // publish row (WaitRowPublished). The table is zeroed each launch by recv core 0.
    constexpr uint64_t SEND_DONE_TABLE_OFFSET = 992 * 1024;
    constexpr uint32_t NOTIFY_TABLE_CELLS = 24;
    constexpr uint32_t NOTIFY_TABLE_ROW_STRIDE = 192;  // int32 units: 24 cells x 32B per row
    constexpr uint32_t NOTIFY_PUBLISH_ROW_INDEX = 24;
    // Shared 32B polling scratch (CheckSyncFlag / GetGroupMAiv / WaitRowPublished), one live
    // copy at a time, above every ubBuf region this kernel lays out from offset 0: the
    // BlockEpilogue's static_assert bounds its single-stage footprint (~120KB at the 32x256
    // tile) and LateStateCleanup's staging ends before 36KB. 183KB keeps the 32B slab inside
    // the 184KB UB budget the gmm1 file sizes its buffers against (the physical UB is 192KB)
    // - the old 184KB base sat exactly on that budget line and only worked because of the
    // 8KB reserve.
    constexpr int64_t TOP_UB_SCRATCH_OFFSET = 183 * 1024;
    // gmm2-moving-forward is active only in deep-fuse mode.
    constexpr bool MOVING_FORWARD = Cam::GMM2_MOVING_FORWARD;
    // gmm1 status-window regions touched by LateStateCleanup; must match the constants in
    // grouped_matmul_slice_m_per_token_dequant_swiglu_quant_multistage_workspace.h.
    constexpr uint64_t GMM1_SOFT_SYNC_OFFSET = 964 * 1024;
    constexpr uint64_t GROUP_TOKEN_NUM_OFFSET = 932 * 1024;
    constexpr uint64_t SHARE_QUANT_SOFT_SYNC_OFFSET = 988 * 1024;
    constexpr uint32_t GROUP_INFO_SIZE = 32;  // int32 units, 128B per expert slot (one spinner per DCCI sector)
    // LateStateCleanup's zero-staging chunk, 32KB per copy - also the staging capacity: the
    // byte offset right after it is where the expertTokenNums staging begins.
    constexpr uint32_t CLEAN_CHUNK_INTS = 8192;
    // gmm1's deep-fuse receive-side regions inside the reserved workspace (gmReserved), also
    // cleaned by LateStateCleanup; must match the constants in
    // grouped_matmul_slice_m_per_token_dequant_swiglu_quant_multistage_workspace.h, which owns
    // the authoritative derivation.
    constexpr uint64_t RECV_PREFIX_OFFSET = 4096;
    constexpr uint32_t RECV_PREFIX_GROUP_STRIDE = 512;
    constexpr uint32_t RECV_PREFIX_MAX_GROUPS = 16;
    constexpr uint32_t RECV_REPLICATE_MAX_CORES = 32;
    constexpr uint32_t RECV_PERFLAG_CORE_INTS = 512 / sizeof(int32_t);  // one full line per core
    constexpr uint32_t RECV_PERFLAG_GROUP_INTS = RECV_REPLICATE_MAX_CORES * RECV_PERFLAG_CORE_INTS;
    constexpr uint64_t RECV_PREFIX_FLAG_BASE =
        RECV_PREFIX_OFFSET + static_cast<uint64_t>(RECV_PREFIX_MAX_GROUPS) * RECV_PREFIX_GROUP_STRIDE;
    constexpr uint32_t RECV_PREFIX_COPY_STRIDE = 288;  // (8 header + 64 ranks) * 4B, EP64 worst case
    constexpr uint32_t RECV_PREFIX_COPY_INTS =
        RECV_PREFIX_MAX_GROUPS * RECV_REPLICATE_MAX_CORES * (RECV_PREFIX_COPY_STRIDE / sizeof(int32_t));
    constexpr uint64_t FIRST_EXPERT_FRACTAL_BYTES = 512;
    constexpr uint64_t FIRST_EXPERT_ACK_OFFSET =
        (RECV_PREFIX_FLAG_BASE +
         static_cast<uint64_t>(RECV_PREFIX_MAX_GROUPS) * RECV_PERFLAG_GROUP_INTS * sizeof(int32_t) +
         RECV_PREFIX_COPY_INTS * sizeof(int32_t) + FIRST_EXPERT_FRACTAL_BYTES - 1) /
        FIRST_EXPERT_FRACTAL_BYTES * FIRST_EXPERT_FRACTAL_BYTES;
    constexpr uint32_t FIRST_EXPERT_CORE_SLOT = 24;
    constexpr uint32_t FIRST_EXPERT_MMA_M = 16;
    constexpr uint32_t FIRST_EXPERT_OUT_TILES = 3;
    constexpr uint32_t FIRST_EXPERT_SLOT_TOTAL = FIRST_EXPERT_OUT_TILES * FIRST_EXPERT_MMA_M;
    constexpr uint32_t FIRST_EXPERT_OUT_STRIDE_BYTES = 512;
    constexpr uint64_t FIRST_EXPERT_REGION_BYTES =
        FIRST_EXPERT_CORE_SLOT * FIRST_EXPERT_FRACTAL_BYTES +
        static_cast<uint64_t>(FIRST_EXPERT_SLOT_TOTAL) * FIRST_EXPERT_OUT_STRIDE_BYTES;
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
        // gmm2 moving forward (deep fuse): dedicated C buffer, epSendCount-based group list
        GM_ADDR ptrC;
        GM_ADDR ptrGroupListI32;
        uint32_t epRankSize;
        GM_ADDR ptrExpertTokenNums;
        // this tree's deep-fuse receive-side regions (recv-prefix flags, first-expert
        // ACK/publish) cleaned by LateStateCleanup
        GM_ADDR gmReserved;

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
               GM_ADDR ptrWorkspace_, void *combiner_, GM_ADDR ptrC_, GM_ADDR ptrGroupListI32_,
               uint32_t epRankSize_, GM_ADDR ptrExpertTokenNums_, GM_ADDR gmReserved_)
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
              ptrC(ptrC_),
              ptrGroupListI32(ptrGroupListI32_),
              epRankSize(epRankSize_),
              ptrExpertTokenNums(ptrExpertTokenNums_),
              gmReserved(gmReserved_)
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

    // gmm2 moving forward: spin until every gmm1 quant worker (aiCoreGroupNum send or recv
    // cores, either way) has announced the quant output of expert group slotIdx (slot
    // problemCount belongs to the shared expert). See NotifyGmm2QuantDone in the gmm1 kernel.
    CATLASS_DEVICE
    void WaitGmm2QuantReady(uint32_t slotIdx)
    {
        AscendC::GlobalTensor<int32_t> notifyTensor;
        notifyTensor.SetGlobalBuffer((__gm__ int32_t *)(syncGmAddr + GMM2::NOTIFY_GMM2_SOFT_SYNC_OFFSET));
        int64_t index = static_cast<int64_t>(slotIdx) * GMM2::NOTIFY_GMM2_SLOT_STRIDE;
        int32_t expected = static_cast<int32_t>(AscendC::GetBlockNum());
        while (FlushAndGetValue<int32_t>(notifyTensor, index) != expected) {
            SPIN_WAIT_CYCLES();
        }
    }

    CATLASS_DEVICE
    __gm__ int32_t *Gmm2GroupMTable(__gm__ void *groupListGm, uint32_t problemCount)
    {
        uint64_t entries = (static_cast<uint64_t>(problemCount) * sizeof(int64_t) +
                            GMM2::GROUP_LIST_REGION_ALIGN - 1) / GMM2::GROUP_LIST_REGION_ALIGN *
                            GMM2::GROUP_LIST_REGION_ALIGN;
        return reinterpret_cast<__gm__ int32_t *>(
            reinterpret_cast<__gm__ uint8_t *>(groupListGm) + entries);
    }

    // gmm2 moving forward: this group's token count from the currentM table - this
    // consumer's PRIVATE 32B cell instead of two reads of the shared epSendCount cumsum
    // lines. The cube core reads it with one DCCI scalar read (its MTE2 only feeds L1);
    // the vector core uses one MTE2 DataCopy (L2 path, no DCCI) into the 32B scratch at
    // UB offset 184KB - above the gmm2 epilogue's footprint, which is smaller than the
    // gmm1 swiglu epilogue's ~134KB.
    CATLASS_DEVICE
    uint32_t GetGroupM(uint32_t groupIdx, uint32_t colIdx, __gm__ int32_t *groupMBase)
    {
        AscendC::GlobalTensor<int32_t> mTensor;
        mTensor.SetGlobalBuffer(groupMBase);
        return static_cast<uint32_t>(FlushAndGetValue<int32_t>(
            mTensor,
            static_cast<int64_t>(groupIdx) * GMM2::GMM2_GROUP_M_ROW_STRIDE +
            static_cast<int64_t>(colIdx) * GMM2::INT32_COUNT_PER_BLOCK));
    }

    CATLASS_DEVICE
    uint32_t GetGroupMAiv(uint32_t groupIdx, uint32_t colIdx, __gm__ int32_t *groupMBase)
    {
        AscendC::LocalTensor<int32_t> mCellTensor =
            resource.ubBuf.template GetBufferByByte<int32_t>(GMM2::TOP_UB_SCRATCH_OFFSET);
        AscendC::GlobalTensor<int32_t> mTensor;
        mTensor.SetGlobalBuffer(groupMBase +
            static_cast<int64_t>(groupIdx) * GMM2::GMM2_GROUP_M_ROW_STRIDE +
            static_cast<int64_t>(colIdx) * GMM2::INT32_COUNT_PER_BLOCK);
        AscendC::DataCopy(mCellTensor, mTensor, GMM2::INT32_COUNT_PER_BLOCK);
        // GetValue is a SCALAR (S-pipe) read, so the drain sync is the MTE2->S event - an
        // MTE2_V gated the V pipe only and left the S pipe free to read the scratch before
        // the copy landed: stale scratch content poisoned every downstream address computed
        // from currentM (the source of the old MTE DDR out-of-range faults).
        AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
        return static_cast<uint32_t>(mCellTensor.GetValue(0));
    }

    // Per-group gate for the ReducePermute side's currentM table reads. That side is
    // gmm1's send cores: under QUANT_ON_RECV_CORE they run the whole gmm1 with no
    // cross-core wait, so they can enter gmm2 a few groups AHEAD of the row writer and
    // read unpublished rows - stale workspace bytes, a huge fake currentM and the bs=1
    // hang (the a2a side is already gated by its own last swiglu-done wait, the AICs by
    // the wgq chain). The LAST send core - the row writer, and the one that can never
    // carry extra blocks - doubles its per-group swiglu-done announce into one 1536B
    // MTE3 copy covering its own row AND the 25th publish row, riding the same FIFO
    // behind that group's currentM row write: this core's private publish cell reaching
    // g + 2 proves row g landed. Waiting PER GROUP is cheap because the last core
    // finishes each group's dequant earliest, so the flag normally leads the waiter.
    // One 32B MTE2 copy + scalar read per poll on this core's OWN cell: no lines shared
    // with any other waiter, no DCCI.
    CATLASS_DEVICE
    void WaitRowPublished(uint32_t groupIdx)
    {
        uint32_t consumerIdx = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
        AscendC::GlobalTensor<float> cellTensor;
        cellTensor.SetGlobalBuffer(
            (__gm__ float *)(syncGmAddr + GMM2::SEND_DONE_TABLE_OFFSET) +
            static_cast<uint64_t>(GMM2::NOTIFY_PUBLISH_ROW_INDEX) * GMM2::NOTIFY_TABLE_ROW_STRIDE +
            static_cast<uint64_t>(consumerIdx) * GMM2::INT32_COUNT_PER_BLOCK);
        // GetGroupMAiv's cell scratch (GMM2::TOP_UB_SCRATCH_OFFSET), reused after this
        // wait returns.
        AscendC::LocalTensor<float> flagTensor =
            resource.ubBuf.template GetBufferByByte<float>(GMM2::TOP_UB_SCRATCH_OFFSET);
        float target = static_cast<float>(static_cast<int32_t>(groupIdx) + 2);
        bool rowPublished = false;
        while (!rowPublished) {
            AscendC::DataCopy(flagTensor, cellTensor, GMM2::INT32_COUNT_PER_BLOCK);
            AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(0);
            AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(0);
            rowPublished = flagTensor.GetValue(0) >= target;
            if (!rowPublished) {
                SPIN_WAIT_CYCLES();
            }
        }
    }

    // Late port of the gmm1 kernel's UpdateAndCleanInfo (deep-fuse part), plus this kernel's
    // own gmm2 soft-sync slot - together, the whole late state cleanup. With gmm2 moving
    // forward the AIVs roll straight from the gmm1 quant into the gmm2 epilogue, so the gmm1
    // trailing SyncAll + cleanup had to go. On the sentinel path the LAST AIV is freed from
    // the fold and runs the big cleans in the window the other cores spend folding, gated on
    // the epilogue-done announce poll; the non-sentinel and shared-expert paths keep them on
    // their existing subblock-0 owner behind the same poll. Safety: the announce poll proves
    // every AIV's epilogue share is done, which transitively implies every quant worker
    // finished all groups (via the notify counts), hence every send core's dequant, every
    // AIC's gmm1 and gmm2, and every recv core's receive - i.e. every producer and consumer
    // of the regions touched below is done, including the gmm2 quant-ready notify slots
    // cleaned below (their only readers are this kernel's own cubes, whose WaitGmm2QuantReady
    // calls precede the very MMADs whose outputs the epilogues have consumed). groupList is
    // NOT written: nothing reads it in deep fuse (both gmm2 sides use epSendCount) and it is
    // not an op output. isCleanupOwner selects the one core that owns the big cleans: the
    // freed last AIV on the sentinel path, the last subblock-0 AIV on the non-sentinel path,
    // the shared-expert subblock 0 (its only caller there); every other caller passes false
    // and cleans only its own core's soft-sync slots.
    //
    // The own gmm2 soft-sync slot (subblock 0) is the AIC->AIV block counter this
    // core-group's epilogue loops consumed via CheckSyncFlag. It used to be a standalone
    // trailing block at the kernel's tail with its own Duplicate + event pair; folded in
    // here it is one more streamed copy off the shared staging. Every call site keeps the
    // clean behind that slot's last reader: the deep paths behind the announce poll (the
    // sibling's tail-side announce proves its routed loop done; the handshake variant still
    // waits the sibling's ProcessCombine head first), the shallow shared path behind the
    // SEND rendezvous (the sibling's ProcessCombine head proves its routed loop done), and
    // the shallow non-shared path behind
    // Process()'s WaitDispatch barrier. That last path passes withGmm1Work=false - the only
    // work left there is this slot (the gmm1-side state of that variant is cleaned by the
    // gmm1 kernel itself, and expertTokenNums comes from the dispatcher's UpdataTokenNumsOut,
    // which this cleanup must not overwrite).
    //
    // Zero staging: ONE Duplicate, sized for the largest single copy this core will issue
    // (the two big reserved-workspace regions are copied in CLEAN_CHUNK_INTS chunks, every
    // other region is smaller), and every clean below re-reads it with plain MTE3 copies.
    // Only that first Duplicate needs its V->MTE3 handoff: the staging is never rewritten
    // afterwards, so no copy needs a pipe-event pair of its own - the old per-chunk
    // re-Duplicate V_MTE3 pairs and the trailing MTE3_S drains only serialized the MTE3
    // queue for nothing. The copies now stream back-to-back down one queue, and kernel exit
    // retires whatever is still in flight.
    CATLASS_DEVICE
    void LateStateCleanup(Params const &params, bool isCleanupOwner, bool withGmm1Work)
    {
        uint32_t aivIdx = AscendC::GetBlockIdx();
        uint32_t subBlockNum = AscendC::GetSubBlockNum();
        // GetSubBlockNum is at least 1 on every launch shape this kernel runs; the fallback
        // only keeps the divisor provably non-zero.
        uint32_t coreIdx = subBlockNum > 0 ? aivIdx / subBlockNum : aivIdx;
        uint32_t localExpertNum = params.problemCount;

        // The one staging, pre-filled ONCE with the largest single copy this core issues:
        // deep fuse is owner-only (one strided slot sweep plus the region list below), the
        // shallow-shared owner caps at GROUP_TOKEN_NUM, and shallow non-owners only zero
        // their own core's soft-sync slots, so one CLEAN_CHUNK_INTS buffer covers them all.
        uint32_t zeroInts = GMM2::INT32_COUNT_PER_BLOCK;  // own soft-sync slots / share-quant slot
        if (withGmm1Work && isCleanupOwner) {
            if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                zeroInts = GMM2::CLEAN_CHUNK_INTS;
            } else {
                zeroInts = GMM2::GROUP_INFO_SIZE * (localExpertNum + 1);
            }
        }
        AscendC::LocalTensor<int32_t> tmpZeroLocalTensor =
            resource.ubBuf.template GetBufferByByte<int32_t>(0);
        AscendC::Duplicate(tmpZeroLocalTensor, (int32_t)0, zeroInts);
        AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(0);
        AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(0);

        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            LateStateCleanupDeepFuse(params, localExpertNum, isCleanupOwner, withGmm1Work,
                                     tmpZeroLocalTensor);
        } else {
            LateStateCleanupShallow(params, isCleanupOwner, withGmm1Work, tmpZeroLocalTensor, coreIdx);
        }
    }

    // Deep-fuse half of LateStateCleanup (see there for the safety argument): the one
    // strided ladder sweep over all three soft-sync tables, then - after the early-out the
    // non-owners take - the owner-only notify-region cleans and the expertTokenNums write.
    CATLASS_DEVICE
    void LateStateCleanupDeepFuse(Params const &params, uint32_t localExpertNum, bool isCleanupOwner,
                                  bool withGmm1Work, AscendC::LocalTensor<int32_t> &tmpZeroLocalTensor)
    {
        // One core, one copy: all three soft-sync ladders sit back-to-back on the same
        // 512B slot pitch - the gmm1 AIC->AIV counters at GMM1_SOFT_SYNC_OFFSET (24
        // slots), this kernel's own gmm2 counters at SOFT_SYNC_OFFSET (24 slots), and
        // the shared expert's quant slot exactly on the next boundary - so blocks of
        // one 32B slot head at dstStride=15 sweep 2*blockNum (+1) heads, the same 32B
        // heads the old per-core own-slot copies zeroed. Every deep-fuse call site runs
        // WaitEpiloguesDone before this function, and that poll proves every AIV's
        // routed and shared epilogue loops - the last readers of both ladders - are
        // done; the non-owners have no slot of their own left to clean.
        if (isCleanupOwner && withGmm1Work) {
            const uint16_t slotBlocks = static_cast<uint16_t>(
                AscendC::GetBlockNum() * 2 +
                ((EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) ? 1 : 0));
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer(
                (__gm__ int32_t *)(syncGmAddr + GMM2::GMM1_SOFT_SYNC_OFFSET));
            AscendC::DataCopy(softSyncTensor, tmpZeroLocalTensor,
                              AscendC::DataCopyParams{slotBlocks, 1, 0, 15});
        }
        if (!isCleanupOwner || !withGmm1Work) {
            return;
        }
        CleanLateNotifyRegions(params, localExpertNum, tmpZeroLocalTensor);
        WriteLateExpertTokenNums(params, localExpertNum);
    }

    // Shallow half of LateStateCleanup (see there for the safety argument): the per-core
    // own-slot cleans - there is no grid-wide epilogue-done poll here, so a core only ever
    // zeroes the slots its own AI core reads - then, for the owner, the notify-region cleans
    // and the expertTokenNums write.
    CATLASS_DEVICE
    void LateStateCleanupShallow(Params const &params, bool isCleanupOwner, bool withGmm1Work,
                                 AscendC::LocalTensor<int32_t> &tmpZeroLocalTensor, uint32_t coreIdx)
    {
        uint32_t localExpertNum = params.problemCount;
        // This kernel's own gmm2 soft-sync slot (subblock 0): the block counter slot at
        // SOFT_SYNC_OFFSET - one streamed copy, no event pair of its own.
        if (AscendC::GetSubBlockIdx() == 0) {
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer((__gm__ int32_t *)(syncGmAddr + GMM2::SOFT_SYNC_OFFSET));
            AscendC::DataCopy(
                softSyncTensor[coreIdx * CVSoftSync::SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                tmpZeroLocalTensor, GMM2::INT32_COUNT_PER_BLOCK);
        }
        if (!withGmm1Work) {
            return;
        }
        // own core's gmm1 AIC->AIV block-counter slot (subblock 0, as before)
        if (AscendC::GetSubBlockIdx() == 0) {
            // The ReducePermute-side publish row needs no clean here: it is the swiglu-done
            // table's 25th row, zeroed each launch by gmm1's recv core 0 together with the
            // rest of the table (see WaitRowPublished).
            AscendC::GlobalTensor<int32_t> softSyncTensor;
            softSyncTensor.SetGlobalBuffer((__gm__ int32_t *)(syncGmAddr + GMM2::GMM1_SOFT_SYNC_OFFSET));
            AscendC::DataCopy(
                softSyncTensor[coreIdx * CVSoftSync::SOFT_SYNC_SPACE_SIZE / sizeof(int32_t)],
                tmpZeroLocalTensor, GMM2::INT32_COUNT_PER_BLOCK);
        }
        if (!isCleanupOwner) {
            return;
        }
        CleanLateNotifyRegions(params, localExpertNum, tmpZeroLocalTensor);
        WriteLateExpertTokenNums(params, localExpertNum);
    }

    // LateStateCleanup's owner-only notify-state cleans. Everything here re-issues plain MTE3
    // copies from the one staging - no pipe events of their own; the queue lands them in order
    // and retires the rest at kernel exit.
    CATLASS_DEVICE
    void CleanLateNotifyRegions(Params const &params, uint32_t localExpertNum,
                                AscendC::LocalTensor<int32_t> &tmpZeroLocalTensor)
    {
        // clean GROUP_TOKEN_NUM (recv->AIC notify fields, incl. the +1 shared-expert
        // slot) and the shared-input-quant slot; by the cleanup owner
        AscendC::GlobalTensor<int32_t> groupTokenNumStateTensor;
        groupTokenNumStateTensor.SetGlobalBuffer(
            (__gm__ int32_t *)(syncGmAddr + GMM2::GROUP_TOKEN_NUM_OFFSET));
        AscendC::DataCopy(groupTokenNumStateTensor, tmpZeroLocalTensor,
                          GMM2::GROUP_INFO_SIZE * (localExpertNum + 1));
        if constexpr ((EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) &&
                      ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0)) {
            // Deep fuse: the shared-input-quant slot already went out as the sweep's
            // last block above; shallow keeps this copy - there is no sweep outside
            // deep fuse.
            AscendC::GlobalTensor<int32_t> shareQuantTokenStateTensor;
            shareQuantTokenStateTensor.SetGlobalBuffer(
                (__gm__ int32_t *)(syncGmAddr + GMM2::SHARE_QUANT_SOFT_SYNC_OFFSET));
            AscendC::DataCopy(shareQuantTokenStateTensor, tmpZeroLocalTensor,
                              GMM2::INT32_COUNT_PER_BLOCK);
        }
        // gmm2 quant-ready notify slots (see NotifyGmm2QuantDone / WaitGmm2QuantReady),
        // moved here from the gmm1 AIC-0 head: the state window is persistent, so a zero
        // retired before this kernel exits is still standing when the next launch's first
        // atomic add runs - which is all the head zero ever guaranteed. Every consumer of
        // this launch's counts is done (see the transitivity note above). The counts are
        // not parity-encoded, so this clean is load-bearing: a launch that dies mid-way
        // leaves stale counts behind and the NEXT launch would read them as ready - on
        // any abnormal termination, restart the process. The copy is one flat read off the
        // CLEAN_CHUNK_INTS staging, so its size caps the slot count at 256 ints-wise
        // (256 slots * 32 ints = 8192) - exactly the MAX_DEEP_FUSE_EXPERT_PER_RANK = 255
        // bound; raising that limit needs a chunked copy like the recv-flag regions.
        if constexpr (GMM2::MOVING_FORWARD && (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE)) {
            const uint32_t notifySlotCount =
                localExpertNum + ((EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) ? 1 : 0);
            AscendC::GlobalTensor<int32_t> gmm2NotifyTensor;
            gmm2NotifyTensor.SetGlobalBuffer(
                (__gm__ int32_t *)(syncGmAddr + GMM2::NOTIFY_GMM2_SOFT_SYNC_OFFSET));
            AscendC::DataCopy(gmm2NotifyTensor, tmpZeroLocalTensor,
                              notifySlotCount * GMM2::NOTIFY_GMM2_SLOT_STRIDE);
        }
        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            CleanLateRecvFlagRegions(params, localExpertNum, tmpZeroLocalTensor);
        }
    }

    // This tree's deep-fuse receive-side regions in the reserved workspace, moved here from
    // the gmm1 kernel's UpdateAndCleanInfo like the cleans above (gmReserved plumbed through
    // GmmDeq). Zero the per-(expert, recv-core) ready flag lines and the whole first-expert
    // ACK/publish region, so a stale value can never read as ready on the next launch: a
    // zero flag never satisfies a flag wait, a zero first-expert slot adds nothing to the
    // fold's byte sum, and a zeroed publish line can never be read as this launch's
    // completion. The flag region is laid out for RECV_PREFIX_MAX_GROUPS groups and the
    // split receive that publishes the flags itself requires no more groups than that, so
    // the clean is capped at the layout bound: with localExpertNum above it the gmm1-side
    // flagInts form would run past the region into the rest of the workspace.
    CATLASS_DEVICE
    void CleanLateRecvFlagRegions(Params const &params, uint32_t localExpertNum,
                                  AscendC::LocalTensor<int32_t> &tmpZeroLocalTensor)
    {
        const uint32_t flagGroups = (localExpertNum < GMM2::RECV_PREFIX_MAX_GROUPS)
                                        ? localExpertNum : GMM2::RECV_PREFIX_MAX_GROUPS;
        const uint32_t flagInts = flagGroups * GMM2::RECV_PERFLAG_GROUP_INTS;
        AscendC::GlobalTensor<int32_t> flagRegion;
        flagRegion.SetGlobalBuffer(
            (__gm__ int32_t *)(params.gmReserved + GMM2::RECV_PREFIX_FLAG_BASE));
        for (uint32_t done = 0; done < flagInts; done += GMM2::CLEAN_CHUNK_INTS) {
            const uint32_t thisChunk = (flagInts - done < GMM2::CLEAN_CHUNK_INTS)
                                          ? (flagInts - done) : GMM2::CLEAN_CHUNK_INTS;
            AscendC::DataCopy(flagRegion[done], tmpZeroLocalTensor, thisChunk);
        }
        const uint32_t firstExpertInts =
            static_cast<uint32_t>(GMM2::FIRST_EXPERT_REGION_BYTES / sizeof(int32_t));
        AscendC::GlobalTensor<int32_t> firstExpertRegion;
        firstExpertRegion.SetGlobalBuffer(
            (__gm__ int32_t *)(params.gmReserved + GMM2::FIRST_EXPERT_ACK_OFFSET),
            firstExpertInts);
        for (uint32_t done = 0; done < firstExpertInts; done += GMM2::CLEAN_CHUNK_INTS) {
            const uint32_t thisChunk = (firstExpertInts - done < GMM2::CLEAN_CHUNK_INTS)
                                          ? (firstExpertInts - done) : GMM2::CLEAN_CHUNK_INTS;
            AscendC::DataCopy(firstExpertRegion[done], tmpZeroLocalTensor, thisChunk);
        }
    }

    // LateStateCleanup's expertTokenNums (op OUTPUT) write, by the cleanup owner, exactly as
    // the gmm1-side code did. This is the ONLY writer of the expert_token_nums output in deep
    // fuse - the shallow path produces it inside the dispatcher (UpdataTokenNumsOut at the
    // end of dispatcher.Process), which deep fuse does not run. groupList is intentionally
    // NOT written: nothing reads it in deep fuse (both gmm2 sides and the gmm1 quant workers
    // use the currentM table behind the groupList entries, the gmm1 AICs use GROUP_TOKEN_NUM)
    // and it is not an op output.
    CATLASS_DEVICE
    void WriteLateExpertTokenNums(Params const &params, uint32_t localExpertNum)
    {
        // Read epSendCount directly, NOT the currentM table: this cold one-core tail
        // runs concurrently with every core's currentM slice zeroing above, so the
        // table is being wiped while this block executes. epSendCount is untouched by
        // the cleanup and holds the same per-group diffs. The per-element DCCI READS
        // stay (the counts are cross-core written); the WRITE side is bulk now: the
        // diffs are staged in UB and the 64B-aligned interior goes out as ONE DataCopy
        // (GetPhyAddr yields the base for the alignment split; the DMA path has no
        // Data Cache to flush). Only the head (base .. first 64B boundary) and the
        // tail (the < 8 elements past the last full 64B) stay scalar SetValue, and
        // their flushes are batched into one DataCacheCleanAndInvalid per side instead
        // of one per element: SINGLE_CACHE_LINE on the head's non-aligned base cleans
        // exactly [base, 64B boundary) - the head and nothing before it - while the
        // tail's start is 64B-aligned, so its DCCI cleans the tail's whole line, which
        // the DataCopy region never enters (the head's does not either: it ends at the
        // boundary). Nothing reads the output back inside this launch, so the batched
        // flush only has to land before kernel exit.
        AscendC::GlobalTensor<int32_t> sendCountsGlobal;
        sendCountsGlobal.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(params.ptrGroupListI32));
        AscendC::GlobalTensor<int64_t> expertTokenNumsTensor;
        expertTokenNumsTensor.SetGlobalBuffer(reinterpret_cast<__gm__ int64_t *>(params.ptrExpertTokenNums));

        const uint64_t tokenNumsAddr =
            reinterpret_cast<uint64_t>(expertTokenNumsTensor.GetPhyAddr());
        const uint32_t headElems = static_cast<uint32_t>(
            (((tokenNumsAddr + 63ULL) & ~63ULL) - tokenNumsAddr) / sizeof(int64_t));
        const uint32_t clampedHead = headElems > localExpertNum ? localExpertNum : headElems;
        const uint32_t midElems = (localExpertNum - clampedHead) & ~7U;
        const uint32_t tailElems = localExpertNum - clampedHead - midElems;

        AscendC::LocalTensor<int64_t> midLocal =
            resource.ubBuf.template GetBufferByByte<int64_t>(GMM2::CLEAN_CHUNK_INTS * sizeof(int32_t));
        uint32_t midIdx = 0;
        uint32_t tmpTokenNum = 0;
        for (uint32_t localMoeIndex = 0; localMoeIndex < localExpertNum; ++localMoeIndex) {
            uint32_t tokenNum = FlushAndGetValue<int32_t>(
                sendCountsGlobal, localMoeIndex * params.epRankSize + params.epRankSize - 1);
            int64_t expertTokenNum =
                static_cast<int64_t>(tokenNum) - static_cast<int64_t>(tmpTokenNum);
            tmpTokenNum = tokenNum;
            if (localMoeIndex < clampedHead || localMoeIndex >= clampedHead + midElems) {
                expertTokenNumsTensor.SetValue(localMoeIndex, expertTokenNum);
            } else {
                midLocal.SetValue(midIdx, expertTokenNum);
                midIdx += 1;
            }
        }
        if (midElems > 0) {
            // UB scalar stores -> MTE3, the same handoff id/pattern as the gmm1
            // kernel's StoreStatePairFlippedByDma.
            AscendC::SetFlag<AscendC::HardEvent::S_MTE3>(0);
            AscendC::WaitFlag<AscendC::HardEvent::S_MTE3>(0);
            AscendC::DataCopy(expertTokenNumsTensor[clampedHead], midLocal, midElems);
        }
        if (clampedHead > 0) {
            AscendC::DataCacheCleanAndInvalid<int64_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                              AscendC::DcciDst::CACHELINE_OUT>(
                expertTokenNumsTensor[0]);
        }
        if (tailElems > 0) {
            AscendC::DataCacheCleanAndInvalid<int64_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                                              AscendC::DcciDst::CACHELINE_OUT>(
                expertTokenNumsTensor[clampedHead + midElems]);
        }
    }

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
        // The gmm2C region is allocated iff moeExpertNumPerRank != 1 (SetWorkSpace), and
        // params.problemCount IS that value, so gate the dedicated C buffer on the same
        // condition the host allocates it under: if this variant ever ran with a single
        // routed expert, gmGmm2C would sit at workspace offset 0 and the C frontier would
        // overwrite the token buffers there - this falls back to the old swap-region C
        // location instead.
        const bool kMovingForward =
            GMM2::MOVING_FORWARD && ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) != 0) && params.problemCount != 1;

        AscendC::GlobalTensor<ElementC> gmC;
        // Moving forward: C lives in its own buffer - written while the gmm1 quant may still be
        // reading swiglu output, which its old location (the swap region) would overrun.
        gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(
            kMovingForward ? params.ptrC : params.ptrWorkspace));
        if constexpr (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) {
            // shared expert data is in the front of the workspace
            gmGroupOffsetC += params.sharedGmm2ProblemShape.m() * params.sharedGmm2ProblemShape.n();
        }

        uint32_t startCoreIdx = 0;
        // Publish scratch at a fixed high UB offset; the AIC side of this kernel stages
        // nothing else in UB. count resets per launch via the aggregate assignment.
        aicSetFunc = {syncGmAddr + GMM2::SOFT_SYNC_OFFSET, static_cast<uint8_t>(AscendC::GetBlockIdx()),
                      resource.ubBuf.template GetBufferByByte<int32_t>(180 * 1024)};
        // currentM reads need no separate ready gate: each group's WaitGmm2QuantReady
        // below chains through the notify -> worker announces -> send cores' announces,
        // which land after the LAST send core's currentM row for that group (one core's
        // FIFO - its announce also carries the publish row).
        __gm__ int32_t *groupMBase = Gmm2GroupMTable(params.ptrGroupList, params.problemCount);
        for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
            if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                gmB.SetGlobalBuffer(reinterpret_cast<__gm__ ElementB *>(
                        gmBlistTensorDesc.GetDataPtr<int32_t>(groupIdx)));
            }
            uint32_t currentM;
            if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) != 0) {
                // Deep fuse: the group size comes from the currentM table (this AIC's
                // private 32B cell; written by gmm1's LAST send core before its group
                // announce). groupList is only written by the late cleanup, after gmm2.
                if (kMovingForward) {
                    // Wait until every gmm1 quant worker has announced this group's quant output
                    // (x2/x2Scale ready; also implies the group's gmm1 MMADs are done, so the
                    // x1/x1Scale rows this quant output overwrites were consumed).
                    WaitGmm2QuantReady(groupIdx);
                }
                currentM = GetGroupM(groupIdx, static_cast<uint32_t>(AscendC::GetBlockIdx()), groupMBase);
            } else {
                currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                            : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
            }
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
            if (kMovingForward) {
                // The shared C region sits at the front of the gmm2 C buffer and overlaps the
                // early routed swiglu rows, so the shared MMADs must wait for the shared quant
                // (all routed quants were already waited for in the loop above).
                WaitGmm2QuantReady(params.problemCount);
            }
            gmA.SetGlobalBuffer(params.ptrSharedA);
            gmB.SetGlobalBuffer(params.ptrSharedB);
            gmC.SetGlobalBuffer(reinterpret_cast<__gm__ ElementC *>(
                kMovingForward ? params.ptrC : params.ptrWorkspace));

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
            if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) &&
                          !MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc>::
                              kUseCombineSentinel) {
                if (AscendC::GetSubBlockIdx() == 0) {
                    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(
                        MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                }
            }
            BlockScheduler blockScheduler;
            BlockEpilogue blockEpilogue(resource, combiner->GetCalcInfo());
            // Same gate as the AIC path above: the gmm2C region exists iff
            // moeExpertNumPerRank != 1, and params.problemCount is that value.
            const bool kMovingForward =
                GMM2::MOVING_FORWARD && ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) != 0) && params.problemCount != 1;

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
            // currentM read gating: the a2a side (gmm1's recv/quant cores) inherits a
            // strict gate from its own last swiglu-done wait (all rows landed, FIFO) and
            // the AICs ride the wgq chain; the ReducePermute side (gmm1's send cores,
            // which run gmm1 wait-free under QUANT_ON_RECV_CORE) would otherwise enter a
            // few groups ahead of the row writer and read unpublished rows - it gates
            // each group below on the publish row's own cell.
            __gm__ int32_t *groupMBase = Gmm2GroupMTable(params.ptrGroupList, params.problemCount);
            for (uint32_t groupIdx = 0; groupIdx < params.problemCount; ++groupIdx) {
                uint32_t currentM;
                if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) != 0) {
                    // Deep fuse: same table-based group size as the AIC (this block's private
                    // cell). groupList is written by the late cleanup AFTER gmm2, so reading
                    // it here would race with the writer (and the sizes must stay identical to
                    // the AIC's anyway to keep the soft-sync block/flag pairing mirrored).
                    if (kMovingForward && AscendC::GetSubBlockIdx() == 1) {
                        // ReducePermute side only: the one side with no gmm1-side gate
                        // behind the row writer - see WaitRowPublished.
                        WaitRowPublished(groupIdx);
                    }
                    currentM = GetGroupMAiv(groupIdx,
                                            GMM2::GMM2_GROUP_M_AIV_COL_BASE +
                                                static_cast<uint32_t>(AscendC::GetBlockIdx()),
                                            groupMBase);
                } else {
                    currentM = (groupIdx == 0) ? groupList.GetValue(groupIdx)
                                                : (groupList.GetValue(groupIdx) - groupList.GetValue(groupIdx - 1));
                }
                GemmCoord inGroupProblemShape{currentM, params.problemShape.n(), params.problemShape.k()};

                auto layoutC = layout::RowMajor{currentM, params.problemShape.n()};
                LayoutScale layoutScale = params.layoutScale;
                LayoutPerTokenScale layoutPerTokenScale =
                    params.layoutPerTokenScale.GetTileLayout(inGroupProblemShape.template GetCoordByAxis<0>());
                LayoutD layoutD = params.layoutD.GetTileLayout(inGroupProblemShape.GetCoordMN());
                EpilogueParams epilogueParams;
                __gm__ ElementC *gmCBase = reinterpret_cast<__gm__ ElementC *>(
                    kMovingForward ? params.ptrC : params.ptrWorkspace);
                if constexpr (EXEC_FLAG & EXEC_FLAG_TENSOR_LIST) {
                    gmScalePtr = reinterpret_cast<__gm__ ElementScale*>(
                                    gmScaleListTensor.GetDataPtr<int32_t>(groupIdx));
                    epilogueParams = EpilogueParams {
                            gmCBase + gmGroupOffsetC,
                            gmScalePtr, layoutScale,
                            params.ptrPerTokenScale + gmGroupOffsetPerTokenScale, layoutPerTokenScale,
                            params.ptrD + gmGroupOffsetD, layoutD};
                } else {
                    epilogueParams = EpilogueParams{
                                            gmCBase + gmGroupOffsetC,
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
                    CheckSyncFlag(syncGmAddr + GMM2::SOFT_SYNC_OFFSET, static_cast<uint8_t>(coreIdx), target,
                                      resource.ubBuf.template GetBufferByByte<int32_t>(GMM2::TOP_UB_SCRATCH_OFFSET));
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
                    if constexpr (!MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc>::
                                      kUseCombineSentinel || !(EXEC_FLAG & EXEC_FLAG_DEEP_FUSE)) {
                        AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(
                            MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                    }
                    if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
                        AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(
                            MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
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
                        reinterpret_cast<__gm__ ElementC *>(kMovingForward ? params.ptrC : params.ptrWorkspace),
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
                        CheckSyncFlag(syncGmAddr + GMM2::SOFT_SYNC_OFFSET, static_cast<uint8_t>(coreIdx), target,
                                      resource.ubBuf.template GetBufferByByte<int32_t>(GMM2::TOP_UB_SCRATCH_OFFSET));
                        target += 1;
                        blockEpilogue(0, UINT32_MAX, blockShapeMNK, blockCoordMNK, actualBlockShapeMNK);
                    }
                    if constexpr (MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc>::
                                      kUseCombineSentinel) {
                        // This AIV's whole epilogue share (routed groups + the shared GEMM) is done:
                        // publish it for the cleanup owner's poll. The sibling announces at the
                        // do-while tail, before it enters ProcessCombine, and the poll below is
                        // exact (it spins until every announceCount_ slot carries this launch's
                        // flag), so no sibling-entry rendezvous is needed ahead of it - the SEND
                        // handshake the fold replaced existed only to order that announce, and
                        // the poll supplies the same ordering by waiting for it.
                        combiner->AnnounceEpilogueDone();
                        // Same window-filling as the non-shared deep-fuse path: this rank's
                        // gmm2-dequant-send is complete, run the gmm1 late cleanup while
                        // waiting for the receive side (ProcessCombine on the sibling). The
                        // poll proves every AIV's epilogue share is done before the zeroing
                        // starts; the big cleans stay with the last subblock-0 AIV - every
                        // core's subblock 0 reaches this point, only one of them is the
                        // owner. Nothing the fold touches is cleaned, so the owner's zeroing
                        // runs concurrently with the other cores' folds.
                        combiner->WaitEpiloguesDone();
                        if (AscendC::GetBlockIdx() ==
                            AscendC::GetBlockNum() * AscendC::GetSubBlockNum() - 2) {
                            // Owner-only: the poll above proves every AIV's epilogue share
                            // done, so the whole cleanup - the strided soft-sync slot
                            // sweep included - runs on this one core while the other
                            // subblock-0 AIVs exit.
                            LateStateCleanup(params, true, true);
                        }
                        // Close the sub-block rendezvous the sibling's ProcessCombine tail is
                        // waiting on (CombineAivBarrier there): on the owner this lands only
                        // after the cleanup, so the cleanup fills the window its own sibling
                        // spends folding; on every other subblock 0 it merely releases the
                        // sibling. Mode 1: 仅同步同一个 AI Core 内的两个 AIV.
                        AscendC::CrossCoreSetFlag<1, PIPE_MTE3>(
                            MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                        AscendC::CrossCoreWaitFlag<1>(
                            MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                    } else if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
                        // Handshake variant (ENABLE_COMBINE_DATA_AS_FLAG == 0): the send/receive
                        // rendezvous is intact on this path, so the cleanup keeps its original
                        // framing - announce, then the SEND wait that proves the sibling's
                        // tail-side announce already landed, then the poll.
                        combiner->AnnounceEpilogueDone();
                        AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                        combiner->WaitEpiloguesDone();
                        if (AscendC::GetBlockIdx() ==
                            AscendC::GetBlockNum() * AscendC::GetSubBlockNum() - 2) {
                            LateStateCleanup(params, true, true);
                        }
                        AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                    } else {
                        AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::SEND_SYNC_EVENT_ID);
                        // No poll needed (everything is quiescent by the gmm1 SyncAll), but
                        // the identity owner keeps the big cleans: GROUP_TOKEN_NUM and the
                        // shared-input-quant slot have no other cleaner in this variant.
                        LateStateCleanup(
                            params, AscendC::GetBlockIdx() ==
                                        AscendC::GetBlockNum() * AscendC::GetSubBlockNum() - 2,
                            true);
                        AscendC::CrossCoreWaitFlag(MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                    }
                }
            }
        } while (false);

        // gmm2 moving forward: every deep-fuse AIV publishes the end of its epilogue share
        // into the announce array; the late-cleanup owner polls it (WaitEpiloguesDone) to
        // prove every producer and consumer of the regions LateStateCleanup touches is done.
        // The shared-expert sub-block 0 announces inside the block above instead, right after
        // its shared GEMM epilogue, ahead of the announce poll and the sub-block rendezvous
        // that close that block.
        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            if constexpr ((EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT) == 0) {
                combiner->AnnounceEpilogueDone();
            } else if (AscendC::GetSubBlockIdx() == 1) {
                combiner->AnnounceEpilogueDone();
            }
        }

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
            if constexpr (MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc>::
                              kUseCombineSentinel) {
                // Per-token readiness needs no send/receive split: every vector core but the
                // LAST one takes a slice of the token work. The last AIV is freed from the
                // fold to run the gmm1 late cleanup in the window the others spend folding
                // (the combiner shrank the fold's core count by one, so the freed core's
                // tokens are covered by the rest with no gap and no overlap).
                if (AscendC::GetBlockIdx() ==
                    AscendC::GetBlockNum() * AscendC::GetSubBlockNum() - 1) {
                    // Freed core: spin until every AIV's epilogue-done announce has landed
                    // (one flat DataCopy of the announce array + Sum - see WaitEpiloguesDone),
                    // then clean. The poll is the barrier the cleanup needs: once every
                    // epilogue share is done, every cube has passed every group's
                    // quant-ready wait and every cleaned region has no reader left in this
                    // launch. Nothing the fold touches is cleaned, so the zeroing runs
                    // concurrently with the other cores' folds instead of after them.
                    combiner->WaitEpiloguesDone();
                    LateStateCleanup(params, true, true);
                    // Close the sub-block rendezvous the sibling's ReducePermute tail is
                    // waiting on (see ReducePermute).
                    AscendC::CrossCoreSetFlag<1, PIPE_MTE3>(
                        MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
                    AscendC::CrossCoreWaitFlag<1>(
                        MoeDistributeCombineImpl::RECV_SYNC_EVENT_ID);
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
                combiner->ReducePermute();
                combiner->TPipeSet(nullptr);
                resource.pipe.Destroy();
                if (AscendC::GetSubBlockIdx() == 0) {
                    // Non-sentinel deep fuse (whole-batch handshake variant): keep the fold
                    // on every core, but gate the cleanup behind the same epilogue-done poll.
                    // The owner is the last subblock-0 AIV, as before.
                    combiner->WaitEpiloguesDone();
                    if (AscendC::GetBlockIdx() ==
                        AscendC::GetBlockNum() * AscendC::GetSubBlockNum() - 2) {
                        // Same owner-only shape as the sentinel path's freed core: the
                        // poll above proves every AIV's epilogue share done.
                        LateStateCleanup(params, true, true);
                    }
                }
            }
        } else {
            resource.pipe.Init();
            combiner->TPipeSet(&resource.pipe);
            combiner->Process();
            combiner->TPipeSet(nullptr);
            resource.pipe.Destroy();
            // The old trailing own-slot block lives inside LateStateCleanup now. This path
            // has no gmm1-side work for it (the gmm1 kernel cleans its own state in this
            // variant, and the dispatcher already wrote expertTokenNums), so only the
            // subblock-0 core's own gmm2 soft-sync slot fires - Process()'s WaitDispatch
            // barrier guarantees both sub-blocks' epilogue loops are done reading it.
            if (AscendC::GetSubBlockIdx() == 0) {
                LateStateCleanup(params, false, false);
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
            // AIV: the writer owns its slot AND its running count (the callback is invoked
            // on this same object once per completed block), so the publish is a pure MTE3
            // copy - no read-modify-write and no DCCI per block. AIC: PublishSyncFlag
            // internally falls back to the old scalar RMW (the cube core has neither
            // Duplicate nor LocalTensor SetValue); the count argument is unused there.
            PublishSyncFlag(flagAddr, idx, ++count, scratch);
        }

        __gm__ uint8_t *flagAddr;
        uint8_t idx;
        AscendC::LocalTensor<int32_t> scratch;
        mutable int32_t count{0};  // int32 word-0 value, same type on both core paths
    };

    AicSetFunc aicSetFunc;

    AscendC::GlobalTensor<GM_ADDR> epWinContext_;
    __gm__ HcclOpResParam *winContext_;
    GM_ADDR syncGmAddr;
    Arch::Resource<ArchTag> resource;
};

}  // namespace Catlass::Gemm::Kernel

#endif  // ACT_GEMM_KERNEL_GROUPED_MATMUL_M_PER_TOKEN_DEQUANT_MULTISTAGE_WORKSPACE_HPP
