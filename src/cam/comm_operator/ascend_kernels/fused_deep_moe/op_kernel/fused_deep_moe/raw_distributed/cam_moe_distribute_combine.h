/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add combine kernel implement
 * Create: 2025-07-21
 * Note:
 * History: 2025-07-21 add combine kernel implement
 */
#ifndef CAM_MOE_DISTRIBUTE_COMBINE_H
#define CAM_MOE_DISTRIBUTE_COMBINE_H
#define OPT_RANK_OFFSET 512

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "../../fused_deep_moe_base.h"
#include "../../fused_deep_moe_tiling.h"
#include "../fused_deep_moe_utils.h"

using namespace Cam;
namespace MoeDistributeCombineImpl {
constexpr uint8_t BUFFER_NUM = 2;  // multi-buf
constexpr uint32_t STATE_OFFSET = 512;
constexpr uint32_t STATE_SIZE = 1024 * 1024;  // 1M
constexpr uint32_t RANK_SIZE_ON_WIN_512 = 512 * 1024;
constexpr uint32_t RANK_SIZE_ON_WIN_256 = 256 * 1024;
constexpr uint32_t TP_RANK_SIZE_ON_WIN = 0;
constexpr uint32_t UB_ALIGN = 32;
constexpr uint32_t SELF_STATE_OFFSET = 256 * 1024;
// One 512B line per vector core instead of 128B. This slot is read-modify-written by every AIV across
// this kernel, the gmm1 kernel and dispatch, so at a 128B stride four consecutive cores land on one line
// and invalidate each other. The region above is unused until STATE_WIN_OFFSET. The stride must match the
// other two files exactly or they will address different words and the parity will diverge.
constexpr uint32_t SELF_STATE_SLOT_INTS = 512 / sizeof(int32_t);
constexpr uint8_t EP_DOMAIN = 0;
constexpr uint8_t TP_DOMAIN = 1;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint16_t SEND_SYNC_EVENT_ID = 6;
constexpr uint16_t RECV_SYNC_EVENT_ID = 7;
// gmm2-moving-forward epilogue-done announce array: one 32B slot per vector core at 800KB of
// the status window - above the band-1 self-state slots (they end at 768KB + aivNum * 512B,
// 792KB for the 48 AIVs of this 24-AI-core part) and below the 900KB state cells. The offset
// is fixed, not dataState-shifted: both halves of the window leave [792KB, 900KB) untouched,
// so the array survives launch-to-launch without colliding with either band. It is never
// cleaned - the poll relies on the per-launch flag parity instead (see WaitEpiloguesDone).
// The band's other fixed occupant is the gmm2 quant-ready notify slots at 802KB (right after
// this array, see NOTIFY_GMM2_SOFT_SYNC_OFFSET in the gmm1/gmm2 kernels).
constexpr uint64_t ANNOUNCE_EPILOGUE_OFFSET = 800 * 1024;
constexpr uint32_t ANNOUNCE_SLOT_FLOATS = 8;  // one 32B DataCopy block per slot

// Combine data-as-flag.
//
// A token occupies h * sizeof(ExpandXType) bytes of the receive region, cut into whole 512B blocks by
// the gmm2 N tile width (256 bf16 elements; tiling rejects any h that is not a multiple of it). This
// rank's gmm1 primes the last 32B of every block with CombineDataAsFlag::SENTINEL_FLAG, and a peer's
// gmm2 epilogue writes the block's payload densely, overwriting those bytes. So "the tail is no longer
// the sentinel" means "this block has landed": no counter, no separate flag word, and no ordering
// between a data write and a flag write.
//
// The layout costs nothing -- the sentinel sits in bytes the payload overwrites anyway, so
// expertPerSizeOnWin_ and every other stride are unchanged.
//
// Set to 0 to restore the previous whole-batch SetStatus/WaitDispatch handshake. Both paths stay in the
// file so a regression can be attributed by rebuilding with this one constant changed.
#define ENABLE_COMBINE_DATA_AS_FLAG 1

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

using namespace AscendC;

struct CombineCalcInfo {
    uint64_t expertPerSizeOnWin_;
    uint32_t epRankId_;
    uint32_t epWorldSize_;
    uint32_t moeExpertPerRankNum_;
    uint32_t axisH_;
    uint32_t moeSendNum_;
    GM_ADDR epSendCount_;
    __gm__ HcclOpResParam *epWinContext_;
    uint64_t winDataSizeOffset_;
};

template <TemplateMC2TypeClass>
class CamMoeDistributeCombine {
public:
    // Both deep-fuse paths poll per-slot readiness. Shared execution assigns combine only to sub-block 1.
    static constexpr bool kUseCombineSentinel =
        (ENABLE_COMBINE_DATA_AS_FLAG != 0) && ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) != 0);

    __aicore__ inline CamMoeDistributeCombine(){};
    __aicore__ inline void Init(GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount,
                                GM_ADDR tpSendCount, GM_ADDR scales, GM_ADDR xActiveMask, GM_ADDR XOut,
                                GM_ADDR workspaceGM, TPipe *pipe, const FusedDeepMoeTilingData *tilingData);
    __aicore__ inline void Process();
    __aicore__ inline void AllToAllSend();
    __aicore__ inline void ReducePermute();
    __aicore__ inline void ProcessCombine();
    __aicore__ inline void CombineAivBarrier();
    // gmm2 moving forward: per-AIV epilogue-done announce / cleanup-owner poll (deep fuse)
    __aicore__ inline void AnnounceEpilogueDone();
    __aicore__ inline void WaitEpiloguesDone();

    __aicore__ inline CombineCalcInfo &GetCalcInfo()
    {
        return calcInfo_;
    }

    __aicore__ inline void TPipeSet(AscendC::TPipe *pipe)
    {
        pipe_barrier(PIPE_ALL);
        tpipe_ = pipe;
    }

private:
    __aicore__ inline void InitStatusTargetSum();
    __aicore__ inline void AlltoAllBuffInit();
    __aicore__ inline void ReduceScatterTrans();
    __aicore__ inline void SetWaitTpStatusAndDisPatch();
    __aicore__ inline void CustomAdd(LocalTensor<ExpandXType> &dst, LocalTensor<ExpandXType> &src0,
                                     LocalTensor<ExpandXType> &src1, uint32_t dataCnt);
    __aicore__ inline void ExpertAlltoAllDispatchInnerCopyAdd(uint32_t tokenNumLoop, uint32_t srcStartTokenIdx,
                                                              uint32_t ep, uint32_t expertIdx);
    __aicore__ inline void ExpertAlltoAllDispatchCopyAdd();
    __aicore__ inline void LocalWindowCopy();
    __aicore__ inline void BuffInit();
    __aicore__ inline void SplitCoreCal();
    __aicore__ inline void SetStatus();
    __aicore__ inline void WaitDispatch();
    __aicore__ inline bool CombineSlotReady(GM_ADDR slotAddr);
    __aicore__ GM_ADDR GetWinAddrByRankId(const int32_t rankId, const uint8_t domain, const uint8_t expertLocalId = 0U)
    {
        if (domain == EP_DOMAIN) {
            return (GM_ADDR)((epRankId_ == rankId)
                                 ? epWinContext_->localWindowsIn
                                 : ((HcclRankRelationResV2 *)(epWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsIn) +
                   winDataSizeOffset_ + expertLocalId * expertPerSizeOnWin_ + rankId * OPT_RANK_OFFSET;
        } else {
            return (GM_ADDR)((tpRankId_ == rankId)
                                 ? tpWinContext_->localWindowsIn
                                 : ((HcclRankRelationResV2 *)(tpWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsIn) +
                   winDataSizeOffset_ + rankId * OPT_RANK_OFFSET;
        }
    }

    __aicore__ GM_ADDR GetWinStateAddrByRankId(const int32_t rankId, const uint8_t domain)
    {
        if (domain == EP_DOMAIN) {
            return (GM_ADDR)((epRankId_ == rankId)
                                 ? epWinContext_->localWindowsExp
                                 : ((HcclRankRelationResV2 *)(epWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsExp) +
                   dataState_ * WIN_STATE_OFFSET;
        } else {
            return (GM_ADDR)((tpRankId_ == rankId)
                                 ? tpWinContext_->localWindowsExp
                                 : ((HcclRankRelationResV2 *)(tpWinContext_->remoteRes[rankId].nextDevicePtr))
                                       ->windowsExp) +
                   dataState_ * WIN_STATE_OFFSET;
        }
    }

    __aicore__ inline uint32_t MIN(uint32_t x, uint32_t y)
    {
        return (x < y) ? x : y;
    }

    __aicore__ static void DoCombineRecv(void *ptr)
    {
        auto *combiner = (CamMoeDistributeCombine<TemplateMC2TypeFunc> *)ptr;
        combiner->ReducePermute();
    }

    TPipe *tpipe_{nullptr};
    GlobalTensor<ExpandXType> expandXGM_;
    GlobalTensor<ExpandIdxType> expertIdsGM_;
    GlobalTensor<ExpandIdxType> expandIdxGM_;
    GlobalTensor<ExpandIdxType> epSendCountGM_;
    GlobalTensor<ExpandIdxType> tpSendCountGM_;
    GlobalTensor<float> expandScalesGM_;
    GlobalTensor<bool> xActiveMaskGM_;
    GlobalTensor<ExpandXType> expandOutGlobal_;
    GlobalTensor<ExpandXType> rankWindow_;
    GlobalTensor<int32_t> rankStates_;
    GlobalTensor<float> epStatusSpaceGlobalTensor_;
    GlobalTensor<float> tpStatusSpaceGlobalTensor_;
    GlobalTensor<ExpandXType> tpRankWindow_;
    GlobalTensor<ExpandXType> rowTmpGlobal_;
    GM_ADDR workspaceGM_;
    GM_ADDR epWindowGM_;
    GM_ADDR epStatusSpaceGm_;
    GM_ADDR tpWindowGM_;
    GM_ADDR tpStatusSpaceGm_;
    GM_ADDR stateGM_;

    LocalTensor<ExpandXType> winTpSendCountTensor_;
    LocalTensor<ExpandXType> gmTpSendCountTensor_;
    LocalTensor<ExpandXType> outTensor_;
    LocalTensor<float> winTpSendCountFloatTensor_;
    LocalTensor<float> gmTpSendCountFloatTensor_;
    LocalTensor<ExpandIdxType> epSendCountLocal_;

    CombineCalcInfo calcInfo_;
    uint32_t axisBS_{0};
    uint32_t axisMaxBs_{0};
    uint32_t axisBsAlignSize_{0};
    uint64_t activeMaskBsCnt_{0};
    uint32_t axisH_{0};
    uint32_t axisK_{0};
    uint32_t aivNum_{0};
    uint32_t epWorldSize_{0};
    uint32_t tpWorldSize_{0};
    uint32_t epRankId_{0};
    uint32_t tpRankId_{0};
    uint32_t coreIdx_{0};  // aiv id
    uint32_t RankNum_{0};
    uint32_t moeExpertNum_{0};
    uint32_t moeExpertPerRankNum_{0};
    uint32_t moeSendNum_{0};  // moeExpertPerRankNum_ * epWorldSize_
    uint32_t tpScatterNum_{0};
    uint32_t firstTpTokenEndIdx_{0};
    uint32_t firstTpTokenEndOffset_{0};
    uint32_t endTok_{0};
    __gm__ HcclOpResParam *epWinContext_{nullptr};
    __gm__ HcclOpResParam *tpWinContext_{nullptr};
    uint32_t epDataOffsetOnWin_{0};
    uint32_t tpDataOffsetOnWin_{0};
    uint32_t epStateOffsetOnWin_{0};
    uint32_t tpStateOffsetOnWin_{0};
    uint32_t axisHFloatSize_{0};
    uint32_t axisHExpandXTypeSize_{0};
    uint32_t bsKNum_{0};
    uint32_t startRankId_{0};
    uint32_t endRankId_{0};
    uint32_t sendRankNum_{0};
    uint32_t ubSize_{0};
    uint32_t dataState_{0};
    uint32_t stateOffset_{0};
    uint64_t winDataSizeOffset_{0};
    uint64_t expertPerSizeOnWin_{0};
    uint64_t totalWinSize_{0};
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> moeQueue_;
    TQue<QuePosition::VECIN, 1> moeSumQueue_;
    // Keep sparse tail transfers separate from payload transfers: both are MTE2-to-V, and a shared
    // event can let a payload consumer observe a poll transfer instead of its own data.
    TQue<QuePosition::VECIN, 1> combineTailQueue_;
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> gmTpSendCountQueue_;
    TQue<QuePosition::VECIN, 1> gmTpSendCountInQueue_;
    TQue<QuePosition::VECIN, 1> winTpSendCountInQueue_;
    TQue<QuePosition::VECOUT, 1> xOutQueue_;
    TBuf<> readStateBuf_;
    TBuf<> expertIdsBuf_;
    TBuf<> expandScalesBuf_;
    TBuf<> rowTmpFloatBuf_;
    TBuf<> sumFloatBuf_;
    TBuf<> mulBuf_;
    TBuf<> sendCountBuf_;
    TBuf<> indexCountsBuf_;
    TBuf<> winTpSendCountFloatBuf_;
    TBuf<> gmTpSendCountFloatBuf_;
    TBuf<> tokenBuf_;
    TBuf<> statusBuf_;
    TBuf<> gatherMaskOutBuf_;  // gather mask output buf
    TBuf<> gatherTmpBuf_;
    TBuf<> statusSumOutBuf_;
    TBuf<> xActMaskTBuf_;
    TBuf<> xActMaskCastTBuf_;
    TBuf<> xActMaskSumTBuf_;
    // Padded tail words and one aligned comparison mask per 64-int32 repeat.
    TBuf<> combinePollBuf_;
    float sumTarget_{0.0};
    int32_t epStateValue_;
    // gmm2 moving forward: per-launch announce flag (1.0f / 2.0f, same parity source as
    // sumTarget_) and the ABSOLUTE AIV count. The fold's aivNum_ is shrunk by one on the
    // sentinel path (the last AIV is freed to run the gmm1 late cleanup), so the announce
    // array - which every AIV writes into - cannot be indexed or sized from aivNum_.
    float announceFlag_{0.0f};
    uint32_t announceCount_{0};
};

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::Init(
    GM_ADDR expandX, GM_ADDR expertIds, GM_ADDR expandIdx, GM_ADDR epSendCount, GM_ADDR tpSendCount, GM_ADDR scales,
    GM_ADDR xActiveMask, GM_ADDR XOut, GM_ADDR workspaceGM, TPipe *pipe, const FusedDeepMoeTilingData *tilingData)
{
    tpipe_ = pipe;
    coreIdx_ = GetBlockIdx();
    epRankId_ = tilingData->fusedDeepMoeInfo.epRankId;
    auto contextGM0 = AscendC::GetHcclContext<HCCL_GROUP_ID_0>();
    epWinContext_ = (__gm__ HcclOpResParam *)contextGM0;
    GlobalTensor<int32_t> selfDataStatusTensor;
    GM_ADDR statusDataSpaceGm = (GM_ADDR)epWinContext_->localWindowsExp;
    selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        // Deep fuse: statically the window half/band OPPOSITE of the dispatch side, which
        // hardcodes 0 in the gmm1 kernel ctor. The old read+flip here plus gmm1's own
        // read+flip hit the SAME 900KB cell twice per launch, so dataState_ was effectively
        // constant already; making it explicit drops two GM round trips per AIV and the
        // dependency on the cell's leftover value. The two flips must be removed as a PAIR -
        // keeping only one would flip the cell once per launch and alternate the window
        // halves across layers (fast rank's layer-N+1 dispatch writes vs slow rank's
        // still-reading layer-N combine). The 256KB self-state flip in InitStatusTargetSum
        // stays: its cell lives in the band selected here and alternates the status flag
        // values per launch, which is what keeps WaitDispatch from being satisfied by the
        // previous launch's stale flags.
        // Shallow mode keeps the read+flip: there it pairs with the dispatcher's own flip
        // (same double-flip -> constant semantics).
        dataState_ = 1;
    } else {
        dataState_ = FlushAndSpinValue<int32_t>(selfDataStatusTensor, coreIdx_ * UB_ALIGN);
    }
    pipe_barrier(PIPE_ALL);

    workspaceGM_ = workspaceGM;
    expandXGM_.SetGlobalBuffer((__gm__ ExpandXType *)expandX);
    expertIdsGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expertIds);
    expandIdxGM_.SetGlobalBuffer((__gm__ ExpandIdxType *)expandIdx);
    epSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)epSendCount);
    expandScalesGM_.SetGlobalBuffer((__gm__ float *)scales);
    xActiveMaskGM_.SetGlobalBuffer((__gm__ bool*)xActiveMask);
    expandOutGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)XOut);
    axisBS_ = tilingData->fusedDeepMoeInfo.bs;
    activeMaskBsCnt_ = axisBS_;
    axisH_ = tilingData->fusedDeepMoeInfo.h;
    axisK_ = tilingData->fusedDeepMoeInfo.k;
    // Token work is split over every vector core once readiness is per-token: the sentinel poll and the
    // fold for a token are independent of every other token, so there is no reason to keep half the
    // cores idle waiting on a batch-wide signal. The non-sentinel paths still hand the work to one
    // sub-block (see gmm2), so they keep the old count and index.
    announceCount_ = AscendC::GetBlockNum() * AscendC::GetSubBlockNum();
    if constexpr (kUseCombineSentinel && !(EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT)) {
        // gmm2 moving forward: the LAST AIV is freed from the fold to run the gmm1 late
        // cleanup while the others fold (see the gmm2 kernel's AIV path). The fold's token
        // ranges are contiguous over aivNum_, so shrinking the divisor by one hands the
        // freed core's tokens to the remaining cores with no gap and no overlap; the freed
        // core itself never enters LocalWindowCopy, and the epilogue-done announce array
        // still indexes all announceCount_ slots. The shared variant keeps the AIC-level
        // count below: its fold runs on sub-block 1 only, and its cleanup owner is the last
        // core's sub-block 0, which was never a fold worker to free.
        aivNum_ = announceCount_ - 1;
    } else if constexpr (EXEC_FLAG & (EXEC_FLAG_DEEP_FUSE | EXEC_FLAG_SHARED_EXPERT)) {
        aivNum_ = tilingData->fusedDeepMoeInfo.aicNum;
    } else {
        aivNum_ = tilingData->fusedDeepMoeInfo.aivNum;
    }
    ubSize_ = tilingData->fusedDeepMoeInfo.totalUbSize;
    moeExpertNum_ = tilingData->fusedDeepMoeInfo.moeExpertNum;
    moeExpertPerRankNum_ = tilingData->fusedDeepMoeInfo.moeExpertNumPerRank;
    epWorldSize_ = tilingData->fusedDeepMoeInfo.epRankSize;
    axisMaxBs_ = tilingData->fusedDeepMoeInfo.globalBs / epWorldSize_;
    moeSendNum_ = epWorldSize_ * moeExpertPerRankNum_;
    tpWorldSize_ = 1;
    tpRankId_ = 0;
    totalWinSize_ = tilingData->fusedDeepMoeInfo.totalWinSize;
    stateOffset_ = (moeSendNum_ > 512) ? (STATE_OFFSET / 2) : STATE_OFFSET;
    expertPerSizeOnWin_ =
        static_cast<uint64_t>(axisMaxBs_) * static_cast<uint64_t>(axisH_) * static_cast<uint64_t>(sizeof(ExpandXType));
    winDataSizeOffset_ = static_cast<uint64_t>(dataState_) * static_cast<uint64_t>(moeSendNum_) * expertPerSizeOnWin_;
    epWindowGM_ = GetWinAddrByRankId(epRankId_, EP_DOMAIN);
    epStatusSpaceGm_ = GetWinStateAddrByRankId(epRankId_, EP_DOMAIN);
    epStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)epStatusSpaceGm_);
    epDataOffsetOnWin_ = epRankId_ * moeExpertPerRankNum_ * static_cast<uint32_t>(expertPerSizeOnWin_);
    epStateOffsetOnWin_ = epRankId_ * stateOffset_;
    axisHFloatSize_ = axisH_ * sizeof(float);
    axisHExpandXTypeSize_ = axisH_ * sizeof(ExpandXType);
    bsKNum_ = axisBS_ * axisK_;

    if constexpr (IsNeedReduceScatter) {
        tpSendCountGM_.SetGlobalBuffer((__gm__ int32_t *)tpSendCount);
        tpWindowGM_ = GetWinAddrByRankId(tpRankId_, TP_DOMAIN);
        tpStatusSpaceGm_ = GetWinStateAddrByRankId(tpRankId_, TP_DOMAIN);
        tpStatusSpaceGlobalTensor_.SetGlobalBuffer((__gm__ float *)tpStatusSpaceGm_);
        tpDataOffsetOnWin_ = tpRankId_ * TP_RANK_SIZE_ON_WIN;
        tpStateOffsetOnWin_ = tpRankId_ * stateOffset_;
        uint32_t tpScatterRankWinOffset = (tpRankId_ == 0) ? TP_RANK_SIZE_ON_WIN : 0;
        GM_ADDR rankGM = tpWindowGM_ + tpScatterRankWinOffset;
        tpRankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    }

    InitStatusTargetSum();
    if constexpr (kUseCombineSentinel && !(EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT)) {
        // The non-shared fold covers aivNum_ = aivNum - 1 cores, indexed by the raw AIV id;
        // the freed last AIV never enters the fold (the gmm2 kernel routes it to the cleanup
        // instead). The shared fold keeps the AIC-level index below: it runs on sub-block 1
        // of every core, one worker per core.
        coreIdx_ = AscendC::GetBlockIdx();
    } else if constexpr (EXEC_FLAG & (EXEC_FLAG_DEEP_FUSE | EXEC_FLAG_SHARED_EXPERT)) {
        coreIdx_ = AscendC::GetBlockIdx() / AscendC::GetSubBlockNum();
    }
    SplitCoreCal();

    calcInfo_.epRankId_ = epRankId_;
    calcInfo_.epWorldSize_ = epWorldSize_;
    calcInfo_.expertPerSizeOnWin_ = expertPerSizeOnWin_;
    calcInfo_.moeExpertPerRankNum_ = moeExpertPerRankNum_;
    calcInfo_.axisH_ = axisH_;
    calcInfo_.moeSendNum_ = moeSendNum_;
    calcInfo_.epSendCount_ = epSendCount;
    calcInfo_.epWinContext_ = epWinContext_;
    calcInfo_.winDataSizeOffset_ = winDataSizeOffset_;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::InitStatusTargetSum()
{
    // ep state. Probe mirrors the dispatch side's "dispatch-gmm1 aiv-init-state": this
    // flip alternates the status flag values per launch; E carries the parity read this
    // launch (state: 0/1) so the profile shows the per-iteration alternation directly.
    // The old scalar pair paid a DCCI line read plus a DCCI line flush per AIV; the copy
    // form reads the whole 32B block with ONE MTE2, flips field 0 and writes it back
    // with ONE MTE3 - two L2 block ops, no flush. The flip is staged with Duplicate
    // (word 0 is the only field anything reads). Both cross-pipe handoffs (MTE2->S for
    // the scalar read, V->MTE3 for the staged write) are SetFlag/WaitFlag pairs on
    // SOFT_SYNC_EVENT_ID (7): this runs right after the gmm1 epilogue, which pre-Sets
    // the small ids of several directions for later consumption, so a small shared id
    // could be falsely notified and the copy would read unflushed UB. tpipe_ is still
    // null in both modes (TPipeSet only runs in the combine phase, and the shallow
    // caller's dispatcher pipe is destroyed before this Init), so a small local TPipe
    // owns the staging; the trailing same-pipe MTE3 barrier drains the copy before
    // Destroy frees the UB.
    AscendC::TPipe localPipe;
    localPipe.Reset();
    AscendC::TBuf<> stateBuf;
    localPipe.InitBuffer(stateBuf, UB_ALIGN);
    AscendC::LocalTensor<int32_t> stateLocal = stateBuf.Get<int32_t>();
    GlobalTensor<int32_t> selfStatusTensor;
    selfStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(epStatusSpaceGm_ + SELF_STATE_OFFSET));
    // MTE block flip on this tree's 512B self-state stride (SELF_STATE_SLOT_INTS), not the
    // gmf line's 128B UB_ALIGN: in shallow mode the cell must coincide with the dispatcher's
    // own flip (aivId_ * SELF_STATE_SLOT_INTS, raw block idx both) so the pair keeps its
    // double-flip -> constant semantics; a mixed stride would leave half the cells single-
    // flipped and alternating, and the dispatcher's per-core flag values would stop agreeing.
    // Deep fuse keeps the same stride for uniformity, where the cell is combine-private in
    // the band-1 half anyway and flips once per launch (alternation).
    AscendC::DataCopy(stateLocal, selfStatusTensor[coreIdx_ * SELF_STATE_SLOT_INTS], 8UL);
    AscendC::SetFlag<AscendC::HardEvent::MTE2_S>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    AscendC::WaitFlag<AscendC::HardEvent::MTE2_S>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    int32_t state = stateLocal.GetValue(0);
    sumTarget_ = state == 0 ? 1.0f : 0.0f;
    epStateValue_ = state == 0 ? 0x3F800000 : 0;
    // gmm2 moving forward: the epilogue-done announce flag rides the same per-launch parity.
    // 1.0f / 2.0f (not 1.0f / 0.0f) so a slot still holding the previous launch's flag can
    // never contribute to this launch's announce sum - see WaitEpiloguesDone.
    announceFlag_ = state == 0 ? 1.0f : 2.0f;
    AscendC::Duplicate<int32_t>(stateLocal, state == 0 ? 0x3F800000 : 0, 8);
    AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    AscendC::DataCopy(selfStatusTensor[coreIdx_ * SELF_STATE_SLOT_INTS], stateLocal, 8UL);
    AscendC::PipeBarrier<PIPE_MTE3>();
    localPipe.Destroy();
}

// gmm2 moving forward: publish the end of this AIV's whole epilogue share (routed groups and,
// on the shared-expert sub-block 0, the shared GEMM epilogue) into its private 32B slot of the
// announce array - one MTE3 DataCopy, the L2 path, so 48 writers never contend on a DCCI line
// and no atomic counter line exists to serialize them. The value alternates per launch with
// the self-state parity, which is what spares the array a per-launch clean. tpipe_ is still
// null at every call site (TPipeSet only wraps the fold phases), so a small local TPipe owns
// the staging; the trailing same-pipe MTE3 barrier drains the copy before Destroy frees the
// UB, exactly like InitStatusTargetSum above.
template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::AnnounceEpilogueDone()
{
    AscendC::TPipe localPipe;
    localPipe.Reset();
    AscendC::TBuf<> flagBuf;
    localPipe.InitBuffer(flagBuf, UB_ALIGN);
    AscendC::LocalTensor<float> flagLocal = flagBuf.Get<float>();
    AscendC::Duplicate<float>(flagLocal, announceFlag_, ANNOUNCE_SLOT_FLOATS);
    AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    AscendC::GlobalTensor<float> announceTensor;
    announceTensor.SetGlobalBuffer(
        (__gm__ float *)((GM_ADDR)epWinContext_->localWindowsExp + ANNOUNCE_EPILOGUE_OFFSET));
    AscendC::DataCopy(announceTensor[AscendC::GetBlockIdx() * ANNOUNCE_SLOT_FLOATS], flagLocal,
                      ANNOUNCE_SLOT_FLOATS);
    AscendC::PipeBarrier<PIPE_MTE3>();
    localPipe.Destroy();
}

// The cleanup owner's half of the announce: one flat MTE2 DataCopy pulls the whole array
// (announceCount_ 32B slots, L2 path - no DCCI), GatherMask extracts the first float of each
// slot and Sum folds them, spinning until the sum equals announceCount_ * announceFlag_.
// The comparison is exact and that is load-bearing: every slot holds either this launch's
// flag F or the previous launch's (1.0f / 2.0f alternation), and any mix sums strictly off
// both targets (n*F + (count-n)*F' == count*F only at n == count), so a stale slot can
// neither satisfy the poll early nor mask a late one - and the array needs no clean. A
// first-ever launch reads zeros in the unwritten slots, which likewise cannot reach either
// target. This poll is the barrier the gmm1 late cleanup's zeroing needs: once every AIV's
// epilogue share is done, every cube has passed every group's quant-ready wait, so the
// notify slots (and the rest of the cleaned regions) have no reader left in this launch.
template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::WaitEpiloguesDone()
{
    const uint32_t count = announceCount_;
    const float target = announceFlag_ * static_cast<float>(static_cast<int32_t>(count));
    AscendC::TPipe localPipe;
    localPipe.Reset();
    AscendC::TBuf<> statusBuf;
    AscendC::TBuf<> gatherBuf;
    AscendC::TBuf<> sumBuf;
    AscendC::TBuf<> gatherTmpBuf;
    AscendC::TBuf<> sumTmpBuf;
    localPipe.InitBuffer(statusBuf, count * ANNOUNCE_SLOT_FLOATS * sizeof(float));
    localPipe.InitBuffer(gatherBuf, count * sizeof(float));
    localPipe.InitBuffer(sumBuf, UB_ALIGN);
    localPipe.InitBuffer(gatherTmpBuf, UB_ALIGN);
    localPipe.InitBuffer(sumTmpBuf, UB_ALIGN);
    AscendC::LocalTensor<float> statusTensor = statusBuf.Get<float>();
    AscendC::LocalTensor<float> gatherTensor = gatherBuf.Get<float>();
    AscendC::LocalTensor<float> sumTensor = sumBuf.Get<float>();
    AscendC::LocalTensor<uint32_t> gatherTmpTensor = gatherTmpBuf.Get<uint32_t>();
    AscendC::LocalTensor<uint8_t> sumTmpTensor = sumTmpBuf.Get<uint8_t>();

    gatherTmpTensor.SetValue(0, 1);
    AscendC::GlobalTensor<float> announceTensor;
    announceTensor.SetGlobalBuffer(
        (__gm__ float *)((GM_ADDR)epWinContext_->localWindowsExp + ANNOUNCE_EPILOGUE_OFFSET));
    // The slots are packed 32B to 32B, so the pull is one flat block-strided copy: one burst
    // per slot, blockLen one 32B block, no source gap.
    AscendC::DataCopyParams flatParams{static_cast<uint16_t>(count), 1, 0, 0};
    AscendC::SumParams sumParams{1, count, count};
    uint32_t mask = 1;
    uint64_t rsvdCnt = 0;
    AscendC::SetFlag<AscendC::HardEvent::S_V>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    AscendC::WaitFlag<AscendC::HardEvent::S_V>(CVSoftSync::SOFT_SYNC_EVENT_ID);
    while (true) {
        AscendC::DataCopy(statusTensor, announceTensor, flatParams);
        AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(CVSoftSync::SOFT_SYNC_EVENT_ID);
        AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(CVSoftSync::SOFT_SYNC_EVENT_ID);
        AscendC::GatherMask(gatherTensor, statusTensor, gatherTmpTensor, true, mask,
                            {1, static_cast<uint16_t>(count), 1, 0}, rsvdCnt);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Sum(sumTensor, gatherTensor, sumTmpTensor, sumParams);
        AscendC::SetFlag<AscendC::HardEvent::V_S>(CVSoftSync::SOFT_SYNC_EVENT_ID);
        AscendC::WaitFlag<AscendC::HardEvent::V_S>(CVSoftSync::SOFT_SYNC_EVENT_ID);
        float sum = sumTensor.GetValue(0);
        if (sum > target - 0.5f && sum < target + 0.5f) {
            break;
        }
        SPIN_WAIT_CYCLES();
    }
    localPipe.Destroy();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::BuffInit()
{
    tpipe_->Reset();
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);
    uint32_t sendNumAlign = Ceil(moeSendNum_ * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(sendCountBuf_, sendNumAlign);
    if constexpr (IsNeedReduceScatter) {
        tpipe_->InitBuffer(winTpSendCountInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        tpipe_->InitBuffer(gmTpSendCountInQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        tpipe_->InitBuffer(xOutQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        if constexpr (AscendC::IsSameType<ExpandXType, bfloat16_t>::value) {
            tpipe_->InitBuffer(winTpSendCountFloatBuf_, axisHFloatSize_);
            tpipe_->InitBuffer(gmTpSendCountFloatBuf_, axisHFloatSize_);
            winTpSendCountFloatTensor_ = winTpSendCountFloatBuf_.Get<float>();
            gmTpSendCountFloatTensor_ = gmTpSendCountFloatBuf_.Get<float>();
        }
    } else {
        tpipe_->InitBuffer(gmTpSendCountQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
    }
    epSendCountLocal_ = sendCountBuf_.Get<int32_t>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::AlltoAllBuffInit()
{
    tpipe_->Reset();
    uint32_t bsMulTopkSizeAligned = Ceil(axisBS_ * axisK_ * sizeof(int32_t), UB_ALIGN) * UB_ALIGN;
    tpipe_->InitBuffer(readStateBuf_, UB_ALIGN);
    // Whole-batch WaitDispatch is compiled out on the sentinel path, and these four buffers exist only
    // for that spin. Keep them off this core's UB so the per-token poll does not pay for them.
    if constexpr (!kUseCombineSentinel) {
        tpipe_->InitBuffer(statusBuf_, sendRankNum_ * UB_ALIGN);
    }
    tpipe_->InitBuffer(expertIdsBuf_, bsMulTopkSizeAligned);
    tpipe_->InitBuffer(expandScalesBuf_, bsMulTopkSizeAligned);
    tpipe_->InitBuffer(tokenBuf_, axisH_ * sizeof(ExpandXType));
    tpipe_->InitBuffer(rowTmpFloatBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(mulBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(sumFloatBuf_, axisHFloatSize_);
    tpipe_->InitBuffer(indexCountsBuf_, bsMulTopkSizeAligned);
    tpipe_->InitBuffer(moeSumQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
    if constexpr (!kUseCombineSentinel) {
        tpipe_->InitBuffer(gatherMaskOutBuf_, epWorldSize_ * sizeof(float));
        tpipe_->InitBuffer(gatherTmpBuf_, sizeof(uint32_t));
        tpipe_->InitBuffer(statusSumOutBuf_, sizeof(float));
    }
    // Scratch for an exact int32 sentinel comparison. The tail queue is padded to complete
    // CompareScalar repeats; the poll buffer holds one aligned mask per repeat.
    if constexpr (kUseCombineSentinel) {
        const uint32_t blocks = axisH_ / CombineDataAsFlag::BLOCK_ELEMS;
        const uint32_t tailWords = blocks * CombineDataAsFlag::TAIL_INTS;
        const uint32_t compareRepeats = Ceil(tailWords, 64U);
        const uint32_t paddedTailBytes = compareRepeats * 64U * sizeof(int32_t);
        const uint32_t maskBytes = compareRepeats * UB_ALIGN;
        tpipe_->InitBuffer(combinePollBuf_, maskBytes + UB_ALIGN);
        tpipe_->InitBuffer(combineTailQueue_, 1U, paddedTailBytes);
    }

    if constexpr (EXEC_FLAG & EXEC_FLAG_X_ACTIVE_MASK) {
        axisBsAlignSize_ = Ceil(axisBS_ * sizeof(bool), UB_ALIGN) * UB_ALIGN;
        tpipe_->InitBuffer(xActMaskTBuf_, axisBsAlignSize_);
        tpipe_->InitBuffer(xActMaskCastTBuf_, axisBsAlignSize_ * sizeof(half));
        tpipe_->InitBuffer(xActMaskSumTBuf_, axisBsAlignSize_ * sizeof(half));
        LocalTensor<bool> xActiveMaskTensor = xActMaskTBuf_.Get<bool>();
        LocalTensor<half> tempTensor = xActMaskCastTBuf_.Get<half>();
        LocalTensor<half> sumOutTensor = xActMaskSumTBuf_.Get<half>();
        DataCopyExtParams xActiveMaskParams{1U, static_cast<uint32_t>(axisBS_ * sizeof(bool)), 0U, 0U, 0U};
        DataCopyPadExtParams<bool> xActiveMaskCopyPadParams{false, 0U, 0U, 0U};
        DataCopyPad(xActiveMaskTensor, xActiveMaskGM_, xActiveMaskParams, xActiveMaskCopyPadParams);
        SyncFunc<AscendC::HardEvent::MTE2_V>();
        LocalTensor<int8_t> xActiveMaskInt8Tensor = xActiveMaskTensor.ReinterpretCast<int8_t>();
        Cast(tempTensor, xActiveMaskInt8Tensor, RoundMode::CAST_NONE, axisBS_);
        PipeBarrier<PIPE_V>();
        SumParams params{1, axisBsAlignSize_, axisBS_};
        Sum(sumOutTensor, tempTensor, params);
        SyncFunc<AscendC::HardEvent::V_S>();
        activeMaskBsCnt_ = static_cast<int32_t>(sumOutTensor.GetValue(0));
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::SplitCoreCal()
{
    sendRankNum_ = epWorldSize_ / aivNum_;
    uint32_t remainderRankNum = epWorldSize_ % aivNum_;
    startRankId_ = sendRankNum_ * coreIdx_;
    if (coreIdx_ < remainderRankNum) {
        sendRankNum_++;
        startRankId_ += coreIdx_;
    } else {
        startRankId_ += remainderRankNum;
    }
    endRankId_ = startRankId_ + sendRankNum_;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ReduceScatterTrans()
{
    uint32_t offset = FlushAndGetValue<ExpandIdxType>(tpSendCountGM_, tpRankId_) * axisH_;
    GlobalTensor<ExpandXType> dataCopyInGM = expandXGM_[offset];
    GM_ADDR rankGM = GetWinAddrByRankId(1 - tpRankId_, TP_DOMAIN) + tpDataOffsetOnWin_;
    rankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    uint32_t copyStartIdx = 0;
    if (startRankId_ > 0) {
        copyStartIdx = FlushAndGetValue<ExpandIdxType>(epSendCountGM_, epWorldSize_ + startRankId_ - 1);
    }
    uint32_t copyEndIdx = FlushAndGetValue<ExpandIdxType>(epSendCountGM_, epWorldSize_ + endRankId_ - 1);
    LocalTensor<ExpandXType> tmpUb;
    for (uint32_t tokenNumIdx = copyStartIdx; tokenNumIdx < copyEndIdx; tokenNumIdx++) {
        tmpUb = moeQueue_.AllocTensor<ExpandXType>();
        DataCopy(tmpUb, dataCopyInGM[tokenNumIdx * axisH_], axisH_);
        moeQueue_.EnQue(tmpUb);
        tmpUb = moeQueue_.DeQue<ExpandXType>();
        DataCopy(rankWindow_[tokenNumIdx * axisH_], tmpUb, axisH_);
        moeQueue_.FreeTensor<ExpandXType>(tmpUb);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::SetWaitTpStatusAndDisPatch()
{
    pipe_barrier(PIPE_ALL);
    if (startRankId_ >= epWorldSize_) {
        return;
    }
    if constexpr (IsNeedReduceScatter) {
        uint32_t tpToRankId = 1 - tpRankId_;
        pipe_barrier(PIPE_ALL);
        LocalTensor<float> statusFlagUb = readStateBuf_.Get<float>();
        statusFlagUb(0) = sumTarget_;
        SyncFunc<AscendC::HardEvent::S_MTE3>();
        GlobalTensor<float> tpWindowInstatusFp32Tensor_;
        stateGM_ = GetWinStateAddrByRankId(tpToRankId, TP_DOMAIN) + coreIdx_ * stateOffset_;
        tpWindowInstatusFp32Tensor_.SetGlobalBuffer((__gm__ float *)stateGM_);
        DataCopy<float>(tpWindowInstatusFp32Tensor_, statusFlagUb, 8UL);
        SyncFunc<AscendC::HardEvent::MTE3_S>();
        LocalTensor<float> statusFp32Tensor_ = readStateBuf_.Get<float>();
        float sumOfFlag = static_cast<float>(-1.0);
        uint32_t statusRankOffset = coreIdx_ * stateOffset_ / sizeof(float);
        while (sumOfFlag != sumTarget_) {
            DataCopy<float>(statusFp32Tensor_, tpStatusSpaceGlobalTensor_[statusRankOffset], 8);
            SyncFunc<AscendC::HardEvent::MTE2_S>();
            sumOfFlag = statusFp32Tensor_.GetValue(0);
            SyncFunc<AscendC::HardEvent::S_MTE2>();
        }
    }
    ExpertAlltoAllDispatchCopyAdd();
    SyncFunc<AscendC::HardEvent::MTE3_S>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ExpertAlltoAllDispatchCopyAdd()
{
    if (startRankId_ >= epWorldSize_) {
        return;
    }
    uint32_t curRankExpertNum = 0;
    DataCopyExtParams epSendCntParams;
    curRankExpertNum = moeExpertPerRankNum_;
    epSendCntParams = {1U, static_cast<uint32_t>(moeSendNum_ * sizeof(uint32_t)), 0U, 0U, 0U};
    DataCopyPadExtParams<int32_t> copyPadParams{false, 0U, 0U, 0U};
    DataCopyPad(epSendCountLocal_, epSendCountGM_, epSendCntParams, copyPadParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();
    uint32_t preCount = 0;
    uint32_t startTokenIdx = 0;
    uint32_t curTokenNum = 0;

    for (uint32_t expertIdx = 0U; expertIdx < curRankExpertNum; expertIdx++) {
        uint32_t sendEpCount = endRankId_ - startRankId_;
        for (uint32_t i = 0; i < sendEpCount; ++i) {
            uint32_t ep = startRankId_ + (i + epRankId_) % sendEpCount;
            if ((ep > 0) || (expertIdx > 0U)) {
                preCount = epSendCountLocal_.GetValue(expertIdx * epWorldSize_ + ep - 1);
            } else {
                preCount = 0;
            }
            curTokenNum = epSendCountLocal_.GetValue(expertIdx * epWorldSize_ + ep) - preCount;
            if (curTokenNum == 0) {
                continue;
            }
            startTokenIdx = preCount * axisH_;
            ExpertAlltoAllDispatchInnerCopyAdd(curTokenNum, startTokenIdx, ep, expertIdx);
        }
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ExpertAlltoAllDispatchInnerCopyAdd(
    uint32_t tokenNumLoop, uint32_t srcStartTokenIdx, uint32_t ep, uint32_t expertIdx)
{
    GM_ADDR rankGM = GetWinAddrByRankId(ep, EP_DOMAIN, expertIdx) + epDataOffsetOnWin_;
    rankWindow_.SetGlobalBuffer((__gm__ ExpandXType *)rankGM);
    uint32_t dataCnt = axisH_;
    for (uint32_t loopIdx = 0; loopIdx < tokenNumLoop; loopIdx++) {
        if constexpr (IsNeedReduceScatter) {
            gmTpSendCountTensor_ = gmTpSendCountInQueue_.AllocTensor<ExpandXType>();
            DataCopy(gmTpSendCountTensor_, expandXGM_[srcStartTokenIdx], dataCnt);
            gmTpSendCountInQueue_.EnQue(gmTpSendCountTensor_);

            winTpSendCountTensor_ = winTpSendCountInQueue_.AllocTensor<ExpandXType>();
            DataCopy(winTpSendCountTensor_, tpRankWindow_[srcStartTokenIdx], dataCnt);
            winTpSendCountInQueue_.EnQue(winTpSendCountTensor_);

            gmTpSendCountTensor_ = gmTpSendCountInQueue_.DeQue<ExpandXType>();
            winTpSendCountTensor_ = winTpSendCountInQueue_.DeQue<ExpandXType>();
            outTensor_ = xOutQueue_.AllocTensor<ExpandXType>();

            CustomAdd(outTensor_, winTpSendCountTensor_, gmTpSendCountTensor_, dataCnt);
            gmTpSendCountInQueue_.FreeTensor<ExpandXType>(gmTpSendCountTensor_);
            winTpSendCountInQueue_.FreeTensor<ExpandXType>(winTpSendCountTensor_);
            xOutQueue_.EnQue(outTensor_);

            outTensor_ = xOutQueue_.DeQue<ExpandXType>();
            DataCopy(rankWindow_[loopIdx * dataCnt], outTensor_, dataCnt);
            xOutQueue_.FreeTensor<ExpandXType>(outTensor_);
        } else {
            gmTpSendCountTensor_ = gmTpSendCountQueue_.AllocTensor<ExpandXType>();
            DataCopy(gmTpSendCountTensor_, expandXGM_[srcStartTokenIdx], dataCnt);
            ExpandXType val = expandXGM_[srcStartTokenIdx].GetValue(0);
            gmTpSendCountQueue_.EnQue(gmTpSendCountTensor_);
            gmTpSendCountTensor_ = gmTpSendCountQueue_.DeQue<ExpandXType>();
            DataCopy(rankWindow_[loopIdx * dataCnt], gmTpSendCountTensor_, dataCnt);
            gmTpSendCountQueue_.FreeTensor<ExpandXType>(gmTpSendCountTensor_);
        }
        srcStartTokenIdx += dataCnt;
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::CustomAdd(LocalTensor<ExpandXType> &dst,
                                                                               LocalTensor<ExpandXType> &src0,
                                                                               LocalTensor<ExpandXType> &src1,
                                                                               uint32_t dataCnt)
{
    if constexpr (AscendC::IsSameType<ExpandXType, bfloat16_t>::value) {
        Cast(winTpSendCountFloatTensor_, src0, RoundMode::CAST_NONE, dataCnt);
        Cast(gmTpSendCountFloatTensor_, src1, RoundMode::CAST_NONE, dataCnt);
        pipe_barrier(PIPE_V);
        Add(winTpSendCountFloatTensor_, winTpSendCountFloatTensor_, gmTpSendCountFloatTensor_, dataCnt);
        pipe_barrier(PIPE_V);
        Cast(dst, winTpSendCountFloatTensor_, RoundMode::CAST_ROUND, dataCnt);
    } else {
        Add(dst, src0, src1, dataCnt);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::SetStatus()
{
    pipe_barrier(PIPE_ALL);
    if (startRankId_ >= epWorldSize_) {
        return;
    }

    LocalTensor<int32_t> statusFlagUb = readStateBuf_.Get<int32_t>();
    statusFlagUb.SetValue(0, epStateValue_);
    SyncFunc<AscendC::HardEvent::S_MTE3>();

    for (uint32_t epIdx = startRankId_; epIdx < endRankId_; epIdx++) {
        stateGM_ = GetWinStateAddrByRankId(epIdx, EP_DOMAIN) + epStateOffsetOnWin_;
        rankStates_.SetGlobalBuffer((__gm__ int32_t *)stateGM_);
        DataCopy(rankStates_, statusFlagUb, 8);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::WaitDispatch()
{
    if (startRankId_ < epWorldSize_) {
        LocalTensor<float> statusTensor = statusBuf_.Get<float>();
        LocalTensor<float> gatherMaskOutTensor = gatherMaskOutBuf_.Get<float>();
        LocalTensor<uint32_t> gatherTmpTensor = gatherTmpBuf_.Get<uint32_t>();
        LocalTensor<float> statusSumOutTensor = statusSumOutBuf_.Get<float>();
        PipeBarrier<PIPE_ALL>();

        gatherTmpTensor.SetValue(0, 1);
        uint32_t mask = 1;  // gatherMask + sum
        uint64_t rsvdCnt = 0;
        DataCopyParams intriParams{static_cast<uint16_t>(sendRankNum_), 1,
                                   static_cast<uint16_t>((moeSendNum_ > 512) ? 7 : 15), 0};  // srcStride is 15 blocks
        float sumOfFlag = static_cast<float>(-1.0);
        float minTarget = (sumTarget_ * sendRankNum_) - (float)0.5;
        float maxTarget = (sumTarget_ * sendRankNum_) + (float)0.5;
        SumParams sumParams{1, sendRankNum_, sendRankNum_};
        SyncFunc<AscendC::HardEvent::S_V>();
        while ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
            DataCopy<float>(statusTensor, epStatusSpaceGlobalTensor_[startRankId_ * stateOffset_ / sizeof(float)],
                            intriParams);
            SyncFunc<AscendC::HardEvent::MTE2_V>();
            GatherMask(gatherMaskOutTensor, statusTensor, gatherTmpTensor, true, mask,
                       {1, (uint16_t)sendRankNum_, 1, 0}, rsvdCnt);
            PipeBarrier<PIPE_V>();
            Sum(statusSumOutTensor, gatherMaskOutTensor, sumParams);
            SyncFunc<AscendC::HardEvent::V_S>();
            sumOfFlag = statusSumOutTensor.GetValue(0);
            if ((sumOfFlag < minTarget) || (sumOfFlag > maxTarget)) {
                SPIN_WAIT_CYCLES();
            }
        }
    }

    AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(RECV_SYNC_EVENT_ID);
    AscendC::CrossCoreWaitFlag(RECV_SYNC_EVENT_ID);
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::CombineAivBarrier()
{
    AscendC::CrossCoreSetFlag<1, PIPE_MTE3>(RECV_SYNC_EVENT_ID);
    AscendC::CrossCoreWaitFlag<1>(RECV_SYNC_EVENT_ID);
}

// Poll every int32 word in every sparse tail. A tail is ready only after none of its words still
// carries the sentinel; the payload is fetched separately by LocalWindowCopy after this returns true.
template <TemplateMC2TypeClass>
__aicore__ inline bool CamMoeDistributeCombine<TemplateMC2TypeFunc>::CombineSlotReady(
    GM_ADDR slotAddr)
{
    const uint32_t blocksPerToken = axisH_ / CombineDataAsFlag::BLOCK_ELEMS;
    if (blocksPerToken == 0U) {
        return true;
    }
    static_assert(sizeof(ExpandXType) == 2, "combine sentinel blocks are 256 2-byte elements");
    const uint32_t tailWords = blocksPerToken * CombineDataAsFlag::TAIL_INTS;
    const uint32_t compareRepeats = (tailWords + 63U) / 64U;
    const uint32_t paddedWords = compareRepeats * 64U;
    GlobalTensor<int32_t> tailGM;
    tailGM.SetGlobalBuffer(
        (__gm__ int32_t *)(slotAddr + CombineDataAsFlag::TAIL_OFFSET),
        (static_cast<uint64_t>(blocksPerToken - 1U) * CombineDataAsFlag::BLOCK_BYTES +
         CombineDataAsFlag::TAIL_BYTES) / sizeof(int32_t));

    DataCopyParams tailParams{
        static_cast<uint16_t>(blocksPerToken), 1U,
        static_cast<uint16_t>(CombineDataAsFlag::BLOCK_BYTES / UB_ALIGN - 1U), 0U};
    LocalTensor<int32_t> tailUb = combineTailQueue_.AllocTensor<int32_t>();
    DataCopy(tailUb, tailGM, tailParams);
    combineTailQueue_.EnQue(tailUb);
    tailUb = combineTailQueue_.DeQue<int32_t>();

    LocalTensor<uint8_t> maskBytes = combinePollBuf_.Get<uint8_t>();
    // CompareScalar consumes complete 64-int32 repeats. The queue is padded so the final
    // repeat can be compared without another UB-to-UB transfer; padding cannot match the sentinel.
    if (paddedWords > tailWords) {
        AscendC::Duplicate<int32_t>(
            tailUb[tailWords], static_cast<int32_t>(0), paddedWords - tailWords);
        AscendC::PipeBarrier<PIPE_V>();
    }
    AscendC::SetMaskNorm();
    for (uint32_t repeat = 0; repeat < compareRepeats; ++repeat) {
        AscendC::Duplicate<int32_t>(
            maskBytes[repeat * UB_ALIGN].ReinterpretCast<int32_t>(), 0, UB_ALIGN / sizeof(int32_t));
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::CompareScalar<int32_t, uint8_t>(
            maskBytes[repeat * UB_ALIGN], tailUb[repeat * 64U],
            CombineDataAsFlag::SENTINEL_FLAG, AscendC::CMPMODE::EQ, 64U);
    }
    SyncFunc<AscendC::HardEvent::V_S>();

    LocalTensor<uint32_t> masks = maskBytes.ReinterpretCast<uint32_t>();
    bool ready = true;
    for (uint32_t repeat = 0; repeat < compareRepeats; ++repeat) {
        if (masks.GetValue(repeat * 8U) != 0U || masks.GetValue(repeat * 8U + 1U) != 0U) {
            ready = false;
        }
    }
    combineTailQueue_.FreeTensor<int32_t>(tailUb);
    return ready;
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::LocalWindowCopy()
{
    if (activeMaskBsCnt_ == 0U) {
        return;
    }
    uint32_t beginIndex = 0;
    uint32_t endIndex = 0;
    uint32_t processLen = 0;
    uint32_t tokenOffset = 0;
    if (activeMaskBsCnt_ < aivNum_) {
        uint32_t aivNumPerToken = aivNum_ / activeMaskBsCnt_;
        if (coreIdx_ >= (activeMaskBsCnt_ * aivNumPerToken)) {
            return;
        }
        uint32_t tokenIndex = coreIdx_ / aivNumPerToken;
        processLen = ((axisH_ / UB_ALIGN) / aivNumPerToken) * UB_ALIGN;
        tokenOffset = processLen * (coreIdx_ % aivNumPerToken);
        if ((coreIdx_ % aivNumPerToken) == (aivNumPerToken - 1)) {
            processLen = axisH_ - ((aivNumPerToken - 1) * processLen);
        }
        beginIndex = tokenIndex;
        endIndex = beginIndex + 1U;
    } else {
        uint32_t tokenPerAivNum = activeMaskBsCnt_ / aivNum_;
        uint32_t remainderToken = activeMaskBsCnt_ % aivNum_;
        beginIndex = tokenPerAivNum * coreIdx_;
        if (coreIdx_ < remainderToken) {
            tokenPerAivNum++;
            beginIndex = tokenPerAivNum * coreIdx_;
        } else {
            beginIndex += remainderToken;
        }
        endIndex = beginIndex + tokenPerAivNum;
        processLen = axisH_;
    }
    LocalTensor<ExpandIdxType> expertIdsLocal = expertIdsBuf_.Get<ExpandIdxType>();
    LocalTensor<float> expandScalesLocal = expandScalesBuf_.Get<float>();

    LocalTensor<float> rowTmpFloatLocal = rowTmpFloatBuf_.Get<float>();
    LocalTensor<float> mulBufLocal = mulBuf_.Get<float>();
    LocalTensor<float> sumFloatBufLocal = sumFloatBuf_.Get<float>();

    LocalTensor<ExpandIdxType> indexCountsLocal = indexCountsBuf_.Get<ExpandIdxType>();
    const DataCopyExtParams bskParams = {1U, static_cast<uint32_t>(bsKNum_ * sizeof(uint32_t)), 0U, 0U, 0U};
    const DataCopyPadExtParams<ExpandIdxType> copyPadParams{false, 0U, 0U, 0U};
    const DataCopyPadExtParams<float> copyPadFloatParams{false, 0U, 0U, 0U};

    DataCopyPad(indexCountsLocal, expandIdxGM_, bskParams, copyPadParams);
    DataCopyPad(expertIdsLocal, expertIdsGM_, bskParams, copyPadParams);
    DataCopyPad(expandScalesLocal, expandScalesGM_, bskParams, copyPadFloatParams);
    SyncFunc<AscendC::HardEvent::MTE2_S>();

    for (uint32_t tokenIndex = beginIndex; tokenIndex < endIndex; tokenIndex++) {
        uint32_t index = tokenIndex * axisK_;
        SyncFunc<AscendC::HardEvent::MTE3_V>();
        Duplicate(sumFloatBufLocal, (float)0, axisH_);
        // Which of this token's slots are real: a negative expert id means it did not route there, so
        // there is nothing to wait for and nothing to fold.
        const uint32_t tokenBase = index;
        uint32_t pending = 0;
        for (uint32_t i = 0; i < axisK_; i++) {
            pending |= static_cast<uint32_t>(expertIdsLocal.GetValue(tokenBase + i) >= 0) << i;
        }
        // Fold a slot the moment it lands instead of waiting for the whole topk first.
        //
        // The wait and the fold used to be two phases: every slot had to be ready before the first
        // payload was even fetched. Interleaving them lets a slot's payload transfer and vector work
        // overlap the wait for the slots that have not arrived, so the token's critical path becomes
        // "wait for the last slot" rather than "wait for the last slot, then fold them all".
        //
        // It cannot publish the result early: the fold accumulates into sumFloatBufLocal and the store
        // below still needs every slot, so the output is identical. The win is latency, not work.
        //
        // The rotation matters as much as the early fold. Each pass re-checks only what is still
        // outstanding, so a slot that is already in never sits behind a slot that is slow -- otherwise
        // the eighth slot landing first would still be invisible until the first one arrived.
        while (pending != 0U) {
            for (uint32_t i = 0; i < axisK_; i++) {
                if ((pending & (1U << i)) == 0U) {
                    continue;
                }
                GM_ADDR slotBase = (__gm__ uint8_t *)(epWindowGM_) +
                                   expertPerSizeOnWin_ * expertIdsLocal.GetValue(tokenBase + i) +
                                   indexCountsLocal.GetValue(tokenBase + i) * axisHExpandXTypeSize_;
                if constexpr (kUseCombineSentinel) {
                    // Poll only the sparse tails. Fetch the assigned slice after readiness is known.
                    if (!CombineSlotReady(slotBase)) {
                        continue;
                    }
                }
                pending &= ~(1U << i);

                float scaleVal = expandScalesLocal.GetValue(tokenBase + i);
                GM_ADDR wAddr = slotBase + tokenOffset * sizeof(ExpandXType);
                rowTmpGlobal_.SetGlobalBuffer((__gm__ ExpandXType *)wAddr);
                LocalTensor<ExpandXType> tmpUb = moeSumQueue_.AllocTensor<ExpandXType>();
                DataCopy(tmpUb, rowTmpGlobal_, processLen);
                moeSumQueue_.EnQue(tmpUb);
                tmpUb = moeSumQueue_.DeQue<ExpandXType>();
                Cast(rowTmpFloatLocal, tmpUb, AscendC::RoundMode::CAST_NONE, processLen);
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Muls(mulBufLocal, rowTmpFloatLocal, scaleVal, processLen);
                AscendC::PipeBarrier<PIPE_V>();
                AscendC::Add(sumFloatBufLocal, sumFloatBufLocal, mulBufLocal, processLen);
                moeSumQueue_.FreeTensor<ExpandXType>(tmpUb);
            }
            if constexpr (kUseCombineSentinel) {
                if (pending != 0U) {
                    SPIN_WAIT_CYCLES();
                }
            }
        }
        LocalTensor<ExpandXType> rowTmpLocal = tokenBuf_.Get<ExpandXType>();

        AscendC::PipeBarrier<PIPE_V>();
        LocalTensor<ExpandXType> sumBufLocal = tokenBuf_.Get<ExpandXType>();
        Cast(sumBufLocal, sumFloatBufLocal, AscendC::RoundMode::CAST_RINT, processLen);
        SyncFunc<AscendC::HardEvent::V_MTE3>();
        DataCopy(expandOutGlobal_[tokenIndex * axisH_ + tokenOffset], sumBufLocal, processLen);
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::Process()
{
    SyncAll<true>();
    if constexpr (IsNeedReduceScatter) {
        tpipe_->InitBuffer(moeQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        ReduceScatterTrans();
    }
    if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
        BuffInit();
        SetWaitTpStatusAndDisPatch();
    }
    AlltoAllBuffInit();
    SetStatus();
    WaitDispatch();
    LocalWindowCopy();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::AllToAllSend()
{
    if constexpr (IsNeedReduceScatter) {
        tpipe_->InitBuffer(moeQueue_, BUFFER_NUM, axisHExpandXTypeSize_);
        ReduceScatterTrans();
    }
    BuffInit();
    if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
        SetWaitTpStatusAndDisPatch();
        AlltoAllBuffInit();
    }
    // The deep-fuse path no longer runs here at all (gmm2 hands the work to ReducePermute with every
    // vector core), so the SEND/RECV rendezvous and the status broadcast exist for the TP-attached
    // shallow path only.
    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        if constexpr (!kUseCombineSentinel) {
            AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
            AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
        }
    } else {
        SyncAll<true>();
    }
    if constexpr (!kUseCombineSentinel) {
        SetStatus();
    }
    if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
        if constexpr (!kUseCombineSentinel) {
            AscendC::CrossCoreWaitFlag(RECV_SYNC_EVENT_ID);
        }
    } else {
        SyncAll<true>();
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ReducePermute()
{
    AlltoAllBuffInit();
    // With per-token readiness there is no send/receive split left to rendezvous: every vector core runs
    // here, primes nothing, and only polls the slots it owns. The SEND flag existed solely to keep the
    // send sub-block ahead of the receive sub-block, and the RECV flag to release it once the peer
    // status had been published -- both are what the sentinel replaced.
    if constexpr (!kUseCombineSentinel) {
        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
        } else {
            SyncAll<true>();
        }
    }

    if constexpr (!kUseCombineSentinel) {
        WaitDispatch();
    }
    LocalWindowCopy();

    if constexpr (kUseCombineSentinel) {
        // Mode 1: 仅同步同一个 AI Core 内的两个 AIV
        AscendC::CrossCoreSetFlag<1, PIPE_MTE3>(RECV_SYNC_EVENT_ID);
        AscendC::CrossCoreWaitFlag<1>(RECV_SYNC_EVENT_ID);
    }

    if constexpr (!kUseCombineSentinel) {
        if constexpr (EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) {
            AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
        }
    }
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombine<TemplateMC2TypeFunc>::ProcessCombine()
{
    // Shared deep-fuse combine has no send-side rendezvous. Let sub-block 1 enter slot polling
    // immediately; the receive barrier below runs only after its local copy is complete and still
    // protects sub0's soft-sync cleanup.
    if constexpr (!kUseCombineSentinel || !(EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT)) {
        AscendC::CrossCoreSetFlag<0x0, PIPE_MTE3>(SEND_SYNC_EVENT_ID);
        AscendC::CrossCoreWaitFlag(SEND_SYNC_EVENT_ID);
    }
    if constexpr ((EXEC_FLAG & EXEC_FLAG_DEEP_FUSE) == 0) {
        BuffInit();
        SetWaitTpStatusAndDisPatch();
    }
    AlltoAllBuffInit();
    if constexpr (!kUseCombineSentinel) {
        SetStatus();
        WaitDispatch();
    }
    LocalWindowCopy();
    if constexpr (kUseCombineSentinel && (EXEC_FLAG & EXEC_FLAG_SHARED_EXPERT)) {
        // Pair with shared sub-block 0 before it clears this core's soft-sync state.
        CombineAivBarrier();
    }
}
}  // namespace MoeDistributeCombineImpl

#endif  // CAM_MOE_DISTRIBUTE_COMBINE_IMPL_H
