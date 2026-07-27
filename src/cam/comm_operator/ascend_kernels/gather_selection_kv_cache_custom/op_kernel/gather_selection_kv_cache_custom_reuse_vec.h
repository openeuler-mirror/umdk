/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionKvCacheCustom reuse-vec kernel header
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create GatherSelectionKvCacheCustom reuse-vec kernel header
 */

#ifndef GATHER_SELECTION_KV_CACHE_CUSTOM_REUSE_VEC_H
#define GATHER_SELECTION_KV_CACHE_CUSTOM_REUSE_VEC_H

#include "kernel_operator.h"

namespace GatherSelectionKvCacheCustomNs {
using namespace AscendC;

constexpr int32_t COMPARE_SCALAR_BYTES = 256;
constexpr int32_t COMPARE_SCALAR_NUM = COMPARE_SCALAR_BYTES / static_cast<int32_t>(sizeof(int32_t));
constexpr int32_t ONE_REPEAT_SORT_NUM = 32;
constexpr int32_t COMPARENUM_SIZE = 16;
constexpr int32_t SORT_SCRATCH_ARRAY_NUM = 8;
constexpr int32_t SORT_OFFSET = 4;
constexpr int32_t SORTED_STAT_TOPK_IDX_OFFSET = 3;
constexpr int32_t SORTED_STAT_TOPK_OFFSET = 2;
constexpr int32_t PLAN_ACTION_BUF_OFFSET = 2;
constexpr int32_t MASK_U64_NUM = 2;
constexpr int32_t VECTOR_REPEAT_STRIDE = 8;
constexpr int32_t GATHER_MASK_SRC0_REPEAT_STRIDE = 8;
constexpr int32_t INVALID_STATUS_VALUE = -1;
constexpr float INVALID_FLOAT_VALUE = -1.0f;
constexpr int32_t CUR_SEG_HIT_FLAG = -10;
constexpr int32_t COPY_FROM_SELECTED_DONE_FLAG = -11;
constexpr int32_t COPY_FROM_FULL_FLAG = -1;
constexpr int32_t STATUS_VALID_NUM_EXTRA = 1;

template <typename T>
class GatherSelectionKvCacheCustomReuseVec {
public:
    __aicore__ inline GatherSelectionKvCacheCustomReuseVec(
        TPipe* pipe, const GatherSelectionKvCacheCustomTilingData* tiling)
        : pipe_(pipe), tiling_(tiling)
    {}

    __aicore__ inline void Init(
        GM_ADDR selectionKRoPE, GM_ADDR selectionKvCache, GM_ADDR selectionKvBlockTable,
        GM_ADDR selectionKvBlockStatus, GM_ADDR selectionTopkIndices, GM_ADDR fullKRoPE, GM_ADDR fullKvCache,
        GM_ADDR fullKvBlockTable, GM_ADDR fullKvActualSeq, GM_ADDR selectionKvActualSeq, GM_ADDR workspace)
    {
        blockIdx_ = GetBlockIdx();
        topkAlign_ = CeilAlign(tiling_->topk, static_cast<int64_t>(BLOCK_BYTES / sizeof(int32_t)));
        topkSortAlign_ = CeilAlign(tiling_->topk, static_cast<int64_t>(ONE_REPEAT_SORT_NUM));
        topkOneAlign_ = CeilAlign(tiling_->topk + STATUS_VALID_NUM_EXTRA,
            static_cast<int64_t>(BLOCK_BYTES / sizeof(int32_t)));
        topkOneSortAlign_ = topkSortAlign_ > topkOneAlign_ ? topkSortAlign_ : topkOneAlign_;

        kRopeUbOffset_ = tiling_->kvCacheUbSize / sizeof(T);
        pipe_->InitBuffer(kvCacheQue_, tiling_->buffNum, tiling_->kvCacheUbSize + tiling_->kRopeUbSize);
        pipe_->InitBuffer(selTopKIdxQue_, 1, topkSortAlign_ * sizeof(int32_t));

        selKvBlockTableUb_ = CeilAlign(
            tiling_->selMaxBlockNum * static_cast<int64_t>(sizeof(int32_t)), static_cast<int64_t>(BLOCK_BYTES));
        selKvActSeqUb_ = BLOCK_BYTES;
        selBlockStatUb_ = topkOneSortAlign_ * sizeof(int32_t);
        pipe_->InitBuffer(workBuf_, selKvBlockTableUb_ + selKvActSeqUb_ + selBlockStatUb_ +
            topkSortAlign_ * sizeof(int32_t) * SORT_SCRATCH_ARRAY_NUM);

        selKRopeGm_.SetGlobalBuffer((__gm__ T*)selectionKRoPE);
        selKvCacheGm_.SetGlobalBuffer((__gm__ T*)selectionKvCache);
        selKvBlockTableGm_.SetGlobalBuffer((__gm__ int32_t*)selectionKvBlockTable);
        selKvBlockStatusGm_.SetGlobalBuffer((__gm__ int32_t*)selectionKvBlockStatus);
        selTopKIndicesGm_.SetGlobalBuffer((__gm__ int32_t*)selectionTopkIndices);
        fullKRopeGm_.SetGlobalBuffer((__gm__ T*)fullKRoPE);
        fullKvCacheGm_.SetGlobalBuffer((__gm__ T*)fullKvCache);
        fullKvBlockTableGm_.SetGlobalBuffer((__gm__ int32_t*)fullKvBlockTable);
        fullKvActualSeqGm_.SetGlobalBuffer((__gm__ int32_t*)fullKvActualSeq);
        selKvActualSeqGm_.SetGlobalBuffer((__gm__ int32_t*)selectionKvActualSeq);

        __gm__ uint8_t* workspaceBase = (__gm__ uint8_t*)workspace;
        planValidNumGm_.SetGlobalBuffer((__gm__ int32_t*)(workspaceBase + tiling_->planValidNumOffset));
        planTopkIdGm_.SetGlobalBuffer((__gm__ int32_t*)(workspaceBase + tiling_->planTopkIdOffset));
        planInsertIdxGm_.SetGlobalBuffer((__gm__ int32_t*)(workspaceBase + tiling_->planInsertIdxOffset));
        planActionGm_.SetGlobalBuffer((__gm__ int32_t*)(workspaceBase + tiling_->planActionOffset));
    }

    __aicore__ inline void Process()
    {
        if (tiling_->usedCoreNum == 0) {
            return;
        }

        InitLocalTensorViews();

        // Phase 1: one leader core per token computes the stateful reuse decision and emits a copy plan.
        for (int64_t tokenIdx = blockIdx_; tokenIdx < tiling_->tokenNum; tokenIdx += tiling_->usedCoreNum) {
            BuildTokenPlan(tokenIdx);
            selTopKIdxQue_.FreeTensor(selTopKIdxLocal_);
        }
        PipeBarrier<PIPE_ALL>();
        SyncAll();

        // Phase 2: all AIV cores share pure full-KV copies over the flattened [token, valid_topk] space.
        CopyPlannedKvWithAllCores();
        PipeBarrier<PIPE_ALL>();
        SyncAll();

        // Phase 3: token leaders commit status/actual_seq only after every copy core has finished.
        for (int64_t tokenIdx = blockIdx_; tokenIdx < tiling_->tokenNum; tokenIdx += tiling_->usedCoreNum) {
            FinalizeToken(tokenIdx);
        }
    }

private:
    __aicore__ inline void InitLocalTensorViews()
    {
        selKvBlockTableLocal_ = workBuf_.Get<int32_t>();
        selKvActSeqLocal_ = selKvBlockTableLocal_[selKvBlockTableUb_ / sizeof(int32_t)];
        selBlockStatLocal_ = selKvActSeqLocal_[selKvActSeqUb_ / sizeof(int32_t)];
        topkIndicesLocal_ = selBlockStatLocal_[selBlockStatUb_ / sizeof(int32_t)];
        insertStatusSameSeqLocal_ = topkIndicesLocal_[topkSortAlign_];
        hitFromSrcSeqLocal_ = insertStatusSameSeqLocal_[topkSortAlign_];
        sortBuf_ = hitFromSrcSeqLocal_[topkSortAlign_];
        ArithProgression<int32_t>(topkIndicesLocal_, 0, 1, topkSortAlign_);
        PipeBarrier<PIPE_V>();
    }

    template <HardEvent event>
    __aicore__ inline void SetWaitFlag(HardEvent evt)
    {
        event_t eventId = static_cast<event_t>(GetTPipePtr()->FetchEventID(evt));
        SetFlag<event>(eventId);
        WaitFlag<event>(eventId);
    }

    __aicore__ inline void CopyInTopKIndices(int64_t tokenIdx)
    {
        LocalTensor<int32_t> local = selTopKIdxQue_.AllocTensor<int32_t>();
        uint8_t padCnt = static_cast<uint8_t>(topkAlign_ - tiling_->topk);
        DataCopyPadExtParams<int32_t> padParams{true, 0, padCnt, INVALID_STATUS_VALUE};
        DataCopyExtParams copyParams{1, static_cast<uint32_t>(tiling_->topk * sizeof(int32_t)), 0, 0, 0};
        DataCopyPad(local, selTopKIndicesGm_[tokenIdx * tiling_->topk], copyParams, padParams);
        selTopKIdxQue_.EnQue(local);
    }

    __aicore__ inline void CopyInBlockStatus(int64_t tokenIdx)
    {
        uint8_t padCnt = static_cast<uint8_t>(topkOneAlign_ - (tiling_->topk + STATUS_VALID_NUM_EXTRA));
        DataCopyPadExtParams<int32_t> padParams{true, 0, padCnt, INVALID_STATUS_VALUE};
        DataCopyExtParams copyParams{
            1, static_cast<uint32_t>((tiling_->topk + STATUS_VALID_NUM_EXTRA) * sizeof(int32_t)), 0, 0, 0};
        DataCopyPad(selBlockStatLocal_,
            selKvBlockStatusGm_[tokenIdx * (tiling_->topk + STATUS_VALID_NUM_EXTRA)], copyParams, padParams);
    }

    __aicore__ inline void CopyInSelKvBlockTable(int64_t tokenIdx)
    {
        DataCopyPadExtParams<int32_t> padParams{false, 0, 0, 0};
        DataCopyExtParams copyParams{
            1, static_cast<uint32_t>(tiling_->selMaxBlockNum * sizeof(int32_t)), 0, 0, 0};
        DataCopyPad(selKvBlockTableLocal_,
            selKvBlockTableGm_[tokenIdx * tiling_->selMaxBlockNum], copyParams, padParams);
    }

    __aicore__ inline void BuildTokenPlan(int64_t tokenIdx)
    {
        const int64_t fullKvSeqLen = fullKvActualSeqGm_.GetValue(tokenIdx);
        CopyInTopKIndices(tokenIdx);
        selTopKIdxLocal_ = selTopKIdxQue_.DeQue<int32_t>();
        CopyInBlockStatus(tokenIdx);
        CopyInSelKvBlockTable(tokenIdx);
        SetWaitFlag<HardEvent::MTE2_S>(HardEvent::MTE2_S);

        validTopkNum_ = 0;
        if (fullKvSeqLen <= 0) {
            CopyPlanToWorkspace(tokenIdx, 0);
            return;
        }

        const int32_t maxSelectionId = static_cast<int32_t>(fullKvSeqLen - STATUS_VALID_NUM_EXTRA);
        const int32_t maxValidCacheId =
            maxSelectionId > 1 ? maxSelectionId - STATUS_VALID_NUM_EXTRA : 0;
        int32_t maxHitSameSeqIdx = INVALID_STATUS_VALUE;

        Duplicate(insertStatusSameSeqLocal_, INVALID_STATUS_VALUE, topkSortAlign_);
        Duplicate(hitFromSrcSeqLocal_, INVALID_STATUS_VALUE, topkSortAlign_);
        PipeBarrier<PIPE_V>();
        GatherInfoGen(maxSelectionId, maxValidCacheId, validTopkNum_, maxHitSameSeqIdx);

        int32_t totalInsertIdx = 0;
        LocalTensor<int32_t> planTopkLocal = sortBuf_;
        LocalTensor<int32_t> planInsertLocal = sortBuf_[topkSortAlign_];
        LocalTensor<int32_t> planActionLocal = sortBuf_[topkSortAlign_ * PLAN_ACTION_BUF_OFFSET];
        for (int32_t topkIdx = 0; topkIdx < validTopkNum_; ++topkIdx) {
            const int32_t topkId = selTopKIdxLocal_.GetValue(topkIdx);
            int32_t action = hitFromSrcSeqLocal_.GetValue(topkIdx);
            int32_t insertIdx = INVALID_STATUS_VALUE;
            if (action != CUR_SEG_HIT_FLAG) {
                for (int32_t candidate = totalInsertIdx; candidate < tiling_->topk; ++candidate) {
                    if (insertStatusSameSeqLocal_.GetValue(candidate) < 0) {
                        insertIdx = candidate;
                        break;
                    }
                }
                ASSERT_MSG(insertIdx >= 0, "failed to find a free selected-cache position");
                totalInsertIdx = insertIdx + 1;
                if (action >= 0) {
                    // A hole in the current token's status can require an in-cache compaction copy.
                    // Keep these copies in the original topk order on the token leader: parallelizing
                    // them could overwrite a source slot before a later move reads it.
                    CopyFromSelectedKv(action, insertIdx);
                    action = COPY_FROM_SELECTED_DONE_FLAG;
                }
            }
            planTopkLocal.SetValue(topkIdx, topkId);
            planInsertLocal.SetValue(topkIdx, insertIdx);
            planActionLocal.SetValue(topkIdx, action);
        }
        CopyPlanToWorkspace(tokenIdx, validTopkNum_);
    }

    __aicore__ inline void CopyPlanToWorkspace(int64_t tokenIdx, int32_t validNum)
    {
        LocalTensor<int32_t> planTopkLocal = sortBuf_;
        LocalTensor<int32_t> planInsertLocal = sortBuf_[topkSortAlign_];
        LocalTensor<int32_t> planActionLocal = sortBuf_[topkSortAlign_ * PLAN_ACTION_BUF_OFFSET];
        selKvActSeqLocal_.SetValue(0, validNum);
        SetWaitFlag<HardEvent::S_MTE3>(HardEvent::S_MTE3);

        DataCopyExtParams validParams{1, static_cast<uint32_t>(sizeof(int32_t)), 0, 0, 0};
        DataCopyPad(planValidNumGm_[tokenIdx], selKvActSeqLocal_, validParams);
        if (validNum > 0) {
            const int64_t planBase = tokenIdx * tiling_->topk;
            DataCopyExtParams planParams{1, static_cast<uint32_t>(validNum * sizeof(int32_t)), 0, 0, 0};
            DataCopyPad(planTopkIdGm_[planBase], planTopkLocal, planParams);
            DataCopyPad(planInsertIdxGm_[planBase], planInsertLocal, planParams);
            DataCopyPad(planActionGm_[planBase], planActionLocal, planParams);
        }
        SetWaitFlag<HardEvent::MTE3_S>(HardEvent::MTE3_S);
    }

    __aicore__ inline void CopyPlannedKvWithAllCores()
    {
        for (int64_t planIdx = blockIdx_; planIdx < tiling_->planItemNum; planIdx += tiling_->usedCoreNum) {
            const int64_t tokenIdx = planIdx / tiling_->topk;
            const int32_t topkIdx = static_cast<int32_t>(planIdx - tokenIdx * tiling_->topk);
            const int32_t validNum = planValidNumGm_.GetValue(tokenIdx);
            if (topkIdx >= validNum) {
                continue;
            }
            const int32_t action = planActionGm_.GetValue(planIdx);
            if (action == CUR_SEG_HIT_FLAG || action == COPY_FROM_SELECTED_DONE_FLAG) {
                continue;
            }
            ASSERT_MSG(action == COPY_FROM_FULL_FLAG, "unexpected copy action in S=1 kernel");
            CopyFromFullKv(tokenIdx, planTopkIdGm_.GetValue(planIdx), planInsertIdxGm_.GetValue(planIdx));
        }
        SetWaitFlag<HardEvent::MTE3_S>(HardEvent::MTE3_S);
    }

    __aicore__ inline void CopyFromFullKv(int64_t tokenIdx, int32_t topkId, int32_t insertIdx)
    {
        const int64_t fullBlockTableIdx = topkId / tiling_->fullKvBlockSize;
        const int64_t fullBlockOffset = topkId % tiling_->fullKvBlockSize;
        const int32_t fullBlockId = fullKvBlockTableGm_.GetValue(
            tokenIdx * tiling_->fullMaxBlockNum + fullBlockTableIdx);
        ASSERT_MSG(fullBlockId >= 0, "full KV block id must be non-negative");

        const int64_t selBlockTableIdx = insertIdx / tiling_->selKvBlockSize;
        const int64_t selBlockOffset = insertIdx % tiling_->selKvBlockSize;
        const int32_t selBlockId = selKvBlockTableGm_.GetValue(
            tokenIdx * tiling_->selMaxBlockNum + selBlockTableIdx);
        ASSERT_MSG(selBlockId >= 0, "selection KV block id must be non-negative");

        const int64_t fullKvAddr =
            fullBlockId * tiling_->fullKvBlockSize * tiling_->kvCacheDim + fullBlockOffset * tiling_->kvCacheDim;
        const int64_t selKvAddr =
            selBlockId * tiling_->selKvBlockSize * tiling_->kvCacheDim + selBlockOffset * tiling_->kvCacheDim;
        const int64_t fullRopeAddr =
            fullBlockId * tiling_->fullKvBlockSize * tiling_->kRopeDim + fullBlockOffset * tiling_->kRopeDim;
        const int64_t selRopeAddr =
            selBlockId * tiling_->selKvBlockSize * tiling_->kRopeDim + selBlockOffset * tiling_->kRopeDim;

        LocalTensor<T> local = kvCacheQue_.AllocTensor<T>();
        DataCopyPadExtParams<T> padParams{false, 0, 0, 0};
        DataCopyExtParams kvParams{
            1, static_cast<uint32_t>(tiling_->kvCacheDim * sizeof(T)), 0, 0, 0};
        DataCopyPad(local, fullKvCacheGm_[fullKvAddr], kvParams, padParams);
        DataCopyExtParams ropeParams{
            1, static_cast<uint32_t>(tiling_->kRopeDim * sizeof(T)), 0, 0, 0};
        if (tiling_->ifQuant != 1) {
            DataCopyPad(local[kRopeUbOffset_], fullKRopeGm_[fullRopeAddr], ropeParams, padParams);
        }
        kvCacheQue_.EnQue(local);
        local = kvCacheQue_.DeQue<T>();
        DataCopyPad(selKvCacheGm_[selKvAddr], local, kvParams);
        if (tiling_->ifQuant != 1) {
            DataCopyPad(selKRopeGm_[selRopeAddr], local[kRopeUbOffset_], ropeParams);
        }
        kvCacheQue_.FreeTensor(local);
    }

    __aicore__ inline void CopyFromSelectedKv(int32_t sourceIdx, int32_t insertIdx)
    {
        const int64_t srcBlockTableIdx = sourceIdx / tiling_->selKvBlockSize;
        const int64_t srcBlockOffset = sourceIdx % tiling_->selKvBlockSize;
        const int32_t srcBlockId = selKvBlockTableLocal_.GetValue(srcBlockTableIdx);
        const int64_t dstBlockTableIdx = insertIdx / tiling_->selKvBlockSize;
        const int64_t dstBlockOffset = insertIdx % tiling_->selKvBlockSize;
        const int32_t dstBlockId = selKvBlockTableLocal_.GetValue(dstBlockTableIdx);
        ASSERT_MSG(srcBlockId >= 0 && dstBlockId >= 0, "selection KV block id must be non-negative");

        const int64_t srcKvAddr =
            srcBlockId * tiling_->selKvBlockSize * tiling_->kvCacheDim + srcBlockOffset * tiling_->kvCacheDim;
        const int64_t dstKvAddr =
            dstBlockId * tiling_->selKvBlockSize * tiling_->kvCacheDim + dstBlockOffset * tiling_->kvCacheDim;
        const int64_t srcRopeAddr =
            srcBlockId * tiling_->selKvBlockSize * tiling_->kRopeDim + srcBlockOffset * tiling_->kRopeDim;
        const int64_t dstRopeAddr =
            dstBlockId * tiling_->selKvBlockSize * tiling_->kRopeDim + dstBlockOffset * tiling_->kRopeDim;

        LocalTensor<T> local = kvCacheQue_.AllocTensor<T>();
        DataCopyPadExtParams<T> padParams{false, 0, 0, 0};
        DataCopyExtParams kvParams{
            1, static_cast<uint32_t>(tiling_->kvCacheDim * sizeof(T)), 0, 0, 0};
        DataCopyPad(local, selKvCacheGm_[srcKvAddr], kvParams, padParams);
        DataCopyExtParams ropeParams{
            1, static_cast<uint32_t>(tiling_->kRopeDim * sizeof(T)), 0, 0, 0};
        if (tiling_->ifQuant != 1) {
            DataCopyPad(local[kRopeUbOffset_], selKRopeGm_[srcRopeAddr], ropeParams, padParams);
        }
        kvCacheQue_.EnQue(local);
        local = kvCacheQue_.DeQue<T>();
        DataCopyPad(selKvCacheGm_[dstKvAddr], local, kvParams);
        if (tiling_->ifQuant != 1) {
            DataCopyPad(selKRopeGm_[dstRopeAddr], local[kRopeUbOffset_], ropeParams);
        }
        kvCacheQue_.FreeTensor(local);
    }

    __aicore__ inline void FinalizeToken(int64_t tokenIdx)
    {
        CopyInBlockStatus(tokenIdx);
        SetWaitFlag<HardEvent::MTE2_S>(HardEvent::MTE2_S);
        const int32_t validTopkNum = planValidNumGm_.GetValue(tokenIdx);
        const int64_t planBase = tokenIdx * tiling_->topk;
        for (int32_t topkIdx = 0; topkIdx < validTopkNum; ++topkIdx) {
            const int64_t planIdx = planBase + topkIdx;
            const int32_t insertIdx = planInsertIdxGm_.GetValue(planIdx);
            if (insertIdx >= 0) {
                selBlockStatLocal_.SetValue(insertIdx, planTopkIdGm_.GetValue(planIdx));
            }
        }
        SetInvalidBlockStatus(validTopkNum);
        selKvActSeqLocal_.SetValue(0, validTopkNum);
        SetWaitFlag<HardEvent::S_MTE3>(HardEvent::S_MTE3);

        DataCopyExtParams seqParams{1, static_cast<uint32_t>(sizeof(int32_t)), 0, 0, 0};
        DataCopyPad(selKvActualSeqGm_[tokenIdx], selKvActSeqLocal_, seqParams);
        DataCopyExtParams statusParams{
            1, static_cast<uint32_t>((tiling_->topk + STATUS_VALID_NUM_EXTRA) * sizeof(int32_t)), 0, 0, 0};
        DataCopyPad(selKvBlockStatusGm_[tokenIdx * (tiling_->topk + STATUS_VALID_NUM_EXTRA)],
            selBlockStatLocal_, statusParams);
        SetWaitFlag<HardEvent::MTE3_S>(HardEvent::MTE3_S);
    }

    __aicore__ inline void SetInvalidBlockStatus(int32_t validTopkNum)
    {
        const int64_t duplicateNum = validTopkNum % ONE_REPEAT_SORT_NUM;
        if (duplicateNum > 0) {
            const int64_t duplicateIndex = validTopkNum - duplicateNum;
            uint64_t mask0 = (UINT64_MAX << duplicateNum) & (UINT64_MAX >> ONE_REPEAT_SORT_NUM);
            uint64_t mask[MASK_U64_NUM] = {mask0, 0};
            Duplicate(selBlockStatLocal_[duplicateIndex], INVALID_STATUS_VALUE, mask, 1, 1, VECTOR_REPEAT_STRIDE);
            PipeBarrier<PIPE_V>();
        }
        const int32_t dupBegin = CeilAlign(validTopkNum, ONE_REPEAT_SORT_NUM);
        if (topkOneSortAlign_ > dupBegin) {
            Duplicate(selBlockStatLocal_[dupBegin], INVALID_STATUS_VALUE, topkOneSortAlign_ - dupBegin);
            PipeBarrier<PIPE_V>();
        }
        SetWaitFlag<HardEvent::V_S>(HardEvent::V_S);
        selBlockStatLocal_.SetValue(tiling_->topk, validTopkNum);
    }

    __aicore__ inline void GatherInfoGen(
        int32_t maxSelectionId, int32_t maxValidCacheId, int32_t& validTopkNum, int32_t& maxHitSameSeqIdx)
    {
        LocalTensor<uint32_t> idxLocal = topkIndicesLocal_.template ReinterpretCast<uint32_t>();
        LocalTensor<int32_t> sortedTopKLocal = sortBuf_;
        LocalTensor<uint32_t> sortedTopKIdxLocal =
            sortBuf_[topkSortAlign_].template ReinterpretCast<uint32_t>();
        LocalTensor<int32_t> sortedStatTopKLocal = sortBuf_[topkSortAlign_ * SORTED_STAT_TOPK_OFFSET];
        LocalTensor<uint32_t> sortedStatTopKIdxLocal =
            sortBuf_[topkSortAlign_ * SORTED_STAT_TOPK_IDX_OFFSET].template ReinterpretCast<uint32_t>();

        GatherValidTopk(selTopKIdxLocal_, sortedTopKLocal, sortedTopKIdxLocal,
            sortedStatTopKIdxLocal, maxSelectionId, validTopkNum);
        if (validTopkNum <= 0) {
            return;
        }

        LocalTensor<float> tempTensor = sortedTopKLocal.template ReinterpretCast<float>();
        LocalTensor<float> sortedLocal = sortBuf_[topkSortAlign_ * SORT_OFFSET].template ReinterpretCast<float>();
        SortTopk(selTopKIdxLocal_, idxLocal, tempTensor, sortedLocal,
            sortedTopKLocal, sortedTopKIdxLocal, validTopkNum);

        tempTensor = sortedStatTopKLocal.template ReinterpretCast<float>();
        sortedLocal = sortBuf_[topkSortAlign_ * SORT_OFFSET].template ReinterpretCast<float>();
        SortTopk(selBlockStatLocal_, idxLocal, tempTensor, sortedLocal,
            sortedStatTopKLocal, sortedStatTopKIdxLocal, tiling_->topk);
        SetWaitFlag<HardEvent::V_S>(HardEvent::V_S);
        FindTopkHit(sortedTopKLocal, sortedTopKIdxLocal, sortedStatTopKLocal,
            sortedStatTopKIdxLocal, validTopkNum, maxValidCacheId, maxHitSameSeqIdx);

        const int32_t emptyPosCnt = maxHitSameSeqIdx + 1 - validTopkNum;
        if (emptyPosCnt > 0) {
            int32_t visited = 0;
            for (int32_t idx = maxHitSameSeqIdx; idx >= 0; --idx) {
                const int32_t topkIdx = insertStatusSameSeqLocal_.GetValue(idx);
                if (topkIdx >= 0) {
                    hitFromSrcSeqLocal_.SetValue(topkIdx, idx);
                    insertStatusSameSeqLocal_.SetValue(idx, INVALID_STATUS_VALUE);
                }
                if (++visited >= emptyPosCnt) {
                    break;
                }
            }
        }
    }

    __aicore__ inline void GatherValidTopk(
        LocalTensor<int32_t>& srcTopkLocal, LocalTensor<int32_t>& tmp1Local,
        LocalTensor<uint32_t>& tmp2Local, LocalTensor<uint32_t>& tmp3Local,
        int32_t maxSelectionId, int32_t& validTopkNum)
    {
        const int64_t compareNum = CeilAlign(topkAlign_, static_cast<int64_t>(COMPARE_SCALAR_NUM));
        LocalTensor<float> topkFloatLocal = tmp1Local.template ReinterpretCast<float>();
        Cast(topkFloatLocal, srcTopkLocal, RoundMode::CAST_ROUND, topkAlign_);
        PipeBarrier<PIPE_V>();
        LocalTensor<uint8_t> maskTensor = tmp2Local.template ReinterpretCast<uint8_t>();
        CompareScalar(maskTensor, topkFloatLocal, INVALID_FLOAT_VALUE, CMPMODE::GT, compareNum);
        PipeBarrier<PIPE_V>();
        LocalTensor<uint8_t> maskTensor1 = tmp3Local.template ReinterpretCast<uint8_t>();
        CompareScalar(maskTensor1, topkFloatLocal, static_cast<float>(maxSelectionId), CMPMODE::LE, compareNum);
        PipeBarrier<PIPE_V>();
        LocalTensor<uint16_t> maskTensorU16 = maskTensor.template ReinterpretCast<uint16_t>();
        LocalTensor<uint16_t> maskTensor1U16 = maskTensor1.template ReinterpretCast<uint16_t>();
        And(maskTensorU16, maskTensorU16, maskTensor1U16, compareNum / COMPARENUM_SIZE);
        PipeBarrier<PIPE_V>();

        uint64_t selected = 0;
        GatherMaskParams params;
        params.repeatTimes = 1;
        params.src0BlockStride = 1;
        params.src0RepeatStride = GATHER_MASK_SRC0_REPEAT_STRIDE;
        params.src1RepeatStride = 0;
        LocalTensor<float> dstFloatLocal = srcTopkLocal.template ReinterpretCast<float>();
        LocalTensor<uint32_t> maskTensorU32 = maskTensor.template ReinterpretCast<uint32_t>();
        GatherMask(dstFloatLocal, topkFloatLocal, maskTensorU32, true, topkAlign_, params, selected);
        PipeBarrier<PIPE_V>();
        Cast(srcTopkLocal, dstFloatLocal, RoundMode::CAST_ROUND, topkAlign_);
        PipeBarrier<PIPE_V>();
        validTopkNum = static_cast<int32_t>(selected);
    }

    __aicore__ inline void SortTopk(
        LocalTensor<int32_t>& srcTopkLocal, LocalTensor<uint32_t>& idxLocal,
        LocalTensor<float>& tempTensor, LocalTensor<float>& sortedLocal,
        LocalTensor<int32_t>& sortedTopKLocal, LocalTensor<uint32_t>& sortedTopKIdx, int32_t validNum)
    {
        LocalTensor<float> topkFloatLocal = srcTopkLocal.template ReinterpretCast<float>();
        Cast(topkFloatLocal, srcTopkLocal, RoundMode::CAST_ROUND, validNum);
        PipeBarrier<PIPE_V>();
        const int64_t remainder = validNum % ONE_REPEAT_SORT_NUM;
        if (remainder > 0) {
            const int64_t duplicateIndex = validNum - remainder;
            uint64_t mask0 = (UINT64_MAX << remainder) & (UINT64_MAX >> ONE_REPEAT_SORT_NUM);
            uint64_t mask[MASK_U64_NUM] = {mask0, 0};
            Duplicate(topkFloatLocal[duplicateIndex], INVALID_FLOAT_VALUE, mask, 1, 1, VECTOR_REPEAT_STRIDE);
            PipeBarrier<PIPE_V>();
        }
        const int64_t sortAlignNum = CeilAlign(validNum, ONE_REPEAT_SORT_NUM);
        LocalTensor<float> concatLocal = topkFloatLocal;
        Concat(concatLocal, topkFloatLocal, tempTensor, sortAlignNum / ONE_REPEAT_SORT_NUM);
        PipeBarrier<PIPE_V>();
        Sort<float, true>(sortedLocal, concatLocal, idxLocal, tempTensor, sortAlignNum / ONE_REPEAT_SORT_NUM);
        PipeBarrier<PIPE_V>();
        LocalTensor<float> sortedTopKFloat = sortedTopKLocal.template ReinterpretCast<float>();
        Extract(sortedTopKFloat, sortedTopKIdx, sortedLocal, sortAlignNum / ONE_REPEAT_SORT_NUM);
        PipeBarrier<PIPE_V>();
        Cast(sortedTopKLocal, sortedTopKFloat, RoundMode::CAST_ROUND, sortAlignNum);
        PipeBarrier<PIPE_V>();
        Cast(srcTopkLocal, topkFloatLocal, RoundMode::CAST_ROUND, sortAlignNum);
        PipeBarrier<PIPE_V>();
    }

    __aicore__ inline void FindTopkHit(
        LocalTensor<int32_t>& sortedTopKLocal, LocalTensor<uint32_t>& sortedTopKIdxLocal,
        LocalTensor<int32_t>& sortedStatTopKLocal, LocalTensor<uint32_t>& sortedStatTopKIdxLocal,
        int32_t validTopkNum, int32_t maxValidCacheId, int32_t& maxHitSameSeqIdx)
    {
        int32_t curIdx = 0;
        int32_t statIdx = 0;
        while (curIdx < validTopkNum && statIdx < tiling_->topk) {
            const int32_t curTop = sortedTopKLocal.GetValue(curIdx);
            const int32_t statTop = sortedStatTopKLocal.GetValue(statIdx);
            if (curTop < 0 || statTop < 0) {
                break;
            }
            if (curTop > maxValidCacheId) {
                ++curIdx;
                continue;
            }
            if (curTop == statTop) {
                const int32_t curRealIdx = sortedTopKIdxLocal.GetValue(curIdx);
                const int32_t statRealIdx = sortedStatTopKIdxLocal.GetValue(statIdx);
                insertStatusSameSeqLocal_.SetValue(statRealIdx, curRealIdx);
                hitFromSrcSeqLocal_.SetValue(curRealIdx, CUR_SEG_HIT_FLAG);
                maxHitSameSeqIdx = statRealIdx > maxHitSameSeqIdx ? statRealIdx : maxHitSameSeqIdx;
                ++curIdx;
                ++statIdx;
            } else if (curTop > statTop) {
                ++curIdx;
            } else {
                ++statIdx;
            }
        }
    }

    template <typename U>
    __aicore__ inline U CeilAlign(U value, U align)
    {
        constexpr U kCeilAlignBias = 1;
        return (value + align - kCeilAlignBias) / align * align;
    }

private:
    static constexpr int32_t BLOCK_BYTES = 32;

    TPipe* pipe_;
    const GatherSelectionKvCacheCustomTilingData* tiling_;
    int32_t blockIdx_ = 0;
    int64_t topkAlign_ = 0;
    int64_t topkSortAlign_ = 0;
    int64_t topkOneAlign_ = 0;
    int64_t topkOneSortAlign_ = 0;
    int32_t kRopeUbOffset_ = 0;
    int32_t selBlockStatUb_ = 0;
    int32_t selKvBlockTableUb_ = 0;
    int32_t selKvActSeqUb_ = 0;
    int32_t validTopkNum_ = 0;

    GlobalTensor<T> selKRopeGm_;
    GlobalTensor<T> selKvCacheGm_;
    GlobalTensor<int32_t> selKvBlockTableGm_;
    GlobalTensor<int32_t> selKvBlockStatusGm_;
    GlobalTensor<int32_t> selTopKIndicesGm_;
    GlobalTensor<T> fullKRopeGm_;
    GlobalTensor<T> fullKvCacheGm_;
    GlobalTensor<int32_t> fullKvBlockTableGm_;
    GlobalTensor<int32_t> fullKvActualSeqGm_;
    GlobalTensor<int32_t> selKvActualSeqGm_;

    GlobalTensor<int32_t> planValidNumGm_;
    GlobalTensor<int32_t> planTopkIdGm_;
    GlobalTensor<int32_t> planInsertIdxGm_;
    GlobalTensor<int32_t> planActionGm_;

    LocalTensor<int32_t> selKvBlockTableLocal_;
    LocalTensor<int32_t> selKvActSeqLocal_;
    LocalTensor<int32_t> selBlockStatLocal_;
    LocalTensor<int32_t> selTopKIdxLocal_;
    LocalTensor<int32_t> topkIndicesLocal_;
    LocalTensor<int32_t> insertStatusSameSeqLocal_;
    LocalTensor<int32_t> hitFromSrcSeqLocal_;
    LocalTensor<int32_t> sortBuf_;

    TQue<QuePosition::VECIN, 1> selTopKIdxQue_;
    TQueBind<QuePosition::VECIN, QuePosition::VECOUT, 1> kvCacheQue_;
    TBuf<QuePosition::VECCALC> workBuf_;
};

} // namespace GatherSelectionKvCacheCustomNs

#endif // GATHER_SELECTION_KV_CACHE_CUSTOM_REUSE_VEC_H
