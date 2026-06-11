/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch layout operator kernel function header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create dispatch layout operator kernel function header file
 */
#ifndef DISPATCH_LAYOUT_H
#define DISPATCH_LAYOUT_H

#include <climits>
#include "kernel_operator.h"

#include "comm_args.h"
#include "data_copy.h"
#include "sync_collectives.h"
#include "moe_distribute_base.h"
#include "dispatch_layout_tiling.h"
namespace MoeDispatchLayout {

constexpr uint32_t UB_32_ALIGN = 32U;
constexpr uint32_t UB_MAX_SIZE = 190U * 1024U;  // 190KB max UB usage per round

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

using namespace AscendC;
using namespace Moe;
template <typename T>
class DispatchLayout {
public:
    __aicore__ inline DispatchLayout(){};

    __aicore__ inline void Init(GM_ADDR topkIdx, GM_ADDR numTokensPerRank, GM_ADDR numTokensPerExpert,
        GM_ADDR isTokenInRank, GM_ADDR notifySendData, GM_ADDR sendTokenIdxSmall, GM_ADDR workspace, TPipe *pipe,
        const DispatchLayoutTilingData *tilingData)
    {
        numTokens_ = tilingData->dispatchLayoutInfo.numTokens;
        numRanks_ = tilingData->dispatchLayoutInfo.numRanks;
        numExperts_ = tilingData->dispatchLayoutInfo.numExperts;
        numTopk_ = tilingData->dispatchLayoutInfo.numTopk;
        tpipe_ = pipe;

        coreIdx_ = GetBlockIdx();
        uint32_t maxAivNum = GetBlockNum();
        aivNum_ = numTokens_ <= maxAivNum ? numTokens_ : maxAivNum;
        // Compute alignment lengths before early return so all cores can calculate tokensPerRound
        numTokensPerRank32AlignIntLen_ = Ceil(numRanks_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN;
        numTokensPerExpert32AlignIntLen_ = Ceil(numExperts_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN;
        if (coreIdx_ >= aivNum_) {
            return;
        }
        uint32_t temp = numTokens_ / aivNum_;
        uint32_t restNum = numTokens_ % aivNum_;
        int64_t topkIdxOffset;
        int64_t isTokenOffset;
        tempTokens_ = temp;
        if (coreIdx_ < restNum) {
            tempTokens_++;
        }
        if (coreIdx_ < restNum) {
            topkIdxOffset = coreIdx_ * tempTokens_ * numTopk_ * sizeof(int64_t);
            isTokenOffset = coreIdx_ * tempTokens_ * numRanks_ * sizeof(T);
        } else {
            topkIdxOffset = (restNum + coreIdx_ * tempTokens_) * numTopk_ * sizeof(int64_t);
            isTokenOffset = (restNum + coreIdx_ * tempTokens_) * numRanks_ * sizeof(T);
        }
        tempExpertGM_.SetGlobalBuffer((__gm__ T *)notifySendData);
        topkIdxGM_.SetGlobalBuffer((__gm__ int64_t *)(topkIdx + topkIdxOffset));
        numTokensPerRankGM_.SetGlobalBuffer((__gm__ T *)numTokensPerRank);
        numTokensPerExpertGM_.SetGlobalBuffer((__gm__ T *)numTokensPerExpert);
        isTokenInRankGM_.SetGlobalBuffer((__gm__ T *)(isTokenInRank + isTokenOffset));
        sendTokenIdxSmallGM_.SetGlobalBuffer((__gm__ T *)(sendTokenIdxSmall + topkIdxOffset / 2));
    }

    __aicore__ inline uint32_t CalcTokensPerRound()
    {
        // Calculate fixed buffer sizes (independent of token count)
        uint32_t fixedSize = numTokensPerRank32AlignIntLen_ + numTokensPerExpert32AlignIntLen_ +
            Ceil(numRanks_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN;  // seenRankBuf

        // Per-token buffer sizes:
        // topkIdxBuf: numTopk_ * sizeof(int64_t) per token
        // isTokenInRankBuf: numRanks_ * sizeof(T) per token
        // sendTokenIdxSmallBuf: numTopk_ * sizeof(T) per token
        uint32_t perTokenSize = Ceil(numTopk_ * sizeof(int64_t), UB_32_ALIGN) * UB_32_ALIGN +
            Ceil(numRanks_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN +
            Ceil(numTopk_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN;

        uint32_t availableSize = UB_MAX_SIZE - fixedSize;
        uint32_t tokensPerRound = availableSize / perTokenSize;

        // Ensure at least 1 token per round
        return tokensPerRound > 0 ? tokensPerRound : 1;
    }

    // Phase 1 per-round: count tokens per rank/expert, write isTokenInRank and atomic-add counts to GM
    __aicore__ inline void CountTokensInRound(uint32_t roundStart, uint32_t roundTokens, int expertsPerRank)
    {
        uint32_t topkLen = Ceil(roundTokens * numTopk_ * sizeof(int64_t), UB_32_ALIGN) * UB_32_ALIGN;
        uint32_t isTokenLen = Ceil(roundTokens * numRanks_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN;
        tpipe_->Reset();
        tpipe_->InitBuffer(topkIdxBuf_, topkLen);
        tpipe_->InitBuffer(numTokensPerRankBuf_, numTokensPerRank32AlignIntLen_);
        tpipe_->InitBuffer(numTokensPerExpertBuf_, numTokensPerExpert32AlignIntLen_);
        tpipe_->InitBuffer(isTokenInRankBuf_, isTokenLen);
        tpipe_->InitBuffer(seenRankBuf_, Ceil(numRanks_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN);
        LocalTensor<int64_t> topkIdxLocal = topkIdxBuf_.AllocTensor<int64_t>();
        const DataCopyExtParams topkCopyParams{1U, topkLen, 0U, 0U, 0U};
        const DataCopyPadExtParams<int64_t> topkPadParams{false, 0U, 0U, 0U};
        DataCopyPad(topkIdxLocal, topkIdxGM_[roundStart * numTopk_], topkCopyParams, topkPadParams);
        SyncFunc<AscendC::HardEvent::MTE2_S>();
        LocalTensor<T> rankLocal = numTokensPerRankBuf_.AllocTensor<T>();
        LocalTensor<T> expertLocal = numTokensPerExpertBuf_.AllocTensor<T>();
        LocalTensor<T> isTokenLocal = isTokenInRankBuf_.AllocTensor<T>();
        LocalTensor<T> seenLocal = seenRankBuf_.AllocTensor<T>();
        Duplicate<T>(rankLocal, 0, numRanks_);
        Duplicate<T>(expertLocal, 0, numExperts_);
        Duplicate<T>(isTokenLocal, 0, roundTokens * numRanks_);
        SyncFunc<AscendC::HardEvent::V_S>();
        for (uint32_t i = 0; i < roundTokens; ++i) {
            SyncFunc<AscendC::HardEvent::S_V>();
            Duplicate<T>(seenLocal, 0, numRanks_);
            SyncFunc<AscendC::HardEvent::V_S>();
            for (uint32_t j = 0; j < numTopk_; ++j) {
                int64_t expertIdx = topkIdxLocal.GetValue(i * numTopk_ + j);
                expertLocal.SetValue(expertIdx, expertLocal.GetValue(expertIdx) + 1);
                int rankId = expertIdx / expertsPerRank;
                if (!seenLocal.GetValue(rankId)) {
                    rankLocal.SetValue(rankId, rankLocal.GetValue(rankId) + 1);
                    isTokenLocal.SetValue(i * numRanks_ + rankId, 1);
                    seenLocal.SetValue(rankId, 1);
                }
            }
        }
        // Write isTokenInRank and atomic-add accumulated counts to GM
        const DataCopyExtParams isTokenParams{1U, roundTokens * numRanks_ * static_cast<uint32_t>(sizeof(T)), 0U, 0U,
            0U};
        DataCopyPad(isTokenInRankGM_[roundStart * numRanks_], isTokenLocal, isTokenParams);
        AscendC::SetAtomicAdd<T>();
        const DataCopyExtParams tempExpertParams{1U, numTokensPerExpert32AlignIntLen_, 0U, 0U, 0U};
        for (uint32_t i = coreIdx_ + 1; i < aivNum_; ++i) {
            DataCopyPad(tempExpertGM_[i * numExperts_], expertLocal, tempExpertParams);
        }
        const DataCopyExtParams rankCopyParams{1U, numRanks_ * static_cast<uint32_t>(sizeof(T)), 0U, 0U, 0U};
        DataCopyPad(numTokensPerRankGM_, rankLocal, rankCopyParams);
        const DataCopyExtParams expertCopyParams{1U, numExperts_ * static_cast<uint32_t>(sizeof(T)), 0U, 0U, 0U};
        DataCopyPad(numTokensPerExpertGM_, expertLocal, expertCopyParams);
        AscendC::SetAtomicNone();
        PipeBarrier<PIPE_MTE3>();
    }

    // Phase 2 per-round: compute sendTokenIdxSmall from accumulated numTokensPerExpert
    __aicore__ inline void CalcSendTokenIdxInRound(uint32_t roundStart, uint32_t roundTokens)
    {
        uint32_t topkLen = Ceil(roundTokens * numTopk_ * sizeof(int64_t), UB_32_ALIGN) * UB_32_ALIGN;
        uint32_t sendIdxLen = Ceil(roundTokens * numTopk_ * sizeof(T), UB_32_ALIGN) * UB_32_ALIGN;
        tpipe_->Reset();
        tpipe_->InitBuffer(topkIdxBuf_, topkLen);
        tpipe_->InitBuffer(numTokensPerExpertBuf_, numTokensPerExpert32AlignIntLen_);
        tpipe_->InitBuffer(sendTokenIdxSmallBuf_, sendIdxLen);
        LocalTensor<int64_t> topkIdxLocal = topkIdxBuf_.AllocTensor<int64_t>();
        const DataCopyExtParams topkCopyParams{1U, topkLen, 0U, 0U, 0U};
        const DataCopyPadExtParams<int64_t> topkPadParams{false, 0U, 0U, 0U};
        DataCopyPad(topkIdxLocal, topkIdxGM_[roundStart * numTopk_], topkCopyParams, topkPadParams);
        LocalTensor<T> expertLocal = numTokensPerExpertBuf_.AllocTensor<T>();
        const DataCopyExtParams expertCopyParams{1U, numTokensPerExpert32AlignIntLen_, 0U, 0U, 0U};
        const DataCopyPadExtParams<T> expertPadParams{false, 0U, 0U, 0U};
        DataCopyPad(expertLocal, tempExpertGM_[coreIdx_ * numExperts_], expertCopyParams, expertPadParams);
        SyncFunc<AscendC::HardEvent::MTE2_S>();
        LocalTensor<T> sendIdxLocal = sendTokenIdxSmallBuf_.AllocTensor<T>();
        for (uint32_t i = 0; i < roundTokens; ++i) {
            for (uint32_t j = 0; j < numTopk_; ++j) {
                int64_t expertIdx = topkIdxLocal.GetValue(i * numTopk_ + j);
                T val = expertLocal(expertIdx);
                sendIdxLocal(i * numTopk_ + j) = val;
                expertLocal(expertIdx) = val + 1;
            }
        }
        SyncFunc<AscendC::HardEvent::S_MTE3>();
        DataCopyPad(tempExpertGM_[coreIdx_ * numExperts_], expertLocal, expertCopyParams);
        const DataCopyExtParams sendIdxCopyParams{
            1U, static_cast<uint32_t>(roundTokens * numTopk_ * sizeof(T)), 0U, 0U, 0U};
        DataCopyPad(sendTokenIdxSmallGM_[roundStart * numTopk_], sendIdxLocal, sendIdxCopyParams);
        PipeBarrier<PIPE_MTE3>();
    }

    __aicore__ inline void Process()
    {
        // All cores must compute maxNumRounds identically to ensure the same SyncAll count.
        // tempTokens_ differs by at most 1 across cores (remainder distribution), which may
        // cause different numRounds per core. Use the maximum to unify barrier counts.
        uint32_t tokensPerRound = CalcTokensPerRound();
        uint32_t maxTempTokens = aivNum_ > 0 ? (numTokens_ / aivNum_ + (numTokens_ % aivNum_ > 0 ? 1 : 0)) : 0;
        uint32_t maxNumRounds = (maxTempTokens + tokensPerRound - 1) / tokensPerRound;

        // Zero out numTokensPerExpert in GM before accumulation (core 0 writes, all cores sync)
        if (coreIdx_ == 0) {
            tpipe_->Reset();
            tpipe_->InitBuffer(numTokensPerExpertBuf_, numTokensPerExpert32AlignIntLen_);
            LocalTensor<T> zeroExpertLocal = numTokensPerExpertBuf_.AllocTensor<T>();
            Duplicate<T>(zeroExpertLocal, 0, numExperts_);
            SyncFunc<AscendC::HardEvent::V_S>();
            const DataCopyExtParams zeroExpertParams{1U, numExperts_ * static_cast<uint32_t>(sizeof(T)), 0U, 0U, 0U};
            DataCopyPad(numTokensPerExpertGM_, zeroExpertLocal, zeroExpertParams);
            PipeBarrier<PIPE_MTE3>();
        }
        SyncAll<true>();

        // Inactive cores: participate in all Phase 1 SyncAll barriers then return.
        // Phase 2 has no cross-core dependency, so no SyncAll is needed there.
        if (coreIdx_ >= aivNum_) {
            for (uint32_t i = 0; i < maxNumRounds; ++i) {
                SyncAll<true>();
            }
            return;
        }

        uint32_t numRounds = (tempTokens_ + tokensPerRound - 1) / tokensPerRound;
        int expertsPerRank = numExperts_ / numRanks_;

        // Phase 1: Count tokens per rank/expert with cross-core atomic accumulation
        for (uint32_t round = 0; round < maxNumRounds; ++round) {
            if (round < numRounds) {
                uint32_t roundStart = round * tokensPerRound;
                uint32_t roundTokens = (round == numRounds - 1) ? (tempTokens_ - roundStart) : tokensPerRound;
                CountTokensInRound(roundStart, roundTokens, expertsPerRank);
            }
            SyncAll<true>();
        }

        // Phase 2: Calculate send token indices (no cross-core sync needed)
        for (uint32_t round = 0; round < numRounds; ++round) {
            uint32_t roundStart = round * tokensPerRound;
            uint32_t roundTokens = (round == numRounds - 1) ? (tempTokens_ - roundStart) : tokensPerRound;
            CalcSendTokenIdxInRound(roundStart, roundTokens);
        }
    }

private:
    GlobalTensor<int64_t> topkIdxGM_;
    GlobalTensor<T> numTokensPerRankGM_;
    GlobalTensor<T> numTokensPerExpertGM_;
    GlobalTensor<T> isTokenInRankGM_;
    GlobalTensor<T> tempExpertGM_;
    GlobalTensor<T> sendTokenIdxSmallGM_;

    TBuf<> topkIdxBuf_;
    TBuf<> numTokensPerRankBuf_;
    TBuf<> numTokensPerExpertBuf_;
    TBuf<> isTokenInRankBuf_;
    TBuf<> seenRankBuf_;
    TBuf<> sendTokenIdxSmallBuf_;

    TPipe *tpipe_{nullptr};
    uint32_t numTokens_{0};
    uint32_t numRanks_{0};
    uint32_t numExperts_{0};
    uint32_t numTopk_{0};
    uint32_t coreIdx_{0};
    uint32_t aivNum_{0};
    uint32_t tempTokens_{0};

    uint32_t numTokensPerRank32AlignIntLen_{0};
    uint32_t numTokensPerExpert32AlignIntLen_{0};
};
}  // namespace MoeDispatchLayout

#endif  // DISPATCH_LAYOUT_H
