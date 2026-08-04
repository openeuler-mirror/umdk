/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: NotifyDispatchZb operator kernel function header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create NotifyDispatchZb operator kernel function header file
 */
#ifndef NOTIFY_DISPATCH_ZB_H
#define NOTIFY_DISPATCH_ZB_H

#include <climits>
#include "kernel_operator.h"

#include "zb_api.h"
#include "comm_args.h"
#include "data_copy.h"
#include "zb_sync_flag.h"

using namespace AscendC;
using namespace Moe;

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

#define KERNELS_ARGS_FUN_ALLGATHER()                                                                            \
    GM_ADDR numTokensPerExpert, GM_ADDR recvDataOutput, GM_ADDR totalRecvTokens, GM_ADDR maxBs,                 \
        GM_ADDR recvTokensPerExpert, GM_ADDR putOffset, int64_t len, uint32_t topkNum, int root, int localRank, \
        int localRankSize, uint64_t commMetaPtr

#define KERNELS_ARGS_CALL_ALLGATHER()                                                                               \
    numTokensPerExpert, recvDataOutput, totalRecvTokens, maxBs, recvTokensPerExpert, putOffset, len, topkNum, root, \
        localRank, localRankSize, commMetaPtr

template <typename T>
class NotifyDispatchZb {
    constexpr static uint32_t UB_FLAG_SIZE = 8U * 1024U;
    // Synchronization flag occupies length
    constexpr static int32_t POST_PROC_BLOCK_GROUP_DIVISOR = 2;
    constexpr static int32_t BUILD_MAX_BS_BLOCK_OFFSET = 0;
    constexpr static int32_t BUILD_TOTAL_RECV_TOKENS_BLOCK_OFFSET = 1;
    constexpr static int32_t BUILD_RECV_TOKEN_PER_EXP_BLOCK_OFFSET = 2;

public:
    __aicore__ inline NotifyDispatchZb(int epRankId_, int epWorldSize_, uint32_t extraFlag)
        : epRankId_(epRankId_), epWorldSize_(epWorldSize_), extraFlag(extraFlag)
    {}

    __aicore__ inline void Init(KERNELS_ARGS_FUN_ALLGATHER())
    {
        this->len = len;
        this->numExperts = len / sendPerGroup;  // len = num_tokens_per_expert length (= expert count)
        this->localRank = localRank;
        this->localRankSize = localRankSize;
        blockIdx_ = GetBlockIdx();
        blockNum_ = GetBlockNum();

        gva_gm = (GM_ADDR)commMetaPtr;  // SHMEM meta base (formerly winContext_)
        topkNum_ = topkNum;
        numTokensPerExpert_ = numTokensPerExpert;
        totalRecvTokens_ = totalRecvTokens;
        allRecvCount_ = putOffset;
        maxBs_ = maxBs;
        recvTokensPerExpert_ = recvTokensPerExpert;
        recvData_ = recvDataOutput;

        recvDataAlignLen_ = Ceil(numExperts * epWorldSize_ * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE;
        numTokensPerExpertAlignLen_ = Ceil(numExperts * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE;
        allRecvCountDataAlignLen_ =
            Ceil(numExperts * epWorldSize_ * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE;

        this->numTokensPerExpertInput = (__gm__ int32_t *)numTokensPerExpert;
        this->recvDataOutput = (__gm__ T *)recvDataOutput;
        recvDataGt_.SetGlobalBuffer((__gm__ int32_t *)recvDataOutput);
        recvCntGt.SetGlobalBuffer((__gm__ int32_t *)allRecvCount_);

        pipe_.InitBuffer(tBuf, UB_FLAG_SIZE);

        // Init ZbSyncFlag — per-core granularity (slotsPerRank = blockNum)
        syncFlag_.Init(gva_gm, static_cast<uint32_t>(epRankId_),
            static_cast<uint32_t>(epWorldSize_),

                static_cast<uint32_t>(blockNum_), tBuf);
    }

    __aicore__ inline void Process()
    {
        // ====== Notify Sync Protocol (magic = M) ======
        // Step 1: IncrementMagic — get magic M
        syncFlag_.IncrementMagic();

        // Step 2: BarrierAll — ensure all ranks have entered and input is ready
        //         numTokensPerExpert readable on all ranks after barrier
        syncFlag_.BarrierAll();

        // Step 4: AllGather each rank's numTokensPerExpert (cross-rank read)
        AllGatherSendData();  // allgather each rank's sendCount
        SyncAll<true>();

        // Step 5: Post-processing (local compute, no cross-rank dependency)
        ReloadRecvData();
        int32_t remainBlockIdx = blockNum_ / POST_PROC_BLOCK_GROUP_DIVISOR;
        BuildTotalRecvCount();
        if (blockIdx_ == remainBlockIdx + BUILD_MAX_BS_BLOCK_OFFSET) {
            BuildMaxBs();
        } else if (blockIdx_ == remainBlockIdx + BUILD_TOTAL_RECV_TOKENS_BLOCK_OFFSET) {
            BuildTotalRecvTokens();
        } else if (blockIdx_ == remainBlockIdx + BUILD_RECV_TOKEN_PER_EXP_BLOCK_OFFSET) {
            BuildRecvTokenPerExp();
        }
        SyncAll<true>();
    }

    __aicore__ inline ZbSyncFlagImpl::ZbSyncFlag &GetSyncFlag() { return syncFlag_; }

private:
    template <typename F>
    __aicore__ inline void SetAtomic(int op);
    __aicore__ inline void UnsetAtomic(int op);
    template <HardEvent eventType>
    __aicore__ inline void SetWaitEvent(event_t eventId);
    template <typename K, typename U = K>
    __aicore__ inline void CpGM2GMPingPong(int64_t dataSizeRemain, const GlobalTensor<U> &sendDataInputGt,
        const GlobalTensor<K> &recvDataOutputGT, int op);
    // Collective / EP context
    int epRankId_;
    int epWorldSize_;
    int64_t blockIdx_;  // Index of the current aicore
    int64_t blockNum_;  // Total number of aicores for the current epRankId_
    int localRank = 0;
    int localRankSize = 0;
    uint32_t extraFlag;
    uint32_t topkNum_;
    int sendPerGroup = 1;
    int64_t len;
    int64_t numExperts;

    GlobalTensor<int32_t> recvDataGt_;
    GlobalTensor<int32_t> recvCntGt;

    LocalTensor<int32_t> recvDataTensor_;
    uint32_t numTokensPerExpertAlignLen_{0};
    uint32_t allRecvCountDataAlignLen_{0};
    uint32_t recvDataAlignLen_{0};
    uint32_t sendDataOffsetAlignLen{0};

    TPipe pipe_;
    TBuf<QuePosition::VECCALC> tBuf;
    ZbSyncFlagImpl::ZbSyncFlag syncFlag_;
    TBuf<> sendCountBuf_;
    TBuf<> recvDataBuf_;
    TBuf<> localRecvDataBuf_;
    TBuf<> tmpBuf_;
    TBuf<> tmpBuf2_;
    TBuf<> tmpBuf3_;
    TBuf<> tmpBuf4_;

    __gm__ int *numTokensPerExpertInput;
    __gm__ T *recvDataOutput;
    __gm__ int32_t *allRecvCountOutput_;
    GM_ADDR numTokensPerExpert_;
    GM_ADDR totalRecvTokens_;
    GM_ADDR allRecvCount_;
    GM_ADDR maxBs_;
    GM_ADDR recvTokensPerExpert_;
    GM_ADDR recvData_;

    GM_ADDR gva_gm;
    GM_ADDR shareRecvDataAddrs[CAM_MAX_RANK_SIZE];  // List of shmem asymmetric output addresses (send_data)

    __aicore__ inline void SplitCoreCal(uint32_t totalNum, uint32_t &perCoreNum, uint32_t &startIdx, uint32_t &endIdx)
    {
        perCoreNum = totalNum / blockNum_;
        uint32_t remainderRankNum = totalNum % blockNum_;

        startIdx = perCoreNum * blockIdx_;
        if (blockIdx_ < remainderRankNum) {
            perCoreNum++;
            startIdx += blockIdx_;
        } else {
            startIdx += remainderRankNum;
        }
        endIdx = startIdx + perCoreNum;
    }

    // AllGather each rank's num_tokens_per_expert with a core-split strategy
    __aicore__ inline void AllGatherSendData()
    {
        uint32_t rankNumPerBlock = 0U;
        uint32_t startRankId = 0U;
        uint32_t endRankId = 0U;
        SplitCoreCal(epWorldSize_, rankNumPerBlock, startRankId, endRankId);
        if (rankNumPerBlock == 0U) {
            return;
        }

        AscendC::GlobalTensor<int32_t> gmRemoteDataGt;
        for (uint32_t targetRankId = startRankId; targetRankId < endRankId; targetRankId++) {
            auto ptr = shmem_ptr(numTokensPerExpert_, targetRankId);
            gmRemoteDataGt.SetGlobalBuffer(reinterpret_cast<__gm__ int32_t *>(ptr));

            CpGM2GMPingPong<int32_t>(numExperts * sizeof(int32_t), gmRemoteDataGt,
                recvDataGt_[targetRankId * numExperts], COPYONLY);

            PipeBarrier<PIPE_ALL>();
        }
    }

    __aicore__ inline void ReloadRecvData()
    {
        pipe_.Reset();
        pipe_.InitBuffer(recvDataBuf_, recvDataAlignLen_);

        recvDataTensor_ = recvDataBuf_.Get<int32_t>();
        DataCopyExtParams recvDataParams = {1U, static_cast<uint32_t>(recvDataAlignLen_), 0, 0, 0};
        DataCopyPadExtParams<int32_t> DataCopyPadExtParams{false, 0U, 0U, 0U};
        DataCopyPad(recvDataTensor_, recvDataGt_, recvDataParams, DataCopyPadExtParams);
        PipeBarrier<PIPE_ALL>();
    }

    __aicore__ inline void ReorderRecvDataOutput(int32_t rankId, LocalTensor<int32_t> &transLt, bool isCumSum = false)
    {
        uint32_t moeExpertPerRankNum = numExperts / epWorldSize_;
        uint32_t startExpId = rankId * moeExpertPerRankNum;
        uint32_t endExpId = rankId * moeExpertPerRankNum + moeExpertPerRankNum;

        SyncFunc<AscendC::HardEvent::V_S>();
        SyncFunc<AscendC::HardEvent::MTE2_S>();
        // Transpose recv_data
        int32_t prefixSum = 0;  // per-rank prefix sum as offsets, starting at 0
        for (uint32_t expId = startExpId; expId < endExpId; ++expId) {
            for (uint32_t srcRank = 0; srcRank < epWorldSize_; ++srcRank) {
                uint32_t index = (expId - startExpId) * epWorldSize_ + srcRank;
                uint32_t pairIdx = srcRank * numExperts + expId;

                int32_t curRecvCount = recvDataTensor_(pairIdx);
                // Fill with prefix-sum offset or raw count
                transLt(index) = isCumSum ? prefixSum : curRecvCount;
                prefixSum += curRecvCount;
            }
        }
        PipeBarrier<PIPE_ALL>();
        SyncFunc<AscendC::HardEvent::S_MTE2>();
    }

    __aicore__ inline void BuildMaxBs()
    {
        // Requires recvData
        pipe_.InitBuffer(localRecvDataBuf_,
            Ceil(numExperts * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);

        pipe_.InitBuffer(tmpBuf_, Ceil(numExperts * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        pipe_.InitBuffer(tmpBuf2_, Ceil(numExperts * sizeof(float), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        pipe_.InitBuffer(tmpBuf3_, Ceil(numExperts * sizeof(float), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        pipe_.InitBuffer(tmpBuf4_, Ceil(numExperts * sizeof(float), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);

        DataCopyExtParams copyParams = {1U, static_cast<uint32_t>(numExperts * sizeof(int32_t)), 0, 0, 0};
        DataCopyPadExtParams<int32_t> copyPadExtParams{false, 0U, 0U, 0U};

        LocalTensor<int32_t> numTokensPerExpertLt = localRecvDataBuf_.Get<int32_t>();
        LocalTensor<int32_t> maxBsLt = tmpBuf_.Get<int32_t>();
        LocalTensor<float> floatExpTokenCntLt = tmpBuf2_.Get<float>();
        LocalTensor<float> floatExpTokenSumCntLt = tmpBuf3_.Get<float>();
        LocalTensor<float> sharedTmpBuffer = tmpBuf4_.Get<float>();
        int32_t maxBsNum = 0;
        for (uint32_t srcRankId = 0; srcRankId < epWorldSize_; srcRankId++) {
            DataCopy(numTokensPerExpertLt, recvDataTensor_[numExperts * srcRankId], numExperts);
            PipeBarrier<PIPE_ALL>();
            SyncFunc<AscendC::HardEvent::MTE2_V>();

            Cast(floatExpTokenCntLt, numTokensPerExpertLt, RoundMode::CAST_NONE, numExperts);
            PipeBarrier<PIPE_V>();
            ReduceSum(floatExpTokenSumCntLt, floatExpTokenCntLt, sharedTmpBuffer, numExperts);
            SyncFunc<AscendC::HardEvent::V_S>();
            int32_t curRankBsNum = static_cast<int32_t>(floatExpTokenSumCntLt(0));
            maxBsNum = curRankBsNum > maxBsNum ? curRankBsNum : maxBsNum;
            PipeBarrier<PIPE_V>();
        }
        PipeBarrier<PIPE_V>();

        // Write to output GT
        GlobalTensor<int32_t> maxBsGt;
        maxBsGt.SetGlobalBuffer((__gm__ int32_t *)maxBs_);

        maxBsGt.SetValue(0, maxBsNum / topkNum_);
        DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(maxBsGt);
    }

    __aicore__ inline void BuildTotalRecvCount()
    {
        uint32_t maxUseCoreNum = epWorldSize_ > (blockNum_ / 2) ? (blockNum_ / 2) : epWorldSize_;
        uint32_t perCoreNum = epWorldSize_ / maxUseCoreNum;
        uint32_t remainderRankNum = epWorldSize_ % maxUseCoreNum;

        uint32_t startRankId = perCoreNum * blockIdx_;
        if (blockIdx_ < remainderRankNum) {
            perCoreNum += 1;
            startRankId += blockIdx_;
        } else {
            startRankId += remainderRankNum;
        }
        uint32_t endRankId = startRankId + perCoreNum;
        if (perCoreNum == 0U || blockIdx_ >= maxUseCoreNum) {
            return;
        }

        pipe_.InitBuffer(sendCountBuf_, Ceil(numExperts * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        LocalTensor<int32_t> recvTokenLt = sendCountBuf_.Get<int32_t>();

        for (uint32_t rank = startRankId; rank < endRankId; ++rank) {
            // Per-rank prefix sum
            ReorderRecvDataOutput(rank, recvTokenLt, true);  // localExpNum * ranks

            SyncFunc<AscendC::HardEvent::MTE2_MTE3>();
            DataCopyExtParams copyParams{1, static_cast<uint32_t>(numExperts * sizeof(int32_t)), 0, 0, 0};
            DataCopyPad(recvCntGt[rank * numExperts], recvTokenLt, copyParams);
        }
    }

    __aicore__ inline void BuildTotalRecvTokens()
    {
        // Need recvData; transpose and take this rank's slice
        pipe_.InitBuffer(localRecvDataBuf_,
            Ceil(numExperts * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);

        pipe_.InitBuffer(tmpBuf_, Ceil(1 * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        pipe_.InitBuffer(tmpBuf2_, Ceil(numExperts * sizeof(float), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        pipe_.InitBuffer(tmpBuf3_, Ceil(numExperts * sizeof(float), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);
        pipe_.InitBuffer(tmpBuf4_, Ceil(numExperts * sizeof(float), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);

        LocalTensor<int32_t> recvTokenLt = localRecvDataBuf_.Get<int32_t>();
        LocalTensor<int32_t> totalCntLt = tmpBuf_.Get<int32_t>();
        LocalTensor<float> floatExpTokenCntLt = tmpBuf2_.Get<float>();
        LocalTensor<float> floatExpTokenSumCntLt = tmpBuf3_.Get<float>();
        LocalTensor<float> sharedTmpBuffer = tmpBuf4_.Get<float>();
        int32_t sumVal = 0;  // max received-token count among ranks
        for (uint32_t srcRankId = 0; srcRankId < epWorldSize_; srcRankId++) {
            ReorderRecvDataOutput(srcRankId, recvTokenLt, false);  // localExpNum * ranks

            SyncFunc<AscendC::HardEvent::MTE2_V>();
            Cast(floatExpTokenCntLt, recvTokenLt, RoundMode::CAST_NONE, numExperts);
            PipeBarrier<PIPE_V>();
            ReduceSum(floatExpTokenSumCntLt, floatExpTokenCntLt, sharedTmpBuffer, numExperts);
            SyncFunc<AscendC::HardEvent::V_S>();
            int32_t recvCnt = static_cast<int32_t>(floatExpTokenSumCntLt.GetValue(0));
            PipeBarrier<PIPE_ALL>();
            sumVal = sumVal > recvCnt ? sumVal : recvCnt;
        }

        // Write to output GT
        GlobalTensor<int32_t> totalCntGt;
        totalCntGt.SetGlobalBuffer((__gm__ int32_t *)totalRecvTokens_);

        totalCntGt.SetValue(0, sumVal);
        DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(totalCntGt);
    }

    __aicore__ inline void BuildRecvTokenPerExp()
    {
        // Need recvData; transpose and take this rank's slice
        uint32_t moeExpertPerRankNum = numExperts / epWorldSize_;
        pipe_.InitBuffer(localRecvDataBuf_,
            Ceil(numExperts * sizeof(int32_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);

        pipe_.InitBuffer(tmpBuf_, Ceil(moeExpertPerRankNum * sizeof(int64_t), Moe::UB_ALIGN_SIZE) * Moe::UB_ALIGN_SIZE);

        LocalTensor<int32_t> recvTokenLt = localRecvDataBuf_.Get<int32_t>();
        ReorderRecvDataOutput(epRankId_, recvTokenLt, false);  // localExpNum * ranks
        SyncFunc<AscendC::HardEvent::MTE2_S>();

        LocalTensor<int64_t> tmpTensor = tmpBuf_.Get<int64_t>();
        for (uint32_t expId = 0; expId < moeExpertPerRankNum; ++expId) {
            int64_t localRecvCount = 0;
            for (uint32_t srcRank = 0; srcRank < epWorldSize_; ++srcRank) {
                uint32_t index = expId * epWorldSize_ + srcRank;
                localRecvCount += recvTokenLt(index);
            }
            tmpTensor(expId) = localRecvCount;
        }
        PipeBarrier<PIPE_ALL>();
        SyncFunc<AscendC::HardEvent::S_MTE2>();
        GlobalTensor<int64_t> recvTokenPerExpGt;
        recvTokenPerExpGt.SetGlobalBuffer((__gm__ int64_t *)recvTokensPerExpert_);
        DataCopyExtParams copyParams{1, static_cast<uint32_t>(moeExpertPerRankNum * sizeof(int64_t)), 0, 0, 0};
        SyncFunc<AscendC::HardEvent::MTE2_MTE3>();
        DataCopyPad(recvTokenPerExpGt, tmpTensor, copyParams);
    }
};

/**
 * @brief Copy data from GM to GM with ping-pong method.
 * @tparam dataSizeRemain The remaining size of data to be copied.
 * @tparam K The type of output data.
 * @tparam U The type of input data.
 * @param sendDataInputGt The global tensor of send data.
 * @param recvDataOutputGT The global tensor of recv data.
 * @param op The operation to be performed during the copy.
 * @details This function copies data from global memory to global memory using a ping-pong method.
 * It first checks if the input and output types are the same. If they are, it uses a single buffer.
 * If they are not, it divides the buffer according to the size ratio of the types and aligns it to 32 bytes.
 * Then, it sets the atomic operation, waits for the flags, and performs the copy operation.
 */
template <typename T>
template <typename K, typename U>
__aicore__ inline void NotifyDispatchZb<T>::CpGM2GMPingPong(int64_t dataSizeRemain,
    const GlobalTensor<U> &sendDataInputGt, const GlobalTensor<K> &recvDataOutputGT, int op)
{
    // General case (U = K), input/output are the same, share one UB
    // Only when conversion is needed (U->K), UB will be divided into two parts according to the ratio of
    // sizeof(U):sizeof(K) and aligned to 32 bytes
    constexpr int32_t ubBlockSize = UB_SINGLE_PING_PONG_ADD_SIZE_MAX;
    constexpr int32_t ubAlignNum = ubBlockSize / (sizeof(K) + sizeof(U)) / Moe::UB_ALIGN_SIZE * Moe::UB_ALIGN_SIZE;
    constexpr int32_t inputUbBlockSize = std::is_same_v<K, U> ? ubBlockSize : ubAlignNum * sizeof(U);
    constexpr int32_t outputUbBlockSize = std::is_same_v<K, U> ? ubBlockSize : ubAlignNum * sizeof(K);

    __gm__ U *input = const_cast<__gm__ U *>(sendDataInputGt.GetPhyAddr());
    __gm__ K *output = const_cast<__gm__ K *>(recvDataOutputGT.GetPhyAddr());
    __ubuf__ U *inputUB[2] = {(__ubuf__ U *)(UB_HEAD_OFFSET), (__ubuf__ U *)(UB_MID_OFFSET)};
    __ubuf__ K *outputUB[2] = {(__ubuf__ K *)inputUB[0], (__ubuf__ K *)inputUB[1]};
    if constexpr (!std::is_same_v<K, U>) {
        outputUB[0] = (__ubuf__ K *)(inputUB[0] + inputUbBlockSize / sizeof(U));
        outputUB[1] = (__ubuf__ K *)(inputUB[1] + inputUbBlockSize / sizeof(U));
    }
    int inputOffsetNum = 0;
    int outputOffsetNum = 0;
    if (dataSizeRemain <= 0) {
        return;
    }

    SetAtomic<K>(op);

    AscendC::SetFlag<HardEvent::MTE3_MTE2>(EVENT_ID0);  // MTE2 waits for MTE3
    AscendC::SetFlag<HardEvent::MTE3_MTE2>(EVENT_ID1);  // MTE2 waits for MTE3
    for (int64_t i = 0; dataSizeRemain > 0; i++) {
        // size and dataSizeRemain both refer to the output size
        uint32_t size = dataSizeRemain > outputUbBlockSize ? outputUbBlockSize : dataSizeRemain;
        event_t eventId = (i & 1) ? EVENT_ID0 : EVENT_ID1;
        AscendC::WaitFlag<HardEvent::MTE3_MTE2>(eventId);
        CpGM2UB((i & 1) ? inputUB[0] : inputUB[1], input + inputOffsetNum, size / sizeof(K) * sizeof(U));
        if constexpr (!std::is_same_v<K, U>) {
            SetWaitEvent<HardEvent::MTE2_V>(eventId);
            CastImpl((i & 1) ? outputUB[0] : outputUB[1], (i & 1) ? inputUB[0] : inputUB[1], RoundMode::CAST_NONE,
                size / sizeof(K));

            SetWaitEvent<HardEvent::V_MTE3>(eventId);
        }
        AscendC::SetFlag<HardEvent::MTE2_MTE3>(eventId);
        AscendC::WaitFlag<HardEvent::MTE2_MTE3>(eventId);
        CpUB2GM(output + outputOffsetNum, (i & 1) ? outputUB[0] : outputUB[1], size);
        AscendC::SetFlag<HardEvent::MTE3_MTE2>(eventId);

        dataSizeRemain -= size;
        inputOffsetNum += (size / sizeof(K));
        outputOffsetNum += (size / sizeof(K));
    }
    AscendC::WaitFlag<HardEvent::MTE3_MTE2>(EVENT_ID0);  // MTE2 waits for MTE3
    AscendC::WaitFlag<HardEvent::MTE3_MTE2>(EVENT_ID1);  // MTE2 waits for MTE3

    AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID3);  // Scalar waits for MTE3
    AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID3);

    UnsetAtomic(op);
    return;
}

template <typename T>
template <typename F>
__aicore__ inline void NotifyDispatchZb<T>::SetAtomic(int op)
{
    PipeBarrier<PIPE_ALL>();
    if (op != -1) {
#ifdef __DAV_C220_VEC__
        SetAtomicOpType<F>(op);
#endif
    }
    PipeBarrier<PIPE_ALL>();
}

template <typename T>
__aicore__ inline void NotifyDispatchZb<T>::UnsetAtomic(int op)
{
    if (op != -1) {
        AscendC::SetAtomicNone();
    }
    PipeBarrier<PIPE_ALL>();
}

template <typename T>
template <HardEvent eventType>
__aicore__ inline void NotifyDispatchZb<T>::SetWaitEvent(event_t eventId)
{
    AscendC::SetFlag<eventType>(eventId);
    AscendC::WaitFlag<eventType>(eventId);
}

#endif  // NOTIFY_DISPATCH_ZB_H
