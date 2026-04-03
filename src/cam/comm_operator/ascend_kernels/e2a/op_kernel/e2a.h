/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: e2a function device header file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create e2a header file in device part
 */

#ifndef CAM_E2A_H
#define CAM_E2A_H

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "moe_distribute_base.h"
#include "data_copy.h"

using namespace AscendC;

#define DATA_FULSH(_gm_tensor, _type) \
    Barrier(); \
    DataCacheCleanAndInvalid<_type, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(_gm_tensor); \
    __asm__("NOP"); \
    dsb(DSB_ALL);

template <typename T>
class E2a {
    constexpr static uint32_t IPC_BUFF_MAX_SIZE_MUL_EXP = 800 * 1024 * 1024;
    constexpr static uint32_t UB_SINGLE_TOTAL_SIZE_MAX = 192 * 1024;
    constexpr static int64_t MAGIC_OFFSET = 32;
    constexpr static uint32_t INT32_COUNT_PER_BLOCK = 8;
    constexpr static uint32_t DOUBLE_BUFFER_COUNT = 2;
    constexpr static uint32_t OPT_RANK_OFFSET = 512;
public:
    __aicore__ inline E2a(int rank, int rankSize)
    {
        this->rank = rank;
        this->rankSize = rankSize;
    }
    __aicore__ inline void init(GM_ADDR expandX, GM_ADDR attenBatchSize, GM_ADDR x, int64_t batchSize, \
            int64_t hiddenSize, int64_t topk, int64_t expertRankSize, \
            int64_t attentionRankSize, int64_t rank, GM_ADDR tiling)
    {
        this->magic = 0;
        this->batchSize = batchSize;
        this->hiddenSize = hiddenSize;
        this->topk = topk;
        this->expertRankSize = expertRankSize;
        this->attentionRankSize = attentionRankSize;

        this->blockIdx = GetBlockIdx();
        this->blockNum = GetBlockNum();

        pipe.InitBuffer(tBuf, UB_SINGLE_TOTAL_SIZE_MAX);
        
        epWinContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<HCCL_GROUP_ID_0>();

        // Set and auto-increment magic
        magicTensor_.SetGlobalBuffer((__gm__ int32_t*)((epWinContext_->localWindowsIn) + 
            IPC_DATA_OFFSET - blockNum * sizeof(int32_t) * INT32_COUNT_PER_BLOCK)); 

        LocalTensor<int32_t> tempLocal = tBuf.GetWithOffset<int32_t>(INT32_COUNT_PER_BLOCK, 0);
        tempLocal(0) = 1;
        // Implement the increment by 1 operation using atomic methods
        AscendC::SetAtomicAdd<int32_t>();
        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0); // wait setvalue finish
        DataCopy(magicTensor_[blockIdx * INT32_COUNT_PER_BLOCK], tempLocal, INT32_COUNT_PER_BLOCK);
        AscendC::SetAtomicNone();
        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0); // wait DataCopy finish
        this->magic = magicTensor_.GetValue(blockIdx * INT32_COUNT_PER_BLOCK);
        PipeBarrier<PIPE_ALL>();

        if (rank >= expertRankSize) {
            shareAddrs[rank] = (GM_ADDR)(epWinContext_->localWindowsIn) + (this->magic % DOUBLE_BUFFER_COUNT) *
                IPC_BUFF_MAX_SIZE_MUL_EXP + rank * OPT_RANK_OFFSET;
            shareAddrs[rank % expertRankSize] = (GM_ADDR)(((HcclRankRelationResV2 *)(epWinContext_->
                remoteRes[rank % expertRankSize].nextDevicePtr))->windowsIn) + (this->magic % DOUBLE_BUFFER_COUNT) *
                IPC_BUFF_MAX_SIZE_MUL_EXP + (rank % expertRankSize) * OPT_RANK_OFFSET;
            pipe_barrier(PIPE_ALL);
        } else {
            pipe_barrier(PIPE_ALL);

            for (int i = 0; i < rankSize; i++) {
                if (i == rank) {
                    shareAddrs[i] = (GM_ADDR)(epWinContext_->localWindowsIn) + (this->magic % DOUBLE_BUFFER_COUNT) *
                        IPC_BUFF_MAX_SIZE_MUL_EXP + rank * OPT_RANK_OFFSET;
                    continue;
                }
                shareAddrs[i] = (GM_ADDR)(((HcclRankRelationResV2 *)(epWinContext_->remoteRes[i].nextDevicePtr))->
                    windowsIn) + (this->magic % DOUBLE_BUFFER_COUNT) * IPC_BUFF_MAX_SIZE_MUL_EXP + i * OPT_RANK_OFFSET;
            }
        }

        expandXGt.SetGlobalBuffer((__gm__ T *)expandX);
        attenBatchSizeGt.SetGlobalBuffer((__gm__ int32_t *)attenBatchSize);
        xGt.SetGlobalBuffer((__gm__ T *)x);

        this->attnToMoeRatio = attentionRankSize > expertRankSize ? (attentionRankSize + expertRankSize - 1) /
            expertRankSize : 1;
        if (expertRankSize != 1 && attentionRankSize > expertRankSize && rank % expertRankSize >= attentionRankSize %
            expertRankSize && attentionRankSize % expertRankSize != 0) {
            attnToMoeRatio-=1;
        }
    }

    __aicore__ inline void process()
    {
        if (rank < expertRankSize) {
            sendWithMte();
        } else {
            recvWithMte();
        }
    }

private:

    __aicore__ inline uint64_t mergeMagicWithValue(uint32_t magic, uint16_t offset, uint16_t count)
    {
        return (static_cast<uint64_t>(magic) << MAGIC_OFFSET) | static_cast<uint64_t>(offset) |
            static_cast<uint64_t>(count);
    }

    __aicore__ inline void sendWithMte()
    {
        int sendRank = rank + expertRankSize;
        int sendOffset = 0;
        int sendBatchSize = batchSize / attnToMoeRatio;
        for (int i = 0; i < attnToMoeRatio; i++) {
            GlobalTensor<T> shareXGt;
            shareXGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[sendRank] + IPC_DATA_OFFSET));
            copyGmToGmWithBlocks(shareXGt, expandXGt[sendOffset], sendBatchSize * hiddenSize, blockNum, blockIdx);
            sendOffset += sendBatchSize * hiddenSize;
            sendRank += expertRankSize;
        }

        SyncAll();
        LocalTensor<uint64_t> flagLt = tBuf.GetWithOffset<uint64_t>(1, 0);
        flagLt.SetValue(0, mergeMagicWithValue(magic, 0, 0));

        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);

        sendRank = rank + expertRankSize;

        for (int i = 0; i < attnToMoeRatio; i++) {
            GlobalTensor<uint64_t> shareFlagGt;
            shareFlagGt.SetGlobalBuffer((__gm__ uint64_t *)(shareAddrs[sendRank]));

            camCpUB2GM(shareFlagGt, flagLt, 1, sizeof(uint64_t));
            sendRank += expertRankSize;
        }
    }

    __aicore__ inline void recvWithMte()
    {
        GlobalTensor<uint64_t> flagGt;
        flagGt.SetGlobalBuffer((__gm__ uint64_t *)(shareAddrs[rank]));
        LocalTensor<uint64_t> flagLt = tBuf.GetWithOffset<uint64_t>(1, 0);
        while (1) {
            camCpGM2UB(flagLt, flagGt, sizeof(uint64_t));
            SetFlag<HardEvent::MTE2_S>(EVENT_ID0);
            WaitFlag<HardEvent::MTE2_S>(EVENT_ID0);
            if (flagLt.GetValue(0) == mergeMagicWithValue(magic, 0, 0)) {
                break;
            }
        }

        GlobalTensor<T> shareXGt;
        shareXGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[rank] + IPC_DATA_OFFSET));
        copyGmToGmWithBlocks(xGt, shareXGt, batchSize * hiddenSize, blockNum, blockIdx);
    }

    GlobalTensor<T> expandXGt;
    GlobalTensor<T> xGt;
    GlobalTensor<int32_t> attenBatchSizeGt;
    GlobalTensor<int32_t> magicTensor_;

    __gm__ T *x;
    __gm__ T *expandX;
    __gm__ HcclOpResParam *epWinContext_{nullptr};
    TPipe pipe;
    TBuf<QuePosition::VECCALC> tBuf;
    GM_ADDR shareAddrs[CAM_MAX_RANK_SIZE];

    int batchSize;
    int hiddenSize;
    int topk;
    int expertRankSize;
    int attentionRankSize;
    int attnToMoeRatio;
    int rank;
    int rankSize;
    int64_t magic;
    int64_t blockIdx;
    int64_t blockNum;
};

#endif // CAM_E2A_H