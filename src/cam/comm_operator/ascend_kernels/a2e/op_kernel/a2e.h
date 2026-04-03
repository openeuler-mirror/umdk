/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: a2e function device header file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create a2e header file in device part
 */

#ifndef CAM_A2E_H
#define CAM_A2E_H

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

template <typename T, typename TQ, bool DynamicQuant>
class A2e {
    constexpr static uint32_t IPC_BUFF_MAX_SIZE_MUL_EXP = 800 * 1024 * 1024;
    constexpr static uint32_t UB_SINGLE_TOTAL_SIZE_MAX = 192 * 1024;
    constexpr static uint64_t MAGIC_OFFSET = 32;
    constexpr static uint32_t WAIT_FLAG_OFFSET_2 = 2;
    constexpr static uint32_t WAIT_FLAG_OFFSET_3 = 3;
    constexpr static uint32_t WAIT_FLAG_OFFSET_4 = 4;
    constexpr static uint32_t DOUBLE_BUFFER_COUNT = 2;
    constexpr static uint32_t BLOCK_IDX_USED_2 = 2;
    constexpr static uint32_t UB_OFFSET = 32;
    constexpr static uint32_t OPT_RANK_OFFSET = 512;
    constexpr static uint32_t INT64_COUNT_PER_BLOCK = 4;
    constexpr static uint32_t INT32_COUNT_PER_BLOCK = 8;
public:
    __aicore__ inline A2e(int rank, int rankSize)
    {
        this->rank = rank;
        this->rankSize = rankSize;
    }

    __aicore__ inline void init(GM_ADDR x, GM_ADDR expertIds, GM_ADDR expertScales, GM_ADDR expandX, \
            GM_ADDR simulateExpertIds, GM_ADDR simulateExpertScales, GM_ADDR attenBatchSize, \
            GM_ADDR xActiveMask, int64_t batchSize, int64_t hiddenSize, int64_t topk, int64_t expertRankSize, \
            int64_t attentionRankSize, int64_t rank, GM_ADDR tiling, int64_t computeGate)
    {
        this->magic = 0;
        this->batchSize = batchSize;
        this->hiddenSize = hiddenSize;
        this->topk = topk;
        this->expertRankSize = expertRankSize;
        this->attentionRankSize = attentionRankSize;
        this->computeGate = computeGate;

        this->blockIdx = GetBlockIdx();
        this->blockNum = GetBlockNum();

        this->flagUnitInt64Num = INT64_COUNT_PER_BLOCK;
        this->x = (__gm__ T *)x;

        this->attnToMoeRatio = attentionRankSize > expertRankSize ? (attentionRankSize + expertRankSize - 1) /
            expertRankSize : 1;
        if (expertRankSize != 1 && attentionRankSize > expertRankSize && rank % expertRankSize >= attentionRankSize %
            expertRankSize && attentionRankSize % expertRankSize != 0) {
            this->attnToMoeRatio-=1;
        }

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

        xGt.SetGlobalBuffer((__gm__ T *)x);
        expertIdsGt.SetGlobalBuffer((__gm__ int32_t *)expertIds);
        expertScalesGt.SetGlobalBuffer((__gm__ float *)expertScales);
        expandXGt.SetGlobalBuffer((__gm__ TQ *)expandX);
        simulateExpertIdsGt.SetGlobalBuffer((__gm__ int32_t *)simulateExpertIds);
        simulateExpertScalesGt.SetGlobalBuffer((__gm__ float *)simulateExpertScales);
        attenBatchSizeGt.SetGlobalBuffer((__gm__ int32_t *) attenBatchSize);
        xActiveMaskOutGt.SetGlobalBuffer((__gm__ bool *)xActiveMask);
    }

    __aicore__ inline void process()
    {
        if (computeGate == 0) {
            if (rank >= expertRankSize) {
                sendWithMte();
            } else {
                int sendRank = rank + expertRankSize;
                for (int i = 0; i < attnToMoeRatio; i++) {
                    recvBatchSize = batchSize / attnToMoeRatio;

                    recvWithMte(i);

                    sendRank += expertRankSize;
                }
            }
        } else {
            if (rank < expertRankSize) {
                int maskOutOffset = 0;
                int sendRank = rank + expertRankSize;
                for ( int i = 0; i < attnToMoeRatio; i++) {
                    recvBatchSize = batchSize / attnToMoeRatio;
                    // computeGate == 1 时去掉 mask 逻辑，保留分核逻辑
                    if (blockIdx < blockNum - 1) {
                        recvWithMte(i);
                    } else {
                        recvExpertIdsWithMte(i);
                    }
                    sendRank += expertRankSize;
                    maskOutOffset += recvBatchSize;
                }
            } else {
                sendWithMte();
            }
        }
    }

private:
    __aicore__ inline void waitFlagWithScalar(int addr, uint32_t magic) {
        GlobalTensor<uint32_t> flagGt;
        flagGt.SetGlobalBuffer((__gm__ uint32_t *)(shareAddrs[rank] + addr));
        while(1) {
            DATA_FULSH(flagGt, uint32_t);
            if (flagGt.GetValue(0) == magic) {
                return;
            }
        }
    }

    __aicore__ inline void sendExpertIds(int sendOffset, int expertIdsOffset) {
        GlobalTensor<int32_t> shareExpertIdsGt;
        shareExpertIdsGt.SetGlobalBuffer((__gm__ int32_t *)(shareAddrs[rank] + IPC_DATA_OFFSET + expertIdsOffset));
        CpGM2GMPingPong(batchSize * topk * sizeof(int32_t), expertIdsGt, shareExpertIdsGt, COPYONLY);

        LocalTensor<uint64_t> flagLt = tBuf.GetWithOffset<uint64_t>(1, 0);
        flagLt.SetValue(0, mergeMagicWithValue(magic, 0));

        GlobalTensor<uint64_t> shareFlagGt;
        shareFlagGt.SetGlobalBuffer((__gm__ uint64_t *)(shareAddrs[rank % expertRankSize]) + 
            (1 * attnToMoeRatio + sendOffset) * flagUnitInt64Num);

        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
        camCpUB2GM(shareFlagGt, flagLt, 1, sizeof(uint64_t));

        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);

        SyncAll();
    }

    __aicore__ inline void sendExpertScales(int sendOffset, int expertScalesOffset) {
        GlobalTensor<float> shareExpertScalesGt;
        shareExpertScalesGt.SetGlobalBuffer((__gm__ float *)(shareAddrs[rank] + IPC_DATA_OFFSET +
            expertScalesOffset));
        CpGM2GMPingPong(batchSize * topk * sizeof(float), expertScalesGt, shareExpertScalesGt, COPYONLY);

        LocalTensor<uint64_t> flagLt = tBuf.GetWithOffset<uint64_t>(1, 0);
        flagLt.SetValue(0, mergeMagicWithValue(magic, 0));

        GlobalTensor<uint64_t> shareFlagGt;
        shareFlagGt.SetGlobalBuffer((__gm__ uint64_t *)(shareAddrs[rank % expertRankSize]) + 
            (WAIT_FLAG_OFFSET_2 * attnToMoeRatio + sendOffset) * flagUnitInt64Num);

        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
        camCpUB2GM(shareFlagGt, flagLt, 1, sizeof(uint64_t));

        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);

        SyncAll();
    }

    __aicore__ inline void sendBatchSize(int sendOffset) {
        LocalTensor<int32_t> batchSizeLt = tBuf.GetWithOffset<int32_t>(1, 0);
        batchSizeLt.SetValue(0, batchSize);

        GlobalTensor<int32_t> batchSizeGt;
        batchSizeGt.SetGlobalBuffer((__gm__ int32_t *)(shareAddrs[rank] + IPC_DATA_OFFSET));
        camCpUB2GM(batchSizeGt, batchSizeLt, 1, sizeof(int32_t));
        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);

        LocalTensor<uint64_t> flagLt = tBuf.GetWithOffset<uint64_t>(1, UB_OFFSET);
        flagLt.SetValue(0, mergeMagicWithValue(magic, 0));

        GlobalTensor<uint64_t> shareFlagGt;
        shareFlagGt.SetGlobalBuffer((__gm__ uint64_t *)(shareAddrs[rank % expertRankSize]) + 
            (WAIT_FLAG_OFFSET_4 * attnToMoeRatio + sendOffset) * flagUnitInt64Num);

        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
        camCpUB2GM(shareFlagGt, flagLt, 1, sizeof(uint64_t));

        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);

        SyncAll();
    }

    __aicore__ inline void sendX(int sendOffset, int xOffset) {
        GlobalTensor<T> shareXGt;
        shareXGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[rank] + IPC_DATA_OFFSET + xOffset));
        
        // 当computeGate == 0时，使用blockNum，因为已经分出去一个核发送batchsize
        // 当computeGate == 1时，使用blockNum - BLOCK_IDX_USED_2
        int actualBlockNum = (computeGate == 0) ? blockNum : (blockNum - BLOCK_IDX_USED_2);
        
        copyGmToGmWithBlocks(shareXGt, xGt, batchSize * hiddenSize, actualBlockNum, blockIdx);

        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);

        SyncAll();

        LocalTensor<uint64_t> flagLt = tBuf.GetWithOffset<uint64_t>(1, 0);
        flagLt.SetValue(0, mergeMagicWithValue(magic, 0));

        GlobalTensor<uint64_t> shareFlagGt;
        shareFlagGt.SetGlobalBuffer((__gm__ uint64_t *)(shareAddrs[rank % expertRankSize]) + 
            (WAIT_FLAG_OFFSET_3 * attnToMoeRatio + sendOffset) * flagUnitInt64Num);

        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
        camCpUB2GM(shareFlagGt, flagLt, 1, sizeof(uint64_t));
    }

    __aicore__ inline void sendWithMte() {
        int sendOffset = rank / expertRankSize - 1;
        int expertIdsReserveSize = batchSize * topk * sizeof(int32_t);
        int expertScalesReserveSize = batchSize * topk * sizeof(float);
        int xReserveSize = batchSize * hiddenSize * sizeof(T);
        int xOffset = sizeof(int32_t) + expertIdsReserveSize + expertScalesReserveSize;
        int expertScalesOffset = sizeof(int32_t) + expertIdsReserveSize;
        int expertIdsOffset = sizeof(int32_t);

        if (computeGate == 0) {
            // 当computeGate == 0时，分出去一个核去发batchsize，blockNum - 1个核发token
            sendX(sendOffset, xOffset);
        } else {
            // 保持computeGate == 1时的逻辑不变
            if (blockIdx == blockNum - 1) {
                sendExpertIds(sendOffset, expertIdsOffset);
            } else if (blockIdx == blockNum - BLOCK_IDX_USED_2) {
                sendExpertScales(sendOffset, expertScalesOffset);
            } else {
                sendX(sendOffset, xOffset);
            }
        }
    }

    __aicore__ inline uint64_t mergeMagicWithValue(uint32_t magic, uint32_t count)
    {
        return (static_cast<uint64_t>(magic) << MAGIC_OFFSET) | static_cast<uint64_t>(count);
    }

    __aicore__ inline void recvWithMte(int index) {
        int expertIdsReserveSize = recvBatchSize * topk * sizeof(int32_t);
        int expertScalesReserveSize = recvBatchSize * topk * sizeof(float);
        int xOffset = sizeof(int32_t) + expertIdsReserveSize + expertScalesReserveSize;
        int expertScalesOffset = sizeof(int32_t) + expertIdsReserveSize;

        int sendRank = rank + (index + 1) * expertRankSize;
        
        if (computeGate == 0) {
            // When computeGate == 0, only receive x, not receive expertscales
            waitFlagWithScalar((WAIT_FLAG_OFFSET_3 * attnToMoeRatio + index) * flagUnitInt64Num * sizeof(uint64_t) +
                sizeof(uint32_t), magic);
            GlobalTensor<T> shareXGt;
            shareXGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[sendRank] + IPC_DATA_OFFSET + xOffset));
            // When computeGate == 0, use blockNum - 1 cores to receive x
            copyGmToGmWithBlocks(expandXGt[expandXOutputOffset], shareXGt, recvBatchSize * hiddenSize, blockNum - 1,
                blockIdx);
            expandXOutputOffset += recvBatchSize * hiddenSize;
        } else {
            // Keep the logic for computeGate == 1 unchanged
            waitFlagWithScalar((WAIT_FLAG_OFFSET_2 * attnToMoeRatio + index) * flagUnitInt64Num * sizeof(uint64_t) +
                sizeof(uint32_t), magic);

            GlobalTensor<float> shareExpertScalesGt;
            shareExpertScalesGt.SetGlobalBuffer((__gm__ float *)(shareAddrs[sendRank] + IPC_DATA_OFFSET +
                expertScalesOffset));
            
            // When computeGate == 1, use blockNum - 1
            copyGmToGmWithBlocks(simulateExpertScalesGt[expertScalesOutputOffset], shareExpertScalesGt,
                recvBatchSize * topk, blockNum - 1, blockIdx);
            expertScalesOutputOffset += recvBatchSize * topk;

            waitFlagWithScalar((WAIT_FLAG_OFFSET_3 * attnToMoeRatio + index) * flagUnitInt64Num * sizeof(uint64_t) +
                sizeof(uint32_t), magic);
            GlobalTensor<T> shareXGt;
            shareXGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[sendRank] + IPC_DATA_OFFSET + xOffset));
            copyGmToGmWithBlocks(expandXGt[expandXOutputOffset], shareXGt, recvBatchSize * hiddenSize, blockNum - 1,
                blockIdx);
            expandXOutputOffset += recvBatchSize * hiddenSize;
        }
    }

    __aicore__ inline void recvExpertIdsWithMte(int index) {
        waitFlagWithScalar((1 * attnToMoeRatio + index) * flagUnitInt64Num * sizeof(uint64_t) + sizeof(uint32_t),
            magic);

        int sendRank = rank + (index + 1) * expertRankSize;
        int expertIdsOffset = sizeof(int32_t);
        int ubOffset = 1024;
        LocalTensor<int32_t> expertIdsLt = tBuf.GetWithOffset<int32_t>(recvBatchSize * topk, ubOffset);

        GlobalTensor<int32_t> shareExpertIdsGt;
        shareExpertIdsGt.SetGlobalBuffer((__gm__ int32_t *)(shareAddrs[sendRank] + IPC_DATA_OFFSET + expertIdsOffset));
        camCpGM2UB(expertIdsLt, shareExpertIdsGt, recvBatchSize * topk * sizeof(int32_t));

        AscendC::SetFlag<HardEvent::MTE2_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE2_MTE3>(EVENT_ID0);
        camCpUB2GM(simulateExpertIdsGt[expertIdsOutputOffset], expertIdsLt, 1, recvBatchSize * topk * sizeof(int32_t));
        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);
        expertIdsOutputOffset += recvBatchSize * topk;
    }

    GlobalTensor<T> xGt;
    GlobalTensor<int32_t> expertIdsGt;
    GlobalTensor<float> expertScalesGt;
    GlobalTensor<TQ> expandXGt;
    GlobalTensor<int32_t> simulateExpertIdsGt;
    GlobalTensor<float> simulateExpertScalesGt;
    GlobalTensor<int32_t> attenBatchSizeGt;
    GlobalTensor<bool> xActiveMaskOutGt;
    GlobalTensor<int32_t> magicTensor_;

    __gm__ T *x;
    __gm__ TQ *expandX;
    __gm__ float *dynamicScales;
    __gm__ HcclOpResParam *epWinContext_{nullptr};
    TPipe pipe;
    TBuf<QuePosition::VECCALC> tBuf;
    GM_ADDR shareAddrs[CAM_MAX_RANK_SIZE];

    int batchSize;
    int hiddenSize;
    int topk;
    int expertRankSize;
    int attentionRankSize;
    int flagUnitInt64Num;
    int recvBatchSize;
    int attnToMoeRatio;
    int expandXOutputOffset = 0;
    int expertIdsOutputOffset = 0;
    int expertScalesOutputOffset = 0;
    int rank;
    int rankSize;
    int64_t computeGate;
    int64_t magic;
    int64_t blockIdx;
    int64_t blockNum;
};

#endif // CAM_A2E_H