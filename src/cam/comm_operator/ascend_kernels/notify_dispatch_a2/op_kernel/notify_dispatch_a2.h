/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: notify dispatch A2 kernel part operator implementation
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create notify dispatch A2 kernel part operator implementation
 */

#ifndef NOTIFY_DISPATCH_A2_H
#define NOTIFY_DISPATCH_A2_H

#include <climits>
#include "kernel_operator.h"

#include "comm_args.h"
#include "data_copy.h"
#include "moe_distribute_base.h"
#include "notify_dispatch_tiling_a2.h"

using namespace AscendC;
using namespace Moe;

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

template <typename T>
class NotifyDispatchA2 {
    constexpr static int32_t MAX_CORE_NUM = 20;
    constexpr static int64_t MULTI_RANK_SIZE = 4;  // 64 rank scenario, each core sends to no more than 4 ranks
    constexpr static int64_t MAX_RANK_SIZE = 64;   // 910B max rank size
    constexpr static int32_t INVALID_RANK = -1;
    constexpr static uint32_t TEMP_BUF_LEN = 128 * 1024;  // tBuf length 128K，other part for other buf

    constexpr static uint32_t BW_ITEM_SIZE = 32;                               // = sizeof(BatchWriteItem)
    constexpr static uint32_t U64_PER_ITEM = BW_ITEM_SIZE / sizeof(uint64_t);  // each BatchWriteItem unit64 num
    constexpr static uint32_t U32_PER_ITEM = BW_ITEM_SIZE / sizeof(uint32_t);  // each BatchWriteItem unit32 num
    constexpr static uint32_t BW_MEB_OFFSET64_LOCAL_GM = 0;  // BatchWriteItem offset，sizeof(unit64)
    constexpr static uint32_t BW_MEB_OFFSET64_REMOTE_GM = 1;  // BatchWriteItem offset，sizeof(unit64)
    constexpr static uint32_t BW_MEB_OFFSET64_DATA_SIZE = 2;  // BatchWriteItem offset，sizeof(unit64)
    constexpr static uint32_t BW_MEB_OFFSET32_DATA_TYPE = 6;  // BatchWriteItem offset，sizeof(unit32)
    constexpr static uint32_t BW_MEB_OFFSET32_TARGET_RANK = 7;  // BatchWriteItem offset，sizeof(unit32)

    constexpr static int32_t FLAG_VALUE = 0xFFFFFFFF;
    constexpr static uint32_t STATUS_ENTRY_SIZE = 32;  // each status entry size, bytes
    constexpr static uint32_t U32_STATUS_ENTRY = STATUS_ENTRY_SIZE / sizeof(int32_t);
    constexpr static uint32_t FLAG_OFFSET = 8;          // status_flag offset in statusTensor中, bytes
    constexpr static uint32_t SOURCE_RANK_OFFSET = 16;  // sourceRankId offset in statusTensor, bytes
    constexpr static uint32_t DEST_RANK_OFFSET = 20;    // destRankId offset in statusTensor, bytes
    constexpr static uint32_t DATALEN_OFFSET = 24;      // dataLen offset in statusTensor, bytes
    constexpr static uint32_t UB_ALIGN = 32;            // UB align
    constexpr static uint64_t EXP_TOKEN_COUNT_FLAG_CNT = UB_ALIGN / sizeof(uint64_t);  // 4
    constexpr static uint32_t GM_ALIGN = 64;                                           // GM align

    constexpr static uint32_t MAX_BS = 4096;  // max batchsize for each rank
    // Synchronization flag occupies length
    constexpr static int64_t FLAG_UNIT_INT_NUM = 4;
    constexpr static int64_t MAGIC_MASK = ~((1LL << 32) - 1);
    constexpr static int64_t NUM_2 = 2;
    constexpr static int64_t NUM_3 = 3;
    constexpr static int64_t NUM_4 = 4;
    constexpr static int64_t NUM_1000 = 1000;

public:
    __aicore__ inline NotifyDispatchA2(int rank, int rankSize, uint32_t extraFlag)
        : rank(rank), rankSize(rankSize), extraFlag(extraFlag)
    {}

    __aicore__ inline void Init(GM_ADDR sendDataInput, GM_ADDR tokenPerExpertDataInput, GM_ADDR tmpDataInput,
        GM_ADDR sendDataOffsetOutput,
        GM_ADDR recvDataOutput, int64_t len, int64_t numTokens, int64_t topkNum, int64_t numExperts, int op, int root,
        int cycleCount, GM_ADDR scale, int64_t scaleCount, GM_ADDR offset, int localRank, int localRankSize,
        GM_ADDR tokenServerIdxOutput, GM_ADDR tokensUniquePerServerOutput, GM_ADDR epRankTokenCntOutput,
        GM_ADDR localEpTokenCntOutput, GM_ADDR srcOffsetRankTokenIdxOutput, GM_ADDR dstOffsetRankTokenIdxOutput,
        GM_ADDR offsetInnerOutput, GM_ADDR countOuterOutput, GM_ADDR expandIdxOutput, GM_ADDR totalRecvTokensOutput,
        GM_ADDR workspace, GM_ADDR tiling)
    {
        return;
    }

    __aicore__ inline void Process()
    {
        return;
    }

private:
    __aicore__ inline void InitAll2AllLayeredRdma(GM_ADDR sendDataInput, GM_ADDR tokenPerExpertDataInput,
        GM_ADDR tmpDataInput, GM_ADDR sendDataOffsetOutput,
        GM_ADDR recvDataOutput, int64_t len, int64_t numTokens, int64_t topkNum, int64_t numExperts, int op, int root,
        int cycleCount, GM_ADDR scale, int64_t scaleCount, GM_ADDR offset, int localRank, int localRankSize,
        GM_ADDR tokenServerIdxOutput, GM_ADDR tokensUniquePerServerOutput, GM_ADDR epRankTokenCntOutput,
        GM_ADDR localEpTokenCntOutput, GM_ADDR srcOffsetRankTokenIdxOutput, GM_ADDR dstOffsetRankTokenIdxOutput,
        GM_ADDR offsetInnerOutput, GM_ADDR countOuterOutput, GM_ADDR expandIdxOutput, GM_ADDR totalRecvTokensOutput,
        GM_ADDR workspace, GM_ADDR tiling)
    {
        this->root = 0;
        this->len = len;
        this->numExperts = numExperts;
        this->numTokens = numTokens;
        this->topkNum = topkNum;
        this->scale = nullptr;
        this->magic = 0;
        this->localRank = localRank;
        this->localRankSize = localRankSize;
        this->xRankSize = localRankSize;
        this->yRankSize = rankSize / localRankSize;
        this->xRankIdx = rank % localRankSize;
        this->yRankIdx = rank / localRankSize;
        this->blockIdx = GetBlockIdx();
        this->blockNum = GetBlockNum();
        uint8_t ctxIdx;

        ctxIdx = COMM_EP_IDX;

        // init RDMA params
        auto tilingData = (__gm__ NotifyDispatchA2TilingData *)tiling;
        __gm__ void *mc2InitTiling = (__gm__ void *)(&(tilingData->mc2InitTiling));
        __gm__ void *mc2CcTiling = (__gm__ void *)(&(tilingData->mc2CcTiling1));

        auto contextGM0 = AscendC::GetHcclContext<HCCL_GROUP_ID_0>();

        hccl_.Init(contextGM0, mc2InitTiling);
        hccl_.SetCcTiling(mc2CcTiling);
        this->winContext_[COMM_EP_IDX] = (__gm__ HcclOpResParam *)contextGM0;
        notifyMemoryOffset = winContext_[COMM_EP_IDX]->winSize - IPC_BUFF_MAX_SIZE * NUM_2;
        // set self increase magic
        magicTensor_.SetGlobalBuffer((__gm__ uint64_t *)(hccl_.GetWindowsInAddr(rank) + IPC_DATA_OFFSET -
                                                         blockNum * sizeof(uint64_t) * EXP_TOKEN_COUNT_FLAG_CNT +
                                                         notifyMemoryOffset));

        pipe.InitBuffer(this->tBuf, TEMP_BUF_LEN);
        LocalTensor<uint64_t> tempLocal = tBuf.Get<uint64_t>();
        tempLocal(0) = 1;
        // +1 by atomic add
        AscendC::SetAtomicAdd<uint64_t>();
        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);  // wait SetValue
        DataCopy(magicTensor_[blockIdx * EXP_TOKEN_COUNT_FLAG_CNT], tempLocal, EXP_TOKEN_COUNT_FLAG_CNT);
        AscendC::SetAtomicNone();
        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID0);  // wait DataCopy
        magic = magicTensor_.GetValue(blockIdx * EXP_TOKEN_COUNT_FLAG_CNT);
        PipeBarrier<PIPE_ALL>();
        // init target rank shareAddrs
        for (int i = 0; i < rankSize; i++) {
            this->shareAddrs[i] =
                hccl_.GetWindowsInAddr(i) + notifyMemoryOffset + (magic % PING_PONG_SIZE) * IPC_BUFF_MAX_SIZE;
        }
    }

    template <typename K, typename U = K>
    __aicore__ inline void CpGM2GMPingPong(int64_t dataSizeRemain, const GlobalTensor<U> &sendDataInputGt,
                                           const GlobalTensor<K> &recvDataOutputGT, int op);
    template <typename F>
    __aicore__ inline void SetAtomic(int op);
    __aicore__ inline void UnsetAtomic(int op);
    template <HardEvent eventType>
    __aicore__ inline void SetWaitEvent(event_t eventId);

    GlobalTensor<T> sendDataInputGt;
    GlobalTensor<int> tokenPerExpertDataInputGt;
    GlobalTensor<int> tmpDataInputGt;
    GlobalTensor<T> sendDataOffsetOutputGt;
    GlobalTensor<T> recvDataOutputGt;
    GlobalTensor<T> readGt;
    GlobalTensor<T> writeGt;
    GlobalTensor<T> remoteGt;

    __gm__ T *sendDataInput;
    __gm__ int *tokenPerExpertDataInput;
    __gm__ int *tmpDataInput;
    __gm__ T *sendDataOffsetOutput;
    __gm__ T *recvDataOutput;

    int64_t queLen;
    int64_t queSize;
    int64_t queElemLen;  // share queue element size (sizeof(T))

    int64_t coreNumBetween;  // step1，core num for comm between Server
    int64_t coreNumWithin;   // step2，core num for comm inside server
    int32_t rankNumPerCore;

    // RDMA params
    int32_t serverNum;                    // Server num
    int32_t serverId;                     // local server ID
    int32_t targetRank[MULTI_RANK_SIZE];  // cross Server send data target rank Id，final target rank
    int32_t targetRankNum;  // cross Server send target rank Id's num'，<=MULTI_RANK_SIZE
    int64_t perRankDataNum;

    int rank;
    int rankSize;
    int localRank = 0;
    int localRankSize = 0;
    int xRankSize = 0;
    int yRankSize = 0;
    int xRankIdx = 0;
    int yRankIdx = 0;
    uint32_t extraFlag;
    int root;
    int sendPerGroup = 3;
    int topkNum;
    int64_t numExperts;
    int64_t numTokens;
    int64_t len;
    uint64_t magic;
    int64_t blockIdx;
    int64_t blockNum;
    int64_t timeout;
    GM_ADDR scale;
    GM_ADDR shareAddrs[CAM_MAX_RANK_SIZE];  // sharememory list
    __gm__ HcclOpResParam *winContext_[COMM_NUM]{nullptr, nullptr};
    TPipe pipe;  // pipe
    TBuf<QuePosition::VECCALC> tBuf;

    Hccl<HCCL_SERVER_TYPE_AICPU> hccl_;
    GM_ADDR windowInGM_;
    GM_ADDR windowOutGM_;
    GlobalTensor<uint64_t> magicTensor_;  // saving magic，located before windowInstatusTensor_
    GlobalTensor<uint32_t> batchWriteInfoTensor_;
    GlobalTensor<int32_t> windowInstatusTensor_;  // status sync between rank
    GlobalTensor<T> windowInTensor_;
    GlobalTensor<int32_t> windowOutstatusTensor_;  // status sync between rank
    GlobalTensor<T> windowOutTensor_;
    TBuf<> batchWriteInfoBuf_;  // for saving tmp batch write info
    TBuf<> tempBuf_;
    TBuf<> statusBuf_;
    LocalTensor<int32_t> statusTensor_;  // for saving tmp statusFlag
    TBuf<> tokenPerExpertDataBuf;
    TBuf<> sendDataOffsetBuf;
    TBuf<> sendDataBuf;
    TBuf<> tempBuf2_;
    TBuf<> tempBuf3_;
    TBuf<> tempBuf4_;
    TBuf<> tempBuf5_;
    TBuf<> tempBuf6_;
    TBuf<> tempBuf7_;
    TBuf<> tempBuf8_;
    TBuf<> tempBuf9_;
    TBuf<> tempBuf10_;
    TBuf<> tempBuf11_;

    uint32_t sendDataAlignLen{0};
    uint32_t tokenPerExpertDataAlignLen{0};
    uint32_t sendDataOffsetAlignLen{0};

    uint32_t numTokensPerExpertAlignLen{0};        // Tokens this card sends to each expert (per-rank view)
    uint32_t gNumTokensPerExpertAlignLen{0};       // Global version: tokens per expert across all ranks
    // Unique tokens this card sends to each server (per-rank, duplicates removed)
    uint32_t numTokensUniquePerServerAlignLen{0};
    uint32_t gNumTokensUniquePerServerAlignLen{0}; // Global version of the above
    uint32_t numTokensPerServerAlignLen{0};        // Tokens this card sends to each server (per-rank, duplicates kept)
    uint32_t gNumTokensPerServerAlignLen{0};       // Global version of the above
    uint32_t tokenServerCntAlignLen{0};            // How many servers each token on this card is sent to (per-rank)
    uint32_t gTokenServerCntAlignLen{0};           // Global version of the above
    // Server indices each token on this card is sent to, in order (per-rank)
    uint32_t tokenServerIdxAlignLen{0};
    uint32_t gTokenServerIdxAlignLen{0};           // Global version of the above
    uint32_t tokenExpertIdxAlignLen{0};            // Expert indices each token is sent to, in order (per-rank)
    uint32_t gTokenExpertIdxAlignLen{0};           // Global version of the above
    // Per-expert offset inside the server for tokens from this card (per-rank)
    uint32_t expertMaxBsSrcOffsetAlignLen{0};
    uint32_t gExpertMaxBsSrcOffsetAlignLen{0};     // Global version of the above
    // Per-expert original offset on the source card for tokens from this card (per-rank)
    uint32_t expertMaxBsOriOffsetAlignLen{0};
    uint32_t gExpertMaxBsOriOffsetAlignLen{0};     // Global version of the above
    uint32_t notifyMemoryOffset{0};

    GlobalTensor<int32_t> gRankEpTokenCntGT_;  // temp data
    GlobalTensor<int32_t> gExpertMaxBsSrcGT_;  // temp data

    // Token-to-server index: -1 = not sent, 0-N = ordinal on target server [bs, serverNum]
    GlobalTensor<int32_t> tokenServerIdxOutputGT_;
    // Tokens this rank sends to each server [serverNum] → value: count
    GlobalTensor<int32_t> tokensUniquePerServerOutputGT_;
    // Tokens each expert receives from every rank [expert_num, rank_num] → value: token_cnt
    GlobalTensor<int32_t> epRankTokenCntOutputGT_;
    // Tokens each local expert on this card receives [local_expert_num]
    GlobalTensor<int64_t> localEpTokenCntOutputGT_;
    // Per-expert, per-rank, per-token source offset [expert_num, rank_num, token_idx] → value: src_offset
    GlobalTensor<int32_t> srcOffsetRankTokenIdxOutputGT_;
    // Per-expert, per-rank, per-token destination offset [expert_num, rank_num, token_idx] → value: dst_offset
    GlobalTensor<int32_t> dstOffsetRankTokenIdxOutputGT_;
    // Tokens sent to each server (deprecated)
    GlobalTensor<int32_t> countInnerOutputGT_;
    // Global expand indices [globalBs, expertNum]
    GlobalTensor<int32_t> offsetInnerOutputGT_;
    // How many servers each token is sent to [bs] → value: server count
    GlobalTensor<int32_t> countOuterOutputGT_;
    // Ordinal position of each token on its target server (same semantics as tokenServerIdxOutputGT_)
    GlobalTensor<int32_t> offsetOuterOutputGT_;
    // Expanded per-expert token counts [bs * numExperts]; prefix-sum of top-k indices replicated across all experts
    GlobalTensor<int32_t> expandIdxOutputGT_;
    // Total tokens received by this card [1] → value: count
    GlobalTensor<int32_t> totalRecvTokensOutputGT_;
};

template <typename T>
template <typename F>
__aicore__ inline void NotifyDispatchA2<T>::SetAtomic(int op)
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
template <HardEvent eventType>
__aicore__ inline void NotifyDispatchA2<T>::SetWaitEvent(event_t eventId)
{
    AscendC::SetFlag<eventType>(eventId);
    AscendC::WaitFlag<eventType>(eventId);
}

template <typename T>
__aicore__ inline void NotifyDispatchA2<T>::UnsetAtomic(int op)
{
    if (op != -1) {
        AscendC::SetAtomicNone();
    }
    PipeBarrier<PIPE_ALL>();
}

template <typename T>
template <typename K, typename U>
__aicore__ inline void NotifyDispatchA2<T>::CpGM2GMPingPong(int64_t dataSizeRemain,
                                                            const GlobalTensor<U> &sendDataInputGt,
                                                            const GlobalTensor<K> &recvDataOutputGT, int op)
{
    // General case (U = K), input/output are the same, share one UB
    // Only when conversion is needed (U->K), UB will be divided into two parts according to the ratio of
    // sizeof(U):sizeof(K) and aligned to 32 bytes
    constexpr int32_t ubBlockSize = UB_SINGLE_PING_PONG_ADD_SIZE_MAX;
    constexpr int32_t ubAlignNum = ubBlockSize / (sizeof(K) + sizeof(U)) / UB_ALIGN_SIZE * UB_ALIGN_SIZE;
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

#endif /* NOTIFY_DISPATCH_A2_H */
