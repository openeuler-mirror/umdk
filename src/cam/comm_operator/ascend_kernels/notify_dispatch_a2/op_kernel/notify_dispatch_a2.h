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
        InitAll2AllLayeredRdma(sendDataInput, tokenPerExpertDataInput, tmpDataInput, sendDataOffsetOutput,
            recvDataOutput, len, numTokens, topkNum, numExperts, op, root, cycleCount, scale, scaleCount, offset,
            localRank, localRankSize, tokenServerIdxOutput, tokensUniquePerServerOutput, epRankTokenCntOutput,
            localEpTokenCntOutput, srcOffsetRankTokenIdxOutput, dstOffsetRankTokenIdxOutput, offsetInnerOutput,
            countOuterOutput, expandIdxOutput, totalRecvTokensOutput, workspace, tiling);

        tokenPerExpertDataAlignLen = Ceil(numExperts * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        sendDataOffsetAlignLen = Ceil(numExperts * sizeof(T), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        sendDataAlignLen = Ceil(len * sizeof(T), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;  // data length
        perRankDataNum = len;                                                     // send all data

        InitTensorLen();

        InitShare();
        // init core split, make sure by outer side all server has the same localRankSize
        serverNum = CeilDiv(rankSize, localRankSize);
        serverId = rank / localRankSize;
        InitCoreGroup();
        // init target rank
        InitTargetRank();
        // init data slice
        InitDataSlice();

        this->sendDataInput = (__gm__ T *)sendDataInput;
        this->tokenPerExpertDataInput = (__gm__ int32_t *)tokenPerExpertDataInput;
        this->tmpDataInput = (__gm__ int32_t *)tmpDataInput;
        this->sendDataOffsetOutput = (__gm__ T *)sendDataOffsetOutput;
        this->recvDataOutput = (__gm__ T *)recvDataOutput;

        sendDataInputGt.SetGlobalBuffer((__gm__ T *)sendDataInput);
        tokenPerExpertDataInputGt.SetGlobalBuffer((__gm__ int32_t *)tokenPerExpertDataInput);
        tmpDataInputGt.SetGlobalBuffer((__gm__ int32_t *)tmpDataInput);
        sendDataOffsetOutputGt.SetGlobalBuffer((__gm__ T *)sendDataOffsetOutput);
        recvDataOutputGt.SetGlobalBuffer((__gm__ T *)recvDataOutput);

        gRankEpTokenCntGT_.SetGlobalBuffer(
            (__gm__ int32_t *)(tmpDataInput),
            gNumTokensPerExpertAlignLen / sizeof(int32_t));  // tmpDataInput for temporary saving params
        gExpertMaxBsSrcGT_.SetGlobalBuffer(
            (__gm__ int32_t *)(tmpDataInput + gNumTokensPerExpertAlignLen),
            gExpertMaxBsSrcOffsetAlignLen / sizeof(int32_t));  // tmpDataInput for temporary saving params

        tokenServerIdxOutputGT_.SetGlobalBuffer((__gm__ int32_t *)tokenServerIdxOutput);
        tokensUniquePerServerOutputGT_.SetGlobalBuffer((__gm__ int32_t *)tokensUniquePerServerOutput);
        epRankTokenCntOutputGT_.SetGlobalBuffer((__gm__ int32_t *)epRankTokenCntOutput);
        localEpTokenCntOutputGT_.SetGlobalBuffer((__gm__ int64_t *)localEpTokenCntOutput);
        srcOffsetRankTokenIdxOutputGT_.SetGlobalBuffer((__gm__ int32_t *)srcOffsetRankTokenIdxOutput);
        dstOffsetRankTokenIdxOutputGT_.SetGlobalBuffer((__gm__ int32_t *)dstOffsetRankTokenIdxOutput);
        offsetInnerOutputGT_.SetGlobalBuffer((__gm__ int32_t *)offsetInnerOutput);
        countOuterOutputGT_.SetGlobalBuffer((__gm__ int32_t *)countOuterOutput);
        expandIdxOutputGT_.SetGlobalBuffer((__gm__ int32_t *)expandIdxOutput);
        totalRecvTokensOutputGT_.SetGlobalBuffer((__gm__ int32_t *)totalRecvTokensOutput);

        // init RDMA params
        // dataSpaceGT_ = workspace; // preserve large space for splited data after exchange with other ranks
        windowInGM_ = this->shareAddrs[rank];
        windowOutGM_ =
            hccl_.GetWindowsOutAddr(rank) + (magic % PING_PONG_SIZE) * IPC_BUFF_MAX_SIZE + notifyMemoryOffset;
        batchWriteInfoTensor_.SetGlobalBuffer((__gm__ uint32_t *)(workspace), rankSize * U32_PER_ITEM);
        // out params temporary use
        windowInstatusTensor_.SetGlobalBuffer((__gm__ int32_t *)(windowInGM_ + IPC_DATA_OFFSET));
        windowInTensor_.SetGlobalBuffer((__gm__ T *)(windowInGM_ + IPC_DATA_OFFSET));
        windowOutstatusTensor_.SetGlobalBuffer((__gm__ int32_t *)(windowOutGM_ + IPC_DATA_OFFSET));
        windowOutTensor_.SetGlobalBuffer((__gm__ T *)(windowOutGM_ + IPC_DATA_OFFSET));

        pipe.InitBuffer(batchWriteInfoBuf_, rankSize * BW_ITEM_SIZE);
        pipe.InitBuffer(tempBuf_, UB_ALIGN);                        // for temporary direct numbers
        pipe.InitBuffer(statusBuf_, rankSize * STATUS_ENTRY_SIZE);  // rankSize * 32B
        // save sending nums and flag，can used to calculate offset in windows
        statusTensor_ = statusBuf_.Get<int32_t>();
        Duplicate<int32_t>(statusTensor_, 0, rankSize * STATUS_ENTRY_SIZE);
    }

    __aicore__ inline void Process()
    {
        if ASCEND_IS_AIV {
            // 1 between server
            if (serverNum > 1) {
                ProcessBetweenServer();
            }

            // 2 inside server
            ProcessWithinServer();
            SyncAll<true>();

            // 3 calculate output and split data after exchanging with other ranks
            SplitAndCalcData();
            SyncAll<true>();

            hccl_.Finalize();
        }
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

    __aicore__ inline void InitTensorLen()
    {
        numTokensPerExpertAlignLen = Ceil(numExperts * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gNumTokensPerExpertAlignLen = Ceil(rankSize * numExperts * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        numTokensUniquePerServerAlignLen = Ceil(serverNum * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gNumTokensUniquePerServerAlignLen = Ceil(rankSize * serverNum * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        numTokensPerServerAlignLen = Ceil(MAX_BS * serverNum * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gNumTokensPerServerAlignLen =
            Ceil(rankSize * MAX_BS * serverNum * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        tokenServerCntAlignLen = Ceil(MAX_BS * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gTokenServerCntAlignLen = Ceil(rankSize * MAX_BS * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        tokenServerIdxAlignLen = Ceil(MAX_BS * serverNum * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gTokenServerIdxAlignLen = Ceil(rankSize * MAX_BS * serverNum * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        tokenExpertIdxAlignLen = Ceil(MAX_BS * numExperts * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gTokenExpertIdxAlignLen = Ceil(rankSize * MAX_BS * numExperts * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        expertMaxBsSrcOffsetAlignLen = Ceil(numExperts * MAX_BS * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gExpertMaxBsSrcOffsetAlignLen =
            Ceil(rankSize * numExperts * MAX_BS * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

        expertMaxBsOriOffsetAlignLen = Ceil(numExperts * MAX_BS * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
        gExpertMaxBsOriOffsetAlignLen =
            Ceil(rankSize * numExperts * MAX_BS * sizeof(int32_t), UB_ALIGN_SIZE) * UB_ALIGN_SIZE;
    }

    template <typename T1, typename T2>
    FORCE_INLINE_AICORE T1 CeilDiv(T1 a, T2 b)
    {
        if (b == 0) {
            return 0;
        }
        return (a + b - 1) / b;
    }

    __aicore__ inline void InitShare()
    {
        int64_t queNum = MAX_CORE_NUM;
        queElemLen = (IPC_BUFF_MAX_SIZE - IPC_DATA_OFFSET) / sizeof(T) / queNum;  // calculate share queue element size
        queSize = (queElemLen * sizeof(T) / GM_ALIGN) * GM_ALIGN;                 // GM align
        queLen = queSize / sizeof(T);  // one queue element size
    }

    __aicore__ inline void InitCoreGroup()
    {
        coreNumBetween = (rankSize <= MAX_CORE_NUM) ? rankSize : MAX_CORE_NUM;
        coreNumWithin = (rankSize <= MAX_CORE_NUM) ? rankSize : MAX_CORE_NUM;
        rankNumPerCore = CeilDiv(rankSize, MAX_CORE_NUM);  // rank num for each core
    }

    // calculate communicate target，two steps
    // step1：between server，Pair-wise，from low id to high id ring
    // step2：inside server，ranks fullmesh，send the data from step 1
    __aicore__ inline void InitTargetRank()
    {
        // step1：between server taget ranks, target rank here is the final target, not the direct send target
        int32_t startRankId = blockIdx * rankNumPerCore;
        targetRankNum = (rankSize - startRankId) < rankNumPerCore ? (rankSize - startRankId) : rankNumPerCore;
        if (targetRankNum < 0) {
            targetRankNum = 0;
        }

        for (int i = 0; i < targetRankNum; i++) {
            targetRank[i] = startRankId + i;
        }
        // invalid for others
        for (int i = targetRankNum; i < MULTI_RANK_SIZE; i++) {
            targetRank[i] = INVALID_RANK;
        }
    }

    __aicore__ inline void InitDataSlice()
    {
        // producer send local rank input to shareAddrs: input-->share
        if (blockIdx < coreNumWithin) {
            writeGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[rank] + IPC_DATA_OFFSET));
        }
    }

    __aicore__ inline void ProcessWithinServer()
    {
        if (blockIdx < coreNumWithin) {
            InputToShareSlice();
            ShareToShareSlice();
        }
    }

    __aicore__ inline uint64_t MergeMagicWithValue(uint64_t magic, uint64_t value)
    {
        // magic as the high part, eventID as the low part, combined into a value for comparison
        return (magic * 2ULL + value);
    }

    // Wait for a part of synchronization flags within a rank
    __aicore__ inline void WaitOneRankPartFlag(__gm__ uint64_t *waitAddr, int64_t flagNum, uint64_t checkValue)
    {
        GlobalTensor<uint64_t> globalWait;
        globalWait.SetGlobalBuffer(waitAddr, flagNum * FLAG_UNIT_INT_NUM);
        LocalTensor<uint64_t> localWait = tBuf.GetWithOffset<uint64_t>(flagNum * FLAG_UNIT_INT_NUM, 0);
        bool isSync = true;
        uint64_t checkedFlagNum = 0;
        do {
            // Copy global synchronization flags to local
            DataCopy(localWait, globalWait[checkedFlagNum * FLAG_UNIT_INT_NUM],
                     (flagNum - checkedFlagNum) * FLAG_UNIT_INT_NUM);
            SetWaitEvent<HardEvent::MTE2_S>(EVENT_ID0);  // Wait for GM->UB

            // Check if the synchronization flags are equal to checkValue
            isSync = true;
            uint64_t remainToCheck = flagNum - checkedFlagNum;
            for (auto i = 0; i < remainToCheck; ++i) {
                // Continue waiting if any core has not reached the checkValue phase
                uint64_t v = localWait.GetValue(i * FLAG_UNIT_INT_NUM);
                if ((v & MAGIC_MASK) != (checkValue & MAGIC_MASK) || v < checkValue) {
                    isSync = false;
                    checkedFlagNum += i;
                    break;
                }
            }
        } while (!isSync);
    }

    __aicore__ inline void SetInnerFlag(uint64_t magic, uint64_t eventID, int64_t setRank, int64_t setBlock)
    {
        uint64_t value = MergeMagicWithValue(magic, eventID);
        __gm__ uint64_t *setAddr = (__gm__ uint64_t *)(shareAddrs[setRank]) + setBlock * FLAG_UNIT_INT_NUM;

        SetWaitEvent<HardEvent::MTE3_S>(EVENT_ID0);
        SetWaitEvent<HardEvent::MTE2_S>(EVENT_ID0);
        GlobalTensor<uint64_t> globalSet;
        globalSet.SetGlobalBuffer(setAddr, FLAG_UNIT_INT_NUM);
        LocalTensor<uint64_t> localSet = tBuf.GetWithOffset<uint64_t>(1, 0);
        localSet.SetValue(0, value);

        // Copy global synchronization flag to local
        SetWaitEvent<HardEvent::S_MTE3>(EVENT_ID0);
        DataCopy(globalSet, localSet, FLAG_UNIT_INT_NUM);
        SetWaitEvent<HardEvent::MTE3_S>(EVENT_ID0);
    }

    // Wait for a single inner-card synchronization flag
    __aicore__ inline void WaitInnerFlag(uint64_t magic, uint64_t eventID, int64_t waitRank, int64_t waitBlock)
    {
        uint64_t value = MergeMagicWithValue(magic, eventID);
        WaitOneRankPartFlag((__gm__ uint64_t *)(shareAddrs[waitRank]) + waitBlock * FLAG_UNIT_INT_NUM, 1, value);
    }

    __aicore__ inline void InputToShareSlice()
    {
        if (blockIdx > 0) {
            return;
        }
        // copy local rank input data to shareAddrs
        int targetRankId = rank;
        int32_t targetServerId = targetRankId / localRankSize;

        int64_t datalen = this->len;
        readGt = sendDataInputGt[0];
        CpGM2GMPingPong<T>(datalen * sizeof(T), readGt, writeGt[queLen * targetRankId + STATUS_ENTRY_SIZE / sizeof(T)],
                           COPYONLY);  // reserve a position for flag

        for (int i = 0; i < localRankSize; ++i) {
            int32_t curServerRankId = serverId * localRankSize + i;
            for (int j = 0; j < serverNum; ++j) {
                // write serverNum signs for each rank in the local server, position: rank + j * localRankSize
                int32_t offset = rank + j * rankSize;  // rank0: 0,16 / rank8: 8,24
                // rank0,server0: 0-7,16-23  rank8,server1: 8-15,24-31
                SetInnerFlag(magic, 1, curServerRankId, offset);
            }
        }
    }

    __aicore__ inline void ShareToShareSlice()
    {
        // Copy data from the corresponding position in the shared memory of other
        // cards within the Server (there are serverNum blocks of data) to the output of this card.
        uint32_t coreForDataBlock = (localRankSize * serverNum) / coreNumWithin;  // 8*2/16=1
        uint32_t remainDataBlock = (localRankSize * serverNum) % coreNumWithin;   // 8*2%16=0
        uint32_t startDataBlockId = coreForDataBlock * blockIdx;
        if (blockIdx < remainDataBlock) {
            startDataBlockId += blockIdx;
            coreForDataBlock += 1;
        } else {
            startDataBlockId += remainDataBlock;
        }
        uint32_t endDataBlockId = startDataBlockId + coreForDataBlock;
        if (coreForDataBlock == 0) {
            return;
        }

        int64_t recvCount = this->len;
        for (int i = startDataBlockId; i < endDataBlockId; ++i) {
            int32_t targetRankId = serverId * localRankSize + (i / serverNum);  // read from local server rankId
            int32_t serverTarRankId = (i % serverNum) * localRankSize + (i / serverNum);

            // server0: 0-7,16-23   server1: 8-15,24-31
            int32_t offset = (i / serverNum + serverId * localRankSize) + (i % serverNum) * rankSize;
            WaitInnerFlag(magic, 1, rank, offset);

            remoteGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[targetRankId] + IPC_DATA_OFFSET +
                                                  serverTarRankId * queSize +
                                                  STATUS_ENTRY_SIZE));  // server-th block
            CpGM2GMPingPong<T>(recvCount * sizeof(T), remoteGt, recvDataOutputGt[serverTarRankId * this->len],
                               COPYONLY);
        }
    }

    __aicore__ inline void ProcessBetweenServer()
    {
        InputToWindowOut();
        ConstructBatchWriteInfo();
        SyncAll<true>();
        SendRdma();
        WaitRdma();
        SyncAll<true>();
        WindowInToOutput();
    }

    __aicore__ inline void InputToWindowOut()
    {
        /* statusFlag and dataFlag are int32_t，occupies 4Bytes of 8B
        ---------------------------------------------------------------------------------------------------------------
        |8B pads|flag 8B|source 4B|target 4B|datalen 4B|4B pads|   Data (datalen * sizeof(T))    | flag 8B | 24B pads |
        ---------------------------------------------------------------------------------------------------------------
        */
        if (blockIdx > 1) {
            return;
        }
        int32_t targetRankId = 0;
        if (blockIdx == 0) {
            return;                                                     // same server no move
        } else {                                                        // blockIdx=1
            // calculate for 2 server，same local rankid's global rank id
            targetRankId = (1 - serverId) * localRankSize + localRank;
        }
        int32_t targetServerId = targetRankId / localRankSize;

        int64_t datalen = this->len;
        readGt = sendDataInputGt[0];  // read all data

        // calculate offset，in bytes
        int64_t statusEntryOffset = queSize * targetRankId;
        int64_t statusFlagOffset = statusEntryOffset + FLAG_OFFSET;
        int64_t sourceRankIdOffset = statusEntryOffset + SOURCE_RANK_OFFSET;
        int64_t destRankIdOffset = statusEntryOffset + DEST_RANK_OFFSET;
        int64_t dataLenOffset = statusEntryOffset + DATALEN_OFFSET;
        int64_t dataOffset = statusEntryOffset + STATUS_ENTRY_SIZE;
        int64_t dataFlagOffset = dataOffset + datalen * sizeof(T);
        CpGM2GMPingPong<T>(datalen * sizeof(T), readGt, windowOutTensor_[dataOffset / sizeof(T)], COPYONLY);

        windowOutstatusTensor_(statusFlagOffset / sizeof(int32_t)) = FLAG_VALUE;
        windowOutstatusTensor_(sourceRankIdOffset / sizeof(int32_t)) = rank;
        windowOutstatusTensor_(destRankIdOffset / sizeof(int32_t)) = targetRankId;
        windowOutstatusTensor_(dataLenOffset / sizeof(int32_t)) = (int32_t)datalen;
        DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
            windowOutstatusTensor_[(statusEntryOffset / sizeof(int32_t))]);
        windowOutstatusTensor_(dataFlagOffset / sizeof(int32_t)) = FLAG_VALUE;
        DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE, AscendC::DcciDst::CACHELINE_OUT>(
            windowOutstatusTensor_[(dataFlagOffset / sizeof(int32_t))]);
    }

    // create RDMA batch write info
    __aicore__ inline void ConstructBatchWriteInfo()
    {
        if (targetRankNum == 0 || blockIdx > 0) {
            return;
        }

        LocalTensor<uint32_t> batchWriteU32Tensor_ = batchWriteInfoBuf_.Get<uint32_t>();
        LocalTensor<uint64_t> batchWriteU64Tensor_ = batchWriteInfoBuf_.Get<uint64_t>();
        uint32_t batchWriteDataType = static_cast<uint32_t>(AscendC::HcclDataType::HCCL_DATA_TYPE_INT8);
        SyncFunc<AscendC::HardEvent::MTE2_S>();

        int32_t targetRankId = (1 - serverId) * localRankSize + localRank;  // 2 server

        int32_t targetServerId = targetRankId / localRankSize;
        uint32_t sendToRankId = targetServerId * localRankSize + localRank;  // target Server same local rankId

        // data position of target GM，making sure data will not overlap in the first round
        uint32_t sendOffset = serverId * localRankSize + (targetRankId % localRankSize);

        int64_t datalen = this->len;
        GM_ADDR localBuf = (__gm__ uint8_t *)(windowOutGM_ + IPC_DATA_OFFSET + targetRankId * queSize);
        GM_ADDR remoteGM = (__gm__ uint8_t *)(shareAddrs[sendToRankId] + IPC_DATA_OFFSET + rank * queSize);
        // payload add 2 flag's size at front and tail
        uint64_t batchWriteDataSize = datalen * sizeof(T) + 2 * STATUS_ENTRY_SIZE;

        batchWriteU64Tensor_(0 * U64_PER_ITEM + BW_MEB_OFFSET64_LOCAL_GM) = (uint64_t)localBuf;
        batchWriteU64Tensor_(0 * U64_PER_ITEM + BW_MEB_OFFSET64_REMOTE_GM) = (uint64_t)remoteGM;
        batchWriteU64Tensor_(0 * U64_PER_ITEM + BW_MEB_OFFSET64_DATA_SIZE) = batchWriteDataSize;
        batchWriteU32Tensor_(0 * U32_PER_ITEM + BW_MEB_OFFSET32_DATA_TYPE) = batchWriteDataType;
        batchWriteU32Tensor_(0 * U32_PER_ITEM + BW_MEB_OFFSET32_TARGET_RANK) = sendToRankId;

        SyncFunc<AscendC::HardEvent::S_MTE3>();
        DataCopy(batchWriteInfoTensor_[0], batchWriteU32Tensor_, 1 * U32_PER_ITEM);
        PipeBarrier<PIPE_ALL>();
    }

    __aicore__ inline void SendRdma()
    {
        if (blockIdx == 0) {
            HcclHandle batchWrResult = hccl_.BatchWrite<true>((GM_ADDR)batchWriteInfoTensor_.GetPhyAddr(), 1);
        }
    }

    __aicore__ inline void WaitRdma()
    {
        if (targetRankNum == 0 || blockIdx > 0) {
            return;
        }

        DataCopyExtParams copyFlagParams{1, static_cast<uint32_t>(sizeof(int32_t)), 0, 0, 0};
        DataCopyPadExtParams<int32_t> padParams{false, 0, 0, 0};
        LocalTensor<int32_t> dataFlagLocal = tempBuf_.Get<int32_t>();
        SyncFunc<AscendC::HardEvent::S_MTE2>();

        int32_t targetRankId = (1 - serverId) * localRankSize + localRank;  // 2 server
        int32_t targetServerId = targetRankId / localRankSize;

        int64_t statusOffset = targetRankId * queSize + FLAG_OFFSET;

        int64_t datalen = 0;
        int32_t statusFlag = 0;
        int32_t dataFlag = 0;
        while (statusFlag != FLAG_VALUE) {
            DataCopy(statusTensor_[0], windowInstatusTensor_[targetRankId * queSize / sizeof(int32_t)],
                     U32_STATUS_ENTRY);
            SyncFunc<AscendC::HardEvent::MTE2_S>();
            statusFlag = statusTensor_(FLAG_OFFSET / sizeof(int32_t));
            datalen = statusTensor_(DATALEN_OFFSET / sizeof(int32_t));
            PipeBarrier<PIPE_MTE2>();
        }

        uint64_t dataFlagOffset = (targetRankId * queSize + datalen * sizeof(T) + STATUS_ENTRY_SIZE) / sizeof(int32_t);
        while (dataFlag != FLAG_VALUE) {
            DataCopyPad(dataFlagLocal, windowInstatusTensor_[dataFlagOffset], copyFlagParams, padParams);
            SyncFunc<AscendC::HardEvent::MTE2_S>();
            dataFlag = dataFlagLocal(0);
            PipeBarrier<PIPE_MTE2>();
        }
        windowInstatusTensor_(dataFlagOffset) = 0;
    }

    // data from RDMA windowInTensor to output
    __aicore__ inline void WindowInToOutput()
    {
        /*
        ----------------------------------------------------------------------------
        | STATUS_ENTRY_SIZE |    Data (datalen * sizeof(T))    | STATUS_ENTRY_SIZE |
        ----------------------------------------------------------------------------
        */
        if (blockIdx > 0) {
            return;
        }
        int32_t targetRankId = (1 - serverId) * localRankSize + localRank;  // 2server
        int64_t recvCount = this->len;
        uint64_t dataOffset = (targetRankId * queSize + STATUS_ENTRY_SIZE) / sizeof(T);
        CpGM2GMPingPong<T>(recvCount * sizeof(T), windowInTensor_[dataOffset],
                           recvDataOutputGt[targetRankId * this->len], COPYONLY);
    }

    // recvData split data and calculate output
    __aicore__ inline void SplitAndCalcData()
    {
        return;
    }

    __aicore__ inline void BuildTokenSeverIdxData()
    {
        return;
    }

    __aicore__ inline void BuildExpandIdxData()
    {
        return;
    }

    __aicore__ inline void GetEpRankSumCnt(int32_t srcRank, LocalTensor<int32_t> &epTokenCntLt)
    {
        return;
    }

    __aicore__ inline void BuildOffsetInnerForRank(int32_t targetRankId, int32_t index, uint32_t startTokenId,
                                                   uint32_t endTokenId)
    {
        return;
    }

    __aicore__ inline void BuildOffsetInnerData(int32_t beginCoreId, int32_t validCoreNum)
    {
        return;
    }

    __aicore__ inline void BuildCountOuterData()
    {
        return;
    }

    __aicore__ inline void BuildTokenUniquePerServerData()
    {
        return;
    }

    __aicore__ inline void GetRankEpTokenCntData(int32_t beginCoreId, int32_t validCoreNum)
    {
        return;
    }

    __aicore__ inline void GetExpertMaxBsSrcData(int32_t beginCoreId, int32_t validCoreNum)
    {
        return;
    }

    __aicore__ inline void BuildEpRankTokenCntData(int32_t beginCoreId, int32_t validCoreNum)
    {
        return;
    }

    __aicore__ inline void BuildTotalRecvTokensData()
    {
        return;
    }

    __aicore__ inline void BuildLocalEpRankTokenCntData(int32_t beginCoreId, int32_t validCoreNum)
    {
        return;
    }

    __aicore__ inline void BuildSrcDstOffsetData(int32_t beginCoreId, int32_t validCoreNum)
    {
        return;
    }

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
