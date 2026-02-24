/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: all2all with detour function device header file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create all2all with detour header file in device part
 */

#ifndef ALL2ALL_SMALL_FULLMESH_WITH_DETOUR_H
#define ALL2ALL_SMALL_FULLMESH_WITH_DETOUR_H

#include "collectives.h"

using namespace AscendC;

template <typename T>
class All2AllSmallFullmeshWithDetour : public Collectives {
    constexpr static int64_t MAX_CORE_NUM = 48;
public:
    __aicore__ inline All2AllSmallFullmeshWithDetour(int rank, int rankSize, uint32_t extraFlag)
        : Collectives(rank, rankSize, extraFlag)
    {}

    __aicore__ inline void Init(KERNELS_ARGS_FUN_ALL2ALL, GM_ADDR commRankIds, uint32_t commRankSize)
    {
        this->commRankSize = commRankSize;
        this->isCamComm = isCamComm;

        GlobalTensor<int32_t> commRankIdsGM;
        commRankIdsGM.SetGlobalBuffer((__gm__ int32_t *)commRankIds);
        for (int i = 0; i < commRankSize; ++i) {
            this->commRankIds[i] = commRankIdsGM.GetValue(i);
        }

        if (!IsValidCommRank()) {
            return;
        }

        Collectives::InitByCamCommDetour(KERNELS_ARGS_CALL_MIX);

        perRankDataNum = GetDataCount(len, commRankSize);
        perRankDataNumForDetour = (perRankDataNum + rankSize - commRankSize) / (rankSize - commRankSize + 1);
        InitCoreGroup();

        this->input = (__gm__ T *)input;
        this->output = (__gm__ T *)output;

        inputGt.SetGlobalBuffer((__gm__ T *)input);
        outputGt.SetGlobalBuffer((__gm__ T *)output);
    }

    __aicore__ inline void Process()
    {
        if (!IsValidCommRank()) {
            return;
        }

        if (blockIdx < coreNumPerStageX) {
            InputToShareSlice();
        }

        if (blockIdx < coreNumPerStageY) {
            ShareToShareSlice();
        }
    }

private:
    __aicore__ inline bool IsValidCommRank()
    {
        for (int i = 0; i < commRankSize; i++) {
            if (commRankIds[i] == rank) {
                commRankIdx = i;
                return true;
            }
        }
        commRankIdx = -1;
        return false;
    }

    __aicore__ inline int64_t GetShareMemOffset(int srcRank, int dstRank, int memRank)
    {
        if (isCamComm) {
#ifdef OPT_RANK_OFFSET
            return (rankSize * srcRank + dstRank) * memLen + memRank * OPT_RANK_OFFSET + (magic % PING_PONG_SIZE) * (memLen / 2);
#else
            return (rankSize * srcRank + dstRank) * memLen + (magic % PING_PONG_SIZE) * (memLen / 2);
#endif
        } else {
            return (rankSize * srcRank + dstRank) * memLen + (magic % PING_PONG_SIZE) * (memLen / 2);
        }
    }

    __aicore__ inline bool IsCommRank(int id)
    {
        for (int i = 0; i < commRankSize; i++) {
            if (commRankIds[i] ==id) {
                return true;
            }
        }
        return false;
    }

    __aicore__ inline int GetDstRankId(int order)
    {
        int count = 0;
        for (int i = 0; i < rankSize; ++i) {
            if (!IsCommRank(i)) {
                if (count == order) {
                    return i;
                }
                ++count;
            }
        }
        return rankSize;
    }

    __aicore__ inline int64_t MergeMagicWithValue(int32_t magic, int32_t value)
    {
        return (static_cast<int64_t>(magic) << MAGIC_OFFSET) | static_cast<int64_t>(value);
    }

    __aicore__ inline void InitCoreGroup()
    {
        coreNumPerStageY = MAX_CORE_NUM;
        coreNumPerStageX = MAX_CORE_NUM;

        rankNumPerCore = (rankSize + MAX_CORE_NUM - 3) / (MAX_CORE_NUM - 2);
    }

    __aicore__ inline void InputToShareSlice()
    {
        __ubuf__ int64_t *inputUB = (__ubuf__ int64_t *)get_imm(0);
        int64_t v;

        if (blockIdx == 0) {
            CpGM2GMPingPong<T>(perRankDataNum * sizeof(T), inputGt[commRankIdx * perRankDataNum], outputGt[commRankIdx * perRankDataNum], COPYONLY);
            pipe_barrier(PIPE_ALL);
            return;
        }

        int dstCommRank;
        if (blockIdx == 1) {
            for (int i = 0; i < commRankSize; i++) {
                dstCommRank = commRankIds[i];
                if (dstCommRank == rank) {
                    continue;
                }
                readGt = inputGt[i * perRankDataNum];
                writeGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[dstCommRank] + GetShareMemOffset(rank, dstCommRank, dstCommRank) + IPC_DATA_OFFSET));
                CpGM2GMPingPong<T>(
                    perRankDataNumForDetour * sizeof(T), readGt, writeGt, COPYONLY);
                v = MergeMagicWithValue(magic, 1);
                *inputUB = v;
                AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
                AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
                CpUB2GM((__gm__ int64_t *)(shareAddrs[dstCommRank] + GetShareMemOffset(rank, dstCommRank, dstCommRank)) + rank * FLAG_UNIT_INT_NUM, inputUB, sizeof(int64_t));
            }
            pipe_barrier(PIPE_ALL);
            return;
        }
        for (int i = 0; i < commRankSize; i++) {
            dstCommRank = commRankIds[i];
            if (dstCommRank == rank) {
                continue;
            }

            int64_t copyOffset = ((blockIdx - 2) * rankNumPerCore + 1) * perRankDataNumForDetour;
            int64_t rankNumCurrentCore = (rankSize - commRankSize) - ((blockIdx - 2) * rankNumPerCore) < rankNumPerCore ? (rankSize - commRankSize) - ((blockIdx - 2) * rankNumPerCore) : rankNumPerCore;

            if (rankNumCurrentCore <= 0) {
                continue;
            }

            for (int j = 0; j < rankNumCurrentCore; j++) {
                int64_t copyOffsetInRank = copyOffset + j * perRankDataNumForDetour;
                copyLen = perRankDataNum - copyOffsetInRank < perRankDataNumForDetour ? perRankDataNum - copyOffsetInRank : perRankDataNumForDetour;
                if (copyLen <= 0) {
                    break;
                }
                readGt = inputGt[i * perRankDataNum + copyOffsetInRank];
                int detourRankId = GetDstRankId((blockIdx - 2) * rankNumPerCore + j);
                writeGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[detourRankId] + GetShareMemOffset(rank, dstCommRank, detourRankId) + IPC_DATA_OFFSET));
                CpGM2GMPingPong<T>(
                    copyLen * sizeof(T), readGt, writeGt, COPYONLY);
                v = MergeMagicWithValue(magic, 1);
                *inputUB = v;
                AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
                AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
                 CpUB2GM((__gm__ int64_t *)(shareAddrs[detourRankId] + GetShareMemOffset(rank, dstCommRank, detourRankId)) + rank * FLAG_UNIT_INT_NUM, inputUB, sizeof(int64_t));
            }
        }
        pipe_barrier(PIPE_ALL);
    }

    __aicore__ inline void ShareToShareSlice()
    {
        __ubuf__ T *inputUB = (__ubuf__ T *)get_imm(96);
        if (blockIdx == 0) {
            return;
        }
        int srcCommRank;
        if (blockIdx == 1) {
            for (int i = 0; i < commRankSize; i++) {
                srcCommRank = commRankIds[i];
                if (srcCommRank == rank) {
                    continue;
                }
                readGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[rank] + GetShareMemOffset(srcCommRank, rank, rank) + IPC_DATA_OFFSET));
                sync.WaitSyncFlag(magic, 1, srcCommRank, rank, 1, GetShareMemOffset(srcCommRank, rank, rank));
                CpGM2GMPingPong<T>(perRankDataNumForDetour * sizeof(T), readGt,
                        outputGt[i * perRankDataNum], COPYONLY);
            }
            return;
        }
        for (int i = 0; i < commRankSize; i++) {
            srcCommRank = commRankIds[i];
            if (srcCommRank == rank) {
                continue;
            }

            int64_t copyOffset = ((blockIdx - 2) * rankNumPerCore + 1) * perRankDataNumForDetour;
            int64_t rankNumCurrentCore = (rankSize - commRankSize) - ((blockIdx - 2) * rankNumPerCore) < rankNumPerCore ? (rankSize - commRankSize) - ((blockIdx - 2) * rankNumPerCore) : rankNumPerCore;
            if (rankNumCurrentCore <= 0) {
                continue;
            }
            for (int j = 0; j < rankNumCurrentCore; j++) {
                int64_t copyOffsetInRank = copyOffset + j * perRankDataNumForDetour;
                copyLen = perRankDataNum - copyOffsetInRank < perRankDataNumForDetour ? perRankDataNum - copyOffsetInRank : perRankDataNumForDetour;
                if (copyLen <= 0) {
                    break;
                }
                int detourRankId = GetDstRankId((blockIdx - 2) * rankNumPerCore + j);
                readGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[detourRankId] + GetShareMemOffset(srcCommRank, rank, detourRankId) + IPC_DATA_OFFSET));
                sync.WaitSyncFlag(magic, 1, srcCommRank, detourRankId, 1, GetShareMemOffset(srcCommRank, rank, detourRankId));
                CpGM2GMPingPong<T>(copyLen * sizeof(T), readGt,
                        outputGt[i * perRankDataNum + copyOffsetInRank], COPYONLY);
            }
        }
    }

    GlobalTensor<T> inputGt;
    GlobalTensor<T> outputGt;
    GlobalTensor<T> readGt;
    GlobalTensor<T> writeGt;
    __gm__ T *input;
    __gm__ T *output;

    int commRankSize;
    int isCamComm;
    int32_t commRankIds[CAM_MAX_RANK_SIZE];
    int commRankIdx;
    int64_t copyLen;

    int64_t perRankDataNum;
    int64_t perRankDataNumForDetour;
    int64_t coreNumPerStageY;
    int64_t coreNumPerStageX;
    int64_t rankNumPerCore;
};

#endif