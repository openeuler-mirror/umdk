/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ReduceScatter with detour operator kernel implementation file
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 create ReduceScatter with detour operator kernel implementation file
 */

#ifndef REDUCE_SCATTER_WITH_DETOUR_H
#define REDUCE_SCATTER_WITH_DETOUR_H

#include "sync_collectives.h"
#include "collectives.h"

using namespace AscendC;

template <typename T, typename U = T>
class ReduceScatterWithDetour : protected Collectives {
    constexpr static int64_t MAX_CORE_NUM = 48;
public:
    FORCE_INLINE_AICORE ReduceScatterWithDetour(int rank, int rankSize, uint32_t extraFlag)
        : Collectives(rank, rankSize, extraFlag)
    {}

    FORCE_INLINE_AICORE void Init(KERNELS_ARGS_FUN_MIX, GM_ADDR commRankIds, uint32_t commRankSize)
    {
        this->commRankSize = commRankSize;
        GlobalTensor<int32_t> commRankIdsGM;
        commRankIdsGM.SetGlobalBuffer((__gm__ int32_t *)commRankIds);
        for (int i = 0; i < commRankSize; ++i) {
            this->commRankIds[i] = commRankIdsGM.GetValue(i);
        }
        if (!IsValidCommRank()) {
            return;
        }
        detourRankSize = rankSize - commRankSize;
        Collectives::InitByCamCommDetour(KERNELS_ARGS_CALL_MIX);
        atomOp = op;
        in2IpcCoreNum = (detourRankSize + 1) * (commRankSize - 1) + 1;
        reduceCoreNum = detourRankSize + 2;
        blockNum = in2IpcCoreNum > reduceCoreNum ? in2IpcCoreNum : reduceCoreNum;
        if (blockIdx >= blockNum) {
            return;
        }
        this->input = input;
        this->output = output;
        perDataNumForDetourRank = (len + detourRankSize) / (detourRankSize + 1);
        piplineNum = commRankSize - 1;
    }

    FORCE_INLINE_AICORE void Process()
    {
        if (blockIdx >= blockNum) {
            return;
        }
        if (blockIdx < in2IpcCoreNum) {
            Input2Ipc();
        }
        if (blockIdx < reduceCoreNum) {
            Reduce();
        }
    }

    FORCE_INLINE_AICORE void Input2Ipc()
    {
        __ubuf__ int64_t *inputUB = (__ubuf__ int64_t *)get_imm(0);
        int64_t v;
        int64_t inputBuffOffsetNum = 0;
        shareMemOffsetInRank = GetShareMemOffsetDetour(rank, rank, rank);
        v = MergeMagicWithValue(magic, 1);
        *inputUB = v;
        if (blockIdx == 0) {
            inputBuffOffsetNum = commRankIdx * len;
            in2IpcSrcGt.SetGlobalBuffer((__gm__ T *)input + inputBuffOffsetNum, len);
            in2IpcDstGtU.SetGlobalBuffer((__gm__ U *)(shareAddrs[rank] + shareMemOffsetInRank + IPC_DATA_OFFSET), len);
            CpGM2GMPingPong(len * sizeof(U), in2IpcSrcGt, in2IpcDstGtU, COPYONLY);
            AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
            AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
            CpUB2GM((__gm__ int64_t *)(shareAddrs[rank] + shareMemOffsetInRank) + rank * FLAG_UNIT_INT_NUM, inputUB, sizeof(int64_t));
            pipe_barrier(PIPE_ALL);
            return;
        }

        int targetCommRankIdx = (blockIdx - 1) / (detourRankSize + 1) < commRankIdx ? (blockIdx - 1) / (detourRankSize + 1) : (blockIdx - 1) / (detourRankSize + 1) + 1;
        in2IpcTargetCommRank = commRankIds[targetCommRankIdx];

        int offsetIdx = (blockIdx - 1) % (detourRankSize + 1);
        in2IpcTargetRank = offsetIdx == 0 ? in2IpcTargetCommRank : GetDetourRankId(offsetIdx - 1);

        int64_t curDataNumForDetourRank = len - offsetIdx * perDataNumForDetourRank < perDataNumForDetourRank ? len - offsetIdx * perDataNumForDetourRank : perDataNumForDetourRank;
        if (curDataNumForDetourRank <= 0) {
            return;
        }
        inputBuffOffsetNum = targetCommRankIdx * len;
        in2IpcSrcGt.SetGlobalBuffer((__gm__ T *)input + inputBuffOffsetNum + offsetIdx * perDataNumForDetourRank, curDataNumForDetourRank);
        int64_t shareMemOffsetInDstRank = GetShareMemOffsetDetour(rank, in2IpcTargetCommRank, in2IpcTargetCommRank);
        in2IpcDstGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[in2IpcTargetRank] + shareMemOffsetInDstRank + IPC_DATA_OFFSET), curDataNumForDetourRank);
        CpGM2GMPingPong(curDataNumForDetourRank * sizeof(T), in2IpcSrcGt, in2IpcDstGt, COPYONLY);
        AscendC::SetFlag<HardEvent::S_MTE3>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::S_MTE3>(EVENT_ID0);
        CpUB2GM((__gm__ int64_t *)(shareAddrs[in2IpcTargetRank] + shareMemOffsetInDstRank) + rank * FLAG_UNIT_INT_NUM, inputUB, sizeof(int64_t));
        pipe_barrier(PIPE_ALL);
    }

    FORCE_INLINE_AICORE void Reduce()
    {
        if (blockIdx == 0) {
            return;
        }
        int offsetIdx = (blockIdx - 1) % (detourRankSize + 1);
        int64_t curReduceDataNum = len - offsetIdx * perDataNumForDetourRank < perDataNumForDetourRank ? len - offsetIdx * perDataNumForDetourRank : perDataNumForDetourRank;
        if (curReduceDataNum <= 0) {
            return;
        }
        reduceDstGt.SetGlobalBuffer((__gm__ U *)(shareAddrs[rank] + shareMemOffsetInRank + IPC_DATA_OFFSET) + (blockIdx - 1) * perDataNumForDetourRank, curReduceDataNum);
        for (int i = 0; i < piplineNum; i++) {
            int srcCommRankIdx = (commRankIdx + 1 + i) % commRankSize;
            int srcCommRank = commRankIds[srcCommRankIdx];
            int64_t shareMemOffsetInDstRank = GetShareMemOffsetDetour(srcCommRank, rank, rank);
            int detourRank = offsetIdx == 0 ? rank : GetDetourRankId(offsetIdx - 1);
            reduceSrcGt.SetGlobalBuffer((__gm__ T *)(shareAddrs[detourRank] + shareMemOffsetInDstRank + IPC_DATA_OFFSET), curReduceDataNum);
            if (i == 0) {
                sync.WaitSyncFlag(magic, 1, rank, rank, 1, shareMemOffsetInRank);
            } else {
                sync.WaitOuterFlagDetour(magic, i, rank, rankSize + rank, shareMemOffsetInRank);
            }
            sync.WaitSyncFlag(magic, 1, srcCommRank, detourRank, 1, shareMemOffsetInDstRank);
            CpGM2GMPingPong(curReduceDataNum * sizeof(U), reduceSrcGt, reduceDstGt, atomOp);
            sync.SetOuterFlagDetour(magic, i + 1, rank, rankSize + rank, shareMemOffsetInRank);
        }
        sync.WaitOuterFlagDetour(magic, piplineNum, rank, rankSize + rank, shareMemOffsetInRank);
        Ipc2OutDstGt.SetGlobalBuffer((__gm__ T *)output + (blockIdx - 1) * perDataNumForDetourRank, curReduceDataNum);
        CpGM2GMPingPong(curReduceDataNum * sizeof(T), reduceDstGt, Ipc2OutDstGt, COPYONLY);
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

    __aicore__ inline bool IsCommRank(int id)
    {
        for (int i = 0; i < commRankSize; i++) {
            if (commRankIds[i] == id) {
                return true;
            }
        }
        return false;
    }

    __aicore__ inline int GetDetourRankId(int order)
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

    int atomOp = COPYONLY;
    GM_ADDR output;
    GM_ADDR input;

    GlobalTensor<T> in2IpcDstGt;
    GlobalTensor<U> in2IpcDstGtU;
    GlobalTensor<T> in2IpcSrcGt;

    int64_t in2IpcTargetRank = 0;
    int64_t in2IpcTargetCommRank = 0;

    int64_t in2IpcCoreNum = 0;
    int64_t piplineNum = 0;

    int64_t reduceCoreNum = 0;
    GlobalTensor<T> Ipc2OutDstGt;

    int32_t commRankIds[CAM_MAX_RANK_SIZE];
    int commRankSize;
    int detourRankSize;
    int64_t commRankIdx;
    int64_t shareMemOffsetInRank;
    int64_t perDataNumForDetourRank;
    GlobalTensor<T> reduceSrcGt;
    GlobalTensor<U> reduceDstGt;
};

#endif