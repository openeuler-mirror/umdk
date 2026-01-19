#ifndef CAM_COLLECTIVES_H
#define CAM_COLLECTIVES_H

#include <climits>

#include "data_copy.h"
#include "comm_group.h"
#include "sync_collectives.h"

using namespace AscendC;
using namespace Moe;

#define KERNELS_ARGS_CALL_ALL2ALL \
    input, output, len, op, root, cycleCount, scale, scaleCount, offset, localRank, \
        localRankSize, commArgs, isCamComm, magic

#define KERNELS_ARGS_FUN_ALL2ALL \
    GM_ADDR input, GM_ADDR output, int64_t len, int op, int root, \
        int cycleCount, GM_ADDR scale, int64_t scaleCount, GM_ADDR offset, int localRank, \
        int localRankSize, GM_ADDR commArgs, int isCamComm, int magic

#define KERNELS_ARGS_CALL_MIX \
    input, output, commArgs, len, magic, op, root, cycleCount, scale, scaleCount, offset, isCamComm

#define KERNELS_ARGS_FUN_MIX \
    GM_ADDR input, GM_ADDR output, GM_ADDR commArgs, int64_t len, int64_t magic, int op, int root, \
        int cycleCount, GM_ADDR scale, int64_t scaleCount, GM_ADDR offset, int isCamComm

class Collectives {
    constexpr static int32_t UB_HEAD_OFFSET = 96;
    constexpr static int32_t UB_MID_OFFSET = UB_HEAD_OFFSET + UB_SINGLE_PING_PONG_ADD_SIZE_MAX + UB_ALIGN_SIZE;
    constexpr static uint64_t STATE_WIN_OFFSET = 900 * 1024;
public:
    constexpr static int64_t UB_SINGLE_TOTAL_SIZE_MAX = 192 * 1024;

    FORCE_INLINE_AICORE Collectives(int rank, int rankSize, uint32_t extraFlag) : rank(rank), rankSize(rankSize),
        extraFlag(extraFlag) {}
    
    FORCE_INLINE_AICORE ~Collectives()
    {
        const int64_t notRunning = 0xdead;
    }

    __aicore__ inline GM_ADDR GetWindAddrByRankId(uint8_t ctxIdx, const int32_t rankId)
    {
        uint32_t curRankId = rank;
#ifdef OPT_RANK_OFFSET
        if (curRankId == rankId) {
            return (GM_ADDR)(winContext_[ctxIdx]->localWindowsIn) + rankId * OPT_RANK_OFFSET;
        }
        return (GM_ADDR)(((HcclRankRelationResV2 *)(winContext_[ctxIdx]->remoteRes[rankId].nextDevicePtr))->windowsIn) +
                rankId * OPT_RANK_OFFSET;
#else
        if (curRankId == rankId) {
            return (GM_ADDR)(winContext_[ctxIdx]->localWindowsIn);
        }
        return (GM_ADDR)(((HcclRankRelationResV2 *)(winContext_[ctxIdx]->remoteRes[rankId].nextDevicePtr))->windowsIn);
#endif
    }

    __aicore__ inline int32_t getMagicValue(void)
    {
        int32_t magic = 0;
        GlobalTensor<int32_t> selfDataStatusTensor;
        GM_ADDR statusDataSpaceGm = (GM_ADDR)(winContext_[COMM_EP_IDX]->localWindowsExp);
        selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t *)(statusDataSpaceGm + STATE_WIN_OFFSET));
        DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[blockIdx * UB_ALIGN_SIZE]);
        magic = selfDataStatusTensor(blockIdx * UB_ALIGN_SIZE);
        if (magic <= 0) {
            magic = 1;
        }
        selfDataStatusTensor(blockIdx * UB_ALIGN_SIZE) = magic + 1;
        return magic;
    }

    __aicore__ inline GM_ADDR GetShareAddrDetour(uint32_t isCamComm, const int32_t rankId, uint8_t ctxIdx)
    {
        if (isCamComm) {
            return (GM_ADDR)peerMemsAddrGm_.GetValue(rankId);
        } else {
            return GetWindAddrByRankId(ctxIdx, rankId);
        }
    }

    template <typename T, typename U = T>
    FORCE_INLINE_AICORE void CpGM2GMPingPong(int64_t dataSizeRemain, const GlobalTensor<U>& inputGT,
                                            const GlobalTensor<T>& outputGT, int op)
    {
        constexpr int32_t ubBlockSize = UB_SINGLE_PING_PONG_ADD_SIZE_MAX;
        constexpr int32_t ubAlignNum = ubBlockSize / (sizeof(T) + sizeof (U)) / UB_ALIGN_SIZE * UB_ALIGN_SIZE;
        constexpr int32_t inputUbBlockSize = std::is_same_v<T, U> ? ubBlockSize : ubAlignNum * sizeof(U);
        constexpr int32_t outputUbBlockSize = std::is_same_v<T, U> ? ubBlockSize : ubAlignNum * sizeof(T);

        __gm__ U *input = const_cast<__gm__ U *>(inputGT.GetPhyAddr());
        __gm__ T *output = const_cast<__gm__ T *>(outputGT.GetPhyAddr());
        __ubuf__ U* inputUB[2] = {(__ubuf__ U*)(UB_HEAD_OFFSET), (__ubuf__ U*)(UB_MID_OFFSET)};
        __ubuf__ T* outputUB[2] = {(__ubuf__ T*)inputUB[0], (__ubuf__ T*)inputUB[1]};
        if constexpr (!std::is_same_v<T, U>) {
            outputUB[0] = (__ubuf__ T*)(inputUB[0] + inputUbBlockSize /sizeof(U));
            outputUB[1] = (__ubuf__ T*)(inputUB[1] + inputUbBlockSize /sizeof(U));
        }
        int inputOffsetNum = 0;
        int outputOffsetNum = 0;
        if (dataSizeRemain <= 0) {
            return;
        }

        SetAtomic<T>(op);
        AscendC::SetFlag<HardEvent::MTE3_MTE2>(EVENT_ID0);
        AscendC::SetFlag<HardEvent::MTE3_MTE2>(EVENT_ID1);
        for (int64_t i = 0; dataSizeRemain > 0; i++) {
            uint32_t size = dataSizeRemain > outputUbBlockSize ? outputUbBlockSize : dataSizeRemain;
            event_t eventId = (i & 1) ? EVENT_ID0 : EVENT_ID1;
            AscendC::WaitFlag<HardEvent::MTE3_MTE2>(eventId);
            CpGM2UB((i & 1) ? inputUB[0] : inputUB[1], input + inputOffsetNum, size / sizeof(T) * sizeof(U));
            if constexpr (!std::is_same_v<T, U>) {
                SetWaitEvent<HardEvent::MTE2_V>(eventId);
                CastImpl((i & 1) ? outputUB[0] : outputUB[1], (i & 1) ? inputUB[0] : inputUB[1], RoundMode::CAST_NONE,
                    size / sizeof(T));
                SetWaitEvent<HardEvent::V_MTE3>(eventId);
            }
            AscendC::SetFlag<HardEvent::MTE2_MTE3>(eventId);
            AscendC::WaitFlag<HardEvent::MTE2_MTE3>(eventId);
            CpUB2GM(output + outputOffsetNum, (i & 1) ? outputUB[0] : outputUB[1], size);
            AscendC::SetFlag<HardEvent::MTE3_MTE2>(eventId);

            dataSizeRemain -= size;
            inputOffsetNum += (size / sizeof(T));
            outputOffsetNum += (size / sizeof(T));
        }
        AscendC::WaitFlag<HardEvent::MTE3_MTE2>(EVENT_ID0);
        AscendC::WaitFlag<HardEvent::MTE3_MTE2>(EVENT_ID1);

        AscendC::SetFlag<HardEvent::MTE3_S>(EVENT_ID3);
        AscendC::WaitFlag<HardEvent::MTE3_S>(EVENT_ID3);

        UnsetAtomic(op);
        return;
    }

    FORCE_INLINE_AICORE void InitByCamCommDetour(KERNELS_ARGS_FUN_MIX)
    {
        this->len = len;
        blockIdx = GetBlockIdx();
        blockNum = GetBlockNum();
        uint8_t ctxIdx = 0;
        this->magic = magic;
        this->memLen = reinterpret_cast<__gm__ CommArgs*>(commArgs)->memLen / (rankSize * rankSize);
        peerMemsAddrGm_.SetGlobalBuffer(
            &(reinterpret_cast<__gm__ CommArgs *>(commArgs))->peerMems[0], CAM_MAX_RANK_SIZE);
        for (int i = 0; i < rankSize; i++) {
            shareAddrs[i] = (GM_ADDR)peerMemsAddrGm_.GetValue(i);
        }
        pipe.InitBuffer(tBuf, UB_SINGLE_TOTAL_SIZE_MAX);
        int64_t shareMemOffset = GetShareMemOffsetDetour(rank, rank, rank);
        sync.InitDetour(rank, rankSize, shareAddrs, shareMemOffset, tBuf);
    }

    __aicore__ inline int64_t GetShareMemOffsetDetour(int srcRank, int dstRank, int memRank)
    {
#ifdef OPT_RANK_OFFSET
        return (rankSize * srcRank + dstRank) * memLen + memRank * OPT_RANK_OFFSET + (magic % PING_PONG_SIZE) * (memLen / 2);
#else
        return (rankSize * srcRank + dstRank) * memLen + (magic % PING_PONG_SIZE) * (memLen / 2);
#endif
    }

protected:
    int rank;
    int rankSize;
    int64_t len;
    uint32_t extraFlag;
    int64_t blockIdx;
    int64_t blockNum;
    int64_t memLen;
    int64_t magic;
    __gm__ HcclOpResParam *winContext_[COMM_NUM]{nullptr, nullptr};
    GlobalTensor<GM_ADDR> peerMemsAddrGm_;
    GM_ADDR shareAddrs[CAM_MAX_RANK_SIZE];
    TPipe pipe;
    TBuf<QuePosition::VECCALC> tBuf;
    SyncCollectives sync;


    template <typename T>
    FORCE_INLINE_AICORE void SetAtomic(int op)
    {
        PipeBarrier<PIPE_ALL>();
        if (op != -1) {
#ifdef __DAV_C220_VEC__
            SetAtomicOpType<T>(op);
#endif
        }
        PipeBarrier<PIPE_ALL>();
    }

    FORCE_INLINE_AICORE void UnsetAtomic(int op)
    {
        if (op != -1) {
            AscendC::SetAtomicNone();
        }
        PipeBarrier<PIPE_ALL>();
    }

    template<HardEvent eventType>
    FORCE_INLINE_AICORE void SetWaitEvent(event_t eventId)
    {
        AscendC::SetFlag<eventType>(eventId);
        AscendC::WaitFlag<eventType>(eventId);
    }
};

FORCE_INLINE_AICORE int64_t GetDataCount(const int64_t dataLen, const int64_t useBlockNum)
{
    return dataLen / useBlockNum;
}
#endif