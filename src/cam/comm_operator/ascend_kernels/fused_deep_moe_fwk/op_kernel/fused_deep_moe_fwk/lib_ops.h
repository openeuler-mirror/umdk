/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Framework ops file
 * Create: 2026-01-20
 */

#pragma once

#include "opx/opx.h"

#include "epilogue/tile/tile_stride_muls.h"
#include "epilogue/tile/tile_stride_binary.h"

#include "fused_deep_moe_fwk_base.h"


template <AscendC::HardEvent EVENT>
CATLASS_DEVICE
void PipeSync()
{
    AscendC::TEventID eventId = static_cast<event_t>(GetTPipePtr()->FetchEventID(EVENT));
    AscendC::SetFlag<EVENT>(eventId);
    AscendC::WaitFlag<EVENT>(eventId);
}

template <AscendC::HardEvent EVENT>
CATLASS_DEVICE
void PipeSync(AscendC::TEventID eventId)
{
    AscendC::SetFlag<EVENT>(eventId);
    AscendC::WaitFlag<EVENT>(eventId);
}

template <typename T>
CATLASS_DEVICE
AscendC::LocalTensor<T> GetBufferByByte(uint32_t& offset, uint32_t len)
{
    offset = RoundUp<uint32_t>(offset, AscendC::ONE_BLK_SIZE);
    len = RoundUp<uint32_t>(len, AscendC::ONE_BLK_SIZE);

    AscendC::TBuffAddr addr;
    addr.logicPos = static_cast<uint8_t>(AscendC::TPosition::VECCALC);
    addr.bufferHandle = nullptr;
    addr.bufferAddr = offset;
    addr.dataLen = len;
    offset += len;

    AscendC::LocalTensor<T> tensor;
    tensor.SetAddr(addr);
    return tensor;
}

template <typename T>
CATLASS_DEVICE
AscendC::LocalTensor<T> GetBufferByByte(uint32_t offset)
{
    return GetBufferByByte<T>(offset, 0);
}


namespace LibOps
{

using namespace CATLASS_NS;

constexpr uint32_t UB_BLOCK_SIZE = AscendC::ONE_BLK_SIZE;
constexpr uint32_t UB_ALIGN = UB_BLOCK_SIZE;
constexpr uint32_t INT32_COUNT_PER_BLOCK = UB_BLOCK_SIZE / sizeof(int32_t);
constexpr uint32_t TOKEN_EXTRA_SPACE = 512;
constexpr uint32_t STATE_OFFSET = 512;

constexpr uint64_t WIN_OPT_RANK_OFFSET = 512;
constexpr uint64_t WIN_STATE_OFFSET = 512 * 1024;
constexpr uint64_t STATE_WIN_OFFSET = 900 * 1024;
constexpr uint64_t GROUP_TOKEN_NUM_OFFSET = 932 * 1024;
constexpr uint64_t SOFT_SYNC_OFFSET = 964 * 1024;
constexpr uint64_t SELF_STATE_OFFSET = 256 * 1024;

constexpr uint32_t CV_FLAG_INDEX = 0;
constexpr uint32_t GROUP_ID_INDEX = 1;
constexpr uint32_t PRE_COUNT_INDEX = 2;
constexpr uint32_t SELF_COUNT_INDEX = 3;
constexpr uint32_t TOTAL_COUNT_INDEX = 4;

constexpr uint32_t GROUP_TOKEN_COUNT = SELF_COUNT_INDEX;
constexpr uint32_t GROUP_INFO_SIZE = 32;

constexpr int32_t TOKEN_FLAG_1 = 0x55555555;
constexpr int32_t TOKEN_FLAG_2 = 0x33333333;
constexpr int32_t V_TO_C_FLAG_1 = 0x03030303;
constexpr int32_t V_TO_C_FLAG_2 = 0x05050505;


struct MoEContext
{
    CATLASS_DEVICE
    MoEContext(
        __gm__ HcclOpResParam *winContext_,
        uint32_t epRankSize_,
        uint32_t epRankId_,
        uint32_t moeExpertNumPerRank_,
        uint32_t batchSize_,
        uint32_t globalBs_,
        uint32_t topK_,
        uint32_t tokenLength_,
        uint32_t xTypeSize_
    ) : winContext(winContext_),
        epRankSize(epRankSize_),
        epRankId(epRankId_),
        moeExpertNumPerRank(moeExpertNumPerRank_),
        batchSize(batchSize_),
        topK(topK_),
        tokenLength(tokenLength_)
    {
        aicNum = AscendC::GetBlockNum();
        aivNum = AscendC::GetBlockNum() * AscendC::GetSubBlockNum();
        expertCntUp = epRankSize * moeExpertNumPerRank;
        expertPerSizeOnWin = (uint64_t)globalBs_ / epRankSize * tokenLength * xTypeSize_;

        gmStatusDataSpace = GetWindowStateAddrByRankId(epRankId);

        uint32_t aivIdx = AscendC::GetBlockIdx();
        uint32_t aivStateGlobalCoreIdx = aivNum + aicNum + aivIdx;

        // Read and update the execute-state, determine which space and the flag value to be used
        using AscendC::CacheLine;
        using AscendC::DcciDst;

        AscendC::GlobalTensor<int32_t> selfDataStatusTensor;
        selfDataStatusTensor.SetGlobalBuffer((__gm__ int32_t*)(gmStatusDataSpace + STATE_WIN_OFFSET));
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        dataState = selfDataStatusTensor(aivIdx * UB_ALIGN);
        if (dataState == 0) {
            selfDataStatusTensor(aivIdx * UB_ALIGN) = 1;
        } else {
            selfDataStatusTensor(aivIdx * UB_ALIGN) = 0;
        }
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");

        // Flag value of C-V communication
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aivStateGlobalCoreIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        int32_t cvDataState = selfDataStatusTensor(aivStateGlobalCoreIdx * UB_ALIGN);
        if (cvDataState == 0) {
            selfDataStatusTensor(aivStateGlobalCoreIdx * UB_ALIGN) = 1;
            vToCFlag = V_TO_C_FLAG_1;
        } else {
            selfDataStatusTensor(aivStateGlobalCoreIdx * UB_ALIGN) = 0;
            vToCFlag = V_TO_C_FLAG_2;
        }
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfDataStatusTensor[aivStateGlobalCoreIdx * UB_ALIGN]);
        __asm__ __volatile__("");

        AscendC::GlobalTensor<int32_t> selfStatusTensor;
        selfStatusTensor.SetGlobalBuffer((__gm__ int32_t*)(
            GetWindowStateAddrByRankId(epRankId) + SELF_STATE_OFFSET));
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");
        int32_t state = selfStatusTensor(aivIdx * UB_ALIGN);
        if (state == 0) {
            sumTarget = 1.0f;
            tokenFlag = TOKEN_FLAG_1;
            selfStatusTensor(aivIdx * UB_ALIGN) = 0x3F800000; // 0x3F800000 equals to 1.0f in hex
        } else {
            sumTarget = 0.0f;
            tokenFlag = TOKEN_FLAG_2;
            selfStatusTensor(aivIdx * UB_ALIGN) = 0;
        }
        __asm__ __volatile__("");
        AscendC::DataCacheCleanAndInvalid<int32_t, CacheLine::SINGLE_CACHE_LINE, DcciDst::CACHELINE_OUT>(
            selfStatusTensor[aivIdx * UB_ALIGN]);
        __asm__ __volatile__("");

        winDataSizeOffset = dataState * epRankSize * expertPerSizeOnWin * moeExpertNumPerRank;
    }

    CATLASS_DEVICE
    GM_ADDR GetWindowStateAddrByRankId(uint32_t rankId)
    {
        GM_ADDR addr;
        if (epRankId == rankId) {
            addr = (GM_ADDR)winContext->localWindowsExp;
        } else {
            auto remoteDevicePtr = winContext->remoteRes[rankId].nextDevicePtr;
            addr = (GM_ADDR)((HcclRankRelationResV2 *)remoteDevicePtr)->windowsExp;
        }
        return addr + dataState * WIN_STATE_OFFSET;
    }

    CATLASS_DEVICE
    GM_ADDR GetWindowDataAddrByRankId(uint32_t rankId)
    {
        GM_ADDR addr;
        if (epRankId == rankId) {
            addr = (GM_ADDR)winContext->localWindowsIn;
        } else {
            auto remoteDevicePtr = winContext->remoteRes[rankId].nextDevicePtr;
            addr = (GM_ADDR)((HcclRankRelationResV2 *)remoteDevicePtr)->windowsIn;
        }
        return addr + winDataSizeOffset + rankId * WIN_OPT_RANK_OFFSET;
    }

public:
    __gm__ HcclOpResParam *winContext{nullptr};
    GM_ADDR gmStatusDataSpace{nullptr};

    uint32_t epRankSize{0};
    uint32_t epRankId{0};
    uint32_t aicNum{0};
    uint32_t aivNum{0};
    uint32_t moeExpertNumPerRank{0};
    uint32_t expertCntUp{0};
    uint32_t batchSize{0};
    uint32_t topK{0};
    uint32_t tokenLength{0};

    int32_t dataState{0};
    int32_t tokenFlag{0};
    int32_t vToCFlag{0};
    float sumTarget{0.0};

    uint64_t expertPerSizeOnWin{0};
    uint64_t winDataSizeOffset{0};
};

template <typename XType, uint32_t BUFFER_NUM, bool ENABLE_X_ACTIVE_MASK>
class OpDispatchSendToken
{
private:
    MoEContext& ctx;

    AscendC::GlobalTensor<XType> xGlobal;
    AscendC::GlobalTensor<uint32_t> expertIdsGlobal;
    AscendC::GlobalTensor<uint32_t> expandIdxGlobal;
    AscendC::GlobalTensor<int8_t> xActiveMaskGlobal;

    uint32_t sendCoreNum;
    uint32_t sendCoreIdx;

public:
    CATLASS_DEVICE
    OpDispatchSendToken(
        MoEContext& ctx_,
        GM_ADDR gmX,
        GM_ADDR gmExpertIds,
        GM_ADDR gmExpandIdx,
        GM_ADDR gmXActiveMask = nullptr
    ) : ctx(ctx_)
    {
        xGlobal.SetGlobalBuffer((__gm__ XType*)gmX);
        expertIdsGlobal.SetGlobalBuffer((__gm__ uint32_t*)gmExpertIds);
        expandIdxGlobal.SetGlobalBuffer((__gm__ uint32_t*)gmExpandIdx);
        xActiveMaskGlobal.SetGlobalBuffer((__gm__ int8_t*)gmXActiveMask);
    }

    CATLASS_DEVICE
    void SetLogicCoreGroup(const opx::LogicCoreGroup& grp)
    {
        sendCoreNum = grp.lgc_core_num;
        sendCoreIdx = grp.lgc_core_idx;
    }

    CATLASS_DEVICE
    void Process()
    {
        uint32_t ubOffset = 0;
        uint32_t activeMaskBsCnt = ctx.batchSize;
        if constexpr (ENABLE_X_ACTIVE_MASK) {
            activeMaskBsCnt = TokenActiveMaskCal(ubOffset);
        }

        uint32_t expertIdsCnt = activeMaskBsCnt * ctx.topK;
        AscendC::LocalTensor<uint32_t> expertIdsLocal = LoadExpertIds(ubOffset, expertIdsCnt);

        CalAndSendTokenCount(ubOffset, expertIdsLocal, expertIdsCnt);

        AscendC::SetDeqScale((half)1.000000e+00f);
        SendToMoeExpert(ubOffset, expertIdsLocal, expertIdsCnt);

        AscendC::PipeBarrier<PIPE_ALL>();
    }

private:
    CATLASS_DEVICE
    uint32_t TokenActiveMaskCal(uint32_t ubOffset)
    {
        uint32_t batchSize = ctx.batchSize;
        AscendC::LocalTensor<int8_t> maskInputLocal =
            GetBufferByByte<int8_t>(ubOffset, batchSize * sizeof(int8_t));
        AscendC::LocalTensor<half> maskTmpLocal =
            GetBufferByByte<half>(ubOffset, batchSize * sizeof(half));

        AscendC::DataCopyExtParams dataCopyExtParams{};
        AscendC::DataCopyPadExtParams<int8_t> dataCopyPadExtParams{};
        dataCopyExtParams.blockCount = 1;
        dataCopyExtParams.blockLen = batchSize * sizeof(int8_t);
        AscendC::DataCopyPad(maskInputLocal, xActiveMaskGlobal, dataCopyExtParams, dataCopyPadExtParams);
        PipeSync<AscendC::HardEvent::MTE2_V>();
        AscendC::Cast(maskTmpLocal, maskInputLocal, AscendC::RoundMode::CAST_NONE, batchSize);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceSum(maskTmpLocal, maskTmpLocal, {}, batchSize);
        PipeSync<AscendC::HardEvent::V_S>();
        return (uint32_t)maskTmpLocal.ReinterpretCast<uint16_t>().GetValue(0);
    }

    CATLASS_DEVICE
    AscendC::LocalTensor<uint32_t> LoadExpertIds(uint32_t& ubOffset, uint32_t expertIdsCnt)
    {
        AscendC::LocalTensor<uint32_t> expertIdsLocal =
            GetBufferByByte<uint32_t>(ubOffset, expertIdsCnt * sizeof(uint32_t));
        AscendC::DataCopyExtParams dataCopyExtParams{};
        dataCopyExtParams.blockCount = 1;
        dataCopyExtParams.blockLen = expertIdsCnt * sizeof(uint32_t);
        AscendC::DataCopyPadExtParams<uint32_t> dataCopyPadExtParams{};
        AscendC::DataCopyPad(expertIdsLocal, expertIdsGlobal, dataCopyExtParams, dataCopyPadExtParams);
        PipeSync<AscendC::HardEvent::MTE2_V>();
        return expertIdsLocal;
    }

    CATLASS_DEVICE
    void CalAndSendTokenCount(uint32_t ubOffset,
        const AscendC::LocalTensor<uint32_t>& expertIdsLocal, uint32_t expertIdsCnt)
    {
        uint32_t totalExpertNum = ctx.moeExpertNumPerRank * ctx.epRankSize;
        uint32_t sendCountExpertNum = totalExpertNum / sendCoreNum;
        uint32_t remainderRankNum = totalExpertNum % sendCoreNum;
        uint32_t startExpertId = sendCountExpertNum * sendCoreIdx;
        // The first remainderRankNum-AIVs needs to send an additional rank of data
        if (sendCoreIdx < remainderRankNum) {
            sendCountExpertNum += 1;
            startExpertId += sendCoreIdx;
        } else {
            startExpertId += remainderRankNum;
        }
        uint32_t endExpertId = startExpertId + sendCountExpertNum;
        if (startExpertId >= totalExpertNum) {
            return;
        }

        uint32_t statusTensorLen = RoundUp(ctx.expertCntUp, INT32_COUNT_PER_BLOCK) * UB_BLOCK_SIZE;
        AscendC::LocalTensor<int32_t> statusTensor = GetBufferByByte<int32_t>(ubOffset, statusTensorLen);
        AscendC::Duplicate(statusTensor, 0, ctx.expertCntUp * INT32_COUNT_PER_BLOCK); // Clear to zero
        if (ctx.sumTarget == 1.0f) {
            // Operates 256B(64-int32_t) at once
            // Set the first number of every 8 numbers to 0x3F800000(hex of 1.0f)
            uint64_t mask[2] = { 0x101010101010101, 0};
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::Duplicate(statusTensor, 0x3F800000, mask,
                CeilDiv(ctx.expertCntUp, INT32_COUNT_PER_BLOCK), 1, INT32_COUNT_PER_BLOCK);
        }

        PipeSync<AscendC::HardEvent::V_S>();

        for (uint32_t expertId = startExpertId; expertId < endExpertId; ++expertId) {
            uint32_t cntPosIndex = expertId * INT32_COUNT_PER_BLOCK + 1;
            statusTensor(cntPosIndex) = CalExpandIdx(ubOffset, expertIdsLocal, expertIdsCnt, expertId);
        }

        PipeSync<AscendC::HardEvent::S_MTE3>();

        AscendC::GlobalTensor<int32_t> rankGMTensor;
        for (uint32_t expertId = startExpertId; expertId < endExpertId; ++expertId) {
            uint32_t dstRankId = expertId / ctx.moeExpertNumPerRank;
            uint32_t offset = (ctx.epRankId + expertId % ctx.moeExpertNumPerRank * ctx.epRankSize) * STATE_OFFSET;

            GM_ADDR rankGM = ctx.GetWindowStateAddrByRankId(dstRankId) + offset;
            rankGMTensor.SetGlobalBuffer((__gm__ int32_t*)rankGM);
            AscendC::DataCopy(rankGMTensor, statusTensor[expertId * INT32_COUNT_PER_BLOCK], INT32_COUNT_PER_BLOCK);
        }

        AscendC::PipeBarrier<PIPE_ALL>();
    }

    /// @brief Count the number of values equal to dstExpertId in the first n values of expertIds array
    /// @param ubOffset The offset of UB memory temporary used by method
    /// @param expertIdsLocal Local tensor that stores the expertIds array
    /// @param n First n number to be calculated
    /// @param dstExpertId Destination expert id
    /// @return The number of values equals to dstExpertId among the first n-element of expertIds array
    CATLASS_DEVICE
    uint32_t CalExpandIdx(uint32_t ubOffset, const AscendC::LocalTensor<uint32_t>& expertIdsLocal,
        uint32_t n, uint32_t dstExpertId)
    {
        if (n == 0) {
            return 0;
        }

        AscendC::LocalTensor<int32_t> tmpLocal = GetBufferByByte<int32_t>(ubOffset, n * sizeof(int32_t));

        AscendC::Duplicate(tmpLocal, (int32_t)dstExpertId, n);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Sub(tmpLocal, expertIdsLocal.ReinterpretCast<int32_t>(), tmpLocal, n);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::LocalTensor<float> tmpFp32 = tmpLocal.ReinterpretCast<float>();
        AscendC::Abs(tmpFp32, tmpFp32, n); // Use Abs to remove the sign-bit of i32
        AscendC::PipeBarrier<PIPE_V>();
        // Set all values that are not equal to dstExpertId to 1
        AscendC::Mins(tmpLocal, tmpLocal, 1, n);
        AscendC::PipeBarrier<PIPE_V>();
        // Count the number of 1. Treat i32 as float to do Reduce,
        // the result is equivalent when every of the i32 is positive and the sum-result is less than 2^23
        AscendC::ReduceSum(tmpFp32, tmpFp32, {}, n);
        PipeSync<AscendC::HardEvent::V_S>();

        // Get the number of 0 by sub n with the number of 1
        return n - (uint32_t)tmpLocal(0);
    }

    CATLASS_DEVICE
    void SendToMoeExpert(uint32_t ubOffset,
        const AscendC::LocalTensor<uint32_t>& expertIdsLocal, uint32_t expertIdsCnt)
    {
        uint32_t sendTokenNum = expertIdsCnt / sendCoreNum;
        uint32_t remainderTokenNum = expertIdsCnt % sendCoreNum;
        uint32_t startTokenId = sendTokenNum * sendCoreIdx;
        if (sendCoreIdx < remainderTokenNum) {
            sendTokenNum += 1;
            startTokenId += sendCoreIdx;
        } else {
            startTokenId += remainderTokenNum;
        }
        uint32_t endTokenId = startTokenId + sendTokenNum;

        if (startTokenId >= expertIdsCnt) {
            return;
        }

        AscendC::LocalTensor<uint32_t> expandIdxLocal =
            GetBufferByByte<uint32_t>(ubOffset, expertIdsCnt * sizeof(uint32_t));
        AscendC::Duplicate<uint32_t>(expandIdxLocal, 0, expertIdsCnt); // Clear zero
        PipeSync<AscendC::HardEvent::V_S>();

        AscendC::LocalTensor<XType> xInTensor[BUFFER_NUM];
        AscendC::LocalTensor<int8_t> yInt8Tensor[BUFFER_NUM];
        AscendC::TEventID ev_MTE2_V[BUFFER_NUM];
        AscendC::TEventID ev_V_MTE3[BUFFER_NUM];
        AscendC::TEventID ev_MTE3_MTE2[BUFFER_NUM];

        AscendC::TPipe& tpipe = *GetTPipePtr();
        uint32_t tokenLength = ctx.tokenLength;
        uint32_t hCommuSize = ctx.tokenLength * sizeof(int8_t) + TOKEN_EXTRA_SPACE;

        for (uint32_t i = 0; i < BUFFER_NUM; i++) {
            xInTensor[i] = GetBufferByByte<XType>(ubOffset, tokenLength * sizeof(XType));
            yInt8Tensor[i] = GetBufferByByte<int8_t>(ubOffset, hCommuSize);

            ev_MTE2_V[i] = tpipe.AllocEventID<AscendC::HardEvent::MTE2_V>();
            ev_V_MTE3[i] = tpipe.AllocEventID<AscendC::HardEvent::V_MTE3>();
            ev_MTE3_MTE2[i] = tpipe.AllocEventID<AscendC::HardEvent::MTE3_MTE2>();

            AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2[i]);
        }

        AscendC::GlobalTensor<int8_t> dstWinGMTensor;

        uint32_t flowId = 0;
        for (uint32_t sendGroupIndex = 0; sendGroupIndex < ctx.moeExpertNumPerRank; ++sendGroupIndex) {
            for (uint32_t tokenIndex = startTokenId; tokenIndex < endTokenId; ++tokenIndex) {
                uint32_t dstExpertId = expertIdsLocal(tokenIndex);
                if ((dstExpertId % ctx.moeExpertNumPerRank) != sendGroupIndex) { // Send low-id expert in priority
                    continue;
                }
                flowId = (flowId + 1) % BUFFER_NUM;

                uint32_t curExpertCnt = CalExpandIdx(ubOffset, expertIdsLocal, tokenIndex, dstExpertId);
                expandIdxLocal(tokenIndex - startTokenId) = curExpertCnt;
                uint32_t dstRankId = dstExpertId / ctx.moeExpertNumPerRank;
                dstWinGMTensor.SetGlobalBuffer((__gm__ int8_t*)(
                    ctx.GetWindowDataAddrByRankId(dstRankId) +
                    ctx.expertPerSizeOnWin *
                        (ctx.epRankId * ctx.moeExpertNumPerRank + dstExpertId % ctx.moeExpertNumPerRank) +
                    hCommuSize * curExpertCnt
                ));

                AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2[flowId]);

                AscendC::DataCopy(xInTensor[flowId], xGlobal[tokenIndex / ctx.topK * tokenLength], tokenLength);

                AscendC::SetFlag<AscendC::HardEvent::MTE2_V>(ev_MTE2_V[flowId]);
                AscendC::WaitFlag<AscendC::HardEvent::MTE2_V>(ev_MTE2_V[flowId]);

                QuantToken(ubOffset, xInTensor[flowId], yInt8Tensor[flowId]);

                AscendC::SetFlag<AscendC::HardEvent::V_MTE3>(ev_V_MTE3[flowId]);
                AscendC::WaitFlag<AscendC::HardEvent::V_MTE3>(ev_V_MTE3[flowId]);

                AscendC::DataCopy(dstWinGMTensor, yInt8Tensor[flowId], tokenLength);
                // Send the data first then the flag
                AscendC::PipeBarrier<PIPE_MTE3>();
                AscendC::DataCopy(dstWinGMTensor[tokenLength], yInt8Tensor[flowId][tokenLength],
                    TOKEN_EXTRA_SPACE / sizeof(int8_t));
                AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2[flowId]);
            }
        }

        for (uint32_t i = 0; i < BUFFER_NUM; i++) {
            AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2[i]);

            tpipe.ReleaseEventID<AscendC::HardEvent::MTE2_V>(ev_MTE2_V[i]);
            tpipe.ReleaseEventID<AscendC::HardEvent::V_MTE3>(ev_V_MTE3[i]);
            tpipe.ReleaseEventID<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2[i]);
        }

        AscendC::DataCopyExtParams dataCopyExtParams{};
        dataCopyExtParams.blockCount = 1;
        dataCopyExtParams.blockLen = sendTokenNum * sizeof(uint32_t);
        AscendC::DataCopyPad(expandIdxGlobal[startTokenId], expandIdxLocal, dataCopyExtParams);
    }

    CATLASS_DEVICE
    void QuantToken(uint32_t ubOffset, const AscendC::LocalTensor<XType>& xInTensor,
        const AscendC::LocalTensor<int8_t>& yInt8Tensor)
    {
        uint32_t tokenLength = ctx.tokenLength;
        AscendC::LocalTensor<float> xFp32TmpTensor = GetBufferByByte<float>(ubOffset, tokenLength * sizeof(float));
        AscendC::LocalTensor<float> xFp32AbsTensor = GetBufferByByte<float>(ubOffset, tokenLength * sizeof(float));
        AscendC::LocalTensor<float> xRowMaxTensor = GetBufferByByte<float>(ubOffset, UB_BLOCK_SIZE);

        AscendC::LocalTensor<int32_t> ytmpInt32Tensor = xFp32TmpTensor.template ReinterpretCast<int32_t>();
        AscendC::LocalTensor<half> yHalfTensor = xFp32TmpTensor.template ReinterpretCast<half>();
        AscendC::LocalTensor<float> yFp32Tensor = yInt8Tensor.template ReinterpretCast<float>();
        AscendC::LocalTensor<int32_t> yInt32Tensor = yInt8Tensor.template ReinterpretCast<int32_t>();

        AscendC::Cast(xFp32TmpTensor, xInTensor, AscendC::RoundMode::CAST_NONE, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Abs(xFp32AbsTensor, xFp32TmpTensor, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::ReduceMax(xRowMaxTensor, xFp32AbsTensor, xFp32AbsTensor, tokenLength, false);
        AscendC::PipeBarrier<PIPE_V>();

        PipeSync<AscendC::HardEvent::V_S>();
        float dynamicQuantScale = float(127.0) / xRowMaxTensor.GetValue(0);
        yFp32Tensor.SetValue(tokenLength / sizeof(float), float(1.0) / dynamicQuantScale);
        yInt32Tensor.SetValue(tokenLength / sizeof(int32_t) + 1, ctx.tokenFlag);
        PipeSync<AscendC::HardEvent::S_V>();

        AscendC::Muls(xFp32TmpTensor, xFp32TmpTensor, dynamicQuantScale, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(ytmpInt32Tensor, xFp32TmpTensor, AscendC::RoundMode::CAST_RINT, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(yHalfTensor, ytmpInt32Tensor, AscendC::RoundMode::CAST_ROUND, tokenLength);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(yInt8Tensor, yHalfTensor, AscendC::RoundMode::CAST_TRUNC, tokenLength);
    }
};

class OpDispatchRecvToken
{
private:
    MoEContext& ctx;

    AscendC::GlobalTensor<int8_t> x1OutGlobal;
    AscendC::GlobalTensor<float> x1ScaleOutGlobal;
    AscendC::GlobalTensor<int32_t> epSendCountsGlobal;
    AscendC::GlobalTensor<int32_t> groupTokenNumStateGlobal;

    uint32_t recvCoreNum;
    uint32_t recvCoreIdx;

public:
    CATLASS_DEVICE
    OpDispatchRecvToken(
        MoEContext& ctx_,
        GM_ADDR gmX1,
        GM_ADDR gmX1Scale,
        GM_ADDR gmEpSendCount,
        GM_ADDR gmGroupTokenNumState
    ) : ctx(ctx_)
    {
        x1OutGlobal.SetGlobalBuffer((__gm__ int8_t*)gmX1);
        x1ScaleOutGlobal.SetGlobalBuffer((__gm__ float*)gmX1Scale);
        epSendCountsGlobal.SetGlobalBuffer((__gm__ int32_t*)gmEpSendCount);
        groupTokenNumStateGlobal.SetGlobalBuffer((__gm__ int32_t*)gmGroupTokenNumState);
    }

    CATLASS_DEVICE
    void SetLogicCoreGroup(const opx::LogicCoreGroup& grp)
    {
        recvCoreNum = grp.lgc_core_num;
        recvCoreIdx = grp.lgc_core_idx;
    }

    CATLASS_DEVICE
    void Process()
    {
        uint32_t ubOffset = 0;
        AscendC::LocalTensor<int32_t> statusTensor =
            GetBufferByByte<int32_t>(ubOffset, ctx.expertCntUp * UB_BLOCK_SIZE);
        AscendC::LocalTensor<int32_t> gatherMaskOutCountTensor =
            GetBufferByByte<int32_t>(ubOffset, ctx.expertCntUp * sizeof(float));

        // Determine how many cores each expert needs first, and then determine
        // the number of source ranks each core receives data from
        uint32_t recvExpertNum = ctx.expertCntUp;
        // Required recvCoreNum is divided evenly by moeExpertNumPerRank
        uint32_t recvCoreNumPerGroup = recvCoreNum / ctx.moeExpertNumPerRank;
        // The number of source ranks each core receives data from
        uint32_t recvRankNumPerCore = ctx.epRankSize / recvCoreNumPerGroup;
        uint32_t remainderRankNum = ctx.epRankSize % recvCoreNumPerGroup;

        uint32_t groupId = recvCoreIdx / recvCoreNumPerGroup; // Determine which group the core is belongs to
        uint32_t recvCoreIdxInGroup = recvCoreIdx % recvCoreNumPerGroup; // The index of core among the group
        uint32_t startRankIdInGroup = recvRankNumPerCore * recvCoreIdxInGroup;
        if (recvCoreIdxInGroup < remainderRankNum) {
            recvRankNumPerCore += 1;
            startRankIdInGroup += recvCoreIdxInGroup;
        } else {
            startRankIdInGroup += remainderRankNum;
        }
        uint32_t endRankIdInGroup = startRankIdInGroup + recvRankNumPerCore;
        uint32_t startRankId = ctx.epRankSize * groupId + startRankIdInGroup;
        uint32_t endRankId = ctx.epRankSize * groupId + endRankIdInGroup;

        // 接收count并计算前缀和
        RecvTokenCountInfo(startRankId, statusTensor.ReinterpretCast<float>(),
            gatherMaskOutCountTensor.ReinterpretCast<float>());

        uint32_t recvTokenCount = RecvToken(ubOffset, startRankId, endRankId,
            statusTensor, gatherMaskOutCountTensor);

        NotifyNextStage(ubOffset, groupId, recvRankNumPerCore * (uint32_t)ctx.vToCFlag, recvTokenCount);

        AscendC::PipeBarrier<PIPE_ALL>();
    }

private:
    CATLASS_DEVICE
    void RecvTokenCountInfo(uint32_t startRankId,
        const AscendC::LocalTensor<float>& statusFp32Tensor,
        const AscendC::LocalTensor<float>& gatherMaskOutFp32Tensor)
    {
        uint32_t recStatusNumPerCore = ctx.expertCntUp;
        uint32_t startStatusIndex = 0; // Each core must receive all count data

        AscendC::GlobalTensor<float> windowInStatusFp32Tensor;
        windowInStatusFp32Tensor.SetGlobalBuffer((__gm__ float*)ctx.GetWindowStateAddrByRankId(ctx.epRankId) +
            startStatusIndex * STATE_OFFSET / sizeof(float));

        AscendC::DataCopyParams dataCopyParams{};
        dataCopyParams.blockCount = (uint16_t)recStatusNumPerCore;
        dataCopyParams.blockLen = 1;
        dataCopyParams.srcStride = 15; // 15 data blocks，actual read stride is 16*32B=512B
        dataCopyParams.dstStride = 0;

        AscendC::GatherMaskParams gatherMaskParams{};
        gatherMaskParams.src0BlockStride = 1;
        gatherMaskParams.repeatTimes = (uint16_t)recStatusNumPerCore;
        gatherMaskParams.src0RepeatStride = 1;
        gatherMaskParams.src1RepeatStride = 0;

        uint8_t src1Pattern = 3; // 3 inner-pattern, select the first element from every 4 elements within each repeat
        uint32_t procElementInRepeat = 1;
        uint64_t rsvdCnt = 0;

        float sumOfFlag = static_cast<float>(-1.0);
        float minTarget = (ctx.sumTarget * recStatusNumPerCore) - (float)0.5;
        float maxTarget = (ctx.sumTarget * recStatusNumPerCore) + (float)0.5;

        // Wait until all source ranks of all experts in this rank to send the flag
        do {
            AscendC::DataCopy(statusFp32Tensor, windowInStatusFp32Tensor, dataCopyParams);
            PipeSync<AscendC::HardEvent::MTE2_V>();
            AscendC::GatherMask(gatherMaskOutFp32Tensor, statusFp32Tensor, src1Pattern,
                true, procElementInRepeat, gatherMaskParams, rsvdCnt);
            AscendC::PipeBarrier<PIPE_V>();
            AscendC::ReduceSum(gatherMaskOutFp32Tensor, gatherMaskOutFp32Tensor, {}, recStatusNumPerCore);
            PipeSync<AscendC::HardEvent::V_S>();
            sumOfFlag = gatherMaskOutFp32Tensor.GetValue(0);
        } while (!(minTarget < sumOfFlag && sumOfFlag < maxTarget));

        // Get the sum of the token nums sent by all source ranks of all experts in this rank
        src1Pattern = 4; // 4 inner-pattern, select the second element from every 4 elements within each repeat
        procElementInRepeat = 2;
        AscendC::GatherMask(gatherMaskOutFp32Tensor, statusFp32Tensor, src1Pattern,
            true, procElementInRepeat, gatherMaskParams, rsvdCnt);
        AscendC::PipeBarrier<PIPE_V>();
        // Calculates the prefix sum of the number of tokens before the rank-id to be processed
        // store to the 0-index of gatherMaskOut array, for later used
        AscendC::ReduceSum(gatherMaskOutFp32Tensor, gatherMaskOutFp32Tensor, {}, startRankId + 1);
        PipeSync<AscendC::HardEvent::V_S>();
    }

    CATLASS_DEVICE
    uint32_t RecvToken(uint32_t ubOffset, uint32_t startRankId, uint32_t endRankId,
        const AscendC::LocalTensor<int32_t>& statusTensor,
        const AscendC::LocalTensor<int32_t>& gatherMaskOutCountTensor)
    {
        uint32_t hCommuSize = ctx.tokenLength * sizeof(int8_t) + TOKEN_EXTRA_SPACE;
        AscendC::LocalTensor<int8_t> xTmpTensor = GetBufferByByte<int8_t>(ubOffset, hCommuSize * sizeof(int8_t));
        AscendC::LocalTensor<int32_t> tmpLocalTensor = GetBufferByByte<int32_t>(ubOffset, UB_BLOCK_SIZE);

        AscendC::TEventID ev_MTE3_MTE2 = GetTPipePtr()->AllocEventID<AscendC::HardEvent::MTE3_MTE2>();
        AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2);

        uint32_t recvTokenCount = 0;
        for (uint32_t index = startRankId; index < endRankId; index++) {
            uint32_t i = index - startRankId;
            if (i > 0) {
                gatherMaskOutCountTensor.SetValue(i,
                    gatherMaskOutCountTensor.GetValue(i - 1) + gatherMaskOutCountTensor.GetValue(index));
            }

            uint32_t count = statusTensor.GetValue(index * INT32_COUNT_PER_BLOCK + 1);
            recvTokenCount += count;
            uint32_t beginIdx = gatherMaskOutCountTensor.GetValue(i) - count;
            uint32_t winOffset = index;
            if (ctx.moeExpertNumPerRank > 1) {
                // The spatial layout of the count is different from that of the token data
                // srcRank: index % epRankSize
                // localExpertId: index / epRankSize
                // addr: (srcRank * moeExpertNumPerRank + localExpertId) * expertPerSizeOnWin
                winOffset = (index % ctx.epRankSize) * ctx.moeExpertNumPerRank + index / ctx.epRankSize;
            }
            GM_ADDR wAddr = ctx.GetWindowDataAddrByRankId(ctx.epRankId) + winOffset * ctx.expertPerSizeOnWin;

            AscendC::GlobalTensor<int8_t> tokGlobal;
            AscendC::GlobalTensor<int32_t> tokGlobalInt32;
            for (uint32_t j = 0; j < count; j++) {
                tokGlobal.SetGlobalBuffer((__gm__ int8_t *)(wAddr + j * hCommuSize));
                tokGlobalInt32.SetGlobalBuffer(
                    (__gm__ int32_t *)(wAddr + j * hCommuSize + ctx.tokenLength * sizeof(int8_t)));

                while (true) {
                    AscendC::DataCopy(tmpLocalTensor, tokGlobalInt32, INT32_COUNT_PER_BLOCK);
                    PipeSync<AscendC::HardEvent::MTE2_S>();
                    if (tmpLocalTensor.GetValue(1) == ctx.tokenFlag) {
                        tokGlobalInt32.SetValue(1, 0);
                        __asm__ __volatile__("");
                        AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                            AscendC::DcciDst::CACHELINE_OUT>(tokGlobalInt32[1]);
                        __asm__ __volatile__("");
                        break;
                    }
                }

                AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2);
                AscendC::DataCopy(xTmpTensor, tokGlobal, hCommuSize / sizeof(int8_t));

                PipeSync<AscendC::HardEvent::MTE2_MTE3>();

                AscendC::DataCopy(x1OutGlobal[(beginIdx + j) * ctx.tokenLength], xTmpTensor, ctx.tokenLength);
                AscendC::DataCopyPad(x1ScaleOutGlobal[beginIdx + j],
                    xTmpTensor[ctx.tokenLength].ReinterpretCast<float>(), {1, sizeof(float), 0, 0, 0});
                AscendC::SetFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2);
            }
        }

        AscendC::WaitFlag<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2);
        GetTPipePtr()->ReleaseEventID<AscendC::HardEvent::MTE3_MTE2>(ev_MTE3_MTE2);

        // Write out the prefix sum of the received token number
        AscendC::DataCopyExtParams dataCopyExtParams{};
        dataCopyExtParams.blockCount = 1;
        dataCopyExtParams.blockLen = (endRankId - startRankId) * sizeof(int32_t);
        AscendC::DataCopyPad(epSendCountsGlobal[startRankId], gatherMaskOutCountTensor, dataCopyExtParams);
        AscendC::PipeBarrier<PIPE_ALL>();

        return recvTokenCount;
    }

    CATLASS_DEVICE
    void NotifyNextStage(uint32_t ubOffset, uint32_t groupId, uint32_t flagValue, uint32_t recvTokenCount)
    {
        // Use AtomicAdd to increase the ready flag of one group
        // AICs and the computing-AIVs will start when the corresponding group's ready flag reaches the target value
        AscendC::LocalTensor<int32_t> tmpLocalTensor = GetBufferByByte<int32_t>(ubOffset, UB_BLOCK_SIZE);

        tmpLocalTensor.SetValue(CV_FLAG_INDEX, flagValue);
        tmpLocalTensor.SetValue(GROUP_ID_INDEX, groupId);
        tmpLocalTensor.SetValue(SELF_COUNT_INDEX, recvTokenCount);

        PipeSync<AscendC::HardEvent::S_MTE3>();

        AscendC::SetAtomicAdd<int32_t>();
        AscendC::DataCopy(groupTokenNumStateGlobal[groupId * GROUP_INFO_SIZE], tmpLocalTensor, INT32_COUNT_PER_BLOCK);
        AscendC::SetAtomicNone();
    }
};

template <
    typename DispatchPolicy,
    typename CType_,
    typename ScaleType_,
    typename PerTokenScaleType_,
    typename TileRowBroadcastMul_,
    typename TileBroadcastOneBlk_,
    typename TileOneBlkColumnBroadcastMul_
>
class OpDequant
{
public:
    using ArchTag = typename DispatchPolicy::ArchTag;
    static constexpr uint32_t UB_STAGES = DispatchPolicy::UB_STAGES;

    // Data infos
    using ElementC = typename CType_::Element;
    using LayoutC = typename CType_::Layout;
    using ElementScale = typename ScaleType_::Element;
    using LayoutScale = typename ScaleType_::Layout;
    using ElementPerTokenScale = typename PerTokenScaleType_::Element;
    using LayoutPerTokenScale = typename PerTokenScaleType_::Layout;

    // Check data infos
    static_assert(
        std::is_same_v<ElementC, int32_t> &&
        std::is_same_v<ElementScale, float> &&
        std::is_same_v<ElementPerTokenScale, float>,
        "The element type template parameters of OpDequant are wrong"
    );
    static_assert(
        std::is_same_v<LayoutC, layout::RowMajor> &&
        std::is_same_v<LayoutScale, layout::VectorLayout> &&
        std::is_same_v<LayoutPerTokenScale, layout::VectorLayout>,
        "The layout template parameters of OpDequant are wrong"
    );

    // Tile compute ops
    using TileRowBroadcastMul = TileRowBroadcastMul_;
    using TileBroadcastOneBlk = TileBroadcastOneBlk_;
    using TileOneBlkColumnBroadcastMul = TileOneBlkColumnBroadcastMul_;

    using TileShape = typename TileRowBroadcastMul::TileShape;
    static_assert(TileShape::ROW * sizeof(float) % BYTE_PER_BLK == 0,
        "The per token scale granularity for word calculation must be 32 bytes aligned.");

    static_assert(
        TileShape::ROW == TileBroadcastOneBlk::COMPUTE_LENGTH &&
        std::is_same_v<TileShape, typename TileOneBlkColumnBroadcastMul::TileShape>,
        "TileShape must be consistent for all tile compute ops"
    );

    // Op framework defines
    enum {
        IN_C_IDX,
        IN_SCALE_IDX,
        IN_PERTOKEN_SCALE_IDX
    };

    OPX_INPUT_PARAM_DECLARE(PIPE_V, PIPE_V, PIPE_V);
    OPX_OUTPUT_PARAM_DECLARE(PIPE_V);

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetInQueUsage(const MatrixCoord&) {
        opx::QueUsageInfo info;
        if constexpr (I == IN_C_IDX) {
            info.buf_num = UB_STAGES;
            info.buf_size = TileShape::COUNT * sizeof(ElementC);
        } else if constexpr (I == IN_SCALE_IDX) {
            info.buf_num = UB_STAGES;
            info.buf_size = TileShape::COLUMN * sizeof(ElementScale);
        } else if constexpr (I == IN_PERTOKEN_SCALE_IDX) {
            info.buf_num = UB_STAGES;
            info.buf_size = TileShape::ROW * sizeof(ElementPerTokenScale);
        }
        return info;
    }

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetOutQueUsage(const MatrixCoord&) {
        return { 1, TileShape::COUNT * sizeof(float) };
    }

    CATLASS_DEVICE
    void Init()
    {
        GetTPipePtr()->InitBuffer(ubTmpMx32BBuf, TileShape::ROW * BYTE_PER_BLK);
    }

    CATLASS_DEVICE
    void LazyInit()
    {
        Init();
    }

    template <typename SrcPipes, typename DstPipes>
    CATLASS_DEVICE
    void Process(InputParam<SrcPipes>& input, OutputParam<DstPipes>& output)
    {
        auto [cQue, scaleQue, perTokenScaleQue] = input.que_tuple;
        auto [outQue] = output.que_tuple;

        AscendC::LocalTensor<float> ubTmpMxN = outQue.template AllocTensor<float>();
        AscendC::LocalTensor<float> ubTmpMx32B = ubTmpMx32BBuf.Get<float>();

        AscendC::LocalTensor<ElementC> ubC = cQue.template DeQue<ElementC>();
        AscendC::Cast(ubTmpMxN, ubC, AscendC::RoundMode::CAST_RINT, TileShape::COUNT);
        cQue.FreeTensor(ubC);

        AscendC::PipeBarrier<PIPE_V>();

        AscendC::LocalTensor<ElementScale> ubScale = scaleQue.template DeQue<ElementScale>();
        tileRowBroadcastMul(ubTmpMxN, ubTmpMxN, ubScale);
        scaleQue.FreeTensor(ubScale);

        AscendC::LocalTensor<ElementPerTokenScale> ubPerTokenScale =
            perTokenScaleQue.template DeQue<ElementPerTokenScale>();
        tileBroadcastOneBlk(ubTmpMx32B, ubPerTokenScale);
        perTokenScaleQue.FreeTensor(ubPerTokenScale);

        AscendC::PipeBarrier<PIPE_V>();

        tileOneBlkColumnBroadcastMul(ubTmpMxN, ubTmpMxN, ubTmpMx32B);
        outQue.EnQue(ubTmpMxN);
    }

protected:
    AscendC::TBuf<AscendC::TPosition::VECCALC> ubTmpMx32BBuf;

    TileRowBroadcastMul tileRowBroadcastMul;
    TileBroadcastOneBlk tileBroadcastOneBlk;
    TileOneBlkColumnBroadcastMul tileOneBlkColumnBroadcastMul;
};

template <
    typename DispatchPolicy,
    typename TileShape_,
    typename DType_
>
class OpSwiglu
{
public:
    using ArchTag = typename DispatchPolicy::ArchTag;
    static constexpr uint32_t UB_STAGES = DispatchPolicy::UB_STAGES;

    using ElementD = typename DType_::Element;
    using LayoutD = typename DType_::Layout;

    // Check data infos
    static_assert(
        std::is_same_v<ElementD, float>,
        "The element type template parameters of OpSwiglu are wrong"
    );
    static_assert(
        std::is_same_v<LayoutD, layout::RowMajor>,
        "The layout template parameters of OpSwiglu are wrong"
    );

    using TileShape = TileShape_;

    static constexpr uint32_t CHUNK_TILE_COLUMN = TileShape::COLUMN / 2;
    using ChunkTileShape = MatrixShape<TileShape::ROW, CHUNK_TILE_COLUMN>;

    using TileStrideMuls = Epilogue::Tile::TileStrideMuls<
        ArchTag, float, ChunkTileShape, ChunkTileShape, TileShape>;
    using TileStrideDiv = Epilogue::Tile::TileStrideDiv<
        ArchTag, float, ChunkTileShape, ChunkTileShape::COLUMN, TileShape::COLUMN, ChunkTileShape::COLUMN>;
    using TileStrideMul = Epilogue::Tile::TileStrideMul<
        ArchTag, float, ChunkTileShape, ChunkTileShape::COLUMN, TileShape::COLUMN, ChunkTileShape::COLUMN>;

    // Op framework defines
    OPX_INPUT_PARAM_DECLARE(PIPE_V);
    OPX_OUTPUT_PARAM_DECLARE(PIPE_V);

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetInQueUsage(const MatrixCoord&) {
        return { 1, TileShape::COUNT * sizeof(float) };
    }

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetOutQueUsage(const MatrixCoord&) {
        return { UB_STAGES, TileShape::COUNT * sizeof(ElementD) };
    }

    CATLASS_DEVICE
    void Init()
    {
        GetTPipePtr()->InitBuffer(ubTmpMxChunkNBuf, ChunkTileShape::COUNT * sizeof(float));
    }

    CATLASS_DEVICE
    void LazyInit()
    {
        Init();
    }

    template <typename SrcPipes, typename DstPipes>
    CATLASS_DEVICE
    void Process(InputParam<SrcPipes>& input, OutputParam<DstPipes>& output)
    {
        auto [inQue] = input.que_tuple;
        auto [outQue] = output.que_tuple;

        AscendC::LocalTensor<float> ubTmpMxN = inQue.template DeQue<float>();
        AscendC::LocalTensor<float> ubTmpMxChunkN = ubTmpMxChunkNBuf.Get<float>();

        tileStrideMuls(ubTmpMxChunkN, ubTmpMxN, -1.0f);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Exp(ubTmpMxChunkN, ubTmpMxChunkN, ChunkTileShape::COUNT);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Adds(ubTmpMxChunkN, ubTmpMxChunkN, 1.0f, ChunkTileShape::COUNT);
        AscendC::PipeBarrier<PIPE_V>();
        tileStrideDiv(ubTmpMxChunkN, ubTmpMxN, ubTmpMxChunkN);
        AscendC::PipeBarrier<PIPE_V>();

        auto ubTmpMxNR = ubTmpMxN[ChunkTileShape::COLUMN];

        AscendC::LocalTensor<ElementD> ubD = outQue.template AllocTensor<ElementD>();
        tileStrideMul(ubD, ubTmpMxNR, ubTmpMxChunkN);
        AscendC::PipeBarrier<PIPE_V>();
        outQue.EnQue(ubD);

        inQue.FreeTensor(ubTmpMxN);
    }

protected:
    AscendC::TBuf<AscendC::TPosition::VECCALC> ubTmpMxChunkNBuf;

    TileStrideMuls tileStrideMuls;
    TileStrideDiv tileStrideDiv;
    TileStrideMul tileStrideMul;
};

class OpSyncAllCleanAndUpdate
{
private:
    MoEContext& ctx;

    AscendC::GlobalTensor<int32_t> groupTokenNumStateGlobal;
    AscendC::GlobalTensor<int32_t> epSendCountsGlobal;
    AscendC::GlobalTensor<int64_t> expertTokenNumOutGlobal;
    AscendC::GlobalTensor<int64_t> nonCumSumExpertTokenNumOutGlobal;

public:
    CATLASS_DEVICE
    OpSyncAllCleanAndUpdate(
        MoEContext& ctx_,
        GM_ADDR gmGroupTokenNumState,
        GM_ADDR gmEpSendCount,
        GM_ADDR gmGroupListOut,
        GM_ADDR gmExpertTokenNumOut
    ) : ctx(ctx_)
    {
        groupTokenNumStateGlobal.SetGlobalBuffer((__gm__ int32_t*)gmGroupTokenNumState);
        epSendCountsGlobal.SetGlobalBuffer((__gm__ int32_t*)gmEpSendCount);
        expertTokenNumOutGlobal.SetGlobalBuffer((__gm__ int64_t*)gmGroupListOut);
        nonCumSumExpertTokenNumOutGlobal.SetGlobalBuffer((__gm__ int64_t*)gmExpertTokenNumOut);
    }

    CATLASS_DEVICE
    void Process()
    {
        icache_preload(8); // 8 * 2k = 16k
        AscendC::SyncAll<false>();
        AscendC::PipeBarrier<PIPE_ALL>();

        uint32_t aivIdx = get_block_idx() * get_subblockdim() + get_subblockid();
        if (aivIdx == 0) {
            // Clear the token number infos
            AscendC::LocalTensor<int32_t> zeroLocal = GetBufferByByte<int32_t>(0);
            AscendC::Duplicate(zeroLocal, (int32_t)0, GROUP_INFO_SIZE * ctx.moeExpertNumPerRank);
            PipeSync<AscendC::HardEvent::V_MTE3>();
            AscendC::DataCopy(groupTokenNumStateGlobal, zeroLocal, GROUP_INFO_SIZE * ctx.moeExpertNumPerRank);
        } else if (aivIdx == 1) {
            // Update the group list infos
            uint32_t tmpTokenNum = 0;
            for (uint32_t localMoeIndex = 0; localMoeIndex < ctx.moeExpertNumPerRank; ++localMoeIndex) {
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int32_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                    AscendC::DcciDst::CACHELINE_OUT>(epSendCountsGlobal[(localMoeIndex + 1) * ctx.epRankSize - 1]);
                __asm__ __volatile__("");
                uint32_t tokenNum = epSendCountsGlobal.GetValue((localMoeIndex + 1) * ctx.epRankSize - 1);
                expertTokenNumOutGlobal.SetValue(localMoeIndex, tokenNum);
                nonCumSumExpertTokenNumOutGlobal.SetValue(localMoeIndex, tokenNum - tmpTokenNum);
                tmpTokenNum = tokenNum;
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int64_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                    AscendC::DcciDst::CACHELINE_OUT>(expertTokenNumOutGlobal[localMoeIndex]);
                __asm__ __volatile__("");
                __asm__ __volatile__("");
                AscendC::DataCacheCleanAndInvalid<int64_t, AscendC::CacheLine::SINGLE_CACHE_LINE,
                    AscendC::DcciDst::CACHELINE_OUT>(nonCumSumExpertTokenNumOutGlobal[localMoeIndex]);
                __asm__ __volatile__("");
            }
        }

        AscendC::PipeBarrier<PIPE_ALL>();
    }
};

class OpBlockQuant
{
public:
    using ElementInput = float;
    using ElementDequantScale = float;
    using ElementOutput = int8_t;

public:
    OPX_INPUT_PARAM_DECLARE(PIPE_V);
    OPX_OUTPUT_PARAM_DECLARE(PIPE_V, PIPE_V);

    CATLASS_DEVICE
    void SetContext(const opx::MatrixDataContext& ctx)
    {
        tileShape = ctx.tile_shape;
        halfTileShape = MakeCoord(tileShape.row(), tileShape.column() / 2);
        tileShapeCount = tileShape.row() * tileShape.column();
        halfTileShapeCount = halfTileShape.row() * halfTileShape.column();
    }

    CATLASS_DEVICE
    void LazyInit()
    {
        AscendC::TPipe& tpipe = *GetTPipePtr();
        ubAbs = AllocLocalTensor<float>(tileShapeCount * sizeof(float), tpipe);
        ubMax = AllocLocalTensor<float>(halfTileShapeCount * sizeof(float), tpipe);
        ubReduceMax = AllocLocalTensor<float>(tileShape.row() * sizeof(float), tpipe);
        ubQuantScale = AllocLocalTensor<float>(tileShape.row() * sizeof(float), tpipe);
        ubInputTmp = ubAbs;
        ubQuantF32 = ubAbs;
        ubQuantS32 = ubAbs.ReinterpretCast<int32_t>();
        ubQuantF16 = ubAbs.ReinterpretCast<half>();
    }

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetInQueUsage(const MatrixCoord&)
    {
        return { 1, tileShapeCount * (uint32_t)sizeof(ElementInput) };
    }

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetOutQueUsage(const MatrixCoord&)
    {
        if constexpr (I == 0) {
            return { 1, tileShape.row() * (uint32_t)sizeof(ElementDequantScale) };
        } else {
            return { 1, tileShapeCount * (uint32_t)sizeof(ElementOutput) };
        }
    }

public:
    template <typename T, typename TPool = AscendC::TPipe>
    CATLASS_DEVICE
    AscendC::LocalTensor<T> AllocLocalTensor(uint32_t size, TPool& tpipe)
    {
        AscendC::TBuf<> buf;
        tpipe.InitBuffer(buf, size);
        return buf.Get<T>();
    }

    OPX_PROCESS_TEMPLATE
    CATLASS_DEVICE
    void Process(OPX_DEFAULT_PROCESS_ARGLIST)
    {
        AscendC::PipeBarrier<PIPE_ALL>();

        auto [inQue] = input.que_tuple;
        auto [dequantScaleQue, outQue] = output.que_tuple;

        AscendC::LocalTensor<ElementInput> ubInput = inQue.template DeQue<ElementInput>();
        AscendC::Abs(ubAbs, ubInput, tileShapeCount);
        AscendC::PipeBarrier<PIPE_V>();

        for (uint32_t rowIdx = 0; rowIdx < halfTileShape.row(); ++rowIdx) {
            AscendC::Max(ubMax[rowIdx * halfTileShape.column()],
                ubAbs[rowIdx * tileShape.column()],
                ubAbs[rowIdx * tileShape.column() + halfTileShape.column()],
                halfTileShape.column());
        }

        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Muls(ubInputTmp, ubInput, 127.f, tileShapeCount);

        constexpr uint32_t elementPerBlk = BYTE_PER_BLK / sizeof(float);
        constexpr int32_t mask = 64;

        AscendC::BinaryRepeatParams maxParams;
        maxParams.dstBlkStride = halfTileShape.column() / elementPerBlk;
        maxParams.src0BlkStride = halfTileShape.column() / elementPerBlk;
        maxParams.src1BlkStride = halfTileShape.column() / elementPerBlk;
        maxParams.dstRepStride = 1;
        maxParams.src0RepStride = 1;
        maxParams.src1RepStride = 1;
        constexpr uint32_t colNumPerCompute = BYTE_PER_VECTOR_FRACTAL / sizeof(float);
        uint32_t reduceWidth = halfTileShape.column();
        while (reduceWidth > (BLK_NUM_PER_VECTOR_FRACTAL * BYTE_PER_BLK / sizeof(float))) {
            reduceWidth >>= 1;
            AscendC::Max(ubMax, ubMax, ubMax[reduceWidth], mask, reduceWidth / elementPerBlk, maxParams);
            AscendC::PipeBarrier<PIPE_V>();
        }

        AscendC::WholeReduceMax(ubReduceMax, ubMax, mask, halfTileShape.row(),
            1, 1, halfTileShape.column() / elementPerBlk, AscendC::ReduceOrder::ORDER_ONLY_VALUE);

        AscendC::TEventID eventVtoS = GetTPipePtr()->AllocEventID<AscendC::HardEvent::V_S>();
        AscendC::SetFlag<AscendC::HardEvent::V_S>(eventVtoS);

        inQue.FreeTensor(ubInput);
        AscendC::PipeBarrier<PIPE_V>();

        AscendC::LocalTensor<ElementDequantScale> ubDequantScale =
            dequantScaleQue.template AllocTensor<ElementDequantScale>();
        AscendC::Muls(ubDequantScale, ubReduceMax, 1.0f / 127.0f, tileShape.row());
        dequantScaleQue.EnQue(ubDequantScale);

        AscendC::WaitFlag<AscendC::HardEvent::V_S>(eventVtoS);
        GetTPipePtr()->ReleaseEventID<AscendC::HardEvent::V_S>(eventVtoS);
        for (uint32_t rowIdx = 0; rowIdx < tileShape.row(); ++rowIdx) {
            AscendC::Muls(ubQuantF32[rowIdx * tileShape.column()], ubInputTmp[rowIdx * tileShape.column()],
                1.f / ubReduceMax.GetValue(rowIdx), tileShape.column());
        }

        AscendC::PipeBarrier<PIPE_V>();
        AscendC::Cast(ubQuantS32, ubQuantF32, AscendC::RoundMode::CAST_RINT, tileShapeCount);
        AscendC::PipeBarrier<PIPE_V>();
        AscendC::SetDeqScale(static_cast<half>(1.0));
        AscendC::Cast(ubQuantF16, ubQuantS32, AscendC::RoundMode::CAST_RINT, tileShapeCount);
        AscendC::PipeBarrier<PIPE_V>();

        AscendC::LocalTensor<ElementOutput> ubOutput = outQue.template AllocTensor<ElementOutput>();
        AscendC::Cast(ubOutput, ubQuantF16, AscendC::RoundMode::CAST_RINT, tileShapeCount);
        outQue.EnQue(ubOutput);

        AscendC::PipeBarrier<PIPE_ALL>();
    }

private:
    MatrixCoord tileShape;
    MatrixCoord halfTileShape;
    uint32_t tileShapeCount;
    uint32_t halfTileShapeCount;

    AscendC::LocalTensor<float> ubAbs;
    AscendC::LocalTensor<float> ubMax;
    AscendC::LocalTensor<float> ubReduceMax;
    AscendC::LocalTensor<float> ubQuantScale;
    AscendC::LocalTensor<float> ubQuantScaleBrcb;
    AscendC::LocalTensor<float> ubInputTmp;
    AscendC::LocalTensor<float> ubQuantF32;
    AscendC::LocalTensor<int32_t> ubQuantS32;
    AscendC::LocalTensor<half> ubQuantF16;
};

template <class TileShape_, class DType_>
class OpCombineSend {
public:
    using ElementD = typename DType_::Element;
    using LayoutD = typename DType_::Layout;
    using TileShape = TileShape_;

    OPX_INPUT_PARAM_DECLARE(PIPE_V);
    OPX_OUTPUT_PARAM_DECLARE();

    template <size_t I>
    CATLASS_DEVICE
    opx::QueUsageInfo GetInQueUsage(const MatrixCoord&)
    {
        return { 1, TileShape::COUNT * (uint32_t)sizeof(float) };
    }

    CATLASS_DEVICE
    GM_ADDR GetWinAddrByRankId(const int32_t rankId, const uint8_t expertLocalId = 0U)
    {
        GM_ADDR rankWinAddr;
        if (calcInfo.epRankId_ == rankId) {
            rankWinAddr = (GM_ADDR)calcInfo.epWinContext_->localWindowsIn;
        } else {
            auto remoteDevicePtr = (HcclRankRelationResV2 *)calcInfo.epWinContext_->remoteRes[rankId].nextDevicePtr;
            rankWinAddr = (GM_ADDR)remoteDevicePtr->windowsIn;
        }
        return rankWinAddr + calcInfo.winDataSizeOffset_ + rankId * WIN_OPT_RANK_OFFSET +
            expertLocalId * calcInfo.expertPerSizeOnWin_;
    }

    CATLASS_DEVICE
    void SetContext(const opx::MatrixDataContext &ctx_)
    {
        this->ctx = &ctx_;
    }

    CATLASS_DEVICE
    void Init(const MoeDistributeCombineImpl::CombineCalcInfo& info_, LayoutD layoutD_)
    {
        calcInfo = info_;
        layoutD = layoutD_;

        GetTPipePtr()->InitBuffer(epSendCountBuf, calcInfo.moeSendNum_ * sizeof(int32_t));
        GetTPipePtr()->InitBuffer(ubDBuf, TileShape::COUNT * sizeof(ElementD));
        ev_MTE3_V = GetTPipePtr()->AllocEventID<AscendC::HardEvent::MTE3_V>();
        AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(ev_MTE3_V);

        epSendCountLocal_ = epSendCountBuf.Get<int32_t>();
        AscendC::GlobalTensor<int32_t> epSendCountGM;
        epSendCountGM.SetGlobalBuffer((__gm__ int32_t *)calcInfo.epSendCount_);
        uint32_t epSendCountSize = calcInfo.moeSendNum_;
        AscendC::DataCopyExtParams epSendCntParams = {
            1U, static_cast<uint32_t>(epSendCountSize * sizeof(uint32_t)), 0U, 0U, 0U };
        AscendC::DataCopyPadExtParams<int32_t> copyPadParams{ false, 0U, 0U, 0U };
        AscendC::DataCopyPad(epSendCountLocal_, epSendCountGM, epSendCntParams, copyPadParams);
        PipeSync<AscendC::HardEvent::MTE2_S>();
    }

    CATLASS_DEVICE
    ~OpCombineSend()
    {
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(ev_MTE3_V);
        GetTPipePtr()->ReleaseEventID<AscendC::HardEvent::MTE3_V>(ev_MTE3_V);
    }

    CATLASS_DEVICE
    void SetCombineSendEpRank(uint32_t epRank, uint32_t &remoteEpRank, uint32_t &localEpRank)
    {
        if ((calcInfo.isShardExpert_) &&
            (epRank < calcInfo.sharedExpertRankNum_)) {
            remoteEpRank = calcInfo.epRankId_;
            localEpRank = epRank;
        } else {
            remoteEpRank = epRank;
            localEpRank = calcInfo.epRankId_;
        }
    }

    template <typename SrcPipes, typename DstPipes>
    CATLASS_DEVICE
    void Process(InputParam<SrcPipes> &input, OutputParam<DstPipes>&)
    {
        auto [inQue] = input.que_tuple;

        auto layoutGmTileD = layoutD.GetTileLayout(ctx->actual_tile_shape);
        auto tileOffsetD = layoutD.GetOffset(ctx->tile_offset);
        auto ubTileStride = MakeCoord(static_cast<int64_t>(TileShape::COLUMN), 1L);
        LayoutD layoutUbD{ ctx->actual_tile_shape, ubTileStride };

        AscendC::LocalTensor<ElementD> ubD = ubDBuf.Get<ElementD>();
        AscendC::LocalTensor<float> ubC = inQue.template DeQue<float>();
        AscendC::WaitFlag<AscendC::HardEvent::MTE3_V>(ev_MTE3_V);
        AscendC::Cast(ubD, ubC, AscendC::RoundMode::CAST_RINT, TileShape::COUNT);
        inQue.FreeTensor(ubC);
        PipeSync<AscendC::HardEvent::V_MTE3>();

        const uint32_t copyTokenLen = layoutGmTileD.shape(1) * sizeof(ElementD);
        const uint32_t copyTokenSrcStride =
            (layoutUbD.stride(0) - layoutUbD.shape(1)) / (BYTE_PER_C0 / sizeof(ElementD));
        const uint32_t copyTokenDstStride = (layoutGmTileD.stride(0) - layoutGmTileD.shape(1)) * sizeof(ElementD);

        uint32_t startToken = ctx->group_m_sum + ctx->tile_offset.row();
        uint32_t tokenOffset = ctx->tile_offset.column();
        uint32_t endToken = startToken + layoutGmTileD.shape(0);
        uint32_t itToken = startToken;

        constexpr uint32_t epRankStart = 0;
        uint32_t expertIdx = ctx->group_loop_i;
        uint32_t expertOffset = expertIdx * calcInfo.epWorldSize_;
        uint32_t sendCount = expertIdx == 0 && epRankStart == 0 ?
            0 : epSendCountLocal_.GetValue(expertOffset + epRankStart - 1);
        for (uint32_t epRank = epRankStart; epRank < calcInfo.epWorldSize_ && itToken < endToken; ++epRank) {
            uint32_t prevSendCount = sendCount;
            sendCount = epSendCountLocal_.GetValue(expertOffset + epRank);
            if (prevSendCount <= itToken && itToken < sendCount) {
                uint32_t copyTokenCount = (sendCount < endToken ? sendCount : endToken) - itToken;
                AscendC::DataCopyExtParams dataCopyParams(copyTokenCount, copyTokenLen, copyTokenSrcStride,
                    copyTokenDstStride, 0);
                uint32_t remoteEpRank;
                uint32_t localEpRank;
                SetCombineSendEpRank(epRank, remoteEpRank, localEpRank);
                GM_ADDR rankGM = GetWinAddrByRankId(remoteEpRank, expertIdx) +
                    localEpRank * calcInfo.moeExpertPerRankNum_ * calcInfo.expertPerSizeOnWin_;
                AscendC::GlobalTensor<ElementD> rankWindow;
                rankWindow.SetGlobalBuffer((__gm__ ElementD *)rankGM);
                AscendC::DataCopyPad(rankWindow[(itToken - prevSendCount) * calcInfo.axisH_ + tokenOffset],
                    ubD[(itToken - startToken) * layoutUbD.stride(0)], dataCopyParams);
                itToken += copyTokenCount;
            }
        }

        AscendC::SetFlag<AscendC::HardEvent::MTE3_V>(ev_MTE3_V);
    }

private:
    AscendC::TBuf<AscendC::TPosition::VECCALC> epSendCountBuf;
    AscendC::TBuf<AscendC::TPosition::VECCALC> ubDBuf;
    AscendC::LocalTensor<int32_t> epSendCountLocal_;
    AscendC::TEventID ev_MTE3_V;

    LayoutD layoutD;
    const opx::MatrixDataContext* ctx{nullptr};
    MoeDistributeCombineImpl::CombineCalcInfo calcInfo;
};

template <TemplateMC2TypeClass>
class OpCombineSetFlag {
public:

    CATLASS_DEVICE
    void Init(MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *combiner_)
    {
        combiner = combiner_;
    }

    CATLASS_DEVICE void Process()
    {
        combiner->AllToAllSend();
    }

private:
    MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *combiner;
};

template <TemplateMC2TypeClass>
class OpCombineRecv {
public:
    CATLASS_DEVICE
    void Init(MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *combiner_)
    {
        combiner = combiner_;
    }

    CATLASS_DEVICE void Process()
    {
        combiner->ReducePermute();
    }

private:
    MoeDistributeCombineImpl::CamMoeDistributeCombine<TemplateMC2TypeFunc> *combiner;
};

template <typename GmType, uint32_t BUFFER_NUM, bool ENABLE_TENSOR_LIST>
struct GmScaleReader
{
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    static constexpr pipe_t SRC_PIPE = PIPE_MTE2;

    CATLASS_DEVICE
    opx::QueUsageInfo GetQueUsage(const MatrixCoord& tile_shape)
    {
        return { BUFFER_NUM, tile_shape.column() * (uint32_t)sizeof(Element) };
    }

    CATLASS_DEVICE
    void DoCopy(const opx::MatrixDataContext& ctx, const AscendC::LocalTensor<Element>& ubTile)
    {
        using CopyGm2Ub = Epilogue::Tile::CopyGm2Ub<
            Arch::AtlasA2, Gemm::GemmType<Element, Layout>>;

        auto scaleTileOffset = ctx.tile_offset.template GetCoordByAxis<1>();
        auto scaleTileShape = ctx.actual_tile_shape.template GetCoordByAxis<1>();

        AscendC::GlobalTensor<Element> gmScale;
        AscendC::ListTensorDesc gmListDesc{gm};
        if constexpr (!ENABLE_TENSOR_LIST) {
            gmScale.SetGlobalBuffer(gmListDesc.GetDataPtr<Element>(0) + ctx.group_loop_i * ctx.problem_shape_n);
        } else {
            gmScale.SetGlobalBuffer(gmListDesc.GetDataPtr<Element>(ctx.group_loop_i));
        }

        auto layoutScale = layout;
        auto gmTileScale = gmScale[layoutScale.GetOffset(scaleTileOffset)];
        auto layoutGmTileScale = layoutScale.GetTileLayout(scaleTileShape);
        auto layoutUbScale = Layout::template MakeLayoutInUb<Element>(scaleTileShape);

        CopyGm2Ub{}(ubTile, gmTileScale, layoutUbScale, layoutGmTileScale);
    }

public:
    GM_ADDR gm;
    Layout layout;
};

template <typename GmType, uint32_t BUFFER_NUM>
struct GmPerTokenScaleReader
{
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    static constexpr pipe_t SRC_PIPE = PIPE_MTE2;

    CATLASS_DEVICE
    opx::QueUsageInfo GetQueUsage(const MatrixCoord& tile_shape)
    {
        return { BUFFER_NUM, tile_shape.row() * (uint32_t)sizeof(Element) };
    }

    CATLASS_DEVICE
    void DoCopy(const opx::MatrixDataContext& ctx, const AscendC::LocalTensor<Element>& ubTile)
    {
        using CopyGm2Ub = Epilogue::Tile::CopyGm2Ub<
            Arch::AtlasA2, Gemm::GemmType<Element, Layout>>;

        auto perTokenScaleTileOffset = ctx.tile_offset.template GetCoordByAxis<0>();
        auto perTokenScaleTileShape = ctx.actual_tile_shape.template GetCoordByAxis<0>();

        auto gmPerTokenScale = gm[ctx.group_m_sum];
        auto layoutPerTokenScale = layout;
        auto gmTilePerTokenScale = gmPerTokenScale[layoutPerTokenScale.GetOffset(perTokenScaleTileOffset)];
        auto layoutGmTileScale = layoutPerTokenScale.GetTileLayout(perTokenScaleTileShape);
        auto layoutUbPerTokenScale = Layout::template MakeLayoutInUb<Element>(perTokenScaleTileShape);

        CopyGm2Ub{}(ubTile, gmTilePerTokenScale, layoutUbPerTokenScale, layoutGmTileScale);
    }

public:
    AscendC::GlobalTensor<Element> gm;
    Layout layout;
};

template <typename GmType, uint32_t BUFFER_NUM>
struct GmSwigluOutputWriter
{
    using Element = typename GmType::Element;
    using Layout = typename GmType::Layout;

    static constexpr pipe_t DST_PIPE = PIPE_MTE3;

    CATLASS_DEVICE
    opx::QueUsageInfo GetQueUsage(const MatrixCoord& tile_shape)
    {
        return {
            BUFFER_NUM,
            // Swiglu only output a half of N, so div 2
            tile_shape.row() * tile_shape.column() / 2U * (uint32_t)sizeof(Element)
        };
    }

    CATLASS_DEVICE
    void DoCopy(const opx::MatrixDataContext& ctx, const AscendC::LocalTensor<Element>& ubTile)
    {
        using CopyUb2Gm = Epilogue::Tile::CopyUb2Gm<
            Arch::AtlasA2, Gemm::GemmType<Element, Layout>>;

        auto actualChunkTileShape = MakeCoord(ctx.actual_tile_shape.row(), ctx.actual_tile_shape.column() >> 1);
        auto chunkTileOffset = MakeCoord(ctx.tile_offset.row(), ctx.tile_offset.column() >> 1);

        auto gmD = gm[ctx.group_m_sum * ctx.problem_shape_n / 2];
        auto gmTileD = gmD[layout.GetOffset(chunkTileOffset)];
        auto layoutGmTileD = layout.GetTileLayout(actualChunkTileShape);
        auto layoutUbD = Layout::template MakeLayoutInUb<Element>(actualChunkTileShape);

        CopyUb2Gm{}(gmTileD, ubTile, layoutGmTileD, layoutUbD);
    }

public:
    AscendC::GlobalTensor<Element> gm;
    Layout layout;
};

} // end namespace LibOps
