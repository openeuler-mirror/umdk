/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: cam_moe_distribute_combine_send function device header file
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#ifndef CAM_MOE_DISTRIBUTE_COMBINE_SEND_H
#define CAM_MOE_DISTRIBUTE_COMBINE_SEND_H
#define OPT_RANK_OFFSET 512

#include "kernel_operator.h"
#include "kernel_tiling/kernel_tiling.h"
#include "cam_moe_distribute_combine_send_tiling.h"
#include "comm_args.h"

namespace MoeDistributeCombineSendImpl {
constexpr uint64_t CAM_MAX_RANK_SIZE = 384;  // max NPUs supported by the Cam comm library
constexpr uint32_t UB_ALIGN = 32;            // UB aligned to 32 bytes
constexpr uint32_t MAX_AIV_NUM = 48;         // max AIV core count
constexpr uint32_t INFO_NUM = 5;  // number of valid batch-info fields; also start/end expert per chunk

template <AscendC::HardEvent event>
__aicore__ inline void SyncFunc()
{
    int32_t eventID = static_cast<int32_t>(GetTPipePtr()->FetchEventID(event));
    AscendC::SetFlag<event>(eventID);
    AscendC::WaitFlag<event>(eventID);
}

#define TemplateMC2TypeClass typename ExpandXType
#define TemplateMC2TypeFunc ExpandXType
using namespace AscendC;
using namespace Cam;
template <TemplateMC2TypeClass>
class CamMoeDistributeCombineSend {
public:
    __aicore__ inline CamMoeDistributeCombineSend(){};
    __aicore__ inline void Init(GM_ADDR expandX, GM_ADDR expandXShared, GM_ADDR workspaceGM, TPipe *pipe,
        const CamMoeDistributeCombineSendTilingData *tilingData, GM_ADDR commArgs, GM_ADDR batchInfo,
        int32_t isCamComm);
    __aicore__ inline void Process();

private:
    __aicore__ inline uint32_t MathCeil(uint32_t n, uint32_t align)
    {
        return align * (n / align + (n % align == 0 ? 0 : 1));
    }

    __aicore__ inline GM_ADDR GetPeerAddrByRankId(const int32_t rankId)
    {
        return (GM_ADDR)peerMemsAddrGMTensor_.GetValue(rankId);
    }

    __aicore__ inline void CombineSend();
    __aicore__ inline void CombineSendShared();

    uint32_t aivId_{0};
    uint32_t aivNum_{0};
    uint32_t moeRankId_{0};
    uint32_t worldSize_{0};
    uint32_t attnRankNum_{0};
    uint32_t moeRankNum_{0};
    uint32_t sharedExpertNumPerMoe_{0};
    uint32_t routeExpertNumPerMoe_{0};
    uint32_t expertNumPerMoe_{0};
    uint32_t expertNum_{0};
    uint32_t batchSize_{0};
    uint32_t hiddenSize_{0};
    uint32_t topk_{0};
    uint64_t totalUbSize_{0};
    uint64_t totalWorkspaceSize_{0};
    uint64_t dispatchOffset_{0};
    uint16_t tpSize_{0};

    GlobalTensor<ExpandXType> xGMTensor_;
    GlobalTensor<ExpandXType> xSharedGMTensor_;
    GlobalTensor<int64_t> batchInfoGMTensor_;
    GlobalTensor<GM_ADDR> peerMemsAddrGMTensor_;

    uint64_t ubReuseSize_{0};
    uint32_t maxUbTokenNum_{0};

    TPipe *tpipe_{nullptr};
    TBuf<> ubBuffer_;
    LocalTensor<uint32_t> tpExpertTokenNumTensor_;
    LocalTensor<uint32_t> tpExpertTokenSendCntTensor_;
    LocalTensor<uint32_t> moePrefixTokenNumTensor_;
    LocalTensor<int64_t>  tpBatchInfoTensor_;
    LocalTensor<ExpandXType> xTensor_;

    bool isError_{false};
};

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombineSend<TemplateMC2TypeFunc>::Init(GM_ADDR expandX, GM_ADDR expandXShared,
    GM_ADDR workspaceGM, TPipe *pipe, const CamMoeDistributeCombineSendTilingData *tilingData, GM_ADDR commArgs,
    GM_ADDR batchInfo, int32_t isCamComm)
{
    aivId_ = GetBlockIdx();
    aivNum_ = tilingData->moeDistributeCombineInfo.aivNum;
    moeRankId_ = tilingData->moeDistributeCombineInfo.moeRankId;
    worldSize_ = tilingData->moeDistributeCombineInfo.worldSize;
    attnRankNum_ = tilingData->moeDistributeCombineInfo.attnRankNum;
    moeRankNum_ = tilingData->moeDistributeCombineInfo.moeRankNum;
    sharedExpertNumPerMoe_ = 1;
    routeExpertNumPerMoe_ = tilingData->moeDistributeCombineInfo.routeExpertNumPerMoe;
    expertNumPerMoe_ = sharedExpertNumPerMoe_ + routeExpertNumPerMoe_;
    expertNum_ = expertNumPerMoe_ * moeRankNum_;
    batchSize_ = tilingData->moeDistributeCombineInfo.batchSize;
    hiddenSize_ = tilingData->moeDistributeCombineInfo.hiddenSize;
    topk_ = tilingData->moeDistributeCombineInfo.topk;
    totalUbSize_ = tilingData->moeDistributeCombineInfo.totalUbSize;
    totalWorkspaceSize_ = tilingData->moeDistributeCombineInfo.totalWorkspaceSize;
    tpSize_ = tilingData->moeDistributeCombineInfo.tpSize;
    dispatchOffset_ = MathCeil(sizeof(uint32_t) * (moeRankNum_ + expertNum_) * MAX_AIV_NUM, UB_ALIGN);

    xGMTensor_.SetGlobalBuffer((__gm__ ExpandXType*)expandX);
    xSharedGMTensor_.SetGlobalBuffer((__gm__ ExpandXType*)expandXShared);
    batchInfoGMTensor_.SetGlobalBuffer((__gm__ int64_t *)batchInfo);
    peerMemsAddrGMTensor_.SetGlobalBuffer(&((__gm__ Moe::CommArgs *)commArgs)->peerMems[0], CAM_MAX_RANK_SIZE);

    tpipe_ = pipe;
    tpipe_->Reset();
    tpipe_->InitBuffer(ubBuffer_, totalUbSize_);

    uint64_t bufOffset = 0;
    uint64_t bufSize;

    bufSize = MathCeil(sizeof(int64_t) * (INFO_NUM + tpSize_ + expertNumPerMoe_ *  tpSize_), UB_ALIGN);
    tpBatchInfoTensor_ = ubBuffer_.GetWithOffset<int64_t>(bufSize / sizeof(int64_t), bufOffset);
    bufOffset += bufSize;

    bufSize = MathCeil(sizeof(uint32_t) * expertNumPerMoe_ * tpSize_, UB_ALIGN);
    tpExpertTokenNumTensor_ = ubBuffer_.GetWithOffset<uint32_t>(bufSize / sizeof(uint32_t), bufOffset);
    bufOffset += bufSize;

    bufSize = MathCeil(sizeof(uint32_t) * expertNumPerMoe_ * 2, UB_ALIGN);
    tpExpertTokenSendCntTensor_ = ubBuffer_.GetWithOffset<uint32_t>(bufSize / sizeof(uint32_t), bufOffset);
    bufOffset += bufSize;

    if (bufOffset > totalUbSize_) {
        isError_ = true;
        return;
    }

    // remaining reusable UB space
    ubReuseSize_ = totalUbSize_ - bufOffset;

    maxUbTokenNum_ = ubReuseSize_ / (sizeof(ExpandXType) * hiddenSize_);

    bufSize = MathCeil(sizeof(uint32_t) * moeRankNum_, UB_ALIGN);
    moePrefixTokenNumTensor_ = ubBuffer_.GetWithOffset<uint32_t>(bufSize / sizeof(uint32_t), bufOffset);

    bufSize = MathCeil(sizeof(ExpandXType) * hiddenSize_ * maxUbTokenNum_, UB_ALIGN);
    xTensor_ = ubBuffer_.GetWithOffset<ExpandXType>(bufSize / sizeof(ExpandXType), bufOffset);
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombineSend<TemplateMC2TypeFunc>::Process()
{
    if (isError_ == true) {
        return;
    }

    // load batch info: total token num, attn rank, layer index, start/end expert,
    // how many tokens attn i sent to prior moes, and how many tokens each expert in this
    // moe received from each attn
    DataCopyPad(tpBatchInfoTensor_, batchInfoGMTensor_,
        {1U, (uint32_t)(sizeof(int64_t) * (INFO_NUM + tpSize_ + expertNumPerMoe_ * tpSize_)), 0U, 0U, 0U},
        {false, 0U, 0U, 0U});
    SyncFunc<HardEvent::MTE2_S>();
    SyncFunc<HardEvent::S_MTE2>();

    CombineSendShared();
    CombineSend();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombineSend<TemplateMC2TypeFunc>::CombineSendShared()
{
    uint32_t startExpert = tpBatchInfoTensor_(3);
    if (startExpert != 1) {
        return;
    }

    uint32_t tpInfoOffset = INFO_NUM + tpSize_;
    uint32_t totalTokenNum = 0;
    for (uint32_t i = 0; i < tpSize_; ++i) {
        totalTokenNum += tpBatchInfoTensor_(tpInfoOffset + i * expertNumPerMoe_);
    }
    uint32_t tpAttnRankId = tpBatchInfoTensor_(1);

    uint32_t totalTokenNumPerAiv = totalTokenNum / aivNum_;
    uint32_t totalTokenNumPerAivRemain = totalTokenNum % aivNum_;
    uint32_t totalTokenNumPerAivStart = totalTokenNumPerAiv * aivId_;
    if (aivId_ < totalTokenNumPerAivRemain) {
        totalTokenNumPerAiv += 1;
        totalTokenNumPerAivStart += aivId_;
    } else {
        totalTokenNumPerAivStart += totalTokenNumPerAivRemain;
    }
    uint32_t totalTokenNumPerAivEnd = totalTokenNumPerAivStart + totalTokenNumPerAiv;

    Duplicate(tpExpertTokenSendCntTensor_, (uint32_t)0, expertNumPerMoe_ * 2);
    SyncFunc<HardEvent::V_S>();

    uint32_t currSendId = 0;
    uint32_t tpIndex = currSendId % tpSize_;
    // (shared + route) * tpIndex; currSendId skips — e.g. attn1's expert1, then attn2's expert1
    uint32_t expertId = (expertNumPerMoe_ * tpIndex) + (currSendId / tpSize_);
    uint32_t currTokenNumCnt = 0;
    uint32_t nextTokenNumCnt = tpBatchInfoTensor_(tpInfoOffset + expertId);

    GlobalTensor<ExpandXType> dstTokenStoreGM;
    GM_ADDR dstRankWorkspaceGm = GetPeerAddrByRankId(tpAttnRankId + tpIndex) + dispatchOffset_;
    // how many tokens this tpIndex attn sent to prior moes
    uint32_t moePrefixTokenNum = tpBatchInfoTensor_(INFO_NUM + tpIndex);
    uint64_t tokenStoreOffset =
        MathCeil(sizeof(uint32_t) * moeRankNum_, UB_ALIGN) + (sizeof(ExpandXType) * hiddenSize_ * moePrefixTokenNum);
    dstTokenStoreGM.SetGlobalBuffer((__gm__ ExpandXType *)(dstRankWorkspaceGm + tokenStoreOffset));

    for (uint32_t i = 0; i < totalTokenNumPerAivEnd;) {
        if (nextTokenNumCnt <= i) {
            currTokenNumCnt += tpBatchInfoTensor_(tpInfoOffset + expertId);
            ++currSendId;
            tpIndex = currSendId % tpSize_;
            expertId = (expertNumPerMoe_ * tpIndex) + (currSendId / tpSize_);
            nextTokenNumCnt += tpBatchInfoTensor_(tpInfoOffset + expertId);

            dstRankWorkspaceGm = GetPeerAddrByRankId(tpAttnRankId + tpIndex) + dispatchOffset_;
            // how many tokens this tpIndex attn sent to prior moes
            moePrefixTokenNum = tpBatchInfoTensor_(INFO_NUM + tpIndex);
            tokenStoreOffset = MathCeil(sizeof(uint32_t) * moeRankNum_, UB_ALIGN)
                + (sizeof(ExpandXType) * hiddenSize_ * moePrefixTokenNum);
            dstTokenStoreGM.SetGlobalBuffer((__gm__ ExpandXType *)(dstRankWorkspaceGm + tokenStoreOffset));
        }

        if (i < totalTokenNumPerAivStart) {
            uint32_t tokenNum;
            if (nextTokenNumCnt < totalTokenNumPerAivStart) {
                tokenNum = nextTokenNumCnt - i;
            } else {
                tokenNum = totalTokenNumPerAivStart - i;
            }
            tpExpertTokenSendCntTensor_(tpIndex) += tokenNum;
            i += tokenNum;
        } else {
            uint32_t sendTokenNumRemain = totalTokenNumPerAivEnd - i;
            uint32_t expertTokenNumRemain = nextTokenNumCnt - i;
            uint32_t cnt = expertTokenNumRemain < sendTokenNumRemain ? expertTokenNumRemain : sendTokenNumRemain;
            cnt = maxUbTokenNum_ < cnt ? maxUbTokenNum_ : cnt;
            uint32_t moeTokenSendIdx = tpExpertTokenSendCntTensor_(tpIndex);

            // copy input to staging: i is offset, cnt is count
            DataCopy(xTensor_, xSharedGMTensor_[hiddenSize_ * i], hiddenSize_ * cnt);
            SyncFunc<HardEvent::MTE2_S>();
            SyncFunc<HardEvent::S_MTE2>();

            SyncFunc<HardEvent::S_MTE3>();
            // copy staging back to the target rank
            DataCopy(dstTokenStoreGM[hiddenSize_ * moeTokenSendIdx], xTensor_, hiddenSize_ * cnt);
            SyncFunc<HardEvent::MTE3_S>();

            tpExpertTokenSendCntTensor_(tpIndex) += cnt;
            i += cnt;
        }
    }
    SyncAll<true>();
}

template <TemplateMC2TypeClass>
__aicore__ inline void CamMoeDistributeCombineSend<TemplateMC2TypeFunc>::CombineSend()
{
    uint32_t totalTokenNum = 0;
    uint32_t tpAttnRankId = tpBatchInfoTensor_(1);
    uint32_t startExpert = tpBatchInfoTensor_(3);
    uint32_t endExpert = tpBatchInfoTensor_(4);
    uint32_t tpInfoOffset = INFO_NUM + tpSize_;

    for (uint32_t i = 0; i < tpSize_; ++i) {
        for (uint32_t j = startExpert; j <= endExpert; ++j) {
            totalTokenNum += tpBatchInfoTensor_(tpInfoOffset + i * expertNumPerMoe_ + j);
        }
    }

    uint32_t totalTokenNumPerAiv = totalTokenNum / aivNum_;
    uint32_t totalTokenNumPerAivRemain = totalTokenNum % aivNum_;
    uint32_t totalTokenNumPerAivStart = totalTokenNumPerAiv * aivId_;
    if (aivId_ < totalTokenNumPerAivRemain) {
        totalTokenNumPerAiv += 1;
        totalTokenNumPerAivStart += aivId_;
    } else {
        totalTokenNumPerAivStart += totalTokenNumPerAivRemain;
    }
    uint32_t totalTokenNumPerAivEnd = totalTokenNumPerAivStart + totalTokenNumPerAiv;

    Duplicate(tpExpertTokenSendCntTensor_, (uint32_t)0, expertNumPerMoe_ * 2);
    SyncFunc<HardEvent::V_S>();

    for (uint32_t i = 0; i < tpSize_; ++i) {
        for (uint32_t j = 0; j < startExpert; ++j) {
            // across rounds: tokens already sent in prior rounds
            tpExpertTokenSendCntTensor_(i) += tpBatchInfoTensor_(tpInfoOffset + i * expertNumPerMoe_ + j);
        }
    }

    uint32_t currSendId = tpSize_ * startExpert;
    uint32_t tpIndex = currSendId % tpSize_;
    // (shared + route) * tpIndex; currSendId skips — e.g. attn1's expert1, then attn2's expert1
    uint32_t expertId = (expertNumPerMoe_ * tpIndex) + (currSendId / tpSize_);
    uint32_t currTokenNumCnt = 0;
    uint32_t nextTokenNumCnt = tpBatchInfoTensor_(tpInfoOffset + expertId);

    GlobalTensor<ExpandXType> dstTokenStoreGM;
    GM_ADDR dstRankWorkspaceGm = GetPeerAddrByRankId(tpAttnRankId + tpIndex) + dispatchOffset_;
    uint32_t moePrefixTokenNum = tpBatchInfoTensor_(INFO_NUM + tpIndex);
    uint64_t tokenStoreOffset = MathCeil(sizeof(uint32_t) * moeRankNum_, UB_ALIGN)
        + (sizeof(ExpandXType) * hiddenSize_ * moePrefixTokenNum);
    dstTokenStoreGM.SetGlobalBuffer((__gm__ ExpandXType *)(dstRankWorkspaceGm + tokenStoreOffset));

    for (uint32_t i = 0; i < totalTokenNumPerAivEnd;) {
        if (nextTokenNumCnt <= i) {
            currTokenNumCnt += tpBatchInfoTensor_(tpInfoOffset + expertId);
            ++currSendId;
            tpIndex = currSendId % tpSize_;
            expertId = (expertNumPerMoe_ * tpIndex) + (currSendId / tpSize_);
            nextTokenNumCnt += tpBatchInfoTensor_(tpInfoOffset + expertId);

            // target attn rank to write back to
            dstRankWorkspaceGm = GetPeerAddrByRankId(tpAttnRankId + tpIndex) + dispatchOffset_;
            // how many tokens prior moe cards wrote back to this tp index's attn card
            moePrefixTokenNum = tpBatchInfoTensor_(INFO_NUM + tpIndex);
            tokenStoreOffset = MathCeil(sizeof(uint32_t) * moeRankNum_, UB_ALIGN)
                + (sizeof(ExpandXType) * hiddenSize_ * moePrefixTokenNum);
            dstTokenStoreGM.SetGlobalBuffer((__gm__ ExpandXType *)(dstRankWorkspaceGm + tokenStoreOffset));
        }

        if (i < totalTokenNumPerAivStart) {
            uint32_t tokenNum;
            if (nextTokenNumCnt < totalTokenNumPerAivStart) {
                tokenNum = nextTokenNumCnt - i;
            } else {
                tokenNum = totalTokenNumPerAivStart - i;
            }
            tpExpertTokenSendCntTensor_(tpIndex) += tokenNum;
            i += tokenNum;
        } else {
            uint32_t sendTokenNumRemain = totalTokenNumPerAivEnd - i;
            uint32_t expertTokenNumRemain = nextTokenNumCnt - i;
            uint32_t cnt = expertTokenNumRemain < sendTokenNumRemain ? expertTokenNumRemain : sendTokenNumRemain;
            cnt = maxUbTokenNum_ < cnt ? maxUbTokenNum_ : cnt;
            // offset on the original attn rank, computed from the total count
            uint32_t moeTokenSendIdx = tpExpertTokenSendCntTensor_(tpIndex);

            // copy input to UB: i is offset, cnt is count, i is per this chunk
            DataCopy(xTensor_, xGMTensor_[hiddenSize_ * i], hiddenSize_ * cnt);
            SyncFunc<HardEvent::MTE2_S>();
            SyncFunc<HardEvent::S_MTE2>();


            SyncFunc<HardEvent::S_MTE3>();
            // copy UB back to the target rank; moeTokenSendIdx includes the prior chunk offset
            DataCopy(dstTokenStoreGM[hiddenSize_ * moeTokenSendIdx], xTensor_, hiddenSize_ * cnt);
            SyncFunc<HardEvent::MTE3_S>();

            tpExpertTokenSendCntTensor_(tpIndex) += cnt;
            i += cnt;
        }
    }
    SyncAll<true>();

    if (endExpert == expertNumPerMoe_ - 1) {
        for (uint32_t i = 0; i < tpSize_; ++i) {
            if (i % aivNum_ != aivId_) {
                continue;
            }
            // how many tokens tp i sent to prior moes
            uint32_t moePrefixTokenNum = tpBatchInfoTensor_(INFO_NUM + i);
            uint32_t moeSelfRankId = moeRankId_;
            uint32_t dstRankId = tpAttnRankId + i;

            GM_ADDR dstRankWorkspaceGm = GetPeerAddrByRankId(dstRankId) + dispatchOffset_;

            GlobalTensor<uint32_t> tokenStatusGM;
            tokenStatusGM.SetGlobalBuffer((__gm__ uint32_t *)dstRankWorkspaceGm);

            moePrefixTokenNumTensor_(0) = moePrefixTokenNum + 1;
            SyncFunc<HardEvent::S_MTE3>();
            DataCopyPad(tokenStatusGM[(moeSelfRankId - attnRankNum_)], moePrefixTokenNumTensor_,
                {1U, sizeof(uint32_t), 0U, 0U, 0U});
            SyncFunc<HardEvent::MTE3_S>();
        }
    }
}
}  // namespace MoeDistributeCombineSendImpl
#endif // CAM_MOE_DISTRIBUTE_COMBINE_SEND_H
