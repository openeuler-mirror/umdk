/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_dispatch_prefill pybind extention file
 * Create: 2026-01-08
 * Note:
 * History: 2026-01-08 create moe_dispatch_prefill pybind extention file
 */

#include "pytorch_npu_helper.hpp"
#include "torch_bind_exception.h"
#include <hccl/hccl.h>
#include <iostream>
#include <torch/csrc/autograd/custom_function.h>
#include <torch/extension.h>
#include <unistd.h>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

namespace {
const uint32_t DIM_TWO = 2;
const uint32_t NO_SCALES = 0;
const uint32_t DYNAMIC_SCALES = 2;
const uint32_t EXPAND_IDX_COUNT_PER_GROUP = 3;
const uint32_t ZERO = 0;
const uint32_t FIRST = 1;
const uint32_t SECOND = 2;
const uint32_t THIRD = 3;
const uint32_t FOURTH = 4;
} // namespace

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillImplNpu(
    const at::Tensor &x,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &numTokensPerExpert,
    const at::Tensor &sendTokenIdxSmall,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks,
    bool useQuant)
{
    const std::string groupEpStr(groupEp.data(), groupEp.size());
    const char* groupEpPtr = groupEpStr.c_str();

    // Convert topkIdx to int32 if necessary
    at::Tensor topkIdxInt32 = topkIdx.scalar_type() == at::kInt ? topkIdx : topkIdx.to(at::kInt);
    at::Tensor expertIds = topkIdxInt32;
    int64_t tpSize = 1;
    int64_t tpRank = 0;
    int64_t quantMode = useQuant ? DYNAMIC_SCALES : NO_SCALES;

    // Type checks
    TORCH_BIND_ASSERT(numTokensPerExpert.scalar_type() == at::kInt);

    // Shape and contiguous checks
    TORCH_BIND_ASSERT(x.dim() == DIM_TWO and x.is_contiguous());
    TORCH_BIND_ASSERT(numTokensPerExpert.dim() == 1 and numTokensPerExpert.is_contiguous());
    TORCH_BIND_ASSERT(numTokensPerExpert.size(0) % numRanks == 0);

    auto numTokens = static_cast<int>(x.size(0));
    auto hidden = static_cast<int>(x.size(1));
    auto numExperts = static_cast<int64_t>(numTokensPerExpert.size(0));
    auto numLocalExperts = static_cast<int>(numExperts / numRanks);

    // Top-k checks
    int numTopk = static_cast<int>(topkIdxInt32.size(1));
    TORCH_BIND_ASSERT(numExperts > 0);
    TORCH_BIND_ASSERT(topkIdxInt32.dim() == DIM_TWO and topkIdxInt32.is_contiguous());
    TORCH_BIND_ASSERT(topkWeights.dim() == DIM_TWO and topkWeights.is_contiguous());
    TORCH_BIND_ASSERT(numTokens == topkIdxInt32.size(0));
    TORCH_BIND_ASSERT(numTopk == topkWeights.size(1));

    int sendPerGroup = EXPAND_IDX_COUNT_PER_GROUP; // (send_to_expert_num, send_to_expert_offset, send_rank_tokens)

    auto sendData = torch::empty({numExperts * sendPerGroup}, at::dtype(at::kInt).device(x.device()));
    int64_t sendCount = sendPerGroup * numLocalExperts * numRanks;

    auto sendDataOffset = torch::empty({numExperts}, at::dtype(at::kInt).device(x.device()));
    at::Tensor recvData = torch::empty({numExperts * sendPerGroup}, at::dtype(at::kInt).device(x.device()));
    at::Tensor totalRecvToken = torch::empty({1}, at::dtype(at::kInt).device(x.device()));
    at::Tensor recvCount = torch::empty({numExperts}, at::dtype(at::kInt).device(x.device()));
    at::Tensor recvOffset = torch::empty({numExperts}, at::dtype(at::kInt).device(x.device()));
    at::Tensor maxBs = torch::empty({1}, at::dtype(at::kInt).device(x.device()));
    at::Tensor recvTokensPerExpert = torch::empty({numLocalExperts}, at::dtype(at::kLong).device(x.device()));

    int64_t localRankSize = numRanks;
    int64_t localRankId = rank % localRankSize;

    at::Tensor dispatchWaitRecvCostStatsOut;

    EXEC_NPU_CMD(aclnnNotifyDispatch, sendData, numTokensPerExpert, sendCount, numTokens,
                 groupEpPtr, // commGroup
                 numRanks,   // rankSize
                 rank,       // rankId
                 localRankSize, localRankId, sendDataOffset, recvData, totalRecvToken, recvCount, recvOffset, maxBs,
                 recvTokensPerExpert);

    int64_t gBs = maxBs.item<int>() * numRanks;
    int64_t trt = totalRecvToken.item<int>();
    int numRecvTokens = (trt == 0) ? 1 : trt;
    auto expandxOut = useQuant ? torch::empty({numRecvTokens, hidden}, at::dtype(at::kChar).device(x.device()))
                               : torch::empty({numRecvTokens, hidden}, x.options());
    auto dynamicScalesOut = torch::empty({numRecvTokens}, at::dtype(at::kFloat).device(x.device()));
    auto expandIdxOut = torch::empty({numRecvTokens * 3}, at::dtype(at::kInt).device(x.device()));

    EXEC_NPU_CMD(aclnnMoeDispatchNormal, x, expertIds, sendDataOffset, sendTokenIdxSmall, recvOffset, recvCount,
                 groupEpPtr,
                 numRanks, // rankSize
                 rank,     // rankId
                 groupEpPtr, tpSize, tpRank, numExperts, quantMode, gBs, expandxOut, dynamicScalesOut, expandIdxOut,
                 dispatchWaitRecvCostStatsOut);

    // Return values
    return {expandxOut, dynamicScalesOut, expandIdxOut, recvCount, recvTokensPerExpert};
}

TensorVector MoeDispatchPrefillBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // 创建输出内存
    return {result, result, result, result, result};
}

/* Normal类算子形状无法提前推导，不支持meta设备注册不支持GE使用 */
std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillImpl(
    const at::Tensor &x,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &numTokensPerExpert,
    const at::Tensor &sendTokenIdxSmall,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks,
    bool useQuant)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_dispatch_prefill", "")
                         .typed<decltype(MoeDispatchPrefillImpl)>();
    return op.call(x, topkIdx, topkWeights, numTokensPerExpert, sendTokenIdxSmall, groupEp, rank, numRanks, useQuant);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class MoeDispatchPrefill : public torch::autograd::Function<MoeDispatchPrefill> {
public:
    static TensorVector forward(AutogradContext *ctx, const at::Tensor &x, const at::Tensor &topkIdx,
                                const at::Tensor &topkWeights, const at::Tensor &numTokensPerExpert,
                                const at::Tensor &sendTokenIdxSmall, c10::string_view groupEp, int64_t rank,
                                int64_t numRanks, bool useQuant)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeDispatchPrefillImpl(x, topkIdx, topkWeights, numTokensPerExpert, sendTokenIdxSmall, groupEp,
                                             rank, numRanks, useQuant);

        return {std::get<0>(result), std::get<1>(result), std::get<2>(result), std::get<3>(result),
                std::get<4>(result)};
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector gradOutputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillImplAutograd(
    const at::Tensor &x,
    const at::Tensor &topkIdx,
    const at::Tensor &topkWeights,
    const at::Tensor &numTokensPerExpert,
    const at::Tensor &sendTokenIdxSmall,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks,
    bool useQuant)
{
    auto result = MoeDispatchPrefill::apply(x, topkIdx, topkWeights, numTokensPerExpert, sendTokenIdxSmall, groupEp,
                                            rank, numRanks, useQuant);
    return std::make_tuple(result[ZERO], result[FIRST], result[SECOND], result[THIRD], result[FOURTH]);
}

// moe_dispatch_prefill
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_dispatch_prefill", &MoeDispatchPrefillImplNpu);
    m.impl("moe_dispatch_prefill_backward", &MoeDispatchPrefillBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_dispatch_prefill", &MoeDispatchPrefillImplAutograd);
}