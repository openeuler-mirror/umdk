/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_combine_prefill pybind extention file
 * Create: 2026-01-08
 * Note:
 * History: 2026-01-08 create moe_combine_prefill pybind extention file
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
} // namespace

at::Tensor MoeCombinePrefillImplNpu(const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &topkWeights,
                                    const at::Tensor &srcIdx, const at::Tensor &sendHead, c10::string_view groupEp,
                                    int64_t rank, int64_t numRanks)
{
    const std::string groupEpStr(groupEp.data(), groupEp.size());
    const char* groupEpPtr = groupEpStr.c_str();

    TORCH_BIND_ASSERT(x.dim() == DIM_TWO and x.is_contiguous());

    // Convert topkIdx to int32 if necessary
    at::Tensor topkIdxInt32 = topkIdx.scalar_type() == at::kInt ? topkIdx : topkIdx.to(at::kInt);
    at::Tensor tokenSrcInfo = srcIdx;
    at::Tensor epSendCounts = sendHead;
    auto device = x.device();

    // Convert topkWeights to float if necessary
    at::Tensor expertScales = topkWeights.scalar_type() == at::kFloat ? topkWeights : topkWeights.to(at::kFloat);

    int64_t hidden = static_cast<int>(x.size(1));
    at::Tensor tpSendCounts = at::empty({1}, at::dtype(at::kInt).device(device));
    int64_t tpWorldSize = 1;
    int64_t tpRankId = 0;
    int64_t moeExpertNumber = sendHead.size(0);
    int64_t globalBs = topkIdxInt32.size(0) * numRanks;

    // Create combineSendCostStatsOut tensor (optional output for performance monitoring)
    at::Tensor combineSendCostStatsOut;

    // Combine data
    auto combinedX = torch::empty({expertScales.size(0), hidden}, x.options());

    EXEC_NPU_CMD(aclnnMoeCombineNormal, x, tokenSrcInfo, epSendCounts, expertScales, tpSendCounts, groupEpPtr, numRanks,
                 rank, groupEpPtr, tpWorldSize, tpRankId, moeExpertNumber, globalBs, combinedX,
                 combineSendCostStatsOut);

    return combinedX;
}

TensorVector MoeCombinePrefillBackwardImplNpu(const at::Tensor &self)
{
    return {at::Tensor()};
}

at::Tensor MoeCombinePrefillImpl(const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &topkWeights,
                                 const at::Tensor &srcIdx, const at::Tensor &sendHead, c10::string_view groupEp,
                                 int64_t rank, int64_t numRanks)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_combine_prefill", "")
                         .typed<decltype(MoeCombinePrefillImpl)>();
    return op.call(x, topkIdx, topkWeights, srcIdx, sendHead, groupEp, rank, numRanks);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class MoeCombinePrefill : public torch::autograd::Function<MoeCombinePrefill> {
public:
    static at::Tensor forward(AutogradContext *ctx, const at::Tensor &x, const at::Tensor &topkIdx,
                              const at::Tensor &topkWeights, const at::Tensor &srcIdx, const at::Tensor &sendHead,
                              c10::string_view groupEp, int64_t rank, int64_t numRanks)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeCombinePrefillImpl(x, topkIdx, topkWeights, srcIdx, sendHead, groupEp, rank, numRanks);
        return result;
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector gradOutputs)
    {
        return {at::Tensor()};
    }
};

at::Tensor MoeCombinePrefillImplAutograd(const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &topkWeights,
                                         const at::Tensor &srcIdx, const at::Tensor &sendHead, c10::string_view groupEp,
                                         int64_t rank, int64_t numRanks)
{
    auto result = MoeCombinePrefill::apply(x, topkIdx, topkWeights, srcIdx, sendHead, groupEp, rank, numRanks);
    return result;
}

// moe_combine_prefill
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_combine_prefill", &MoeCombinePrefillImplNpu);
    m.impl("moe_combine_prefill_backward", &MoeCombinePrefillBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_combine_prefill", &MoeCombinePrefillImplAutograd);
}