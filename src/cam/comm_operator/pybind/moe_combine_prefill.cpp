/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_combine_prefill pybind extention file
 * Create: 2026-01-08
 * Note:
 * History: 2026-01-08 create moe_combine_prefill pybind extention file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include "utils.h"
#include <hccl/hccl.h>
#include <iostream>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

at::Tensor MoeCombinePrefillImplNpu(
    const at::Tensor& x,
    const at::Tensor& topkIdx,
    const at::Tensor& topkWeights,
    const at::Tensor& srcIdx,
    const at::Tensor& sendHead,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks)
{
    std::vector<char> groupEpChrs(groupEp.begin(), groupEp.end());
    groupEpChrs.push_back('\0');
    char* groupEpPtr = &groupEpChrs[0];

    TORCH_BIND_ASSERT(x.dim() == 2 and x.is_contiguous());
    at::Tensor recvX = x;
    at::Tensor topkIdxP = topkIdx;
    at::Tensor tokenSrcInfo = srcIdx;
    at::Tensor epSendCounts = sendHead;
    auto device = x.device();

    int64_t hidden = static_cast<int>(recvX.size(1));
    at::Tensor tpSendCounts = at::empty({1}, at::dtype(at::kInt).device(device));
    int64_t tpWorldSize = 1;
    int64_t tpRankId = 0;
    int64_t moeExpertNumber = sendHead.size(0);
    int64_t globalBs = topkIdxP.size(0) * numRanks;

    // Combine data
    auto combinedX = torch::empty({topkWeights.size(0), hidden}, x.options());

    EXEC_NPU_CMD(aclnnMoeCombineNormal,
        recvX,
        tokenSrcInfo,
        epSendCounts,
        topkWeights,
        tpSendCounts,
        groupEpPtr,
        numRanks,
        rank,
        groupEpPtr,
        tpWorldSize,
        tpRankId,
        moeExpertNumber,
        globalBs,
        combinedX);

    return combinedX;
}

TensorVector MoeCombinePrefillBackwardImplNpu(const at::Tensor &self)
{
    return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
}

at::Tensor MoeCombinePrefillImpl(
    const at::Tensor& x,
    const at::Tensor& topkIdx,
    const at::Tensor& topkWeights,
    const at::Tensor& srcIdx,
    const at::Tensor& sendHead,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::moe_combine_prefill", "")
                        .typed<decltype(MoeCombinePrefillImpl)>();
    return op.call(x, topkIdx, topkWeights, srcIdx, sendHead, groupEp, rank, numRanks);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class ExtMoeCombinePrefill : public torch::autograd::Function<ExtMoeCombinePrefill> {
public:
    static at::Tensor forward(
        AutogradContext *ctx, \
        const at::Tensor& x,
        const at::Tensor& topkIdx,
        const at::Tensor& topkWeights,
        const at::Tensor& srcIdx,
        const at::Tensor& sendHead,
        c10::string_view groupEp,
        int64_t rank,
        int64_t numRanks)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeCombinePrefillImpl(x, topkIdx, topkWeights, srcIdx, sendHead, \
            groupEp, rank, numRanks);
        return result;
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

at::Tensor MoeCombinePrefillImplAutograd(
    const at::Tensor& x,
    const at::Tensor& topkIdx,
    const at::Tensor& topkWeights,
    const at::Tensor& srcIdx,
    const at::Tensor& sendHead,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks)
{
    auto result = ExtMoeCombinePrefill::apply(x, topkIdx, topkWeights, srcIdx, sendHead, \
        groupEp, rank, numRanks);
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