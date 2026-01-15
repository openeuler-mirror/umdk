/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add get_dispatch_layout pybind extention file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create get_dispatch_layout pybind extention file
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

std::tuple<at::Tensor, at::Tensor, at::Tensor> GetDispatchLayoutImplNpu(
    const at::Tensor& topkIdx,
    int64_t numExperts,
    int64_t numRanks)
{
    TORCH_BIND_ASSERT(topkIdx.dim() == 2);
    TORCH_BIND_ASSERT(topkIdx.is_contiguous());
    TORCH_BIND_ASSERT(numExperts > 0);

    const int numTokens = topkIdx.size(0);
    const int numTopk = topkIdx.size(1);

    auto device = topkIdx.device();
    auto numTokensPerExpert = at::zeros({numExperts}, at::dtype(at::kInt).device(device));
    auto numTokensPerRank = at::zeros({numRanks}, at::dtype(at::kInt).device(device));
    auto isTokenInRank = at::zeros({numTokens, numRanks}, at::dtype(at::kInt).device(device));

    EXEC_NPU_CMD(aclnnDispatchLayout,
        topkIdx,
        numTokens,
        numRanks,
        numExperts,
        numTopk,
        numTokensPerRank,
        numTokensPerExpert,
        isTokenInRank);

    auto isTokenInRank_bool = isTokenInRank.to(at::kBool);

    return std::make_tuple(numTokensPerRank, numTokensPerExpert, isTokenInRank_bool);
}

TensorVector GetDispatchLayoutBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // 创建输出内存
    return {result, result, result};
}

std::tuple<at::Tensor, at::Tensor, at::Tensor> GetDispatchLayoutImpl(
    const at::Tensor& topkIdx,
    int64_t numExperts,
    int64_t numRanks)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::get_dispatch_layout", "")
                        .typed<decltype(GetDispatchLayoutImpl)>();
    return op.call(topkIdx, numExperts, numRanks);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class ExtGetDispatchLayout : public torch::autograd::Function<ExtGetDispatchLayout> {
public:
    static TensorVector forward(
        AutogradContext *ctx, \
        const at::Tensor& topkIdx,
        int64_t numExperts,
        int64_t numRanks)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = GetDispatchLayoutImpl(topkIdx, numExperts, numRanks);

        return {std::get<0>(result), std::get<1>(result), std::get<2>(result)};
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

std::tuple<at::Tensor, at::Tensor, at::Tensor> GetDispatchLayoutImplAutograd(
    const at::Tensor& topkIdx,
    int64_t numExperts,
    int64_t numRanks)
{
    auto result = ExtGetDispatchLayout::apply(topkIdx, numExperts, numRanks);
    return std::make_tuple(result[0], result[1], result[2]);
}

// get_dispatch_layout
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("get_dispatch_layout", &GetDispatchLayoutImplNpu);
    m.impl("get_dispatch_layout_backward", &GetDispatchLayoutBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("get_dispatch_layout", &GetDispatchLayoutImplAutograd);
}