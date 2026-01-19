/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add get_dispatch_layout pybind extention file
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 create get_dispatch_layout pybind extention file
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
const int LOCAL_RANK_SIZE = 8;
const int MAX_BATCH_SIZE = 4096;
const int EXPERT_DATA_SIZE = 1 + MAX_BATCH_SIZE; // 4097
const uint32_t DIM_TWO = 2;
const uint32_t ZERO = 0;
const uint32_t FIRST = 1;
} // namespace

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutImplNpu(const at::Tensor &topkIdx, int64_t numExperts,
                                                            int64_t numRanks)
{
    // Convert topk_idx to int64 if necessary
    at::Tensor topkIdxInt64 = topkIdx.scalar_type() == at::kLong ? topkIdx : topkIdx.to(at::kLong);

    TORCH_BIND_ASSERT(topkIdxInt64.dim() == DIM_TWO);
    TORCH_BIND_ASSERT(topkIdxInt64.is_contiguous());
    TORCH_BIND_ASSERT(numExperts > 0);

    const int numTokens = topkIdxInt64.size(0);
    const int numTopk = topkIdxInt64.size(1);
    const int localRanksize = LOCAL_RANK_SIZE;
    auto serverNum = numRanks / localRanksize;

    auto device = topkIdxInt64.device();
    auto numTokensPerExpert = at::zeros({numExperts}, at::dtype(at::kInt).device(device));
    auto numTokensPerRank = at::zeros({numRanks}, at::dtype(at::kInt).device(device));
    auto isTokenInRank = at::zeros({numTokens, numRanks}, at::dtype(at::kInt).device(device));
    const int notifySendDataSize =
        numExperts * EXPERT_DATA_SIZE + serverNum + MAX_BATCH_SIZE * (1 + 2 * serverNum + numExperts);
    auto sendTokenIdxSmall = at::zeros({numTokens, numTopk}, at::dtype(at::kInt).device(device));
    auto notifySendData = at::zeros({notifySendDataSize}, at::dtype(at::kInt).device(device));
    EXEC_NPU_CMD(aclnnDispatchLayout, topkIdxInt64, numTokens, numRanks, numExperts, numTopk, localRanksize,
                 numTokensPerRank, numTokensPerExpert, isTokenInRank, notifySendData, sendTokenIdxSmall);

    return std::make_tuple(numTokensPerExpert, sendTokenIdxSmall);
}

TensorVector GetDispatchLayoutBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // 创建输出内存
    return {result, result};
}

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutImpl(const at::Tensor &topkIdx, int64_t numExperts,
                                                         int64_t numRanks)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::get_dispatch_layout", "")
                         .typed<decltype(GetDispatchLayoutImpl)>();
    return op.call(topkIdx, numExperts, numRanks);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class GetDispatchLayout : public torch::autograd::Function<GetDispatchLayout> {
public:
    static TensorVector forward(AutogradContext *ctx, const at::Tensor &topkIdx, int64_t numExperts, int64_t numRanks)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = GetDispatchLayoutImpl(topkIdx, numExperts, numRanks);

        return {std::get<0>(result), std::get<1>(result)};
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector gradOutputs)
    {
        return {at::Tensor(), at::Tensor()};
    }
};

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutImplAutograd(const at::Tensor &topkIdx, int64_t numExperts,
                                                                 int64_t numRanks)
{
    auto result = GetDispatchLayout::apply(topkIdx, numExperts, numRanks);
    return std::make_tuple(result[ZERO], result[FIRST]);
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