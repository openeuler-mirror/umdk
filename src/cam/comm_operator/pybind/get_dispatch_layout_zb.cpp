/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add get_dispatch_layout_zb pybind extension file
 * Create: 2026-07-31
 * Note:
 * History: 2026-07-31 create get_dispatch_layout_zb pybind extension file
 */

#include <iostream>
#include <unistd.h>

#include <torch/csrc/autograd/custom_function.h>
#include <torch/extension.h>

#include "pytorch_npu_helper.hpp"
#include "torch_bind_exception.h"
#include "zb_shmem_utils.h"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

namespace {
const int LOCAL_RANK_SIZE = 8;
const int MAX_BATCH_SIZE = 4096;
const int EXPERT_DATA_SIZE = 1 + MAX_BATCH_SIZE;  // 4097
const uint32_t DIM_TWO = 2;
const uint32_t ZERO = 0;
const uint32_t FIRST = 1;
}  // namespace

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutZbImplNpu(const at::Tensor &topkIdx, int64_t numExperts,
    int64_t numRanks)
{
    // Align with dispatch/combine ZB: topk_idx is int32 (expert ids fit in int32).
    at::Tensor topkIdxInt32 = topkIdx.scalar_type() == at::kInt ? topkIdx : topkIdx.to(at::kInt);

    TORCH_BIND_ASSERT(topkIdxInt32.dim() == DIM_TWO);
    TORCH_BIND_ASSERT(topkIdxInt32.is_contiguous());
    TORCH_BIND_ASSERT(numExperts > 0);

    const int numTokens = topkIdxInt32.size(0);
    const int numTopk = topkIdxInt32.size(1);
    const int localRanksize = LOCAL_RANK_SIZE;
    auto serverNum = numRanks / localRanksize;

    auto device = topkIdxInt32.device();
    // notify AllGather uses shmem_ptr(numTokensPerExpert); allocate on SHMEM directly.
    auto numTokensPerExpert = cam_zb::CreateTensorFromShmem({numExperts}, at::kInt, device);
    numTokensPerExpert.zero_();
    auto numTokensPerRank = at::zeros({numRanks}, at::dtype(at::kInt).device(device));
    auto isTokenInRank = at::zeros({numTokens, numRanks}, at::dtype(at::kInt).device(device));
    const int notifySendDataSize =
        numExperts * EXPERT_DATA_SIZE + serverNum + MAX_BATCH_SIZE * (1 + 2 * serverNum + numExperts);
    auto sendTokenIdx = at::zeros({numTokens, numTopk}, at::dtype(at::kInt).device(device));
    auto notifySendData = at::zeros({notifySendDataSize}, at::dtype(at::kInt).device(device));
    EXEC_NPU_CMD(aclnnDispatchLayoutZb, topkIdxInt32, numTokens, numRanks, numExperts, numTopk, localRanksize,
        numTokensPerRank, numTokensPerExpert, isTokenInRank, notifySendData, sendTokenIdx);

    return std::make_tuple(numTokensPerExpert, sendTokenIdx);
}

TensorVector GetDispatchLayoutZbBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);
    return {result, result};
}

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutZbImpl(const at::Tensor &topkIdx, int64_t numExperts,
    int64_t numRanks)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::get_dispatch_layout_zb", "")
                         .typed<decltype(GetDispatchLayoutZbImpl)>();
    return op.call(topkIdx, numExperts, numRanks);
}

class GetDispatchLayoutZb : public torch::autograd::Function<GetDispatchLayoutZb> {
public:
    static TensorVector forward(AutogradContext *ctx, const at::Tensor &topkIdx, int64_t numExperts, int64_t numRanks)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = GetDispatchLayoutZbImpl(topkIdx, numExperts, numRanks);
        return {std::get<0>(result), std::get<1>(result)};
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector gradOutputs)
    {
        return {at::Tensor(), at::Tensor()};
    }
};

std::tuple<at::Tensor, at::Tensor> GetDispatchLayoutZbImplAutograd(const at::Tensor &topkIdx, int64_t numExperts,
    int64_t numRanks)
{
    auto result = GetDispatchLayoutZb::apply(topkIdx, numExperts, numRanks);
    return std::make_tuple(result[ZERO], result[FIRST]);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("get_dispatch_layout_zb", &GetDispatchLayoutZbImplNpu);
    m.impl("get_dispatch_layout_zb_backward", &GetDispatchLayoutZbBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("get_dispatch_layout_zb", &GetDispatchLayoutZbImplAutograd);
}
