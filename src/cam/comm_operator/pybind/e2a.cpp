/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add e2a pybind extention file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create e2a pybind extention file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include <iostream>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

at::Tensor E2aImplNpu(
    const at::Tensor &expandX, \
    const at::Tensor &attenBatchSize, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum)
{
    int32_t baseBatchSize = (rank >= expertRankSize) ? expandX.sizes()[0] : batchSize;
    
    at::Tensor xOut;
    if (rank < expertRankSize) {
        xOut = at::empty({1, 1}, expandX.options().dtype(at::kBFloat16));
    } else {
        xOut = at::empty({baseBatchSize, hiddenSize}, expandX.options().dtype(at::kBFloat16));
    }

    vector<char> groupEpChars(groupEp.begin(), groupEp.end());
    groupEpChars.push_back('\0');
    char *groupEpPtr = &groupEpChars[0];
    EXEC_NPU_CMD(aclnnE2a,
        // input
        expandX, attenBatchSize, \
        // attr
        baseBatchSize, hiddenSize, topk, expertRankSize, attentionRankSize, rank, \
        groupEpPtr, aivNum, \
        // output
        xOut);

    return xOut;
}

TensorVector E2aBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // Create output memory
    return {result, result, result};
}

at::Tensor E2aImplMeta(
    const at::Tensor &expandX, \
    const at::Tensor &attenBatchSize, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum)
{
    int32_t baseBatchSize = batchSize;
    if (rank >= expertRankSize) {
        baseBatchSize = expandX.sizes()[0];
    }
    
    at::Tensor xOut;
    if (rank < expertRankSize) {
        xOut = at::empty({1, 1}, expandX.options().dtype(at::kBFloat16));
    } else {
        xOut = at::empty({baseBatchSize, hiddenSize}, expandX.options().dtype(at::kBFloat16));
    }
    return xOut;
}

at::Tensor E2aImpl(
    const at::Tensor &expandX, \
    const at::Tensor &attenBatchSize, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::e2a", "")
                        .typed<decltype(E2aImpl)>();
    return op.call(expandX, attenBatchSize, batchSize, hiddenSize, topk, \
        expertRankSize, attentionRankSize, rank, groupEp, aivNum);
}

// Bind forward and backward computations by inheriting the torch::autograd::Function class.
class E2a : public torch::autograd::Function<E2a> {
public:
    static at::Tensor forward(
        AutogradContext *ctx, \
        const at::Tensor &expandX, \
        const at::Tensor &attenBatchSize, \
        int64_t batchSize, \
        int64_t hiddenSize, \
        int64_t topk, \
        int64_t expertRankSize, \
        int64_t attentionRankSize, \
        int64_t rank, \
        c10::string_view groupEp, \
        int64_t aivNum)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = E2aImpl(expandX, attenBatchSize, batchSize, hiddenSize, topk, \
        expertRankSize, attentionRankSize, rank, groupEp, aivNum);

        return result;
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

at::Tensor E2aImplAutograd(
    const at::Tensor &expandX, \
    const at::Tensor &attenBatchSize, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum)
{
    auto result = E2a::apply(expandX, attenBatchSize, batchSize, hiddenSize, topk, \
        expertRankSize, attentionRankSize, rank, groupEp, aivNum);
    return result;
}

// e2a
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("e2a", &E2aImplNpu);
    m.impl("e2a_backward", &E2aBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("e2a", &E2aImplAutograd);
}

// Register the forward and backward implementation for Meta devices.
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("e2a", &E2aImplMeta);
}