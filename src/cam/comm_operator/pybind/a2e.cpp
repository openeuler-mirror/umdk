/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add a2e pybind extention file
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 create a2e pybind extention file
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

TensorVector A2eImplNpu(
    const at::Tensor &x, \
    const c10::optional<at::Tensor> &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum,
    int64_t computeGate)
{
    int32_t baseBatchSize = (rank >= expertRankSize) ? x.sizes()[0] : batchSize;

    at::Tensor expandXOut;
    if (rank >= expertRankSize) {
        expandXOut = at::empty({1, 1}, x.options().dtype(at::kBFloat16));
    } else {
        expandXOut = at::empty({baseBatchSize, hiddenSize}, x.options().dtype(at::kBFloat16));
    }

    at::Tensor expandIdx;
    at::Tensor simulateExpertIds;
    at::Tensor simulateExpertScales;
    at::Tensor attenBatchSize;
    at::Tensor xActiveMaskOut;
    if (rank < expertRankSize && rank < attentionRankSize) {
        simulateExpertIds = at::empty({baseBatchSize, topk}, x.options().dtype(at::kInt));
        simulateExpertScales = at::empty({baseBatchSize, topk}, x.options().dtype(at::kFloat));
        xActiveMaskOut = at::empty(baseBatchSize, x.options().dtype(at::kBool));
    } else {
        simulateExpertIds = at::empty({1, 1}, x.options().dtype(at::kInt));
        simulateExpertScales = at::empty({1, 1}, x.options().dtype(at::kFloat));
        xActiveMaskOut = at::empty(1, x.options().dtype(at::kBool));
    }
    attenBatchSize = at::empty({(attentionRankSize + expertRankSize - 1) / expertRankSize},
        x.options().dtype(at::kInt));

    vector<char> groupEpChars(groupEp.begin(), groupEp.end());
    groupEpChars.push_back('\0');
    char *groupEpPtr = &groupEpChars[0];

    EXEC_NPU_CMD(aclnnA2e,
        // input
        x, expertIds, scales, \
        // attr
        baseBatchSize, hiddenSize, topk, expertRankSize, attentionRankSize, rank, \
        groupEpPtr, aivNum, computeGate, \
        // output
        expandXOut, simulateExpertIds, simulateExpertScales, attenBatchSize, xActiveMaskOut);

    TensorVector result = {
        expandXOut,
        simulateExpertIds,
        simulateExpertScales,
        attenBatchSize,
        xActiveMaskOut
    };
    return result;
}

TensorVector A2eBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // Create output memory
    return {result, result, result};
}

TensorVector A2eImplMeta(
    const at::Tensor &x, \
    const c10::optional<at::Tensor> &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum,
    int64_t computeGate)
{
    int32_t baseBatchSize = (rank >= expertRankSize) ? x.sizes()[0] : batchSize;

    at::Tensor expandXOut;
    if (rank >= expertRankSize) {
        expandXOut = at::empty({1, 1}, x.options().dtype(at::kBFloat16));
    } else {
        expandXOut = at::empty({baseBatchSize, hiddenSize}, x.options().dtype(at::kBFloat16));
    }

    at::Tensor expandIdx;
    at::Tensor simulateExpertIds;
    at::Tensor simulateExpertScales;
    at::Tensor attenBatchSize;
    at::Tensor xActiveMaskOut;
    if (rank < expertRankSize && rank < attentionRankSize) {
        simulateExpertIds = at::empty({baseBatchSize, topk}, x.options().dtype(at::kInt));
        simulateExpertScales = at::empty({baseBatchSize, topk}, x.options().dtype(at::kFloat));
        xActiveMaskOut = at::empty(baseBatchSize, x.options().dtype(at::kBool));
    } else {
        simulateExpertIds = at::empty({1, 1}, x.options().dtype(at::kInt));
        simulateExpertScales = at::empty({1, 1}, x.options().dtype(at::kFloat));
        xActiveMaskOut = at::empty(1, x.options().dtype(at::kBool));
    }
    attenBatchSize = at::empty({(attentionRankSize + expertRankSize - 1) / expertRankSize},
        x.options().dtype(at::kInt));

    TensorVector result = {
        expandXOut,
        simulateExpertIds,
        simulateExpertScales,
        attenBatchSize,
        xActiveMaskOut
    };
    return result;
}

TensorVector A2eImpl(\
    const at::Tensor &x, \
    const c10::optional<at::Tensor> &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum,\
    int64_t computeGate)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::a2e", "")
                        .typed<decltype(A2eImpl)>();
    return op.call(x, expertIds, scales, batchSize, hiddenSize, topk, \
        expertRankSize, attentionRankSize, rank, groupEp, aivNum, computeGate);
}

// Bind forward and backward computations by inheriting the torch::autograd::Function class.
class A2e : public torch::autograd::Function<A2e> {
public:
    static TensorVector forward(
        AutogradContext *ctx, \
        const at::Tensor &x, \
        const c10::optional<at::Tensor> &expertIds, \
        const c10::optional<at::Tensor> &scales, \
        int64_t batchSize, \
        int64_t hiddenSize, \
        int64_t topk, \
        int64_t expertRankSize, \
        int64_t attentionRankSize, \
        int64_t rank, \
        c10::string_view groupEp, \
        int64_t aivNum,
        int64_t computeGate)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = A2eImpl(x, expertIds, scales, batchSize, hiddenSize, topk, \
        expertRankSize, attentionRankSize, rank, groupEp, aivNum, computeGate);

        return result;
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

TensorVector A2eImplAutograd(
    const at::Tensor &x, \
    const c10::optional<at::Tensor> &expertIds, \
    const c10::optional<at::Tensor> &scales, \
    int64_t batchSize, \
    int64_t hiddenSize, \
    int64_t topk, \
    int64_t expertRankSize, \
    int64_t attentionRankSize, \
    int64_t rank, \
    c10::string_view groupEp, \
    int64_t aivNum,
    int64_t computeGate)
{
    auto result = A2e::apply(x, expertIds, scales, batchSize, hiddenSize, topk, \
        expertRankSize, attentionRankSize, rank, groupEp, aivNum, computeGate);
    return result;
}

// a2e
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("a2e", &A2eImplNpu);
    m.impl("a2e_backward", &A2eBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("a2e", &A2eImplAutograd);
}

// Register the forward and backward implementation for Meta devices.
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("a2e", &A2eImplMeta);
}