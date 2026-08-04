/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_combine_prefill_zb pybind extension file
 * Create: 2026-07-31
 * Note:
 * History: 2026-07-31 create moe_combine_prefill_zb pybind extension file
 *          2026-08-03 drop send_cost_stats / grad_out from public API
 *          2026-08-03 remove train path (prob_grad / grad_out) from combine ZB
 */

#include <iostream>
#include <unistd.h>

#include <torch/csrc/autograd/custom_function.h>
#include <torch/extension.h>

#include "pytorch_npu_helper.hpp"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

at::Tensor MoeCombinePrefillZbImplNpu(const at::Tensor &recvX, const at::Tensor &epRecvCounts,
    const at::Tensor &recvTopkWeights, const at::Tensor &topkIdx,
    const c10::optional<at::Tensor> &sendTokenIdx, int64_t commMetaPtr, int64_t epWorldSize,
    int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs)
{
    auto combinedX = at::empty({recvTopkWeights.size(0), recvX.size(1)}, recvX.options());

    // Profiling optional output not exposed on the Python API.
    c10::optional<at::Tensor> sendCostStats = c10::nullopt;

    // EXEC_NPU_CMD takes non-const lvalue refs; keep uint64_t as a local, not a temporary cast.
    uint64_t commMetaPtrU64 = static_cast<uint64_t>(commMetaPtr);
    EXEC_NPU_CMD(aclnnMoeCombineNormalZb, recvX, epRecvCounts, recvTopkWeights, topkIdx, sendTokenIdx,
        commMetaPtrU64, epWorldSize, epRankId, tpWorldSize, tpRankId, moeExpertNum, globalBs, combinedX,
        sendCostStats);
    return combinedX;
}

TensorVector MoeCombinePrefillZbBackwardImplNpu(const at::Tensor &self)
{
    return {at::Tensor(), at::Tensor(), at::Tensor()};
}

at::Tensor MoeCombinePrefillZbImplMeta(const at::Tensor &recvX, const at::Tensor &epRecvCounts,
    const at::Tensor &recvTopkWeights, const at::Tensor &topkIdx,
    const c10::optional<at::Tensor> &sendTokenIdx, int64_t commMetaPtr, int64_t epWorldSize,
    int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs)
{
    (void)epRecvCounts;
    (void)topkIdx;
    (void)sendTokenIdx;
    (void)commMetaPtr;
    (void)epWorldSize;
    (void)epRankId;
    (void)tpWorldSize;
    (void)tpRankId;
    (void)moeExpertNum;
    (void)globalBs;
    return at::empty({recvTopkWeights.size(0), recvX.size(1)}, recvX.options().device(at::kMeta));
}

at::Tensor MoeCombinePrefillZbImpl(const at::Tensor &recvX, const at::Tensor &epRecvCounts,
    const at::Tensor &recvTopkWeights, const at::Tensor &topkIdx,
    const c10::optional<at::Tensor> &sendTokenIdx, int64_t commMetaPtr, int64_t epWorldSize,
    int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_combine_prefill_zb", "")
                         .typed<decltype(MoeCombinePrefillZbImpl)>();
    return op.call(recvX, epRecvCounts, recvTopkWeights, topkIdx, sendTokenIdx, commMetaPtr,
        epWorldSize, epRankId, tpWorldSize, tpRankId, moeExpertNum, globalBs);
}

class ExtMoeCombinePrefillZb : public torch::autograd::Function<ExtMoeCombinePrefillZb> {
public:
    static at::Tensor forward(AutogradContext *ctx, const at::Tensor &recvX, const at::Tensor &epRecvCounts,
        const at::Tensor &recvTopkWeights, const at::Tensor &topkIdx,
        const c10::optional<at::Tensor> &sendTokenIdx, int64_t commMetaPtr, int64_t epWorldSize,
        int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        return MoeCombinePrefillZbImpl(recvX, epRecvCounts, recvTopkWeights, topkIdx, sendTokenIdx, commMetaPtr,
            epWorldSize, epRankId, tpWorldSize, tpRankId, moeExpertNum, globalBs);
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector gradOutputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

at::Tensor MoeCombinePrefillZbImplAutograd(const at::Tensor &recvX, const at::Tensor &epRecvCounts,
    const at::Tensor &recvTopkWeights, const at::Tensor &topkIdx,
    const c10::optional<at::Tensor> &sendTokenIdx, int64_t commMetaPtr, int64_t epWorldSize,
    int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs)
{
    return ExtMoeCombinePrefillZb::apply(recvX, epRecvCounts, recvTopkWeights, topkIdx, sendTokenIdx, commMetaPtr,
        epWorldSize, epRankId, tpWorldSize, tpRankId, moeExpertNum, globalBs);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_combine_prefill_zb", &MoeCombinePrefillZbImplNpu);
    m.impl("moe_combine_prefill_zb_backward", &MoeCombinePrefillZbBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_combine_prefill_zb", &MoeCombinePrefillZbImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_combine_prefill_zb", &MoeCombinePrefillZbImplMeta);
}
