/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: moe_dispatch_prefill_zb pybind — wraps notify + dispatch like
 *   master moe_dispatch_prefill / deepep internode_dispatch.
 * Create: 2026-07-31
 * Note:
 * History: 2026-07-31 create moe_dispatch_prefill_zb pybind extension file
 *          2026-08-01 fuse notify_dispatch_zb + dispatch into one Python API
 *          2026-08-03 drop wait_recv_cost_stats from public API
 *          2026-08-03 remove assist_info_for_combine + wait_recv_cost from kernel/API
 */

#include <iostream>
#include <unistd.h>

#include <torch/csrc/autograd/custom_function.h>
#include <torch/extension.h>

#include "pytorch_npu_helper.hpp"
#include "zb_shmem_utils.h"

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

namespace {
constexpr int64_t DYNAMIC_QUANT_MODE = 2;
constexpr int64_t TP_WORLD_SIZE = 1;
constexpr int64_t TP_RANK_ID = 0;
// deepep / ZB notify: send_per_group = 1, send_count = num_experts
constexpr int64_t SEND_PER_GROUP = 1;

constexpr uint32_t OUT_RECV_X = 0;
constexpr uint32_t OUT_SCALES = 1;
constexpr uint32_t OUT_PUT_OFFSET = 2;
constexpr uint32_t OUT_TOTAL_RECV = 3;
constexpr uint32_t OUT_RECV_PER_EXP = 4;
}  // namespace

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillZbImplNpu(
    const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &sendTokenIdx,
    const at::Tensor &numTokensPerExpert, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, int64_t commMetaPtr)
{
    auto device = x.device();
    auto hidden = static_cast<int64_t>(x.size(1));
    int64_t maxRecvTokens = std::max<int64_t>(globalBs, 1);
    int64_t numExperts = numTokensPerExpert.size(0);
    int64_t numLocalExperts = moeExpertNum / epWorldSize;
    int64_t topkNum = topkIdx.size(1);
    int64_t localRankSize = epWorldSize;
    int64_t localRankId = epRankId % localRankSize;
    int64_t sendCount = SEND_PER_GROUP * moeExpertNum;

    // ---- 1) notify (same role as aclnnNotifyDispatch inside moe_dispatch_prefill) ----
    // num_tokens_per_expert must already be SHMEM-symmetric (layout_zb allocates it that way).
    auto recvData = cam_zb::CreateTensorFromShmem({epWorldSize, numExperts}, at::kInt, device);
    auto totalRecvTokens = at::empty({1}, at::dtype(at::kInt).device(device));
    auto maxBs = at::empty({1}, at::dtype(at::kInt).device(device));
    auto recvTokensPerExpert = at::empty({numLocalExperts}, at::dtype(at::kLong).device(device));
    auto putOffset = at::empty({numExperts, epWorldSize}, at::dtype(at::kInt).device(device));

    uint64_t commMetaPtrU64 = static_cast<uint64_t>(commMetaPtr);
    EXEC_NPU_CMD(aclnnNotifyDispatchZb, numTokensPerExpert, sendCount, epWorldSize, epRankId, localRankSize,
        localRankId, topkNum, commMetaPtrU64, recvData, totalRecvTokens, maxBs, recvTokensPerExpert, putOffset);

    // ---- 2) dispatch (aclnnMoeDispatchNormalZb) ----
    // Size recv buffer by static global_bs (deepep style); avoid host sync on totalRecvTokens.
    at::Tensor recvX;
    at::Tensor recvXScales;
    if (quantMode == DYNAMIC_QUANT_MODE) {
        recvX = cam_zb::CreateTensorFromShmem({maxRecvTokens, hidden}, at::kChar, device);
        recvXScales = cam_zb::CreateTensorFromShmem({maxRecvTokens}, at::kFloat, device);
    } else {
        recvX = cam_zb::CreateTensorFromShmem({maxRecvTokens, hidden}, x.scalar_type(), device);
        recvXScales = at::empty({1}, at::dtype(at::kFloat).device(device));
    }

    EXEC_NPU_CMD(aclnnMoeDispatchNormalZb, x, topkIdx, sendTokenIdx, putOffset, epWorldSize, epRankId,
        TP_WORLD_SIZE, TP_RANK_ID, moeExpertNum, quantMode, globalBs, commMetaPtrU64, recvX, recvXScales);

    (void)recvData;
    return std::make_tuple(recvX, recvXScales, putOffset, totalRecvTokens, recvTokensPerExpert);
}

TensorVector MoeDispatchPrefillZbBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);
    return {result, result, result, result, result};
}

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillZbImplMeta(
    const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &sendTokenIdx,
    const at::Tensor &numTokensPerExpert, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, int64_t commMetaPtr)
{
    (void)topkIdx;
    (void)sendTokenIdx;
    (void)epRankId;
    (void)commMetaPtr;

    auto hidden = static_cast<int64_t>(x.size(1));
    int64_t maxRecvTokens = std::max<int64_t>(globalBs, 1);
    int64_t numExperts = numTokensPerExpert.size(0);
    int64_t numLocalExperts = moeExpertNum / std::max<int64_t>(epWorldSize, 1);
    at::TensorOptions options = at::TensorOptions(at::kMeta);
    at::Tensor recvX;
    if (quantMode == DYNAMIC_QUANT_MODE) {
        recvX = at::empty({maxRecvTokens, hidden}, x.options().dtype(at::kChar).device(at::kMeta));
    } else {
        recvX = at::empty({maxRecvTokens, hidden}, x.options().device(at::kMeta));
    }
    auto recvXScales = at::empty({maxRecvTokens}, options.dtype(at::kFloat));
    auto putOffset = at::empty({numExperts, epWorldSize}, options.dtype(at::kInt));
    auto totalRecvTokens = at::empty({1}, options.dtype(at::kInt));
    auto recvTokensPerExpert = at::empty({numLocalExperts}, options.dtype(at::kLong));
    return std::make_tuple(recvX, recvXScales, putOffset, totalRecvTokens, recvTokensPerExpert);
}

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillZbImpl(
    const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &sendTokenIdx,
    const at::Tensor &numTokensPerExpert, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, int64_t commMetaPtr)
{
    static auto op = torch::Dispatcher::singleton()
                         .findSchemaOrThrow("umdk_cam_op_lib::moe_dispatch_prefill_zb", "")
                         .typed<decltype(MoeDispatchPrefillZbImpl)>();
    return op.call(x, topkIdx, sendTokenIdx, numTokensPerExpert, epWorldSize, epRankId, moeExpertNum, quantMode,
        globalBs, commMetaPtr);
}

class ExtMoeDispatchPrefillZb : public torch::autograd::Function<ExtMoeDispatchPrefillZb> {
public:
    static TensorVector forward(AutogradContext *ctx, const at::Tensor &x, const at::Tensor &topkIdx,
        const at::Tensor &sendTokenIdx, const at::Tensor &numTokensPerExpert, int64_t epWorldSize,
        int64_t epRankId, int64_t moeExpertNum, int64_t quantMode, int64_t globalBs, int64_t commMetaPtr)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeDispatchPrefillZbImpl(x, topkIdx, sendTokenIdx, numTokensPerExpert, epWorldSize, epRankId,
            moeExpertNum, quantMode, globalBs, commMetaPtr);
        return {std::get<0>(result), std::get<1>(result), std::get<2>(result), std::get<3>(result),
            std::get<4>(result)};
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector gradOutputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillZbImplAutograd(
    const at::Tensor &x, const at::Tensor &topkIdx, const at::Tensor &sendTokenIdx,
    const at::Tensor &numTokensPerExpert, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, int64_t commMetaPtr)
{
    auto result = ExtMoeDispatchPrefillZb::apply(x, topkIdx, sendTokenIdx, numTokensPerExpert, epWorldSize, epRankId,
        moeExpertNum, quantMode, globalBs, commMetaPtr);
    return std::make_tuple(result[OUT_RECV_X], result[OUT_SCALES], result[OUT_PUT_OFFSET], result[OUT_TOTAL_RECV],
        result[OUT_RECV_PER_EXP]);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_dispatch_prefill_zb", &MoeDispatchPrefillZbImplNpu);
    m.impl("moe_dispatch_prefill_zb_backward", &MoeDispatchPrefillZbBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_dispatch_prefill_zb", &MoeDispatchPrefillZbImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("moe_dispatch_prefill_zb", &MoeDispatchPrefillZbImplMeta);
}
