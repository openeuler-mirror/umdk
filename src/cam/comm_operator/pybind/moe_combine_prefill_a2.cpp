/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_combine_prefill_a2 pybind extention file
 * Create: 2026-01-12
 * Note:
 * History: 2026-01-12 create moe_combine_prefill_a2 pybind extention file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include "torch_bind_exception.h"
#include <hccl/hccl.h>
#include <iostream>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using tensorList = std::vector<at::Tensor>;
using namespace at;
using namespace std;

constexpr int MAX_BATCH_SIZE = 4096;
constexpr int X_DIM = 2;

#define MOE_COMBINE_PREFILL_A2_DEF \
    const at::Tensor& x, \
    const at::Tensor& topkIdx, \
    const at::Tensor& topkWeights, \
    const at::Tensor& srcIdx, \
    const at::Tensor& sendHead, \
    const at::Tensor& expandScales, \
    const at::Tensor& offsetInner, \
    const at::Tensor& offsetOuter, \
    const at::Tensor& countOuter, \
    c10::string_view groupEp, \
    int64_t rank, \
    int64_t numRanks

#define MOE_COMBINE_PREFILL_A2_CALL \
    x, \
    topkIdx, \
    topkWeights, \
    srcIdx, \
    sendHead, \
    expandScales, \
    offsetInner, \
    offsetOuter, \
    countOuter, \
    groupEp, \
    rank, \
    numRanks

at::Tensor MoeCombinePrefillA2ImplNpu(MOE_COMBINE_PREFILL_A2_DEF)
{
    at::Tensor newTopkIdx = topkIdx;
    TORCH_BIND_ASSERT(x.dim() == X_DIM and x.is_contiguous());
    at::Tensor recvX = x;

    at::Tensor topkIdxP = topkIdx;

    auto topkIdxInt32 = topkIdxP.to(at::kInt);
    at::Tensor expertIds = topkIdxInt32;
    // In the A2 implementation, the tensor is expanded from [bs, k] to [bs, numExpert].
    at::Tensor expandIdx = srcIdx;
    // A2 needs global send counts, [numExpert, numRank]
    at::Tensor epSendCounts = sendHead;
    auto device = x.device();

    const int numTokens = topkIdxP.size(0);
    const int numTopk = topkIdxP.size(1);
    at::Tensor expertScales = at::empty({1}, at::dtype(at::kFloat).device(x.device()));

    int64_t hidden = static_cast<int>(recvX.size(1));
    at::Tensor tpSendCounts = at::empty({1}, at::dtype(at::kInt).device(device));
    int64_t tpWorldSize = 1;
    int64_t tpRankId = 0;
    int64_t moeExpertNumber = sendHead.size(0);
    int64_t globalBs = static_cast<int64_t>(MAX_BATCH_SIZE * numRanks);

    // ep comm
    const std::string groupEpStr(groupEp.data(), groupEp.size());
    const char* groupEpPtr = groupEpStr.c_str();
    
    // Combine data
    auto combinedX = torch::empty({newTopkIdx.size(0), hidden}, x.options());
    std::optional<torch::Tensor> recvTopkWeights;
    at::Tensor xActiveMask;
    at::Tensor activationScale;
    at::Tensor weightScale;
    at::Tensor groupList;
    int64_t expertSharedType = 0;
    int64_t outDtype = 0;
    int64_t commQuantMode = 0;
    int64_t groupListType = 0;
    int64_t sharedExpertNum = 1;
    int64_t sharedExpertRankNum = 0; // not support shared expert now;
    EXEC_NPU_CMD(
        aclnnMoeDistributeCombineA2,
        recvX,
        expertIds,
        expandIdx,
        epSendCounts,
        expertScales,
        tpSendCounts,
        xActiveMask,
        activationScale,
        weightScale,
        groupList,
        expandScales, // a2 new
        offsetInner, // a2 new
        offsetOuter, // a2 new
        countOuter, // a2 new
        groupEpPtr,
        numRanks,
        rank,
        moeExpertNumber,
        groupEpPtr,
        tpWorldSize,
        tpRankId,
        expertSharedType,
        sharedExpertNum,
        sharedExpertRankNum,
        globalBs,
        outDtype,
        commQuantMode,
        groupListType,
        combinedX);
    return combinedX;
}

tensorList MoeCombinePrefillA2BackwardImplNpu(const at::Tensor &self)
{
    return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
}

at::Tensor MoeCombinePrefillA2Impl(MOE_COMBINE_PREFILL_A2_DEF)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::moe_combine_prefill_a2", "")
                        .typed<decltype(MoeCombinePrefillA2Impl)>();
    return op.call(MOE_COMBINE_PREFILL_A2_CALL);
}

class MoeCombinePrefillA2 : public torch::autograd::Function<MoeCombinePrefillA2> {
public:
    static at::Tensor forward(
        AutogradContext *ctx, \
        MOE_COMBINE_PREFILL_A2_DEF)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeCombinePrefillA2Impl(MOE_COMBINE_PREFILL_A2_CALL);
        return result;
    }

    static tensorList backward(
        AutogradContext *ctx, \
        tensorList gradOutputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

at::Tensor MoeCombinePrefillA2ImplAutograd(MOE_COMBINE_PREFILL_A2_DEF)
{
    auto result = MoeCombinePrefillA2::apply(MOE_COMBINE_PREFILL_A2_CALL);
    return result;
}

// moe_combine_prefill_a2
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_combine_prefill_a2", &MoeCombinePrefillA2ImplNpu);
    m.impl("moe_combine_prefill_a2_backward", &MoeCombinePrefillA2BackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_combine_prefill_a2", &MoeCombinePrefillA2ImplAutograd);
}
