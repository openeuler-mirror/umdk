/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add fused_deep_moe file
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 fused_deep_moe file
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
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

namespace {
const uint32_t DIM_TWO = 2;
} // namespace

TensorVector FusedDeepMoeImplNpu(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1Weight, \
    const at::TensorList &gmm1WeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &shareGmm1WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional, \
    const c10::optional<at::Tensor> &expertSmoothScales, \
    const c10::optional<at::Tensor> &shareSmoothScales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs
)
{
    TORCH_BIND_ASSERT(x.dim() == DIM_TWO);
    TORCH_BIND_ASSERT(expertIds.dim() == DIM_TWO);
    auto xShape = x.sizes();
    auto expertIdsShape = expertIds.sizes();
    int h = xShape[1];
    int bs = xShape[0];
    int topk = expertIdsShape[1];
    
    at::Tensor output = at::empty({bs, h}, x.options());
    at::Tensor shareOutput = at::empty({bs, h}, x.options());

    int64_t localExpertNum = moeExpertNum / epRankSize;
    auto opts = expertIds.options().dtype(at::kLong);
    at::Tensor expertTokenNums = at::empty({localExpertNum}, opts);
    
    const std::string groupEpStr(groupEp.data(), groupEp.size());
    const char* groupEpPtr = groupEpStr.c_str();

    EXEC_NPU_CMD(aclnnFusedDeepMoe,
        // input
        x, expertIds, gmm1Weight, gmm1WeightScale, gmm2Weight, gmm2WeightScale, \
        expertScales, \
        shareGmm1WeightOptional, shareGmm1WeightScaleOptional, \
        shareGmm2WeightOptional, shareGmm2WeightScaleOptional, \
        expertSmoothScales, shareSmoothScales, xActiveMask, \
        // attr
        groupEpPtr, epRankSize, epRankId, moeExpertNum, quantMode, globalBs, \
        // output
        output, shareOutput, expertTokenNums);
    return {output, shareOutput, expertTokenNums};
}

TensorVector FusedDeepMoeBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self);
    return {result, result};
}

TensorVector FusedDeepMoeImplMeta(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1Weight, \
    const at::TensorList &gmm1WeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &shareGmm1WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional, \
    const c10::optional<at::Tensor> &expertSmoothScales, \
    const c10::optional<at::Tensor> &shareSmoothScales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs)
{
    auto xShape = x.sizes();
    int h = xShape[1];
    int bs = xShape[0];
    at::Tensor output = at::empty({bs, h}, x.options().device(at::kMeta));
    at::Tensor shareOutput = at::empty({bs, h}, x.options().device(at::kMeta));

    int64_t localExpertNum = moeExpertNum / epRankSize;
    auto opts = expertIds.options().dtype(at::kLong);
    at::Tensor expertTokenNums = at::empty({localExpertNum}, opts.device(at::kMeta));
    
    return {output, shareOutput, expertTokenNums};
}

TensorVector FusedDeepMoeImpl(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1Weight, \
    const at::TensorList &gmm1WeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &shareGmm1WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional, \
    const c10::optional<at::Tensor> &expertSmoothScales, \
    const c10::optional<at::Tensor> &shareSmoothScales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::fused_deep_moe", "")
                        .typed<decltype(FusedDeepMoeImpl)>();
    return op.call(x, expertIds, gmm1Weight, gmm1WeightScale, gmm2Weight, gmm2WeightScale, \
        expertScales, \
        shareGmm1WeightOptional, shareGmm1WeightScaleOptional, \
        shareGmm2WeightOptional, shareGmm2WeightScaleOptional, \
        expertSmoothScales, shareSmoothScales, xActiveMask, \
        groupEp, epRankSize, epRankId, moeExpertNum, quantMode, globalBs);
}

class FusedDeepMoe : public torch::autograd::Function<FusedDeepMoe> {
public:
    static TensorVector forward(AutogradContext *ctx, \
                            const at::Tensor &x, \
                            const at::Tensor &expertIds, \
                            const at::TensorList &gmm1Weight, \
                            const at::TensorList &gmm1WeightScale, \
                            const at::TensorList &gmm2Weight, \
                            const at::TensorList &gmm2WeightScale, \
                            const at::Tensor &expertScales, \
                            const c10::optional<at::Tensor> &shareGmm1WeightOptional, \
                            const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional, \
                            const c10::optional<at::Tensor> &shareGmm2WeightOptional, \
                            const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional, \
                            const c10::optional<at::Tensor> &expertSmoothScales, \
                            const c10::optional<at::Tensor> &shareSmoothScales, \
                            const c10::optional<at::Tensor> &xActiveMask, \
                            c10::string_view groupEp, \
                            int64_t epRankSize, \
                            int64_t epRankId, \
                            int64_t moeExpertNum, \
                            int64_t quantMode, \
                            int64_t globalBs)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = FusedDeepMoeImpl(x, expertIds, gmm1Weight, gmm1WeightScale, gmm2Weight, \
            gmm2WeightScale, expertScales, \
            shareGmm1WeightOptional, shareGmm1WeightScaleOptional, \
            shareGmm2WeightOptional, shareGmm2WeightScaleOptional, \
            expertSmoothScales, shareSmoothScales, xActiveMask, \
            groupEp, epRankSize, epRankId, moeExpertNum, quantMode, globalBs);
        return result;
    }

    static TensorVector backward(AutogradContext *ctx, TensorVector grad_outputs)
    {
        return {at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor(),
                at::Tensor()};
    }
};

TensorVector FusedDeepMoeImplAutograd(
    const at::Tensor &x, \
    const at::Tensor &expertIds, \
    const at::TensorList &gmm1Weight, \
    const at::TensorList &gmm1WeightScale, \
    const at::TensorList &gmm2Weight, \
    const at::TensorList &gmm2WeightScale, \
    const at::Tensor &expertScales, \
    const c10::optional<at::Tensor> &shareGmm1WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm1WeightScaleOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightOptional, \
    const c10::optional<at::Tensor> &shareGmm2WeightScaleOptional, \
    const c10::optional<at::Tensor> &expertSmoothScales, \
    const c10::optional<at::Tensor> &shareSmoothScales, \
    const c10::optional<at::Tensor> &xActiveMask, \
    c10::string_view groupEp, \
    int64_t epRankSize, \
    int64_t epRankId, \
    int64_t moeExpertNum, \
    int64_t quantMode, \
    int64_t globalBs)
{
    auto result = FusedDeepMoe::apply(x, expertIds, gmm1Weight, gmm1WeightScale, gmm2Weight, \
            gmm2WeightScale, expertScales, \
            shareGmm1WeightOptional, shareGmm1WeightScaleOptional, \
            shareGmm2WeightOptional, shareGmm2WeightScaleOptional, \
            expertSmoothScales, shareSmoothScales, xActiveMask, \
            groupEp, epRankSize, epRankId, moeExpertNum, quantMode, globalBs);
        return result;
}

// fused_deep_moe
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("fused_deep_moe", &FusedDeepMoeImplNpu);
    m.impl("fused_deep_moe_backward", &FusedDeepMoeBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("fused_deep_moe", &FusedDeepMoeImplAutograd);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("fused_deep_moe", &FusedDeepMoeImplMeta);
}